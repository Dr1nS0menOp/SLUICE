//! Records through a real Fluent Bit, with a generated filter or without one.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Map, Value};

use crate::FluentBitError;
use crate::filter::CALL;

/// How to run Fluent Bit: a command that takes Fluent Bit's own arguments (`-q -c FILE`), the
/// `fluent-bit` binary or a wrapper that runs it in a container with the temporary directory
/// mounted at the same path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FluentBit {
    command: PathBuf,
}

impl FluentBit {
    /// Fluent Bit run as `command`.
    #[must_use]
    pub fn new(command: impl Into<PathBuf>) -> Self {
        Self {
            command: command.into(),
        }
    }

    /// The records as Fluent Bit forwards them, read from its `stdin` input: through the Lua
    /// `script` (with `enable_flb_null`, as a deployment must set it), or through no filter, which
    /// shows what Fluent Bit itself does to them. In the order of `records`.
    ///
    /// # Errors
    ///
    /// [`FluentBitError`] when Fluent Bit cannot be run, fails, or forwards another number of
    /// records than it was given.
    pub fn run(
        &self,
        script: Option<&str>,
        records: &[&Map<String, Value>],
    ) -> Result<Vec<Map<String, Value>>, FluentBitError> {
        let dir = Scratch::new()?;
        let filter = match script {
            Some(script) => {
                let path = dir.path().join("filter.lua");
                write(&path, script)?;
                format!(
                    "[FILTER]\n    Name lua\n    Match *\n    Script {}\n    Call {CALL}\n    \
                     enable_flb_null true\n",
                    path.display()
                )
            }
            None => String::new(),
        };
        let conf = dir.path().join("fluent-bit.conf");
        write(
            &conf,
            &format!(
                "[SERVICE]\n    Flush 1\n    Log_Level error\n[INPUT]\n    Name stdin\n    Tag \
                 sluice\n    Buffer_Size 64M\n{filter}[OUTPUT]\n    Name stdout\n    Match *\n    \
                 Format json_lines\n    json_date_key false\n"
            ),
        )?;
        let mut child = Command::new(&self.command)
            .arg("-q")
            .arg("-c")
            .arg(&conf)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                FluentBitError::Run(format!("cannot start {}: {e}", self.command.display()))
            })?;
        let input: String = records
            .iter()
            .map(|r| Value::Object((*r).clone()).to_string() + "\n")
            .collect();
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| FluentBitError::Run("no stdin".to_owned()))?;
        let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| FluentBitError::Run("no stdout".to_owned()))?;
        let mut out = Vec::with_capacity(records.len());
        for line in BufReader::new(stdout).lines() {
            let line = line.map_err(|e| FluentBitError::Output(e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(&line) {
                Ok(Value::Object(record)) => out.push(record),
                _ => return Err(FluentBitError::Output(format!("not a record: {line}"))),
            }
        }
        let output = child
            .wait_with_output()
            .map_err(|e| FluentBitError::Run(e.to_string()))?;
        writer
            .join()
            .map_err(|_| FluentBitError::Run("writing the records failed".to_owned()))?
            .map_err(|e| FluentBitError::Run(format!("writing the records: {e}")))?;
        if !output.status.success() {
            return Err(FluentBitError::Run(format!(
                "Fluent Bit exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        if out.len() != records.len() {
            return Err(FluentBitError::Output(format!(
                "{} records in, {} out: {}",
                records.len(),
                out.len(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(out)
    }
}

fn write(path: &Path, text: &str) -> Result<(), FluentBitError> {
    std::fs::write(path, text)
        .map_err(|e| FluentBitError::Run(format!("writing {}: {e}", path.display())))
}

/// A directory of its own under the temporary directory, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Self, FluentBitError> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "sluice-fluent-bit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path)
            .map_err(|e| FluentBitError::Run(format!("creating {}: {e}", path.display())))?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
