//! Records through a real OpenTelemetry Collector, with generated statements or without them.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use crate::OtelError;

/// How long the collector may take to forward the records.
const DEADLINE: Duration = Duration::from_secs(120);

/// How to run the collector: a command that takes the collector's own arguments (`--config
/// FILE`), the `otelcol-contrib` binary or a wrapper that runs it in a container with the
/// temporary directory mounted at the same path. It needs the `filelog` receiver, the
/// `transform` processor and the `file` exporter (the contrib distribution has them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collector {
    command: PathBuf,
}

impl Collector {
    /// The collector run as `command`.
    #[must_use]
    pub fn new(command: impl Into<PathBuf>) -> Self {
        Self {
            command: command.into(),
        }
    }

    /// The records' bodies as the collector forwards them: read by `filelog` with
    /// `json_parser` into the body, through the `statements` (failing on any error, so a
    /// statement that fails shows) or through none, which shows what the collector itself does
    /// to them. In the order of `records`.
    ///
    /// # Errors
    ///
    /// [`OtelError`] when the collector cannot be run, fails, or does not forward one body per
    /// record in time.
    pub fn run(
        &self,
        statements: Option<&[String]>,
        records: &[&Map<String, Value>],
    ) -> Result<Vec<Map<String, Value>>, OtelError> {
        let dir = Scratch::new()?;
        let input = dir.path().join("records.ndjson");
        let output = dir.path().join("out.json");
        let lines: String = records
            .iter()
            .map(|r| Value::Object((*r).clone()).to_string() + "\n")
            .collect();
        write(&input, &lines)?;
        let (processor, processors) = match statements {
            Some(statements) => {
                let quoted: Vec<String> = statements
                    .iter()
                    .map(|s| format!("          - '{}'\n", s.replace('\'', "''")))
                    .collect();
                (
                    format!(
                        "processors:\n  transform:\n    error_mode: propagate\n    \
                         log_statements:\n      - context: log\n        statements:\n{}",
                        quoted.concat()
                    ),
                    "[transform]",
                )
            }
            None => (String::new(), "[]"),
        };
        let config = dir.path().join("collector.yaml");
        write(
            &config,
            &format!(
                "receivers:\n  filelog:\n    include: [{}]\n    start_at: beginning\n    \
                 include_file_record_number: true\n    max_log_size: 64MiB\n    operators:\n      - type: json_parser\n        \
                 parse_to: body\n{processor}exporters:\n  file:\n    path: {}\nservice:\n  \
                 telemetry:\n    logs:\n      level: error\n  pipelines:\n    logs:\n      \
                 receivers: [filelog]\n      processors: {processors}\n      exporters: \
                 [file]\n",
                input.display(),
                output.display()
            ),
        )?;
        let mut child = Command::new(&self.command)
            .arg("--config")
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| OtelError::Run(format!("cannot start {}: {e}", self.command.display())))?;
        let started = Instant::now();
        let bodies = loop {
            let bodies = read(&output)?;
            let exited = child
                .try_wait()
                .map_err(|e| OtelError::Run(e.to_string()))?;
            if bodies.len() >= records.len() || exited.is_some() || started.elapsed() > DEADLINE {
                break bodies;
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        stop(&mut child);
        let stderr = child
            .wait_with_output()
            .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_owned())
            .unwrap_or_default();
        if bodies.len() != records.len() {
            return Err(OtelError::Output(format!(
                "{} records in, {} out: {stderr}",
                records.len(),
                bodies.len()
            )));
        }
        Ok(bodies)
    }
}

/// Asks the collector to stop (SIGTERM, which a container wrapper passes on), and kills it if
/// it does not within a few seconds.
fn stop(child: &mut std::process::Child) {
    if let Some(pid) = i32::try_from(child.id())
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
    }
    let asked = Instant::now();
    while asked.elapsed() < Duration::from_secs(20) {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
}

/// The bodies of every log record in the file exporter's output so far (one OTLP JSON
/// document per line), in the order of the input's lines: batches may arrive in another, so
/// each record carries its line number (`log.file.record_number`).
fn read(path: &Path) -> Result<Vec<Map<String, Value>>, OtelError> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(Vec::new());
    };
    let mut out: Vec<(u64, Map<String, Value>)> = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(document) = serde_json::from_str::<Value>(line) else {
            // A line still being written.
            break;
        };
        let records = document["resourceLogs"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|r| r["scopeLogs"].as_array().into_iter().flatten())
            .flat_map(|s| s["logRecords"].as_array().into_iter().flatten());
        for record in records {
            let line = record["attributes"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|kv| kv["key"] == "log.file.record_number")
                .and_then(|kv| any_value(&kv["value"]).as_u64())
                .ok_or_else(|| OtelError::Output("a record without its line number".to_owned()))?;
            match any_value(&record["body"]) {
                Value::Object(body) => out.push((line, body)),
                other => return Err(OtelError::Output(format!("a body that is no map: {other}"))),
            }
        }
    }
    out.sort_by_key(|(line, _)| *line);
    Ok(out.into_iter().map(|(_, body)| body).collect())
}

/// An OTLP JSON `AnyValue` as JSON: an empty one is null, an `intValue` (a string in OTLP
/// JSON) a number.
pub(crate) fn any_value(value: &Value) -> Value {
    if let Some(s) = value.get("stringValue") {
        return s.clone();
    }
    if let Some(b) = value.get("boolValue") {
        return b.clone();
    }
    if let Some(d) = value.get("doubleValue") {
        return d.clone();
    }
    if let Some(i) = value.get("intValue") {
        return i
            .as_str()
            .and_then(|s| s.parse::<i64>().ok())
            .map_or_else(|| i.clone(), Value::from);
    }
    if let Some(list) = value.get("arrayValue") {
        let values = list["values"]
            .as_array()
            .map(|v| v.iter().map(any_value).collect());
        return Value::Array(values.unwrap_or_default());
    }
    if let Some(map) = value.get("kvlistValue") {
        let mut out = Map::new();
        for kv in map["values"].as_array().into_iter().flatten() {
            if let Some(key) = kv["key"].as_str() {
                out.insert(key.to_owned(), any_value(&kv["value"]));
            }
        }
        return Value::Object(out);
    }
    if let Some(bytes) = value.get("bytesValue") {
        return bytes.clone();
    }
    Value::Null
}

fn write(path: &Path, text: &str) -> Result<(), OtelError> {
    std::fs::File::create(path)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .map_err(|e| OtelError::Run(format!("writing {}: {e}", path.display())))
}

/// A directory of its own under the temporary directory, open to the collector's user in a
/// container, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Self, OtelError> {
        use std::os::unix::fs::PermissionsExt;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "sluice-otel-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let io = |e: std::io::Error| OtelError::Run(format!("{}: {e}", path.display()));
        std::fs::create_dir_all(&path).map_err(io)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).map_err(io)?;
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn otlp_values_read_as_json() {
        let body = json!({"kvlistValue": {"values": [
            {"key": "s", "value": {"stringValue": "x"}},
            {"key": "i", "value": {"intValue": "7"}},
            {"key": "d", "value": {"doubleValue": 1.5}},
            {"key": "b", "value": {"boolValue": true}},
            {"key": "n", "value": {}},
            {"key": "a", "value": {"arrayValue": {}}},
            {"key": "m", "value": {"kvlistValue": {}}}
        ]}});
        assert_eq!(
            any_value(&body),
            json!({"s": "x", "i": 7, "d": 1.5, "b": true, "n": null, "a": [], "m": {}})
        );
    }
}
