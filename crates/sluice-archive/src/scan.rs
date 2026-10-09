//! Streaming the selected events out of the archive.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use chrono::DateTime;
use flate2::read::MultiGzDecoder;
use serde_json::{Map, Value};
use sluice_core::event::Timestamp;
use sluice_core::ids::SourceId;

use crate::error::ArchiveError;
use crate::layout::{ArchiveFile, files};
use crate::query::Query;

/// The field in which Vector records when it received an event (its default `timestamp_key`).
const RECEIVED_AT: &str = "timestamp";

/// One archived event.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// The source it came from.
    pub source: SourceId,
    /// When Vector received it, or the start of its file's hour if that is not recorded.
    pub time: Timestamp,
    /// The event exactly as archived.
    pub fields: Map<String, Value>,
}

/// What a scan read, so a search or replay can say how complete its answer is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    /// Files opened.
    pub files: usize,
    /// Lines read.
    pub lines: u64,
    /// Events selected.
    pub matched: u64,
    /// Lines that are not a JSON object.
    pub bad_lines: u64,
    /// Files that ended early with the reason: the newest hour while Vector still writes it, or a
    /// damaged file. The events before that point were read.
    pub incomplete: Vec<(PathBuf, String)>,
}

/// An iterator over the archived events a [`Query`] selects, in file order (hour, then source)
/// and line order within a file.
///
/// Problems with single files or lines do not end the scan; they are counted in [`Stats`].
pub struct Scan {
    query: Query,
    pending: std::vec::IntoIter<ArchiveFile>,
    current: Option<Open>,
    stats: Stats,
    line: Vec<u8>,
}

struct Open {
    file: ArchiveFile,
    reader: BufReader<MultiGzDecoder<File>>,
}

impl Scan {
    /// Starts a scan of the archive under `root`.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::Io`] if the archive's directories cannot be listed.
    pub fn new(root: &Path, query: Query) -> Result<Self, ArchiveError> {
        let pending = files(root, &query)?.into_iter();
        Ok(Self {
            query,
            pending,
            current: None,
            stats: Stats::default(),
            line: Vec::new(),
        })
    }

    /// What has been read so far; complete once the iterator returns `None`.
    #[must_use]
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// The next line of the open file, opening files as needed; `None` when all are read.
    fn next_line(&mut self) -> Option<(SourceId, Timestamp)> {
        loop {
            if let Some(open) = &mut self.current {
                self.line.clear();
                match open.reader.read_until(b'\n', &mut self.line) {
                    Ok(0) => self.current = None,
                    Ok(_) => return Some((open.file.source.clone(), open.file.hour)),
                    Err(error) => {
                        let path = open.file.path.clone();
                        self.stats.incomplete.push((path, error.to_string()));
                        self.current = None;
                    }
                }
                continue;
            }
            let file = self.pending.next()?;
            match File::open(&file.path) {
                Ok(handle) => {
                    self.stats.files += 1;
                    let reader = BufReader::new(MultiGzDecoder::new(handle));
                    self.current = Some(Open { file, reader });
                }
                Err(error) => self.stats.incomplete.push((file.path, error.to_string())),
            }
        }
    }
}

impl Iterator for Scan {
    type Item = Record;

    fn next(&mut self) -> Option<Record> {
        loop {
            let (source, hour) = self.next_line()?;
            if self.line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            self.stats.lines += 1;
            let Ok(Value::Object(fields)) = serde_json::from_slice(&self.line) else {
                self.stats.bad_lines += 1;
                continue;
            };
            let time = received_at(&fields).unwrap_or(hour);
            if self.query.matches(time, &fields) {
                self.stats.matched += 1;
                return Some(Record {
                    source,
                    time,
                    fields,
                });
            }
        }
    }
}

fn received_at(fields: &Map<String, Value>) -> Option<Timestamp> {
    let text = fields.get(RECEIVED_AT)?.as_str()?;
    let time = DateTime::parse_from_rfc3339(text).ok()?;
    Some(Timestamp(time.timestamp()))
}
