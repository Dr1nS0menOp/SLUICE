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
    /// The line budget ([`Scan::with_line_budget`]) ran out before the selection was read to the
    /// end, so more events may match.
    pub budget_exhausted: bool,
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
    budget: Option<u64>,
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
            budget: None,
        })
    }

    /// Stops the scan after reading `lines` lines, matching or not, so a search over a large
    /// archive ends in bounded time. [`Stats::budget_exhausted`] then tells the caller.
    #[must_use]
    pub fn with_line_budget(mut self, lines: u64) -> Self {
        self.budget = Some(lines);
        self
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
            if self.budget.is_some_and(|budget| self.stats.lines >= budget) {
                self.stats.budget_exhausted = true;
                return None;
            }
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    /// A fresh archive root for one test.
    fn root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sluice-scan-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Writes `lines` gzipped as `<root>/<source>/<date>/<hour>.ndjson.gz`.
    fn archive(root: &Path, source: &str, date: &str, hour: &str, content: &[u8]) -> PathBuf {
        let dir = root.join(source).join(date);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{hour}.ndjson.gz"));
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(content).unwrap();
        std::fs::write(&path, encoder.finish().unwrap()).unwrap();
        path
    }

    fn query() -> Query {
        Query::default()
    }

    #[test]
    fn blank_and_broken_lines_are_counted_not_fatal() {
        let dir = root("lines");
        archive(
            &dir,
            "s",
            "2026-10-14",
            "08",
            b"{\"a\":1}\n\n   \nnot json\n[1]\n{\"b\":2}",
        );
        let mut scan = Scan::new(&dir, query()).unwrap();
        let found: Vec<Record> = scan.by_ref().collect();
        assert_eq!(found.len(), 2, "the last line needs no newline");
        assert_eq!(scan.stats().lines, 4, "blank lines do not count");
        assert_eq!(scan.stats().bad_lines, 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_truncated_file_yields_what_it_holds_and_is_reported() {
        let dir = root("truncated");
        let path = archive(
            &dir,
            "s",
            "2026-10-14",
            "08",
            "{\"a\":1}\n".repeat(1_000).as_bytes(),
        );
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
        let mut scan = Scan::new(&dir, query()).unwrap();
        let found = scan.by_ref().count();
        assert!(found > 0 && found < 1_000, "{found}");
        assert_eq!(scan.stats().incomplete.len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_line_budget_stops_the_scan_and_says_so() {
        let dir = root("budget");
        archive(
            &dir,
            "s",
            "2026-10-14",
            "08",
            "{\"a\":1}\n".repeat(10).as_bytes(),
        );
        let mut scan = Scan::new(&dir, query()).unwrap().with_line_budget(3);
        assert_eq!(scan.by_ref().count(), 3);
        assert!(scan.stats().budget_exhausted);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn time_comes_from_the_received_timestamp_else_the_files_hour() {
        let dir = root("time");
        archive(
            &dir,
            "s",
            "2026-10-14",
            "08",
            b"{\"timestamp\":\"2026-10-14T08:30:00Z\"}\n{\"timestamp\":\"yesterday\"}\n{}\n",
        );
        let times: Vec<i64> = Scan::new(&dir, query())
            .unwrap()
            .map(|r| r.time.0)
            .collect();
        let hour = chrono::DateTime::parse_from_rfc3339("2026-10-14T08:00:00Z")
            .unwrap()
            .timestamp();
        assert_eq!(times, [hour + 1_800, hour, hour]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn files_are_read_oldest_hour_first_then_by_source() {
        let dir = root("order");
        archive(&dir, "b", "2026-10-14", "09", b"{\"n\":3}\n");
        archive(&dir, "b", "2026-10-14", "08", b"{\"n\":1}\n");
        archive(&dir, "a", "2026-10-14", "09", b"{\"n\":2}\n");
        let order: Vec<(String, i64)> = Scan::new(&dir, query())
            .unwrap()
            .map(|r| (r.source.to_string(), r.fields["n"].as_i64().unwrap()))
            .collect();
        assert_eq!(order, [("b".into(), 1), ("a".into(), 2), ("b".into(), 3)]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn names_outside_the_layout_are_skipped() {
        let dir = root("layout");
        archive(&dir, "s", "2026-10-14", "08", b"{\"ok\":1}\n");
        archive(&dir, "s", "2026-13-40", "08", b"{\"bad_date\":1}\n");
        archive(&dir, "s", "2026-10-14", "24", b"{\"bad_hour\":1}\n");
        archive(&dir, "s", "2026-10-14", "xx", b"{\"bad_hour\":1}\n");
        std::fs::write(dir.join("s").join("2026-10-14").join("notes.txt"), "x").unwrap();
        std::fs::write(dir.join("README"), "x").unwrap();
        let found: Vec<Record> = Scan::new(&dir, query()).unwrap().collect();
        assert_eq!(found.len(), 1);
        assert!(found[0].fields.contains_key("ok"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_missing_archive_is_an_error_not_an_empty_answer() {
        assert!(Scan::new(&root("missing"), query()).is_err());
    }
}
