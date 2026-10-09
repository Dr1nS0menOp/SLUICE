//! Errors of the archive reader.

use std::path::PathBuf;

/// Why the archive cannot be searched.
///
/// A file that cannot be read completely does not stop a scan: it is reported in
/// [`Stats`](crate::Stats) instead, because the newest hour is always still being written.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    /// The archive directory or one of its subdirectories cannot be listed.
    #[error("cannot read {}: {source}", path.display())]
    Io {
        /// The directory.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A `--where` condition is not `field=value`, `field!=value` or `field~text`.
    #[error("invalid condition {0:?}: expected field=value, field!=value or field~text")]
    Condition(String),
    /// A time is neither RFC 3339 nor a `YYYY-MM-DD` date.
    #[error("invalid time {0:?}: expected RFC 3339 (2026-10-09T17:00:00Z) or a date (2026-10-09)")]
    Time(String),
    /// A replay request failed; the events before it were delivered.
    #[error("replay to {url} failed after {sent} events were sent: {reason}")]
    Replay {
        /// The destination.
        url: String,
        /// Events delivered before the failure.
        sent: u64,
        /// What went wrong.
        reason: String,
    },
}
