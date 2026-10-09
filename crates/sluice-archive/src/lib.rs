//! Reading the full-fidelity archive that `sluice up` has Vector write (safety contract rule 2).
//!
//! The archive is plain gzip NDJSON, one file per source and UTC hour:
//!
//! ```text
//! <archive_dir>/<source>/<YYYY-MM-DD>/<HH>.ndjson.gz
//! ```
//!
//! Every event is stored exactly as Vector received it, before any reduction. [`Scan`] streams
//! the events a [`Query`] selects, reading only the files whose source and hour can match, so
//! memory use is flat whatever the archive size. `sluice search` prints them and `sluice replay`
//! sends them on to a destination.
//!
//! Reading is deliberately simple: no index and no query engine. ADR 0006 explains why.

mod error;
mod layout;
mod query;
mod replay;
mod scan;

pub use crate::error::ArchiveError;
pub use crate::layout::{ArchiveFile, files};
pub use crate::query::{Condition, Op, Query, parse_time};
pub use crate::replay::replay;
pub use crate::scan::{Record, Scan, Stats};
