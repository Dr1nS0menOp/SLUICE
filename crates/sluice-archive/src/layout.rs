//! Finding the archive files a query can match.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::NaiveDate;
use sluice_core::event::Timestamp;
use sluice_core::ids::SourceId;

use crate::error::ArchiveError;
use crate::query::{HOUR, Query};

/// One archive file: the events of one source in one UTC hour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveFile {
    /// The source.
    pub source: SourceId,
    /// Start of the hour.
    pub hour: Timestamp,
    /// The file.
    pub path: PathBuf,
}

/// Lists the files under `root` whose source and hour `query` selects, oldest hour first, then by
/// source. Names outside the archive layout are skipped, so other files in the directory are
/// harmless.
///
/// # Errors
///
/// Returns [`ArchiveError::Io`] if a directory cannot be listed.
pub fn files(root: &Path, query: &Query) -> Result<Vec<ArchiveFile>, ArchiveError> {
    let mut found = Vec::new();
    for (name, source_dir) in subdirectories(root)? {
        let source = SourceId::new(name);
        if !query.wants_source(&source) {
            continue;
        }
        for (date, date_dir) in subdirectories(&source_dir)? {
            let Ok(date) = NaiveDate::parse_from_str(&date, "%Y-%m-%d") else {
                continue;
            };
            let midnight = date.and_hms_opt(0, 0, 0).map(|t| t.and_utc().timestamp());
            let Some(midnight) = midnight else { continue };
            for (hour, path) in hour_files(&date_dir)? {
                let hour = Timestamp(midnight + hour * HOUR);
                if query.overlaps_hour(hour) {
                    found.push(ArchiveFile {
                        source: source.clone(),
                        hour,
                        path,
                    });
                }
            }
        }
    }
    found.sort_by(|a, b| (a.hour, &a.source).cmp(&(b.hour, &b.source)));
    Ok(found)
}

fn entries(dir: &Path) -> Result<Vec<fs::DirEntry>, ArchiveError> {
    let io = |source| ArchiveError::Io {
        path: dir.to_owned(),
        source,
    };
    fs::read_dir(dir)
        .map_err(io)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io)
}

fn subdirectories(dir: &Path) -> Result<Vec<(String, PathBuf)>, ArchiveError> {
    Ok(entries(dir)?
        .into_iter()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| Some((e.file_name().into_string().ok()?, e.path())))
        .collect())
}

/// `HH.ndjson.gz` files with an hour from 00 to 23.
fn hour_files(dir: &Path) -> Result<Vec<(i64, PathBuf)>, ArchiveError> {
    Ok(entries(dir)?
        .into_iter()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let hour: i64 = name.strip_suffix(".ndjson.gz")?.parse().ok()?;
            (0..24).contains(&hour).then(|| (hour, e.path()))
        })
        .collect())
}
