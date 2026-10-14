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

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sluice-layout-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn touch(root: &Path, relative: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"").unwrap();
    }

    /// 2026-10-14T00:00:00Z.
    const DAY: i64 = 1_791_936_000;

    #[test]
    fn only_names_in_the_layout_are_listed_oldest_hour_first_then_by_source() {
        let root = scratch("layout");
        for file in [
            "b/2026-10-14/01.ndjson.gz",
            "a/2026-10-14/01.ndjson.gz",
            "a/2026-10-14/00.ndjson.gz",
            "a/2026-10-14/24.ndjson.gz",
            "a/2026-10-14/-1.ndjson.gz",
            "a/2026-10-14/xx.ndjson.gz",
            "a/2026-10-14/02.ndjson",
            "a/2026-13-01/00.ndjson.gz",
            "a/not-a-date/00.ndjson.gz",
            "loose.ndjson.gz",
        ] {
            touch(&root, file);
        }
        let found = files(&root, &Query::default()).unwrap();
        let listed: Vec<(i64, &str)> = found
            .iter()
            .map(|f| (f.hour.0 - DAY, f.source.as_str()))
            .collect();
        assert_eq!(listed, [(0, "a"), (3_600, "a"), (3_600, "b")]);
    }

    #[test]
    fn the_query_selects_sources_and_hours() {
        let root = scratch("select");
        for file in [
            "a/2026-10-14/00.ndjson.gz",
            "a/2026-10-14/05.ndjson.gz",
            "b/2026-10-14/05.ndjson.gz",
        ] {
            touch(&root, file);
        }
        let query = Query {
            sources: [SourceId::new("a")].into(),
            from: Some(Timestamp(DAY + 5 * HOUR + 1_800)),
            ..Query::default()
        };
        let found = files(&root, &query).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].hour, Timestamp(DAY + 5 * HOUR));
        assert_eq!(found[0].source, SourceId::new("a"));
    }

    #[test]
    fn a_missing_root_is_an_error_and_an_empty_one_lists_nothing() {
        let root = scratch("empty");
        assert_eq!(files(&root, &Query::default()).unwrap().len(), 0);
        assert!(files(&root.join("nope"), &Query::default()).is_err());
    }
}
