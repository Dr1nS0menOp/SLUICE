//! Scanning an archive laid out the way Vector's file sink writes it.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::{Value, json};
use sluice_archive::{Query, Scan, parse_time};
use sluice_core::ids::SourceId;

/// A fresh directory per test, so tests can run in parallel.
fn archive(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("archive-{name}"));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn gzip(lines: &[Value]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    for line in lines {
        writeln!(encoder, "{line}").expect("writing to memory");
    }
    encoder.finish().expect("writing to memory")
}

fn write(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("a relative file path"))
        .expect("creating the directory");
    fs::write(path, bytes).expect("writing the file");
}

fn event(n: u32, at: &str) -> Value {
    json!({"n": n, "EventID": 4624 + n % 2, "timestamp": at})
}

#[test]
fn a_line_budget_bounds_a_search_that_matches_nothing() {
    let root = archive("budget");
    let lines: Vec<Value> = (0..50).map(|n| event(n, "2026-10-09T17:00:00Z")).collect();
    write(&root, "sysmon/2026-10-09/17.ndjson.gz", &gzip(&lines));
    let query = Query {
        conditions: vec!["n=never".parse().expect("a valid condition")],
        ..Query::default()
    };
    let mut scan = Scan::new(&root, query.clone())
        .expect("the archive exists")
        .with_line_budget(10);
    assert_eq!(scan.by_ref().count(), 0);
    assert_eq!(scan.stats().lines, 10);
    assert!(scan.stats().budget_exhausted);

    let mut unbounded = Scan::new(&root, query).expect("the archive exists");
    assert_eq!(unbounded.by_ref().count(), 0);
    assert_eq!(unbounded.stats().lines, 50);
    assert!(!unbounded.stats().budget_exhausted);
}

#[test]
fn selects_by_source_time_and_condition_in_hour_order() {
    let root = archive("select");
    write(
        &root,
        "dns/2026-10-09/17.ndjson.gz",
        &gzip(&[
            event(1, "2026-10-09T17:10:00Z"),
            event(2, "2026-10-09T17:50:00Z"),
        ]),
    );
    write(
        &root,
        "windows-security/2026-10-09/16.ndjson.gz",
        &gzip(&[event(3, "2026-10-09T16:59:00Z")]),
    );
    write(
        &root,
        "windows-security/2026-10-09/17.ndjson.gz",
        &gzip(&[event(4, "2026-10-09T17:20:00Z")]),
    );
    write(&root, "windows-security/2026-10-09/notes.txt", b"ignored");

    let all: Vec<u64> = Scan::new(&root, Query::default())
        .unwrap()
        .map(|r| r.fields["n"].as_u64().unwrap())
        .collect();
    assert_eq!(all, [3, 1, 2, 4], "hour first, then source, then line");

    let query = Query {
        sources: [SourceId::new("windows-security")].into(),
        from: Some(parse_time("2026-10-09T17:00:00Z").unwrap()),
        ..Query::default()
    };
    let picked: Vec<u64> = Scan::new(&root, query)
        .unwrap()
        .map(|r| r.fields["n"].as_u64().unwrap())
        .collect();
    assert_eq!(picked, [4]);

    let query = Query {
        conditions: vec!["EventID=4625".parse().unwrap()],
        to: Some(parse_time("2026-10-09T17:30:00Z").unwrap()),
        ..Query::default()
    };
    let mut scan = Scan::new(&root, query).unwrap();
    let picked: Vec<u64> = scan
        .by_ref()
        .map(|r| r.fields["n"].as_u64().unwrap())
        .collect();
    assert_eq!(picked, [3, 1]);
    assert_eq!(scan.stats().files, 3, "the 16:00 and both 17:00 files");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_file_still_being_written_yields_what_is_readable() {
    let root = archive("truncated");
    let lines: Vec<Value> = (0..200).map(|n| event(n, "2026-10-09T17:00:00Z")).collect();
    let full = gzip(&lines);
    write(&root, "s/2026-10-09/17.ndjson.gz", &full[..full.len() / 2]);
    write(
        &root,
        "s/2026-10-09/18.ndjson.gz",
        &[gzip(&lines[..1]), b"not gzip".to_vec()].concat(),
    );

    let mut scan = Scan::new(&root, Query::default()).unwrap();
    let read = scan.by_ref().count();
    assert!(read > 0 && read < 201, "{read}");
    assert_eq!(scan.stats().incomplete.len(), 2);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn bad_lines_are_counted_and_events_without_a_receive_time_use_their_hour() {
    let root = archive("lines");
    let mut bytes = gzip(&[json!({"a": 1}), json!([1, 2])]);
    bytes.extend(gzip(&[json!({"a": 2})]));
    write(&root, "s/2026-10-09/05.ndjson.gz", &bytes);

    let mut scan = Scan::new(&root, Query::default()).unwrap();
    let records: Vec<_> = scan.by_ref().collect();
    assert_eq!(records.len(), 2, "both gzip members are read");
    assert_eq!(records[0].time, parse_time("2026-10-09T05:00:00Z").unwrap());
    assert_eq!(scan.stats().bad_lines, 1);
    assert_eq!(scan.stats().incomplete.len(), 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_missing_archive_is_an_error() {
    assert!(Scan::new(&archive("missing"), Query::default()).is_err());
}
