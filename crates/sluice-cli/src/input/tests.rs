use std::path::PathBuf;

use super::*;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sluice-input-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn source(id: &str) -> Source {
    serde_json::from_value(serde_json::json!({
        "id": id, "logsource": {"product": "linux"}, "format": {"kind": "json"}
    }))
    .unwrap()
}

#[test]
fn a_sources_file_without_sources_or_with_unknown_keys_is_refused() {
    let dir = scratch("sources");
    let path = dir.join("sources.yaml");
    fs::write(&path, "sources: []\n").unwrap();
    assert!(sources(&path).is_err());
    fs::write(&path, "sources: []\nextra: 1\n").unwrap();
    assert!(sources(&path).is_err());
    fs::write(
        &path,
        "sources:\n  - id: s\n    logsource: {product: linux}\n    format: {kind: json}\n",
    )
    .unwrap();
    assert_eq!(sources(&path).unwrap().len(), 1);
    assert!(sources(&dir.join("missing.yaml")).is_err());
}

#[test]
fn events_are_ordered_by_time_and_numbered_from_zero() {
    let dir = scratch("order");
    fs::write(
        dir.join("a.ndjson"),
        "{\"@timestamp\":\"2026-10-14T00:00:02Z\",\"n\":1}\n\n   \n{\"n\":2}\n",
    )
    .unwrap();
    fs::write(
        dir.join("b.ndjson"),
        "{\"@timestamp\":\"2026-10-14T00:00:01+00:00\",\"n\":3}\n{\"@timestamp\":12,\"n\":4}\n",
    )
    .unwrap();
    let events = events(&dir, &[source("a"), source("b")]).unwrap();
    let order: Vec<_> = events.iter().map(|e| e.fields["n"].clone()).collect();
    assert_eq!(
        order,
        [2, 4, 3, 1],
        "untimed and non-string times first, in file order"
    );
    let ids: Vec<_> = events.iter().map(|e| e.id.0).collect();
    assert_eq!(ids, [0, 1, 2, 3]);
    assert_eq!(events[0].source, source("a").id);
}

#[test]
fn a_byte_order_mark_and_crlf_line_ends_are_not_part_of_a_record() {
    let dir = scratch("bom");
    fs::write(dir.join("s.ndjson"), "\u{feff}{\"n\":1}\r\n{\"n\":2}\r\n").unwrap();
    let events = events(&dir, &[source("s")]).unwrap();
    assert_eq!(events.len(), 2);
}

#[test]
fn a_line_that_is_not_a_json_object_names_its_file_and_line() {
    let dir = scratch("bad");
    fs::write(dir.join("s.ndjson"), "{\"n\":1}\n[1,2]\n").unwrap();
    let error = format!("{:#}", events(&dir, &[source("s")]).unwrap_err());
    assert!(error.contains("s.ndjson:2"), "{error}");
    fs::write(dir.join("s.ndjson"), "{\"n\":1\n").unwrap();
    let error = format!("{:#}", events(&dir, &[source("s")]).unwrap_err());
    assert!(error.contains("s.ndjson:1: not JSON"), "{error}");
}

#[test]
fn a_missing_sample_file_is_an_error() {
    let dir = scratch("missing");
    assert!(events(&dir, &[source("absent")]).is_err());
}

#[test]
fn files_are_found_recursively_sorted_and_by_extension_in_any_case() {
    let dir = scratch("files");
    fs::create_dir_all(dir.join("b/c")).unwrap();
    fs::write(dir.join("b/c/2.xml"), "two").unwrap();
    fs::write(dir.join("1.XML"), "one").unwrap();
    fs::write(dir.join("notes.txt"), "no").unwrap();
    fs::write(dir.join("xml"), "no extension").unwrap();
    let found = files(&dir, &["xml"]).unwrap();
    let texts: Vec<_> = found.iter().map(|(_, t)| t.as_str()).collect();
    assert_eq!(texts, ["one", "two"]);
}

#[test]
fn a_symbolic_link_loop_ends_and_each_directory_is_read_once() {
    let dir = scratch("loop");
    fs::create_dir_all(dir.join("rules")).unwrap();
    fs::write(dir.join("rules/r.xml"), "rule").unwrap();
    std::os::unix::fs::symlink(&dir, dir.join("rules/back")).unwrap();
    std::os::unix::fs::symlink(dir.join("rules"), dir.join("again")).unwrap();
    let found = files(&dir, &["xml"]).unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
}

#[test]
fn a_missing_directory_is_an_error() {
    assert!(files(&scratch("gone").join("nope"), &["xml"]).is_err());
}

#[test]
fn sigma_pipeline_specs_need_a_known_schema_and_an_equals_sign() {
    for bad in ["ecs", "nonsense=ecs_windows", "ecs=no_such_pipeline"] {
        assert!(sigma_pipelines(&[bad.to_owned()]).is_err(), "{bad}");
    }
    assert_eq!(sigma_pipelines(&[]).unwrap().len(), 0);
}

#[test]
fn without_rules_there_is_no_wazuh_or_sentinel_rule_set() {
    assert!(wazuh(None, None).unwrap().is_none());
    assert!(sentinel(None).unwrap().is_none());
}
