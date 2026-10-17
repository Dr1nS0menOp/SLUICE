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
fn sigma_pipelines_are_built_in_names_or_files() {
    let dir = scratch("pipeline");
    let file = dir.join("snake.yml");
    fs::write(
        &file,
        "name: snake\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      EventID: event_id\n",
    )
    .unwrap();
    let specs = [
        "ecs=ecs_windows".to_owned(),
        format!(" cim ={}", file.display()),
    ];
    let pipelines = sigma_pipelines(&specs).unwrap();
    let names: Vec<_> = pipelines
        .iter()
        .map(|p| (p.schema(), p.name().to_owned()))
        .collect();
    assert_eq!(
        names,
        [
            (sluice_core::schema::Schema::Ecs, "ecs_windows".to_owned()),
            (sluice_core::schema::Schema::Cim, file.display().to_string()),
        ]
    );
}

#[test]
fn wazuh_rules_load_with_or_without_decoders() {
    let dir = scratch("wazuh");
    fs::create_dir_all(dir.join("rules")).unwrap();
    fs::create_dir_all(dir.join("decoders")).unwrap();
    fs::write(
        dir.join("rules/local.xml"),
        "<group name=\"t,\"><rule id=\"1\" level=\"3\"><decoded_as>sshd</decoded_as></rule></group>",
    )
    .unwrap();
    fs::write(
        dir.join("decoders/sshd.xml"),
        "<decoder name=\"sshd\"><program_name>^sshd</program_name></decoder>",
    )
    .unwrap();
    let bounded = wazuh(Some(&dir.join("rules")), Some(&dir.join("decoders")))
        .unwrap()
        .unwrap();
    assert!(!bounded.requirements()[0].prefilter.is_always());
    let unbounded = wazuh(Some(&dir.join("rules")), None).unwrap().unwrap();
    assert!(unbounded.requirements()[0].prefilter.is_always());
    assert!(wazuh(Some(&dir.join("missing")), None).is_err());
}

#[test]
fn a_fetched_elastic_inventory_reads_its_rules_not_its_manifest() {
    let dir = scratch("elastic");
    fs::write(
        dir.join("rules.ndjson"),
        "{\"rule_id\":\"a\",\"type\":\"query\",\"query\":\"user.name : root\"}\n",
    )
    .unwrap();
    fs::write(
        dir.join(sluice_core::inventory::MANIFEST_FILE),
        "{\"system\":\"elastic\",\"from\":\"k\",\"fetched_at\":\"t\",\"complete\":true,\"counts\":{}}\n",
    )
    .unwrap();
    let rules = elastic(Some(&dir)).unwrap().unwrap();
    assert_eq!(rules.problems(), &[] as &[String]);
    assert_eq!(rules.requirements().len(), 1);
}

#[test]
fn fail_closed_every_rule_file_but_the_fetch_manifest_is_read() {
    let dir = scratch("manifest-like");
    let rule = "{\"rule_id\":\"a\",\"type\":\"query\",\"query\":\"user.name : root\"}\n";
    fs::write(dir.join("rules-inventory.json"), rule).unwrap();
    fs::create_dir_all(dir.join("team")).unwrap();
    fs::write(
        dir.join("team").join(sluice_core::inventory::MANIFEST_FILE),
        rule.replace("\"a\"", "\"b\""),
    )
    .unwrap();
    let rules = elastic(Some(&dir)).unwrap().unwrap();
    assert_eq!(rules.requirements().len(), 2, "{:?}", rules.problems());
}

#[test]
fn sentinel_rules_load_and_keep_their_problems() {
    let dir = scratch("sentinel");
    fs::write(
        dir.join("ok.yaml"),
        "id: a\nquery: SecurityEvent | where EventID == 1\n",
    )
    .unwrap();
    fs::write(dir.join("broken.yml"), "id: [unclosed\n").unwrap();
    let rules = sentinel(Some(&dir)).unwrap().unwrap();
    assert_eq!(rules.problems().len(), 1, "{:?}", rules.problems());
    // The unreadable file stays a rule that may read anything: fail closed.
    assert_eq!(rules.requirements().len(), 2);
    assert!(
        rules
            .requirements()
            .iter()
            .any(|r| r.fields == sluice_core::rules::RequiredFields::Unknown)
    );
}

#[test]
fn sentinel_table_specs_are_checked_before_the_emulator_is_asked() {
    let rules = sluice_rules::SentinelRules::parse(std::iter::empty::<(&str, &str)>());
    // An address nothing listens on: the spec errors must come first.
    let url = "http://127.0.0.1:9";
    let error = format!(
        "{:#}",
        kusto(url, &rules, &["win".to_owned()], &[]).unwrap_err()
    );
    assert!(error.contains("expected SOURCE=TABLE"), "{error}");
    let error = format!(
        "{:#}",
        kusto(url, &rules, &["win=Nope".to_owned()], &[]).unwrap_err()
    );
    assert!(error.contains("cannot load table `Nope`"), "{error}");
    let error = format!(
        "{:#}",
        kusto(url, &rules, &["win = SecurityEvent".to_owned()], &[]).unwrap_err()
    );
    assert!(
        error.contains("connecting to the Kusto emulator"),
        "{error}"
    );
}

#[test]
fn without_rules_there_is_no_wazuh_or_sentinel_rule_set() {
    assert!(wazuh(None, None).unwrap().is_none());
    assert!(sentinel(None).unwrap().is_none());
}
