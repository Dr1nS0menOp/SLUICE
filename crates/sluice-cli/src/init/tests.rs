use std::path::PathBuf;

use serde_json::json;
use sluice_core::source::SourceFormat;

use super::*;

/// A sample directory of its own, with `files` as `(source id, records)`.
fn sample(name: &str, files: &[(&str, Vec<Value>)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sluice-init-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the directory is created");
    for (id, records) in files {
        let lines: Vec<String> = records.iter().map(Value::to_string).collect();
        std::fs::write(dir.join(format!("{id}.ndjson")), lines.join("\n")).expect("written");
    }
    dir
}

fn nginx_lines() -> Vec<Value> {
    (0..50)
        .map(|n| {
            json!({"host": {"name": "web01"}, "log": {"file": {"path": "/var/log/nginx/access.log"}}, "message": format!(
                "10.0.0.{n} - - [10/Oct/2026:08:00:00 +0000] \"GET /p{n} HTTP/1.1\" 200 5 \"-\" \"curl\""
            )})
        })
        .collect()
}

fn security_events() -> Vec<Value> {
    (0..50)
        .map(|n| {
            json!({"EventID": 4624, "Channel": "Security", "Computer": "ws1",
                   "TargetUserName": format!("u{n}"), "SubjectUserName": "-"})
        })
        .collect()
}

#[test]
fn a_text_source_gets_the_pack_its_lines_fit_and_the_pack_s_log_source() {
    let book = ParserBook::embedded().expect("packs");
    let dir = sample("nginx", &[("web", nginx_lines())]);
    let proposal = propose(&dir.join("web.ndjson"), &book).expect("proposed");
    assert_eq!(
        proposal.text,
        Some(("message".to_owned(), Some("nginx/combined".to_owned())))
    );
    assert_eq!(proposal.logsource.product.as_deref(), Some("nginx"));
    assert_eq!(proposal.logsource.category.as_deref(), Some("webserver"));
    assert_eq!(proposal.schema, Schema::Sigma);
}

#[test]
fn a_windows_source_gets_its_channel_s_log_source_and_the_convention_its_names_follow() {
    let book = ParserBook::embedded().expect("packs");
    let dir = sample("windows", &[("sec", security_events())]);
    let proposal = propose(&dir.join("sec.ndjson"), &book).expect("proposed");
    assert_eq!(proposal.text, None);
    assert_eq!(proposal.logsource.product.as_deref(), Some("windows"));
    assert_eq!(proposal.logsource.service.as_deref(), Some("security"));
    assert_eq!(proposal.schema, Schema::Sigma);
    assert!(
        proposal
            .notes
            .iter()
            .any(|n| n.contains("`Channel` says Security"))
    );
}

#[test]
fn records_that_say_nothing_get_an_empty_log_source_and_no_schema_with_a_note_why() {
    let book = ParserBook::embedded().expect("packs");
    let unknown: Vec<Value> = (0..20).map(|n| json!({"a": n, "b": "x"})).collect();
    let dir = sample("unknown", &[("app", unknown)]);
    let proposal = propose(&dir.join("app.ndjson"), &book).expect("proposed");
    assert_eq!(proposal.logsource, LogSource::default());
    assert_eq!(proposal.schema, Schema::Undeclared);
    assert!(
        proposal
            .notes
            .iter()
            .any(|n| n.contains("set `schema` yourself"))
    );
}

#[test]
fn what_init_writes_is_a_sources_file_analyze_reads_with_its_packs_resolved() {
    let dir = sample(
        "roundtrip",
        &[("sec", security_events()), ("web", nginx_lines())],
    );
    let out = dir.join("sources.yaml");
    init(&InitArgs {
        input: dir.clone(),
        out: out.clone(),
    })
    .expect("init runs");
    let sources = crate::input::sources(&out).expect("the file reads back");
    assert_eq!(sources.len(), 2);
    let web = sources
        .iter()
        .find(|s| s.id.as_str() == "web")
        .expect("web");
    assert!(matches!(web.format, SourceFormat::Text { .. }));
    assert_eq!(
        web.format.parser().map(|p| p.id.as_str()),
        Some("nginx/combined")
    );
    let error = init(&InitArgs { input: dir, out }).expect_err("never overwrites");
    assert!(error.to_string().contains("exists"), "{error}");
}

#[test]
fn a_mixed_auth_log_gets_the_pack_that_reads_all_its_kinds_of_line() {
    let book = ParserBook::embedded().expect("packs");
    let lines = [
        "Oct 10 08:00:02 b sshd[1]: Accepted publickey for alice from 10.0.0.1 port 4 ssh2",
        "Oct 10 08:00:02 b sudo[2]: alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
        "Oct 10 08:00:02 b CRON[3]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
    ];
    let records: Vec<Value> = lines
        .iter()
        .cycle()
        .take(30)
        .map(|l| json!({"message": l}))
        .collect();
    let dir = sample("auth", &[("auth", records)]);
    let proposal = propose(&dir.join("auth.ndjson"), &book).expect("proposed");
    assert_eq!(
        proposal.text.and_then(|(_, p)| p).as_deref(),
        Some("linux/auth")
    );
}
