//! The `sluice` binary end to end: `demo` writes a sample and results, and `analyze` on that
//! sample with the same rules produces the same data plane.

use std::path::Path;
use std::process::Command;

fn sluice(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_sluice"))
        .args(args)
        .output()
        .expect("sluice runs");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "sluice {args:?} failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn demo_then_analyze_agree() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli");
    let _ = std::fs::remove_dir_all(&root);
    let demo = root.join("demo");
    let again = root.join("again");

    let summary = sluice(&["demo", "--out", demo.to_str().unwrap(), "--scale", "5"]);
    assert!(summary.contains("✓ no detection changed"), "{summary}");
    // Demo sources leave the category unknown, so category rules apply: Sluice says so.
    assert!(summary.contains("add `complete: true`"), "{summary}");
    assert!(read(&demo.join("report.html")).contains("Sluice report"));

    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/rules/sigma");
    sluice(&[
        "analyze",
        "--input",
        demo.join("samples").to_str().unwrap(),
        "--sources",
        demo.join("sluice.yaml").to_str().unwrap(),
        "--rules",
        rules.to_str().unwrap(),
        "--out",
        again.to_str().unwrap(),
        // The demo's own rules: complete, as the demo takes them to be.
        "--rules-complete",
    ]);
    // Same events, rules and recipes: the same VRL. (Paths in the config differ by `--out`.)
    let programs = |dir: &Path| {
        read(&dir.join("vector.yaml"))
            .lines()
            .filter(|l| !l.contains(dir.to_str().unwrap()))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(programs(&demo), programs(&again));
}

#[test]
fn c3_analyze_without_a_complete_inventory_summarizes_nothing() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-partial");
    let _ = std::fs::remove_dir_all(&root);
    let demo = root.join("demo");
    sluice(&["demo", "--out", demo.to_str().unwrap(), "--scale", "5"]);
    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/rules/sigma");
    let partial = root.join("partial");
    let summary = sluice(&[
        "analyze",
        "--input",
        demo.join("samples").to_str().unwrap(),
        "--sources",
        demo.join("sluice.yaml").to_str().unwrap(),
        "--rules",
        rules.to_str().unwrap(),
        "--out",
        partial.to_str().unwrap(),
    ]);
    assert!(summary.contains("0 events summarized"), "{summary}");
    assert!(read(&partial.join("report.html")).contains("the rules are not known to be complete"));
}

#[test]
fn c5_prove_passes_the_generated_config_and_fails_one_that_loses_alerts() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-prove");
    let _ = std::fs::remove_dir_all(&root);
    let demo = root.join("demo");
    sluice(&["demo", "--out", demo.to_str().unwrap(), "--scale", "5"]);
    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/rules/sigma");
    let prove = |config: &Path| {
        Command::new(env!("CARGO_BIN_EXE_sluice"))
            .args([
                "prove",
                "--config",
                config.to_str().unwrap(),
                "--input",
                demo.join("samples").to_str().unwrap(),
                "--sources",
                demo.join("sluice.yaml").to_str().unwrap(),
                "--rules",
                rules.to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("sluice runs")
    };

    let passed = prove(&demo.join("vector.yaml"));
    let stdout = String::from_utf8_lossy(&passed.stdout);
    assert!(
        passed.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&passed.stderr)
    );
    let summary: serde_json::Value = serde_json::from_str(&stdout).expect("JSON");
    assert_eq!(summary["holds"], true);
    assert!(
        summary["alerts_full"].as_u64().unwrap() > 0,
        "the demo plants attacks"
    );
    assert!(summary["bytes_out"].as_u64() < summary["bytes_in"].as_u64());

    // The same configuration, with one program edited to summarize every event.
    let mut config: serde_json::Value =
        serde_yaml_ng::from_str(&read(&demo.join("vector.yaml"))).unwrap();
    let program = &mut config["transforms"]["sluice_windows_security"]["source"];
    *program = format!(
        "{}\n%sluice.route = \"summarize\"\n",
        program.as_str().unwrap()
    )
    .into();
    let broken = root.join("broken.yaml");
    std::fs::write(&broken, serde_yaml_ng::to_string(&config).unwrap()).unwrap();
    let failed = prove(&broken);
    assert_eq!(failed.status.code(), Some(1));
    let summary: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&failed.stdout)).expect("JSON");
    assert_eq!(summary["holds"], false);
    assert_ne!(summary["missing"], serde_json::json!([]));
}

#[test]
fn c5_prove_fails_an_empty_proof_unless_told_otherwise() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-empty-proof");
    let _ = std::fs::remove_dir_all(&root);
    let demo = root.join("demo");
    sluice(&["demo", "--out", demo.to_str().unwrap(), "--scale", "5"]);
    // A rule no event of the sample can match: the proof compares two empty alert sets.
    let rules = root.join("rules");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("never.yml"),
        "title: Never\nid: 00000000-0000-4000-8000-000000000999\nlogsource: { product: windows }\n\
         detection:\n  selection: { EventID: 999999 }\n  condition: selection\n",
    )
    .unwrap();
    let prove = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sluice"))
            .arg("prove")
            .arg("--config")
            .arg(demo.join("vector.yaml"))
            .arg("--input")
            .arg(demo.join("samples"))
            .arg("--sources")
            .arg(demo.join("sluice.yaml"))
            .arg("--rules")
            .arg(&rules)
            .args(extra)
            .output()
            .expect("sluice runs")
    };
    let failed = prove(&[]);
    assert_eq!(failed.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&failed.stderr).contains("raised no alerts"));
    let allowed = prove(&["--allow-no-alerts"]);
    assert!(allowed.status.success());
    assert!(String::from_utf8_lossy(&allowed.stdout).contains("raised no alerts"));
}

#[test]
fn rules_requirements_include_filter_fields_and_correlations() {
    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/rules/sigma");
    let out = sluice(&["rules", "requirements", "--rules", rules.to_str().unwrap()]);
    let requirements: serde_json::Value = serde_json::from_str(&out).expect("JSON");
    let failed_logon = requirements
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["rule"] == "sigma:5c0f3b1e-8f0a-4d7e-9a61-2d4b8c1e7f01")
        .expect("the failed-logon rule");
    assert_eq!(
        failed_logon["stateful"], true,
        "its correlation is folded in"
    );
}

#[test]
fn recipes_lists_the_built_in_recipes() {
    let listing = sluice(&["recipes"]);
    assert!(listing.contains("microsoft/windows/sysmon/image-loaded"));
}

#[test]
fn exported_recipes_can_be_edited_and_used() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-export");
    let _ = std::fs::remove_dir_all(&root);
    let export = root.join("recipes");
    sluice(&["recipes", "export", "--out", export.to_str().unwrap()]);
    assert!(read(&export.join("recipe.schema.json")).contains("Sluice recipe"));
    let recipe = export.join("microsoft/windows/sysmon/image-loaded.yaml");
    assert!(read(&recipe).contains("id: microsoft/windows/sysmon/image-loaded"));

    let demo = root.join("demo");
    sluice(&["demo", "--out", demo.to_str().unwrap(), "--scale", "1"]);
    sluice(&[
        "analyze",
        "--input",
        demo.join("samples").to_str().unwrap(),
        "--sources",
        demo.join("sluice.yaml").to_str().unwrap(),
        "--recipes",
        export.to_str().unwrap(),
        "--out",
        root.join("again").to_str().unwrap(),
    ]);

    let again = Command::new(env!("CARGO_BIN_EXE_sluice"))
        .args(["recipes", "export", "--out"])
        .arg(&export)
        .output()
        .expect("sluice runs");
    assert!(!again.status.success(), "export never overwrites");
}

#[test]
fn analyze_reports_missing_input_clearly() {
    let output = Command::new(env!("CARGO_BIN_EXE_sluice"))
        .args([
            "analyze",
            "--input",
            "/nonexistent",
            "--sources",
            "/nonexistent/sluice.yaml",
        ])
        .output()
        .expect("sluice runs");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("error: reading /nonexistent/sluice.yaml"),
        "{stderr}"
    );
}

#[test]
fn unknown_llm_is_rejected_with_the_accepted_forms() {
    let output = Command::new(env!("CARGO_BIN_EXE_sluice"))
        .args(["demo", "--scale", "1", "--llm", "gpt", "--out"])
        .arg(Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-llm"))
        .output()
        .expect("sluice runs");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ollama:MODEL"), "{stderr}");
}

#[test]
fn search_prints_matching_archived_events() {
    use std::io::Write;

    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-archive");
    let _ = std::fs::remove_dir_all(&root);
    let dir = root.join("windows-security/2026-10-09");
    std::fs::create_dir_all(&dir).expect("creating the archive");
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    for id in [4624, 4625, 4624] {
        writeln!(
            gz,
            r#"{{"EventID":{id},"timestamp":"2026-10-09T17:05:00Z"}}"#
        )
        .expect("gzip");
    }
    std::fs::write(dir.join("17.ndjson.gz"), gz.finish().expect("gzip")).expect("writing");

    let archive = root.to_str().unwrap();
    let count = sluice(&[
        "search",
        "--archive",
        archive,
        "--where",
        "EventID=4624",
        "--count",
    ]);
    assert_eq!(count, "2\n");
    let events = sluice(&["search", "--archive", archive, "--where", "EventID!=4624"]);
    assert_eq!(
        events,
        "{\"EventID\":4625,\"timestamp\":\"2026-10-09T17:05:00Z\"}\n"
    );
    let none = sluice(&[
        "search",
        "--archive",
        archive,
        "--from",
        "2026-10-10",
        "--count",
    ]);
    assert_eq!(none, "0\n");
}

#[test]
fn connect_prints_a_destination_without_secrets() {
    let out = sluice(&["connect", "splunk", "--endpoint", "https://splunk:8088"]);
    assert!(out.contains("one file each in /run/secrets/siem"), "{out}");
    let yaml: serde_yaml_ng::Value = serde_yaml_ng::from_str(&out).expect("valid YAML");
    let sink = &yaml["destinations"]["splunk"];
    assert_eq!(sink["type"], "splunk_hec_logs");
    assert_eq!(sink["endpoint"], "https://splunk:8088");
    assert_eq!(sink["default_token"], "SECRET[siem.splunk_hec_token]");
    assert_eq!(yaml["vector_secrets"]["siem"]["type"], "directory");
}

#[test]
fn up_check_validates_without_starting() {
    let config = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/up/sluice-up.yaml");
    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/rules/sigma");
    let vector = sluice(&[
        "up",
        "--config",
        config.to_str().unwrap(),
        "--rules",
        rules.to_str().unwrap(),
        "--check",
    ]);
    assert!(vector.contains("sluice_windows_security_tap"), "{vector}");

    // The container example listens beyond loopback: without a token it is refused.
    let docker = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/docker/sluice.yaml");
    let output = Command::new(env!("CARGO_BIN_EXE_sluice"))
        .args(["up", "--check", "--config"])
        .arg(&docker)
        .env_remove("SLUICE_CONTROL_TOKEN")
        .output()
        .expect("sluice runs");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to start"));
}
