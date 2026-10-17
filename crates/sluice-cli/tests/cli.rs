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
    let plan: serde_json::Value =
        serde_json::from_str(&read(&demo.join("plan.json"))).expect("the plan is JSON");
    assert_eq!(plan["format"], "sluice.plan/1");
    assert_eq!(plan["proof"]["holds"], true);

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

/// Runs `sluice` expecting it to fail; returns what it wrote to stderr.
fn sluice_fails(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_sluice"))
        .args(args)
        .output()
        .expect("sluice runs");
    assert!(!output.status.success(), "sluice {args:?} succeeded");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

#[test]
fn connect_sentinel_derives_a_custom_table_and_its_rule_from_a_sample() {
    let dir = scratch("connect-custom");
    let sample = dir.join("firewall.ndjson");
    std::fs::write(
        &sample,
        "{\"host\":\"fw1\",\"action\":\"deny\",\"bytes\":10}\n\n{\"host\":\"fw2\",\"action\":\"allow\",\"bytes\":20}\n",
    )
    .unwrap();
    let out_dir = dir.join("azure");
    let workspace =
        "/subscriptions/s/resourceGroups/g/providers/Microsoft.OperationalInsights/workspaces/w";
    let out = sluice(&[
        "connect",
        "sentinel",
        "--sample",
        sample.to_str().unwrap(),
        "--table",
        "Firewall",
        "--out",
        out_dir.to_str().unwrap(),
        "--workspace",
        workspace,
    ]);
    assert!(out.contains("Replace the placeholder endpoint"), "{out}");
    assert!(out.contains("Create the table Firewall_CL"), "{out}");
    let yaml: serde_yaml_ng::Value = serde_yaml_ng::from_str(&out).expect("valid YAML");
    let stream = yaml["destinations"]["sentinel"]["stream_name"]
        .as_str()
        .expect("a stream");
    assert_eq!(stream, "Custom-Firewall", "the rule's input stream");
    let table = read(&out_dir.join("Firewall_CL.table.json"));
    assert!(
        table.contains("\"action\"") && table.contains("\"bytes\""),
        "{table}"
    );
    assert!(read(&out_dir.join("Firewall.dcr.json")).contains(workspace));
}

#[test]
fn connect_sentinel_writes_the_rule_of_each_standard_table() {
    let dir = scratch("connect-standard");
    for (table, file, shape) in [
        ("syslog", "Syslog.dcr.json", "sentinel_syslog"),
        (
            "common-security-log",
            "CommonSecurityLog.dcr.json",
            "sentinel_common_security_log",
        ),
        (
            "asim-network-session",
            "ASimNetworkSessionLogs.dcr.json",
            "sentinel_asim_network_session",
        ),
        (
            "asim-dns",
            "ASimDnsActivityLogs.dcr.json",
            "sentinel_asim_dns",
        ),
        (
            "asim-web-session",
            "ASimWebSessionLogs.dcr.json",
            "sentinel_asim_web_session",
        ),
    ] {
        let out = sluice(&[
            "connect",
            "sentinel",
            "--standard-table",
            table,
            "--out",
            dir.to_str().unwrap(),
            "--endpoint",
            "https://dce.example",
        ]);
        assert!(out.contains(&format!("shape: {shape}")), "{out}");
        assert!(!out.contains("Replace the placeholder"), "{out}");
        let yaml: serde_yaml_ng::Value = serde_yaml_ng::from_str(&out).expect("valid YAML");
        assert!(
            yaml["destinations"]["sentinel"]["stream_name"].is_string(),
            "{table}"
        );
        let dcr: serde_json::Value =
            serde_json::from_str(&read(&dir.join(file))).expect("a JSON rule");
        assert!(dcr.is_object(), "{table}");
    }
}

#[test]
fn connect_sentinel_sends_summaries_to_a_table_of_their_own() {
    let dir = scratch("connect-summaries");
    let out = sluice(&[
        "connect",
        "sentinel",
        "--standard-table",
        "syslog",
        "--summary-table",
        "--out",
        dir.to_str().unwrap(),
        "--endpoint",
        "https://dce.example",
    ]);
    let yaml: serde_yaml_ng::Value = serde_yaml_ng::from_str(&out).expect("valid YAML");
    let events = &yaml["destinations"]["sentinel"];
    let summaries = &yaml["destinations"]["sentinel_summaries"];
    assert_eq!(events["sluice_records"][0], "events", "{out}");
    assert_eq!(summaries["sluice_records"][0], "summaries", "{out}");
    assert_eq!(summaries["stream_name"], "Custom-SluiceSummary");
    for file in [
        "SluiceSummary_CL.table.json",
        "SluiceSummary.dcr.json",
        "SluiceCounts.kql",
    ] {
        assert!(dir.join(file).is_file(), "{file}");
    }
}

#[test]
fn connect_refuses_sentinel_options_elsewhere_and_samples_that_are_not_json() {
    let dir = scratch("connect-refused");
    let out = dir.to_str().unwrap();
    let error = sluice_fails(&[
        "connect",
        "elastic",
        "--standard-table",
        "syslog",
        "--out",
        out,
    ]);
    assert!(error.contains("only applies to `sentinel`"), "{error}");

    let sample = dir.join("bad.ndjson");
    std::fs::write(&sample, "{\"a\":1}\nnot json\n").unwrap();
    let sample = sample.to_str().unwrap();
    let error = sluice_fails(&[
        "connect", "splunk", "--sample", sample, "--table", "T", "--out", out,
    ]);
    assert!(error.contains("only applies to `sentinel`"), "{error}");
    let error = sluice_fails(&[
        "connect", "sentinel", "--sample", sample, "--table", "T", "--out", out,
    ]);
    assert!(error.contains("line 2: not a JSON object"), "{error}");
}

#[test]
fn agent_windows_prints_a_vector_config_and_writes_the_rule_on_request() {
    let dir = scratch("agent");
    let dcr = dir.join("windows.dcr.json");
    let workspace =
        "/subscriptions/s/resourceGroups/g/providers/Microsoft.OperationalInsights/workspaces/w";
    let out = sluice(&[
        "agent",
        "windows",
        "--to",
        "http://sluice:8601",
        "--events-to",
        "http://sluice:8602",
        "--channel",
        "Security",
        "--channel",
        "System",
        "--dcr",
        dcr.to_str().unwrap(),
        "--workspace",
        workspace,
    ]);
    let yaml: serde_yaml_ng::Value = serde_yaml_ng::from_str(&out).expect("valid YAML");
    let text = serde_json::to_string(&yaml).unwrap();
    for wanted in [
        "windows_event_log",
        "http://sluice:8601",
        "http://sluice:8602",
        "System",
    ] {
        assert!(text.contains(wanted), "{wanted}: {out}");
    }
    assert!(read(&dcr).contains(workspace));

    let error = sluice_fails(&["agent", "windows", "--to", "http://x", "--dcr", "d.json"]);
    assert!(error.contains("--workspace"), "{error}");
}

/// Runs `sluice` without the credentials of the user running the tests; returns stderr.
fn sluice_fails_without_credentials(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_sluice"))
        .args(args)
        .env_remove("WAZUH_API_PASSWORD")
        .env_remove("AZURE_TENANT_ID")
        .env("AZURE_CLIENT_ID", "")
        .output()
        .expect("sluice runs");
    assert!(!output.status.success(), "sluice {args:?} succeeded");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn rules_fetch_needs_a_directory_and_credentials_before_it_asks_anything() {
    let error = sluice_fails_without_credentials(&[
        "rules",
        "fetch",
        "wazuh",
        "--api",
        "https://127.0.0.1:9",
        "--user",
        "u",
    ]);
    assert!(error.contains("--out DIR is required"), "{error}");
    let out = scratch("fetch-credentials");
    let out = out.join("rules");
    let out = out.to_str().unwrap();
    let error = sluice_fails_without_credentials(&[
        "rules",
        "fetch",
        "wazuh",
        "--api",
        "https://127.0.0.1:9",
        "--user",
        "u",
        "--out",
        out,
    ]);
    assert!(error.contains("WAZUH_API_PASSWORD is not set"), "{error}");
    let error = sluice_fails_without_credentials(&[
        "rules",
        "fetch",
        "sentinel",
        "--workspace",
        "/subscriptions/s/resourceGroups/g/providers/Microsoft.OperationalInsights/workspaces/w",
        "--out",
        out,
    ]);
    assert!(error.contains("AZURE_TENANT_ID is not set"), "{error}");
    assert!(!Path::new(out).exists(), "nothing written");
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

#[test]
fn contributed_recipes_are_checked_and_never_replace_a_file() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cli-contribute");
    let _ = std::fs::remove_dir_all(&root);
    let from = root.join("ai-recipes");
    let into = root.join("hub");
    let recipe = "id: contrib/nginx/health\ndescription: Health checks\nmatch:\n  logsource: \
                  { product: nginx }\n  pattern: GET /health\nreductions:\n  - op: summarize\n    \
                  summary_keys: [host.name]\nrationale: Load balancer probes.\n";
    std::fs::create_dir_all(from.join("contrib/nginx")).unwrap();
    std::fs::write(from.join("contrib/nginx/health.yaml"), recipe).unwrap();
    let args = [
        "recipes",
        "contribute",
        "--from",
        from.to_str().unwrap(),
        "--into",
        into.to_str().unwrap(),
    ];
    sluice(&args);
    assert_eq!(read(&into.join("contrib/nginx/health.yaml")), recipe);
    let again = Command::new(env!("CARGO_BIN_EXE_sluice"))
        .args(args)
        .output()
        .expect("sluice runs");
    assert!(
        !again.status.success(),
        "an existing recipe is not replaced"
    );

    // A recipe the book refuses is not copied.
    std::fs::write(
        from.join("contrib/nginx/health.yaml"),
        recipe.replace("pattern: GET /health\n", ""),
    )
    .unwrap();
    let refused = Command::new(env!("CARGO_BIN_EXE_sluice"))
        .args([
            "recipes",
            "contribute",
            "--from",
            from.to_str().unwrap(),
            "--into",
        ])
        .arg(root.join("other"))
        .output()
        .expect("sluice runs");
    assert!(!refused.status.success());
    assert!(!root.join("other").exists());
}
