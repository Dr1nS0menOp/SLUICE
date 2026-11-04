//! `sluice analyze` with Splunk's searches run in a real Splunk (ADR 0037), end to end. Runs
//! when `SLUICE_SPLUNK_URL` names a Splunk for the proof (`scripts/splunk-check.sh` starts one),
//! with its `admin` password in `SLUICE_SPLUNK_PASSWORD` and, if the collector is not on the
//! port Splunk reports, its address in `SLUICE_SPLUNK_HEC`.

#![allow(
    clippy::print_stderr,
    reason = "a test reports when its engine is missing"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The demo's example rules, as the saved searches a Splunk would run.
const SEARCHES: &str = r#"
[Failed Logon]
search = `wineventlog_security` EventID=4625 NOT TargetUserName="*$"
enableSched = 1

[Failed Logon Burst]
search = `wineventlog_security` EventID=4625 NOT TargetUserName="*$" \
| bin _time span=1m | stats count by _time, TargetUserName | where count >= 10
enableSched = 1

[LSASS Network Connection]
search = `wineventlog_security` EventID=5156 Application="*\\lsass.exe"
enableSched = 1

[Unused Report]
search = index=wineventlog | top Application
"#;

const MACROS: &str = r"
[wineventlog_security]
definition = index=wineventlog source=XmlWinEventLog:Security
";

fn fresh(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&root);
    root
}

fn sluice(args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sluice"))
        .args(args)
        .env_remove("SPLUNK_PROOF_TOKEN")
        .env_remove("SPLUNK_PROOF_PASSWORD")
        .envs(env.iter().copied())
        .output()
        .expect("sluice runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn analyze_runs_splunk_searches_in_splunk_for_the_proof() {
    let Ok(url) = std::env::var("SLUICE_SPLUNK_URL") else {
        eprintln!("skipped: set SLUICE_SPLUNK_URL");
        return;
    };
    let password = std::env::var("SLUICE_SPLUNK_PASSWORD").unwrap_or_default();
    let hec = std::env::var("SLUICE_SPLUNK_HEC").ok();
    let root = fresh("splunk-analyze");
    let demo = root.join("demo");
    let made = sluice(
        &["demo", "--scale", "5", "--out", demo.to_str().unwrap()],
        &[],
    );
    assert!(made.status.success(), "{}", text(&made.stderr));
    // The demo's records, declared as Splunk extracts a JSON event's keys.
    let sources = demo.join("sluice.yaml");
    let declared = std::fs::read_to_string(&sources)
        .expect("the demo's sources")
        .replace("schema: sigma", "schema: splunk");
    assert!(declared.contains("schema: splunk"), "{declared}");
    std::fs::write(&sources, declared).expect("written");
    let rules = root.join("splunk");
    std::fs::create_dir_all(&rules).expect("a directory");
    std::fs::write(rules.join("savedsearches.conf"), SEARCHES).expect("written");
    std::fs::write(rules.join("macros.conf"), MACROS).expect("written");

    let out = root.join("out");
    let samples = demo.join("samples");
    let mut args = vec![
        "analyze",
        "--input",
        samples.to_str().unwrap(),
        "--sources",
        sources.to_str().unwrap(),
        "--splunk-rules",
        rules.to_str().unwrap(),
        "--rules-complete",
        "--splunk",
        &url,
        "--splunk-insecure",
        "--out",
        out.to_str().unwrap(),
    ];
    if let Some(hec) = &hec {
        args.extend(["--splunk-hec", hec]);
    }
    let analyzed = sluice(
        &args,
        // The SIEM's own token is set too: the proof never takes it to its Splunk.
        &[
            ("SPLUNK_PROOF_PASSWORD", &password),
            ("SPLUNK_TOKEN", "the-siem-s-read-only-token"),
        ],
    );
    let (stdout, stderr) = (text(&analyzed.stdout), text(&analyzed.stderr));
    assert!(analyzed.status.success(), "{stdout}\n{stderr}");
    assert!(
        stderr.contains("3 searches run there; 0 it cannot run"),
        "{stderr}"
    );
    assert!(stdout.contains("✓ no detection changed"), "{stdout}");
    let plan: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("plan.json")).expect("plan.json"))
            .expect("JSON");
    let proof = &plan["proof"];
    assert_eq!(proof["holds"], true, "{proof}");
    // Splunk's alerts are the proof's: the sample has failed logons and LSASS connections.
    assert!(proof["alerts_full"].as_u64() > Some(0), "{proof}");
    assert_eq!(proof["alerts_full"], proof["alerts_forwarded"], "{proof}");
    let rows = std::fs::read_to_string(out.join("rules.json")).expect("rules.json");
    assert!(rows.contains("splunk:LSASS Network Connection"), "{rows}");
    assert!(!rows.contains("Unused Report"), "{rows}");
    // Something was saved, and Splunk raised the same alerts on what is left.
    let total = &plan["total"];
    assert!(
        total["bytes_out"].as_u64() < total["bytes_in"].as_u64(),
        "{total}"
    );
}

#[test]
fn the_proofs_splunk_needs_credentials_of_its_own() {
    let root = fresh("splunk-credentials");
    let demo = root.join("demo");
    let made = sluice(
        &["demo", "--scale", "2", "--out", demo.to_str().unwrap()],
        &[],
    );
    assert!(made.status.success(), "{}", text(&made.stderr));
    let rules = root.join("splunk");
    std::fs::create_dir_all(&rules).expect("a directory");
    std::fs::write(rules.join("savedsearches.conf"), SEARCHES).expect("written");
    let analyzed = sluice(
        &[
            "analyze",
            "--input",
            demo.join("samples").to_str().unwrap(),
            "--sources",
            demo.join("sluice.yaml").to_str().unwrap(),
            "--splunk-rules",
            rules.to_str().unwrap(),
            "--splunk",
            "https://127.0.0.1:9",
            "--out",
            root.join("out").to_str().unwrap(),
        ],
        // The SIEM's read-only account is no account for the proof's Splunk.
        &[("SPLUNK_TOKEN", "the-siem-s-read-only-token")],
    );
    assert!(!analyzed.status.success());
    let stderr = text(&analyzed.stderr);
    assert!(stderr.contains("SPLUNK_PROOF_PASSWORD"), "{stderr}");
}

#[test]
fn splunk_without_its_searches_is_refused_before_anything_is_read() {
    let made = sluice(
        &[
            "analyze",
            "--input",
            "nowhere",
            "--sources",
            "nowhere.yaml",
            "--splunk",
            "https://127.0.0.1:9",
        ],
        &[],
    );
    assert!(!made.status.success());
    let stderr = text(&made.stderr);
    assert!(stderr.contains("--splunk-rules"), "{stderr}");
}
