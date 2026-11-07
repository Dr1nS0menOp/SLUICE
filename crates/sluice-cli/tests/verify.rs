//! `sluice verify` end to end: the demo's plan checked on its own sample, with rules added, on
//! data of a kind it does not know, and against a rule its counting would silence (ADR 0039).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

/// What `sluice verify` printed and its exit code.
struct Run {
    stdout: String,
    stderr: String,
    code: Option<i32>,
}

fn sluice(args: &[&str]) -> Run {
    let Output {
        status,
        stdout,
        stderr,
    } = Command::new(env!("CARGO_BIN_EXE_sluice"))
        .args(args)
        .output()
        .expect("sluice runs");
    Run {
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        code: status.code(),
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join("verify")
}

/// The demo's output directory, written once.
fn demo() -> &'static Path {
    static DEMO: OnceLock<PathBuf> = OnceLock::new();
    DEMO.get_or_init(|| {
        let dir = root().join("demo");
        let _ = std::fs::remove_dir_all(&dir);
        let run = sluice(&[
            "demo",
            "--scale",
            "5",
            "--out",
            dir.to_str().expect("UTF-8"),
        ]);
        assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
        dir
    })
}

fn example_rules() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/rules/sigma")
}

/// `sluice verify` of the demo's plan on `samples` with the Sigma rules in `rules`.
fn verify(samples: &Path, rules: &Path, extra: &[&str]) -> Run {
    let demo = demo();
    let mut args = vec![
        "verify",
        "--analysis",
        demo.to_str().expect("UTF-8"),
        "--input",
        samples.to_str().expect("UTF-8"),
        "--sources",
    ];
    let sources = demo.join("sluice.yaml");
    args.push(sources.to_str().expect("UTF-8"));
    args.extend(["--rules", rules.to_str().expect("UTF-8")]);
    args.extend(extra);
    sluice(&args)
}

/// The example rules and one more, in a directory of their own.
fn rules_with(name: &str, rule: &str) -> PathBuf {
    let dir = root().join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the directory is created");
    for entry in std::fs::read_dir(example_rules()).expect("the examples are there") {
        let path = entry.expect("an entry").path();
        std::fs::copy(&path, dir.join(path.file_name().expect("a file"))).expect("copied");
    }
    std::fs::write(dir.join("added.yml"), rule).expect("the rule is written");
    dir
}

#[test]
fn a_plan_verified_on_its_own_sample_and_rules_holds() {
    let run = verify(
        &demo().join("samples"),
        &example_rules(),
        &["--rules-complete"],
    );
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    assert!(run.stdout.contains("✓ the plan holds"), "{}", run.stdout);
    assert!(
        run.stdout.contains("0 new, 0 read differently, 0 gone"),
        "{}",
        run.stdout
    );
}

#[test]
fn c3_a_plan_that_counts_needs_rules_known_to_be_complete() {
    let run = verify(&demo().join("samples"), &example_rules(), &[]);
    assert_eq!(run.code, Some(3), "{}{}", run.stdout, run.stderr);
    assert!(
        run.stdout.contains("needs every rule the SIEM runs"),
        "{}",
        run.stdout
    );
}

#[test]
fn c3_a_rule_added_since_the_plan_makes_it_out_of_date() {
    let rules = rules_with(
        "rules-added",
        "title: Any whoami\nid: 0a1b2c3d-0000-4000-8000-000000000001\n\
         logsource: { product: windows, category: process_creation }\n\
         detection:\n  sel: { Image|endswith: '\\whoami.exe' }\n  condition: sel\n",
    );
    let run = verify(
        &demo().join("samples"),
        &rules,
        &["--rules-complete", "--json"],
    );
    assert_eq!(run.code, Some(3), "{}{}", run.stdout, run.stderr);
    let result: serde_json::Value = serde_json::from_str(&run.stdout).expect("JSON");
    assert_eq!(result["verdict"], "out_of_date");
    assert_eq!(
        result["rules"]["added"],
        serde_json::json!(["sigma:0a1b2c3d-0000-4000-8000-000000000001"])
    );
}

#[test]
fn c5_a_rule_whose_events_the_plan_counts_means_it_does_not_hold() {
    // Sysmon's process access events (EventID 10) are counted by the demo's plan; a rule on
    // every one of them would lose its alerts.
    let rules = rules_with(
        "rules-counted",
        "title: Any process access\nid: 0a1b2c3d-0000-4000-8000-000000000002\n\
         logsource: { product: windows, service: sysmon }\n\
         detection:\n  sel: { EventID: 10 }\n  condition: sel\n",
    );
    let run = verify(&demo().join("samples"), &rules, &["--rules-complete"]);
    assert_eq!(run.code, Some(1), "{}{}", run.stdout, run.stderr);
    assert!(
        run.stdout.contains("✗ the plan does not hold"),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("missing sigma:0a1b2c3d"),
        "{}",
        run.stdout
    );
}

#[test]
fn events_of_a_kind_the_plan_does_not_know_are_counted_as_sent_whole() {
    let samples = root().join("new-kind");
    let _ = std::fs::remove_dir_all(&samples);
    std::fs::create_dir_all(&samples).expect("the directory is created");
    for entry in std::fs::read_dir(demo().join("samples")).expect("the samples are there") {
        let path = entry.expect("an entry").path();
        std::fs::copy(&path, samples.join(path.file_name().expect("a file"))).expect("copied");
    }
    let mut dns = std::fs::read_to_string(samples.join("dns.ndjson")).expect("read");
    dns.extend((0..2000).map(|n| {
        format!("{{\"@timestamp\":\"2026-10-10T08:30:00.000Z\",\"brand_new_field\":\"{n}\"}}\n")
    }));
    std::fs::write(samples.join("dns.ndjson"), dns).expect("written");
    let run = verify(&samples, &example_rules(), &["--rules-complete", "--json"]);
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    let result: serde_json::Value = serde_json::from_str(&run.stdout).expect("JSON");
    assert_eq!(result["savings"]["unknown_percent_plan"], 0.0);
    assert!(
        result["savings"]["unknown_percent_now"].as_f64() > Some(0.0),
        "{}",
        run.stdout
    );
}

#[test]
fn a_plan_of_another_format_is_refused() {
    let dir = root().join("other-format");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the directory is created");
    let plan = std::fs::read_to_string(demo().join("plan.json")).expect("read");
    std::fs::write(
        dir.join("plan.json"),
        plan.replace("\"sluice.plan/1\"", "\"sluice.plan/2\""),
    )
    .expect("written");
    std::fs::copy(demo().join("vector.yaml"), dir.join("vector.yaml")).expect("copied");
    let run = sluice(&[
        "verify",
        "--analysis",
        dir.to_str().expect("UTF-8"),
        "--input",
        demo().join("samples").to_str().expect("UTF-8"),
        "--sources",
        demo().join("sluice.yaml").to_str().expect("UTF-8"),
        "--rules",
        example_rules().to_str().expect("UTF-8"),
    ]);
    assert_eq!(run.code, Some(1), "{}{}", run.stdout, run.stderr);
    assert!(
        run.stderr.contains("the plan is format sluice.plan/2"),
        "{}",
        run.stderr
    );
}
