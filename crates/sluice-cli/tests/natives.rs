//! The native generators end to end: `sluice` writes each tool's configuration and proves it in
//! that tool. Each test runs only with its engine attached, as the crates' own engine tests do
//! (`scripts/elastic-check.sh`, `fluentbit-check.sh`, `otel-check.sh` and `kql-check.sh` attach
//! them).

#![allow(
    clippy::print_stderr,
    reason = "a test reports when its engine is missing"
)]

use std::path::{Path, PathBuf};
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

fn engine(variable: &str) -> Option<String> {
    let value = std::env::var(variable).ok();
    if value.is_none() {
        eprintln!("skipped: set {variable}");
    }
    value
}

/// A fresh directory for one test.
fn fresh(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&root);
    root
}

fn files(dir: &Path, extension: &str) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == extension))
                .collect()
        })
        .unwrap_or_default()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn elastic_native_writes_proven_pipelines_and_runtime_fields() {
    let Some(url) = engine("SLUICE_ELASTIC_URL") else {
        return;
    };
    let out = fresh("native-elastic");
    let summary = sluice(&[
        "demo",
        "--scale",
        "5",
        "--out",
        out.to_str().unwrap(),
        "--elasticsearch",
        &url,
        "--native",
        "elastic",
    ]);
    assert!(
        summary.contains("every removed field also removed by Vector"),
        "{summary}"
    );
    assert!(summary.contains("put back at query time"), "{summary}");
    let dir = out.join("elastic");
    let pipelines: Vec<PathBuf> = files(&dir, "json")
        .into_iter()
        .filter(|p| p.to_string_lossy().ends_with(".pipeline.json"))
        .collect();
    assert_ne!(pipelines.len(), 0, "no pipeline written");
    let runtime = dir.join("windows-security.runtime.json");
    let fields: serde_json::Value = serde_json::from_str(&read(&runtime)).expect("JSON");
    assert!(
        fields
            .as_object()
            .is_some_and(|f| f.values().all(|d| d["script"]["source"].is_string())),
        "{fields}"
    );
}

#[test]
fn fluent_bit_native_writes_proven_lua_filters() {
    let Some(command) = engine("SLUICE_FLUENT_BIT") else {
        return;
    };
    let out = fresh("native-fluent-bit");
    let summary = sluice(&[
        "demo",
        "--scale",
        "5",
        "--out",
        out.to_str().unwrap(),
        "--fluent-bit",
        &command,
        "--native",
        "fluent-bit",
    ]);
    assert!(
        summary.contains("every removed field also removed by Vector"),
        "{summary}"
    );
    let dir = out.join("fluent-bit");
    assert_ne!(files(&dir, "lua").len(), 0, "no filter written");
    assert!(read(&dir.join("filters.conf")).contains("[FILTER]"));
}

#[test]
fn otel_native_writes_proven_transform_statements() {
    let Some(command) = engine("SLUICE_OTEL_COLLECTOR") else {
        return;
    };
    let out = fresh("native-otel");
    let summary = sluice(&[
        "demo",
        "--scale",
        "5",
        "--out",
        out.to_str().unwrap(),
        "--otel-collector",
        &command,
        "--native",
        "otel",
    ]);
    assert!(
        summary.contains("every removed field also removed by Vector"),
        "{summary}"
    );
    assert!(read(&out.join("otel").join("processors.yaml")).contains("transform"));
}

/// The demo's samples in `to`, with `windows-security` as a flat JSON application sends it: no
/// empty or nested fields, as `scripts/sentinel-custom-check.sh` makes it.
fn flat_samples(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for path in files(from, "ndjson") {
        let name = path.file_name().expect("a name");
        let text = read(&path);
        let text = if name == "windows-security.ndjson" {
            text.lines()
                .map(|line| {
                    let record: serde_json::Map<String, serde_json::Value> =
                        serde_json::from_str(line).expect("a record");
                    let flat: serde_json::Map<String, serde_json::Value> = record
                        .into_iter()
                        .filter(|(_, v)| {
                            !(v.is_null()
                                || v.as_str() == Some("")
                                || v.is_object()
                                || v.as_array().is_some_and(Vec::is_empty))
                        })
                        .collect();
                    serde_json::Value::Object(flat).to_string() + "\n"
                })
                .collect()
        } else {
            text
        };
        std::fs::write(to.join(name), text).expect("written");
    }
}

/// As `scripts/sentinel-custom-check.sh`: a JSON source in a custom table, its rule written with
/// a proven transformation, and the same transformation again from the rule Sluice wrote.
#[test]
fn sentinel_native_writes_a_proven_rule_and_rewrites_it_the_same() {
    let Some(url) = engine("SLUICE_KUSTO_URL") else {
        return;
    };
    let root = fresh("native-sentinel");
    let demo = root.join("demo");
    sluice(&["demo", "--out", demo.to_str().unwrap(), "--scale", "5"]);
    let samples = root.join("samples");
    flat_samples(&demo.join("samples"), &samples);
    let connect = root.join("connect");
    sluice(&[
        "connect",
        "sentinel",
        "--sample",
        samples.join("windows-security.ndjson").to_str().unwrap(),
        "--table",
        "Win",
        "--out",
        connect.to_str().unwrap(),
        "--workspace",
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/r/providers/\
         Microsoft.OperationalInsights/workspaces/w",
    ]);
    let rules = root.join("rules");
    std::fs::create_dir_all(&rules).expect("a directory");
    std::fs::write(
        rules.join("failed-logons.yaml"),
        "id: 11111111-1111-1111-1111-111111111111\nname: Failed logons on a custom table\n\
         kind: Scheduled\nquery: |\n  Win_CL\n  | where EventID == 4625\n  | project \
         TimeGenerated, TargetUserName, IpAddress\n",
    )
    .expect("written");
    let analyze = |rule: &Path, out: &Path| {
        sluice(&[
            "analyze",
            "--input",
            samples.to_str().unwrap(),
            "--sources",
            demo.join("sluice.yaml").to_str().unwrap(),
            "--sentinel-rules",
            rules.to_str().unwrap(),
            "--kusto",
            &url,
            "--sentinel-table",
            "windows-security=Win_CL",
            "--native",
            "sentinel",
            "--sentinel-dcr",
            rule.to_str().unwrap(),
            "--rules-complete",
            "--no-examples",
            "--out",
            out.to_str().unwrap(),
        ])
    };
    let first = root.join("first");
    analyze(&connect.join("Win.dcr.json"), &first);
    let kql = read(
        &first
            .join("sentinel")
            .join("windows-security.transform.kql"),
    );
    assert!(
        kql.contains("extend ['Message']"),
        "Message is not removed:\n{kql}"
    );
    assert!(
        kql.contains("project-rename"),
        "the rule's own renames are gone:\n{kql}"
    );
    let written = first.join("sentinel").join("dcr.json");
    let rule: serde_json::Value = serde_json::from_str(&read(&written)).expect("JSON");
    assert!(rule["properties"]["dataFlows"].is_array(), "{rule}");
    // Again, on the rule Sluice wrote: its part is replaced, not added.
    let again = root.join("again.json");
    std::fs::copy(&written, &again).expect("copied");
    let second = root.join("second");
    analyze(&again, &second);
    assert_eq!(
        read(
            &second
                .join("sentinel")
                .join("windows-security.transform.kql")
        ),
        kql,
        "a second run changed the transformation"
    );
}
