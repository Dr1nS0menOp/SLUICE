//! `sluice mcp` end to end: a demo's advice served over stdio, and a configuration proven
//! through it, as an assistant would call the tools.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use serde_json::{Value, json};

fn sluice(args: &[&str]) {
    let status = Command::new(env!("CARGO_BIN_EXE_sluice"))
        .args(args)
        .stdout(Stdio::null())
        .status()
        .expect("sluice runs");
    assert!(status.success(), "sluice {args:?}");
}

/// A demo's output, written once for these tests (they run in parallel).
fn demo() -> PathBuf {
    static DEMO: OnceLock<PathBuf> = OnceLock::new();
    DEMO.get_or_init(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("mcp-demo");
        let _ = std::fs::remove_dir_all(&dir);
        sluice(&[
            "demo",
            "--scale",
            "2",
            "--out",
            dir.to_str().expect("UTF-8"),
        ]);
        dir
    })
    .clone()
}

/// Sends `requests` (one per line, after the handshake) to `sluice mcp` and gives the answers to
/// them by id.
fn session(args: &[&str], requests: &[Value]) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sluice"))
        .arg("mcp")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("sluice mcp starts");
    let mut lines = vec![
        json!({"jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    ];
    lines.extend(requests.iter().cloned());
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for line in &lines {
            writeln!(stdin, "{line}").expect("written");
        }
    }
    let output = child.wait_with_output().expect("sluice mcp ends");
    assert!(output.status.success(), "sluice mcp failed");
    let answers: Vec<Value> = String::from_utf8(output.stdout)
        .expect("UTF-8")
        .lines()
        .map(|l| serde_json::from_str(l).expect("one JSON message per line"))
        .collect();
    assert_eq!(answers[0]["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(answers.len(), requests.len() + 1, "{answers:?}");
    answers[1..].to_vec()
}

fn call(id: u64, name: &str, arguments: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": name, "arguments": arguments}})
}

#[test]
fn an_assistant_reads_the_advice() {
    let dir = demo();
    let out = dir.to_str().expect("UTF-8");
    let answers = session(
        &["--out", out],
        &[
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
            call(2, "summary", &json!({})),
            call(3, "source_plan", &json!({"source": "windows-security"})),
            call(4, "source_plan", &json!({"source": "nope"})),
            call(5, "files", &json!({})),
            call(6, "read_file", &json!({"path": "vector.yaml"})),
            call(7, "read_file", &json!({"path": "../plan.json"})),
            call(8, "prove_vector", &json!({"config": "transforms: {}"})),
            call(9, "problems", &json!({})),
        ],
    );
    let names: Vec<&str> = answers[0]["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert_eq!(
        names,
        [
            "summary",
            "source_plan",
            "problems",
            "files",
            "read_file",
            "prove_vector",
            "prove_transform_kql"
        ]
    );

    let source_plan = &answers[0]["result"]["tools"][1]["inputSchema"];
    assert_eq!(source_plan["type"], "object");
    assert_eq!(source_plan["required"], json!(["source"]));
    assert_eq!(source_plan["additionalProperties"], false);
    assert_eq!(source_plan["properties"]["template"]["type"], "string");
    let summary = &answers[1]["result"]["structuredContent"];
    let plan: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("plan.json")).expect("the plan"))
            .expect("JSON");
    assert_eq!(summary["proof"], plan["proof"]);
    assert_eq!(summary["total"], plan["total"]);
    assert!(summary["saved_percent"].as_f64().expect("a number") > 0.0);
    let sources: Vec<&str> = summary["sources"]
        .as_array()
        .expect("sources")
        .iter()
        .filter_map(|s| s["id"].as_str())
        .collect();
    assert!(sources.contains(&"windows-security"), "{sources:?}");
    assert!(summary["proving"].is_null(), "no sample was given");

    let source = &answers[2]["result"]["structuredContent"];
    assert_eq!(source["id"], "windows-security");
    assert!(
        source["templates"]
            .as_array()
            .is_some_and(|t| !t.is_empty())
    );
    assert_eq!(answers[3]["result"]["isError"], true);

    let files: Vec<&str> = answers[4]["result"]["structuredContent"]["files"]
        .as_array()
        .expect("files")
        .iter()
        .filter_map(|f| f["path"].as_str())
        .collect();
    assert!(
        files.contains(&"vector.yaml") && files.contains(&"plan.json"),
        "{files:?}"
    );
    assert!(
        !files
            .iter()
            .any(|f| f.starts_with("samples/") || *f == "report.html"),
        "the sample and the report are not offered: {files:?}"
    );
    let vector = std::fs::read_to_string(dir.join("vector.yaml")).expect("vector.yaml");
    assert_eq!(answers[5]["result"]["structuredContent"]["text"], vector);
    assert_eq!(
        answers[6]["result"]["isError"], true,
        "a path outside the list is refused"
    );
    let refused = answers[7]["result"]["content"][0]["text"]
        .as_str()
        .expect("text");
    assert!(refused.contains("no sample to prove on"), "{refused}");
    assert!(answers[8]["result"]["structuredContent"]["problems"].is_array());
}

#[test]
fn a_draft_is_proven_on_the_sample_before_it_is_proposed() {
    let dir = demo();
    let out = dir.to_str().expect("UTF-8");
    let samples = dir.join("samples");
    let sources = dir.join("sluice.yaml");
    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/rules/sigma");
    let vector = std::fs::read_to_string(dir.join("vector.yaml")).expect("vector.yaml");
    let answers = session(
        &[
            "--out",
            out,
            "--input",
            samples.to_str().expect("UTF-8"),
            "--sources",
            sources.to_str().expect("UTF-8"),
            "--rules",
            rules.to_str().expect("UTF-8"),
        ],
        &[
            call(1, "prove_vector", &json!({"config": vector})),
            call(2, "prove_vector", &json!({"config": "transforms: {}"})),
            call(
                3,
                "prove_transform_kql",
                &json!({"source": "windows-security", "kql": "source"}),
            ),
            call(4, "summary", &json!({})),
        ],
    );
    let proof = &answers[0]["result"]["structuredContent"];
    assert_eq!(proof["holds"], true, "{proof}");
    assert_eq!(proof["alerts_full"], proof["alerts_forwarded"]);
    assert!(proof["bytes_out"].as_u64() < proof["bytes_in"].as_u64());
    let refused = answers[1]["result"]["content"][0]["text"]
        .as_str()
        .expect("text");
    assert_eq!(answers[1]["result"]["isError"], true);
    assert!(refused.contains("no Sluice program"), "{refused}");
    let no_kusto = answers[2]["result"]["content"][0]["text"]
        .as_str()
        .expect("text");
    assert!(no_kusto.contains("no Kusto emulator"), "{no_kusto}");
    assert_eq!(
        answers[3]["result"]["structuredContent"]["proving"]["sigma"],
        true
    );
}

/// The demo's Windows Security records flat, as an application sends them to a custom table and
/// the table stores them (an empty field is a missing one); the other sources as they are.
fn flat_samples(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for entry in std::fs::read_dir(from).expect("the samples") {
        let path = entry.expect("an entry").path();
        let text = std::fs::read_to_string(&path).expect("a sample");
        let text = if path.ends_with("windows-security.ndjson") {
            text.lines()
                .map(|line| {
                    let record: serde_json::Map<String, Value> =
                        serde_json::from_str(line).expect("a record");
                    let flat: serde_json::Map<String, Value> = record
                        .into_iter()
                        .filter(|(_, v)| {
                            !(v.is_null()
                                || v.as_str() == Some("")
                                || v.is_object()
                                || v.is_array())
                        })
                        .collect();
                    Value::Object(flat).to_string() + "\n"
                })
                .collect()
        } else {
            text
        };
        std::fs::write(to.join(path.file_name().expect("a name")), text).expect("written");
    }
}

/// `prove_transform_kql` in the real Kusto emulator (`SLUICE_KUSTO_URL`, as
/// `scripts/kql-check.sh` sets it), on a custom table with a Sentinel rule on failed logons: a
/// draft that empties `Message` holds, one that drops the failed logons does not, and a function
/// beyond Sluice's own is named.
#[test]
fn a_drafted_transformation_is_proven_in_the_kusto_emulator() {
    let Ok(url) = std::env::var("SLUICE_KUSTO_URL") else {
        eprintln!("skipped: set SLUICE_KUSTO_URL");
        return;
    };
    let dir = demo();
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("mcp-kusto");
    let _ = std::fs::remove_dir_all(&root);
    let samples = root.join("samples");
    flat_samples(&dir.join("samples"), &samples);
    let rules = root.join("rules");
    std::fs::create_dir_all(&rules).expect("a directory");
    std::fs::write(
        rules.join("failed-logons.yaml"),
        "id: 11111111-1111-1111-1111-111111111111\nname: Failed logons on a custom table\n\
         kind: Scheduled\nquery: |\n  Win_CL\n  | where EventID == 4625\n  | project \
         TimeGenerated, TargetUserName, IpAddress\n",
    )
    .expect("written");
    let path = |p: &Path| p.to_str().expect("UTF-8").to_owned();
    let args = [
        "--out".to_owned(),
        path(&dir),
        "--input".to_owned(),
        path(&samples),
        "--sources".to_owned(),
        path(&dir.join("sluice.yaml")),
        "--sentinel-rules".to_owned(),
        path(&rules),
        "--kusto".to_owned(),
        url,
        "--sentinel-table".to_owned(),
        "windows-security=Win_CL".to_owned(),
    ];
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let answers = session(
        &args,
        &[
            call(
                1,
                "prove_transform_kql",
                &json!({"source": "windows-security",
                "kql": "source | project-away Message"}),
            ),
            call(
                2,
                "prove_transform_kql",
                &json!({"source": "windows-security",
                "kql": "source | where EventID != 4625"}),
            ),
            call(
                3,
                "prove_transform_kql",
                &json!({"source": "windows-security",
                "kql": "source | extend t = now()"}),
            ),
        ],
    );
    let kept = &answers[0]["result"]["structuredContent"];
    assert_eq!(kept["holds"], true, "{kept}");
    assert!(kept["alerts_full"].as_u64() > Some(0), "{kept}");
    assert!(
        kept["emptied_columns"]["Message"].as_u64() > Some(0),
        "{kept}"
    );
    assert!(
        kept["bytes_after"].as_u64() < kept["bytes_before"].as_u64(),
        "{kept}"
    );
    let dropped = &answers[1]["result"]["structuredContent"];
    assert_eq!(dropped["holds"], false, "{dropped}");
    assert!(dropped["dropped"].as_u64() > Some(0), "{dropped}");
    assert!(dropped["missing_alerts"].as_u64() > Some(0), "{dropped}");
    let clock = &answers[2]["result"]["structuredContent"];
    assert_eq!(clock["holds"], true, "{clock}");
    assert_eq!(clock["unverified_functions"], json!(["now"]), "{clock}");
}
