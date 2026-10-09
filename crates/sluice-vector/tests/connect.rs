//! Every `sluice connect` sink in one Vector configuration, written to cargo's test scratch
//! directory so `scripts/vector-check.sh` can run the real `vector validate` on it.

use serde_json::{Map, Value, json};
use sluice_vector::Target;

#[test]
fn every_target_renders_a_sink_without_secrets() {
    let mut sinks = Map::new();
    for target in Target::ALL {
        let mut sink = target.sink(target.example_endpoint());
        let text = sink.to_string();
        for secret in target.secrets() {
            assert!(text.contains(&format!("${{{secret}}}")), "{secret}");
        }
        sink["inputs"] = json!(["demo"]);
        sinks.insert(target.name().to_owned(), sink);
    }
    // Vector checks file sink paths at load time; keep the Wazuh file in the scratch directory.
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    sinks["wazuh"]["path"] = json!(dir.join("wazuh-%Y-%m-%d.ndjson"));

    let config = json!({
        "data_dir": dir,
        "sources": { "demo": { "type": "demo_logs", "format": "json", "count": 1 } },
        "sinks": Value::Object(sinks),
    });
    let yaml = serde_yaml_ng::to_string(&config).expect("YAML");
    std::fs::write(dir.join("connect.yaml"), yaml).expect("write connect.yaml");
}

#[test]
fn wazuh_notes_name_the_file_it_writes() {
    let notes = Target::Wazuh.notes("/srv/sluice.ndjson");
    assert!(notes.contains("<location>/srv/sluice.ndjson</location>"));
}
