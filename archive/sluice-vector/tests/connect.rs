//! Every `sluice connect` sink in one Vector configuration, written to cargo's test scratch
//! directory so `scripts/vector-check.sh` can run the real `vector validate` on it.

use serde_json::{Map, Value, json};
use sluice_vector::{FORMATS_KEY, SECRET_BACKEND, Target};

#[test]
fn every_target_renders_a_sink_without_secrets() {
    let mut sinks = Map::new();
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    // Vector reads every referenced secret at load time: one dummy file per secret.
    let secrets = dir.join("siem-secrets");
    std::fs::create_dir_all(&secrets).expect("secret directory");
    for target in Target::ALL {
        // Vector checks file sink paths at load time; keep Wazuh's files in the scratch directory.
        let endpoint = if target == Target::Wazuh {
            dir.join("wazuh-%Y-%m-%d.ndjson").display().to_string()
        } else {
            target.example_endpoint().to_owned()
        };
        for (name, mut sink) in target.destinations(target.name(), &endpoint) {
            let text = sink.to_string();
            assert!(!text.contains("${"), "no environment references: {text}");
            for secret in target.secrets() {
                assert!(
                    text.contains(&format!("SECRET[{SECRET_BACKEND}.{secret}]")),
                    "{secret}"
                );
                std::fs::write(secrets.join(secret), "dummy").expect("secret file");
            }
            // `sluice up` removes Sluice's own key before Vector sees the sink.
            sink.as_object_mut().unwrap().remove(FORMATS_KEY);
            sink["inputs"] = json!(["demo"]);
            sinks.insert(name, sink);
        }
    }
    assert_eq!(sinks["wazuh_lines"]["encoding"]["codec"], "text");
    assert_eq!(
        sinks["sentinel"]["batch"]["max_bytes"],
        sluice_vector::AZURE_MAX_BATCH_BYTES,
        "Azure refuses requests over 1 MB"
    );

    let config = json!({
        "data_dir": dir,
        "sources": { "demo": { "type": "demo_logs", "format": "json", "count": 1 } },
        "sinks": Value::Object(sinks),
        "secret": { SECRET_BACKEND: { "type": "directory", "path": secrets } },
    });
    let yaml = serde_yaml_ng::to_string(&config).expect("YAML");
    std::fs::write(dir.join("connect.yaml"), yaml).expect("write connect.yaml");
}

#[test]
fn every_example_endpoint_is_a_url_or_for_wazuh_a_file() {
    let endpoints: std::collections::BTreeSet<&str> =
        Target::ALL.iter().map(|t| t.example_endpoint()).collect();
    assert_eq!(endpoints.len(), Target::ALL.len(), "one each");
    for target in Target::ALL {
        let endpoint = target.example_endpoint();
        let expected = if target == Target::Wazuh {
            "/"
        } else {
            "https://"
        };
        assert!(
            endpoint.starts_with(expected),
            "{}: {endpoint}",
            target.name()
        );
    }
}

#[test]
fn targets_with_secrets_bring_a_directory_backend_and_the_others_none() {
    for target in Target::ALL {
        match target.secret_backend() {
            Some((name, settings)) => {
                assert!(!target.secrets().is_empty(), "{}", target.name());
                assert_eq!(name, SECRET_BACKEND);
                assert_eq!(settings["type"], "directory");
                assert!(
                    settings["path"]
                        .as_str()
                        .is_some_and(|p| p.starts_with('/'))
                );
            }
            None => assert!(target.secrets().is_empty(), "{}", target.name()),
        }
    }
    assert!(Target::Splunk.secret_backend().is_some());
}

#[test]
fn wazuh_notes_name_the_file_it_writes() {
    let notes = Target::Wazuh.notes("/srv/sluice.ndjson");
    assert!(notes.contains("<location>/srv/sluice.ndjson</location>"));
    assert!(
        notes.contains("<log_format>syslog</log_format>\n    <location>/srv/sluice.log</location>"),
        "{notes}"
    );
}
