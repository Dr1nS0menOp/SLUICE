//! The generated Vector configuration. The file is written to cargo's test scratch directory so
//! `scripts/vector-check.sh` can run the real `vector validate` and `vector test` on it.

mod common;

use std::collections::BTreeSet;

use common::{discovery, guarded, sample, template};
use sluice_core::guard::EffectiveRecipe;
use sluice_core::recipe::Reduction;
use sluice_vector::{Paths, Plan, compile_reducer, vector_config};

fn rendered() -> String {
    let logon = template("windows-security:4624:");
    let access = template("sysmon:10:");
    let mut recipes: Vec<EffectiveRecipe> = Vec::new();
    for t in &discovery().templates {
        let recipe = if t.id == logon.id {
            guarded(
                t,
                vec![
                    Reduction::DropFields {
                        fields: BTreeSet::from(["Message".into()]),
                    },
                    Reduction::DropEmptyFields,
                ],
            )
        } else if t.id == access.id {
            guarded(
                t,
                vec![Reduction::ForwardMatching {
                    summary_keys: vec!["SourceImage".into(), "TargetImage".into()],
                }],
            )
        } else {
            EffectiveRecipe::passthrough(t.id.clone())
        };
        recipes.push(recipe);
    }
    let plans: Vec<Plan<'_>> = discovery()
        .templates
        .iter()
        .zip(&recipes)
        .map(|(template, recipe)| Plan { template, recipe })
        .collect();
    let reducer = compile_reducer(plans.iter().copied()).expect("programs compile");
    let paths = Paths {
        input_dir: "./samples".to_owned(),
        output_dir: "./out".to_owned(),
    };
    vector_config(
        &sample().sources,
        &plans,
        &reducer,
        &sample().events,
        &paths,
    )
    .expect("config renders")
}

#[test]
fn config_is_valid_yaml_with_a_pipeline_and_tests_per_source() {
    let yaml = rendered();
    let config: serde_json::Value = serde_yaml_ng::from_str(&yaml).expect("valid YAML");
    for component in [
        "sluice_windows_security",
        "sluice_sysmon_route",
        "sluice_dns_archive",
    ] {
        let found = ["transforms", "sinks"]
            .iter()
            .any(|section| config[section].get(component).is_some());
        assert!(found, "missing {component}");
    }
    let names: Vec<&str> = config["tests"]
        .as_array()
        .expect("tests list")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(
        names
            .iter()
            .any(|n| n.contains("sysmon:10:") && n.contains("-> summarize"))
    );
    assert!(
        names
            .iter()
            .any(|n| n.contains("sysmon:10:") && n.contains("-> forward"))
    );
    assert!(
        names
            .iter()
            .any(|n| n.contains("windows-security:4624:") && n.contains("-> forward"))
    );
    assert!(
        names.iter().any(|n| n.starts_with("nginx ")),
        "pass-through test per source"
    );

    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(dir.join("vector.yaml"), &yaml).expect("write vector.yaml");
}

#[test]
fn config_is_deterministic() {
    assert_eq!(rendered(), rendered());
}
