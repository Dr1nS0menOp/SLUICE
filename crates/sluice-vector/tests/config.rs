//! The generated Vector configuration. The file is written to cargo's test scratch directory so
//! `scripts/vector-check.sh` can run the real `vector validate` and `vector test` on it.

mod common;

use std::collections::BTreeSet;

use common::{discovery, guarded, sample, template};
use sluice_core::guard::EffectiveRecipe;
use sluice_core::recipe::Reduction;
use sluice_core::reduce::Reducer;
use sluice_vector::{Paths, Plan, VrlReducer, compile_reducer, deployed, vector_config};

fn rendered() -> String {
    rendered_with_reducer().0
}

fn rendered_with_reducer() -> (String, VrlReducer) {
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
    let yaml = vector_config(
        &sample().sources,
        &plans,
        &reducer,
        &sample().events,
        &paths,
    )
    .expect("config renders");
    (yaml, reducer)
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

// ---------- `sluice prove`: the reductions read back from the configuration (M11) ----------

#[test]
fn the_programs_read_back_from_the_config_reduce_exactly_as_the_proven_ones() {
    let (yaml, proven) = rendered_with_reducer();
    let read = deployed(&yaml, &sample().sources, None).expect("Sluice's own config");
    for event in &sample().events {
        assert_eq!(
            read.reducer.reduce(event).unwrap(),
            proven.reduce(event).unwrap(),
            "event {}",
            event.id
        );
    }
}

/// `yaml` with one edit applied to its parsed form.
fn edited(edit: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut config: serde_json::Value =
        serde_yaml_ng::from_str(&rendered()).expect("the rendered config is YAML");
    edit(&mut config);
    serde_yaml_ng::to_string(&config).expect("an edited config serializes")
}

fn refused(yaml: &str) -> String {
    match deployed(yaml, &sample().sources, None) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("an edited configuration was accepted"),
    }
}

#[test]
fn c3_a_route_that_forwards_less_is_refused() {
    let yaml = edited(|c| {
        c["transforms"]["sluice_sysmon_route"]["route"]["forward"] = "false".into();
    });
    assert!(refused(&yaml).contains("sluice_sysmon_route"));
}

#[test]
fn c3_a_program_that_drops_events_on_error_is_refused() {
    let yaml = edited(|c| {
        c["transforms"]["sluice_sysmon"]["reroute_dropped"] = false.into();
    });
    assert!(refused(&yaml).contains("reroute_dropped"));
}

#[test]
fn c3_an_output_that_goes_nowhere_is_refused() {
    let yaml = edited(|c| {
        let sink = &mut c["sinks"]["sluice_sysmon_forward"]["inputs"];
        *sink = serde_json::json!([
            "sluice_sysmon_route.forward",
            "sluice_sysmon_route._unmatched"
        ]);
    });
    assert!(refused(&yaml).contains("sluice_sysmon.dropped"));
}

#[test]
fn c3_a_filter_or_an_aborting_remap_is_refused() {
    let filter = edited(|c| {
        c["transforms"]["drop_noise"] = serde_json::json!({
            "type": "filter", "inputs": ["sluice_sysmon_parse"], "condition": "false"
        });
    });
    assert!(refused(&filter).contains("drop_noise"));
    let abort = edited(|c| {
        c["transforms"]["sluice_sysmon_parse"]["source"] =
            ". = parse_json!(string!(.message))\nif .EventID == 10 { abort }".into();
    });
    assert!(refused(&abort).contains("sluice_sysmon_parse"));
}

#[test]
fn a_config_without_any_sluice_program_is_refused() {
    let yaml = edited(|c| {
        let transforms = c["transforms"].as_object_mut().unwrap();
        transforms.retain(|id, _| {
            !sample()
                .sources
                .iter()
                .any(|s| *id == format!("sluice_{}", s.id.as_str().replace('-', "_")))
        });
    });
    assert!(refused(&yaml).contains("no Sluice program"));
}
