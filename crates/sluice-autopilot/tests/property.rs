//! The core property: whatever recipes are proposed, including deliberately unsafe ones, the data
//! plane the autopilot enforces raises exactly the alerts of the full data.
//!
//! Proposals are random per template: drop a random subset of its fields (rule fields included),
//! maybe drop empty fields, and maybe route (L2) or summarize (L3) it. The RNG is seeded, so the
//! test is deterministic.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use sluice_autopilot::{Helpers, Input, Settings, analyze_proposals};
use sluice_core::field::FieldPath;
use sluice_core::ids::TemplateId;
use sluice_core::proof::prove;
use sluice_core::recipe::{Provenance, Recipe, Reduction};
use sluice_core::template::Template;
use sluice_discover::{DiscoverConfig, Discovery, discover};
use sluice_rules::SigmaRules;
use sluice_synth::{Sample, SynthConfig, generate};

const SIGMA: [&str; 3] = [
    include_str!("../../../examples/rules/sigma/windows.yml"),
    include_str!("../../../examples/rules/sigma/linux.yml"),
    include_str!("../../../examples/rules/sigma/network.yml"),
];

fn sample() -> &'static Sample {
    static SAMPLE: OnceLock<Sample> = OnceLock::new();
    SAMPLE.get_or_init(|| {
        generate(&SynthConfig {
            scale_percent: 5,
            ..SynthConfig::default()
        })
    })
}

fn discovery() -> &'static Discovery {
    static DISCOVERY: OnceLock<Discovery> = OnceLock::new();
    DISCOVERY.get_or_init(|| {
        discover(
            DiscoverConfig::default(),
            &sample().sources,
            &sample().events,
        )
    })
}

fn rules() -> &'static SigmaRules {
    static RULES: OnceLock<SigmaRules> = OnceLock::new();
    RULES.get_or_init(|| SigmaRules::parse(SIGMA).expect("example rules parse"))
}

/// One template's random proposal: (field mask, drop empty, routing: 0 none, 1 L2, 2 L3).
type Choice = (u64, bool, u8);

fn proposal(template: &Template, (mask, drop_empty, routing): Choice) -> Option<Recipe> {
    let fields: BTreeSet<FieldPath> = template
        .fields
        .iter()
        .enumerate()
        .filter(|(i, _)| mask >> (i % 64) & 1 == 1)
        .map(|(_, f)| f.clone())
        .collect();
    let keys: Vec<FieldPath> = template.fields.iter().take(2).cloned().collect();
    let mut reductions = Vec::new();
    if !fields.is_empty() {
        reductions.push(Reduction::DropFields { fields });
    }
    if drop_empty {
        reductions.push(Reduction::DropEmptyFields);
    }
    match routing {
        1 if !keys.is_empty() => reductions.push(Reduction::ForwardMatching { summary_keys: keys }),
        2 if !keys.is_empty() => reductions.push(Reduction::Summarize { summary_keys: keys }),
        _ => {}
    }
    if reductions.is_empty() {
        return None;
    }
    let recipe = Recipe::new(
        template.id.clone(),
        reductions,
        Provenance::Ai {
            model: "chaos".into(),
        },
        "random",
    );
    Some(recipe.expect("at most one routing reduction"))
}

#[test]
fn any_proposals_yield_an_alert_preserving_data_plane() {
    let templates = &discovery().templates;
    let config = Config {
        cases: 6,
        failure_persistence: None,
        ..Config::default()
    };
    let mut runner =
        TestRunner::new_with_rng(config, TestRng::deterministic_rng(RngAlgorithm::ChaCha));
    let strategy = vec((any::<u64>(), any::<bool>(), 0u8..3), templates.len());
    let engine = rules().engine(&sample().sources).expect("rules compile");

    runner
        .run(&strategy, |choices| {
            let proposals: BTreeMap<TemplateId, Recipe> = templates
                .iter()
                .zip(choices)
                .filter_map(|(t, c)| proposal(t, c).map(|r| (t.id.clone(), r)))
                .collect();
            let input = Input {
                sources: &sample().sources,
                events: &sample().events,
                sigma: rules(),
                wazuh: None,
            };
            let analysis = analyze_proposals(
                input,
                discovery().clone(),
                proposals,
                &Settings::default(),
                Helpers::default(),
                Vec::new(),
            )
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
            // Independent re-proof of the enforced data plane, not the selection's own verdict.
            let proof = prove(&sample().events, &engine, &analysis.data_plane)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert!(
                proof.holds(),
                "missing {:?}, extra {:?}",
                proof.missing,
                proof.extra
            );
            Ok(())
        })
        .expect("property holds");
}
