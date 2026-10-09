//! The autopilot on the demo: synthetic sample, example Sigma rules, embedded recipes.

use std::sync::OnceLock;

use sluice_autopilot::{Analysis, Helpers, Input, RecipeBook, Settings, analyze};
use sluice_core::guard::{ContractRule, Route};
use sluice_core::proof::prove;
use sluice_core::reduce::{Outcome, Reducer};
use sluice_rules::SigmaRules;
use sluice_synth::{Sample, SynthConfig, generate};

const SIGMA: [&str; 3] = [
    include_str!("../../../examples/rules/sigma/windows.yml"),
    include_str!("../../../examples/rules/sigma/linux.yml"),
    include_str!("../../../examples/rules/sigma/network.yml"),
];

struct Demo {
    sample: Sample,
    rules: SigmaRules,
    analysis: Analysis,
}

fn demo() -> &'static Demo {
    static DEMO: OnceLock<Demo> = OnceLock::new();
    DEMO.get_or_init(|| {
        let sample = generate(&SynthConfig {
            scale_percent: 10,
            ..SynthConfig::default()
        });
        let rules = SigmaRules::parse(SIGMA).expect("example rules parse");
        let book = RecipeBook::embedded().expect("embedded recipes are valid");
        let input = Input {
            sources: &sample.sources,
            events: &sample.events,
            sigma: &rules,
            wazuh: None,
        };
        let analysis = analyze(input, &book, &Settings::default(), Helpers::default())
            .expect("analysis succeeds");
        Demo {
            sample,
            rules,
            analysis,
        }
    })
}

fn recipe_of(prefix: &str) -> &'static sluice_core::guard::EffectiveRecipe {
    let demo = demo();
    let index = demo
        .analysis
        .discovery
        .templates
        .iter()
        .position(|t| t.id.as_str().starts_with(prefix))
        .expect("template exists");
    &demo.analysis.selection.recipes[index]
}

#[test]
fn the_enforced_data_plane_is_independently_proven() {
    let demo = demo();
    let engine = demo
        .rules
        .engine(&demo.sample.sources)
        .expect("rules compile");
    let proof = prove(&demo.sample.events, &engine, &demo.analysis.data_plane).expect("proof runs");
    assert!(
        proof.holds(),
        "missing {:?}, extra {:?}",
        proof.missing,
        proof.extra
    );
    assert_eq!(proof.full_alerts.len(), proof.forwarded_alerts.len());
}

#[test]
fn the_demo_saves_more_than_half_of_the_bytes() {
    let total = demo().analysis.selection.proof.total;
    let saved = total.bytes_in - total.bytes_out;
    assert!(
        saved * 2 > total.bytes_in,
        "saved {saved} of {} bytes ({} of {} events summarized)",
        total.bytes_in,
        total.summarized,
        total.events
    );
}

#[test]
fn every_attack_event_reaches_the_siem() {
    let demo = demo();
    for scenario in &demo.sample.scenarios {
        for id in &scenario.events {
            let event = &demo.sample.events[usize::try_from(id.0).expect("small id")];
            let reduced = demo.analysis.data_plane.reduce(event).expect("reduces");
            assert!(
                matches!(reduced.outcome, Outcome::Forwarded(_)),
                "{} event {id} was summarized",
                scenario.name
            );
        }
    }
}

#[test]
fn rare_templates_are_left_alone() {
    let rare = recipe_of("windows-security:4720:");
    assert!(rare.is_passthrough());
    assert!(
        rare.adjustments
            .iter()
            .any(|a| a.contract == ContractRule::RareNeverCut)
    );
}

#[test]
fn rule_guided_routing_is_enforced_where_rules_allow() {
    assert!(matches!(
        recipe_of("sysmon:7:").route,
        Route::ForwardMatching { .. }
    ));
    assert!(matches!(
        recipe_of("sysmon:10:").route,
        Route::ForwardMatching { .. }
    ));
    // The failed-logon correlation no longer blocks WFP events (ADR 0004).
    assert!(matches!(
        recipe_of("windows-security:5156:").route,
        Route::ForwardMatching { .. }
    ));
}

#[test]
fn no_recipe_was_rolled_back_on_the_demo() {
    let rolled_back: Vec<_> = demo()
        .analysis
        .selection
        .recipes
        .iter()
        .filter(|r| {
            r.adjustments
                .iter()
                .any(|a| a.contract == ContractRule::ProvenBeforeEnforced)
        })
        .map(|r| r.template.as_str())
        .collect();
    assert!(rolled_back.is_empty(), "{rolled_back:?}");
    assert!(
        demo().analysis.problems.is_empty(),
        "{:?}",
        demo().analysis.problems
    );
}
