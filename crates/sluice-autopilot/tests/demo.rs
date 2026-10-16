//! The autopilot on the demo: synthetic sample, example Sigma rules, embedded recipes.

use std::sync::OnceLock;

use sluice_autopilot::{
    Analysis, Helpers, Input, PLAN_FORMAT, Placement, RecipeBook, Report, SavingsPlan, Settings,
    TemplatePlan, analyze,
};
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
            sentinel: None,
        };
        let analysis = analyze(
            input,
            &book,
            &Settings::with_complete_rules(),
            Helpers::default(),
        )
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

fn plan() -> SavingsPlan {
    let demo = demo();
    let input = Input {
        sources: &demo.sample.sources,
        events: &demo.sample.events,
        sigma: &demo.rules,
        wazuh: None,
        sentinel: None,
    };
    let report = Report::new(&demo.analysis, input);
    SavingsPlan::new(&demo.analysis, &report, &demo.sample.sources)
}

fn planned(plan: &SavingsPlan, prefix: &str) -> TemplatePlan {
    plan.sources
        .iter()
        .flat_map(|s| &s.templates)
        .find(|t| t.id.starts_with(prefix))
        .expect("template in the plan")
        .clone()
}

#[test]
fn the_plan_lists_every_source_and_kind_of_event_with_the_proof() {
    let plan = plan();
    assert_eq!(plan.format, PLAN_FORMAT);
    assert!(plan.proof.holds);
    assert_eq!(plan.proof.alerts_full, plan.proof.alerts_forwarded);
    assert!(plan.proof.alerts_full > 0 && plan.proof.note.is_none());
    assert_eq!(plan.total, demo().analysis.selection.proof.total);
    let ids: Vec<&str> = plan.sources.iter().map(|s| s.id.as_str()).collect();
    let expected: Vec<&str> = demo()
        .sample
        .sources
        .iter()
        .map(|s| s.id.as_str())
        .collect();
    assert_eq!(ids, expected, "every source, in the configured order");
    let templates: usize = plan.sources.iter().map(|s| s.templates.len()).sum();
    assert_eq!(templates, demo().analysis.discovery.templates.len());
    for source in &plan.sources {
        let sizes: Vec<u64> = source.templates.iter().map(|t| t.volume.bytes_in).collect();
        assert!(
            sizes.windows(2).all(|w| w[0] >= w[1]),
            "largest first in {}",
            source.id
        );
    }
}

#[test]
fn counting_runs_only_in_a_pipeline_and_removing_fields_also_in_the_siem() {
    let plan = plan();
    let counted = planned(&plan, "sysmon:10:");
    assert!(counted.count_instead.is_some());
    assert_eq!(counted.runs_in, [Placement::Pipeline]);

    let removed = plan
        .sources
        .iter()
        .flat_map(|s| &s.templates)
        .find(|t| t.count_instead.is_none() && !t.remove_fields.is_empty())
        .expect("a template that only removes fields");
    assert_eq!(
        removed.runs_in,
        [Placement::Pipeline, Placement::SiemIngest]
    );

    let rare = planned(&plan, "windows-security:4720:");
    assert!(rare.runs_in.is_empty(), "sent unchanged");

    // The report says the same, in words.
    let demo = demo();
    let input = Input {
        sources: &demo.sample.sources,
        events: &demo.sample.events,
        sigma: &demo.rules,
        wazuh: None,
        sentinel: None,
    };
    let report = Report::new(&demo.analysis, input);
    let row = |id: &str| report.templates.iter().find(|t| t.id == id).expect("a row");
    assert!(
        row(&counted.id)
            .runs_in
            .as_deref()
            .is_some_and(|r| r.contains("pipeline tool such as Vector"))
    );
    assert!(
        row(&removed.id)
            .runs_in
            .as_deref()
            .is_some_and(|r| r.contains("SIEM's own ingestion"))
    );
    assert_eq!(row(&rare.id).runs_in, None);
    assert!(
        rare.reasons.iter().any(|r| r.contains("rare")),
        "{:?}",
        rare.reasons
    );
}

#[test]
fn the_plan_is_json_a_tool_can_read() {
    let json: serde_json::Value =
        serde_json::from_str(&plan().to_json().expect("serializes")).expect("valid JSON");
    assert_eq!(json["format"], PLAN_FORMAT);
    assert_eq!(json["proof"]["rules_basis"], "self_contained");
    let template = &json["sources"][0]["templates"][0];
    for key in ["id", "shape", "volume", "runs_in"] {
        assert!(template.get(key).is_some(), "{key}: {template}");
    }
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
