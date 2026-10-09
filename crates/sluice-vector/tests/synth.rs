//! The generated VRL against the synthetic sample: classification agrees with discovery,
//! pre-filters are supersets of what rsigma matches, and reductions do what the guard allows.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{discovery, guarded, rules, sample, template};
use sluice_core::alert::RuleEngine;
use sluice_core::guard::{EffectiveRecipe, Route};
use sluice_core::ids::{SourceId, TemplateId};
use sluice_core::recipe::Reduction;
use sluice_core::reduce::{Outcome, Reducer};
use sluice_vector::{Plan, PredicateProgram, compile_reducer};

#[test]
fn vrl_classification_agrees_with_discovery_for_every_event() {
    let recipes: Vec<EffectiveRecipe> = discovery()
        .templates
        .iter()
        .map(|t| EffectiveRecipe::passthrough(t.id.clone()))
        .collect();
    let plans = discovery()
        .templates
        .iter()
        .zip(&recipes)
        .map(|(template, recipe)| Plan { template, recipe });
    let data_plane = compile_reducer(plans).expect("programs compile");

    let mut disagreements: BTreeMap<SourceId, Vec<(TemplateId, Option<TemplateId>)>> =
        BTreeMap::new();
    for event in &sample().events {
        let reduced = data_plane.reduce(event).expect("reduction succeeds");
        assert!(matches!(&reduced.outcome, Outcome::Forwarded(body) if *body == event.fields));
        let expected = &discovery().assignments[&event.id];
        if reduced.template.as_ref() != Some(expected) {
            disagreements
                .entry(event.source.clone())
                .or_default()
                .push((expected.clone(), reduced.template));
        }
    }
    assert!(disagreements.is_empty(), "{disagreements:#?}");
}

#[test]
fn prefilters_match_every_event_rsigma_alerts_on() {
    let engine = rules().engine(&sample().sources).expect("rules compile");
    let alerts = engine
        .alerts(&sample().events)
        .expect("evaluation succeeds");
    let events: BTreeMap<_, _> = sample().events.iter().map(|e| (e.id, e)).collect();
    let mut checked = 0;
    for requirement in rules().requirements() {
        let program = PredicateProgram::compile(&requirement.prefilter).expect("compiles");
        for alert in alerts.iter().filter(|a| a.rule == requirement.rule) {
            let event = events[&alert.event];
            assert!(
                program.matches(&event.fields).expect("runs"),
                "{} alerted on {} but its pre-filter does not match:\n{}",
                requirement.rule,
                alert.event,
                program.source()
            );
            checked += 1;
        }
    }
    // LSASS 1 + whoami 1 + encoded PowerShell 1 + SSH 30 + bad domain 1 + path traversal 4.
    // (The failed-logon base rule does not alert on its own: `generate` defaults to false.)
    assert_eq!(checked, 38);
}

#[test]
fn lossless_reduction_drops_boilerplate_and_empty_fields_only() {
    let logon = template("windows-security:4624:");
    let recipe = guarded(
        logon,
        vec![
            Reduction::DropFields {
                fields: BTreeSet::from(["Message".into(), "TimeCreated".into()]),
            },
            Reduction::DropEmptyFields,
        ],
    );
    assert_eq!(recipe.drop_fields.len(), 2, "{:#?}", recipe.adjustments);
    let data_plane = compile_reducer([Plan {
        template: logon,
        recipe: &recipe,
    }])
    .expect("program compiles");

    let mut saved = 0usize;
    let mut total = 0usize;
    for event in sample()
        .events
        .iter()
        .filter(|e| discovery().assignments[&e.id] == logon.id)
    {
        let reduced = data_plane.reduce(event).expect("reduction succeeds");
        let Outcome::Forwarded(body) = reduced.outcome else {
            panic!("lossless reductions never summarize");
        };
        assert!(!body.contains_key("Message") && !body.contains_key("TimeCreated"));
        assert!(
            !body.contains_key("RemoteCredentialGuard"),
            "null fields are dropped"
        );
        for (key, value) in &event.fields {
            if !["Message", "TimeCreated", "RemoteCredentialGuard"].contains(&key.as_str()) {
                assert_eq!(body.get(key), Some(value), "{key} must survive unchanged");
            }
        }
        let before = sluice_core::event::encoded_size(&event.fields);
        total += before;
        saved += before - sluice_core::event::encoded_size(&body);
    }
    assert!(
        saved * 2 > total,
        "expected over half saved, got {saved}/{total}"
    );
}

#[test]
fn rule_guided_routing_forwards_the_lsass_dump_and_summarizes_the_rest() {
    let access = template("sysmon:10:");
    let recipe = guarded(
        access,
        vec![Reduction::ForwardMatching {
            summary_keys: vec![
                "SourceImage".into(),
                "TargetImage".into(),
                "GrantedAccess".into(),
            ],
        }],
    );
    assert!(
        matches!(recipe.route, Route::ForwardMatching { .. }),
        "{:#?}",
        recipe.adjustments
    );
    let data_plane = compile_reducer([Plan {
        template: access,
        recipe: &recipe,
    }])
    .expect("program compiles");

    let dump: BTreeSet<_> = sample()
        .scenarios
        .iter()
        .find(|s| s.name == "lsass-access")
        .expect("scenario exists")
        .events
        .iter()
        .copied()
        .collect();
    let (mut forwarded, mut summarized) = (0, 0);
    for event in sample()
        .events
        .iter()
        .filter(|e| discovery().assignments[&e.id] == access.id)
    {
        match data_plane
            .reduce(event)
            .expect("reduction succeeds")
            .outcome
        {
            Outcome::Forwarded(_) => forwarded += 1,
            Outcome::Summarized => {
                assert!(
                    !dump.contains(&event.id),
                    "the LSASS dump must be forwarded"
                );
                summarized += 1;
            }
        }
    }
    // Defender's LSASS reads match the rule's positive selection (the exclusion is ignored by
    // the superset), so they are forwarded too; everything else is summarized.
    assert!(
        forwarded >= 1 && summarized > forwarded * 2,
        "{forwarded} forwarded, {summarized} summarized"
    );
}
