//! A text source read with its parser pack (ADR 0043): rules on the fields the SIEM parses out
//! of the line bound what is counted, and the proof evaluates them on the same parse.

use sluice_autopilot::{Helpers, Input, RecipeBook, Settings, analyze};
use sluice_core::guard::{Reason, Route};
use sluice_core::source::Source;
use sluice_rules::{ParserBook, SigmaRules};
use sluice_synth::{SynthConfig, generate};

const SIGMA: [&str; 3] = [
    include_str!("../../../examples/rules/sigma/windows.yml"),
    include_str!("../../../examples/rules/sigma/linux.yml"),
    include_str!("../../../examples/rules/sigma/network.yml"),
];

/// The demo's analysis with its sources as given: their packs resolved, or only named.
fn nginx_routes(resolve: bool) -> (Vec<(Route, Vec<Reason>)>, usize, bool) {
    let sample = generate(&SynthConfig {
        scale_percent: 10,
        ..SynthConfig::default()
    });
    let mut sources: Vec<Source> = sample.sources.clone();
    if resolve {
        ParserBook::embedded()
            .expect("the built-in packs are valid")
            .resolve(&mut sources)
            .expect("the demo's packs exist");
    }
    let rules = SigmaRules::parse(SIGMA).expect("example rules parse");
    let analysis = analyze(
        Input {
            sources: &sources,
            events: &sample.events,
            sigma: &rules,
            wazuh: None,
            sentinel: None,
            elastic: None,
            splunk: None,
        },
        &RecipeBook::embedded().expect("embedded recipes are valid"),
        &Settings::with_complete_rules(),
        Helpers::default(),
    )
    .expect("analysis succeeds");
    let routes = analysis
        .discovery
        .templates
        .iter()
        .zip(&analysis.selection.recipes)
        .filter(|(t, _)| t.source.as_str() == "nginx" && t.stats.events >= 100)
        .map(|(_, recipe)| {
            (
                recipe.route.clone(),
                recipe
                    .adjustments
                    .iter()
                    .map(|a| a.reason.clone())
                    .collect(),
            )
        })
        .collect();
    (
        routes,
        analysis.selection.proof.full_alerts.len(),
        analysis.selection.proof.holds(),
    )
}

#[test]
fn c3_with_its_parser_a_rule_on_a_parsed_field_bounds_what_is_counted() {
    let (routes, alerts, holds) = nginx_routes(true);
    assert!(holds);
    assert_ne!(routes.len(), 0);
    for (route, _) in &routes {
        let Route::ForwardMatching { prefilter, .. } = route else {
            panic!("an access line no rule could match is counted: {route:?}");
        };
        let text = format!("{prefilter:?}");
        assert!(
            text.contains("cs-user-agent"),
            "the parsed field bounds it: {text}"
        );
    }
    let (_, without, _) = nginx_routes(false);
    assert!(
        alerts > without,
        "the scanner rule fires on the parsed user agent"
    );
}

#[test]
fn c3_without_its_parser_a_rule_on_a_parsed_field_keeps_every_line() {
    let (routes, _, holds) = nginx_routes(false);
    assert!(holds);
    for (route, reasons) in &routes {
        assert_eq!(route, &Route::ForwardAll);
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, Reason::FieldsParsedFromText { .. })),
            "{reasons:?}"
        );
    }
}
