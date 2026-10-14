//! Problems reading any rule set reach the analysis, so the report shows them, not only the
//! terminal of whoever ran it.

use sluice_autopilot::{Helpers, Input, RecipeBook, Sentinel, Settings, analyze};
use sluice_rules::{SentinelRules, SigmaRules};
use sluice_synth::{SynthConfig, generate};

#[test]
fn sentinel_rule_problems_are_listed_in_the_analysis() {
    let sample = generate(&SynthConfig {
        scale_percent: 2,
        ..SynthConfig::default()
    });
    let sigma = SigmaRules::parse([include_str!("../../../examples/rules/sigma/linux.yml")])
        .expect("rules parse");
    let sentinel = SentinelRules::parse([("broken.yaml", "query: [unclosed")]);
    assert_eq!(sentinel.problems().len(), 1);
    let input = Input {
        sources: &sample.sources,
        events: &sample.events,
        sigma: &sigma,
        wazuh: None,
        sentinel: Some(Sentinel {
            rules: &sentinel,
            engine: None,
        }),
    };
    let analysis = analyze(
        input,
        &RecipeBook::embedded().expect("recipes"),
        &Settings::default(),
        Helpers::default(),
    )
    .expect("analysis");
    assert!(
        analysis.problems.iter().any(|p| p.contains("broken.yaml")),
        "{:?}",
        analysis.problems
    );
}
