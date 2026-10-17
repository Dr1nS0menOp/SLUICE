//! Problems reading any rule set reach the analysis, so the report shows them, not only the
//! terminal of whoever ran it.

use sluice_autopilot::{Elastic, Helpers, Input, RecipeBook, Report, Sentinel, Settings, analyze};
use sluice_rules::{ElasticRules, SentinelRules, SigmaRules};
use sluice_synth::{SynthConfig, generate};

#[test]
fn sentinel_and_elastic_rule_problems_are_listed_in_the_analysis() {
    let sample = generate(&SynthConfig {
        scale_percent: 2,
        ..SynthConfig::default()
    });
    let sigma = SigmaRules::parse([include_str!("../../../examples/rules/sigma/linux.yml")])
        .expect("rules parse");
    let sentinel = SentinelRules::parse([("broken.yaml", "query: [unclosed")]);
    assert_eq!(sentinel.problems().len(), 1);
    let elastic = ElasticRules::parse([("broken.ndjson", "{\"rule_id\":\"x\"}\n")]);
    assert_eq!(elastic.problems().len(), 1);
    let input = Input {
        sources: &sample.sources,
        events: &sample.events,
        sigma: &sigma,
        wazuh: None,
        sentinel: Some(Sentinel {
            rules: &sentinel,
            engine: None,
        }),
        elastic: Some(Elastic {
            rules: &elastic,
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
    for file in ["broken.yaml", "broken.ndjson"] {
        assert!(
            analysis.problems.iter().any(|p| p.contains(file)),
            "{file}: {:?}",
            analysis.problems
        );
    }
    let report = Report::new(&analysis, input);
    assert!(
        report
            .rules
            .iter()
            .any(|(set, n)| set == "Elastic" && *n == 1)
    );
    assert!(report.rule_rows.iter().any(|r| r.set == "Elastic"));
}
