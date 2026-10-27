//! Problems reading any rule set reach the analysis, so the report shows them, not only the
//! terminal of whoever ran it.

use sluice_autopilot::{
    Elastic, Helpers, Input, RecipeBook, Report, SavingsPlan, Sentinel, Settings, analyze,
};
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
    for needle in ["broken.yaml", "broken.ndjson"] {
        assert!(
            analysis.problems.iter().any(|p| p.message.contains(needle)),
            "{needle}: {:?}",
            analysis.problems
        );
    }
    let report = Report::new(&analysis, input);
    for set in ["Sentinel", "Elastic"] {
        assert!(
            report.rules.iter().any(|(s, n)| s == set && *n == 1),
            "{set}"
        );
        assert!(report.rule_rows.iter().any(|r| r.set == set), "{set}");
    }
    // And in `plan.json`, for tools that act on them.
    let plan = SavingsPlan::new(&analysis, &report, &sample.sources);
    for needle in ["broken.yaml", "broken.ndjson"] {
        assert!(
            plan.problems
                .iter()
                .any(|p| p.kind == "unreadable" && p.message.contains(needle)),
            "{needle}: {:?}",
            plan.problems
        );
    }
}
