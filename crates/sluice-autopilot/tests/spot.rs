//! Spot checks with the SIEM's own per-event rules (as Wazuh `logtest` provides): a recipe that
//! changes what such a rule sees is rolled back, others stay.

use std::collections::BTreeSet;

use serde_json::{Map, Value};
use sluice_autopilot::{Helpers, Input, RecipeBook, Settings, analyze};
use sluice_core::alert::{EngineError, EventRules};
use sluice_core::guard::{ContractRule, Reason};
use sluice_core::ids::{RuleId, TemplateId};
use sluice_rules::SigmaRules;
use sluice_synth::{SynthConfig, generate};

/// A SIEM rule Sluice cannot see: it alerts on logon events whose rendered `Message` is present.
struct MessageRule;

impl EventRules for MessageRule {
    fn fired(&self, fields: &Map<String, Value>) -> Result<BTreeSet<RuleId>, EngineError> {
        let logon = fields.get("EventID") == Some(&Value::from(4624));
        let rule = RuleId::new("wazuh:900001");
        Ok(if logon && fields.contains_key("Message") {
            BTreeSet::from([rule])
        } else {
            BTreeSet::new()
        })
    }

    fn fired_line(&self, _line: &str) -> Result<BTreeSet<RuleId>, EngineError> {
        Ok(BTreeSet::new())
    }
}

/// A text rule (like Wazuh's syslog rules) on cron session lines, which only matches the raw
/// line: wrapped in JSON it would never fire.
struct CronRule;

impl EventRules for CronRule {
    fn fired(&self, _fields: &Map<String, Value>) -> Result<BTreeSet<RuleId>, EngineError> {
        Ok(BTreeSet::new())
    }

    fn fired_line(&self, line: &str) -> Result<BTreeSet<RuleId>, EngineError> {
        Ok(if line.contains("pam_unix(cron:session)") {
            BTreeSet::from([RuleId::new("wazuh:900002")])
        } else {
            BTreeSet::new()
        })
    }
}

fn analyze_with(rules: &dyn EventRules) -> sluice_autopilot::Analysis {
    let sample = generate(&SynthConfig {
        // Large enough that linux-auth templates are not rare (contract rule 4 leaves rare ones alone).
        scale_percent: 40,
        ..SynthConfig::default()
    });
    let sigma = SigmaRules::parse([
        include_str!("../../../examples/rules/sigma/windows.yml"),
        include_str!("../../../examples/rules/sigma/linux.yml"),
    ])
    .expect("rules");
    let input = Input {
        sources: &sample.sources,
        events: &sample.events,
        sigma: &sigma,
        wazuh: None,
    };
    let helpers = Helpers {
        event_rules: Some(rules),
        ..Helpers::default()
    };
    analyze(
        input,
        &RecipeBook::embedded().expect("recipes"),
        &Settings::default(),
        helpers,
    )
    .expect("analysis")
}

#[test]
fn text_sources_are_checked_as_raw_lines() {
    let analysis = analyze_with(&CronRule);
    let check = analysis.spot_check.as_ref().expect("spot check ran");
    assert!(
        check.fired > 0,
        "the cron rule fires on the raw lines: {check:?}"
    );
    let rolled: Vec<&str> = check.rolled_back.iter().map(TemplateId::as_str).collect();
    assert!(
        rolled.iter().any(|t| t.starts_with("linux-auth:")),
        "summarizing cron sessions would hide the SIEM's alerts: {rolled:?}"
    );
    assert!(analysis.selection.proof.holds());
}

#[test]
fn a_recipe_the_siem_disagrees_with_is_rolled_back() {
    let sample = generate(&SynthConfig {
        scale_percent: 5,
        ..SynthConfig::default()
    });
    let rules = SigmaRules::parse([include_str!("../../../examples/rules/sigma/windows.yml")])
        .expect("rules");
    let input = Input {
        sources: &sample.sources,
        events: &sample.events,
        sigma: &rules,
        wazuh: None,
    };
    let helpers = Helpers {
        event_rules: Some(&MessageRule),
        ..Helpers::default()
    };
    let analysis = analyze(
        input,
        &RecipeBook::embedded().expect("recipes"),
        &Settings::default(),
        helpers,
    )
    .expect("analysis");

    let check = analysis.spot_check.as_ref().expect("spot check ran");
    assert!(check.checked > 0);
    let rolled: Vec<&str> = check.rolled_back.iter().map(TemplateId::as_str).collect();
    assert_eq!(rolled.len(), 1, "{rolled:?}");
    assert!(rolled[0].starts_with("windows-security:4624:"));

    let logon = analysis
        .selection
        .recipes
        .iter()
        .find(|r| r.template.as_str() == rolled[0])
        .expect("recipe exists");
    assert!(logon.is_passthrough());
    assert!(
        logon
            .adjustments
            .iter()
            .any(|a| a.contract == ContractRule::ProvenBeforeEnforced
                && a.reason == Reason::StatelessRulesChanged)
    );
    // Other Windows templates keep their recipe.
    assert!(
        analysis.selection.recipes.iter().any(|r| r
            .template
            .as_str()
            .starts_with("windows-security:4634:")
            && !r.is_passthrough())
    );
    assert!(analysis.selection.proof.holds());
}
