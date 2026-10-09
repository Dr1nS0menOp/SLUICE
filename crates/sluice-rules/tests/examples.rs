//! The example rules against the synthetic sample: every planted attack is detected, benign
//! look-alikes are not, and requirements capture what the guardrails need.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use sluice_core::alert::{Alert, RuleEngine};
use sluice_core::ids::{EventId, RuleId};
use sluice_core::rules::{RequiredFields, RuleRequirements};
use sluice_rules::{SigmaRules, WazuhRules};
use sluice_synth::{Sample, SynthConfig, generate};

const SIGMA: [&str; 3] = [
    include_str!("../../../examples/rules/sigma/windows.yml"),
    include_str!("../../../examples/rules/sigma/linux.yml"),
    include_str!("../../../examples/rules/sigma/network.yml"),
];
const WAZUH: &str = include_str!("../../../examples/rules/wazuh/local_rules.xml");

const FAILED_LOGON: &str = "sigma:5c0f3b1e-8f0a-4d7e-9a61-2d4b8c1e7f01";
const FAILED_LOGON_BURST: &str = "sigma:5c0f3b1e-8f0a-4d7e-9a61-2d4b8c1e7f02";
const LSASS: &str = "sigma:5c0f3b1e-8f0a-4d7e-9a61-2d4b8c1e7f03";
const WHOAMI: &str = "sigma:5c0f3b1e-8f0a-4d7e-9a61-2d4b8c1e7f04";
const ENCODED_POWERSHELL: &str = "sigma:5c0f3b1e-8f0a-4d7e-9a61-2d4b8c1e7f05";
const SSH_UNKNOWN_USER: &str = "sigma:5c0f3b1e-8f0a-4d7e-9a61-2d4b8c1e7f11";
const BAD_DOMAIN: &str = "sigma:5c0f3b1e-8f0a-4d7e-9a61-2d4b8c1e7f21";
const PATH_TRAVERSAL: &str = "sigma:5c0f3b1e-8f0a-4d7e-9a61-2d4b8c1e7f22";

fn sample() -> &'static Sample {
    static SAMPLE: OnceLock<Sample> = OnceLock::new();
    SAMPLE.get_or_init(|| {
        generate(&SynthConfig {
            scale_percent: 10,
            ..SynthConfig::default()
        })
    })
}

fn rules() -> &'static SigmaRules {
    static RULES: OnceLock<SigmaRules> = OnceLock::new();
    RULES.get_or_init(|| SigmaRules::parse(SIGMA).expect("example Sigma rules parse"))
}

fn alerts() -> &'static BTreeSet<Alert> {
    static ALERTS: OnceLock<BTreeSet<Alert>> = OnceLock::new();
    ALERTS.get_or_init(|| {
        let engine = rules().engine(&sample().sources).expect("rules compile");
        engine
            .alerts(&sample().events)
            .expect("evaluation succeeds")
    })
}

fn fired(rule: &str) -> BTreeSet<EventId> {
    alerts()
        .iter()
        .filter(|a| a.rule.as_str() == rule)
        .map(|a| a.event)
        .collect()
}

fn scenario(name: &str) -> BTreeSet<EventId> {
    let scenario = sample().scenarios.iter().find(|s| s.name == name);
    scenario
        .expect("scenario exists")
        .events
        .iter()
        .copied()
        .collect()
}

fn requirement(rule: &str) -> &'static RuleRequirements {
    let found = rules()
        .requirements()
        .iter()
        .find(|r| r.rule.as_str() == rule);
    found.expect("requirement exists")
}

#[test]
fn example_rules_load_without_problems() {
    assert!(rules().problems().is_empty(), "{:?}", rules().problems());
    assert_eq!(rules().requirements().len(), 7);
}

#[test]
fn failed_logon_burst_correlation_fires_on_the_burst() {
    let burst = scenario("failed-logon-burst");
    let correlation = fired(FAILED_LOGON_BURST);
    assert!(!correlation.is_empty());
    assert!(correlation.is_subset(&burst), "{correlation:?}");
    // Sigma's `generate` defaults to false: rules referenced by a correlation stop alerting on
    // their own.
    assert!(fired(FAILED_LOGON).is_empty());
}

#[test]
fn lsass_rule_catches_the_dump_but_not_defender() {
    let dump = scenario("lsass-access");
    let lsass = fired(LSASS);
    assert_eq!(
        lsass.len(),
        1,
        "Defender's 0x1410 reads must be filtered: {lsass:?}"
    );
    assert!(lsass.is_subset(&dump));
}

#[test]
fn discovery_and_encoded_powershell_are_detected() {
    let attack = scenario("encoded-powershell");
    let detected: BTreeSet<_> = fired(WHOAMI)
        .union(&fired(ENCODED_POWERSHELL))
        .copied()
        .collect();
    assert_eq!(detected, attack);
}

#[test]
fn ssh_keyword_rule_fires_only_on_the_brute_force() {
    let attempts = fired(SSH_UNKNOWN_USER);
    assert_eq!(attempts.len(), 30);
    assert!(attempts.is_subset(&scenario("ssh-brute-force")));
}

#[test]
fn bad_domain_and_path_traversal_are_detected() {
    assert_eq!(fired(BAD_DOMAIN), scenario("bad-domain-lookup"));
    assert_eq!(fired(PATH_TRAVERSAL), scenario("path-traversal"));
}

#[test]
fn requirements_capture_filters_correlations_and_keywords() {
    let lsass = requirement(LSASS);
    assert_eq!(
        lsass.fields,
        RequiredFields::known([
            "GrantedAccess".into(),
            "SourceImage".into(),
            "TargetImage".into()
        ])
    );
    assert!(!lsass.stateful);

    let failed_logon = requirement(FAILED_LOGON);
    assert!(failed_logon.stateful, "a correlation counts its events");
    assert_eq!(
        failed_logon.fields,
        RequiredFields::known(["EventID".into(), "TargetUserName".into()])
    );

    let ssh = requirement(SSH_UNKNOWN_USER);
    assert!(ssh.matches_raw_text);
    assert_eq!(
        ssh.fields,
        RequiredFields::Unknown,
        "keywords scan every field"
    );
}

#[test]
fn evaluation_is_deterministic() {
    let engine = rules().engine(&sample().sources).unwrap();
    assert_eq!(&engine.alerts(&sample().events).unwrap(), alerts());
}

#[test]
fn unparseable_document_becomes_an_opaque_requirement() {
    let broken = "title: no detection section\nlogsource:\n    product: x\n";
    let rules = SigmaRules::parse([broken]).unwrap();
    assert_eq!(rules.problems().len(), 1, "{:?}", rules.problems());
    assert_eq!(
        rules.requirements(),
        [RuleRequirements::opaque("sigma:unparsed:0".into())]
    );
}

#[test]
fn wazuh_examples_parse() {
    let wazuh = WazuhRules::parse([WAZUH]).unwrap();
    assert!(wazuh.problems().is_empty(), "{:?}", wazuh.problems());
    let ids: Vec<&RuleId> = wazuh.requirements().iter().map(|r| &r.rule).collect();
    assert_eq!(ids.len(), 4);
    let stateful: Vec<_> = wazuh
        .requirements()
        .iter()
        .filter(|r| r.stateful)
        .map(|r| r.rule.as_str())
        .collect();
    assert_eq!(stateful, ["wazuh:100101", "wazuh:100111"]);
}
