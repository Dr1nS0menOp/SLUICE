//! Discovery on the synthetic sample: the templates later steps rely on.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use sluice_core::template::Template;
use sluice_discover::{DiscoverConfig, Discovery, discover};
use sluice_synth::{Sample, SynthConfig, generate};

fn sample() -> &'static Sample {
    static SAMPLE: OnceLock<Sample> = OnceLock::new();
    SAMPLE.get_or_init(|| {
        generate(&SynthConfig {
            scale_percent: 10,
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

fn templates_of(source: &str) -> Vec<&'static Template> {
    discovery()
        .templates
        .iter()
        .filter(|t| t.source.as_str() == source)
        .collect()
}

fn template(id_prefix: &str) -> &'static Template {
    let matches: Vec<_> = discovery()
        .templates
        .iter()
        .filter(|t| t.id.as_str().starts_with(id_prefix))
        .collect();
    assert_eq!(matches.len(), 1, "expected one template for {id_prefix}");
    matches[0]
}

#[test]
fn every_event_is_assigned_to_a_known_template() {
    let d = discovery();
    assert_eq!(d.assignments.len(), sample().events.len());
    let known: Vec<_> = d.templates.iter().map(|t| &t.id).collect();
    assert!(d.assignments.values().all(|id| known.contains(&id)));
}

#[test]
fn template_stats_add_up_to_the_sample() {
    let d = discovery();
    let total: u64 = d.templates.iter().map(|t| t.stats.events).sum();
    assert_eq!(total, u64::try_from(sample().events.len()).unwrap());
    let mut per_source: BTreeMap<_, u64> = BTreeMap::new();
    for t in &d.templates {
        *per_source.entry(&t.source).or_default() += t.stats.events;
    }
    for t in &d.templates {
        assert_eq!(t.stats.source_events, per_source[&t.source]);
    }
}

fn labels(source: &str) -> Vec<String> {
    let mut labels: Vec<String> = templates_of(source)
        .iter()
        .map(|t| {
            let label = t.id.as_str().split(':').nth(1);
            label
                .expect("JSON template ids are source:label:hash")
                .to_owned()
        })
        .collect();
    labels.sort_by_key(|label| label.parse::<u32>().unwrap_or(u32::MAX));
    labels
}

#[test]
fn windows_event_ids_become_one_template_each() {
    assert_eq!(
        labels("windows-security"),
        ["4624", "4625", "4634", "4672", "4720", "5156"]
    );
    assert_eq!(labels("sysmon"), ["1", "3", "7", "10", "11", "22"]);
}

#[test]
fn firewall_actions_are_separate_templates() {
    assert_eq!(templates_of("firewall").len(), 2);
    assert_eq!(
        template("firewall:pass:").stats.events + template("firewall:block:").stats.events,
        {
            let n = sample()
                .events
                .iter()
                .filter(|e| e.source.as_str() == "firewall")
                .count();
            u64::try_from(n).unwrap()
        }
    );
}

#[test]
fn rendered_messages_are_detected_as_free_text() {
    let logon = template("windows-security:4624:");
    assert!(logon.text_fields.contains("Message"));
    assert!(!logon.text_fields.contains("TargetUserName"));
    assert_eq!(logon.logsource.service.as_deref(), Some("security"));
}

#[test]
fn text_sources_cluster_into_few_templates() {
    for source in ["linux-auth", "nginx"] {
        let templates = templates_of(source);
        assert!(
            (2..=20).contains(&templates.len()),
            "{source}: {} templates: {:#?}",
            templates.len(),
            templates.iter().map(|t| &t.pattern).collect::<Vec<_>>()
        );
        assert!(templates.iter().all(|t| t.text_fields.contains("message")));
    }
}

#[test]
fn brute_force_lines_share_a_template_with_a_wildcard_user() {
    let brute_force = &sample()
        .scenarios
        .iter()
        .find(|s| s.name == "ssh-brute-force")
        .unwrap()
        .events;
    let failed = &discovery().assignments[&brute_force[0]];
    let same: Vec<_> = brute_force[..30]
        .iter()
        .map(|id| &discovery().assignments[id])
        .collect();
    assert!(same.iter().all(|id| *id == failed));
    let pattern = &discovery()
        .templates
        .iter()
        .find(|t| &t.id == failed)
        .unwrap()
        .pattern;
    assert!(
        pattern.contains("Failed password for invalid user <*> from"),
        "{pattern}"
    );
}

/// Drain merges health checks with other short requests (see `docs/notes/drain.md`), but all
/// health checks must at least land in one template.
#[test]
fn health_checks_land_in_one_template() {
    let ids: std::collections::BTreeSet<_> = sample()
        .events
        .iter()
        .filter(|e| {
            e.fields
                .get("message")
                .and_then(|m| m.as_str())
                .is_some_and(|m| m.contains("/healthz"))
        })
        .map(|e| &discovery().assignments[&e.id])
        .collect();
    assert_eq!(ids.len(), 1, "{ids:?}");
}

#[test]
fn rare_events_stay_rare() {
    assert_eq!(template("windows-security:4720:").stats.events, 2);
}

#[test]
fn discovery_is_deterministic() {
    let again = discover(
        DiscoverConfig::default(),
        &sample().sources,
        &sample().events,
    );
    assert_eq!(&again, discovery());
}
