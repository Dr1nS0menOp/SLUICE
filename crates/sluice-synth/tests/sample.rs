//! Properties of generated samples that the demo and the proof tests rely on.

use std::collections::BTreeSet;

use sluice_core::event::Timestamp;
use sluice_core::source::SourceFormat;
use sluice_synth::{SynthConfig, generate};

fn small() -> SynthConfig {
    SynthConfig {
        scale_percent: 10,
        ..SynthConfig::default()
    }
}

#[test]
fn same_config_gives_identical_sample() {
    assert_eq!(generate(&small()), generate(&small()));
}

#[test]
fn different_seed_gives_different_sample() {
    let other = SynthConfig { seed: 2, ..small() };
    assert_ne!(generate(&small()).events, generate(&other).events);
}

#[test]
fn events_are_time_ordered_with_sequential_ids_inside_the_window() {
    let config = small();
    let sample = generate(&config);
    let end = Timestamp(config.start.0 + config.duration_secs + 120);
    for (n, pair) in sample.events.windows(2).enumerate() {
        assert!(
            pair[0].timestamp <= pair[1].timestamp,
            "out of order at {n}"
        );
    }
    for (n, event) in (0u64..).zip(&sample.events) {
        assert_eq!(event.id.0, n);
        assert!(event.timestamp >= config.start && event.timestamp <= end);
    }
}

#[test]
fn every_event_belongs_to_a_declared_source() {
    let sample = generate(&small());
    let declared: BTreeSet<_> = sample.sources.iter().map(|s| &s.id).collect();
    assert_eq!(declared.len(), 6);
    assert!(sample.events.iter().all(|e| declared.contains(&e.source)));
}

#[test]
fn text_sources_carry_their_raw_line() {
    let sample = generate(&small());
    for source in &sample.sources {
        let SourceFormat::Text { field } = &source.format else {
            continue;
        };
        let events = sample.events.iter().filter(|e| e.source == source.id);
        for event in events {
            assert!(
                event
                    .fields
                    .get(field.as_str())
                    .is_some_and(serde_json::Value::is_string)
            );
        }
    }
}

#[test]
fn every_scenario_is_planted_with_its_full_event_count() {
    let sample = generate(&small());
    let counts: Vec<(&str, usize)> = sample
        .scenarios
        .iter()
        .map(|s| (s.name.as_str(), s.events.len()))
        .collect();
    assert_eq!(
        counts,
        [
            ("failed-logon-burst", 12),
            ("lsass-access", 3),
            ("encoded-powershell", 2),
            ("ssh-brute-force", 31),
            ("bad-domain-lookup", 1),
            ("path-traversal", 4),
        ]
    );
}

#[test]
fn scenarios_do_not_depend_on_scale() {
    let tiny = SynthConfig {
        scale_percent: 1,
        ..SynthConfig::default()
    };
    let small_sample = generate(&small());
    let tiny_sample = generate(&tiny);
    let sizes = |s: &sluice_synth::Sample| {
        s.scenarios
            .iter()
            .map(|x| x.events.len())
            .collect::<Vec<_>>()
    };
    assert_eq!(sizes(&small_sample), sizes(&tiny_sample));
}

#[test]
fn default_volume_is_about_eighty_thousand_events_per_hour() {
    let sample = generate(&SynthConfig::default());
    assert!(
        (75_000..=85_000).contains(&sample.events.len()),
        "{}",
        sample.events.len()
    );
}
