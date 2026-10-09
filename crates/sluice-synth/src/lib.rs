//! Deterministic synthetic security logs.
//!
//! [`generate`] produces an hour (by default) of logs from a small fictional company network:
//! Windows Security, Sysmon, Linux auth, a firewall, DNS and nginx. The volumes and the "fat" are
//! realistic: rendered `Message` boilerplate, empty fields, duplicate timestamps and originals,
//! constant agent envelopes, and high-volume noise such as Sysmon image loads and health checks.
//!
//! The sample also contains a few attacks ([`Scenario`]) that example rules detect. Sluice must
//! forward their events in full, whatever it cuts.
//!
//! The same [`SynthConfig`] always yields byte-identical output.

mod fields;
mod rng;
mod sources;
mod world;

use std::collections::BTreeMap;

use sluice_core::event::{Event, Timestamp};
use sluice_core::field::FieldPath;
use sluice_core::ids::{EventId, SourceId};
use sluice_core::logsource::LogSource;

use crate::rng::Rng;
use crate::sources::{Ctx, Draft};

/// What to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynthConfig {
    /// Seed for every random choice.
    pub seed: u64,
    /// Start of the time window.
    pub start: Timestamp,
    /// Length of the time window in seconds.
    pub duration_secs: i64,
    /// Volume relative to the default (100 = about 80 000 events per hour).
    pub scale_percent: u64,
}

impl Default for SynthConfig {
    fn default() -> Self {
        Self {
            seed: 1,
            start: Timestamp(1_791_619_200), // 2026-10-10T08:00:00Z
            duration_secs: 3_600,
            scale_percent: 100,
        }
    }
}

/// How a source's events are encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Format {
    /// Structured JSON fields.
    Json,
    /// A raw text line, held in `field`, plus envelope fields.
    Text {
        /// Field that holds the raw line.
        field: FieldPath,
    },
}

/// A source in the sample and what it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceInfo {
    /// Source id, as set on every event of the source.
    pub id: SourceId,
    /// What the source is, for rule scoping.
    pub logsource: LogSource,
    /// How events are encoded.
    pub format: Format,
}

/// A planted attack and the events that make it up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scenario {
    /// Short name, such as `lsass-access`.
    pub name: String,
    /// What happens in the scenario.
    pub description: String,
    /// The scenario's events, in time order.
    pub events: Vec<EventId>,
}

/// A generated sample.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// Every event, sorted by time, with ids `0..n` in that order.
    pub events: Vec<Event>,
    /// The sources present in `events`.
    pub sources: Vec<SourceInfo>,
    /// The planted attacks.
    pub scenarios: Vec<Scenario>,
}

/// Generates a sample.
#[must_use]
pub fn generate(config: &SynthConfig) -> Sample {
    let root = Rng::new(config.seed);
    let start = config.start.0;
    let mut tagged: Vec<(SourceId, Draft)> = Vec::new();
    let mut sources = Vec::new();

    for spec in sources::SPECS {
        let rng = root.fork(spec.id);
        let mut ctx = Ctx::new(rng, start, config.duration_secs, config.scale_percent);
        (spec.generate)(&mut ctx);
        let id = SourceId::new(spec.id);
        tagged.extend(ctx.into_drafts().into_iter().map(|d| (id.clone(), d)));
        sources.push(SourceInfo {
            id,
            logsource: (spec.logsource)(),
            format: (spec.format)(),
        });
    }

    // Stable sort: equal timestamps keep source order, then generation order.
    tagged.sort_by_key(|(_, draft)| draft.timestamp);

    let mut scenario_events: BTreeMap<&'static str, Vec<EventId>> = BTreeMap::new();
    let events = tagged
        .into_iter()
        .zip(0u64..)
        .map(|((source, draft), n)| {
            let id = EventId(n);
            if let Some(name) = draft.scenario {
                scenario_events.entry(name).or_default().push(id);
            }
            Event {
                id,
                timestamp: Timestamp(draft.timestamp),
                source,
                fields: draft.fields,
            }
        })
        .collect();

    let scenarios = sources::SCENARIOS
        .iter()
        .filter_map(|(name, description)| {
            scenario_events.remove(name).map(|events| Scenario {
                name: (*name).to_owned(),
                description: (*description).to_owned(),
                events,
            })
        })
        .collect();

    Sample {
        events,
        sources,
        scenarios,
    }
}
