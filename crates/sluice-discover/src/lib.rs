//! Log template discovery.
//!
//! A template is a recurring event shape within a source. Recipes target templates, and the
//! guardrails reason per template, so discovery decides the granularity of every later step.
//!
//! - **JSON sources:** a template is the source, the values of a few *discriminator* fields
//!   (`EventID`, `event.action`, …) and the set of field paths.
//! - **Text sources:** a template is a Drain cluster of the line content (syslog headers reduced
//!   to the program name), masked for numbers and hex identifiers.
//!
//! Discovery is online: [`Discoverer::observe`] takes one event at a time, so the live control
//! plane can use the same code as the offline analysis.

mod drain;
mod flatten;
mod id;
mod mask;
mod preprocess;
mod shape;

use std::collections::BTreeMap;

use sluice_core::event::Event;
use sluice_core::field::FieldPath;
use sluice_core::ids::{EventId, SourceId, TemplateId};
use sluice_core::source::{Source, SourceFormat};
use sluice_core::template::{Template, TemplateShape};

pub use crate::drain::DrainConfig;
use crate::drain::{ClusterIndex, Drain};
use crate::shape::{Group, Keyset};

/// Discovery settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverConfig {
    /// Drain parameters for text sources.
    pub drain: DrainConfig,
    /// JSON fields whose value distinguishes event types. Only fields present in an event count.
    pub discriminators: Vec<FieldPath>,
    /// A string field counts as free text if its values average at least this many characters…
    pub text_min_avg_len: u64,
    /// …and at least this share of them (percent) contains whitespace.
    pub text_min_whitespace_percent: u64,
}

impl Default for DiscoverConfig {
    fn default() -> Self {
        Self {
            drain: DrainConfig::default(),
            discriminators: ["EventID", "event.code", "event.action", "action"]
                .into_iter()
                .map(FieldPath::from)
                .collect(),
            text_min_avg_len: 40,
            text_min_whitespace_percent: 50,
        }
    }
}

/// The result of discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// Every template found, sorted by id.
    pub templates: Vec<Template>,
    /// The template of every observed event.
    pub assignments: BTreeMap<EventId, TemplateId>,
}

/// Where an observed event provisionally belongs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum GroupKey {
    Keyset(Keyset),
    Cluster(SourceId, ClusterIndex),
}

/// Online template discovery.
#[derive(Debug)]
pub struct Discoverer {
    config: DiscoverConfig,
    sources: BTreeMap<SourceId, Source>,
    drains: BTreeMap<SourceId, Drain>,
    groups: BTreeMap<GroupKey, Group>,
    assignments: Vec<(EventId, GroupKey)>,
    source_events: BTreeMap<SourceId, u64>,
}

impl Discoverer {
    /// Creates a discoverer for the given sources. Events from other sources are treated as
    /// JSON with an unknown log source.
    #[must_use]
    pub fn new(config: DiscoverConfig, sources: &[Source]) -> Self {
        Self {
            config,
            sources: sources.iter().map(|s| (s.id.clone(), s.clone())).collect(),
            drains: BTreeMap::new(),
            groups: BTreeMap::new(),
            assignments: Vec::new(),
            source_events: BTreeMap::new(),
        }
    }

    /// Assigns one event to a template, creating or generalizing templates as needed.
    pub fn observe(&mut self, event: &Event) {
        let (key, header) = self.group_key(event);
        let group = self
            .groups
            .entry(key.clone())
            .or_insert_with(|| Group::new(event.source.clone()));
        group.add(event);
        if let Some(syslog) = header {
            group.note_header(syslog);
        }
        *self.source_events.entry(event.source.clone()).or_default() += 1;
        self.assignments.push((event.id, key));
    }

    /// The event's group, and for text lines whether they had a syslog header.
    fn group_key(&mut self, event: &Event) -> (GroupKey, Option<bool>) {
        let line = self
            .text_field(&event.source)
            .and_then(|field| flatten::get(&event.fields, field))
            .and_then(serde_json::Value::as_str);
        match line {
            Some(text) => {
                let line = preprocess::line(text);
                let drain = self
                    .drains
                    .entry(event.source.clone())
                    .or_insert_with(|| Drain::new(self.config.drain));
                let key = GroupKey::Cluster(event.source.clone(), drain.add(line.tokens));
                (key, Some(line.syslog))
            }
            // JSON sources, and text events that lack their line: group by shape.
            None => (
                GroupKey::Keyset(Keyset::of(event, &self.config.discriminators)),
                None,
            ),
        }
    }

    fn text_field(&self, source: &SourceId) -> Option<&FieldPath> {
        match self.sources.get(source).map(|s| &s.format) {
            Some(SourceFormat::Text { field }) => Some(field),
            _ => None,
        }
    }

    /// Finalizes the templates and every event's assignment.
    #[must_use]
    #[expect(
        clippy::missing_panics_doc,
        reason = "the expects guard internal invariants that no caller input can break"
    )]
    pub fn finish(mut self) -> Discovery {
        let mut resolved: BTreeMap<GroupKey, TemplateId> = BTreeMap::new();
        let mut templates: BTreeMap<TemplateId, Template> = BTreeMap::new();

        let groups = std::mem::take(&mut self.groups);
        for (key, group) in groups {
            let (id, pattern, shape) = match &key {
                GroupKey::Keyset(keyset) => {
                    (keyset.template_id(), keyset.pattern(), keyset.shape())
                }
                GroupKey::Cluster(source, index) => {
                    let drain = self
                        .drains
                        .get(source)
                        .expect("a cluster key is only created by its source's drain");
                    let field = self
                        .text_field(source)
                        .expect("a cluster key is only created for a text source")
                        .clone();
                    let tokens = drain.template(*index);
                    let (id, pattern) = shape::cluster_identity(source, tokens);
                    let shape = TemplateShape::Text {
                        field,
                        header: group.header(),
                        tokens: tokens.to_vec(),
                    };
                    (id, pattern, shape)
                }
            };
            let source = group.source().clone();
            let source_info = self.sources.get(&source);
            let mut template = group.into_template(id.clone(), pattern, shape, &self.config);
            template.logsource = source_info.map(|s| s.logsource.clone()).unwrap_or_default();
            if let Some(SourceFormat::Text { field }) = source_info.map(|s| &s.format) {
                template.text_fields.insert(field.clone());
            }
            template.stats.source_events = self.source_events.get(&source).copied().unwrap_or(0);
            // Drain clusters can converge on the same final template: merge them.
            templates
                .entry(id.clone())
                .and_modify(|existing| shape::merge(existing, &template))
                .or_insert(template);
            resolved.insert(key, id);
        }

        let assignments = self
            .assignments
            .into_iter()
            .map(|(event, key)| {
                let id = resolved
                    .get(&key)
                    .expect("every assigned group was resolved above");
                (event, id.clone())
            })
            .collect();
        Discovery {
            templates: templates.into_values().collect(),
            assignments,
        }
    }
}

/// Discovers templates in a batch of events.
#[must_use]
pub fn discover<'a>(
    config: DiscoverConfig,
    sources: &[Source],
    events: impl IntoIterator<Item = &'a Event>,
) -> Discovery {
    let mut discoverer = Discoverer::new(config, sources);
    for event in events {
        discoverer.observe(event);
    }
    discoverer.finish()
}
