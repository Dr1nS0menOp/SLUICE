//! Log template discovery.
//!
//! A template is a recurring event shape within a source. Recipes target templates, and the
//! guardrails reason per template, so discovery decides the granularity of every later step.
//!
//! - **JSON sources:** a template is the source, the values of the fields that name the kind of
//!   event (`EventID`, `event.action`, the defaults for the source's product and its own
//!   `event_type`, see `event_type.rs`) and the set of field paths.
//! - **Text sources:** a template is a Drain cluster of the line content (syslog headers reduced
//!   to the program name), masked for numbers and hex identifiers, and split at the positions
//!   where only a few words alternate (`categorical.rs`), so `Accepted` and `Failed` stay apart.
//!
//! Discovery is online: [`Discoverer::observe`] takes one event at a time.

mod categorical;
mod drain;
mod event_type;
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
use crate::shape::{Group, Keyset, Kind};
use sluice_core::guard::GuardrailConfig;

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
    /// A position Drain made a wildcard is categorical, a word such as `Accepted` or `Failed`
    /// rather than a parameter, when it takes at most this many distinct values in a cluster.
    /// Each value then gets a template of its own.
    pub categorical_max_values: usize,
    /// The rarity floor of the guardrails. A JSON key set this rare keeps a template of its own
    /// instead of joining the other key sets of its kind of event, so it is never cut.
    pub rarity: GuardrailConfig,
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
            categorical_max_values: 6,
            rarity: GuardrailConfig::default(),
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
    /// A text line: its source, its Drain cluster, and its own masked tokens. Lines stay apart
    /// until the clusters are final, when lines that agree on every categorical position merge.
    Line(SourceId, ClusterIndex, Vec<String>),
}

/// The lines of one Drain cluster: each distinct masked token sequence with its group.
type Lines = Vec<(Vec<String>, Group)>;

/// Online template discovery.
#[derive(Debug)]
pub struct Discoverer {
    config: DiscoverConfig,
    sources: BTreeMap<SourceId, Source>,
    /// The fields that name the kind of event, per JSON source.
    event_types: BTreeMap<SourceId, Vec<FieldPath>>,
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
            event_types: sources
                .iter()
                .map(|s| {
                    (
                        s.id.clone(),
                        event_type::fields_for(&config.discriminators, s),
                    )
                })
                .collect(),
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
        if let Some(text) = line {
            let line = preprocess::line(text);
            let drain = self
                .drains
                .entry(event.source.clone())
                .or_insert_with(|| Drain::new(self.config.drain));
            let cluster = drain.add(line.tokens.clone());
            let key = GroupKey::Line(event.source.clone(), cluster, line.tokens);
            (key, Some(line.syslog))
        } else {
            // JSON sources, and text events that lack their line: group by shape.
            let fields = self
                .event_types
                .get(&event.source)
                .unwrap_or(&self.config.discriminators);
            (GroupKey::Keyset(Keyset::of(event, fields)), None)
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
        let mut clusters: BTreeMap<(SourceId, ClusterIndex), Lines> = BTreeMap::new();
        let mut kinds: BTreeMap<Kind, Vec<(Keyset, Group)>> = BTreeMap::new();

        let groups = std::mem::take(&mut self.groups);
        for (key, group) in groups {
            match key {
                GroupKey::Keyset(keyset) => match keyset.kind() {
                    Some(kind) => kinds.entry(kind).or_default().push((keyset, group)),
                    // Without event-type values, the key set is all that tells events apart.
                    None => self.exact(keyset, group, &mut resolved, &mut templates),
                },
                GroupKey::Line(source, index, tokens) => {
                    clusters
                        .entry((source, index))
                        .or_default()
                        .push((tokens, group));
                }
            }
        }

        for (kind, variants) in kinds {
            self.kind(&kind, variants, &mut resolved, &mut templates);
        }

        for ((source, index), members) in clusters {
            let drain = self
                .drains
                .get(&source)
                .expect("a line key is only created by its source's drain");
            let field = self
                .text_field(&source)
                .expect("a line key is only created for a text source")
                .clone();
            let cluster = drain.template(index);
            let lines: Vec<&[String]> = members.iter().map(|(t, _)| t.as_slice()).collect();
            let split = categorical::positions(cluster, &lines, self.config.categorical_max_values);
            let mut variants: BTreeMap<Vec<String>, Group> = BTreeMap::new();
            for (tokens, group) in members {
                let variant = categorical::specialize(cluster, &tokens, &split);
                let (id, _) = shape::cluster_identity(&source, &variant);
                resolved.insert(GroupKey::Line(source.clone(), index, tokens), id);
                match variants.entry(variant) {
                    std::collections::btree_map::Entry::Vacant(slot) => {
                        slot.insert(group);
                    }
                    std::collections::btree_map::Entry::Occupied(mut slot) => {
                        slot.get_mut().absorb(group);
                    }
                }
            }
            for (tokens, group) in variants {
                let (id, pattern) = shape::cluster_identity(&source, &tokens);
                let shape = TemplateShape::Text {
                    field: field.clone(),
                    header: group.header(),
                    tokens,
                };
                let template = self.template(group, id, pattern, shape);
                add(&mut templates, template);
            }
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

    /// One template for exactly one key set.
    fn exact(
        &self,
        keyset: Keyset,
        group: Group,
        resolved: &mut BTreeMap<GroupKey, TemplateId>,
        templates: &mut BTreeMap<TemplateId, Template>,
    ) {
        let template = self.template(
            group,
            keyset.template_id(),
            keyset.pattern(),
            keyset.shape(),
        );
        resolved.insert(GroupKey::Keyset(keyset), template.id.clone());
        add(templates, template);
    }

    /// The templates of one kind of event: one for all its frequent key sets, and one for each
    /// rare key set, which the rarity floor then keeps from being cut (ADR 0019).
    fn kind(
        &self,
        kind: &Kind,
        variants: Vec<(Keyset, Group)>,
        resolved: &mut BTreeMap<GroupKey, TemplateId>,
        templates: &mut BTreeMap<TemplateId, Template>,
    ) {
        let source_events = self.source_events.get(&kind.source).copied().unwrap_or(0);
        let (rare, frequent): (Vec<_>, Vec<_>) = variants.into_iter().partition(|(_, group)| {
            self.config
                .rarity
                .is_rare_count(group.events(), source_events)
        });
        for (keyset, group) in rare {
            self.exact(keyset, group, resolved, templates);
        }
        let id = kind.template_id();
        let mut key_sets = Vec::new();
        let mut merged: Option<Group> = None;
        for (keyset, group) in frequent {
            key_sets.push(keyset.path_set());
            resolved.insert(GroupKey::Keyset(keyset), id.clone());
            match &mut merged {
                Some(all) => all.absorb(group),
                None => merged = Some(group),
            }
        }
        if let Some(group) = merged {
            let pattern = kind.pattern(&key_sets);
            let template = self.template(group, id, pattern, kind.shape(key_sets));
            add(templates, template);
        }
    }

    /// A finished template from one group, with what its source says about it.
    fn template(
        &self,
        group: Group,
        id: TemplateId,
        pattern: String,
        shape: TemplateShape,
    ) -> Template {
        let source = group.source().clone();
        let source_info = self.sources.get(&source);
        let mut template = group.into_template(id, pattern, shape, &self.config);
        template.logsource = source_info.map(|s| s.logsource.clone()).unwrap_or_default();
        template.schema = source_info.map(|s| s.schema).unwrap_or_default();
        if let Some(SourceFormat::Text { field }) = source_info.map(|s| &s.format) {
            template.text_fields.insert(field.clone());
        }
        template.stats.source_events = self.source_events.get(&source).copied().unwrap_or(0);
        template
    }
}

/// Adds a template; Drain clusters can converge on the same final template, which then merge.
fn add(templates: &mut BTreeMap<TemplateId, Template>, template: Template) {
    templates
        .entry(template.id.clone())
        .and_modify(|existing| shape::merge(existing, &template))
        .or_insert(template);
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
