//! Event shapes (JSON keysets) and per-template accumulation.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use sluice_core::event::{Event, encoded_size};
use sluice_core::field::FieldPath;
use sluice_core::ids::{SourceId, TemplateId};
use sluice_core::logsource::LogSource;
use sluice_core::template::{LineHeader, Template, TemplateShape, TemplateStats};

use crate::DiscoverConfig;
use crate::flatten::{for_each_leaf, get};
use crate::id::{fnv1a, template_id};

/// The shape of a JSON event: source, discriminator values and the set of leaf paths.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Keyset {
    source: SourceId,
    discriminators: Vec<(FieldPath, String)>,
    paths: Vec<String>,
}

impl Keyset {
    pub(crate) fn of(event: &Event, discriminators: &[FieldPath]) -> Self {
        let discriminators = discriminators
            .iter()
            .filter_map(|field| get(&event.fields, field).map(|v| (field.clone(), render(v))))
            .collect();
        let mut paths = Vec::new();
        for_each_leaf(&event.fields, &mut |path, _| paths.push(path.to_owned()));
        paths.sort();
        Self {
            source: event.source.clone(),
            discriminators,
            paths,
        }
    }

    pub(crate) fn template_id(&self) -> TemplateId {
        let label = self
            .discriminators
            .iter()
            .map(|(_, value)| sanitize(value))
            .collect::<Vec<_>>()
            .join("/");
        let discriminator_parts = self
            .discriminators
            .iter()
            .flat_map(|(field, value)| [field.as_str(), value.as_str()]);
        let hash = fnv1a(
            [self.source.as_str(), "json"]
                .into_iter()
                .chain(discriminator_parts)
                .chain(self.paths.iter().map(String::as_str)),
        );
        template_id(&self.source, &label, hash)
    }

    pub(crate) fn shape(&self) -> TemplateShape {
        TemplateShape::Keyset {
            discriminators: self.discriminators.clone(),
            paths: self
                .paths
                .iter()
                .map(|p| FieldPath::new(p.as_str()))
                .collect(),
        }
    }

    pub(crate) fn pattern(&self) -> String {
        let mut pattern: Vec<String> = self
            .discriminators
            .iter()
            .map(|(field, value)| format!("{field}={value}"))
            .collect();
        pattern.push(format!("[{} fields]", self.paths.len()));
        pattern.join(" ")
    }
}

/// Id and pattern of a final Drain template.
pub(crate) fn cluster_identity(source: &SourceId, tokens: &[String]) -> (TemplateId, String) {
    let pattern = tokens.join(" ");
    let hash = fnv1a([source.as_str(), "text", pattern.as_str()]);
    (template_id(source, "", hash), pattern)
}

fn render(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Keeps ids readable and unambiguous: separators and whitespace become `_`.
fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c == ':' || c == '/' || c.is_whitespace() {
                '_'
            } else {
                c
            }
        })
        .collect()
}

/// Statistics of one string field across a group, for free-text detection.
#[derive(Debug, Default, Clone, Copy)]
struct StringStats {
    values: u64,
    total_len: u64,
    with_whitespace: u64,
}

/// Everything accumulated for one provisional template.
#[derive(Debug)]
pub(crate) struct Group {
    source: SourceId,
    fields: BTreeSet<FieldPath>,
    strings: BTreeMap<String, StringStats>,
    events: u64,
    bytes: u64,
    header: Option<LineHeader>,
}

impl Group {
    pub(crate) fn new(source: SourceId) -> Self {
        Self {
            source,
            fields: BTreeSet::new(),
            strings: BTreeMap::new(),
            events: 0,
            bytes: 0,
            header: None,
        }
    }

    /// Records whether a text line of this group had a syslog header.
    pub(crate) fn note_header(&mut self, syslog: bool) {
        let seen = if syslog {
            LineHeader::Syslog
        } else {
            LineHeader::None
        };
        self.header = Some(match self.header {
            None => seen,
            Some(previous) if previous == seen => seen,
            Some(_) => LineHeader::Mixed,
        });
    }

    pub(crate) fn header(&self) -> LineHeader {
        self.header.unwrap_or(LineHeader::None)
    }

    pub(crate) fn source(&self) -> &SourceId {
        &self.source
    }

    pub(crate) fn add(&mut self, event: &Event) {
        self.events += 1;
        self.bytes += u64::try_from(encoded_size(&event.fields)).unwrap_or(u64::MAX);
        for_each_leaf(&event.fields, &mut |path, value| {
            if !self.fields.contains(path) {
                self.fields.insert(FieldPath::new(path));
            }
            if let Value::String(text) = value {
                let stats = self.strings.entry(path.to_owned()).or_default();
                stats.values += 1;
                stats.total_len += u64::try_from(text.len()).unwrap_or(u64::MAX);
                stats.with_whitespace += u64::from(text.contains(char::is_whitespace));
            }
        });
    }

    pub(crate) fn into_template(
        self,
        id: TemplateId,
        pattern: String,
        shape: TemplateShape,
        config: &DiscoverConfig,
    ) -> Template {
        let text_fields = self
            .strings
            .iter()
            .filter(|(_, s)| {
                s.values > 0
                    && s.total_len / s.values >= config.text_min_avg_len
                    && s.with_whitespace * 100 >= config.text_min_whitespace_percent * s.values
            })
            .map(|(path, _)| FieldPath::new(path.as_str()))
            .collect();
        Template {
            id,
            source: self.source,
            logsource: LogSource::default(),
            pattern,
            shape,
            fields: self.fields,
            text_fields,
            stats: TemplateStats {
                events: self.events,
                bytes: self.bytes,
                source_events: 0,
            },
        }
    }
}

/// Folds `other` into `existing` (both describe the same final template). Clusters that
/// converged from lines with and without a syslog header get a `Mixed` header.
pub(crate) fn merge(existing: &mut Template, other: &Template) {
    if let (TemplateShape::Text { header: mine, .. }, TemplateShape::Text { header: theirs, .. }) =
        (&mut existing.shape, &other.shape)
        && mine != theirs
    {
        *mine = LineHeader::Mixed;
    }
    existing.fields.extend(other.fields.iter().cloned());
    existing
        .text_fields
        .extend(other.text_fields.iter().cloned());
    existing.stats.events += other.stats.events;
    existing.stats.bytes += other.stats.bytes;
}
