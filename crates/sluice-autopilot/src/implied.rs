//! Values implied by the kind of event, or by another field of the event, learned from the
//! sample (`docs/notes/field-value.md`).
//!
//! Such a value can be removed while the field holds it and be put back exactly: an absent
//! field means the implied value. A value learned by coincidence costs nothing but its saving,
//! since a field holding any other value is kept. The guardrails and the proof still decide
//! what is removed, as for every proposal.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};
use sluice_core::event::Event;
use sluice_core::field::FieldPath;
use sluice_core::ids::TemplateId;
use sluice_core::recipe::{ImpliedValue, Literal};
use sluice_core::schema::Schema;
use sluice_core::template::TemplateShape;
use sluice_discover::Discovery;

use crate::analyze::Settings;

/// Events each value of an implying field needs before what it implies is learned. Fewer
/// would mostly add entries that save little.
const MIN_SUPPORT: usize = 20;
/// Distinct values a field may have to imply another; more would not be a category.
const MAX_IMPLYING_VALUES: usize = 32;
/// A value is implied where it holds on at least this many tenths of the events it is learned on.
/// The removal is lossless whatever the share, since a value guard leaves every other value in
/// place; the share only says how much it saves. Nine in ten keeps most of what a lower share
/// saves on the sample, and more of it lasts on a later one (docs/notes/field-theory.md).
const MIN_SHARE_TENTHS: usize = 9;
/// Implied values per kind of event, largest saving first: each is one test per event.
const MAX_PER_TEMPLATE: usize = 64;

/// The fields that name the machine an event came from, in the order they are tried: Windows'
/// and Sentinel's, ECS's, then common syslog and appliance names.
const HOST_FIELDS: [&str; 11] = [
    "Computer",
    "host.name",
    "host.hostname",
    "agent.hostname",
    "hostname",
    "host",
    "ComputerName",
    "DeviceName",
    "Hostname",
    "dvc",
    "observer.hostname",
];

/// What the implied values were learned on (ADR 0042).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evidence {
    /// The samples the events came from (`--input` given that many times).
    pub samples: usize,
    /// Per source, the machines its events name; absent when no event names one.
    pub hosts: BTreeMap<String, usize>,
    /// Values held back: the same on every kind of event of their source, seen on one machine.
    pub withheld: Vec<Withheld>,
}

/// A value that looked implied on every kind of event of a source but was not learned: on a
/// sample of one machine, nothing tells a value the kind of event fixes from one the machine
/// does, such as its name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Withheld {
    /// The source.
    pub source: String,
    /// The field.
    pub field: FieldPath,
    /// The value it held on every kind of event.
    pub value: Literal,
    /// On how many kinds of event.
    pub kinds: usize,
}

/// The implied values learned, and what they were learned on.
#[derive(Debug, Default)]
pub(crate) struct Learned {
    /// Per template, its implied values.
    pub(crate) values: BTreeMap<TemplateId, Vec<ImpliedValue>>,
    /// What they were learned on.
    pub(crate) evidence: Evidence,
}

/// Where an event came from: the sample it was read from and the machine that logged it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Origin<'a> {
    sample: u16,
    host: Option<&'a str>,
}

/// One event of a template, with where it came from.
type Sourced<'a> = (&'a Map<String, Value>, Origin<'a>);

/// The implied values of every frequent JSON template in `discovery`. A value must hold in each
/// sample and on each machine that has enough of its events; a value that is the same on every
/// kind of event of a source is learned only from more than one machine (ADR 0042).
#[must_use]
pub(crate) fn learn(discovery: &Discovery, events: &[Event], settings: &Settings) -> Learned {
    let guardrails = settings.guardrails;
    let mut by_template: BTreeMap<&TemplateId, Vec<Sourced<'_>>> = BTreeMap::new();
    let mut hosts: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut samples: BTreeSet<u16> = BTreeSet::new();
    let host_fields = host_fields(events);
    for event in events {
        let origin = Origin {
            sample: sample_of(event, &settings.samples),
            host: host_fields
                .get(event.source.as_str())
                .and_then(|field| text(&event.fields, field)),
        };
        samples.insert(origin.sample);
        if let Some(host) = origin.host {
            hosts.entry(event.source.as_str()).or_default().insert(host);
        }
        if let Some(template) = discovery.assignments.get(&event.id) {
            by_template
                .entry(template)
                .or_default()
                .push((&event.fields, origin));
        }
    }
    let mut values: BTreeMap<TemplateId, Vec<ImpliedValue>> = discovery
        .templates
        .iter()
        .filter(|template| !guardrails.is_rare(template))
        .filter_map(|template| {
            let TemplateShape::Keyset {
                discriminators,
                variants,
                ..
            } = &template.shape
            else {
                return None;
            };
            let sourced = by_template.get(&template.id)?;
            let events: Vec<&Map<String, Value>> = sourced.iter().map(|(e, _)| *e).collect();
            let mut skipped: BTreeSet<&FieldPath> = discriminators.iter().map(|(f, _)| f).collect();
            if template.schema == Schema::Sentinel {
                skipped.extend(variants.iter().flatten().filter(|f| workspace_column(f)));
            }
            let values: Vec<ImpliedValue> = learn_template(&skipped, variants, &events)
                .into_iter()
                .filter(|value| holds_everywhere(value, sourced))
                .collect();
            (!values.is_empty()).then(|| (template.id.clone(), values))
        })
        .collect();
    let withheld = withhold(discovery, &mut values, &hosts, samples.len());
    Learned {
        values,
        evidence: Evidence {
            samples: samples.len().max(1),
            hosts: hosts
                .into_iter()
                .map(|(source, names)| (source.to_owned(), names.len()))
                .collect(),
            withheld,
        },
    }
}

/// The sample `event` came from: its index in `samples`, by event id.
fn sample_of(event: &Event, samples: &[u16]) -> u16 {
    usize::try_from(event.id.0)
        .ok()
        .and_then(|at| samples.get(at))
        .copied()
        .unwrap_or(0)
}

/// Per source, the field of [`HOST_FIELDS`] that names its machines: of those its events have,
/// the one with the most distinct values, first in the list on a tie. A field that names one
/// value only may be a log collector's (OTRF's samples carry the collector in `host` and the
/// machine in `Hostname`).
fn host_fields(events: &[Event]) -> BTreeMap<&str, FieldPath> {
    let mut seen: BTreeMap<(&str, usize), BTreeSet<&str>> = BTreeMap::new();
    for event in events {
        for (rank, name) in HOST_FIELDS.iter().enumerate() {
            if let Some(host) = text(&event.fields, &FieldPath::new(*name)) {
                seen.entry((event.source.as_str(), rank))
                    .or_default()
                    .insert(host);
            }
        }
    }
    let mut best: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for ((source, rank), hosts) in &seen {
        let entry = best.entry(source).or_insert((hosts.len(), *rank));
        if hosts.len() > entry.0 {
            *entry = (hosts.len(), *rank);
        }
    }
    best.into_iter()
        .map(|(source, (_, rank))| (source, FieldPath::new(HOST_FIELDS[rank])))
        .collect()
}

/// The non-empty text at `path` in an event.
fn text<'a>(fields: &'a Map<String, Value>, path: &FieldPath) -> Option<&'a str> {
    lookup(fields, path)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

/// Whether `value` holds, at the share it was learned with, in every origin (sample and machine)
/// with at least [`MIN_SUPPORT`] of the events it applies to. On one origin that is the sample
/// itself, which learned it; across several, a value one machine or one day had and another
/// lacks was that machine's or that day's, not the kind of event's.
fn holds_everywhere(value: &ImpliedValue, events: &[Sourced<'_>]) -> bool {
    let mut per_origin: BTreeMap<Origin<'_>, (usize, usize)> = BTreeMap::new();
    for (fields, origin) in events {
        if let Some((on, expected)) = &value.when
            && lookup(fields, on).and_then(Literal::of).as_ref() != Some(expected)
        {
            continue;
        }
        let Some(held) = lookup(fields, &value.field).and_then(Literal::of) else {
            continue;
        };
        let (total, matching) = per_origin.entry(*origin).or_default();
        *total += 1;
        *matching += usize::from(held == value.value);
    }
    per_origin
        .values()
        .filter(|(total, _)| *total >= MIN_SUPPORT)
        .all(|(total, matching)| matching * 10 >= total * MIN_SHARE_TENTHS)
}

/// Takes out of `values` each value the kind of event alone implies alike on every kind of event
/// of its source, unless that source shows more than one machine (or, naming none, more than one
/// sample), and returns them. On one machine its name and domain look like that too.
fn withhold(
    discovery: &Discovery,
    values: &mut BTreeMap<TemplateId, Vec<ImpliedValue>>,
    hosts: &BTreeMap<&str, BTreeSet<&str>>,
    samples: usize,
) -> Vec<Withheld> {
    let source_of: BTreeMap<&TemplateId, &str> = discovery
        .templates
        .iter()
        .map(|t| (&t.id, t.source.as_str()))
        .collect();
    // Per source and field: the values the kind of event alone implies, on how many kinds, and
    // whether another field implies it anywhere.
    let mut seen: BTreeMap<(&str, FieldPath), (BTreeSet<Literal>, usize, bool)> = BTreeMap::new();
    for (template, learned) in values.iter() {
        let Some(source) = source_of.get(template) else {
            continue;
        };
        for value in learned {
            let entry = seen.entry((source, value.field.clone())).or_default();
            match value.when {
                None => {
                    entry.0.insert(value.value.clone());
                    entry.1 += 1;
                }
                Some(_) => entry.2 = true,
            }
        }
    }
    let evidence = |source: &str| match hosts.get(source) {
        Some(names) => names.len() > 1,
        None => samples > 1,
    };
    let held_back: BTreeMap<(&str, FieldPath), (Literal, usize)> = seen
        .into_iter()
        .filter(|((source, _), (alike, kinds, conditional))| {
            alike.len() == 1 && *kinds > 1 && !conditional && !evidence(source)
        })
        .filter_map(|(key, (alike, kinds, _))| alike.into_iter().next().map(|v| (key, (v, kinds))))
        .collect();
    if held_back.is_empty() {
        return Vec::new();
    }
    for (template, learned) in values.iter_mut() {
        let Some(source) = source_of.get(template) else {
            continue;
        };
        learned.retain(|value| {
            value.when.is_some() || !held_back.contains_key(&(*source, value.field.clone()))
        });
    }
    values.retain(|_, learned| !learned.is_empty());
    held_back
        .into_iter()
        .map(|((source, field), (value, kinds))| Withheld {
            source: source.to_owned(),
            field,
            value,
            kinds,
        })
        .collect()
}

/// A column a Log Analytics workspace adds to every record itself (its standard columns):
/// removing it before ingestion saves nothing.
fn workspace_column(field: &FieldPath) -> bool {
    matches!(field.as_str(), "Type" | "TenantId") || field.as_str().starts_with('_')
}

/// Whether `field` is named as an identifier (`SystemThreadId`, `SubjectLogonId`, `LogonGuid`,
/// `process_id`): it names one thread, session or process, not a kind. On one host and a short
/// sample a few of them can look like a category; elsewhere and later they would not be.
fn identifier(field: &FieldPath) -> bool {
    let name = field.segments().last().unwrap_or_default();
    ["Id", "ID", "Guid", "GUID", "_id", "_guid"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

/// Whether `field` holds a network observation: a port by its name (`DestinationPort`,
/// `IpPort`, `src_port`, `port`), or an IP address in every event of the sample. An address
/// or a port that stayed the same through a sample is the lab's or the log collector's
/// (OTRF's APT29 data learned the collector's `port` as a constant, and `SourcePort` per
/// program), not the kind of event's, and an analyst pivots on exactly these values: such a
/// field is never implied, and implies nothing.
fn network(field: &FieldPath, column: &[Literal]) -> bool {
    let name = field.segments().last().unwrap_or_default();
    let port = name == "port" || name.ends_with("Port") || name.ends_with("_port");
    let addresses = !column.is_empty()
        && column.iter().all(|value| {
            matches!(value, Literal::Text(text) if text.parse::<std::net::IpAddr>().is_ok())
        });
    port || addresses
}

/// Whether every value of `column` in the later half of the sample already occurs in the
/// earlier half. A category (a logon type, an account) repeats its values; an identifier (a
/// thread, a process, a logon session) keeps bringing new ones, and what it seems to imply on
/// a sample is a coincidence that would save nothing later.
fn closed(column: &[Literal]) -> bool {
    let (earlier, later) = column.split_at(column.len() / 2);
    let seen: BTreeSet<&Literal> = earlier.iter().collect();
    later.iter().all(|value| seen.contains(value))
}

/// One field's candidate: its implied values, what they would save, and the field implying
/// them (`None` for a value the kind of event implies alone).
struct Candidate<'a> {
    bytes: usize,
    field: &'a FieldPath,
    implying: Option<&'a FieldPath>,
    values: Vec<ImpliedValue>,
}

/// The implied values of one template's `events`, in sample order. Only fields every variant
/// carries count (an absent field must mean the implied value), and never a `skipped` one,
/// such as the fields that name the kind of event.
fn learn_template(
    skipped: &BTreeSet<&FieldPath>,
    variants: &[BTreeSet<FieldPath>],
    events: &[&Map<String, Value>],
) -> Vec<ImpliedValue> {
    let Some((first, rest)) = variants.split_first() else {
        return Vec::new();
    };
    let columns: BTreeMap<&FieldPath, Vec<Literal>> = first
        .iter()
        .filter(|field| !skipped.contains(field) && rest.iter().all(|v| v.contains(*field)))
        .filter_map(|field| {
            let column: Option<Vec<Literal>> = events
                .iter()
                .map(|event| lookup(event, field).and_then(Literal::of))
                .collect();
            Some((field, column?))
        })
        .filter(|(field, column)| !network(field, column))
        .collect();
    let mut candidates: Vec<Candidate<'_>> = columns
        .iter()
        .filter_map(|(field, column)| candidate(field, column, &columns))
        .collect();
    candidates.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.field.cmp(b.field)));

    // A removed field must never be one that implies another: that one could not be rebuilt.
    let mut removed: BTreeSet<&FieldPath> = BTreeSet::new();
    let mut implying: BTreeSet<&FieldPath> = BTreeSet::new();
    let mut out = Vec::new();
    for candidate in candidates {
        if implying.contains(candidate.field)
            || candidate.implying.is_some_and(|on| removed.contains(on))
            || out.len() + candidate.values.len() > MAX_PER_TEMPLATE
        {
            continue;
        }
        removed.insert(candidate.field);
        implying.extend(candidate.implying);
        out.extend(candidate.values);
    }
    out.sort();
    out
}

/// `field`'s implied values, whichever saves the most bytes: the value the kind of event
/// implies alone, or one value per value of another field, each held by at least nine in ten of
/// the events it is learned on.
fn candidate<'a>(
    field: &'a FieldPath,
    column: &[Literal],
    columns: &'a BTreeMap<&'a FieldPath, Vec<Literal>>,
) -> Option<Candidate<'a>> {
    let found = dominant(column.iter());
    let alone = found.map(|(value, held)| Candidate {
        bytes: held * size(field, value),
        field,
        implying: None,
        values: vec![ImpliedValue {
            field: field.clone(),
            value: value.clone(),
            when: None,
        }],
    });
    // A value that holds on every event needs no other field to say when.
    if found.is_some_and(|(_, held)| held == column.len()) {
        return alone;
    }
    columns
        .iter()
        .filter(|(on, _)| *on != &field)
        .filter_map(|(on, implying)| implied_by(field, column, on, implying))
        .chain(alone)
        // The most bytes; of equal ones, the kind of event alone (`None`), then the first field.
        .max_by(|a, b| a.bytes.cmp(&b.bytes).then(b.implying.cmp(&a.implying)))
}

/// `field`'s values implied by `on`: for each value of `on` with enough events, the one value
/// `field` then always holds. A field named as an identifier is never implied this way: a
/// thread, a process or an agent's run that one machine kept through a sample changes at its
/// next restart (OTRF's APT3 data learned `ExecutionThreadID` per `Computer`, the demo
/// `agent.ephemeral_id`), so the saving would not last. The kind of event may still imply one,
/// such as a `SubjectLogonId` that is always `0x0`.
fn implied_by<'a>(
    field: &'a FieldPath,
    column: &[Literal],
    on: &'a FieldPath,
    implying: &[Literal],
) -> Option<Candidate<'a>> {
    let mut groups: BTreeMap<&Literal, Vec<&Literal>> = BTreeMap::new();
    for (key, value) in implying.iter().zip(column) {
        groups.entry(key).or_default().push(value);
    }
    if !(2..=MAX_IMPLYING_VALUES).contains(&groups.len())
        || !closed(implying)
        || identifier(on)
        || identifier(field)
    {
        return None;
    }
    let mut values = Vec::new();
    let mut bytes = 0;
    for (key, held) in &groups {
        if held.len() < MIN_SUPPORT {
            continue;
        }
        if let Some((value, events)) = dominant(held.iter().copied()) {
            bytes += events * size(field, value);
            values.push(ImpliedValue {
                field: field.clone(),
                value: (*value).clone(),
                when: Some((on.clone(), (*key).clone())),
            });
        }
    }
    (!values.is_empty()).then_some(Candidate {
        bytes,
        field,
        implying: Some(on),
        values,
    })
}

/// The value `values` hold most often, and on how many, if that is at least [`MIN_SHARE_TENTHS`]
/// of them; of values held equally often, the least, so the choice does not depend on order.
fn dominant<'a>(values: impl Iterator<Item = &'a Literal>) -> Option<(&'a Literal, usize)> {
    let mut counts: BTreeMap<&Literal, usize> = BTreeMap::new();
    let mut total = 0;
    for value in values {
        *counts.entry(value).or_default() += 1;
        total += 1;
    }
    let (value, held) = counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(a.0)))?;
    (held * 10 >= total * MIN_SHARE_TENTHS).then_some((value, held))
}

/// The value at `path` in an event, following nested objects.
fn lookup<'a>(fields: &'a Map<String, Value>, path: &FieldPath) -> Option<&'a Value> {
    let mut segments = path.segments();
    let mut value = fields.get(segments.next()?)?;
    for segment in segments {
        value = value.as_object()?.get(segment)?;
    }
    Some(value)
}

/// About the bytes `"name":value,` takes in compact JSON.
fn size(field: &FieldPath, value: &Literal) -> usize {
    let name = field.segments().last().map_or(0, str::len);
    let value = match value {
        Literal::Bool(b) => b.to_string().len(),
        Literal::Integer(i) => i.to_string().len(),
        Literal::Text(s) => Value::String(s.clone()).to_string().len(),
    };
    name + 4 + value
}

#[cfg(test)]
mod tests;
