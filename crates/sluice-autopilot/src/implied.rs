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
use sluice_core::guard::GuardrailConfig;
use sluice_core::ids::TemplateId;
use sluice_core::recipe::{ImpliedValue, Literal};
use sluice_core::schema::Schema;
use sluice_core::template::TemplateShape;
use sluice_discover::Discovery;

/// Events each value of an implying field needs before what it implies is learned. Fewer
/// would mostly add entries that save little.
const MIN_SUPPORT: usize = 20;
/// Distinct values a field may have to imply another; more would not be a category.
const MAX_IMPLYING_VALUES: usize = 32;
/// Implied values per kind of event, largest saving first: each is one test per event.
const MAX_PER_TEMPLATE: usize = 64;

/// The implied values of every frequent JSON template in `discovery`.
#[must_use]
pub(crate) fn learn(
    discovery: &Discovery,
    events: &[Event],
    guardrails: GuardrailConfig,
) -> BTreeMap<TemplateId, Vec<ImpliedValue>> {
    let mut by_template: BTreeMap<&TemplateId, Vec<&Map<String, Value>>> = BTreeMap::new();
    for event in events {
        if let Some(template) = discovery.assignments.get(&event.id) {
            by_template.entry(template).or_default().push(&event.fields);
        }
    }
    discovery
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
            let events = by_template.get(&template.id)?;
            let mut skipped: BTreeSet<&FieldPath> = discriminators.iter().map(|(f, _)| f).collect();
            if template.schema == Schema::Sentinel {
                skipped.extend(variants.iter().flatten().filter(|f| workspace_column(f)));
            }
            let values = learn_template(&skipped, variants, events);
            (!values.is_empty()).then(|| (template.id.clone(), values))
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

/// `field`'s implied values: one value on every event, or, for the field that covers the most
/// bytes, one value per value of another field.
fn candidate<'a>(
    field: &'a FieldPath,
    column: &[Literal],
    columns: &'a BTreeMap<&'a FieldPath, Vec<Literal>>,
) -> Option<Candidate<'a>> {
    let distinct: BTreeSet<&Literal> = column.iter().collect();
    if let (1, Some(value)) = (distinct.len(), distinct.first()) {
        return Some(Candidate {
            bytes: column.iter().map(|v| size(field, v)).sum(),
            field,
            implying: None,
            values: vec![ImpliedValue {
                field: field.clone(),
                value: (*value).clone(),
                when: None,
            }],
        });
    }
    columns
        .iter()
        .filter(|(on, _)| *on != &field)
        .filter_map(|(on, implying)| implied_by(field, column, on, implying))
        .max_by(|a, b| a.bytes.cmp(&b.bytes).then(b.implying.cmp(&a.implying)))
}

/// `field`'s values implied by `on`: for each value of `on` with enough events, the one value
/// `field` then always holds.
fn implied_by<'a>(
    field: &'a FieldPath,
    column: &[Literal],
    on: &'a FieldPath,
    implying: &[Literal],
) -> Option<Candidate<'a>> {
    let mut groups: BTreeMap<&Literal, BTreeSet<&Literal>> = BTreeMap::new();
    let mut counts: BTreeMap<&Literal, usize> = BTreeMap::new();
    for (key, value) in implying.iter().zip(column) {
        groups.entry(key).or_default().insert(value);
        *counts.entry(key).or_default() += 1;
    }
    if !(2..=MAX_IMPLYING_VALUES).contains(&groups.len()) || !closed(implying) || identifier(on) {
        return None;
    }
    let mut values = Vec::new();
    let mut bytes = 0;
    for (key, held) in &groups {
        let [value] = held.iter().collect::<Vec<_>>()[..] else {
            continue;
        };
        let events = counts.get(key).copied().unwrap_or_default();
        if events >= MIN_SUPPORT {
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
        Literal::Text(s) => serde_json::to_string(s).map_or(s.len() + 2, |json| json.len()),
    };
    name + 4 + value
}

#[cfg(test)]
mod tests;
