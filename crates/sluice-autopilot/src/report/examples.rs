//! A few events of each source as the SIEM receives them: what is left after the savings, next
//! to what was left out and why. The data plane of the analysis reduces them, so they are
//! exactly what the proof saw.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sluice_core::event::{Event, encoded_size};
use sluice_core::guard::EffectiveRecipe;
use sluice_core::ids::{SourceId, TemplateId};
use sluice_core::proof::{Volume, removed_members};
use sluice_core::reduce::{Outcome, Reducer};
use sluice_core::template::Template;

use super::text;
use crate::analyze::{Analysis, Input};

/// Events shown per source.
pub const EXAMPLES_PER_SOURCE: usize = 10;
/// Events of one kind tried in search of one that is sent: most events of a summarized kind are
/// counted instead, and trying every one would reduce the whole sample a second time.
const ATTEMPTS: usize = 1_000;
/// A text value is cut to this many characters in an example.
const VALUE_CHARS: usize = 80;

/// One source's examples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceExamples {
    /// Source id.
    pub source: String,
    /// Volume of its kinds of event.
    pub volume: Volume,
    /// Its events as sent, one of each kind of event first, the kind with most bytes left first.
    pub examples: Vec<Example>,
}

/// One event as the SIEM receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Example {
    /// The kind of event it is.
    pub pattern: String,
    /// The body sent, as compact JSON, with long text values cut to 80 characters.
    pub body: String,
    /// Bytes of the event as it came in.
    pub bytes_in: u64,
    /// Bytes of the event as sent.
    pub bytes_out: u64,
    /// What was left out of it, largest first.
    pub omitted: Vec<Omitted>,
}

/// A field left out of an example.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Omitted {
    /// Its path.
    pub path: String,
    /// The bytes it took.
    pub bytes: u64,
    /// Why it was left out.
    pub reason: Omission,
}

/// Why a field was left out of an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Omission {
    /// The recipe removes it: it repeats the event.
    Recipe,
    /// It was null or empty.
    Empty,
    /// It held the value the kind of event or another field implies, shown here (cut to
    /// 80 characters): it can be put back exactly.
    Implied(String),
}

/// Up to `per_source` events of every source of `input`, as `analysis` sends them.
pub(crate) fn pick(
    analysis: &Analysis,
    input: Input<'_>,
    per_source: usize,
) -> Vec<SourceExamples> {
    if per_source == 0 {
        return Vec::new();
    }
    let kinds: BTreeMap<&TemplateId, (&Template, &EffectiveRecipe)> = analysis
        .discovery
        .templates
        .iter()
        .zip(&analysis.selection.recipes)
        .map(|(template, recipe)| (&template.id, (template, recipe)))
        .collect();
    let found = find(analysis, &kinds, input.events, per_source);
    let per_template = &analysis.selection.proof.per_template;
    input
        .sources
        .iter()
        .map(|source| {
            let mut buckets: Vec<(u64, Option<&TemplateId>, &Vec<Example>)> = found
                .iter()
                .filter(|((s, _), _)| *s == &source.id)
                .map(|((_, template), bucket)| {
                    let left = template
                        .and_then(|t| per_template.get(&Some(t.clone())))
                        .map_or(0, |v| v.bytes_out);
                    (left, *template, &bucket.examples)
                })
                .collect();
            buckets.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            let mut volume = Volume::default();
            for (template, _) in kinds.values().filter(|(t, _)| t.source == source.id) {
                let v = per_template
                    .get(&Some(template.id.clone()))
                    .copied()
                    .unwrap_or_default();
                volume.events += v.events;
                volume.forwarded += v.forwarded;
                volume.summarized += v.summarized;
                volume.bytes_in += v.bytes_in;
                volume.bytes_out += v.bytes_out;
            }
            SourceExamples {
                source: source.id.to_string(),
                volume,
                examples: round_robin(
                    &buckets
                        .iter()
                        .map(|(_, _, e)| e.as_slice())
                        .collect::<Vec<_>>(),
                    per_source,
                ),
            }
        })
        .collect()
}

#[derive(Default)]
struct Bucket {
    tried: usize,
    examples: Vec<Example>,
}

/// Per source and kind of event, the first `per_kind` events sent.
fn find<'a>(
    analysis: &'a Analysis,
    kinds: &BTreeMap<&TemplateId, (&Template, &EffectiveRecipe)>,
    events: &'a [Event],
    per_kind: usize,
) -> BTreeMap<(&'a SourceId, Option<&'a TemplateId>), Bucket> {
    let mut found: BTreeMap<(&SourceId, Option<&TemplateId>), Bucket> = BTreeMap::new();
    for event in events {
        let template = analysis.discovery.assignments.get(&event.id);
        let bucket = found.entry((&event.source, template)).or_default();
        if bucket.examples.len() >= per_kind || bucket.tried >= ATTEMPTS {
            continue;
        }
        bucket.tried += 1;
        // An event the data plane cannot reduce is not shown; the proof reports it.
        let Ok(reduced) = analysis.data_plane.reduce(event) else {
            continue;
        };
        if let Outcome::Forwarded(body) = reduced.outcome {
            let kind = template.and_then(|t| kinds.get(t));
            bucket.examples.push(example(
                &event.fields,
                &body,
                kind.map(|(t, _)| t.pattern.as_str()),
                kind.map(|(_, r)| *r),
            ));
        }
    }
    found
}

/// Takes the first of each list, then the second of each, and so on, until `n`.
fn round_robin(lists: &[&[Example]], n: usize) -> Vec<Example> {
    let longest = lists.iter().map(|l| l.len()).max().unwrap_or(0);
    (0..longest)
        .flat_map(|i| lists.iter().filter_map(move |l| l.get(i)))
        .take(n)
        .cloned()
        .collect()
}

fn example(
    before: &Map<String, Value>,
    after: &Map<String, Value>,
    pattern: Option<&str>,
    recipe: Option<&EffectiveRecipe>,
) -> Example {
    let mut omitted: Vec<Omitted> = removed_members(before, after)
        .into_iter()
        .map(|member| Omitted {
            path: member.path.to_string(),
            bytes: to_u64(member.bytes),
            reason: match recipe {
                Some(r) if r.drop_fields.iter().any(|f| f.covers(&member.path)) => Omission::Recipe,
                Some(r) if text::implied(&member.path, r) => {
                    Omission::Implied(cut(&compact(member.value)))
                }
                _ => Omission::Empty,
            },
        })
        .collect();
    omitted.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.path.cmp(&b.path)));
    Example {
        pattern: pattern.unwrap_or("(no kind of event)").to_owned(),
        body: compact(&Value::Object(shortened(after))),
        bytes_in: to_u64(encoded_size(before)),
        bytes_out: to_u64(encoded_size(after)),
        omitted,
    }
}

/// `body` with every text value cut to 80 characters.
fn shortened(body: &Map<String, Value>) -> Map<String, Value> {
    body.iter()
        .map(|(key, value)| (key.clone(), shorten(value)))
        .collect()
}

fn shorten(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(cut(text)),
        Value::Array(items) => Value::Array(items.iter().map(shorten).collect()),
        Value::Object(members) => Value::Object(shortened(members)),
        other => other.clone(),
    }
}

/// `text` cut to [`VALUE_CHARS`] characters, with an ellipsis when it was longer.
fn cut(text: &str) -> String {
    if text.chars().count() <= VALUE_CHARS {
        text.to_owned()
    } else {
        let kept: String = text.chars().take(VALUE_CHARS - 1).collect();
        kept + "…"
    }
}

fn compact(value: &Value) -> String {
    // Serializing a `Value` cannot fail: its keys are strings.
    serde_json::to_string(value).unwrap_or_default()
}

fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sluice_core::recipe::{ImpliedValue, Literal};

    use super::*;

    fn object(value: Value) -> Map<String, Value> {
        let Value::Object(map) = value else {
            unreachable!("the tests pass objects")
        };
        map
    }

    fn named(pattern: &str) -> Example {
        Example {
            pattern: pattern.into(),
            body: String::new(),
            bytes_in: 0,
            bytes_out: 0,
            omitted: Vec::new(),
        }
    }

    #[test]
    fn every_kind_of_event_is_shown_once_before_any_is_shown_twice() {
        let a = [named("a1"), named("a2"), named("a3")];
        let b = [named("b1")];
        let c = [named("c1"), named("c2")];
        let shown: Vec<String> = round_robin(&[&a, &b, &c], 5)
            .into_iter()
            .map(|e| e.pattern)
            .collect();
        assert_eq!(shown, ["a1", "b1", "c1", "a2", "c2"]);
        assert_eq!(round_robin(&[], 10), Vec::<Example>::new());
    }

    #[test]
    fn each_left_out_field_says_why_and_an_implied_one_shows_the_value_to_put_back() {
        let recipe = EffectiveRecipe {
            drop_fields: ["Message".into()].into(),
            drop_empty_except: Some(std::collections::BTreeSet::new()),
            drop_implied: vec![ImpliedValue {
                field: "Channel".into(),
                value: Literal::Text("Security".into()),
                when: None,
            }],
            ..EffectiveRecipe::passthrough("t".into())
        };
        let before = object(json!({
            "EventID": 4624, "Message": "An account was logged on.", "Channel": "Security",
            "Note": ""
        }));
        let after = object(json!({"EventID": 4624}));
        let shown = example(&before, &after, Some("4624"), Some(&recipe));
        let reasons: Vec<(&str, &Omission)> = shown
            .omitted
            .iter()
            .map(|o| (o.path.as_str(), &o.reason))
            .collect();
        assert_eq!(
            reasons,
            [
                ("Message", &Omission::Recipe),
                ("Channel", &Omission::Implied("\"Security\"".into())),
                ("Note", &Omission::Empty),
            ]
        );
        assert_eq!(shown.body, r#"{"EventID":4624}"#);
        assert_eq!(shown.bytes_out, 16);
    }

    #[test]
    fn a_long_value_is_cut_so_one_event_cannot_fill_the_page() {
        let long = "x".repeat(500);
        let shown = example(
            &object(json!({"CommandLine": long, "Tags": [long]})),
            &object(json!({"CommandLine": long, "Tags": [long]})),
            None,
            None,
        );
        let cut = format!("{}…", "x".repeat(VALUE_CHARS - 1));
        assert_eq!(
            shown.body,
            format!(r#"{{"CommandLine":"{cut}","Tags":["{cut}"]}}"#)
        );
        assert_eq!(shown.pattern, "(no kind of event)");
        assert_eq!(
            shown.bytes_in, shown.bytes_out,
            "the bytes are the real event's"
        );
    }
}
