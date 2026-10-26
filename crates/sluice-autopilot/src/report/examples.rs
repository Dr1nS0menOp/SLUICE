//! A few events of each source as the SIEM receives them: what is left after the savings, next
//! to what was left out and why. The data plane of the analysis reduces them, so they are
//! exactly what the proof saw.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sluice_core::event::{Event, encoded_size};
use sluice_core::guard::EffectiveRecipe;
use sluice_core::ids::{EventId, SourceId, TemplateId};
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
    /// The body sent, as indented JSON, with long text values cut to 80 characters.
    pub raw: String,
    /// The values sent, one per field (nested objects flattened to dotted paths; an emptied
    /// object holds no value and is left out), in the body's order.
    pub sent: Vec<SentField>,
    /// Bytes of the event as it came in.
    pub bytes_in: u64,
    /// Bytes of the event as sent.
    pub bytes_out: u64,
    /// What was left out of it, largest first.
    pub omitted: Vec<Omitted>,
}

/// A field an example sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentField {
    /// Its path.
    pub path: String,
    /// Its value: a text as it is, anything else as compact JSON, cut to 80 characters.
    pub value: String,
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
    /// It held the value the kind of event or another field implies, shown here as a sent value
    /// is (a text as it is, anything else as compact JSON, cut to 80 characters): it can be put
    /// back exactly.
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
    let found = find(
        &analysis.discovery.assignments,
        &analysis.data_plane,
        &kinds,
        input.events,
        per_source,
    );
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
            SourceExamples {
                source: source.id.to_string(),
                volume: volume_of(
                    kinds
                        .values()
                        .filter(|(t, _)| t.source == source.id)
                        .map(|(t, _)| per_template.get(&Some(t.id.clone()))),
                ),
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

/// The sum of `volumes`; a template the proof did not see counts nothing.
fn volume_of<'a>(volumes: impl Iterator<Item = Option<&'a Volume>>) -> Volume {
    let mut total = Volume::default();
    for v in volumes.flatten() {
        total.events += v.events;
        total.forwarded += v.forwarded;
        total.summarized += v.summarized;
        total.summaries += v.summaries;
        total.bytes_in += v.bytes_in;
        total.bytes_out += v.bytes_out;
    }
    total
}

#[derive(Default)]
struct Bucket {
    tried: usize,
    examples: Vec<Example>,
}

/// Per source and kind of event (as `assignments` gives it), the first `per_kind` events
/// `data_plane` sends, trying at most [`ATTEMPTS`] of each.
fn find<'a>(
    assignments: &'a BTreeMap<EventId, TemplateId>,
    data_plane: &impl Reducer,
    kinds: &BTreeMap<&TemplateId, (&Template, &EffectiveRecipe)>,
    events: &'a [Event],
    per_kind: usize,
) -> BTreeMap<(&'a SourceId, Option<&'a TemplateId>), Bucket> {
    let mut found: BTreeMap<(&SourceId, Option<&TemplateId>), Bucket> = BTreeMap::new();
    for event in events {
        let template = assignments.get(&event.id);
        let bucket = found.entry((&event.source, template)).or_default();
        if bucket.examples.len() >= per_kind || bucket.tried >= ATTEMPTS {
            continue;
        }
        bucket.tried += 1;
        // An event the data plane cannot reduce is not shown; the proof reports it.
        let Ok(reduced) = data_plane.reduce(event) else {
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
    // A field of an object the recipe removes whole is shown as that object, with its bytes;
    // the shell of an object that went because its fields did is no field of its own.
    let mut by_recipe: BTreeMap<String, u64> = BTreeMap::new();
    let mut omitted: Vec<Omitted> = Vec::new();
    for member in removed_members(before, after) {
        let named = recipe.and_then(|r| {
            r.drop_fields
                .iter()
                .filter(|f| f.covers(&member.path))
                .min()
        });
        if let Some(named) = named {
            *by_recipe.entry(named.to_string()).or_default() += to_u64(member.bytes);
        } else if !member.shell {
            omitted.push(Omitted {
                path: member.path.to_string(),
                bytes: to_u64(member.bytes),
                reason: match recipe {
                    Some(r) if text::implied(&member.path, r) => {
                        Omission::Implied(shown(member.value))
                    }
                    _ => Omission::Empty,
                },
            });
        }
    }
    omitted.extend(by_recipe.into_iter().map(|(path, bytes)| Omitted {
        path,
        bytes,
        reason: Omission::Recipe,
    }));
    omitted.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.path.cmp(&b.path)));
    let shown = shortened(after);
    let mut sent = Vec::new();
    flatten("", &shown, &mut sent);
    Example {
        pattern: pattern.unwrap_or("(no kind of event)").to_owned(),
        // Serializing a `Value` cannot fail: its keys are strings.
        raw: serde_json::to_string_pretty(&Value::Object(shown)).unwrap_or_default(),
        sent,
        bytes_in: to_u64(encoded_size(before)),
        bytes_out: to_u64(encoded_size(after)),
        omitted,
    }
}

/// Every value of `body` below `prefix`, nested objects as dotted paths.
fn flatten(prefix: &str, body: &Map<String, Value>, out: &mut Vec<SentField>) {
    for (key, value) in body {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match value {
            Value::Object(members) => flatten(&path, members, out),
            other => out.push(SentField {
                path,
                value: shown(other),
            }),
        }
    }
}

/// A value as an example shows it: a text as it is, anything else as compact JSON, cut to
/// [`VALUE_CHARS`] characters.
fn shown(value: &Value) -> String {
    match value {
        Value::String(text) => cut(text),
        other => cut(&compact(other)),
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
            raw: String::new(),
            sent: Vec::new(),
            bytes_in: 0,
            bytes_out: 0,
            omitted: Vec::new(),
        }
    }

    /// A data plane that forwards (or summarizes) every event unchanged, counting its calls.
    struct Counting {
        forward: bool,
        calls: std::cell::Cell<usize>,
    }

    impl Reducer for Counting {
        fn reduce(
            &self,
            event: &Event,
        ) -> Result<sluice_core::reduce::Reduced, sluice_core::reduce::ReduceError> {
            self.calls.set(self.calls.get() + 1);
            Ok(sluice_core::reduce::Reduced {
                template: None,
                outcome: if self.forward {
                    Outcome::Forwarded(event.fields.clone())
                } else {
                    Outcome::Summarized(serde_json::Map::new())
                },
            })
        }
    }

    fn events(n: usize, source: &str) -> Vec<Event> {
        (0..n)
            .map(|i| Event {
                id: EventId(i as u64),
                timestamp: sluice_core::event::Timestamp(0),
                source: SourceId::new(source),
                fields: object(json!({"n": i})),
            })
            .collect()
    }

    fn all_in(template: &TemplateId, events: &[Event]) -> BTreeMap<EventId, TemplateId> {
        events.iter().map(|e| (e.id, template.clone())).collect()
    }

    #[test]
    fn a_kind_of_event_stops_being_tried_once_it_has_enough_examples() {
        let template = TemplateId::from("t");
        let sample = events(50, "s");
        let plane = Counting {
            forward: true,
            calls: 0.into(),
        };
        let assignments = all_in(&template, &sample);
        let found = find(&assignments, &plane, &BTreeMap::new(), &sample, 3);
        assert_eq!(plane.calls.get(), 3);
        let source = SourceId::new("s");
        let bucket = &found[&(&source, Some(&template))];
        assert_eq!(bucket.examples.len(), 3);
    }

    #[test]
    fn a_kind_of_event_whose_events_are_all_counted_is_tried_a_thousand_times_at_most() {
        let template = TemplateId::from("t");
        let sample = events(ATTEMPTS + 500, "s");
        let plane = Counting {
            forward: false,
            calls: 0.into(),
        };
        let assignments = all_in(&template, &sample);
        let found = find(&assignments, &plane, &BTreeMap::new(), &sample, 10);
        assert_eq!(plane.calls.get(), ATTEMPTS);
        assert!(found.values().all(|b| b.examples.is_empty()));
    }

    #[test]
    fn sources_and_kinds_of_event_are_kept_apart_and_an_unclassified_event_has_its_own() {
        let template = TemplateId::from("t");
        let mut sample = events(4, "a");
        sample.extend(events(2, "b").into_iter().map(|e| Event {
            id: EventId(e.id.0 + 100),
            ..e
        }));
        // The first two of `a` are of `t`; the rest are unclassified.
        let assignments: BTreeMap<EventId, TemplateId> = [
            (EventId(0), template.clone()),
            (EventId(1), template.clone()),
        ]
        .into();
        let plane = Counting {
            forward: true,
            calls: 0.into(),
        };
        let found = find(&assignments, &plane, &BTreeMap::new(), &sample, 10);
        let (a, b) = (SourceId::new("a"), SourceId::new("b"));
        assert_eq!(found[&(&a, Some(&template))].examples.len(), 2);
        assert_eq!(found[&(&a, None)].examples.len(), 2);
        assert_eq!(found[&(&b, None)].examples.len(), 2);
        assert_eq!(found.len(), 3);
    }

    #[test]
    fn a_source_s_volume_is_its_kinds_of_event_together() {
        let one = Volume {
            events: 10,
            forwarded: 4,
            summarized: 6,
            summaries: 0,
            bytes_in: 1_000,
            bytes_out: 300,
        };
        let two = Volume {
            events: 1,
            forwarded: 1,
            summarized: 0,
            summaries: 0,
            bytes_in: 50,
            bytes_out: 50,
        };
        assert_eq!(
            volume_of([Some(&one), None, Some(&two)].into_iter()),
            Volume {
                events: 11,
                forwarded: 5,
                summarized: 6,
                summaries: 0,
                bytes_in: 1_050,
                bytes_out: 350,
            }
        );
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
                ("Channel", &Omission::Implied("Security".into())),
                ("Note", &Omission::Empty),
            ]
        );
        assert_eq!(shown.raw, "{\n  \"EventID\": 4624\n}");
        assert_eq!(shown.bytes_out, 16);
    }

    #[test]
    fn a_whole_object_the_recipe_removes_is_one_field_and_an_emptied_object_is_none() {
        let recipe = EffectiveRecipe {
            drop_fields: ["EventData".into()].into(),
            drop_implied: vec![ImpliedValue {
                field: "agent.id".into(),
                value: Literal::Text("a".into()),
                when: None,
            }],
            ..EffectiveRecipe::passthrough("t".into())
        };
        let before = object(json!({
            "EventID": 1, "EventData": {"User": "bob", "Note": "x"}, "agent": {"id": "a"}
        }));
        let after = object(json!({"EventID": 1}));
        let shown = example(&before, &after, None, Some(&recipe));
        let left: Vec<(&str, u64, &Omission)> = shown
            .omitted
            .iter()
            .map(|o| (o.path.as_str(), o.bytes, &o.reason))
            .collect();
        // `"EventData":{"User":"bob","Note":"x"},` is 38 bytes; `"id":"a",` is 9.
        assert_eq!(
            left,
            [
                ("EventData", 38, &Omission::Recipe),
                ("agent.id", 9, &Omission::Implied("a".into())),
            ]
        );
    }

    #[test]
    fn a_left_out_text_is_shown_as_the_text_it_is_even_when_cut_short() {
        let recipe = EffectiveRecipe {
            drop_implied: vec![ImpliedValue {
                field: "Image".into(),
                value: Literal::Text(format!(r"C:\Windows\{}", "x".repeat(100))),
                when: None,
            }],
            ..EffectiveRecipe::passthrough("t".into())
        };
        let before = object(json!({"Image": format!(r"C:\Windows\{}", "x".repeat(100))}));
        let shown = example(&before, &Map::new(), None, Some(&recipe));
        let Omission::Implied(text) = &shown.omitted[0].reason else {
            panic!("implied: {:?}", shown.omitted)
        };
        assert!(text.starts_with(r"C:\Windows\x"), "no JSON escapes: {text}");
        assert_eq!(text.chars().count(), VALUE_CHARS);
    }

    #[test]
    fn the_values_sent_are_flattened_to_paths_and_an_emptied_object_holds_none() {
        let body = object(json!({
            "EventID": 4624, "Channel": "Security", "agent": {"name": "WS-BOB", "id": {}},
            "ecs": {}, "Tags": ["a", "b"], "Gone": null
        }));
        let shown = example(&body, &body, None, None);
        let sent: Vec<(&str, &str)> = shown
            .sent
            .iter()
            .map(|f| (f.path.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(
            sent,
            [
                ("Channel", "Security"),
                ("EventID", "4624"),
                ("Gone", "null"),
                ("Tags", r#"["a","b"]"#),
                ("agent.name", "WS-BOB"),
            ]
        );
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
            shown.raw,
            format!("{{\n  \"CommandLine\": \"{cut}\",\n  \"Tags\": [\n    \"{cut}\"\n  ]\n}}")
        );
        assert_eq!(shown.sent[0].value, cut, "a sent text is cut too");
        assert_eq!(
            shown.sent[1].value.chars().count(),
            VALUE_CHARS,
            "and so is a list"
        );
        assert_eq!(shown.pattern, "(no kind of event)");
        assert_eq!(
            shown.bytes_in, shown.bytes_out,
            "the bytes are the real event's"
        );
    }
}
