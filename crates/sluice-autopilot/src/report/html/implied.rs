//! "What implied means": the mode `implied` in plain words, for a reader without context, with
//! the largest implied value of this sample as the example.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use super::{bytes, escape, thousands};
use crate::mode::Mode;
use crate::report::{RemovedField, Report, TemplateRow};

/// Microsoft's reference page of event 4624, the explanation's example (checked 2026-10-26): it
/// gives the event's description, and says `RestrictedAdminMode` is `-` on every logon that is
/// not remote interactive.
const EVENT_4624: &str = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/\
                          windows-10/security/threat-protection/auditing/event-4624";

/// The explanation, or nothing when the mode did not run.
pub(super) fn explain(report: &Report) -> String {
    if !report.modes.contains(&Mode::Implied) {
        return String::new();
    }
    format!(
        "<section class=\"meaning\"><h2>What “implied” means</h2>\
         <p>A value is <b>implied</b> when the rest of the event already says what it is. That \
         happens in two ways.</p>\
         <ul><li><b>The kind of event fixes it.</b> Every Windows event 4624 (a successful \
         logon) comes from <code>Channel</code> <code>Security</code>, and Sentinel's \
         <code>Activity</code> column holds the same text on each of them: <code>4624 - An \
         account was successfully logged on.</code> Such a text carries no data of the event \
         itself: it is the event ID's description, which Microsoft's event reference on the \
         internet gives for every ID (for 4624: <a href=\"{EVENT_4624}\">4624(S) An account \
         was successfully logged on</a>), so it can always be looked up again.</li>\
         <li><b>Another field fixes it.</b> In the same event 4624, \
         <code>RestrictedAdminMode</code> is <code>-</code> on every logon whose \
         <code>LogonType</code> is not 10 (remote desktop), as the same reference says: once \
         the SIEM has <code>LogonType</code>, it knows <code>RestrictedAdminMode</code>.</li>\
         </ul>\
         <p><b>What Sluice does with it.</b> It leaves the field out only on an event that holds \
         exactly that value. An event with any other value in the field is sent with the field \
         as it is. <code>plan.json</code> lists every implied value and when it applies, under \
         <code>remove_implied</code>, so any tool can put the field back exactly. In Microsoft \
         Sentinel, query <code>&lt;Table&gt;Full</code> instead of <code>&lt;Table&gt;</code>: \
         Sluice writes that function, and it fills the fields back in. In Elasticsearch, the \
         runtime fields Sluice writes do the same in searches and data views. The archive \
         keeps every event whole.</p>\
         <p><b>How Sluice finds them.</b> It learns them from this sample, and only on kinds of \
         event frequent enough to be reduced at all: a rare kind of event is always sent \
         whole. A value the kind of event fixes must be the same on every event of that kind \
         in the sample. A field that fixes another must behave as a category: 2 to 32 distinct \
         values, no value in the second half of the sample that the first half lacked, and a \
         name that is not an identifier's (ending in <code>Id</code> or <code>Guid</code>, \
         such as a logon ID). Each of its values needs at least 20 events before Sluice learns \
         what it fixes. A field named as an identifier is itself fixed only by the kind of \
         event, never by another field: a thread or a process one machine kept through the \
         sample changes at its next restart. A field a detection rule reads is never left out of an event that rule \
         could match.</p>\
         <p><b>When the data changes.</b> If an event later holds another value, that event \
         simply carries the field: the saving gets smaller, and nothing is lost or \
         wrong.</p>{example}{everywhere}</section>",
        example = example(report),
        everywhere = everywhere(report),
    )
}

/// One field's implied constants on the kinds of event of a source.
#[derive(Default)]
struct Seen<'a> {
    values: BTreeSet<&'a str>,
    kinds: usize,
    bytes: u64,
}

/// Values shown per source in [`everywhere`].
const SHOWN: usize = 4;

/// Per source, the values that are implied alike on every kind of event that has them: on a
/// sample of one machine its name looks implied too, and nothing in the data tells it from a
/// value the kind of event fixes. Said with what they saved, so a reader knows how much of the
/// saving a sample from more machines could take back.
fn everywhere(report: &Report) -> String {
    let mut by_source: BTreeMap<&str, BTreeMap<&str, Seen<'_>>> = BTreeMap::new();
    let mut conditional: BTreeSet<(&str, &str)> = BTreeSet::new();
    for row in &report.templates {
        for field in row.removed.iter().filter(|f| f.mode == Mode::Implied) {
            match &field.constant {
                Some(value) => {
                    let entry = by_source
                        .entry(&row.source)
                        .or_default()
                        .entry(&field.path)
                        .or_default();
                    entry.values.insert(value);
                    entry.kinds += 1;
                    entry.bytes += field.bytes;
                }
                None => {
                    conditional.insert((&row.source, &field.path));
                }
            }
        }
    }
    let mut out = String::new();
    for (source, fields) in by_source {
        let alike: Vec<(&str, &str, u64)> = fields
            .into_iter()
            .filter(|(field, seen)| {
                seen.values.len() == 1 && seen.kinds > 1 && !conditional.contains(&(source, *field))
            })
            .filter_map(|(field, seen)| {
                seen.values.first().map(|value| (field, *value, seen.bytes))
            })
            .collect();
        if alike.is_empty() {
            continue;
        }
        let saved: u64 = alike.iter().map(|(_, _, b)| b).sum();
        let mut shown: Vec<String> = alike
            .iter()
            .take(SHOWN)
            .map(|(field, value, _)| {
                format!(
                    "<code>{}</code> = <code>{}</code>",
                    escape(field),
                    escape(value)
                )
            })
            .collect();
        if alike.len() > SHOWN {
            shown.push(format!("{} more", alike.len() - SHOWN));
        }
        let _ = write!(
            out,
            "<p class=\"muted\"><b>Check these on {source}.</b> {n} {fields} the same value on \
             every kind of event that has {them}: {list}. {together} {saved}. A value \
             that is the same everywhere may belong to the machine the sample came from, such \
             as its name or its domain, rather than to the kind of event. If so, events from \
             other machines simply carry the field: the saving there is smaller, and no data is \
             lost. A sample from several machines tells the two apart.</p>",
            source = escape(source),
            n = alike.len(),
            fields = if alike.len() == 1 {
                "field has"
            } else {
                "fields have"
            },
            them = if alike.len() == 1 { "it" } else { "them" },
            together = if alike.len() == 1 {
                "It saves"
            } else {
                "Together they save"
            },
            list = shown.join(", "),
            saved = bytes(saved),
        );
    }
    out
}

/// The implied value that saved the most on this sample, in one sentence.
fn example(report: &Report) -> String {
    let largest: Option<(&TemplateRow, &RemovedField)> = report
        .templates
        .iter()
        .flat_map(|row| row.removed.iter().map(move |field| (row, field)))
        .filter(|(_, field)| field.mode == Mode::Implied)
        .max_by(|(a, x), (b, y)| x.bytes.cmp(&y.bytes).then(b.id.cmp(&a.id)));
    let Some((row, field)) = largest else {
        return "<p class=\"muted\">In this sample, no field held an implied value Sluice could \
                leave out.</p>"
            .to_owned();
    };
    format!(
        "<p class=\"muted\">The largest in this sample: <code>{path}</code> on {source} events of \
         the kind <code>{pattern}</code>. Why: {why}. Leaving it out of {events} events saved \
         {saved}.</p>",
        path = escape(&field.path),
        source = escape(&row.source),
        pattern = escape(&row.pattern.chars().take(60).collect::<String>()),
        why = escape(&field.why),
        events = thousands(field.events),
        saved = bytes(field.bytes),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::report::RemovedField;

    #[test]
    fn the_explanation_appears_only_when_the_mode_ran_and_names_the_largest_value() {
        let mut report = crate::report::tests::report();
        report.modes = BTreeSet::from([Mode::Rules]);
        assert_eq!(explain(&report), "");

        report.modes = Mode::ALL.into();
        assert!(explain(&report).contains("no field held an implied value"));

        let mut row = crate::report::tests::row_removing(&[]);
        row.source = "windows-security".into();
        row.removed = vec![RemovedField {
            path: "Keywords".into(),
            events: 1_200,
            bytes: 45_000,
            mode: Mode::Implied,
            constant: None,
            why: "always \"0x8020000000000000\" on this kind of event".into(),
            runs_in: String::new(),
        }];
        report.templates = vec![row];
        let text = explain(&report);
        assert!(text.contains("only on an event that holds exactly that value"));
        assert!(text.contains("Microsoft's event reference"), "{text}");
        assert!(
            text.contains(
                "<a href=\"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/\
                 windows-10/security/threat-protection/auditing/event-4624\">"
            ),
            "{text}"
        );
        assert!(text.contains("at least 20 events"), "{text}");
        assert!(text.contains("changes at its next restart"), "{text}");
        assert!(text.contains("<code>Keywords</code> on windows-security events"));
        assert!(text.contains("Leaving it out of 1,200 events saved 45 KB"));
    }

    fn constant(path: &str, value: &str, bytes: u64) -> RemovedField {
        RemovedField {
            path: path.into(),
            events: 1,
            bytes,
            mode: Mode::Implied,
            constant: Some(value.into()),
            why: String::new(),
            runs_in: String::new(),
        }
    }

    #[test]
    fn values_alike_on_every_kind_of_event_are_said_to_maybe_belong_to_the_machine() {
        let kind = |id: &str, removed: Vec<RemovedField>| {
            let mut row = crate::report::tests::row_removing(&[]);
            row.id = id.into();
            row.source = "SecurityEvent".into();
            row.removed = removed;
            row
        };
        let mut report = crate::report::tests::report();
        report.templates = vec![
            kind(
                "a",
                vec![
                    constant("Computer", "DESKTOP-1", 600),
                    constant("Task", "12544", 50),
                ],
            ),
            kind(
                "b",
                vec![
                    constant("Computer", "DESKTOP-1", 400),
                    constant("Task", "13824", 50),
                ],
            ),
            // One kind of event only: nothing to compare it with.
            kind("c", vec![constant("ObjectServer", "Security", 30)]),
        ];
        let text = everywhere(&report);
        assert!(
            text.contains(
                "<b>Check these on SecurityEvent.</b> 1 field has the same value on every kind of \
                 event that has it: <code>Computer</code> = <code>DESKTOP-1</code>. It saves 1 \
                 KB."
            ),
            "{text}"
        );
        assert!(!text.contains("Task"), "it differs per kind of event");
        assert!(!text.contains("ObjectServer"));
        assert_eq!(everywhere(&crate::report::tests::report()), "");
    }
    #[test]
    fn more_than_four_alike_values_are_counted_not_listed() {
        let kind = |id: &str, n: usize| {
            let mut row = crate::report::tests::row_removing(&[]);
            row.id = id.into();
            row.source = "s".into();
            row.removed = (0..n)
                .map(|i| constant(&format!("F{i}"), "v", 10))
                .collect();
            row
        };
        let with = |n: usize| {
            let mut report = crate::report::tests::report();
            report.templates = vec![kind("a", n), kind("b", n)];
            everywhere(&report)
        };
        assert!(!with(4).contains("more"), "{}", with(4));
        assert!(with(4).contains("<code>F3</code>"));
        assert!(with(6).contains(", 2 more. Together"), "{}", with(6));
        assert!(
            with(6).contains("6 fields have the same value"),
            "{}",
            with(6)
        );
        assert!(!with(6).contains("<code>F4</code>"));
    }
}
