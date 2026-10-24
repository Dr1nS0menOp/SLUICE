//! "What implied means": the mode `implied` in plain words, for a reader without context, with
//! the largest implied value of this sample as the example.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use super::{bytes, escape, thousands};
use crate::mode::Mode;
use crate::report::{RemovedField, Report, TemplateRow};

/// The explanation, or nothing when the mode did not run.
pub(super) fn explain(report: &Report) -> String {
    if !report.modes.contains(&Mode::Implied) {
        return String::new();
    }
    format!(
        "<section class=\"meaning\"><h2>What “implied” means</h2>\
         <p>Many fields of a log event hold a value that follows from what kind of event it is. \
         Every event in the Windows Security log says <code>Channel: Security</code>. Others \
         follow from another field: in a Windows logon (event 4624), \
         <code>RestrictedAdminMode</code> is <code>-</code> unless <code>LogonType</code> is 10, \
         a remote desktop logon. Sending such a value tells the SIEM nothing it could not work \
         out itself, much as a form need not repeat the country on every line once it is \
         printed at the top. Sluice calls such a value <b>implied</b>.</p>\
         <p>Sluice leaves an implied value out <b>only while the event holds exactly that \
         value</b>: an event that holds another one is sent with the field as it is. So nothing \
         is lost. <code>plan.json</code> lists every implied value, which lets any tool fill a \
         missing field back in exactly. For Microsoft Sentinel, the function \
         <code>&lt;Table&gt;Full</code> that Sluice writes does that when a query runs, and for \
         Elasticsearch the runtime fields it writes do so in a search or a data view. The \
         archive keeps every event whole.</p>\
         <p>Implied values are learned from this sample, only from fields that behave as \
         categories: few values, each seen often, and no new value late in the sample. \
         Identifiers such as logon IDs never count, and a field a detection rule reads stays on \
         every event that rule could match. If the data changes later, a value that no longer \
         holds is simply sent: the saving shrinks, nothing goes wrong.</p>{example}{everywhere}\
         </section>",
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
            "<p class=\"muted\">On <b>{source}</b>, {n} implied value(s) are the same on every \
             kind of event that has them ({list}), {saved} of the saving. If the sample comes \
             from one machine, some of them may be that machine's, such as its name, rather \
             than the kind of event's: on other machines such a field is simply sent, so the \
             saving there is lower, never the data. A sample from several machines settles \
             it.</p>",
            source = escape(source),
            n = alike.len(),
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
        assert!(text.contains("only while the event holds exactly that value"));
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
                "On <b>SecurityEvent</b>, 1 implied value(s) are the same on every kind of event \
                 that has them (<code>Computer</code> = <code>DESKTOP-1</code>), 1 KB of the saving"
            ),
            "{text}"
        );
        assert!(!text.contains("Task"), "it differs per kind of event");
        assert!(!text.contains("ObjectServer"));
        assert_eq!(everywhere(&crate::report::tests::report()), "");
    }
}
