//! "What implied means": the mode `implied` in plain words, for a reader without context, with
//! the largest implied value of this sample as the example.

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
         holds is simply sent: the saving shrinks, nothing goes wrong.</p>{example}</section>",
        example = example(report),
    )
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
            why: "always \"0x8020000000000000\" on this kind of event".into(),
            runs_in: String::new(),
        }];
        report.templates = vec![row];
        let text = explain(&report);
        assert!(text.contains("only while the event holds exactly that value"));
        assert!(text.contains("<code>Keywords</code> on windows-security events"));
        assert!(text.contains("Leaving it out of 1,200 events saved 45 KB"));
    }
}
