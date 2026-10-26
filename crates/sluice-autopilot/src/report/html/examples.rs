//! "What the SIEM still receives": per source, a few events as they are sent, one row per event
//! and one column per field, so a reader sees at a glance which values still go and which were
//! left out, and why. The JSON of each event is folded away below the table.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use super::{bytes, escape, thousands};
use crate::report::{Example, Omission, Omitted, SourceExamples};

/// A kind of event's pattern is cut to this many characters; the whole is in its title.
const PATTERN_CHARS: usize = 48;

/// The section, or nothing when there are no examples.
pub(super) fn section(sources: &[SourceExamples]) -> String {
    if sources.is_empty() {
        return String::new();
    }
    let items: Vec<String> = sources
        .iter()
        .enumerate()
        .map(|(i, source)| item(source, i == 0))
        .collect();
    format!(
        "<h2>What the SIEM still receives</h2><p class=\"sub\">Per source, events from the sample \
         exactly as they are sent after the savings (as Vector sends them), one of each kind of \
         event first, the kinds with the most data left first. Each row is one event and each \
         column one field: a plain value is sent, a struck-through value is left out with the \
         reason in its marker, and a dot means the event has no such field. Scroll sideways for \
         every field.</p><p class=\"muted\">These are events of the sample as it was given, with \
         long text cut short: from your own logs, they hold your real values. Leave them out \
         with <code>sluice analyze --no-examples</code> before you share such a report outside \
         your team.</p>{}",
        items.concat()
    )
}

fn item(source: &SourceExamples, open: bool) -> String {
    let v = &source.volume;
    let counted = if v.summarized > 0 {
        format!(", {} counted into summaries", thousands(v.summarized))
    } else {
        String::new()
    };
    let body = if source.examples.is_empty() {
        "<p class=\"muted\">No event of this source is sent one by one: every one is counted \
         into summaries.</p>"
            .to_owned()
    } else {
        format!(
            "{}{}{}",
            legend(&source.examples),
            table(&source.source, &source.examples),
            raw(&source.examples)
        )
    };
    format!(
        "<details class=\"item\"{open}><summary><span class=\"what\"><b>{name}</b><span \
         class=\"muted\">{shown} of {events} events shown; {sent} sent{counted}</span></span>\
         <span class=\"amount\"><span class=\"muted\">{bin} → {bout}</span></span></summary>\
         <div class=\"body\">{body}</div></details>",
        open = if open { " open" } else { "" },
        name = escape(&source.source),
        shown = source.examples.len(),
        events = thousands(v.events),
        sent = thousands(v.forwarded),
        bin = bytes(v.bytes_in),
        bout = bytes(v.bytes_out),
    )
}

/// What each marker means, with how often it occurs in these examples.
fn legend(examples: &[Example]) -> String {
    let mut counts = [0usize; 3];
    for field in examples.iter().flat_map(|e| &e.omitted) {
        counts[match field.reason {
            Omission::Implied(_) => 0,
            Omission::Recipe => 1,
            Omission::Empty => 2,
        }] += 1;
    }
    format!(
        "<div class=\"legend\"><span><span class=\"v sent\">value</span> sent</span>\
         <span><span class=\"mk i\">I</span> implied: left out while it holds this value, and \
         put back from the plan ({})</span><span><span class=\"mk r\">R</span> repeats the \
         event: text made of fields it has ({})</span><span><span class=\"mk e\">E</span> \
         empty: it held nothing ({})</span><span><span class=\"absent\">·</span> not in that \
         event</span></div>",
        counts[0], counts[1], counts[2]
    )
}

/// A field shown as a column: in how many examples it is sent and left out.
#[derive(Default)]
struct Column {
    sent: usize,
    left: usize,
}

/// Every field of `examples`, those sent most often first, then those left out most often.
fn columns(examples: &[Example]) -> Vec<(&str, Column)> {
    let mut seen: BTreeMap<&str, Column> = BTreeMap::new();
    for example in examples {
        for field in &example.sent {
            seen.entry(&field.path).or_default().sent += 1;
        }
        for field in &example.omitted {
            seen.entry(&field.path).or_default().left += 1;
        }
    }
    let mut columns: Vec<(&str, Column)> = seen.into_iter().collect();
    columns.sort_by(|(a, x), (b, y)| y.sent.cmp(&x.sent).then(y.left.cmp(&x.left)).then(a.cmp(b)));
    columns
}

/// Under a column's name: whether the field goes, stays, or both.
fn note(column: &Column, examples: usize) -> String {
    match (column.sent, column.left) {
        (_, 0) => "sent".to_owned(),
        (0, left) => format!("left out in {left} of {examples}"),
        (sent, left) => format!("left out in {left}, sent in {sent}"),
    }
}

fn table(source: &str, examples: &[Example]) -> String {
    let columns = columns(examples);
    let mut heads = String::new();
    for (name, column) in &columns {
        let _ = write!(
            heads,
            "<th><code>{}</code><span class=\"note\">{}</span></th>",
            escape(name),
            note(column, examples.len())
        );
    }
    let rows: String = examples
        .iter()
        .enumerate()
        .map(|(i, example)| row(i + 1, example, &columns))
        .collect();
    format!(
        "<div class=\"events\" role=\"region\" tabindex=\"0\" aria-label=\"Events of {} as \
         sent\"><table class=\"events\"><tr><th class=\"c1 n\">#</th><th class=\"c2\">Kind of \
         event</th><th class=\"c3 n\">Bytes in → sent</th>{heads}</tr>{rows}</table></div>",
        escape(source)
    )
}

fn row(n: usize, example: &Example, columns: &[(&str, Column)]) -> String {
    let pattern: String = example.pattern.chars().take(PATTERN_CHARS).collect();
    let state = if example.omitted.is_empty() {
        "<span class=\"note\">sent whole</span>".to_owned()
    } else {
        format!(
            "<span class=\"note\">{} {} left out</span>",
            example.omitted.len(),
            if example.omitted.len() == 1 {
                "field"
            } else {
                "fields"
            }
        )
    };
    let sent: BTreeMap<&str, &str> = example
        .sent
        .iter()
        .map(|f| (f.path.as_str(), f.value.as_str()))
        .collect();
    let left: BTreeMap<&str, &Omitted> = example
        .omitted
        .iter()
        .map(|f| (f.path.as_str(), f))
        .collect();
    let cells: String = columns
        .iter()
        .map(|(name, _)| cell(sent.get(name).copied(), left.get(name).copied()))
        .collect();
    format!(
        "<tr><td class=\"c1 n\">{n}</td><td class=\"c2\"><code title=\"{full}\">{pattern}</code>\
         {state}</td><td class=\"c3 n\">{bin} → <b>{bout}</b>{kept}</td>{cells}</tr>",
        full = escape(&example.pattern),
        pattern = escape(&pattern),
        bin = bytes(example.bytes_in),
        bout = bytes(example.bytes_out),
        kept = kept(example),
    )
}

/// A bar of the share of the event that is still sent.
fn kept(example: &Example) -> String {
    let share = example
        .bytes_out
        .saturating_mul(100)
        .checked_div(example.bytes_in)
        .map_or(100, |share| share.clamp(2, 100));
    format!("<span class=\"bar kept\"><span class=\"s3\" style=\"width:{share}%\"></span></span>")
}

/// One field of one event: its value sent, the value left out and why, or a dot.
fn cell(sent: Option<&str>, left: Option<&Omitted>) -> String {
    match (left, sent) {
        (Some(field), _) => match &field.reason {
            Omission::Implied(value) => format!(
                "<td><span class=\"gone\" title=\"Left out as implied: {t}\"><span class=\"mk \
                 i\">I</span><span class=\"v\">{t}</span></span></td>",
                t = escape(value)
            ),
            Omission::Recipe => format!(
                "<td><span class=\"gone\" title=\"Left out: it repeats the event\"><span \
                 class=\"mk r\">R</span>repeats, {}</span></td>",
                bytes(field.bytes)
            ),
            Omission::Empty => "<td><span class=\"gone\" title=\"Left out: it held nothing\">\
                                <span class=\"mk e\">E</span>empty</span></td>"
                .to_owned(),
        },
        (None, Some(value)) => format!(
            "<td><span class=\"v sent\" title=\"{v}\">{v}</span></td>",
            v = escape(value)
        ),
        (None, None) => {
            "<td><span class=\"absent\" aria-label=\"not in this event\">·</span></td>".to_owned()
        }
    }
}

/// Each event's JSON as sent, folded away below the table.
fn raw(examples: &[Example]) -> String {
    let mut out =
        String::from("<details class=\"raw\"><summary>Raw JSON, as each event is sent</summary>");
    for (i, example) in examples.iter().enumerate() {
        let _ = write!(
            out,
            "<p class=\"muted\">#{n} · <code>{pattern}</code> · {bout}</p><pre><code>{raw}</code>\
             </pre>",
            n = i + 1,
            pattern = escape(
                &example
                    .pattern
                    .chars()
                    .take(PATTERN_CHARS)
                    .collect::<String>()
            ),
            bout = bytes(example.bytes_out),
            raw = escape(&example.raw),
        );
    }
    out.push_str("</details>");
    out
}

#[cfg(test)]
mod tests {
    use sluice_core::proof::Volume;

    use super::*;
    use crate::report::SentField;

    fn source(examples: Vec<Example>) -> SourceExamples {
        SourceExamples {
            source: "windows-security".into(),
            volume: Volume {
                events: 100,
                forwarded: 40,
                summarized: 60,
                summaries: 0,
                bytes_in: 50_000,
                bytes_out: 9_000,
            },
            examples,
        }
    }

    fn sent(path: &str, value: &str) -> SentField {
        SentField {
            path: path.into(),
            value: value.into(),
        }
    }

    fn left(path: &str, reason: Omission) -> Omitted {
        Omitted {
            path: path.into(),
            bytes: 200,
            reason,
        }
    }

    fn example(sent: Vec<SentField>, omitted: Vec<Omitted>) -> Example {
        Example {
            pattern: "4624".into(),
            raw: "{\n  \"EventID\": 4624\n}".into(),
            sent,
            bytes_in: 300,
            bytes_out: 30,
            omitted,
        }
    }

    #[test]
    fn each_field_is_a_column_and_each_cell_says_sent_left_out_and_why_or_absent() {
        let first = example(
            vec![sent("EventID", "4624"), sent("Note", "<b>")],
            vec![
                left("Message", Omission::Recipe),
                left("Channel", Omission::Implied("Security".into())),
                left("Blank", Omission::Empty),
            ],
        );
        let second = example(
            vec![sent("EventID", "4634"), sent("Channel", "Security")],
            vec![],
        );
        let html = section(&[source(vec![first, second])]);
        assert!(html.contains("<b>windows-security</b>"));
        assert!(html.contains("2 of 100 events shown; 40 sent, 60 counted into summaries"));
        assert!(
            html.contains("<span class=\"v sent\" title=\"&lt;b&gt;\">&lt;b&gt;</span>"),
            "a sent value, escaped: {html}"
        );
        assert!(html.contains("<span class=\"mk r\">R</span>repeats, 200 B"));
        assert!(html.contains("<span class=\"mk i\">I</span><span class=\"v\">Security</span>"));
        assert!(html.contains("<span class=\"mk e\">E</span>empty"));
        assert!(
            html.contains("<span class=\"absent\""),
            "the second has no Note"
        );
        assert!(html.contains("<code>Channel</code><span class=\"note\">left out in 1, sent in 1"));
        assert!(html.contains("<code>EventID</code><span class=\"note\">sent</span>"));
        assert!(html.contains("<code>Message</code><span class=\"note\">left out in 1 of 2"));
        assert!(html.contains("3 fields left out"));
        assert!(html.contains("sent whole"));
        assert!(html.contains("(1)</span>"), "the legend counts each reason");
        assert!(
            html.contains("--no-examples"),
            "it says how to leave them out"
        );
    }

    #[test]
    fn the_fields_sent_most_often_come_first() {
        let a = example(
            vec![sent("Z", "1"), sent("A", "1")],
            vec![left("M", Omission::Recipe)],
        );
        let b = example(
            vec![sent("Z", "2")],
            vec![left("M", Omission::Recipe), left("E", Omission::Empty)],
        );
        let examples = [a, b];
        let names: Vec<&str> = columns(&examples).into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["Z", "A", "M", "E"]);
    }

    #[test]
    fn the_raw_json_of_every_event_is_folded_below_the_table() {
        let html = section(&[source(vec![example(vec![sent("EventID", "4624")], vec![])])]);
        let table = html.find("<table class=\"events\">").expect("the table");
        let raw = html.find("<details class=\"raw\">").expect("the raw JSON");
        assert!(table < raw);
        assert!(html[raw..].contains("<pre><code>{\n  &quot;EventID&quot;: 4624\n}</code></pre>"));
    }

    #[test]
    fn the_bar_shows_the_share_still_sent_and_never_vanishes() {
        let mut e = example(vec![], vec![]);
        assert!(kept(&e).contains("width:10%"), "30 of 300 bytes");
        e.bytes_out = 0;
        assert!(kept(&e).contains("width:2%"));
        e.bytes_in = 0;
        assert!(kept(&e).contains("width:100%"));
    }

    #[test]
    fn a_source_with_nothing_sent_says_so_and_no_examples_means_no_section() {
        assert!(section(&[source(Vec::new())]).contains("every one is counted"));
        assert_eq!(section(&[]), "");
    }

    #[test]
    fn the_first_source_is_open_the_rows_count_from_one_and_no_counting_is_not_mentioned() {
        let one = || example(vec![sent("EventID", "1")], vec![]);
        let mut quiet = source(vec![one(), one()]);
        quiet.source = "dns".into();
        quiet.volume.summarized = 0;
        let html = section(&[source(vec![one()]), quiet]);
        let first = html
            .find("<b>windows-security</b>")
            .expect("the first source");
        let second = html.find("<b>dns</b>").expect("the second source");
        assert!(
            html[..first].ends_with("<details class=\"item\" open><summary><span class=\"what\">")
        );
        assert!(!html[first..second].contains(" open>"));
        assert!(html[first..second].contains(", 60 counted into summaries"));
        assert!(
            !html[second..].contains("counted into summaries"),
            "none are counted"
        );
        assert!(html[second..].contains("<tr><td class=\"c1 n\">1</td>"));
        assert!(html[second..].contains("<tr><td class=\"c1 n\">2</td>"));
    }
}
