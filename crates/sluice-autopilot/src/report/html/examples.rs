//! "What the SIEM still receives": per source, a few events as they are sent, with what was
//! left out of each and why.

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
         event first, the kinds with the most data left first. Under each event: what was left \
         out, and why.</p><p class=\"muted\">These are real events from your sample, with long \
         text cut short. Leave them out with <code>sluice analyze --no-examples</code> before you \
         share this report outside your team.</p>{}",
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
        let rows: Vec<String> = source
            .examples
            .iter()
            .enumerate()
            .map(|(i, example)| row(i + 1, example))
            .collect();
        format!(
            "<div class=\"scroll\"><table class=\"examples\"><tr><th>#</th><th>Kind of event</th>\
             <th>Sent to the SIEM</th><th>Bytes in → out</th><th>Left out, and why</th></tr>{}\
             </table></div>",
            rows.concat()
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

fn row(n: usize, example: &Example) -> String {
    let pattern: String = example.pattern.chars().take(PATTERN_CHARS).collect();
    format!(
        "<tr><td class=\"n\">{n}</td><td><code title=\"{full}\">{pattern}</code></td><td><code>\
         {body}</code></td><td class=\"n\">{bin} → {bout}</td><td>{omitted}</td></tr>",
        full = escape(&example.pattern),
        pattern = escape(&pattern),
        body = escape(&example.body),
        bin = bytes(example.bytes_in),
        bout = bytes(example.bytes_out),
        omitted = omitted(example),
    )
}

/// What was left out of an event, one field per line: the largest [`SHOWN`], the rest folded.
fn omitted(example: &Example) -> String {
    if example.omitted.is_empty() {
        return "<span class=\"muted\">nothing: sent whole</span>".to_owned();
    }
    let (shown, rest) = example.omitted.split_at(example.omitted.len().min(SHOWN));
    let mut out: String = shown.iter().map(line).collect();
    if !rest.is_empty() {
        let size: u64 = rest.iter().map(|field| field.bytes).sum();
        let _ = write!(
            out,
            "<details><summary class=\"muted\">{} more, {}</summary>{}</details>",
            rest.len(),
            bytes(size),
            rest.iter().map(line).collect::<String>()
        );
    }
    out
}

/// Fields left out of an event shown before the rest is folded away.
const SHOWN: usize = 6;

fn line(field: &Omitted) -> String {
    let why = match &field.reason {
        Omission::Recipe => "<span class=\"muted\">repeats the event</span>".to_owned(),
        Omission::Empty => "<span class=\"muted\">empty</span>".to_owned(),
        Omission::Implied(value) => format!(
            "= <code>{}</code> <span class=\"tag\">implied</span>",
            escape(value)
        ),
    };
    format!(
        "<div><code>{}</code> {why} <span class=\"muted\">{}</span></div>",
        escape(&field.path),
        bytes(field.bytes)
    )
}

#[cfg(test)]
mod tests {
    use sluice_core::proof::Volume;

    use super::*;

    fn source(examples: Vec<Example>) -> SourceExamples {
        SourceExamples {
            source: "windows-security".into(),
            volume: Volume {
                events: 100,
                forwarded: 40,
                summarized: 60,
                bytes_in: 50_000,
                bytes_out: 9_000,
            },
            examples,
        }
    }

    #[test]
    fn an_example_shows_the_event_sent_and_each_field_left_out_with_why() {
        let example = Example {
            pattern: "4624".into(),
            body: r#"{"EventID":4624,"Note":"<b>"}"#.into(),
            bytes_in: 300,
            bytes_out: 30,
            omitted: vec![
                Omitted {
                    path: "Message".into(),
                    bytes: 200,
                    reason: Omission::Recipe,
                },
                Omitted {
                    path: "Channel".into(),
                    bytes: 20,
                    reason: Omission::Implied("\"Security\"".into()),
                },
            ],
        };
        let html = section(&[source(vec![example])]);
        assert!(html.contains("<b>windows-security</b>"));
        assert!(html.contains("1 of 100 events shown; 40 sent, 60 counted into summaries"));
        assert!(
            html.contains("&quot;Note&quot;:&quot;&lt;b&gt;&quot;"),
            "data is escaped"
        );
        assert!(html.contains("<code>Message</code> <span class=\"muted\">repeats the event"));
        assert!(html.contains(
            "<code>Channel</code> = <code>&quot;Security&quot;</code> <span class=\"tag\">implied"
        ));
        assert!(
            html.contains("--no-examples"),
            "it says how to leave them out"
        );
    }

    #[test]
    fn a_long_list_of_left_out_fields_shows_the_largest_and_folds_the_rest() {
        let field = |i: u64| Omitted {
            path: format!("f{i}"),
            bytes: 100 - i,
            reason: Omission::Empty,
        };
        let example = Example {
            pattern: String::new(),
            body: String::new(),
            bytes_in: 0,
            bytes_out: 0,
            omitted: (0..10).map(field).collect(),
        };
        let html = omitted(&example);
        let folded = html.find("<details>").expect("the rest is folded");
        assert!(html[..folded].contains("<code>f5</code>"));
        assert!(!html[..folded].contains("<code>f6</code>"));
        assert!(
            html.contains("4 more, 370 B"),
            "f6 to f9: 94 + 93 + 92 + 91 bytes"
        );
    }

    #[test]
    fn a_source_with_nothing_sent_says_so_and_no_examples_means_no_section() {
        assert!(section(&[source(Vec::new())]).contains("every one is counted"));
        assert_eq!(section(&[]), "");
    }
}
