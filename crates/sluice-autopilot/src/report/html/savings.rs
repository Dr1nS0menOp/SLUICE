//! The advice: the largest savings first, by kind of event and by source, with the smaller ones
//! and the data sent unchanged folded away.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use sluice_core::proof::Volume;

use super::{bytes, escape, list, thousands};
use crate::report::{TemplateRow, percent};

/// The "biggest savings" list stops once it covers this share of all saved bytes, in percent.
const MAIN_SHARE: u64 = 90;
/// And holds at most this many kinds of event; the rest are folded away.
const MAIN_MAX: usize = 12;
/// A pattern is cut to this many characters in a summary line; the whole is in its title.
const PATTERN_CHARS: usize = 90;

/// The savings sections. `rows` come largest saving first.
pub(super) fn advice(rows: &[TemplateRow]) -> String {
    let saved: u64 = rows.iter().map(TemplateRow::saved_bytes).sum();
    let (main, rest) = split(rows, saved);
    let (smaller, unchanged): (Vec<&TemplateRow>, Vec<&TemplateRow>) =
        rest.into_iter().partition(|row| row.saved_bytes() > 0);

    let mut out = String::from("<h2>Biggest savings</h2>");
    if main.is_empty() {
        out.push_str(
            "<p class=\"muted\">Nothing can be saved on this sample without changing a detection. \
             Why each kind of event is sent unchanged is listed below.</p>",
        );
    } else {
        let covered: u64 = main.iter().map(|row| row.saved_bytes()).sum();
        let _ = write!(
            out,
            "<p class=\"sub\">{} {} {:.0}% of what can be saved. Open one to see what to \
             change, which fields go, and why that is safe.</p>",
            kinds(main.len()),
            if main.len() == 1 { "makes" } else { "make" },
            percent(covered, saved)
        );
        for (rank, row) in main.iter().enumerate() {
            out.push_str(&item(Some(rank + 1), row, rank == 0));
        }
    }
    out.push_str(&sources(rows));
    out.push_str(&folded(
        "Smaller savings",
        &smaller,
        "Each saves little on its own; together they are the rest of the saving.",
    ));
    out.push_str(&folded(
        "Sent unchanged",
        &unchanged,
        "Nothing is removed from these; each says why.",
    ));
    out
}

/// The leading rows that make up [`MAIN_SHARE`] of `saved`, at most [`MAIN_MAX`], and the rest.
fn split(rows: &[TemplateRow], saved: u64) -> (Vec<&TemplateRow>, Vec<&TemplateRow>) {
    let mut main = Vec::new();
    let mut rest = Vec::new();
    let mut covered: u64 = 0;
    for row in rows {
        let wanted = covered.saturating_mul(100) < saved.saturating_mul(MAIN_SHARE);
        if row.saved_bytes() > 0 && wanted && main.len() < MAIN_MAX {
            covered += row.saved_bytes();
            main.push(row);
        } else {
            rest.push(row);
        }
    }
    (main, rest)
}

/// "1 kind of event", "2 kinds of event".
fn kinds(n: usize) -> String {
    if n == 1 {
        "1 kind of event".to_owned()
    } else {
        format!("{n} kinds of event")
    }
}

/// A folded section of rows, with how many there are and what they save.
fn folded(title: &str, rows: &[&TemplateRow], note: &str) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let saved: u64 = rows.iter().map(|row| row.saved_bytes()).sum();
    let size: u64 = rows.iter().map(|row| row.volume.bytes_in).sum();
    let items: Vec<String> = rows.iter().map(|row| item(None, row, false)).collect();
    format!(
        "<details class=\"section\"><summary><h2>{title}</h2><span class=\"muted\">{}, {} in, \
         {} saved</span></summary><p class=\"muted\">{note}</p>{}</details>",
        kinds(rows.len()),
        bytes(size),
        bytes(saved),
        items.concat()
    )
}

/// One kind of event: its saving in the summary line, everything else when opened.
fn item(rank: Option<usize>, row: &TemplateRow, open: bool) -> String {
    let v = &row.volume;
    let saved = saved_percent(v);
    let pattern: String = row.pattern.chars().take(PATTERN_CHARS).collect();
    let headline = headline(row);
    let rank = rank.map_or_else(String::new, |n| format!("<span class=\"rank\">{n}</span>"));
    format!(
        "<details class=\"item\"{open}><summary>{rank}<span class=\"what\"><b>{source}</b> \
         <code title=\"{full}\">{pattern}</code><span class=\"muted\">{headline}</span></span>\
         <span class=\"amount\">{pill}<span class=\"muted\">{out} of {size} saved</span>{bar}\
         </span></summary><div class=\"body\">{body}</div></details>",
        open = if open { " open" } else { "" },
        source = escape(&row.source),
        full = escape(&row.pattern),
        pattern = escape(&pattern),
        headline = escape(&headline),
        pill = pill(saved),
        out = bytes(row.saved_bytes()),
        size = bytes(v.bytes_in),
        bar = bar(saved),
        body = body(row),
    )
}

/// The change that saves the most, in one line: counting events instead of sending them, then
/// the first field removal on the events still sent.
fn headline(row: &TemplateRow) -> String {
    let v = &row.volume;
    let mut parts = Vec::new();
    if v.summarized > 0 {
        parts.push(if v.forwarded == 0 {
            format!(
                "count all {} events instead of sending them",
                thousands(v.events)
            )
        } else {
            format!(
                "count {} of {} events instead of sending them",
                thousands(v.summarized),
                thousands(v.events)
            )
        });
    }
    if v.forwarded > 0
        && let Some(removal) = row.actions.iter().find(|a| a.starts_with("drop "))
    {
        parts.push(removal.clone());
    }
    if parts.is_empty() {
        "sent unchanged".to_owned()
    } else {
        parts.join("; ")
    }
}

/// What an opened item shows: the numbers, what to change, the fields, and why.
fn body(row: &TemplateRow) -> String {
    let v = &row.volume;
    let mut out = format!(
        "<div class=\"facts\"><div><span class=\"k\">Events</span>{events}</div>\
         <div><span class=\"k\">Sent, in full or reduced</span>{forwarded}</div>\
         <div><span class=\"k\">Counted into summaries</span>{summarized}</div>\
         <div><span class=\"k\">Bytes in → out</span>{bin} → {bout}</div></div>",
        events = thousands(v.events),
        forwarded = thousands(v.forwarded),
        summarized = thousands(v.summarized),
        bin = bytes(v.bytes_in),
        bout = bytes(v.bytes_out),
    );
    out.push_str("<h4>What to change</h4>");
    if row.actions.is_empty() {
        out.push_str("<p class=\"muted\">Nothing: it is sent as it is.</p>");
    } else {
        out.push_str(&list(&row.actions));
    }
    if let Some(runs_in) = &row.runs_in {
        let _ = write!(out, "<p class=\"muted\">Runs in: {}</p>", escape(runs_in));
    }
    if !row.removed.is_empty() {
        out.push_str(&removed(row));
    }
    if !row.adjustments.is_empty() {
        out.push_str("<h4>Why, and what was held back</h4>");
        out.push_str(&list(&row.adjustments));
    }
    let _ = write!(
        out,
        "<p class=\"muted\">{}Kind of event <code>{}</code></p>",
        row.provenance
            .as_ref()
            .map(|p| format!("{}. ", escape(p)))
            .unwrap_or_default(),
        escape(&row.id)
    );
    out
}

/// The fields removed from the sample's events: what each saved, why it may go, and where its
/// removal can run; then the recipe's own reasoning.
fn removed(row: &TemplateRow) -> String {
    let lines: Vec<String> = row
        .removed
        .iter()
        .map(|field| {
            format!(
                "<tr><td><code>{}</code></td><td class=\"n\">{} of {}</td><td class=\"n\">{}</td>\
                 <td>{}</td><td>{}</td></tr>",
                escape(&field.path),
                thousands(field.events),
                thousands(row.volume.forwarded),
                bytes(field.bytes),
                escape(&field.why),
                escape(&field.runs_in),
            )
        })
        .collect();
    let mut out = format!(
        "<h4>Fields removed on the sample</h4><div class=\"scroll\"><table class=\"fields\"><tr>\
         <th>Field</th><th>Events that lost it</th><th>Bytes</th><th>Why it may go</th>\
         <th>Where</th></tr>{}</table></div>",
        lines.concat()
    );
    if let Some(rationale) = &row.rationale {
        let _ = write!(
            out,
            "<p class=\"muted\">The recipe's reasoning: {}</p>",
            escape(rationale)
        );
    }
    if row
        .removed
        .iter()
        .any(|f| f.mode == crate::mode::Mode::Implied)
    {
        out.push_str(
            "<p class=\"muted\">An implied value is not lost: <code>plan.json</code> lists it \
             under <code>remove_implied</code>, so it can be put back. For Microsoft Sentinel \
             the function <code>&lt;Table&gt;Full</code> that <code>--sentinel-native</code> \
             writes puts it back at query time, and for Elasticsearch the runtime fields that \
             <code>--elastic-native</code> writes. The archive keeps every event whole.</p>",
        );
    }
    out
}

/// Each source with what it saves, largest first; opened, its kinds of event.
fn sources(rows: &[TemplateRow]) -> String {
    let mut by_source: BTreeMap<&str, (Volume, Vec<&TemplateRow>)> = BTreeMap::new();
    for row in rows {
        let (volume, members) = by_source.entry(&row.source).or_default();
        volume.events += row.volume.events;
        volume.forwarded += row.volume.forwarded;
        volume.summarized += row.volume.summarized;
        volume.bytes_in += row.volume.bytes_in;
        volume.bytes_out += row.volume.bytes_out;
        members.push(row);
    }
    let mut sources: Vec<(&str, (Volume, Vec<&TemplateRow>))> = by_source.into_iter().collect();
    sources
        .sort_by(|(a, (va, _)), (b, (vb, _))| saved_bytes(vb).cmp(&saved_bytes(va)).then(a.cmp(b)));
    let items: Vec<String> = sources
        .iter()
        .map(|(source, (volume, members))| {
            let saved = saved_percent(volume);
            let kinds_of_event: Vec<String> = members
                .iter()
                .map(|row| {
                    let pattern: String = row.pattern.chars().take(PATTERN_CHARS).collect();
                    format!(
                        "<tr><td><code title=\"{}\">{}</code></td><td class=\"n\">{}</td>\
                         <td class=\"n\">{} → {}</td><td class=\"n\">{}</td></tr>",
                        escape(&row.pattern),
                        escape(&pattern),
                        thousands(row.volume.events),
                        bytes(row.volume.bytes_in),
                        bytes(row.volume.bytes_out),
                        pill(saved_percent(&row.volume)),
                    )
                })
                .collect();
            format!(
                "<details class=\"item\"><summary><span class=\"what\"><b>{source}</b>\
                 <span class=\"muted\">{events} events, {kinds}</span></span><span \
                 class=\"amount\">{pill}<span class=\"muted\">{bin} → {bout}</span>{bar}</span>\
                 </summary><div class=\"body\"><div class=\"scroll\"><table class=\"fields\"><tr>\
                 <th>Kind of event</th><th>Events</th><th>Bytes in → out</th><th>Saved</th></tr>\
                 {rows}</table></div></div></details>",
                source = escape(source),
                events = thousands(volume.events),
                kinds = kinds(members.len()),
                pill = pill(saved),
                bin = bytes(volume.bytes_in),
                bout = bytes(volume.bytes_out),
                bar = bar(saved),
                rows = kinds_of_event.concat(),
            )
        })
        .collect();
    format!(
        "<h2>Savings by source</h2><p class=\"sub\">Each type of data, largest saving first. Open \
         one for its kinds of event.</p>{}",
        items.concat()
    )
}

fn saved_bytes(volume: &Volume) -> u64 {
    volume.bytes_in.saturating_sub(volume.bytes_out)
}

fn saved_percent(volume: &Volume) -> f64 {
    percent(saved_bytes(volume), volume.bytes_in)
}

/// The colour step of a saving: none, a little, some, much, most.
pub(super) fn level(saved: f64) -> u8 {
    match saved {
        s if s < 1.0 => 0,
        s if s < 10.0 => 1,
        s if s < 30.0 => 2,
        s if s < 60.0 => 3,
        _ => 4,
    }
}

/// The saving as a coloured percentage.
pub(super) fn pill(saved: f64) -> String {
    format!("<span class=\"pill s{}\">−{saved:.0}%</span>", level(saved))
}

/// The saving as a coloured bar; the empty part is what is still sent.
pub(super) fn bar(saved: f64) -> String {
    format!(
        "<span class=\"bar\"><span class=\"s{}\" style=\"width:{:.1}%\"></span></span>",
        level(saved),
        saved.clamp(0.0, 100.0)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, bytes_in: u64, bytes_out: u64) -> TemplateRow {
        TemplateRow {
            id: id.into(),
            source: "s".into(),
            pattern: id.into(),
            volume: Volume {
                events: 1,
                forwarded: 1,
                summarized: 0,
                bytes_in,
                bytes_out,
            },
            actions: Vec::new(),
            adjustments: Vec::new(),
            provenance: None,
            runs_in: None,
            removed: Vec::new(),
            rationale: None,
        }
    }

    #[test]
    fn the_biggest_savings_stop_once_they_cover_most_of_the_saving() {
        // Saved: 80, 15, 4, 1 and 0 of 100.
        let rows = [
            row("a", 100, 20),
            row("b", 100, 85),
            row("c", 100, 96),
            row("d", 100, 99),
            row("e", 100, 100),
        ];
        let (main, rest) = split(&rows, 100);
        let ids = |rows: &[&TemplateRow]| rows.iter().map(|r| r.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&main), ["a", "b"], "80 + 15 reach 90 % of 100");
        assert_eq!(ids(&rest), ["c", "d", "e"]);
    }

    #[test]
    fn nothing_saved_puts_nothing_in_the_biggest_savings() {
        let rows = [row("a", 100, 100)];
        let (main, rest) = split(&rows, 0);
        assert_eq!(main.len(), 0);
        assert_eq!(rest.len(), 1);
    }

    #[test]
    fn the_biggest_savings_hold_at_most_twelve() {
        let rows: Vec<TemplateRow> = (0..20).map(|i| row(&format!("{i:02}"), 10, 9)).collect();
        let (main, rest) = split(&rows, 20);
        assert_eq!(main.len(), MAIN_MAX);
        assert_eq!(rest.len(), 8);
    }

    #[test]
    fn the_headline_names_the_change_that_saves_the_most() {
        let mut counted = row("a", 100, 0);
        counted.volume.events = 15_000;
        counted.volume.forwarded = 0;
        counted.volume.summarized = 15_000;
        counted.actions = vec!["drop Message".into(), "forward events …".into()];
        assert_eq!(
            headline(&counted),
            "count all 15,000 events instead of sending them"
        );

        counted.volume.forwarded = 470;
        counted.volume.summarized = 14_530;
        assert_eq!(
            headline(&counted),
            "count 14,530 of 15,000 events instead of sending them; drop Message"
        );

        let mut reduced = row("b", 100, 40);
        reduced.actions = vec!["drop Message".into()];
        assert_eq!(headline(&reduced), "drop Message");
        assert_eq!(headline(&row("c", 100, 100)), "sent unchanged");
    }

    #[test]
    fn a_saving_is_coloured_by_its_size() {
        assert_eq!(level(0.0), 0);
        assert_eq!(level(0.9), 0);
        assert_eq!(level(4.0), 1);
        assert_eq!(level(25.0), 2);
        assert_eq!(level(45.0), 3);
        assert_eq!(level(74.0), 4);
        assert!(pill(62.4).contains("class=\"pill s4\">−62%"));
        assert!(bar(150.0).contains("width:100.0%"), "a bar never overflows");
    }
}
