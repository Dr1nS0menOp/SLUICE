//! The report as one self-contained HTML page: no scripts, no external resources. It reads as
//! advice: what can be saved first, largest saving first, and the detail folded away.

mod examples;
mod implied;
mod savings;

use std::collections::BTreeMap;
use std::fmt::Write as _;

use sluice_core::ids::{Engine, RuleId};
use sluice_core::problem::{Problem, ProblemKind};

use super::{Report, RuleRow, rules::label};
use crate::mode::Mode;

const STYLE: &str = r#"
:root { --bg:#ffffff; --fg:#1b1f24; --muted:#5b6470; --line:#e3e6ea; --card:#f6f8fa;
        --good:#1a7f37; --bad:#cf222e; --accent:#0969da;
        --s0:#8c959f; --s1:#d4a72c; --s2:#a2c03a; --s3:#2da44e; --s4:#1a7f37; --on:#ffffff;
        --on-light:#1b1f24; --i-bg:#ddf4ff; --i-fg:#0550ae; --r-bg:#fff1d6; --r-fg:#7d4e00;
        --e-bg:#eaeef2; --e-fg:#424a53; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0d1117; --fg:#e6edf3; --muted:#9198a1; --line:#30363d; --card:#161b22;
          --good:#3fb950; --bad:#f85149; --accent:#4493f8;
          --s0:#6e7681; --s1:#d29922; --s2:#a5c63b; --s3:#3fb950; --s4:#56d364; --on:#0d1117;
          --on-light:#0d1117; --i-bg:#0c2d6b; --i-fg:#a5d6ff; --r-bg:#3d2c00; --r-fg:#f2cc60;
          --e-bg:#30363d; --e-fg:#c9d1d9; }
}
* { box-sizing: border-box; }
body { margin:0; padding:24px 16px; background:var(--bg); color:var(--fg);
       font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
main { max-width:1100px; margin:0 auto; }
h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:18px; margin:32px 0 6px; }
h4 { font-size:13px; margin:16px 0 6px; }
.sub { color:var(--muted); margin:0 0 16px; }
.meaning { border-left:4px solid var(--accent); padding:2px 0 2px 14px; margin:0 0 20px; }
.meaning h2 { font-size:15px; margin:0 0 4px; } .meaning p { margin:0; max-width:80ch; }
.meaning p:not(:first-of-type), .meaning ul { margin-top:8px; max-width:80ch; }
.hero { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:20px;
        margin:0 0 16px; }
.hero .big { font-size:40px; font-weight:700; line-height:1.1; }
.hero .big small { font-size:18px; font-weight:600; color:var(--muted); }
.hero .bar { height:14px; margin-top:14px; }
.modes { display:grid; gap:6px; margin-top:14px; }
.mode { display:flex; flex-wrap:wrap; gap:10px; align-items:center; }
.mode code { min-width:64px; font-weight:700; }
.t0 { color:var(--s0); } .t1 { color:var(--s1); } .t2 { color:var(--s2); }
.t3 { color:var(--s3); } .t4 { color:var(--s4); }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px 14px; }
.card .k, .facts .k { display:block; color:var(--muted); font-size:12px; }
.card .v { font-size:20px; font-weight:600; }
.good { color:var(--good); } .bad { color:var(--bad); } .muted { color:var(--muted); }
a { color:var(--accent); }
.pill { display:inline-block; min-width:56px; text-align:center; padding:2px 10px;
        border-radius:999px; font-weight:700; font-variant-numeric:tabular-nums; }
.pill.s0, .pill.s1, .pill.s2 { color:var(--on-light); } .pill.s3, .pill.s4 { color:var(--on); }
.s0 { background:var(--s0); } .s1 { background:var(--s1); } .s2 { background:var(--s2); }
.s3 { background:var(--s3); } .s4 { background:var(--s4); }
.bar { display:block; height:8px; background:var(--line); border-radius:999px; overflow:hidden; }
.bar > span { display:block; height:100%; border-radius:999px; }
details.item { border:1px solid var(--line); border-radius:10px; margin:8px 0; background:var(--bg); }
details.item > summary { display:grid; grid-template-columns:auto 1fr minmax(180px,260px);
        gap:12px; align-items:center; padding:12px 14px; cursor:pointer; list-style:none; }
details.item > summary::-webkit-details-marker { display:none; }
details.item > summary::after { content:"▸"; grid-column:4; color:var(--muted); }
details.item[open] > summary::after { content:"▾"; }
details.item[open] > summary { border-bottom:1px solid var(--line); }
.rank { display:inline-flex; width:28px; height:28px; border-radius:50%; align-items:center;
        justify-content:center; background:var(--card); border:1px solid var(--line); font-weight:700; }
.what { min-width:0; display:flex; flex-direction:column; gap:2px; }
.what code { color:var(--muted); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.amount { display:flex; flex-direction:column; gap:4px; align-items:flex-end; }
.amount .bar { width:100%; }
.body { padding:4px 16px 14px; }
.facts { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:8px;
         margin-top:12px; font-variant-numeric:tabular-nums; }
details.section { margin-top:24px; }
details.section > summary { cursor:pointer; }
details.section > summary h2 { display:inline; margin-right:8px; }
.scroll { overflow-x:auto; border:1px solid var(--line); border-radius:8px; }
table { border-collapse:collapse; width:100%; }
table.rules { min-width:800px; }
.legend { display:flex; flex-wrap:wrap; gap:6px 16px; align-items:center; font-size:13px;
          margin:12px 0; } .legend > span { display:inline-flex; gap:6px; align-items:center; }
div.events { overflow:auto; max-height:560px; border:1px solid var(--line); border-radius:8px; }
table.events { border-collapse:separate; border-spacing:0; font-size:12px;
               font-variant-numeric:tabular-nums; }
table.events th { position:sticky; top:0; z-index:2; white-space:nowrap; color:var(--fg); }
table.events th code { display:block; }
table.events td { max-width:220px; }
table.events .c1, table.events .c2, table.events .c3 { position:sticky; z-index:1;
                                                       background:var(--bg); }
table.events th.c1, table.events th.c2, table.events th.c3 { z-index:3; background:var(--card); }
table.events .c1 { left:0; width:44px; min-width:44px; }
table.events .c2 { left:44px; width:180px; min-width:180px; white-space:normal; }
table.events .c3 { left:224px; min-width:120px; border-right:1px solid var(--line); }
.note { display:block; font-size:11px; font-weight:400; color:var(--muted); }
.v { display:block; max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
     font:12px ui-monospace,SFMono-Regular,Menlo,monospace; }
.legend .v.sent { display:inline; padding:1px 6px; border-radius:4px; background:var(--card);
                  border:1px solid var(--line); }
.gone { display:flex; gap:6px; align-items:center; max-width:220px; color:var(--muted);
        white-space:nowrap; } .gone .v { text-decoration:line-through; }
.mk { flex:none; display:inline-flex; width:16px; height:16px; border-radius:4px; font-size:10px;
      font-weight:700; align-items:center; justify-content:center; }
.mk.i { background:var(--i-bg); color:var(--i-fg); } .mk.r { background:var(--r-bg); color:var(--r-fg); }
.mk.e { background:var(--e-bg); color:var(--e-fg); } .absent { color:var(--s0); }
.bar.kept { width:88px; height:6px; margin:4px 0 0 auto; }
details.raw { margin-top:12px; } details.raw > summary { cursor:pointer; font-weight:600; }
.tag { display:inline-block; padding:0 6px; border-radius:4px; font-size:11px; font-weight:600;
       background:var(--accent); color:var(--on); }
th, td { text-align:left; vertical-align:top; padding:8px 10px; border-bottom:1px solid var(--line); }
th { background:var(--card); font-size:12px; color:var(--muted); font-weight:600; }
td.n { text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap; }
code { font:12px ui-monospace,SFMono-Regular,Menlo,monospace; word-break:break-all; }
ul { margin:0; padding-left:18px; }
pre { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:8px 10px;
      overflow-x:auto; } pre code { word-break:normal; white-space:pre; }
@media (max-width:700px) {
  details.item > summary { grid-template-columns:auto 1fr; }
  .amount { grid-column:1 / -1; align-items:stretch; }
  details.item > summary::after { display:none; }
  .hero .big { font-size:32px; }
}
"#;

/// Renders the report as HTML.
#[must_use]
pub fn render_html(report: &Report) -> String {
    let mut parts = vec![
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">".to_owned(),
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">".to_owned(),
        format!("<title>Sluice report</title><style>{STYLE}</style></head><body><main>"),
        "<h1>Sluice report</h1>".to_owned(),
        "<p class=\"sub\">Where you can send less to your SIEM without changing a detection, \
         largest saving first, and the proof.</p>"
            .to_owned(),
        meaning(report),
        hero(report),
        summary(report),
        notes(report),
        implied::explain(report),
        savings::advice(&report.templates),
        examples::section(&report.examples),
        rules(report),
    ];
    if !report.problems.is_empty() {
        parts.push(format!(
            "<details class=\"section\"><summary><h2>Problems</h2><span class=\"muted\">{} \
             found</span></summary>{}</details>",
            report.problems.len(),
            problems(&report.problems)
        ));
    }
    parts.push("</main></body></html>\n".to_owned());
    parts.concat()
}

/// What the report means, for a reader who gets it without context, such as a manager: it is
/// advice about data no detection uses, not advice to collect less security data. Each claim
/// holds for this report: the one about alerts only when the sample raised some.
fn meaning(report: &Report) -> String {
    let proof = if !report.proven {
        "On this sample the alerts were <b>not</b> the same, so these savings are not proven."
    } else if report.alerts_full == 0 {
        "This sample raised no alerts, so it could not show that every detection still works: \
         try a sample that does."
    } else {
        "On this sample, every alert was raised exactly as before."
    };
    let implied = if report.modes.contains(&Mode::Implied) {
        " values that follow from the kind of event (implied, explained below),"
    } else {
        ""
    };
    format!(
        "<section class=\"meaning\"><h2>What this report means</h2><p>A SIEM charges for every \
         byte it receives, but its detection rules use only part of each event. Sluice compared \
         the rules this SIEM runs with a sample of its data, and lists what no rule uses: mostly \
         text that repeats fields the event already has, empty fields,{implied} and frequent \
         events no rule can match, which are counted instead of sent one by one. <b>This is not \
         advice to \
         collect less security data or to throw logs away.</b> The savings assume a full copy of \
         every event is kept in a cheaper archive; the configurations Sluice writes for Vector \
         and Microsoft Sentinel keep one. {proof} Nothing changes until your team reviews the \
         proposed configuration and deploys it.</p></section>"
    )
}

/// The saving at a glance: the share, the bytes, and a bar; then what each mode saved.
fn hero(report: &Report) -> String {
    let t = &report.total;
    let saved = report.saved_percent();
    format!(
        "<section class=\"hero\"><div class=\"big t{level}\">{saved:.1}% <small>less ingest\
         </small></div><div class=\"muted\">{bin} in, {bout} sent to the SIEM; {summarized} of \
         {events} events counted into {summaries} summary records instead of sent one by one\
         </div>{bar}{modes}</section>",
        level = savings::level(saved),
        bin = bytes(t.bytes_in),
        bout = bytes(t.bytes_out),
        summarized = thousands(t.summarized),
        summaries = thousands(t.summaries),
        events = thousands(t.events),
        bar = savings::bar(saved),
        modes = modes(report),
    )
}

/// Each mode with what it saved, side by side; a mode not asked for says how to ask for it.
fn modes(report: &Report) -> String {
    let rows: Vec<String> = Mode::ALL
        .iter()
        .map(|&mode| {
            if report.modes.contains(&mode) {
                let share = report.saved_percent_by(mode);
                format!(
                    "<div class=\"mode\"><code>{name}</code>{pill}<span>{bytes} saved</span>\
                     <span class=\"muted\">{what}</span></div>",
                    name = mode.name(),
                    pill = savings::pill(share),
                    bytes = bytes(report.saved_by(mode)),
                    what = mode.describe(),
                )
            } else {
                format!(
                    "<div class=\"mode\"><code>{name}</code><span class=\"muted\">not run: add it \
                     with <code>--mode</code> to also remove {what}</span></div>",
                    name = mode.name(),
                    what = mode.describe(),
                )
            }
        })
        .collect();
    let overlap = if report.modes.len() > 1 {
        "<p class=\"muted\">Implied values count what they save after the recipes' removals. On \
         their own (<code>--mode implied</code>) they save more, since the recipes then leave \
         more fields in place.</p>"
    } else {
        ""
    };
    format!("<div class=\"modes\">{}</div>{overlap}", rows.concat())
}

/// `n` with a comma between thousands, as the command line prints counts.
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

fn summary(report: &Report) -> String {
    let t = &report.total;
    let verdict = if report.proven {
        format!(
            "<span class=\"good\">✓ {} = {}</span>",
            report.alerts_full, report.alerts_forwarded
        )
    } else {
        format!(
            "<span class=\"bad\">✗ {} ≠ {}</span>",
            report.alerts_full, report.alerts_forwarded
        )
    };
    let cards = [
        ("Events in", thousands(t.events)),
        ("Sent, in full or reduced", thousands(t.forwarded)),
        ("Counted into summaries", thousands(t.summarized)),
        ("Bytes saved", bytes(t.bytes_in.saturating_sub(t.bytes_out))),
        ("Alerts full = forwarded", verdict),
    ];
    let cards: Vec<String> = cards
        .into_iter()
        .map(|(k, v)| {
            format!(
                "<div class=\"card\"><div class=\"k\">{k}</div><div class=\"v\">{v}</div></div>"
            )
        })
        .collect();
    format!("<div class=\"cards\">{}</div>", cards.concat())
}

/// The sentences a reader must not miss: an empty proof, and what the rules' completeness
/// rests on.
fn notes(report: &Report) -> String {
    let empty = report
        .proof_note()
        .map(|note| format!("<p class=\"bad\">{}</p>", escape(note)))
        .unwrap_or_default();
    format!(
        "{empty}<p class=\"muted\">{}</p>",
        escape(report.rules_basis.describe())
    )
}

/// "Rules in the SIEM": each rule next to what Sluice made of it, folded away by default.
fn rule_table(rows: &[RuleRow]) -> String {
    let body: Vec<String> = rows
        .iter()
        .map(|row| {
            let class = match row.status {
                super::RuleStatus::Understood => "good",
                super::RuleStatus::ReadBroadly => "muted",
                super::RuleStatus::NotRead => "bad",
            };
            format!(
                "<tr><td>{set}</td><td>{name}<div class=\"muted\"><code>{id}</code></div></td>\
                 <td class=\"{class}\">{status}</td><td>{detail}</td></tr>",
                set = escape(&row.set),
                name = escape(row.name.as_deref().unwrap_or("")),
                id = escape(&row.rule),
                status = label(row.status),
                detail = escape(&row.detail),
            )
        })
        .collect();
    format!(
        "<h4>Every rule, and what Sluice made of it</h4><div class=\"scroll\"><table \
         class=\"rules\"><tr><th>Set</th><th>Rule</th><th>Status</th><th>What Sluice took from \
         it</th></tr>{}</table></div>",
        body.concat()
    )
}

/// "Rules in the SIEM", folded away: what the advice rests on.
fn rules(report: &Report) -> String {
    let counts: Vec<String> = report
        .rules
        .iter()
        .map(|(engine, n)| format!("{n} {}", escape(engine)))
        .collect();
    let mut out = format!(
        "<details class=\"section\"><summary><h2>Rules in the SIEM</h2><span class=\"muted\">{} \
         rules loaded</span></summary><p>{}</p>",
        counts.join(", "),
        escape(&report.rules_verdict())
    );
    if !report.inventory_notes.is_empty() {
        out.push_str(
            "<p class=\"muted\">What fetching the rules noted, such as rules that run without a \
             query to read:</p>",
        );
        out.push_str(&list(&report.inventory_notes));
    }
    out.push_str(&rule_table(&report.rule_rows));
    if !report.scope_hints.is_empty() {
        out.push_str(
            "<p class=\"muted\">Scope: rules that apply only because a source's log source is \
             not fully described. Describing it lets Sluice ignore them.</p>",
        );
        out.push_str(&list(&report.scope_hints));
    }
    if !report.coverage_gaps.is_empty() {
        out.push_str(
            "<p class=\"muted\">Coverage gaps: rules no data in this sample can reach.</p>",
        );
        out.push_str(&list(&report.coverage_gaps));
    }
    out.push_str("</details>");
    out
}

/// The problems grouped by kind, each group with what it costs and what the reader can do.
/// Functions the rules call without their source come first, one line per function: giving that
/// source is what can save the most.
fn problems(problems: &[Problem]) -> String {
    let mut out = functions(problems);
    for kind in [
        ProblemKind::Unreadable,
        ProblemKind::Unchecked,
        ProblemKind::ReadBroadly,
        ProblemKind::SharedId,
        ProblemKind::MissingRule,
        ProblemKind::LeftOut,
        ProblemKind::Recipe,
    ] {
        let messages: Vec<String> = problems
            .iter()
            .filter(|p| p.kind == kind)
            .map(|p| p.message.clone())
            .collect();
        if !messages.is_empty() {
            let _ = write!(out, "<p class=\"muted\">{}</p>", escape(advice(&kind)));
            out.push_str(&list(&messages));
        }
    }
    out
}

/// What a kind of problem costs, and what the reader can do about it.
fn advice(kind: &ProblemKind) -> &'static str {
    super::text::problem_advice(kind.name()).expect("every kind of problem has its advice")
}

/// One line per function the rules call without its source, with the rules that call it, and
/// how to give the source.
fn functions(problems: &[Problem]) -> String {
    let mut calls: BTreeMap<(Engine, &str), Vec<&str>> = BTreeMap::new();
    for problem in problems {
        if let ProblemKind::UnknownFunction { engine, name } = &problem.kind {
            calls
                .entry((*engine, name.as_str()))
                .or_default()
                .push(problem.rule.as_ref().map_or("", RuleId::as_str));
        }
    }
    let Some(&(_, example)) = calls.keys().next() else {
        return String::new();
    };
    let items: Vec<String> = calls
        .iter()
        .map(|((_, name), rules)| {
            let shown: Vec<String> = rules
                .iter()
                .take(5)
                .map(|r| format!("<code>{}</code>", escape(r)))
                .collect();
            let more = match rules.len() {
                n if n > 5 => format!(" and {} more", n - 5),
                _ => String::new(),
            };
            format!(
                "<li><code>{}</code>: called by {} ({}{more})</li>",
                escape(name),
                if rules.len() == 1 {
                    "1 rule".to_owned()
                } else {
                    format!("{} rules", rules.len())
                },
                shown.join(", ")
            )
        })
        .collect();
    let mut out = format!(
        "<p>Functions your rules call whose source Sluice does not have. {}</p><ul>{}</ul>",
        escape(super::text::FUNCTIONS),
        items.concat()
    );
    if calls.keys().any(|(engine, _)| *engine == Engine::Sentinel) {
        let _ = write!(
            out,
            "<p class=\"muted\">For Microsoft Sentinel, run <code>sluice rules fetch \
             sentinel</code>, which reads every function in the workspace, or save each \
             function next to the rules as a YAML file with its query (in the Azure portal: \
             Logs, Functions):</p><pre><code>FunctionName: {}\nFunctionQuery: |\n  …the \
             function's query…</code></pre><p class=\"muted\">ASIM parsers come with \
             Azure/Azure-Sentinel: add its <code>Parsers/ASim*/Parsers</code> and \
             <code>ASIM/lib/functions</code>.</p>",
            escape(example)
        );
    }
    out
}

fn list(items: &[String]) -> String {
    let items: Vec<String> = items
        .iter()
        .map(|i| format!("<li>{}</li>", escape(i)))
        .collect();
    format!("<ul>{}</ul>", items.concat())
}

/// Human-readable byte count, rounded, in decimal units, in the largest unit that keeps the
/// number below 1,000 ("8.7 MB", never "8703 KB"). Megabytes and gigabytes get one decimal, as
/// the command line prints them, so the report and the summary show the same numbers.
fn bytes(n: u64) -> String {
    if n < 1_000 {
        return format!("{n} B");
    }
    let kilobytes = n.saturating_add(500) / 1_000;
    if kilobytes < 1_000 {
        return format!("{kilobytes} KB");
    }
    let tenths_of_megabytes = n.saturating_add(50_000) / 100_000;
    if tenths_of_megabytes < 10_000 {
        return format!(
            "{}.{} MB",
            tenths_of_megabytes / 10,
            tenths_of_megabytes % 10
        );
    }
    let tenths_of_gigabytes = n.saturating_add(50_000_000) / 100_000_000;
    format!(
        "{}.{} GB",
        tenths_of_gigabytes / 10,
        tenths_of_gigabytes % 10
    )
}

/// Escapes text for HTML content and attribute values.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup_from_data() {
        assert_eq!(
            escape("<script>\"x\" & 'y'</script>"),
            "&lt;script&gt;&quot;x&quot; &amp; &#39;y&#39;&lt;/script&gt;"
        );
    }

    #[test]
    fn bytes_are_readable() {
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(123_456), "123 KB");
        assert_eq!(bytes(56_000_000), "56.0 MB");
    }

    #[test]
    fn bytes_round_as_the_command_line_does() {
        // The demo's summary line: 120,960,000 bytes is "121.0 MB" there, not "120 MB".
        assert_eq!(bytes(120_960_000), "121.0 MB");
        assert_eq!(bytes(31_549_999), "31.5 MB");
        assert_eq!(bytes(123_500), "124 KB");
    }

    #[test]
    fn bytes_never_show_a_number_of_a_thousand_or_more_below_gigabytes() {
        assert_eq!(bytes(8_703_494), "8.7 MB", "not 8703 KB");
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(1_000), "1 KB");
        assert_eq!(bytes(999_499), "999 KB");
        assert_eq!(bytes(999_500), "1.0 MB");
        assert_eq!(bytes(999_949_999), "999.9 MB");
        assert_eq!(bytes(999_950_000), "1.0 GB");
        assert_eq!(bytes(u64::MAX), "18446744073.7 GB");
    }

    #[test]
    fn counts_have_a_comma_between_thousands() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(80_536), "80,536");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn the_meaning_says_it_is_not_advice_to_throw_logs_away_and_claims_only_what_holds() {
        let proven = Report {
            alerts_full: 3,
            alerts_forwarded: 3,
            proven: true,
            ..super::super::tests::report()
        };
        let text = meaning(&proven);
        assert!(text.contains("This is not advice to collect less security data"));
        assert!(text.contains("every alert was raised exactly as before"));
        let empty = Report {
            alerts_full: 0,
            alerts_forwarded: 0,
            ..proven.clone()
        };
        assert!(!meaning(&empty).contains("every alert was raised"));
        let failed = Report {
            proven: false,
            ..proven
        };
        assert!(meaning(&failed).contains("not</b> the same"));
    }

    #[test]
    fn plain_text_is_unchanged_by_escaping() {
        assert_eq!(escape(""), "");
        assert_eq!(escape("EventID 4625 · é ✓"), "EventID 4625 · é ✓");
    }
}
