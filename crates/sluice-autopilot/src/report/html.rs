//! The report as one self-contained HTML page: no scripts, no external resources.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use sluice_core::ids::{Engine, RuleId};
use sluice_core::problem::{Problem, ProblemKind};

use super::{Report, RuleRow, TemplateRow, percent, rules::label};

const STYLE: &str = r#"
:root { --bg:#ffffff; --fg:#1b1f24; --muted:#5b6470; --line:#e3e6ea; --card:#f6f8fa;
        --good:#1a7f37; --bad:#cf222e; --accent:#0969da; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0d1117; --fg:#e6edf3; --muted:#9198a1; --line:#30363d; --card:#161b22;
          --good:#3fb950; --bad:#f85149; --accent:#4493f8; }
}
* { box-sizing: border-box; }
body { margin:0; padding:24px 16px; background:var(--bg); color:var(--fg);
       font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
main { max-width:1200px; margin:0 auto; }
h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:16px; margin:28px 0 8px; }
.sub { color:var(--muted); margin:0 0 20px; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px 14px; }
.card .k { color:var(--muted); font-size:12px; } .card .v { font-size:20px; font-weight:600; }
.good { color:var(--good); } .bad { color:var(--bad); }
.scroll { overflow-x:auto; border:1px solid var(--line); border-radius:8px; }
table { border-collapse:collapse; width:100%; min-width:900px; }
th, td { text-align:left; vertical-align:top; padding:8px 10px; border-bottom:1px solid var(--line); }
th { background:var(--card); font-size:12px; color:var(--muted); font-weight:600; }
td.n { text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap; }
code { font:12px ui-monospace,SFMono-Regular,Menlo,monospace; word-break:break-all; }
ul { margin:0; padding-left:18px; } .muted { color:var(--muted); }
pre { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:8px 10px;
      overflow-x:auto; } pre code { word-break:normal; white-space:pre; }
"#;

/// Renders the report as HTML.
#[must_use]
pub fn render_html(report: &Report) -> String {
    let mut parts = vec![
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">".to_owned(),
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">".to_owned(),
        format!("<title>Sluice report</title><style>{STYLE}</style></head><body><main>"),
        "<h1>Sluice report</h1>".to_owned(),
        "<p class=\"sub\">What the generated configuration saves, why, and the proof that no \
         detection changes. You decide what runs.</p>"
            .to_owned(),
        summary(report),
        notes(report),
        rules(report),
        "<h2>Templates</h2>".to_owned(),
        templates(&report.templates),
    ];
    if !report.problems.is_empty() {
        parts.push("<h2>Problems</h2>".to_owned());
        parts.push(problems(&report.problems));
    }
    parts.push("</main></body></html>\n".to_owned());
    parts.concat()
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
        ("Events in", t.events.to_string()),
        (
            "Bytes in → out",
            format!("{} → {}", bytes(t.bytes_in), bytes(t.bytes_out)),
        ),
        ("Ingest saved", format!("{:.1}%", report.saved_percent())),
        (
            "Summarized events",
            format!("{} of {}", t.summarized, t.events),
        ),
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
        "<details><summary>Every rule, and what Sluice made of it</summary><div class=\"scroll\">\
         <table><tr><th>Set</th><th>Rule</th><th>Status</th><th>What Sluice took from it</th>\
         </tr>{}</table></div></details>",
        body.concat()
    )
}

fn rules(report: &Report) -> String {
    let counts: Vec<String> = report
        .rules
        .iter()
        .map(|(engine, n)| format!("{n} {}", escape(engine)))
        .collect();
    let mut out = format!(
        "<h2>Rules in the SIEM</h2><p>{} rules loaded. {}</p>",
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
    out
}

fn templates(rows: &[TemplateRow]) -> String {
    let header = "<tr><th>Template</th><th>Pattern</th><th>Events</th><th>Forwarded / \
                  summarized</th><th>Bytes in → out</th><th>What happens</th><th>Why</th></tr>";
    let body: Vec<String> = rows.iter().map(template_row).collect();
    format!(
        "<div class=\"scroll\"><table>{header}{}</table></div>",
        body.concat()
    )
}

fn template_row(row: &TemplateRow) -> String {
    let v = &row.volume;
    let saved = percent(v.bytes_in - v.bytes_out.min(v.bytes_in), v.bytes_in);
    let mut actions = if row.actions.is_empty() {
        "<span class=\"muted\">forwarded unchanged</span>".to_owned()
    } else {
        list(&row.actions)
    };
    if let Some(runs_in) = &row.runs_in {
        actions = format!(
            "{actions}<div class=\"muted\">runs in: {}</div>",
            escape(runs_in)
        );
    }
    let mut why = list(&row.adjustments);
    if let Some(provenance) = &row.provenance {
        why = format!("<div class=\"muted\">{}</div>{why}", escape(provenance));
    }
    let pattern: String = row.pattern.chars().take(90).collect();
    format!(
        "<tr><td><code>{id}</code><div class=\"muted\">{source}</div></td>\
         <td><code title=\"{full}\">{pattern}</code></td><td class=\"n\">{events}</td>\
         <td class=\"n\">{fwd} / {sum}</td><td class=\"n\">{bin} → {bout}<div class=\"muted\">\
         −{saved:.0}%</div></td><td>{actions}</td><td>{why}</td></tr>",
        id = escape(&row.id),
        source = escape(&row.source),
        full = escape(&row.pattern),
        pattern = escape(&pattern),
        events = v.events,
        fwd = v.forwarded,
        sum = v.summarized,
        bin = bytes(v.bytes_in),
        bout = bytes(v.bytes_out),
    )
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
    match kind {
        ProblemKind::Unreadable => {
            "Files and rules Sluice could not read. Each stands in as a rule that may read \
             anything, which keeps every field of every event: fix it, or leave it out if your \
             SIEM does not run it."
        }
        ProblemKind::UnknownFunction { .. } => FUNCTIONS,
        ProblemKind::Unchecked => {
            "Names Sluice could not check. Each is read as it most likely is; give Sluice a way \
             to check them, as each problem says."
        }
        ProblemKind::ReadBroadly => {
            "Parts of rules Sluice reads as broadly as they could reach, such as free text or a \
             wildcard field name. Those rules keep more than they may need: that costs savings, \
             not detections."
        }
        ProblemKind::SharedId => {
            "Rules that share an id, so the proof cannot tell their alerts apart. Give each rule \
             its own id."
        }
        ProblemKind::MissingRule => {
            "Rules that name a rule that is not loaded. They keep every field of every event \
             until the rule they name is given too."
        }
        ProblemKind::LeftOut => "Left out on purpose.",
        ProblemKind::Recipe => "Recipes Sluice could not apply, and AI advice it did not take.",
    }
}

/// What a function without its source costs.
const FUNCTIONS: &str = "Each rule that calls a function whose source Sluice does not have is \
     read as reading every column of every record, so that data is kept whole. Give Sluice the \
     source and it reads what the function reads.";

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
        escape(FUNCTIONS),
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

/// Human-readable byte count.
fn bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = n;
    let mut unit = 0;
    while value >= 10_000 && unit < UNITS.len() - 1 {
        value /= 1_000;
        unit += 1;
    }
    format!("{value} {}", UNITS[unit])
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
        assert_eq!(bytes(56_000_000), "56 MB");
    }

    #[test]
    fn bytes_switch_unit_at_ten_thousand_and_stop_at_gigabytes() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(9_999), "9999 B");
        assert_eq!(bytes(10_000), "10 KB");
        assert_eq!(bytes(9_999_999_999), "9999 MB");
        assert_eq!(bytes(u64::MAX), "18446744073 GB");
    }

    #[test]
    fn plain_text_is_unchanged_by_escaping() {
        assert_eq!(escape(""), "");
        assert_eq!(escape("EventID 4625 · é ✓"), "EventID 4625 · é ✓");
    }
}
