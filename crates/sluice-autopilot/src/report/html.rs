//! The report as one self-contained HTML page: no scripts, no external resources.

use super::{Report, TemplateRow, percent};

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
"#;

/// Renders the report as HTML.
#[must_use]
pub fn render_html(report: &Report) -> String {
    let mut parts = vec![
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">".to_owned(),
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">".to_owned(),
        format!("<title>Sluice report</title><style>{STYLE}</style></head><body><main>"),
        "<h1>Sluice report</h1>".to_owned(),
        "<p class=\"sub\">What the autopilot enforces, why, and the proof that no detection \
         changes.</p>"
            .to_owned(),
        summary(report),
        rules(report),
        "<h2>Templates</h2>".to_owned(),
        templates(&report.templates),
    ];
    if !report.problems.is_empty() {
        parts.push("<h2>Problems</h2>".to_owned());
        parts.push(list(&report.problems));
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

fn rules(report: &Report) -> String {
    let counts: Vec<String> = report
        .rules
        .iter()
        .map(|(engine, n)| format!("{n} {}", escape(engine)))
        .collect();
    let mut out = format!(
        "<h2>Rules</h2><p>{} rules loaded. Sigma rules are evaluated in the proof; Wazuh rules \
         constrain the guardrails.</p>",
        counts.join(", ")
    );
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
    let actions = if row.actions.is_empty() {
        "<span class=\"muted\">forwarded unchanged</span>".to_owned()
    } else {
        list(&row.actions)
    };
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
}
