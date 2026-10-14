"""Generates the two architecture diagrams of docs/architecture.md as standalone SVG.

Usage: python3 scripts/architecture-diagrams.py [docs/images]

Edit the cards and arrows below and run it again; the SVGs are committed. Coordinates are in
pixels of the viewBox; text does not wrap, so keep each line within its card.
"""
import sys
from html import escape

OUT = sys.argv[1] if len(sys.argv) > 1 else "docs/images"
INK, MUTED, BODY = "#15232D", "#4B5A62", "#33434B"
TEAL, OCHRE, RED = "#1D6E8A", "#9A5B16", "#B3261E"
SANS = "-apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"


class Svg:
    def __init__(self, w, h, title):
        self.w, self.h, self.parts = w, h, []
        self.title = title

    def add(self, s):
        self.parts.append(s)

    def band(self, x, y, w, h, fill, stroke, dashed=False):
        dash = ' stroke-dasharray="6 5"' if dashed else ""
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{fill}" '
                 f'stroke="{stroke}"{dash}/>')

    def text(self, x, y, s, size=13, color=MUTED, weight="400", anchor="start", mono=False,
             spacing=None):
        family = MONO if mono else SANS
        ls = f' letter-spacing="{spacing}"' if spacing else ""
        self.add(f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" '
                 f'font-weight="{weight}" fill="{color}" text-anchor="{anchor}"{ls}>'
                 f'{escape(s)}</text>')

    def card(self, x, y, w, h, title, desc, mono, color, step=None, limit=False):
        if limit:
            self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="#FBEAE6" '
                     f'stroke="{RED}" stroke-width="2" stroke-dasharray="6 4"/>')
        else:
            width = "2" if color == INK and step is None and title == "SIEM" else "1.5"
            self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="#FFFFFF" '
                     f'stroke="{color}" stroke-width="{width}"/>')
        cy = y + 24
        if limit:
            self.text(x + 12, y + 20, title, 11.5, RED, "700", spacing="0.6")
            cy = y + 38
            for line in desc:
                self.text(x + 12, cy, line, 13, INK)
                cy += 17
            return
        head = f"{step}  {title}" if step else title
        self.add(f'<text x="{x + 12}" y="{cy}" font-family="{SANS}" font-size="16" '
                 f'font-weight="700" fill="{INK}">'
                 + (f'<tspan fill="{color}">{escape(step)}</tspan>  {escape(title)}' if step
                    else escape(title)) + '</text>')
        cy += 20
        for line in desc:
            self.text(x + 12, cy, line, 13, BODY)
            cy += 17
        cy += 3
        for line in mono:
            self.text(x + 12, cy, line, 11.5, color if color != INK else MUTED, mono=True)
            cy += 15

    def arrow(self, points, color, head=True, dash=False):
        d = " ".join(f"{x},{y}" for x, y in points)
        marker = f' marker-end="url(#h{color[1:]})"' if head else ""
        dashes = ' stroke-dasharray="6 5"' if dash else ""
        self.add(f'<polyline points="{d}" fill="none" stroke="{color}" stroke-width="2" '
                 f'stroke-linejoin="round"{dashes}{marker}/>')

    def render(self):
        defs = "".join(
            f'<marker id="h{c[1:]}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
            f'markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" '
            f'fill="{c}"/></marker>'
            for c in (INK, TEAL, OCHRE, MUTED))
        return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" '
                f'width="{self.w}" height="{self.h}" role="img" aria-label="{escape(self.title)}">'
                f'<title>{escape(self.title)}</title><defs>{defs}</defs>'
                f'<rect width="{self.w}" height="{self.h}" fill="#F6F7F4"/>'
                + "\n".join(self.parts) + "</svg>\n")


def data_path():
    s = Svg(1200, 600, "The data path: what Vector does with every event")
    s.band(184, 20, 760, 460, "#E1EDF0", "#B9D3DA")
    s.text(926, 40, "DATA PATH · VECTOR · EVERY EVENT", 12, TEAL, "700", "end", spacing="0.8")
    # arrows first
    s.arrow([(164, 250), (201, 250)], INK)
    s.arrow([(354, 250), (391, 250)], TEAL)
    s.arrow([(544, 250), (581, 250)], TEAL)
    s.arrow([(279, 202), (279, 151)], TEAL)
    s.arrow([(354, 88), (988, 88)], MUTED, dash=True)
    s.arrow([(1070, 148), (1070, 167)], MUTED, dash=True)
    s.arrow([(469, 298), (469, 367)], TEAL)
    s.arrow([(734, 250), (754, 250)], TEAL, head=False)
    s.arrow([(754, 190), (754, 310)], TEAL, head=False)
    s.arrow([(754, 190), (772, 190)], TEAL)
    s.arrow([(754, 310), (772, 310)], TEAL)
    s.arrow([(924, 190), (944, 190), (944, 310), (924, 310)], TEAL, head=False)
    s.arrow([(944, 250), (962, 250)], TEAL)
    s.arrow([(469, 450), (469, 530)], TEAL)
    s.arrow([(659, 560), (659, 300)], OCHRE)
    # cards
    s.card(24, 202, 140, 96, "Source", ["e.g. a Windows", "server"], ["Vector agent"], INK)
    s.card(204, 40, 150, 108, "Archive", ["full copy, before", "any change"],
           ["file sink", "gzip NDJSON"], TEAL, "2")
    s.card(204, 202, 150, 96, "Receive", ["events arrive"], ["Vector source:", "http_server, file"],
           TEAL, "1")
    s.card(394, 202, 150, 96, "Shape", ["optional: the SIEM", "table's record"],
           ["VRL remap"], TEAL, "3")
    s.card(394, 370, 150, 80, "Tap", ["1 in 10 to Sluice"], ["sample + HTTP sink"], TEAL, "4")
    s.card(584, 202, 150, 96, "Reduce", ["template, route,", "drop fields"],
           ["generated VRL"], TEAL, "5")
    s.card(774, 150, 150, 80, "Forward", ["whole, or trimmed"], ["Vector sink"], TEAL, "6")
    s.card(774, 270, 150, 80, "Summarize", ["counts per minute"], ["reduce transform"], TEAL, "7")
    s.card(964, 170, 212, 160, "SIEM", ["Sentinel, Splunk, Elastic,", "SecOps or Wazuh.",
                                        "Detection rules run here."],
           ["Vector sinks", "(azure_logs_ingestion, …)"], INK)
    s.card(990, 40, 160, 108, "Search, replay", ["events back from", "the archive"],
           ["sluice search", "sluice replay"], INK)
    # labels
    s.text(183, 240, "HTTP", 12, MUTED, anchor="middle")
    s.text(1080, 162, "replay", 12, MUTED)
    s.text(481, 515, "copy to Sluice, step A", 12, TEAL)
    s.text(671, 545, "new vector.yaml from Sluice, step H", 12, OCHRE)
    return s


def decision_path():
    s = Svg(1200, 660, "The decision path: what Sluice decides every five minutes")
    s.band(12, 50, 1176, 600, "#F3E8D8", "#DEC9A6")
    s.text(24, 640, "DECISION PATH · SLUICE CONTROL PLANE (sluice up) · EVERY 5 MINUTES", 12,
           OCHRE, "700", spacing="0.8")
    xs = [24, 312, 600, 888]
    # arrows
    s.arrow([(144, 8), (144, 87)], TEAL)
    for a, b in zip(xs, xs[1:]):
        s.arrow([(a + 240, 150), (b - 2, 150)], OCHRE)
        s.arrow([(a + 240, 390), (b - 2, 390)], OCHRE)
    s.arrow([(1008, 210), (1008, 270), (144, 270), (144, 327)], OCHRE)
    s.arrow([(1128, 390), (1180, 390), (1180, 8)], OCHRE)
    s.arrow([(697, 450), (697, 497)], MUTED)
    s.arrow([(743, 500), (743, 453)], MUTED)
    rows = [
        ("A", "Window", ["the tapped sample per source:", "up to 20,000 events, 1 hour"],
         ["sluice-server · axum · /tap"]),
        ("B", "Templates", ["one kind of event per source;", "rare variants stay apart"],
         ["sluice-discover", "Drain (text), key sets (JSON)"]),
        ("C", "Recipes", ["proposals: drop fields (L1),", "count the rest (L2, L3)"],
         ["recipes/*.yaml · own · AI"]),
        ("D", "Rules to requirements", ["per rule: log source, fields,", "pre-filter"],
         ["rsigma · quick-xml (Wazuh)", "KQL reader (Sentinel)"]),
        ("E", "Guardrails", ["the safety contract:", "what may be cut?"], ["sluice-core"]),
        ("F", "Proof", ["same alerts on full and", "forwarded data?"],
         ["vrl crate · rsigma", "Kusto emulator"]),
        ("G", "Lifecycle", ["shadow; enforced after 24 h", "and 3 proofs; rolled back", "on a failure"],
         ["sluice-autopilot"]),
        ("H", "New config", ["write vector.yaml;", "Vector reloads (SIGHUP)"],
         ["sluice-vector", "sluice-server"]),
    ]
    for i, (step, title, desc, mono) in enumerate(rows):
        x, y = xs[i % 4], 90 if i < 4 else 330
        s.card(x, y, 240, 120, title, desc, mono, OCHRE, step)
    s.card(24, 500, 270, 96, "LIMIT · D · M12", ["Text lines are not parsed:",
                                                  "Sigma field rules keep text",
                                                  "sources whole."], [], RED, limit=True)
    s.card(312, 500, 270, 96, "LIMIT · D · M10", ["Rules come from directories;",
                                                  "hunts, dashboards and other",
                                                  "SIEM languages are not read."], [], RED,
           limit=True)
    s.card(600, 500, 240, 96, "Operators", ["console, sluice status, MCP:", "watch, explain, intervene"],
           ["web console · rmcp"], INK)
    s.text(156, 30, "tap from Vector, step 4", 12, TEAL)
    s.text(1170, 30, "to Vector, step 5", 12, OCHRE, anchor="end")
    s.text(687, 480, "status", 12, MUTED, anchor="end")
    s.text(753, 480, "actions", 12, MUTED)
    return s


for name, build in (("data-path", data_path), ("decision-path", decision_path)):
    with open(f"{OUT}/{name}.svg", "w", encoding="utf-8") as f:
        f.write(build().render())
print("written to", OUT)
