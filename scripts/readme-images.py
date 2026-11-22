"""Writes the README's images (docs/images/*.svg), each in a light and a dark variant.

The figures they show are measured (docs/adr/0041-three-modes.md, the example report): change
them here when a new measurement changes them, then run

    python3 scripts/readme-images.py
"""

from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "docs" / "images"

# A sluice: slate ink, water, a brass gate.
THEMES = {
    "light": {
        "bg": "#F3F6F7",
        "panel": "#FFFFFF",
        "ink": "#15232C",
        "muted": "#5A6B75",
        "line": "#D3DDE1",
        "water": "#1D7487",
        "water_soft": "#BFDCE2",
        "brass": "#B5832F",
        "saved": "#E4ECEE",
    },
    "dark": {
        "bg": "#0F181E",
        "panel": "#16222A",
        "ink": "#E7EEF1",
        "muted": "#93A6B0",
        "line": "#2A3A44",
        "water": "#4CB3C6",
        "water_soft": "#1E4752",
        "brass": "#DDAE58",
        "saved": "#1B2A33",
    },
}

FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

# OTRF's APT29 sample: MB sent to the SIEM per choice of modes (ADR 0041).
APT29_IN = 357.3
MODES = [
    ("nothing", "", APT29_IN, "every event, every field"),
    ("duplicates", "--mode duplicates", 239.2, "every event, every value"),
    ("duplicates,implied", "--mode duplicates,implied", 139.7, "every event; values come back"),
    ("all three", "the default", 78.2, "unmatched events arrive as counts"),
]


def svg(width: int, height: int, theme: dict, body: str, label: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{label}">\n'
        f'<rect width="{width}" height="{height}" rx="16" fill="{theme["bg"]}"/>\n'
        f"{body}</svg>\n"
    )


def text(x, y, content, theme, size=16, weight=400, color="ink", anchor="start", family=FONT,
         spacing=0):
    return (
        f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" '
        f'font-weight="{weight}" fill="{theme[color]}" text-anchor="{anchor}" '
        f'letter-spacing="{spacing}">{content}</text>\n'
    )


def hero(theme: dict) -> str:
    body = text(64, 128, "Sluice", theme, size=76, weight=700, spacing=-1.5)
    body += text(66, 176, "Send your SIEM less. Keep every detection.", theme, size=26, weight=500)
    body += text(
        66, 214,
        "Every saving is proven on your own data and rules before you deploy it.",
        theme, size=17, color="muted",
    )
    body += text(
        66, 262, "VECTOR · SENTINEL · ELASTIC · WAZUH · SPLUNK · SIGMA · FLUENT BIT · OTEL",
        theme, size=12, weight=600, color="muted", spacing=1.6,
    )
    # The sluice: eight streams in, a gate, two streams on to the SIEM, one to the archive.
    x0, gate, x1 = 790, 1000, 1210
    for n in range(8):
        y = 92 + n * 20
        opacity = 1.0 if n in (3, 4) else 0.45
        body += (
            f'<path d="M{x0} {y} C {x0 + 110} {y}, {gate - 90} {150 + (n - 3.5) * 6}, {gate - 14} '
            f'{150 + (n - 3.5) * 6}" stroke="{theme["water"]}" stroke-width="4" fill="none" '
            f'stroke-linecap="round" opacity="{opacity}"/>\n'
        )
    body += f'<rect x="{gate - 10}" y="58" width="20" height="74" rx="3" fill="{theme["brass"]}"/>\n'
    body += f'<rect x="{gate - 10}" y="172" width="20" height="98" rx="3" fill="{theme["brass"]}"/>\n'
    for y in (144, 156):
        body += (
            f'<path d="M{gate + 14} {y} H {x1}" stroke="{theme["water"]}" stroke-width="4" '
            f'stroke-linecap="round"/>\n'
        )
    body += (
        f'<path d="M{gate + 14} 236 C {gate + 70} 236, {gate + 80} 262, {gate + 150} 262 H {x1}" '
        f'stroke="{theme["muted"]}" stroke-width="2" stroke-dasharray="6 6" fill="none"/>\n'
    )
    body += text(x0, 74, "357.3 MB in", theme, size=14, weight=600, color="muted")
    body += text(x1, 128, "78.2 MB to the SIEM", theme, size=14, weight=600, anchor="end")
    body += text(x1, 290, "every event to the archive", theme, size=13, color="muted",
                 anchor="end")
    body += text(x1, 190, "987 = 987 alerts", theme, size=14, weight=700, color="brass",
                 anchor="end", family=MONO)
    return svg(1280, 320, theme, body, "Sluice: send your SIEM less, keep every detection")


def modes(theme: dict) -> str:
    left, right = 330, 1120
    scale = (right - left) / APT29_IN
    body = text(40, 52, "OTRF's APT29 sample, 357.3 MB: what reaches the SIEM", theme, size=18,
                weight=600)
    body += text(40, 78, "Eight detection rules, the same 987 alerts every time.", theme,
                 size=14, color="muted")
    for n, (name, flag, sent, arrives) in enumerate(MODES):
        y = 116 + n * 78
        body += text(40, y + 20, name, theme, size=17, weight=600)
        body += text(40, y + 42, flag, theme, size=13, color="muted", family=MONO)
        full = (right - left)
        width = sent * scale
        body += f'<rect x="{left}" y="{y}" width="{full:.1f}" height="34" rx="5" fill="{theme["saved"]}"/>\n'
        color = theme["muted"] if n == 0 else theme["water"]
        body += f'<rect x="{left}" y="{y}" width="{width:.1f}" height="34" rx="5" fill="{color}"/>\n'
        saved = (APT29_IN - sent) / APT29_IN * 100
        figure = f"{sent:.1f} MB" if n == 0 else f"{sent:.1f} MB  ·  {saved:.1f} % saved"
        body += text(left + width + 12, y + 23, figure, theme, size=14, weight=600,
                     family=MONO)
        body += text(left, y + 56, arrives, theme, size=12, color="muted")
    # The scale, so the bars can be read.
    base = 116 + len(MODES) * 78 - 4
    for mb in (0, 100, 200, 300):
        x = left + mb * scale
        body += f'<line x1="{x:.1f}" y1="{base}" x2="{x:.1f}" y2="{base + 6}" stroke="{theme["line"]}" stroke-width="2"/>\n'
        body += text(f"{x:.1f}", base + 22, f"{mb} MB", theme, size=11, color="muted",
                     anchor="middle", family=MONO)
    return svg(1280, base + 40, theme, body, "What each choice of modes sends on OTRF's APT29 sample")


def box(x, y, w, h, title, lines, theme, filled=False):
    fill = theme["water"] if filled else theme["panel"]
    stroke = theme["water"] if filled else theme["line"]
    ink = "bg" if filled else "ink"
    sub = "bg" if filled else "muted"
    out = f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>\n'
    out += text(x + 18, y + 32, title, theme, size=16, weight=700, color=ink)
    for n, line in enumerate(lines):
        out += text(x + 18, y + 56 + n * 20, line, theme, size=13, color=sub)
    return out


def arrow(x1, y1, x2, y2, theme):
    """A line from (x1, y1) to (x2, y2) with its head at the end, in any direction."""
    length = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
    ux, uy = (x2 - x1) / length, (y2 - y1) / length
    # The head's two barbs, 10 back along the line and 6 to either side of it.
    bx, by = x2 - 10 * ux, y2 - 10 * uy
    left = (bx - 6 * uy, by + 6 * ux)
    right = (bx + 6 * uy, by - 6 * ux)
    return (
        f'<path d="M{x1} {y1} L{x2 - 2 * ux:.1f} {y2 - 2 * uy:.1f}" stroke="{theme["muted"]}" '
        f'stroke-width="2" fill="none"/>\n'
        f'<path d="M{left[0]:.1f} {left[1]:.1f} L{x2} {y2} L{right[0]:.1f} {right[1]:.1f}" '
        f'stroke="{theme["muted"]}" stroke-width="2" fill="none" stroke-linejoin="round"/>\n'
    )


def flow(theme: dict) -> str:
    body = box(32, 40, 220, 96, "Your rules", ["read-only, from the SIEM", "or from files"], theme)
    body += box(32, 168, 220, 96, "A sample", ["an hour or a day,", "one file per source"], theme)
    body += box(300, 40, 300, 224, "sluice analyze", [
        "sorts events into kinds",
        "proposes savings (--mode)",
        "keeps what every rule reads",
        "proves the same alerts",
        "on what would be sent",
        "",
        "changes nothing itself",
    ], theme, filled=True)
    body += box(648, 40, 240, 224, "What it writes", [
        "report.html, for people",
        "plan.json, for tools",
        "vector.yaml",
        "Sentinel DCR, ingest",
        "pipeline, Fluent Bit, OTel",
    ], theme)
    body += box(936, 40, 312, 96, "Your tools", ["you review and deploy;", "sluice verify checks it later"], theme)
    body += box(936, 168, 148, 96, "SIEM", ["less data,", "same alerts"], theme)
    body += box(1100, 168, 148, 96, "Archive", ["every event,", "whole"], theme)
    body += arrow(252, 88, 300, 120, theme)
    body += arrow(252, 216, 300, 184, theme)
    body += arrow(600, 152, 648, 152, theme)
    body += arrow(888, 100, 936, 88, theme)
    body += arrow(1010, 136, 1010, 168, theme)
    body += arrow(1174, 136, 1174, 168, theme)
    return svg(1280, 304, theme, body, "How Sluice works, from rules and a sample to your tools")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, draw in (("hero", hero), ("modes", modes), ("flow", flow)):
        for variant, theme in THEMES.items():
            (OUT / f"{name}-{variant}.svg").write_text(draw(theme), encoding="utf-8")
            print(f"wrote docs/images/{name}-{variant}.svg")


if __name__ == "__main__":
    main()
