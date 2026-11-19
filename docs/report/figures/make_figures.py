#!/usr/bin/env python3
"""Write the report's figures as SVG files next to this script.

    python3 docs/report/figures/make_figures.py

No dependencies. The numbers in figures 3 and 4 are copied from the report's
tables (sections 5.1 and 5.2); change them there and here together.
"""

from pathlib import Path

HERE = Path(__file__).resolve().parent
FONT = 'font-family="Helvetica, Arial, DejaVu Sans, sans-serif"'
INK = "#1b1f23"
GREY = "#8a9099"
LIGHT = "#eef1f4"
ACCENT = "#1f8a7d"
WARN = "#b5472f"


def svg(w, h, body):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" {FONT}>\n'
        f'<rect width="{w}" height="{h}" fill="#ffffff"/>\n'
        '<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
        f'<path d="M0,0 L10,5 L0,10 z" fill="{INK}"/></marker>'
        '<marker id="r" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
        f'<path d="M0,0 L10,5 L0,10 z" fill="{WARN}"/></marker></defs>\n'
        + body
        + "</svg>\n"
    )


def box(x, y, w, h, title, sub=None, fill="#ffffff", stroke=INK, bold=True):
    t = f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{fill}" stroke="{stroke}" stroke-width="1.3"/>\n'
    ty = y + (h / 2 + 4 if sub is None else h / 2 - 3)
    wt = ' font-weight="600"' if bold else ""
    t += f'<text x="{x + w / 2}" y="{ty}" font-size="12.5" text-anchor="middle" fill="{INK}"{wt}>{title}</text>\n'
    if sub:
        t += f'<text x="{x + w / 2}" y="{ty + 15}" font-size="10.5" text-anchor="middle" fill="{GREY}">{sub}</text>\n'
    return t


def arrow(
    x1,
    y1,
    x2,
    y2,
    label=None,
    lx=None,
    ly=None,
    colour=INK,
    marker="a",
    dash=False,
    anchor="middle",
):
    d = ' stroke-dasharray="5 4"' if dash else ""
    t = f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{colour}" stroke-width="1.3" marker-end="url(#{marker})"{d}/>\n'
    if label:
        lx = (x1 + x2) / 2 if lx is None else lx
        ly = (y1 + y2) / 2 - 6 if ly is None else ly
        t += f'<text x="{lx}" y="{ly}" font-size="10.5" text-anchor="{anchor}" fill="{colour}">{label}</text>\n'
    return t


def fig_call_path():
    b = ""
    b += box(20, 30, 130, 46, "User and IdP", "logs in, consents")
    b += box(20, 130, 130, 46, "Orchestrator", "agent, hop 0")
    b += box(20, 230, 130, 46, "Sub-agent", "agent, hop 1")
    b += f'<rect x="300" y="20" width="290" height="290" rx="8" fill="{LIGHT}" stroke="{INK}" stroke-width="1.3"/>\n'
    b += f'<text x="445" y="42" font-size="13" font-weight="600" text-anchor="middle" fill="{INK}">attenuo (token server and MCP proxy)</text>\n'
    b += box(
        320,
        56,
        250,
        40,
        "Token exchange (RFC 8693)",
        "child must be narrower than parent",
        bold=False,
    )
    b += f'<text x="445" y="120" font-size="11" text-anchor="middle" fill="{GREY}">checks on every tool call, in order</text>\n'
    stages = [
        "1  token and every hop's lease",
        "2  capabilities and run limits",
        "3  Cedar policy over the arguments",
        "4  approval, if the policy asks",
        "5  append decision to the audit log",
    ]
    for i, s in enumerate(stages):
        y = 128 + i * 34
        b += f'<rect x="320" y="{y}" width="250" height="27" rx="4" fill="#ffffff" stroke="{ACCENT}" stroke-width="1.2"/>\n'
        b += f'<text x="332" y="{y + 18}" font-size="11.5" fill="{INK}">{s}</text>\n'
    b += box(700, 150, 120, 50, "MCP server", "the tool")
    b += arrow(85, 76, 85, 128, "ID token", lx=92, ly=106, anchor="start")
    b += arrow(85, 176, 85, 228, "child token", lx=92, ly=206, anchor="start")
    for x1, y1, x2, y2, letter in [
        (150, 140, 318, 68, "A"),
        (150, 166, 318, 86, "B"),
        (150, 253, 318, 142, "C"),
    ]:
        b += arrow(x1, y1, x2, y2)
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        b += f'<circle cx="{mx}" cy="{my}" r="9" fill="#ffffff" stroke="{INK}" stroke-width="1.1"/>\n'
        b += f'<text x="{mx}" y="{my + 4}" font-size="11" font-weight="600" text-anchor="middle" fill="{INK}">{letter}</text>\n'
    b += arrow(590, 175, 698, 175, "allowed calls only", ly=167)
    b += arrow(590, 262, 640, 262, None, colour=WARN, marker="r")
    for k, line in enumerate(
        [
            "denied: an error with a reason",
            "and a decision id; the server",
            "never sees the call",
        ]
    ):
        b += f'<text x="648" y="{258 + k * 14}" font-size="10.5" fill="{WARN}">{line}</text>\n'
    for k, line in enumerate(
        [
            "A   the user's ID token is exchanged for a root token",
            "B   the root token is exchanged for a narrower child token",
            "C   the sub-agent calls a tool with the child token",
        ]
    ):
        b += f'<text x="20" y="{336 + k * 16}" font-size="11" fill="{INK}">{line}</text>\n'
    return svg(840, 380, b)


def fig_narrowing():
    b = ""
    rows = [
        (
            20,
            760,
            "User's grant to the orchestrator (hop 0)",
            ["github / *", "repo: any", "calls: no limit", "expires 10:30"],
        ),
        (
            90,
            620,
            "Orchestrator's grant to the coder (hop 1)",
            [
                "github / read_file",
                "repo: prefix alice/public-",
                "calls: at most 20",
                "expires 10:15",
            ],
        ),
        (
            120,
            560,
            "Coder's grant to a helper (hop 2)",
            [
                "github / read_file",
                "repo = alice/public-site",
                "calls: at most 5",
                "expires 10:05",
            ],
        ),
    ]
    y = 20
    for x, w, title, cells in rows:
        b += f'<rect x="{x}" y="{y}" width="{w}" height="62" rx="6" fill="{LIGHT}" stroke="{INK}" stroke-width="1.3"/>\n'
        b += f'<text x="{x + 12}" y="{y + 20}" font-size="12.5" font-weight="600" fill="{INK}">{title}</text>\n'
        cw = (w - 24) / 4
        for i, c in enumerate(cells):
            cx = x + 12 + i * cw
            b += f'<rect x="{cx}" y="{y + 30}" width="{cw - 8}" height="22" rx="4" fill="#ffffff" stroke="{ACCENT}" stroke-width="1.1"/>\n'
            b += f'<text x="{cx + (cw - 8) / 2}" y="{y + 45}" font-size="10.5" text-anchor="middle" fill="{INK}">{c}</text>\n'
        y += 92
    for i in range(2):
        yy = 82 + i * 92
        b += arrow(
            400,
            yy,
            400,
            yy + 28,
            "exchange: accepted only if narrower",
            lx=412,
            ly=yy + 19,
            anchor="start",
        )
    return svg(800, 276, b)


def bars(title_left, groups, series, ymax_label, w=800, h=330, note=None):
    """groups: [(label, [(num, den), ...])]; series: [(name, colour)]"""
    b = ""
    left, right, top, bottom = 60, 20, 30, 70
    pw, ph = w - left - right, h - top - bottom
    for t in range(0, 101, 20):
        y = top + ph - ph * t / 100
        b += f'<line x1="{left}" y1="{y}" x2="{w - right}" y2="{y}" stroke="#d9dde2" stroke-width="1"/>\n'
        b += f'<text x="{left - 8}" y="{y + 4}" font-size="10.5" text-anchor="end" fill="{GREY}">{t}%</text>\n'
    b += f'<text x="14" y="{top + ph / 2}" font-size="11" text-anchor="middle" fill="{INK}" transform="rotate(-90 14 {top + ph / 2})">{title_left}</text>\n'
    gw = pw / len(groups)
    n = len(series)
    bw = min(46, gw * 0.7 / n)
    for gi, (label, vals) in enumerate(groups):
        gx = left + gi * gw + gw / 2
        for si, (num, den) in enumerate(vals):
            x = gx + (si - n / 2) * (bw + 6) + 3
            hh = ph * num / den
            y = top + ph - hh
            b += f'<rect x="{x}" y="{y}" width="{bw}" height="{max(hh, 0.8)}" fill="{series[si][1]}"/>\n'
            b += f'<text x="{x + bw / 2}" y="{y - 5}" font-size="10.5" text-anchor="middle" fill="{INK}">{num}/{den}</text>\n'
        for li, line in enumerate(label.split("|")):
            b += f'<text x="{gx}" y="{top + ph + 18 + li * 13}" font-size="11.5" text-anchor="middle" fill="{INK}">{line}</text>\n'
    lx = left + 10
    for name, colour in series:
        b += f'<rect x="{lx}" y="{h - 18}" width="12" height="12" fill="{colour}"/>\n'
        b += f'<text x="{lx + 18}" y="{h - 8}" font-size="11.5" fill="{INK}">{name}</text>\n'
        lx += 30 + 7 * len(name)
    return svg(w, h, b)


def fig_agentdojo():
    groups = [
        ("slack", [(78, 99), (15, 99)]),
        ("banking", [(73, 143), (0, 143)]),
        ("travel", [(28, 140), (8, 140)]),
        ("workspace", [(28, 554), (2, 554)]),
        ("all four suites", [(207, 936), (25, 936)]),
    ]
    return bars(
        "attack cases scored as landed",
        groups,
        [("model alone", GREY), ("model behind attenuo", ACCENT)],
        100,
    )


def fig_suite():
    groups = [
        ("direct|(no check)", [(38, 38)]),
        ("tool names|only", [(21, 38)]),
        ("+ argument|constraints", [(14, 38)]),
        ("policy only,|broad token", [(11, 38)]),
        ("attenuo|(base)", [(7, 38)]),
        ("attenuo +|output labels", [(1, 38)]),
    ]
    return bars(
        "attack calls allowed (test split)",
        groups,
        [("attack calls that got through, of 38", ACCENT)],
        100,
    )


if __name__ == "__main__":
    for name, fn in [
        ("fig1-call-path.svg", fig_call_path),
        ("fig2-narrowing.svg", fig_narrowing),
        ("fig3-agentdojo-local-model.svg", fig_agentdojo),
        ("fig4-injection-suite-arms.svg", fig_suite),
    ]:
        (HERE / name).write_text(fn(), encoding="utf-8")
        print("wrote", name)
