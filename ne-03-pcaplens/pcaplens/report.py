"""Self-contained HTML report: inline CSS and SVG, no JavaScript, no external requests.

Everything that came from the capture (hostnames, DNS names, addresses) is attacker
controlled, so every such string goes through `esc` before it reaches the page.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape as esc

from .analyze import Analysis
from .models import Finding

CSS = """
:root { --bg:#fbfbfa; --card:#ffffff; --fg:#1d2330; --muted:#5d6676; --line:#dfe2e8;
  --bar:#2e6fba; --bar2:#7aa6d8; --high:#b3261e; --medium:#a15c00; --low:#4b5563; }
@media (prefers-color-scheme: dark) { :root { --bg:#14171d; --card:#1c2029; --fg:#e6e9ef;
  --muted:#9aa3b2; --line:#2f3542; --bar:#6aa3e8; --bar2:#3f6aa3; --high:#ff8a80;
  --medium:#ffc266; --low:#aab2c0; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui,sans-serif; }
main { max-width:1000px; margin:0 auto; padding:24px 16px 48px; }
h1 { font-size:1.5rem; margin:0 0 4px; } h2 { font-size:1.1rem; margin:0 0 12px; }
.sub { color:var(--muted); margin:0 0 20px; word-break:break-all; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:20px; }
.card, section { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:14px 16px; }
section { margin-bottom:16px; }
.card b { display:block; font-size:1.4rem; } .card span { color:var(--muted); font-size:.85rem; }
table { width:100%; border-collapse:collapse; font-size:.9rem; }
th, td { text-align:left; padding:5px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; } td.n, th.n { text-align:right; font-variant-numeric:tabular-nums; }
code { font:.85em ui-monospace,monospace; word-break:break-all; }
.badge { display:inline-block; padding:1px 8px; border-radius:10px; font-size:.75rem; font-weight:700;
  border:1px solid currentColor; text-transform:uppercase; }
.high { color:var(--high); } .medium { color:var(--medium); } .low { color:var(--low); }
.finding { padding:10px 0; border-bottom:1px solid var(--line); } .finding:last-child { border:0; }
.ok { color:var(--muted); } svg text { fill:var(--fg); font:12px system-ui,sans-serif; }
svg .bar { fill:var(--bar); } svg .bar2 { fill:var(--bar2); } svg .axis { stroke:var(--line); }
svg .area { fill:var(--bar2); opacity:.6; } svg .line { fill:none; stroke:var(--bar); stroke-width:1.5; }
.two { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:16px; }
details summary { cursor:pointer; color:var(--muted); }
"""


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def hbar(
    items: list[tuple[str, float, str]], width: int = 460, label_w: int = 150
) -> str:
    """Horizontal bars: (label, value, value text). Returns an inline SVG."""
    if not items:
        return '<p class="ok">no data</p>'
    row, top = 22, 4
    peak = max(v for _, v, _ in items) or 1
    avail = (
        width - label_w - 8 - 7 * max(len(t) for _, _, t in items)
    )  # room for value text
    parts = [
        f'<svg viewBox="0 0 {width} {len(items) * row + top}" width="100%" role="img">'
    ]
    for i, (label, value, text) in enumerate(items):
        y = top + i * row
        w = max(1.0, avail * value / peak)
        short = label if len(label) <= 24 else label[:23] + "…"
        parts.append(
            f'<text x="{label_w - 6}" y="{y + 14}" text-anchor="end">{esc(short)}</text>'
            f'<rect class="bar" x="{label_w}" y="{y + 3}" width="{w:.1f}" height="14" rx="2"/>'
            f'<text x="{label_w + w + 5:.1f}" y="{y + 14}">{esc(text)}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def timeline_svg(
    points: list[tuple[float, int, int]], width: int = 900, height: int = 130
) -> str:
    if len(points) < 2:
        return '<p class="ok">capture is too short for a timeline</p>'
    left, bottom, top = 46, 20, 8
    peak = max(p for _, p, _ in points) or 1
    n = len(points)
    xs = [left + (width - left - 8) * i / (n - 1) for i in range(n)]
    ys = [top + (height - top - bottom) * (1 - p / peak) for _, p, _ in points]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))
    base = height - bottom
    area = f"{xs[0]:.1f},{base} {line} {xs[-1]:.1f},{base}"
    t0 = datetime.fromtimestamp(points[0][0], timezone.utc).strftime("%H:%M:%S")
    t1 = datetime.fromtimestamp(points[-1][0], timezone.utc).strftime("%H:%M:%S")
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" role="img">'
        f'<line class="axis" x1="{left}" y1="{base}" x2="{width - 8}" y2="{base}"/>'
        f'<polygon class="area" points="{area}"/><polyline class="line" points="{line}"/>'
        f'<text x="{left - 6}" y="{top + 10}" text-anchor="end">{peak}</text>'
        f'<text x="{left - 6}" y="{base}" text-anchor="end">0</text>'
        f'<text x="{left}" y="{height - 4}">{t0} UTC</text>'
        f'<text x="{width - 8}" y="{height - 4}" text-anchor="end">{t1} UTC</text>'
        f'<text x="{width // 2}" y="{height - 4}" text-anchor="middle">packets per bucket</text>'
        "</svg>"
    )


def _table(
    headers: list[str], rows: list[list[str]], numeric: set[int] = frozenset()
) -> str:
    head = "".join(
        f'<th class="{"n" if i in numeric else ""}">{esc(h)}</th>'
        for i, h in enumerate(headers)
    )
    body = "".join(
        "<tr>"
        + "".join(
            f'<td class="{"n" if i in numeric else ""}">{c}</td>'
            for i, c in enumerate(r)
        )
        + "</tr>"
        for r in rows
    )
    return f"<table><tr>{head}</tr>{body}</table>"


def _evidence(f: Finding) -> str:
    rows = "".join(
        f"<tr><th>{esc(str(k))}</th><td><code>{esc(str(v))}</code></td></tr>"
        for k, v in f.evidence.items()
    )
    return f"<details><summary>evidence</summary><table>{rows}</table></details>"


def render_html(
    a: Analysis, findings: list[Finding], source: str, top: int = 10
) -> str:
    start = (
        datetime.fromtimestamp(a.start, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        if a.start
        else "n/a"
    )
    cards = [
        (f"{a.packets:,}", "packets"),
        (human_bytes(a.bytes), "bytes"),
        (f"{a.duration:.1f}s", "duration"),
        (str(len(a.hosts)), "hosts"),
        (str(len(findings)), "findings"),
    ]
    out = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>PCAP report</title><style>{CSS}</style></head><body><main>",
        "<h1>PCAP analysis report</h1>",
        f'<p class="sub"><code>{esc(source)}</code> &middot; first packet {esc(start)}</p>',
        '<div class="cards">'
        + "".join(
            f'<div class="card"><b>{esc(v)}</b><span>{esc(k)}</span></div>'
            for v, k in cards
        )
        + "</div>",
    ]
    # Findings
    out.append("<section><h2>Findings</h2>")
    if findings:
        for f in findings:
            out.append(
                f'<div class="finding"><span class="badge {esc(f.severity)}">{esc(f.severity)}</span> '
                f"<b>{esc(f.kind)}</b> &middot; {esc(f.summary)}{_evidence(f)}</div>"
            )
    else:
        out.append(
            '<p class="ok">Nothing suspicious found with the current thresholds.</p>'
        )
    out.append("</section>")
    # Talkers
    by_bytes = a.top_hosts(top, "bytes")
    by_pkts = a.top_hosts(top, "packets")
    out.append('<section><h2>Top talkers</h2><div class="two"><div><b>By bytes</b>')
    out.append(hbar([(h.ip, h.bytes, human_bytes(h.bytes)) for h in by_bytes]))
    out.append("</div><div><b>By packets</b>")
    out.append(hbar([(h.ip, h.packets, f"{h.packets:,}") for h in by_pkts]))
    out.append("</div></div>")
    out.append(
        _table(
            ["Host", "Sent", "Received", "Packets"],
            [
                [
                    f"<code>{esc(h.ip)}</code>",
                    human_bytes(h.tx_bytes),
                    human_bytes(h.rx_bytes),
                    f"{h.packets:,}",
                ]
                for h in by_bytes
            ],
            {1, 2, 3},
        )
    )
    convs = a.top_conversations(top)
    out.append("<h2 style='margin-top:16px'>Top conversations</h2>")
    out.append(
        _table(
            ["Pair", "Bytes", "Packets"],
            [
                [f"<code>{esc(x)} &harr; {esc(y)}</code>", human_bytes(b), f"{p:,}"]
                for (x, y), b, p in convs
            ],
            {1, 2},
        )
    )
    out.append("</section>")
    # Protocols and timeline
    protos = sorted(a.protocol_bytes.items(), key=lambda kv: -kv[1])[:12]
    out.append("<section><h2>Protocols</h2>")
    out.append(
        hbar(
            [
                (n, b, f"{human_bytes(b)} / {a.protocol_packets[n]:,} pkts")
                for n, b in protos
            ],
            width=620,
        )
    )
    out.append(
        "</section><section><h2>Traffic over time</h2>"
        + timeline_svg(a.timeline)
        + "</section>"
    )
    # DNS
    d = a.dns
    out.append("<section><h2>DNS</h2>")
    if d.queries or d.responses:
        out.append(
            f"<p>{d.queries:,} queries, {d.responses:,} responses, NXDOMAIN rate "
            f"<b>{d.nxdomain_rate:.1%}</b></p><div class='two'><div><b>Response codes</b>"
            + hbar(
                [(k, v, str(v)) for k, v in d.rcodes.most_common()],
                width=380,
                label_w=110,
            )
            + "</div><div><b>Query types</b>"
            + hbar(
                [(k, v, str(v)) for k, v in d.qtypes.most_common(8)],
                width=380,
                label_w=110,
            )
            + "</div></div>"
        )
        out.append("<p><b>Most queried names</b></p>")
        out.append(
            _table(
                ["Name", "Queries"],
                [
                    [f"<code>{esc(n)}</code>", str(c)]
                    for n, c in d.top_names.most_common(top)
                ],
                {1},
            )
        )
        if d.nxdomain_names:
            out.append("<p><b>Names that returned NXDOMAIN</b></p>")
            out.append(
                _table(
                    ["Name", "Count"],
                    [
                        [f"<code>{esc(n)}</code>", str(c)]
                        for n, c in d.nxdomain_names.most_common(top)
                    ],
                    {1},
                )
            )
    else:
        out.append('<p class="ok">No DNS traffic in this capture.</p>')
    out.append("</section>")
    # TCP
    t = a.tcp
    out.append("<section><h2>TCP health</h2>")
    out.append(
        _table(
            ["Metric", "Value"],
            [
                ["TCP packets", f"{t.packets:,}"],
                ["Connection attempts (SYN)", f"{t.syns:,}"],
                ["SYN-ACK replies", f"{t.synacks:,}"],
                [
                    "Retransmissions",
                    f"{t.retransmissions:,} ({t.retransmission_rate:.1%})",
                ],
                ["Out-of-order segments", f"{t.out_of_order:,}"],
                ["Resets (RST)", f"{t.resets:,}"],
            ],
            {1},
        )
    )
    if t.reset_pairs:
        out.append("<p><b>Resets by sender</b></p>")
        out.append(
            _table(
                ["Direction", "RSTs"],
                [
                    [f"<code>{esc(k)}</code>", str(v)]
                    for k, v in t.reset_pairs.most_common(top)
                ],
                {1},
            )
        )
    if t.retrans_flows:
        out.append("<p><b>Flows with retransmissions</b></p>")
        out.append(
            _table(
                ["Flow", "Retransmissions"],
                [
                    [f"<code>{esc(k)}</code>", str(v)]
                    for k, v in t.retrans_flows.most_common(top)
                ],
                {1},
            )
        )
    out.append("</section>")
    out.append(
        '<p class="ok">Generated by pcaplens. Detections are heuristics: check the evidence before acting.</p>'
    )
    out.append("</main></body></html>")
    return "".join(out)
