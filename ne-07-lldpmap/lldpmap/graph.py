"""Interactive HTML graph (pyvis / vis-network), self-contained."""

from __future__ import annotations

import re
from html import escape as html_escape
from pathlib import Path
from typing import Optional

from pyvis.network import Network

from lldpmap.diff import compare
from lldpmap.topology import Link, Topology

VENDOR_COLOR = {"frr": "#4C8BF5", "eos": "#2E9E6B", "ios": "#D9822B"}
UNKNOWN = "#9AA0A6"
ADDED, REMOVED = "#1E9E3A", "#D93025"


def _edge_label(l: Link) -> str:
    return f"{l.a_port} - {l.b_port}"


def _caption(topo: Topology, previous: Optional[Topology]) -> str:
    text = f"Topology from {topo.seed}, crawled {topo.taken}"
    if previous:
        text += (
            f" (compared with {previous.taken}: red dashed = removed, green = added)"
        )
    return text


def render(
    topo: Topology,
    out: Path,
    previous: Optional[Topology] = None,
    height: str = "720px",
) -> None:
    """Write the graph. With `previous`, links gone since then are drawn as red dashed
    lines and new links in green."""
    net = Network(
        height=height,
        width="100%",
        directed=False,
        cdn_resources="in_line",
        heading="",
    )
    net.set_options(
        '{"physics":{"solver":"forceAtlas2Based",'
        '"forceAtlas2Based":{"springLength":260,"gravitationalConstant":-90,"springConstant":0.05},'
        '"stabilization":{"iterations":200}},'
        '"edges":{"font":{"size":11,"align":"middle","strokeWidth":3,"strokeColor":"#ffffff"},'
        '"smooth":{"type":"continuous"}}}'
    )
    delta = compare(previous, topo) if previous else None
    removed = set(delta.links_removed) if delta else set()
    added = set(delta.links_added) if delta else set()
    gone = set(delta.devices_removed) if delta else set()

    devices = dict(topo.devices)
    if previous:
        for name in gone:
            devices[name] = previous.devices[name]

    for name, d in sorted(devices.items()):
        color = VENDOR_COLOR.get(d.vendor, UNKNOWN) if d.crawled else UNKNOWN
        title = f"{name}\nvendor: {d.vendor}\nhost: {d.host or '-'}"
        if d.note:
            title += f"\nnot crawled: {d.note}"
        net.add_node(
            name,
            label=name,
            title=title,
            color={"background": color, "border": REMOVED if name in gone else color},
            shape="box" if d.crawled else "ellipse",
            font={"color": "#ffffff" if d.crawled else "#202124", "size": 16},
            borderWidth=3 if name in gone else 1,
            shapeProperties={"borderDashes": [6, 4]} if name in gone else {},
        )
    for l in sorted(topo.links | removed):
        kwargs: dict = {"width": 2}
        status = "present"
        if l in removed:
            kwargs.update(color=REMOVED, dashes=True, width=3)
            status = "REMOVED since previous run"
        elif l in added:
            kwargs.update(color=ADDED, width=4)
            status = "ADDED since previous run"
        net.add_edge(
            l.a_dev, l.b_dev, label=_edge_label(l), title=f"{l}\n{status}", **kwargs
        )
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    html = net.generate_html()
    caption = (
        '<p style="font:14px sans-serif;margin:8px 12px">'
        f"{html_escape(_caption(topo, previous))}</p>"
    )
    html = html.replace("<body>", "<body>\n" + caption, 1)
    # pyvis links Bootstrap from a CDN for page styling only; drop it so the file
    # has no external requests and works offline.
    html = re.sub(
        r"<(?:link|script)[^>]*cdn\.jsdelivr\.net[^>]*>(?:\s*</script>)?", "", html
    )
    out.write_text(html)
