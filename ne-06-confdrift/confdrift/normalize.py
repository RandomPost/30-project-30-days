"""Turn a device config into comparable blocks.

A block is a top-level line plus its indented children. Comments, `exit`/`end`
markers, CLI banners and the lines in IGNORE are dropped, so two configs that mean
the same thing compare equal even when produced by different tools."""

from __future__ import annotations

import re

# Lines every FRR running-config carries that the generated config never has.
IGNORE = (
    r"^frr version\b",
    r"^frr defaults\b",
    r"^log\b",
    r"^service integrated-vtysh-config$",
    r"^line vty$",
)
_NOISE = (
    r"^!",
    r"^%",
    r"^Building configuration",
    r"^Current configuration",
    r"^exit$",
    r"^end$",
)

Blocks = dict[str, list[str]]


def parse(text: str, ignore: tuple[str, ...] = IGNORE) -> Blocks:
    drop = [re.compile(p) for p in _NOISE + tuple(ignore)]
    blocks: Blocks = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if any(p.search(stripped) for p in drop):
            if not line[0].isspace():
                current = None
            continue
        if line[0].isspace():
            if current is not None:
                blocks[current].append(stripped)
        else:
            current = stripped
            blocks.setdefault(current, [])
    return blocks


def canonical(blocks: Blocks) -> str:
    """Stable text: blocks and their children sorted, children indented one space.

    Sorting means command order inside a block is ignored. That is right for
    interfaces and routing processes, wrong for ordered lists such as ACLs."""
    out = []
    for header in sorted(blocks):
        out.append(header)
        out.extend(" " + child for child in sorted(set(blocks[header])))
    return "\n".join(out) + ("\n" if out else "")


_CHROME = re.compile(
    r"^(%|Building configuration|Current configuration|! Last configuration change|"
    r"! NVRAM config last updated|! Time:)"
)


def strip_chrome(text: str) -> str:
    """Drop CLI chatter that changes between runs without the config changing, so a
    backup only differs from the last one when the configuration did."""
    lines = [ln.rstrip() for ln in text.splitlines() if not _CHROME.match(ln)]
    while lines and not lines[0].strip():
        lines.pop(0)
    return "\n".join(lines) + "\n"
