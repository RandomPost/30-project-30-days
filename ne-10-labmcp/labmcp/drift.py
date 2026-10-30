"""Compare a router's running-config with the intended config file. Pure."""

from __future__ import annotations

import difflib
import re

# Lines FRR adds or rewrites that say nothing about intent.
IGNORED_PREFIXES = (
    "!", "frr version", "frr defaults", "building configuration", "current configuration",
    "hostname", "service integrated", "log ", "end", "line vty",
)  # fmt: skip


# FRR prints some things differently from how they are configured.
REWRITES = (
    (re.compile(r"\b65535:666\b"), "blackhole"),  # well-known community by name
    (
        re.compile(r"^(bgp community-list standard \S+) seq \d+ "),
        r"\1 ",
    ),  # auto sequence number
)


# FRR adds this by itself to route-server peer groups.
IMPLICIT = re.compile(r"neighbor \S+ attribute-unchanged next-hop")


def normalize(text: str) -> list[str]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith(IGNORED_PREFIXES):
            continue
        # keep nesting: indentation changes meaning, so fold it into the line
        line = " ".join(line.split())
        for pat, repl in REWRITES:
            line = pat.sub(repl, line)
        if IMPLICIT.fullmatch(line):
            continue
        out.append(("  " if raw.startswith(" ") else "") + line)
    return out


def blocks(lines: list[str]) -> dict[str, list[str]]:
    """Group lines under their top-level stanza so drift names where it happened."""
    cur, out = "(global)", {"(global)": []}
    for line in lines:
        if line.startswith("  "):
            out[cur].append(line.strip())
        else:
            cur = line
            out.setdefault(cur, [])
            out[cur].append("")  # marker so an empty stanza still counts
    # FRR prints an empty `rpki` stanza on routers that do not use it
    if out.get("rpki") == [""]:
        del out["rpki"]
    return {k: sorted(v) for k, v in out.items()}


def diff(intended: str, running: str) -> list[str]:
    """Human-readable drift lines; empty means no drift (order inside a stanza is ignored)."""
    want, have = blocks(normalize(intended)), blocks(normalize(running))
    out = []
    for stanza in sorted(set(want) | set(have)):
        w, h = want.get(stanza, []), have.get(stanza, [])
        if w == h:
            continue
        if stanza not in have:
            out.append(f"stanza missing on device: {stanza}")
        elif stanza not in want:
            out.append(f"stanza not in intended config: {stanza}")
        for line in difflib.ndiff(w, h):
            if line.startswith("- ") and line[2:]:
                out.append(f"[{stanza}] intended but not running: {line[2:]}")
            elif line.startswith("+ ") and line[2:]:
                out.append(f"[{stanza}] running but not intended: {line[2:]}")
    return out
