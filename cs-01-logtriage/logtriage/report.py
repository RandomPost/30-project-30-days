"""Render findings as a terminal table or JSON."""

from __future__ import annotations

import json

from .detector import Finding


def to_table(findings: list[Finding]) -> str:
    header = ["RANK", "IP", "FAILS", "PEAK/WIN", "USERS", "FLAG"]
    rows = [
        [
            str(i),
            f.ip,
            str(f.failures),
            str(f.max_in_window),
            str(len(f.usernames)),
            "BRUTE-FORCE" if f.flagged else "-",
        ]
        for i, f in enumerate(findings, 1)
    ]
    widths = [max(len(r[c]) for r in [header, *rows]) for c in range(len(header))]
    lines = ["  ".join(v.ljust(w) for v, w in zip(r, widths)) for r in [header, *rows]]
    return "\n".join(lines)


def to_json(findings: list[Finding]) -> str:
    out = [
        {
            "rank": i,
            "ip": f.ip,
            "failures": f.failures,
            "max_in_window": f.max_in_window,
            "usernames": f.usernames,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
            "flagged": f.flagged,
        }
        for i, f in enumerate(findings, 1)
    ]
    return json.dumps(out, indent=2)
