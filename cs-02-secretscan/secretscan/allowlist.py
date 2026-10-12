"""Allowlist for false positives.

File format (`.secretscan-allow`), one entry per line, `#` starts a comment:

    path:docs/*.md          ignore every finding in matching files (fnmatch glob)
    rule:high-entropy-string  ignore a rule everywhere
    fp:3fa9c1d2e4b5         ignore one finding by fingerprint (shown in output)

A line containing `secretscan:ignore` is also skipped during scanning.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from .scanner import Finding


@dataclass
class Allowlist:
    paths: list[str] = field(default_factory=list)
    rules: set[str] = field(default_factory=set)
    fingerprints: set[str] = field(default_factory=set)

    def allows(self, f: Finding) -> bool:
        return (
            f.rule in self.rules
            or f.fingerprint in self.fingerprints
            or any(fnmatch.fnmatch(f.path, g) for g in self.paths)
        )


def parse_allowlist(text: str) -> Allowlist:
    allow = Allowlist()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        kind, _, value = line.partition(":")
        value = value.strip()
        if not value:
            continue
        if kind == "path":
            allow.paths.append(value)
        elif kind == "rule":
            allow.rules.add(value)
        elif kind == "fp":
            allow.fingerprints.add(value)
    return allow
