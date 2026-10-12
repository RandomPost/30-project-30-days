"""Pure scanning logic: text in, findings out. No file or git access here."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .rules import (
    CANDIDATE,
    ENTROPY_RULE_ID,
    ENTROPY_THRESHOLD,
    RULES,
    looks_placeholder,
    shannon_entropy,
)

IGNORE_MARKER = "secretscan:ignore"


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    description: str
    secret: str

    @property
    def fingerprint(self) -> str:
        """Stable id so one finding can be allowlisted without hiding the rule."""
        raw = f"{self.path}:{self.rule}:{self.secret}".encode()
        return hashlib.sha256(raw).hexdigest()[:12]

    @property
    def redacted(self) -> str:
        s = self.secret
        return s if len(s) <= 8 else f"{s[:4]}...{s[-2:]} ({len(s)} chars)"


def scan_text(text: str, path: str = "<text>") -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if IGNORE_MARKER in line:
            continue
        findings.extend(_scan_line(line, lineno, path))
    return findings


def _scan_line(line: str, lineno: int, path: str) -> list[Finding]:
    out: list[Finding] = []
    covered: set[str] = set()
    for rule in RULES:
        for m in rule.pattern.finditer(line):
            secret = m.group(rule.group)
            if looks_placeholder(secret):
                continue
            covered.add(secret)
            out.append(Finding(path, lineno, rule.id, rule.description, secret))
    for m in CANDIDATE.finditer(line):
        value = m.group(1)
        if value in covered or looks_placeholder(value):
            continue
        if shannon_entropy(value) >= ENTROPY_THRESHOLD:
            out.append(
                Finding(path, lineno, ENTROPY_RULE_ID, "High-entropy string", value)
            )
    return out
