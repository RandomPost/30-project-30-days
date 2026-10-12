"""Detection rules: named regexes plus a Shannon-entropy check."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    pattern: re.Pattern[str]
    group: int = 0  # which regex group holds the secret itself


RULES: tuple[Rule, ...] = (
    Rule(
        "aws-access-key-id",
        "AWS access key ID",
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b"),
    ),
    Rule(
        "aws-secret-access-key",
        "AWS secret access key assignment",
        re.compile(
            r"(?i)aws.{0,20}?(?:secret|private).{0,20}?[=:]\s*['\"]?"
            r"([A-Za-z0-9/+=]{40})\b"
        ),
        group=1,
    ),
    Rule(
        "private-key",
        "PEM private key block",
        re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----"),
    ),
    Rule(
        "github-token",
        "GitHub token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
    ),
    Rule(
        "slack-token",
        "Slack token",
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    Rule(
        "google-api-key",
        "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    Rule(
        "generic-api-key",
        "Generic API key / secret / token assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b['\"]?\s*[:=]\s*"
            r"['\"]([A-Za-z0-9_\-/+=.]{16,})['\"]"
        ),
        group=1,
    ),
)

ENTROPY_RULE_ID = "high-entropy-string"
ENTROPY_THRESHOLD = 4.5  # bits per char; random base64/hex-ish strings land above
ENTROPY_MIN_LEN = 24
CANDIDATE = re.compile(r"['\"]([A-Za-z0-9+/_=-]{%d,})['\"]" % ENTROPY_MIN_LEN)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def looks_placeholder(value: str) -> bool:
    """Cheap filter for obvious non-secrets (repeated chars, 'example', etc.)."""
    low = value.lower()
    if any(w in low for w in ("example", "placeholder", "changeme", "your_", "xxxx")):
        return True
    return len(set(value)) <= 4
