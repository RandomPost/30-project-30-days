"""Severity and fixed-version extraction from OSV vulnerability records. Pure."""

from __future__ import annotations

import math

from .models import Dep, Finding

# CVSS v3.x base score metric weights
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
GITHUB_LEVELS = {"CRITICAL", "HIGH", "MODERATE", "LOW"}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """Base score from a `CVSS:3.x/AV:N/...` vector, or None if not v3."""
    if not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(part.split(":") for part in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = (_PR_C if changed else _PR_U)[m["PR"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        impact = (
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        )
        expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + expl) if changed else impact + expl
    return _roundup(min(total, 10))


def label_for_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "UNKNOWN"


def severity_of(vuln: dict) -> tuple[str, float | None]:
    """Prefer a computed CVSS v3 score; fall back to the advisory's own label."""
    for s in vuln.get("severity", []):
        score = cvss3_score(s.get("score", ""))
        if score is not None:
            return label_for_score(score), score
    label = str(vuln.get("database_specific", {}).get("severity", "")).upper()
    if label in GITHUB_LEVELS:
        return ("MEDIUM" if label == "MODERATE" else label), None
    return "UNKNOWN", None


def fixed_versions(vuln: dict, dep: Dep) -> tuple[str, ...]:
    out: list[str] = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != dep.ecosystem:
            continue
        if pkg.get("name", "").lower().replace("_", "-") != dep.name.lower().replace(
            "_", "-"
        ):
            continue
        for rng in aff.get("ranges", []):
            out += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return tuple(dict.fromkeys(out))


def to_finding(vuln: dict, dep: Dep) -> Finding:
    sev, score = severity_of(vuln)
    return Finding(
        dep=dep,
        vuln_id=vuln["id"],
        aliases=tuple(vuln.get("aliases", [])),
        summary=vuln.get("summary") or (vuln.get("details", "")[:120]),
        severity=sev,
        score=score,
        fixed=fixed_versions(vuln, dep),
    )
