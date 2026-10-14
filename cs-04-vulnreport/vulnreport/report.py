"""Text, Markdown and JSON reports grouped by severity."""

from __future__ import annotations

import json
from itertools import groupby

from .models import SEVERITIES, Finding


def _fix(f: Finding) -> str:
    return "upgrade to " + " / ".join(f.fixed) if f.fixed else "no fix listed"


def to_text(findings: list[Finding], n_deps: int) -> str:
    if not findings:
        return f"No known vulnerabilities in {n_deps} dependencies."
    lines = [f"{len(findings)} vulnerabilities in {n_deps} dependencies"]
    for sev, group in groupby(findings, key=lambda f: f.severity):
        group = list(group)
        lines += ["", f"{sev} ({len(group)})"]
        for f in group:
            lines.append(
                f"  {f.dep.name} {f.dep.version}  {f.vuln_id}  {_fix(f)}\n"
                f"      {f.summary}"
            )
    return "\n".join(lines)


def to_markdown(findings: list[Finding], n_deps: int) -> str:
    out = ["# Dependency vulnerability report", "", f"{n_deps} dependencies scanned."]
    if not findings:
        return "\n".join(out + ["", "No known vulnerabilities."]) + "\n"
    for sev in SEVERITIES:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        out += ["", f"## {sev} ({len(group)})", "", "| Package | Version | ID | Fix |"]
        out.append("|---|---|---|---|")
        for f in group:
            out.append(f"| {f.dep.name} | {f.dep.version} | {f.vuln_id} | {_fix(f)} |")
    return "\n".join(out) + "\n"


def to_json(findings: list[Finding]) -> str:
    return json.dumps(
        [
            {
                "package": f.dep.name,
                "version": f.dep.version,
                "ecosystem": f.dep.ecosystem,
                "id": f.vuln_id,
                "aliases": list(f.aliases),
                "severity": f.severity,
                "score": f.score,
                "fixed": list(f.fixed),
                "summary": f.summary,
            }
            for f in findings
        ],
        indent=2,
    )
