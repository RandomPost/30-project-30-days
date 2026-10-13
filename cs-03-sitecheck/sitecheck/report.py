"""Markdown and CSV output."""

from __future__ import annotations

import csv
import io

from .models import SiteResult


def to_markdown(results: list[SiteResult]) -> str:
    lines = [
        "# Security hygiene report",
        "",
        "| Site | Grade | Score |",
        "|---|---|---|",
    ]
    for r in results:
        lines.append(f"| {r.domain} | {r.grade} | {r.score} |")
    for r in results:
        lines += ["", f"## {r.domain}: {r.grade} ({r.score}/100)"]
        if r.tls:
            lines.append(
                f"TLS {r.tls.version}, certificate valid {r.tls.days_left} days."
            )
        if not r.issues:
            lines.append("No issues found.")
        for i in r.issues:
            lines.append(f"- **{i.check}** (-{i.penalty}): {i.reason}. Fix: {i.fix}")
    return "\n".join(lines) + "\n"


def to_csv(results: list[SiteResult]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["domain", "grade", "score", "check", "penalty", "reason", "fix"])
    for r in results:
        if not r.issues:
            w.writerow([r.domain, r.grade, r.score, "", 0, "", ""])
        for i in r.issues:
            w.writerow(
                [r.domain, r.grade, r.score, i.check, i.penalty, i.reason, i.fix]
            )
    return buf.getvalue()


def to_table(results: list[SiteResult]) -> str:
    width = max([len(r.domain) for r in results] + [4])
    rows = [f"{'SITE':<{width}}  GRADE  SCORE  ISSUES"]
    for r in results:
        rows.append(f"{r.domain:<{width}}  {r.grade:<5}  {r.score:<5}  {len(r.issues)}")
    return "\n".join(rows)
