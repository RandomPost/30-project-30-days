"""Format findings for humans."""

from __future__ import annotations

from .scanner import Finding


def format_findings(findings: list[Finding]) -> str:
    if not findings:
        return "No secrets found."
    lines = [f"{len(findings)} possible secret(s) found:"]
    for f in findings:
        lines.append(
            f"  {f.path}:{f.line}  [{f.rule}]  {f.redacted}  (fp:{f.fingerprint})"
        )
    lines.append(
        "Remove the secret, or allowlist a false positive in .secretscan-allow "
        "(or add `secretscan:ignore` to the line)."
    )
    return "\n".join(lines)
