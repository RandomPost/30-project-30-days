"""Static MITRE ATT&CK table for the techniques the lab emulates, plus tag helpers."""

from __future__ import annotations

import re

TACTIC_ORDER = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)

TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1595.002": ("Vulnerability Scanning", "reconnaissance"),
    "T1595.003": ("Wordlist Scanning", "reconnaissance"),
    "T1190": ("Exploit Public-Facing Application", "initial-access"),
    "T1110": ("Brute Force", "credential-access"),
    "T1110.001": ("Password Guessing", "credential-access"),
    "T1110.003": ("Password Spraying", "credential-access"),
    "T1078": ("Valid Accounts", "initial-access"),
    "T1082": ("System Information Discovery", "discovery"),
    "T1033": ("System Owner/User Discovery", "discovery"),
    "T1083": ("File and Directory Discovery", "discovery"),
    "T1057": ("Process Discovery", "discovery"),
    "T1016": ("System Network Configuration Discovery", "discovery"),
    "T1087": ("Account Discovery", "discovery"),
    "T1087.001": ("Local Account Discovery", "discovery"),
    "T1036": ("Masquerading", "defense-evasion"),
    "T1036.005": ("Match Legitimate Name or Location", "defense-evasion"),
    "T1053": ("Scheduled Task/Job", "persistence"),
    "T1053.003": ("Cron", "persistence"),
}

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def normalize_tag(tag: str) -> str | None:
    """'attack.t1110.001' -> 'T1110.001'; None for tactic or non-ATT&CK tags."""
    tag = tag.strip()
    if not tag.lower().startswith("attack."):
        return None
    candidate = tag[len("attack.") :].upper()
    return candidate if _TECHNIQUE_RE.match(candidate) else None


def parent_of(technique_id: str) -> str:
    """'T1110.001' -> 'T1110'; a parent technique is returned unchanged."""
    return technique_id.split(".", 1)[0]


def covers(rule_tag_id: str, technique_id: str) -> bool:
    """True if a rule tagged `rule_tag_id` covers `technique_id`."""
    return rule_tag_id == technique_id or rule_tag_id == parent_of(technique_id)


def name_of(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, (technique_id, ""))[0]


def tactic_of(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, ("", ""))[1]


def tactic_rank(tactic: str) -> int:
    """Kill-chain position of a tactic; unknown tactics sort last."""
    try:
        return TACTIC_ORDER.index(tactic)
    except ValueError:
        return len(TACTIC_ORDER)
