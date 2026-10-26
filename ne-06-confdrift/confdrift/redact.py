"""Remove secrets from a config before it is stored or compared."""

from __future__ import annotations

import re

MASK = "<redacted>"

# Each pattern keeps group 1 (the command) and masks the rest of the line.
_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"^(\s*username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:password|secret)\s+(?:\d\s+)?)\S.*$",
        r"^(\s*enable\s+(?:password|secret)\s+(?:\d\s+)?)\S.*$",
        r"^(\s*snmp-server\s+community\s+)\S+(.*)$",
        r"^(\s*(?:ospf\s+)?(?:ip\s+ospf\s+)?message-digest-key\s+\d+\s+md5\s+(?:\d\s+)?)\S.*$",
        r"^(\s*(?:key-string|pre-shared-key|password|secret)\s+(?:\d\s+)?)\S.*$",
        r"^(\s*(?:tacacs|radius)-server\s+(?:host\s+\S+\s+)?key\s+(?:\d\s+)?)\S.*$",
    )
]


def redact(text: str) -> str:
    lines = []
    for line in text.splitlines():
        for pat in _PATTERNS:
            m = pat.match(line)
            if m:
                tail = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
                line = f"{m.group(1)}{MASK}{tail}"
                break
        lines.append(line)
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
