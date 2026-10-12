"""Parse failed SSH logins from auth.log or journalctl exports."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator

# "Oct 12 03:01:04 host sshd[123]: Failed password for [invalid user] bob from 1.2.3.4 port 22 ssh2"
_SYSLOG_TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s")
# ISO timestamps as produced by `journalctl -o short-iso`
_ISO_TS = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
_FAILED = re.compile(
    r"sshd\[\d+\]:\s+(?:Failed \w+|Invalid user|Connection closed by invalid user)"
    r".*?(?:for (?:invalid user )?|user )(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)


@dataclass(frozen=True)
class Failure:
    time: datetime
    user: str
    ip: str


def parse_timestamp(line: str, year: int) -> datetime | None:
    """Return the line's timestamp, or None. Syslog lines carry no year."""
    m = _ISO_TS.match(line)
    if m:
        return datetime.fromisoformat(m["ts"])
    m = _SYSLOG_TS.match(line)
    if m:
        return datetime.strptime(
            f"{year} {' '.join(m['ts'].split())}", "%Y %b %d %H:%M:%S"
        )
    return None


def parse_line(line: str, year: int) -> Failure | None:
    """Parse one log line into a Failure, or None if it is not a failed login."""
    m = _FAILED.search(line)
    if not m:
        return None
    ts = parse_timestamp(line, year)
    if ts is None:
        return None
    return Failure(time=ts, user=m["user"], ip=m["ip"])


def parse_lines(lines: Iterable[str], year: int) -> Iterator[Failure]:
    for line in lines:
        failure = parse_line(line, year)
        if failure:
            yield failure
