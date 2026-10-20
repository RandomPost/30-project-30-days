"""Turn raw log lines into normalized event dicts (keys of db.EVENT_FIELDS)."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import unquote_plus

MONTHS = {
    m: i
    for i, m in enumerate(
        "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1
    )
}

# "Oct 18 02:14:09 web01 sshd[812]: message"  (syslog treated as UTC, no year)
SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
# "2026-10-18T02:14:09+00:00 web01 sshd[812]: message"
ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
NGINX_RE = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] \"(?P<req>[^\"]*)\" "
    r"(?P<status>\d{3}) (?P<bytes>\d+|-) \"(?P<ref>[^\"]*)\" \"(?P<ua>[^\"]*)\""
)

SSH_FAILED = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+"
)
SSH_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) "
    r"from (?P<ip>\S+) port \d+"
)
SSH_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)")
SUDO_CMD = re.compile(r"^\s*(?P<user>\S+)\s*: .*?COMMAND=(?P<cmd>.*)$")
SUDO_FAIL = re.compile(r"^\s*(?P<user>\S+)\s*: .*incorrect password attempt")
SU_FAIL = re.compile(r"FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on")
SU_OK = re.compile(r"Successful su for (?P<target>\S+) by (?P<user>\S+)")
USERADD = re.compile(r"new user: name=(?P<user>[^,\s]+)")
CRONTAB = re.compile(r"\((?P<user>[^)]+)\) (?P<verb>REPLACE|DELETE)\b")
CRON_CMD = re.compile(r"\((?P<user>[^)]+)\) CMD ")
CMDAUDIT = re.compile(r"user=(?P<user>\S+) src=(?P<ip>\S+) cmd=(?P<cmd>.*)$")

_UTC = timezone.utc


def iso(dt: datetime) -> str:
    return dt.astimezone(_UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _blank(source: str, raw: str) -> dict:
    return {
        "source": source,
        "raw": raw,
        "action": "other",
        "outcome": None,
        "host": None,
        "program": None,
        "pid": None,
        "message": None,
        "src_ip": None,
        "user": None,
        "command": None,
        "http_method": None,
        "http_path": None,
        "http_status": None,
        "http_bytes": None,
        "user_agent": None,
    }


def _classify(ev: dict, prog: str, msg: str) -> None:
    """Fill action/outcome/user/src_ip/command from a syslog program + message."""
    if prog == "sshd":
        for rx, action, outcome in (
            (SSH_FAILED, "login", "failure"),
            (SSH_ACCEPTED, "login", "success"),
            (SSH_INVALID, "invalid_user", "failure"),
        ):
            m = rx.search(msg)
            if m:
                ev.update(
                    action=action,
                    outcome=outcome,
                    user=m["user"] or None,
                    src_ip=m["ip"],
                )
                return
    elif prog == "sudo":
        m = SUDO_FAIL.match(msg)
        if m:
            ev.update(action="sudo", outcome="failure", user=m["user"])
            return
        m = SUDO_CMD.match(msg)
        if m:
            ev.update(
                action="sudo",
                outcome="success",
                user=m["user"],
                command=m["cmd"].strip(),
            )
            return
    elif prog == "su":
        m = SU_FAIL.search(msg)
        if m:
            ev.update(action="su", outcome="failure", user=m["user"])
            return
        m = SU_OK.search(msg)
        if m:
            ev.update(action="su", outcome="success", user=m["user"])
            return
    elif prog == "useradd":
        m = USERADD.search(msg)
        if m:
            ev.update(action="user_created", outcome="success", user=m["user"])
            return
    elif prog == "crontab":
        m = CRONTAB.search(msg)
        if m:
            ev.update(action="cron_change", outcome="success", user=m["user"])
            return
    elif prog == "cmdaudit":
        m = CMDAUDIT.search(msg)
        if m:
            ev.update(
                action="command",
                outcome="success",
                user=m["user"],
                src_ip=m["ip"],
                command=m["cmd"].strip(),
            )
    elif prog in ("CRON", "cron"):
        m = CRON_CMD.search(msg)
        if m:
            ev.update(action="cron_exec", outcome="success", user=m["user"])


def parse_syslog_line(line: str, source: str, year: int) -> dict | None:
    """Parse a syslog-style line (auth.log or syslog). None if it isn't one."""
    line = line.rstrip("\n")
    m = SYSLOG_RE.match(line)
    if m:
        try:
            ts = datetime(
                year,
                MONTHS[m["mon"]],
                int(m["day"]),
                *map(int, m["time"].split(":")),
                tzinfo=_UTC,
            )
        except (KeyError, ValueError):
            return None
    else:
        m = ISO_RE.match(line)
        if not m:
            return None
        try:
            ts = datetime.fromisoformat(m["ts"].replace("Z", "+00:00"))
        except ValueError:
            return None
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=_UTC)
    ev = _blank(source, line)
    ev.update(
        ts=iso(ts),
        host=m["host"],
        program=m["prog"],
        pid=int(m["pid"]) if m["pid"] else None,
        message=m["msg"],
    )
    _classify(ev, m["prog"], m["msg"])
    return ev


def decode_path(path: str) -> str:
    """URL-decode up to three times so double-encoded payloads are still visible."""
    for _ in range(3):
        decoded = unquote_plus(path)
        if decoded == path:
            break
        path = decoded
    return path


def parse_nginx_line(line: str, source: str = "nginx", year: int = 0) -> dict | None:
    """Parse an nginx/Apache combined-format access log line."""
    line = line.rstrip("\n")
    m = NGINX_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    parts = m["req"].split(" ")
    method = parts[0] if parts and parts[0] else None
    if len(parts) >= 3 and parts[-1].startswith("HTTP/"):
        path = " ".join(parts[1:-1])
    else:
        path = " ".join(parts[1:])
    status = int(m["status"])
    ev = _blank(source, line)
    ev.update(
        ts=iso(ts),
        src_ip=m["ip"],
        user=None if m["user"] == "-" else m["user"],
        action="http_request",
        outcome="failure" if status >= 400 else "success",
        http_method=method,
        http_path=decode_path(path) if path else None,
        http_status=status,
        http_bytes=None if m["bytes"] == "-" else int(m["bytes"]),
        user_agent=m["ua"] or None,
    )
    return ev


PARSERS = {
    "auth": parse_syslog_line,
    "syslog": parse_syslog_line,
    "nginx": parse_nginx_line,
}
