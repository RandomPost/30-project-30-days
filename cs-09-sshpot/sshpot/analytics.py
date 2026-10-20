"""Summarize honeypot JSON-lines logs: credentials, countries, clients, commands."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Iterable

from .geoip import GeoDB, country_name


def read_events(lines: Iterable[str]) -> tuple[list[dict], int]:
    """Parse JSON lines, skipping blanks. Returns (events, number of bad lines)."""
    events, bad = [], 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if isinstance(obj, dict) and isinstance(obj.get("event"), str):
            events.append(obj)
        else:
            bad += 1
    return events, bad


def _top(counter: Counter, n: int, key: str = "value") -> list[dict]:
    return [{key: k, "count": c} for k, c in counter.most_common(n)]


def _cmd_name(line: str) -> str:
    parts = line.split()
    while parts and parts[0] in ("sudo", "nohup", "time", "env"):
        parts = parts[1:]
    return parts[0] if parts else ""


def analyze(
    events: list[dict], geo: GeoDB | None = None, top: int = 10, bad_lines: int = 0
) -> dict:
    by_type: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        by_type[e["event"]].append(e)
    stamps = sorted(e["ts"] for e in events if isinstance(e.get("ts"), str))

    auths = by_type["auth"]
    users = Counter(str(a.get("username", "")) for a in auths)
    passwords = Counter(str(a.get("password", "")) for a in auths)
    pairs = Counter(f"{a.get('username', '')}:{a.get('password', '')}" for a in auths)

    connects = by_type["connect"]
    ip_conns = Counter(str(c.get("src_ip", "?")) for c in connects)
    country_conns: Counter = Counter()
    country_ips: dict[str, set] = defaultdict(set)
    for ip, n in ip_conns.items():
        code = geo.lookup(ip) if geo else "??"
        country_conns[code] += n
        country_ips[code].add(ip)
    countries = [
        {
            "country": code,
            "name": country_name(code),
            "connections": n,
            "unique_ips": len(country_ips[code]),
        }
        for code, n in country_conns.most_common(top)
    ]

    clients = Counter(str(c.get("client_version", "")) for c in by_type["client"])
    client_ids = Counter(str(c.get("client_id", "")) for c in by_type["client"])
    pubkeys = Counter(str(k.get("fingerprint", "")) for k in by_type["auth_pubkey"])

    # one command sequence per shell/exec channel (a connection can open several)
    per_session: dict[tuple, list[str]] = defaultdict(list)
    for c in by_type["command"]:
        key = (str(c.get("session", "?")), c.get("channel"))
        per_session[key].append(str(c.get("input", "")))
    commands = Counter(c for seq in per_session.values() for c in seq)
    names = Counter(_cmd_name(c) for c in commands.elements() if _cmd_name(c))
    sequences = Counter(tuple(seq) for seq in per_session.values() if seq)
    bigrams: Counter = Counter()
    for seq in per_session.values():
        bn = [_cmd_name(c) for c in seq]
        bigrams.update(f"{a} -> {b}" for a, b in zip(bn, bn[1:]))

    urls: Counter = Counter()
    ips: Counter = Counter()
    for c in by_type["command"]:
        urls.update(c.get("urls") or [])
        ips.update(c.get("ips") or [])

    timeline = Counter(
        str(c["ts"])[:13] + ":00Z" for c in connects if isinstance(c.get("ts"), str)
    )
    logged_in = {a.get("session") for a in auths if a.get("success")}

    return {
        "summary": {
            "events": len(events),
            "bad_lines": bad_lines,
            "first_ts": stamps[0] if stamps else None,
            "last_ts": stamps[-1] if stamps else None,
            "connections": len(connects),
            "unique_ips": len(ip_conns),
            "auth_attempts": len(auths),
            "successful_logins": len(logged_in),
            "pubkey_attempts": len(by_type["auth_pubkey"]),
            "sessions_with_commands": len(per_session),
            "commands": sum(commands.values()),
            "forward_attempts": len(by_type["forward_attempt"]),
        },
        "top_usernames": _top(users, top),
        "top_passwords": _top(passwords, top),
        "top_credential_pairs": _top(pairs, top),
        "top_ips": _top(ip_conns, top, "ip"),
        "countries": countries,
        "clients": _top(clients, top),
        "client_ids": _top(client_ids, top),
        "pubkey_fingerprints": _top(pubkeys, top),
        "top_commands": _top(commands, top),
        "top_command_names": _top(names, top),
        "command_bigrams": _top(bigrams, top),
        "command_sequences": [
            {"commands": list(seq), "sessions": n}
            for seq, n in sequences.most_common(top)
        ],
        "indicator_urls": _top(urls, top),
        "indicator_ips": _top(ips, top),
        "timeline": [
            {"hour": h, "connections": n} for h, n in sorted(timeline.items())
        ],
    }


def _table(title: str, rows: list[dict], cols: list[tuple[str, str]]) -> list[str]:
    out = [f"\n{title}"]
    if not rows:
        return out + ["  (none)"]
    for r in rows:
        out.append(
            "  "
            + "  ".join(
                f"{str(r[k])[:70]:<{w}}" if i == 0 else str(r[k])
                for i, (k, w) in enumerate(cols)
            ).rstrip()
        )
    return out


def render_text(rep: dict) -> str:
    s = rep["summary"]
    lines = [
        "Honeypot report",
        f"  window        {s['first_ts']} .. {s['last_ts']}",
        f"  connections   {s['connections']} from {s['unique_ips']} IPs",
        f"  auth attempts {s['auth_attempts']} ({s['successful_logins']} sessions got in)",
        f"  commands      {s['commands']} in {s['sessions_with_commands']} sessions",
        f"  other         {s['pubkey_attempts']} pubkey tries, {s['forward_attempts']} forward attempts, {s['bad_lines']} unreadable lines",
    ]
    lines += _table(
        "Top usernames", rep["top_usernames"], [("value", 30), ("count", 0)]
    )
    lines += _table(
        "Top passwords", rep["top_passwords"], [("value", 30), ("count", 0)]
    )
    lines += _table(
        "Top credential pairs",
        rep["top_credential_pairs"],
        [("value", 40), ("count", 0)],
    )
    lines += _table(
        "Source countries",
        rep["countries"],
        [("name", 22), ("connections", 8), ("unique_ips", 0)],
    )
    lines += _table("Top source IPs", rep["top_ips"], [("ip", 40), ("count", 0)])
    lines += _table("Client versions", rep["clients"], [("value", 40), ("count", 0)])
    lines += _table(
        "Public key fingerprints offered",
        rep["pubkey_fingerprints"],
        [("value", 60), ("count", 0)],
    )
    lines += _table("Top commands", rep["top_commands"], [("value", 50), ("count", 0)])
    lines += _table(
        "Command transitions", rep["command_bigrams"], [("value", 40), ("count", 0)]
    )
    lines.append("\nCommand sequences (one per shell or exec session)")
    if not rep["command_sequences"]:
        lines.append("  (none)")
    for seq in rep["command_sequences"]:
        lines.append(
            f"  x{seq['sessions']}  " + "  ;  ".join(c[:60] for c in seq["commands"])
        )
    lines += _table(
        "Download URLs in commands",
        rep["indicator_urls"],
        [("value", 70), ("count", 0)],
    )
    lines += _table(
        "Connections per hour", rep["timeline"], [("hour", 22), ("connections", 0)]
    )
    return "\n".join(lines) + "\n"


def _md_cell(text) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _md_code(text) -> str:
    """Log values are attacker-controlled: show them as inert code spans."""
    return "`" + _md_cell(text).replace("`", "'") + "`"


def render_markdown(rep: dict) -> str:
    s = rep["summary"]
    out = [
        "# Honeypot report",
        "",
        f"{s['connections']} connections from {s['unique_ips']} IPs "
        f"between {s['first_ts']} and {s['last_ts']}.",
        "",
        "| metric | value |",
        "|---|---|",
    ]
    out += [f"| {k.replace('_', ' ')} | {_md_cell(v)} |" for k, v in s.items()]

    def section(title: str, rows: list[dict], cols: list[tuple[str, str]]) -> None:
        """cols: (header, key); the first column holds the untrusted value."""
        out.extend(["", f"## {title}", ""])
        if not rows:
            out.append("None.")
            return
        out.append("| " + " | ".join(h for h, _ in cols) + " |")
        out.append("|" + "---|" * len(cols))
        for r in rows:
            cells = [
                _md_code(r[k]) if i == 0 else _md_cell(r[k])
                for i, (_h, k) in enumerate(cols)
            ]
            out.append("| " + " | ".join(cells) + " |")

    section(
        "Top usernames",
        rep["top_usernames"],
        [("username", "value"), ("count", "count")],
    )
    section(
        "Top passwords",
        rep["top_passwords"],
        [("password", "value"), ("count", "count")],
    )
    section(
        "Source countries",
        rep["countries"],
        [
            ("country", "name"),
            ("connections", "connections"),
            ("unique IPs", "unique_ips"),
        ],
    )
    section(
        "Top commands", rep["top_commands"], [("command", "value"), ("count", "count")]
    )
    out.extend(["", "## Command sequences", ""])
    for seq in rep["command_sequences"]:
        out.append(
            f"- x{seq['sessions']}: "
            + " ; ".join(_md_code(c[:80]) for c in seq["commands"])
        )
    if not rep["command_sequences"]:
        out.append("None.")
    section(
        "Download URLs in commands",
        rep["indicator_urls"],
        [("url", "value"), ("count", "count")],
    )
    return "\n".join(out) + "\n"
