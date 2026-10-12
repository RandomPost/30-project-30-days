"""Generate a synthetic auth.log so the tool can be tried without real data."""

from __future__ import annotations

import random
from datetime import datetime, timedelta

_USERS = ["root", "admin", "ubuntu", "test", "oracle", "alice"]


def generate(seed: int = 1, start: datetime | None = None) -> list[str]:
    rng = random.Random(seed)
    t = start or datetime(2026, 10, 12, 2, 0, 0)
    lines: list[str] = []

    def fail(when: datetime, user: str, ip: str) -> str:
        stamp = f"{when:%b} {when.day:2d} {when:%H:%M:%S}"
        invalid = "invalid user " if user != "alice" else ""
        return (
            f"{stamp} host sshd[{rng.randint(1000, 9999)}]: "
            f"Failed password for {invalid}{user} from {ip} port "
            f"{rng.randint(30000, 60000)} ssh2"
        )

    # burst attackers
    for ip, n in [("203.0.113.9", 40), ("198.51.100.23", 15)]:
        for i in range(n):
            lines.append(fail(t + timedelta(seconds=i * 2), rng.choice(_USERS), ip))
    # slow, below-threshold noise
    for i in range(6):
        lines.append(fail(t + timedelta(minutes=i * 10), "alice", "192.0.2.44"))
    lines.sort(key=lambda s: datetime.strptime(f"2026 {s[:15]}", "%Y %b %d %H:%M:%S"))
    return lines
