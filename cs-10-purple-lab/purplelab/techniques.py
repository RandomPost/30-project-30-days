"""Bounded, benign ATT&CK technique emulation for the purple-team lab.

Every technique routes its network/command actions through the injected
`Context` (``ctx.http`` / ``ctx.ssh`` / ``ctx.sleep``) so tests can fake them.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Protocol


class SshAuthError(Exception):
    """Raised by an SshFactory when authentication is rejected.

    This is the *expected* outcome for brute-force/spray techniques and must
    not be treated as a failure by the runner.
    """


class SshSession(Protocol):
    def exec(self, cmd: str) -> tuple[int, str]: ...

    def close(self) -> None: ...


SshFactory = Callable[[str, str], SshSession]
HttpFn = Callable[..., int]


@dataclass
class Context:
    web_base: str
    ssh_host: str
    ssh_port: int
    ssh_user: str
    ssh_password: str
    root_password: str
    ssh: SshFactory
    http: HttpFn
    sleep: Callable[[float], None]


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str
    channel: str
    description: str
    run: Callable[["Context"], str]


def _run_ssh_commands(ctx: Context, cmds: list[str]) -> str:
    session = ctx.ssh(ctx.ssh_user, ctx.ssh_password)
    try:
        results = []
        for cmd in cmds:
            rc, _out = session.exec(cmd)
            results.append(f"{cmd!r}->{rc}")
        return "; ".join(results)
    finally:
        session.close()


SCAN_PATHS = [
    "/",
    "/admin",
    "/wp-login.php",
    "/.env",
    "/phpmyadmin/",
    "/.git/config",
    "/server-status",
    "/robots.txt",
]
SCAN_USER_AGENTS = ["Nikto/2.5.0", "sqlmap/1.7"]


def t1595_002(ctx: Context) -> str:
    statuses = []
    for i, path in enumerate(SCAN_PATHS):
        ua = SCAN_USER_AGENTS[i % len(SCAN_USER_AGENTS)]
        statuses.append(
            ctx.http("GET", ctx.web_base + path, headers={"User-Agent": ua})
        )
    return f"{len(SCAN_PATHS)} scanner requests, statuses={statuses}"


WORDLIST_PATHS = [f"/xq{i:03d}-notfound" for i in range(40)]


def t1595_003(ctx: Context) -> str:
    for path in WORDLIST_PATHS:
        ctx.http("GET", ctx.web_base + path)
    return f"{len(WORDLIST_PATHS)} wordlist requests for distinct nonexistent paths"


EXPLOIT_PAYLOADS = {
    "sqli": "' OR 1=1--",
    "traversal": "../../etc/passwd",
    "jndi": "${jndi:ldap://x/a}",
}


def t1190(ctx: Context) -> str:
    statuses = {}
    for name, payload in EXPLOIT_PAYLOADS.items():
        url = f"{ctx.web_base}/?q={urllib.parse.quote(payload, safe='')}"
        statuses[name] = ctx.http("GET", url)
    return f"exploit probes statuses={statuses}"


WRONG_PASSWORDS = [f"wrongpass{i}" for i in range(8)]


def t1110_001(ctx: Context) -> str:
    attempts = 0
    for pw in WRONG_PASSWORDS:
        attempts += 1
        try:
            session = ctx.ssh(ctx.ssh_user, pw)
            session.close()
        except SshAuthError:
            continue
    return f"{attempts} password guesses against {ctx.ssh_user}"


SPRAY_USERNAMES = [
    "bob",
    "alice",
    "oracle",
    "admin2",
    "deploy",
    "test1",
    "backup",
    "svc-sql",
]
SPRAY_PASSWORD = "Spring2024!"


def t1110_003(ctx: Context) -> str:
    attempts = 0
    for user in SPRAY_USERNAMES:
        attempts += 1
        try:
            session = ctx.ssh(user, SPRAY_PASSWORD)
            session.close()
        except SshAuthError:
            continue
    return f"{attempts} spray attempts across {len(SPRAY_USERNAMES)} usernames"


def t1078(ctx: Context) -> str:
    session = ctx.ssh("root", ctx.root_password)
    try:
        rc, _out = session.exec("true")
    finally:
        session.close()
    return f"root login ok, 'true' rc={rc}"


def t1082(ctx: Context) -> str:
    return _run_ssh_commands(ctx, ["uname -a", "cat /etc/os-release", "hostname"])


def t1033(ctx: Context) -> str:
    return _run_ssh_commands(ctx, ["whoami", "id", "w"])


def t1083(ctx: Context) -> str:
    return _run_ssh_commands(ctx, ["ls -la /etc", "find /home -maxdepth 2"])


def t1057(ctx: Context) -> str:
    return _run_ssh_commands(ctx, ["ps aux"])


def t1016(ctx: Context) -> str:
    return _run_ssh_commands(ctx, ["ip addr", "ip route", "cat /etc/resolv.conf"])


def t1087_001(ctx: Context) -> str:
    return _run_ssh_commands(ctx, ["cat /etc/passwd", "getent passwd"])


def t1036_005(ctx: Context) -> str:
    return _run_ssh_commands(
        ctx,
        ["cp /bin/sleep /tmp/svchost", "/tmp/svchost 1", "rm -f /tmp/svchost"],
    )


def t1053_003(ctx: Context) -> str:
    return _run_ssh_commands(
        ctx,
        [
            '(crontab -l 2>/dev/null; echo "* * * * * /bin/true # purplelab") | crontab -',
            "crontab -l | grep -v purplelab | crontab -",
        ],
    )


def _technique(
    id_: str,
    name: str,
    tactic: str,
    channel: str,
    description: str,
    run: Callable[[Context], str],
) -> Technique:
    return Technique(
        id=id_,
        name=name,
        tactic=tactic,
        channel=channel,
        description=description,
        run=run,
    )


REGISTRY: dict[str, Technique] = {
    t.id: t
    for t in [
        _technique(
            "T1595.002",
            "Active Scanning: Vulnerability Scanning",
            "reconnaissance",
            "web",
            "~8 requests with scanner User-Agents to common paths",
            t1595_002,
        ),
        _technique(
            "T1595.003",
            "Active Scanning: Wordlist Scanning",
            "reconnaissance",
            "web",
            "40 requests for distinct nonexistent paths (404 flood)",
            t1595_003,
        ),
        _technique(
            "T1190",
            "Exploit Public-Facing Application",
            "initial-access",
            "web",
            "SQLi, path traversal, and JNDI strings in query strings",
            t1190,
        ),
        _technique(
            "T1110.001",
            "Brute Force: Password Guessing",
            "credential-access",
            "ssh",
            "8 wrong passwords for the lab user over SSH",
            t1110_001,
        ),
        _technique(
            "T1110.003",
            "Brute Force: Password Spraying",
            "credential-access",
            "ssh",
            "one wrong password against 8 non-existent usernames over SSH",
            t1110_003,
        ),
        _technique(
            "T1078",
            "Valid Accounts",
            "initial-access",
            "ssh",
            "successful SSH login as root with the lab-only password",
            t1078,
        ),
        _technique(
            "T1082",
            "System Information Discovery",
            "discovery",
            "ssh",
            "uname -a, cat /etc/os-release, hostname",
            t1082,
        ),
        _technique(
            "T1033",
            "System Owner/User Discovery",
            "discovery",
            "ssh",
            "whoami, id, w",
            t1033,
        ),
        _technique(
            "T1083",
            "File and Directory Discovery",
            "discovery",
            "ssh",
            "ls -la /etc, find /home -maxdepth 2",
            t1083,
        ),
        _technique(
            "T1057",
            "Process Discovery",
            "discovery",
            "ssh",
            "ps aux",
            t1057,
        ),
        _technique(
            "T1016",
            "System Network Configuration Discovery",
            "discovery",
            "ssh",
            "ip addr, ip route, cat /etc/resolv.conf",
            t1016,
        ),
        _technique(
            "T1087.001",
            "Account Discovery: Local Account",
            "discovery",
            "ssh",
            "cat /etc/passwd, getent passwd",
            t1087_001,
        ),
        _technique(
            "T1036.005",
            "Masquerading: Match Legitimate Name or Location",
            "defense-evasion",
            "ssh",
            "copy /bin/sleep to /tmp/svchost, run it, remove it",
            t1036_005,
        ),
        _technique(
            "T1053.003",
            "Scheduled Task/Job: Cron",
            "persistence",
            "ssh",
            "install a harmless crontab entry, then remove it",
            t1053_003,
        ),
    ]
}


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def make_http() -> HttpFn:
    """Real HttpFn: urllib based, never follows redirects, 3s timeout."""

    opener = urllib.request.build_opener(_NoRedirectHandler)

    def http(
        method: str, url: str, headers: dict | None = None, data: bytes | None = None
    ) -> int:
        req = urllib.request.Request(
            url, data=data, headers=headers or {}, method=method
        )
        try:
            resp = opener.open(req, timeout=3)
            return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return 0

    return http


def make_ssh_factory(host: str, port: int = 22) -> SshFactory:
    """Real SshFactory using paramiko (imported lazily)."""

    def factory(user: str, password: str) -> SshSession:
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host,
                port=port,
                username=user,
                password=password,
                timeout=3,
                banner_timeout=3,
                auth_timeout=3,
                look_for_keys=False,
                allow_agent=False,
            )
        except paramiko.AuthenticationException as exc:
            client.close()
            raise SshAuthError(str(exc)) from exc

        class _ParamikoSession:
            def exec(self, cmd: str) -> tuple[int, str]:
                _stdin, stdout, stderr = client.exec_command(cmd)
                rc = stdout.channel.recv_exit_status()
                out = stdout.read().decode("utf-8", "replace") + stderr.read().decode(
                    "utf-8", "replace"
                )
                return rc, out

            def close(self) -> None:
                client.close()

        return _ParamikoSession()

    return factory
