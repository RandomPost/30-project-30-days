"""The honeypot: an asyncssh server that logs everything and runs nothing.

It speaks real SSH (so scanners and bots engage), records every credential, public
key, client fingerprint, shell/exec command, port-forward attempt and session length
as JSON lines, and answers commands from `fakeshell` with canned text. There is no
shell, no subprocess, no filesystem access beyond the log and host key, and no
outbound connection.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
from dataclasses import dataclass, field

import asyncssh

from .config import Config
from .fakeshell import FakeShell
from .logs import JsonlLogger

MOTD = (
    "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n"
    " * Documentation:  https://help.ubuntu.com\n\n"
    "Last login: Mon Oct 19 21:03:11 2026 from 10.0.0.2\n"
)


@dataclass
class Context:
    cfg: Config
    log: JsonlLogger
    active: int = 0
    total: int = 0
    sessions: dict = field(default_factory=dict)
    # failed password attempts per source IP (bounded), so bots that try one
    # password per connection are still let in after `accept_after` tries
    ip_failures: dict = field(default_factory=dict)
    by_conn: dict = field(default_factory=dict)  # connection -> HoneypotServer


def ensure_host_key(path: str, log: JsonlLogger) -> asyncssh.SSHKey:
    """Load the host key, creating it on first start. Falls back to an in-memory key
    when the location is read-only so the container still comes up."""
    if os.path.exists(path):
        return asyncssh.read_private_key(path)
    key = asyncssh.generate_private_key("ssh-ed25519")
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key.export_private_key())
    except OSError as exc:
        log.log("host_key_not_persisted", path=path, error=str(exc))
    return key


def client_fingerprint(conn: asyncssh.SSHServerConnection) -> dict:
    """Banner plus negotiated algorithms, hashed. (Not HASSH: asyncssh does not expose
    the client's offered algorithm lists.)"""
    parts = [
        str(conn.get_extra_info("client_version", "")),
        str(conn.get_extra_info("recv_cipher", "")),
        str(conn.get_extra_info("recv_mac", "")),
        str(conn.get_extra_info("recv_compression", "")),
    ]
    return {
        "client_version": parts[0],
        "cipher": parts[1],
        "mac": parts[2],
        "compression": parts[3],
        "client_id": hashlib.sha256("|".join(parts).encode()).hexdigest()[:16],
    }


class HoneypotServer(asyncssh.SSHServer):
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.sid = secrets.token_hex(6)
        self.src_ip = "?"
        self.src_port = 0
        self.attempts = 0
        self.username: str | None = None
        self.commands = 0
        self.channels = 0
        self.authenticated = False
        self.refused = False
        self.started = 0.0
        self.conn: asyncssh.SSHServerConnection | None = None
        self.quiet = False

    def _log(self, event: str, **fields) -> None:
        if self.quiet:
            return
        self.ctx.log.log(
            event,
            session=self.sid,
            src_ip=self.src_ip,
            src_port=self.src_port,
            **fields,
        )

    # --- connection lifecycle ---------------------------------------------------

    def connection_made(self, conn) -> None:
        self.conn = conn
        peer = conn.get_extra_info("peername") or ("?", 0)
        self.src_ip, self.src_port = str(peer[0]), int(peer[1])
        self.started = asyncio.get_running_loop().time()
        self.quiet = self.ctx.cfg.quiet_loopback and self.src_ip in ("127.0.0.1", "::1")
        self.ctx.total += 1
        self.ctx.by_conn[conn] = self
        if self.ctx.active >= self.ctx.cfg.max_connections:
            self.refused = True
            self._log("refused", reason="max_connections")
            conn.close()
            return
        self.ctx.active += 1
        self._log("connect")

    def connection_lost(self, exc) -> None:
        self.ctx.by_conn.pop(self.conn, None)
        self.ctx.sessions.pop(self.sid, None)
        if self.refused:
            return
        self.ctx.active -= 1
        duration = asyncio.get_running_loop().time() - self.started
        self._log(
            "disconnect",
            duration=round(duration, 2),
            attempts=self.attempts,
            commands=self.commands,
            authenticated=self.authenticated,
            reason=str(exc) if exc else "closed",
        )

    # --- authentication ---------------------------------------------------------

    def begin_auth(self, username: str) -> bool:
        if "client_id" not in self.ctx.sessions.get(self.sid, {}) and self.conn:
            fp = client_fingerprint(self.conn)
            self.ctx.sessions[self.sid] = fp
            self._log("client", **fp)
        return True

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        self._log(
            "auth_pubkey",
            username=username,
            key_type=key.algorithm.decode(),
            fingerprint=key.get_fingerprint(),
            success=False,
        )
        return False  # never trust a key; the fingerprint is the useful part

    def validate_password(self, username: str, password: str) -> bool:
        cfg = self.ctx.cfg
        self.attempts += 1
        prior = self.ctx.ip_failures.get(self.src_ip, 0)
        ok = (username, password) in cfg.accepted_credentials or (
            cfg.accept_after > 0 and prior + 1 >= cfg.accept_after
        )
        self._count_failure(ok)
        self._log(
            "auth",
            method="password",
            username=username,
            password=password,
            attempt=self.attempts,
            success=ok,
        )
        if ok:
            self.username = username
            self.authenticated = True
        elif self.attempts >= cfg.max_auth_attempts and self.conn:
            self.conn.close()
        return ok

    def _count_failure(self, ok: bool) -> None:
        table = self.ctx.ip_failures
        if ok:
            table.pop(self.src_ip, None)
            return
        if self.src_ip not in table and len(table) >= 10_000:
            table.pop(next(iter(table)))  # drop the oldest entry
        table[self.src_ip] = table.get(self.src_ip, 0) + 1

    # --- everything after login -------------------------------------------------

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        self._log("forward_attempt", dest_host=dest_host, dest_port=dest_port)
        return False

    def server_requested(self, listen_host, listen_port):
        self._log("listen_attempt", listen_host=listen_host, listen_port=listen_port)
        return False

    def _run(self, shell: FakeShell, line: str, kind: str, channel: int):
        self.commands += 1
        result = shell.run(line)
        self._log(
            "command",
            channel=channel,
            kind=kind,
            input=line,
            status=result.status,
            cwd=shell.cwd,
            urls=result.urls,
            ips=result.ips,
        )
        return result

    async def _handle_process(self, process: asyncssh.SSHServerProcess) -> None:
        cfg = self.ctx.cfg
        shell = FakeShell(cfg.hostname, self.username or "root")
        exec_cmd = process.command
        self.channels += 1
        channel = self.channels
        self._log(
            "session_open",
            channel=channel,
            kind="exec" if exec_cmd is not None else "shell",
            term=process.get_terminal_type() or "",
        )
        try:
            if exec_cmd is not None:
                result = self._run(shell, exec_cmd, "exec", channel)
                process.stdout.write(result.output)
                process.exit(result.status)
                return
            process.stdout.write(MOTD)
            await self._interactive(process, shell, channel)
        except (asyncssh.Error, ConnectionError, OSError):
            pass
        finally:
            process.exit(0)

    async def _interactive(self, process, shell: FakeShell, channel: int) -> None:
        cfg = self.ctx.cfg
        loop = asyncio.get_running_loop()
        deadline = loop.time() + cfg.session_timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                self._log("session_timeout", reason="session")
                return
            process.stdout.write(shell.prompt)
            try:
                line = await asyncio.wait_for(
                    process.stdin.readline(), min(cfg.idle_timeout, remaining)
                )
            except asyncio.TimeoutError:
                self._log("session_timeout", reason="idle")
                return
            except (asyncssh.BreakReceived, asyncssh.SignalReceived):
                process.stdout.write("^C\n")
                continue
            except asyncssh.TerminalSizeChanged:
                continue
            if not line:
                return
            result = self._run(shell, line.rstrip("\r\n"), "shell", channel)
            process.stdout.write(result.output)
            if result.exit:
                process.stdout.write("logout\n")
                return
            if self.commands >= cfg.max_commands:
                self._log("session_timeout", reason="max_commands")
                return


async def start(cfg: Config):
    """Start listening. Returns (acceptor, context); call acceptor.close() to stop."""
    log = JsonlLogger(cfg.log_path, cfg.log_max_bytes, cfg.log_stdout)
    ctx = Context(cfg, log)
    key = ensure_host_key(cfg.host_key, log)

    async def handle_process(process: asyncssh.SSHServerProcess) -> None:
        handler = ctx.by_conn.get(process.channel.get_connection())
        if handler is None:
            process.exit(1)
            return
        await handler._handle_process(process)

    acceptor = await asyncssh.create_server(
        lambda: HoneypotServer(ctx),
        cfg.host,
        cfg.port,
        server_host_keys=[key],
        process_factory=handle_process,
        server_version=cfg.banner,
        login_timeout=cfg.login_timeout,
        encoding="utf-8",
        agent_forwarding=False,
        x11_forwarding=False,
        allow_scp=False,
    )
    port = acceptor.sockets[0].getsockname()[1]
    log.log("server_start", host=cfg.host, port=port, banner=cfg.banner)
    return acceptor, ctx


async def serve_forever(cfg: Config) -> None:
    acceptor, ctx = await start(cfg)
    try:
        await acceptor.wait_closed()
    finally:
        ctx.log.close()
