"""Runtime settings, from CLI flags with environment-variable defaults."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Config:
    host: str = "0.0.0.0"  # inside a container; the container publishes the port
    port: int = 2222
    host_key: str = "data/ssh_host_key"  # created on first start if missing
    log_path: str | None = "data/sshpot.jsonl"
    log_stdout: bool = True
    log_max_bytes: int = 50 * 1024 * 1024
    hostname: str = "srv04"
    # A login succeeds when the pair is listed, or on the Nth password attempt from
    # the same source IP (counted across connections; 0 = never by count).
    accept_after: int = 3
    accepted_credentials: set[tuple[str, str]] = field(default_factory=set)
    max_connections: int = 100
    login_timeout: float = 20.0
    idle_timeout: float = 60.0
    session_timeout: float = 300.0
    max_commands: int = 200
    max_auth_attempts: int = 6
    # Don't log connections from loopback (container health checks).
    quiet_loopback: bool = False
    banner: str = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
