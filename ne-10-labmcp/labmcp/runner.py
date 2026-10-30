"""The only code that talks to the lab. It cannot run a command that is not read-only:
vtysh commands must match an allow-list of `show` forms, and everything is executed with
an argument list (never through a shell)."""

from __future__ import annotations

import re
import subprocess
from typing import Protocol

CONTAINER_PREFIX = "clab-bgp-"
MAX_OUTPUT = 20000

# Every vtysh command the server may ever send. Nothing else, including `configure`, passes.
VTYSH_ALLOWED = [
    re.compile(p)
    for p in (
        r"show ip route",
        r"show ip route \d{1,3}(\.\d{1,3}){3}/\d{1,2}",
        r"show bgp ipv4 unicast",
        r"show bgp ipv4 unicast \d{1,3}(\.\d{1,3}){3}/\d{1,2}( json)?",
        r"show bgp summary( json)?",
        r"show interface brief",
        r"show running-config",
    )
]


class CommandRefused(RuntimeError):
    pass


class Runner(Protocol):
    def vtysh(self, device: str, command: str) -> str: ...
    def ping(self, device: str, target: str) -> str: ...
    def is_running(self, device: str) -> bool: ...


def check_vtysh(command: str) -> str:
    if not any(p.fullmatch(command) for p in VTYSH_ALLOWED):
        raise CommandRefused(
            f"vtysh command not on the read-only allow-list: {command!r}"
        )
    return command


def _clip(text: str) -> str:
    return (
        text if len(text) <= MAX_OUTPUT else text[:MAX_OUTPUT] + "\n[output truncated]"
    )


class DockerRunner:
    def _exec(self, device: str, argv: list[str], timeout: int) -> str:
        r = subprocess.run(
            ["docker", "exec", CONTAINER_PREFIX + device, *argv],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if r.returncode != 0 and not r.stdout:
            raise RuntimeError(r.stderr.strip() or f"exit status {r.returncode}")
        return _clip(r.stdout + (r.stderr if r.returncode else ""))

    def vtysh(self, device: str, command: str) -> str:
        return self._exec(device, ["vtysh", "-c", check_vtysh(command)], 20)

    def ping(self, device: str, target: str) -> str:
        # fixed count and timeout; the target was validated as a bare IPv4 address
        return self._exec(device, ["ping", "-n", "-c", "3", "-W", "1", target], 15)

    def is_running(self, device: str) -> bool:
        r = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{.State.Running}}",
                CONTAINER_PREFIX + device,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return r.stdout.strip() == "true"
