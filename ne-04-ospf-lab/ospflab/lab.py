"""Thin wrappers around `docker exec` for the running lab. The only module that shells out."""

from __future__ import annotations

import json
import subprocess

from .topology import container


class LabError(RuntimeError):
    """The lab is not running or a command could not be run in it."""


def run(node: str, *cmd: str, timeout: float = 30.0) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["docker", "exec", container(node), *cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise LabError("docker not found on PATH") from None
    except subprocess.TimeoutExpired:
        raise LabError(f"timed out running {' '.join(cmd)} on {node}") from None


def vtysh(router: str, command: str) -> str:
    p = run(router, "vtysh", "-c", command)
    if p.returncode != 0:
        raise LabError(
            f"{router}: vtysh -c {command!r} failed: {p.stderr.strip() or p.stdout.strip()}"
        )
    return p.stdout


def vtysh_json(router: str, command: str) -> dict:
    out = vtysh(router, command)
    try:
        return json.loads(out) if out.strip() else {}
    except json.JSONDecodeError as exc:
        raise LabError(f"{router}: {command!r} did not return JSON: {exc}") from None


def is_running(node: str) -> bool:
    try:
        p = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container(node)],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return p.returncode == 0 and p.stdout.strip() == "true"


def ping(
    host_node: str, target: str, count: int = 3, wait: int = 2
) -> tuple[bool, str]:
    p = run(
        host_node,
        "ping",
        "-c",
        str(count),
        "-W",
        str(wait),
        target,
        timeout=count * wait + 15,
    )
    return p.returncode == 0, (p.stdout + p.stderr).strip()
