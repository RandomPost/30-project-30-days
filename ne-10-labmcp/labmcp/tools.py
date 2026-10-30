"""The six tools as plain functions over a Runner, so tests can use a fake lab."""

from __future__ import annotations

import json
import os
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import drift, policy
from .runner import Runner

HERE = Path(__file__).resolve().parent.parent
DEVICES = ("cust", "isp1", "isp2", "rs", "content", "rogue")


@dataclass
class Config:
    runner: Runner
    devices: tuple[str, ...] = DEVICES
    lab_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("LABMCP_LAB_DIR", HERE.parent / "ne-09-bgplab")
        )
    )
    design: str = field(default_factory=lambda: os.environ.get("LABMCP_DESIGN", "a"))
    batfish_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("LABMCP_BATFISH_DIR", HERE.parent / "ne-08-batfish")
        )
    )
    batfish_host: str = field(
        default_factory=lambda: os.environ.get("BATFISH_HOST", "localhost")
    )

    def checks(self) -> tuple[str, ...]:
        """baseline plus one check per proposed change shipped with NE-08."""
        changes = sorted(p.stem for p in (self.batfish_dir / "changes").glob("*.patch"))
        return ("baseline", *changes)


def list_devices(cfg: Config) -> dict:
    return {d: {"running": cfg.runner.is_running(d)} for d in cfg.devices}


def show_routes(cfg: Config, device: str, prefix: str | None = None) -> str:
    dev = policy.device(device, cfg.devices)
    if prefix is None:
        return cfg.runner.vtysh(dev, "show bgp ipv4 unicast")
    p = policy.prefix(prefix)
    return (
        "== BGP paths (best path is marked, bestpath.selectionReason says why)\n"
        + cfg.runner.vtysh(dev, f"show bgp ipv4 unicast {p} json")
        + "\n== RIB\n"
        + cfg.runner.vtysh(dev, f"show ip route {p}")
    )


def show_interfaces(cfg: Config, device: str) -> str:
    dev = policy.device(device, cfg.devices)
    return (
        cfg.runner.vtysh(dev, "show interface brief")
        + "\n"
        + cfg.runner.vtysh(dev, "show bgp summary")
    )


def ping_from(cfg: Config, device: str, target: str) -> str:
    dev = policy.device(device, cfg.devices)
    return cfg.runner.ping(dev, policy.target(target))


def get_config_drift(cfg: Config, device: str) -> dict:
    dev = policy.device(device, cfg.devices)
    path = cfg.lab_dir / "designs" / cfg.design / f"{dev}.conf"
    if not path.is_file():
        raise policy.InvalidInput(f"no intended config for {dev} (design {cfg.design})")
    lines = drift.diff(path.read_text(), cfg.runner.vtysh(dev, "show running-config"))
    return {
        "device": dev,
        "intended": str(path.relative_to(cfg.lab_dir.parent)),
        "drift": lines,
        "in_sync": not lines,
    }


def run_batfish_check(cfg: Config, name: str) -> dict:
    """Run one NE-08 pre-change check. `baseline` checks the current network; any other name
    is a proposed change from ne-08-batfish/changes applied to a scratch copy."""
    check = policy.check_name(name, cfg.checks())
    try:
        socket.create_connection((cfg.batfish_host, 9996), timeout=3).close()
    except OSError:
        return {
            "check": check,
            "ran": False,
            "error": f"Batfish not reachable at {cfg.batfish_host}:9996 (start it with `make up` in ne-08-batfish)",
        }
    if check == "baseline":
        argv = ["python3", "-m", "pytest", "-q", "tests/test_policies.py"]
    else:
        argv = ["sh", "scripts/try-change.sh", f"changes/{check}.patch"]
    r = subprocess.run(
        argv, cwd=cfg.batfish_dir, capture_output=True, text=True, timeout=300
    )
    return {
        "check": check,
        "ran": True,
        "passed": r.returncode == 0,
        "output": (r.stdout + r.stderr)[-4000:],
    }


def dumps(obj: object) -> str:
    return json.dumps(obj, indent=2)
