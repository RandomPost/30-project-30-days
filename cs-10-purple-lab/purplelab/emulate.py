"""Lab-only safety guard and emulation runner CLI for purplelab."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Sequence

from .techniques import Context, REGISTRY, Technique, make_http, make_ssh_factory


class SafetyError(Exception):
    """Raised when the lab safety guard refuses to run."""


ResolveFn = Callable[[str], list[str]]


def default_resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        raise SafetyError(f"cannot resolve host {host!r}: {exc}") from exc
    return [info[4][0] for info in infos]


def _is_private_or_loopback(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    return bool(ip.is_loopback or ip.is_private)


def check_safety(
    hosts: Iterable[str],
    allowed: Iterable[str],
    resolve: ResolveFn | None = None,
) -> None:
    """Raise SafetyError unless the lab is explicitly enabled and every host
    is allowlisted and resolves to a private/loopback address."""
    if resolve is None:
        resolve = default_resolve
    if os.environ.get("PURPLELAB_LAB") != "1":
        raise SafetyError("PURPLELAB_LAB=1 is required to run emulation")
    allowed_set = set(allowed)
    for host in hosts:
        if host not in allowed_set:
            raise SafetyError(f"host {host!r} is not in the allowlist")
        addrs = resolve(host)
        if not addrs:
            raise SafetyError(f"host {host!r} did not resolve to any address")
        for addr in addrs:
            if not _is_private_or_loopback(addr):
                raise SafetyError(f"host {host!r} resolved to public address {addr}")


def default_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(
    ctx: Context,
    techniques: Sequence[Technique],
    log_path: str | Path,
    pause: float,
    run_id: str,
) -> list[dict]:
    """Run each technique, appending one JSON record per line to log_path.

    A technique raising never stops the run: it is recorded with ok=false
    and the error in detail.
    """
    records: list[dict] = []
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for tech in techniques:
            start = _now_iso()
            try:
                detail = tech.run(ctx)
                ok = True
            except Exception as exc:  # noqa: BLE001 - isolate technique failures
                detail = f"{type(exc).__name__}: {exc}"
                ok = False
            end = _now_iso()
            target = ctx.web_base if tech.channel == "web" else ctx.ssh_host
            record = {
                "run_id": run_id,
                "technique_id": tech.id,
                "name": tech.name,
                "tactic": tech.tactic,
                "start": start,
                "end": end,
                "ok": ok,
                "target": target,
                "detail": detail,
            }
            fh.write(json.dumps(record) + "\n")
            fh.flush()
            records.append(record)
            if pause:
                ctx.sleep(pause)
    return records


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="purplelab emulate")
    parser.add_argument("--web")
    parser.add_argument("--ssh")
    parser.add_argument("--user")
    parser.add_argument("--password")
    parser.add_argument("--root-password")
    parser.add_argument("--log")
    parser.add_argument("--only")
    parser.add_argument("--allow")
    parser.add_argument("--pause", type=float, default=1.5)
    parser.add_argument("--run-id")
    parser.add_argument("--list", action="store_true")
    return parser


def main(argv: Sequence[str]) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.list:
        for tech in REGISTRY.values():
            print(f"{tech.id}\t{tech.name}\t{tech.tactic}\t{tech.channel}")
        return 0

    required = {
        "web": args.web,
        "ssh": args.ssh,
        "user": args.user,
        "password": args.password,
        "root_password": args.root_password,
        "log": args.log,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        flags = ", ".join("--" + name.replace("_", "-") for name in missing)
        parser.error(f"missing required arguments: {flags}")

    web_host = urllib.parse.urlparse(args.web).hostname
    ssh_host, _, ssh_port_s = args.ssh.partition(":")
    ssh_port = int(ssh_port_s) if ssh_port_s else 22

    allow_env = os.environ.get("PURPLELAB_ALLOWED_HOSTS", "")
    allow_arg = args.allow if args.allow is not None else allow_env
    allowed = {h for h in allow_arg.split(",") if h}

    try:
        check_safety({web_host, ssh_host}, allowed)
    except SafetyError as exc:
        print(f"refusing to run: {exc}", file=sys.stderr)
        return 1

    only = {t for t in (args.only or "").split(",") if t}
    selected = [t for t in REGISTRY.values() if not only or t.id in only]

    ctx = Context(
        web_base=args.web,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=args.user,
        ssh_password=args.password,
        root_password=args.root_password,
        ssh=make_ssh_factory(ssh_host, ssh_port),
        http=make_http(),
        sleep=time.sleep,
    )

    run_id = args.run_id or default_run_id()
    records = run(ctx, selected, args.log, args.pause, run_id)
    ok_count = sum(1 for r in records if r["ok"])
    print(f"ran {len(records)} techniques, {ok_count} ok, log={args.log}")
    return 0
