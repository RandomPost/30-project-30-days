"""Command line: serve the honeypot, analyze its logs, make sample data."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from importlib import resources
from pathlib import Path

from .analytics import analyze, read_events, render_markdown, render_text
from .config import Config
from .geoip import GeoDB
from .sample import generate


def _env(name: str, default):
    return type(default)(os.environ.get(f"SSHPOT_{name}", default))


def _creds(items: list[str]) -> set[tuple[str, str]]:
    out = set()
    for item in items:
        user, sep, pw = item.partition(":")
        if not sep:
            raise SystemExit(f"--accept expects user:password, got {item!r}")
        out.add((user, pw))
    return out


def cmd_serve(a) -> int:
    from .server import serve_forever

    cfg = Config(
        host=a.host,
        port=a.port,
        host_key=a.host_key,
        log_path=a.log or None,
        hostname=a.hostname,
        accept_after=a.accept_after,
        accepted_credentials=_creds(a.accept or []),
        max_connections=a.max_connections,
        quiet_loopback=a.quiet_loopback,
    )
    try:
        asyncio.run(serve_forever(cfg))
    except KeyboardInterrupt:
        pass
    return 0


def _load_geo(path: str | None) -> GeoDB:
    if path:
        return GeoDB.load(path)
    sample = resources.files("sshpot").joinpath("data/geoip-sample.csv")
    with resources.as_file(sample) as p:
        return GeoDB.load(p)


def cmd_analyze(a) -> int:
    with open(a.log, encoding="utf-8", errors="replace") as fh:
        events, bad = read_events(fh)
    report = analyze(events, _load_geo(a.geoip), a.top, bad)
    if a.json:
        print(json.dumps(report, indent=2))
    elif a.md:
        print(render_markdown(report), end="")
    else:
        print(render_text(report), end="")
    return 0


def cmd_healthcheck(a) -> int:
    """Exit 0 if something answers with an SSH banner on the port."""
    import socket

    try:
        with socket.create_connection(("127.0.0.1", a.port), timeout=3) as s:
            return 0 if s.recv(4) == b"SSH-" else 1
    except OSError:
        return 1


def cmd_sample(a) -> int:
    n = generate(a.out, a.seed, a.sessions)
    print(f"wrote {n} events to {a.out}")
    return 0


def cmd_simulate(a) -> int:
    from .simulate import run

    stats = asyncio.run(run(a.host, a.port))
    print(json.dumps(stats))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sshpot", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("serve", help="run the honeypot")
    sp.add_argument("--host", default=_env("HOST", "0.0.0.0"))
    sp.add_argument("--port", type=int, default=_env("PORT", 2222))
    sp.add_argument("--host-key", default=_env("HOST_KEY", "data/ssh_host_key"))
    sp.add_argument(
        "--log",
        default=_env("LOG", "data/sshpot.jsonl"),
        help="JSONL file ('' for stdout only)",
    )
    sp.add_argument("--hostname", default=_env("HOSTNAME_SHOWN", "srv04"))
    sp.add_argument(
        "--accept-after",
        type=int,
        default=_env("ACCEPT_AFTER", 3),
        help="let a source IP in on its Nth password try (0 = never)",
    )
    sp.add_argument(
        "--accept",
        action="append",
        metavar="USER:PASS",
        help="always accept this pair (repeatable)",
    )
    sp.add_argument("--max-connections", type=int, default=_env("MAX_CONNECTIONS", 100))
    sp.add_argument(
        "--quiet-loopback",
        action="store_true",
        default=_env("QUIET_LOOPBACK", "0") == "1",
        help="do not log connections from 127.0.0.1 (health checks)",
    )
    sp.set_defaults(fn=cmd_serve)

    sp = sub.add_parser(
        "healthcheck", help="check the local honeypot answers (for Docker)"
    )
    sp.add_argument("--port", type=int, default=_env("PORT", 2222))
    sp.set_defaults(fn=cmd_healthcheck)

    sp = sub.add_parser("analyze", help="summarize a JSONL log")
    sp.add_argument("log")
    sp.add_argument(
        "--geoip", help="CSV of start_ip,end_ip,country (default: bundled demo data)"
    )
    sp.add_argument("--top", type=int, default=10)
    fmt = sp.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true")
    fmt.add_argument("--md", action="store_true", help="Markdown report")
    sp.set_defaults(fn=cmd_analyze)

    sp = sub.add_parser("sample", help="write a synthetic log")
    sp.add_argument("out")
    sp.add_argument("--seed", type=int, default=1)
    sp.add_argument("--sessions", type=int, default=60)
    sp.set_defaults(fn=cmd_sample)

    sp = sub.add_parser("simulate", help="run a scripted attacker against a honeypot")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=2222)
    sp.set_defaults(fn=cmd_simulate)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
