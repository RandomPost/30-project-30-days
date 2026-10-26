from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from confdrift import drift as driftlib
from confdrift.config import Config, ConfigError, credentials, load_config
from confdrift.fetch import FetchError, Fetcher, NetmikoFetcher
from confdrift.normalize import strip_chrome
from confdrift.redact import redact
from confdrift.store import GitError, Store

DEFAULT_CONFIG = Path("devices.yml")


def intended_configs(cfg: Config) -> dict[str, str]:
    """Render the netgen source of truth; keys are device names."""
    from netgen.loader import SourceError, load
    from netgen.render import render_all
    from netgen.validate import validate

    try:
        inv = load(cfg.intended)
    except (SourceError, FileNotFoundError) as exc:
        raise ConfigError(f"intended config {cfg.intended}: {exc}") from exc
    problems = validate(inv)
    if problems:
        raise ConfigError(
            f"intended config {cfg.intended} is invalid:\n  " + "\n  ".join(problems)
        )
    return {name.removesuffix(".cfg"): text for name, text in render_all(inv).items()}


def fetch_all(cfg: Config, fetcher: Fetcher) -> tuple[dict[str, str], dict[str, str]]:
    """Read every device. Returns (configs, failures) keyed by device name."""

    def one(dev):
        try:
            return dev.name, fetcher.fetch(dev), None
        except FetchError as exc:
            return dev.name, None, str(exc)

    with ThreadPoolExecutor(max_workers=min(8, len(cfg.devices))) as pool:
        results = list(pool.map(one, cfg.devices))
    return (
        {n: t for n, t, err in results if err is None},
        {n: err for n, t, err in results if err is not None},
    )


def run_backup(cfg: Config, fetcher: Fetcher, out=None) -> int:
    out = out or sys.stdout
    configs, failed = fetch_all(cfg, fetcher)
    store = Store(cfg.backups)
    store.init()
    for name, text in configs.items():
        store.write(name, redact(strip_chrome(text)))
    subject = store.commit_run(total=len(cfg.devices), failed=failed)
    print(
        subject or f"no changes on {len(configs)} device(s); nothing committed",
        file=out,
    )
    for name, why in sorted(failed.items()):
        print(f"FAILED {name}: {why}", file=sys.stderr)
    return 2 if failed else 0


def run_drift(cfg: Config, fetcher: Fetcher, out=None) -> int:
    out = out or sys.stdout
    intended = intended_configs(cfg)
    unknown = [d.name for d in cfg.devices if d.name not in intended]
    if unknown:
        raise ConfigError(
            f"no intended config for {', '.join(unknown)} in {cfg.intended}"
        )
    configs, failed = fetch_all(cfg, fetcher)
    drifted = 0
    for dev in cfg.devices:
        if dev.name in failed:
            continue
        result = driftlib.compare(dev.name, intended[dev.name], configs[dev.name])
        print(result.report(), file=out)
        drifted += result.drifted
    for name, why in sorted(failed.items()):
        print(f"FAILED {name}: {why}", file=sys.stderr)
    if failed:
        return 2
    return 1 if drifted else 0


def main(argv: list[str] | None = None, fetcher: Fetcher | None = None) -> int:
    p = argparse.ArgumentParser(prog="confdrift", description=__doc__)
    p.add_argument("-c", "--config", type=Path, default=DEFAULT_CONFIG)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("backup", help="save running configs, one git commit per run")
    sub.add_parser("drift", help="compare running configs with the intended configs")
    sub.add_parser("intended", help="print the intended config of every device")
    lg = sub.add_parser("log", help="commit history of one device's backups")
    lg.add_argument("device")
    a = p.parse_args(argv)

    try:
        cfg = load_config(a.config)
        if a.cmd == "intended":
            for name, text in intended_configs(cfg).items():
                print(f"### {name}\n{text}")
            return 0
        if a.cmd == "log":
            print(Store(cfg.backups).history(a.device), end="")
            return 0
        if fetcher is None:
            fetcher = NetmikoFetcher(*credentials())
        return (run_backup if a.cmd == "backup" else run_drift)(cfg, fetcher)
    except (ConfigError, GitError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
