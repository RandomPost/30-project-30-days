from __future__ import annotations

import argparse
import sys
from pathlib import Path

from netgen import render, scaffold
from netgen.loader import SourceError, load
from netgen.validate import validate

DEFAULT_SOURCE = Path("data/sites.yml")
DEFAULT_OUT = Path("rendered")


def _load_valid(path: Path):
    try:
        inv = load(path)
    except FileNotFoundError:
        print(f"error: {path} not found", file=sys.stderr)
        return None
    except SourceError as exc:
        print(f"{path}: schema errors", file=sys.stderr)
        print(
            "\n".join("  - " + line for line in str(exc).splitlines()), file=sys.stderr
        )
        return None
    problems = validate(inv)
    if problems:
        print(f"{path}: {len(problems)} validation error(s)", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return None
    return inv


def cmd_validate(a: argparse.Namespace) -> int:
    inv = _load_valid(a.source)
    if inv is None:
        return 1
    devices = sum(len(s.devices) for s in inv.sites)
    print(f"OK: {len(inv.sites)} sites, {devices} devices")
    return 0


def _show_plan(plan: dict, show_diff: bool) -> None:
    for name, (status, text) in plan.items():
        print(f"{status:<9} {name}")
        if show_diff and text:
            print(text if text.endswith("\n") else text + "\n", end="")


def cmd_diff(a: argparse.Namespace) -> int:
    inv = _load_valid(a.source)
    if inv is None:
        return 1
    plan = render.plan(render.render_all(inv), a.out)
    _show_plan(plan, show_diff=True)
    changed = any(s != "unchanged" for s, _ in plan.values())
    return 2 if (a.check and changed) else 0


def cmd_render(a: argparse.Namespace) -> int:
    inv = _load_valid(a.source)
    if inv is None:
        return 1
    rendered = render.render_all(inv)
    plan = render.plan(rendered, a.out)
    _show_plan(plan, show_diff=not a.quiet)
    if not a.dry_run:
        a.out.mkdir(parents=True, exist_ok=True)
        for name, text in rendered.items():
            if plan[name][0] != "unchanged":
                (a.out / name).write_text(text)
        n = sum(1 for s, _ in plan.values() if s != "unchanged")
        print(f"wrote {n} file(s) to {a.out}/, {len(plan) - n} unchanged")
    return 0


def cmd_new_site(a: argparse.Namespace) -> int:
    try:
        site = scaffold.build_site(a.name, a.number, scaffold.parse_vlans(a.vlans))
    except SourceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    problems = scaffold.append_site(a.source, site)
    if problems:
        print(
            "not added; the new site would break the source of truth:", file=sys.stderr
        )
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(f"added site {a.name!r} to {a.source}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netgen", description=__doc__)
    p.add_argument("-s", "--source", type=Path, default=DEFAULT_SOURCE)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("validate", help="check the source of truth").set_defaults(
        fn=cmd_validate
    )

    d = sub.add_parser("diff", help="show what render would change")
    d.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    d.add_argument("--check", action="store_true", help="exit 2 if anything differs")
    d.set_defaults(fn=cmd_diff)

    r = sub.add_parser("render", help="render configs, showing a diff first")
    r.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("-q", "--quiet", action="store_true", help="no diff output")
    r.set_defaults(fn=cmd_render)

    n = sub.add_parser("new-site", help="add a standard site to the source of truth")
    n.add_argument("--name", required=True)
    n.add_argument("--number", type=int, required=True, help="site number 1-254")
    n.add_argument("--vlans", required=True, help="name=id,name=id")
    n.set_defaults(fn=cmd_new_site)

    a = p.parse_args(argv)
    return a.fn(a)
