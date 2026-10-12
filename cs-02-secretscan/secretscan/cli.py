"""Command line entry point: scan, hook (Claude Code) and install-hook (git)."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from . import files
from .allowlist import Allowlist, parse_allowlist
from .report import format_findings
from .scanner import Finding, scan_text

PRE_COMMIT = Path(__file__).resolve().parent.parent / "hooks" / "pre-commit"


def load_allowlist(root: Path) -> Allowlist:
    f = root / files.ALLOWLIST_NAME
    return parse_allowlist(f.read_text()) if f.is_file() else Allowlist()


def filter_findings(found: list[Finding], allow: Allowlist) -> list[Finding]:
    return [f for f in found if not allow.allows(f)]


def scan_paths(paths: list[Path], allow: Allowlist) -> list[Finding]:
    found: list[Finding] = []
    for root in paths:
        for p in files.walk(root):
            text = files.read_text(p)
            if text is not None:
                found += scan_text(text, str(p))
    return filter_findings(found, allow)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secretscan", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan files or directories (or --staged)")
    s.add_argument("paths", nargs="*", type=Path, default=[Path(".")])
    s.add_argument("--staged", action="store_true", help="scan the git index")
    s.add_argument("--allowlist-dir", type=Path, help="where .secretscan-allow lives")
    sub.add_parser("hook", help="Claude Code PostToolUse hook (JSON on stdin)")
    sub.add_parser("install-hook", help="install the git pre-commit hook")
    return p


def cmd_scan(args: argparse.Namespace) -> int:
    if args.staged:
        root = files.repo_root(Path.cwd())
        allow = load_allowlist(args.allowlist_dir or root)
        found = []
        for name, text in files.staged_files(root):
            found += scan_text(text, name)
        found = filter_findings(found, allow)
    else:
        allow = load_allowlist(args.allowlist_dir or Path.cwd())
        found = scan_paths(args.paths, allow)
    print(format_findings(found))
    return 1 if found else 0


def cmd_hook(stdin_text: str) -> int:
    """Read a PostToolUse event, scan the touched file, exit 2 to notify Claude."""
    try:
        event = json.loads(stdin_text)
        path = Path(event["tool_input"]["file_path"])
    except (ValueError, KeyError, TypeError):
        return 0  # not a file edit; nothing to scan
    text = files.read_text(path)
    if text is None:
        return 0
    project = Path(os.environ.get("CLAUDE_PROJECT_DIR", Path.cwd()))
    found = filter_findings(scan_text(text, str(path)), load_allowlist(project))
    if not found:
        return 0
    print(format_findings(found), file=sys.stderr)
    print(
        f"You just wrote a possible secret to {path}. Replace it with an "
        "environment variable or secrets manager reference.",
        file=sys.stderr,
    )
    return 2  # exit 2 = stderr is fed back to Claude


def cmd_install_hook() -> int:
    dest = files.hooks_dir(Path.cwd()) / "pre-commit"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(PRE_COMMIT, dest)
    dest.chmod(0o755)
    print(f"installed {dest}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "hook":
        return cmd_hook(sys.stdin.read())
    return cmd_install_hook()


if __name__ == "__main__":
    sys.exit(main())
