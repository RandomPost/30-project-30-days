"""File and git access: the only module that touches the filesystem or git."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterator

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox"}
MAX_BYTES = 1_000_000
ALLOWLIST_NAME = ".secretscan-allow"


def read_text(path: Path) -> str | None:
    """Return file text, or None for binary, huge or unreadable files."""
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data:
        return None
    return data.decode("utf-8", errors="replace")


def walk(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and not SKIP_DIRS.intersection(p.relative_to(root).parts):
            yield p


def staged_files(cwd: Path) -> list[tuple[str, str]]:
    """(path, content-as-staged) for added/changed/renamed files in the index."""
    names = _git(cwd, "diff", "--cached", "--name-only", "--diff-filter=ACMR")
    result = []
    for name in names.splitlines():
        blob = subprocess.run(
            ["git", "show", f":{name}"], cwd=cwd, capture_output=True, check=False
        ).stdout
        if b"\0" not in blob and len(blob) <= MAX_BYTES:
            result.append((name, blob.decode("utf-8", errors="replace")))
    return result


def repo_root(cwd: Path) -> Path:
    return Path(_git(cwd, "rev-parse", "--show-toplevel").strip())


def hooks_dir(cwd: Path) -> Path:
    out = _git(cwd, "rev-parse", "--git-path", "hooks").strip()
    p = Path(out)
    return p if p.is_absolute() else cwd / p


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout
