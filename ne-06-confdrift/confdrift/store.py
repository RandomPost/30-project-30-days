"""A git repository of device configs: one file per device, one commit per run."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

MAX_LINES_PER_DEVICE = 12


class GitError(Exception):
    pass


@dataclass
class Change:
    device: str
    added: int
    removed: int
    new: bool
    lines: list[str]  # "+..." / "-..." content lines of the diff


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)

    # -- git plumbing -------------------------------------------------------
    def git(self, *args: str, check: bool = True) -> str:
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": os.environ.get("GIT_AUTHOR_NAME", "confdrift"),
            "GIT_AUTHOR_EMAIL": os.environ.get(
                "GIT_AUTHOR_EMAIL", "confdrift@localhost"
            ),
            "GIT_COMMITTER_NAME": os.environ.get("GIT_COMMITTER_NAME", "confdrift"),
            "GIT_COMMITTER_EMAIL": os.environ.get(
                "GIT_COMMITTER_EMAIL", "confdrift@localhost"
            ),
        }
        proc = subprocess.run(
            ["git", "-C", str(self.path), *args],
            capture_output=True,
            text=True,
            env=env,
        )
        if check and proc.returncode != 0:
            raise GitError(f"git {' '.join(args)}: {proc.stderr.strip()}")
        return proc.stdout

    def init(self) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        if not (self.path / ".git").exists():
            self.git("init", "-q", "-b", "main")

    # -- backups ------------------------------------------------------------
    def write(self, device: str, text: str) -> None:
        (self.path / f"{device}.cfg").write_text(
            text if text.endswith("\n") else text + "\n"
        )

    def staged_changes(self) -> list[Change]:
        self.git("add", "-A")
        numstat = self.git("diff", "--cached", "--numstat", "--no-renames")
        status = dict(
            line.split("\t")[::-1]
            for line in self.git("diff", "--cached", "--name-status", "--no-renames")
            .strip()
            .splitlines()
        )
        changes = []
        for row in numstat.strip().splitlines():
            added, removed, name = row.split("\t")
            body = self.git("diff", "--cached", "--no-renames", "-U0", "--", name)
            lines = [
                ln
                for ln in body.splitlines()
                if ln[:1] in "+-" and not ln.startswith(("+++", "---"))
            ]
            changes.append(
                Change(
                    device=name.removesuffix(".cfg"),
                    added=int(added),
                    removed=int(removed),
                    new=status.get(name) == "A",
                    lines=lines,
                )
            )
        return changes

    def commit_run(
        self, total: int, failed: dict[str, str] | None = None
    ) -> str | None:
        """Commit whatever changed. Returns the commit subject, or None if nothing did."""
        failed = failed or {}
        changes = self.staged_changes()
        if not changes:
            return None
        subject, body = describe(changes, total, failed)
        self.git("commit", "-q", "-m", subject, "-m", body)
        return subject

    def history(self, device: str, limit: int = 20) -> str:
        return self.git(
            "log",
            f"-{limit}",
            "--date=short",
            "--format=%h %ad %s",
            "--",
            f"{device}.cfg",
        )


def describe(
    changes: list[Change], total: int, failed: dict[str, str]
) -> tuple[str, str]:
    """Commit subject and body for a run, from the staged changes."""
    names = [c.device for c in changes]
    added = sum(c.added for c in changes)
    removed = sum(c.removed for c in changes)
    if all(c.new for c in changes):
        subject = (
            f"backup: first snapshot of {len(changes)} device(s): {', '.join(names)}"
        )
    else:
        new = [c.device for c in changes if c.new]
        shown = ", ".join(names[:4]) + (
            f" and {len(names) - 4} more" if len(names) > 4 else ""
        )
        subject = f"backup: config changed on {shown} (+{added}/-{removed} lines)"
        if new:
            subject += f"; new: {', '.join(new)}"
    body = [f"{len(changes)} of {total} device(s) changed since the previous run.", ""]
    for c in changes:
        body.append(
            f"{c.device}: {'new file, ' if c.new else ''}+{c.added}/-{c.removed}"
        )
        if not c.new:
            body += [f"    {ln}" for ln in c.lines[:MAX_LINES_PER_DEVICE]]
            if len(c.lines) > MAX_LINES_PER_DEVICE:
                body.append(f"    ... {len(c.lines) - MAX_LINES_PER_DEVICE} more")
    if failed:
        body += ["", "Not backed up this run (previous copy kept):"]
        body += [f"    {d}: {why}" for d, why in sorted(failed.items())]
    return subject, "\n".join(body)
