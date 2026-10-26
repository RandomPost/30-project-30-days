from __future__ import annotations

import difflib
from dataclasses import dataclass, field

from confdrift import normalize
from confdrift.redact import redact

Lines = dict[str, list[str]]


@dataclass
class Drift:
    device: str
    # block exists on both sides, these child lines differ
    missing: Lines = field(default_factory=dict)  # intended, not on device
    extra: Lines = field(default_factory=dict)  # on device, not intended
    # the whole block (header and children) exists on one side only
    missing_blocks: Lines = field(default_factory=dict)
    extra_blocks: Lines = field(default_factory=dict)
    diff: str = ""

    @property
    def drifted(self) -> bool:
        return bool(
            self.missing or self.extra or self.missing_blocks or self.extra_blocks
        )

    @property
    def line_count(self) -> int:
        child_lines = sum(
            len(v) for d in (self.missing, self.extra) for v in d.values()
        )
        block_lines = sum(
            1 + len(v)
            for d in (self.missing_blocks, self.extra_blocks)
            for v in d.values()
        )
        return child_lines + block_lines

    def report(self) -> str:
        """One-line verdict, a per-block summary, then the unified diff."""
        if not self.drifted:
            return f"{self.device}: in sync with intended config"
        out = [f"{self.device}: DRIFT ({self.line_count} line(s) differ)"]
        for header, kids in sorted(self.missing_blocks.items()):
            out.append(f"  missing on device: {header}" + _kids(kids))
        for header, kids in sorted(self.extra_blocks.items()):
            out.append(f"  unexpected on device: {header}" + _kids(kids))
        for header in sorted(set(self.missing) | set(self.extra)):
            out.append(f"  [{header}]")
            out += [f"    missing on device: {x}" for x in self.missing.get(header, [])]
            out += [
                f"    unexpected on device: {x}" for x in self.extra.get(header, [])
            ]
        out += ["", self.diff.rstrip("\n")]
        return "\n".join(out)


def _kids(kids: list[str]) -> str:
    return f" ({len(kids)} child line(s))" if kids else ""


def compare(
    device: str,
    intended: str,
    running: str,
    ignore: tuple[str, ...] = normalize.IGNORE,
) -> Drift:
    want = normalize.parse(redact(intended), ignore)
    have = normalize.parse(redact(running), ignore)
    drift = Drift(device)
    for header in sorted(set(want) | set(have)):
        w, h = set(want.get(header, [])), set(have.get(header, []))
        if header not in have:
            drift.missing_blocks[header] = sorted(w)
        elif header not in want:
            drift.extra_blocks[header] = sorted(h)
        else:
            if w - h:
                drift.missing[header] = sorted(w - h)
            if h - w:
                drift.extra[header] = sorted(h - w)
    drift.diff = "".join(
        difflib.unified_diff(
            normalize.canonical(want).splitlines(keepends=True),
            normalize.canonical(have).splitlines(keepends=True),
            fromfile=f"intended/{device}",
            tofile=f"running/{device}",
        )
    )
    return drift
