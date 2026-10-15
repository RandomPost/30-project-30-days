"""Render THREAT_MODEL.md from a template and emit citations.tsv.

Template citations look like [[path|fragment]] or [[path|fragment|N]] (Nth match,
default 1). Each becomes `path:LINE`, where LINE is the line of the repo at which
the fragment actually appears, and is recorded in citations.tsv for the checker.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PATTERN = re.compile(r"\[\[([^|\]]+)\|([^|\]]+)(?:\|(\d+))?\]\]")


def find_line(repo: Path, rel: str, fragment: str, nth: int) -> int:
    lines = (repo / rel).read_text(errors="replace").splitlines()
    hits = [i for i, line in enumerate(lines, 1) if fragment in line]
    if len(hits) < nth:
        raise SystemExit(f"fragment not found: {rel} {fragment!r} (match {nth})")
    return hits[nth - 1]


def render(template: str, repo: Path) -> tuple[str, list[tuple[str, int, str]]]:
    cites: list[tuple[str, int, str]] = []

    def sub(m: re.Match[str]) -> str:
        rel, frag, nth = m.group(1), m.group(2), int(m.group(3) or 1)
        line = find_line(repo, rel, frag, nth)
        if (rel, line, frag) not in cites:
            cites.append((rel, line, frag))
        return f"`{rel}:{line}`"

    return PATTERN.sub(sub, template), cites


def main(argv: list[str]) -> int:
    template, repo, out_dir = Path(argv[1]), Path(argv[2]), Path(argv[3])
    text, cites = render(template.read_text(), repo)
    (out_dir / "THREAT_MODEL.md").write_text(text)
    rows = ["\t".join((rel, str(line), frag)) for rel, line, frag in cites]
    (out_dir / "citations.tsv").write_text("\n".join(rows) + "\n")
    print(f"{len(cites)} citations")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
