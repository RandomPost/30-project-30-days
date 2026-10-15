"""Verify THREAT_MODEL.md citations against a checkout of the analysed repo.

usage: python scripts/check_citations.py PATH_TO_FILEBROWSER_CHECKOUT

Checks that (1) every `path:LINE` in THREAT_MODEL.md is listed in citations.tsv,
(2) every tsv entry's quoted fragment is on exactly that line of that file.
Exit code 1 on any mismatch.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REF = re.compile(r"`([\w./-]+):(\d+)`")


def load_citations(tsv: str) -> list[tuple[str, int, str]]:
    rows = []
    for line in tsv.splitlines():
        if line.strip():
            path, num, frag = line.split("\t", 2)
            rows.append((path, int(num), frag))
    return rows


def md_refs(markdown: str) -> set[tuple[str, int]]:
    return {(p, int(n)) for p, n in REF.findall(markdown)}


def check(markdown: str, tsv: str, repo: Path) -> list[str]:
    problems = []
    rows = load_citations(tsv)
    listed = {(p, n) for p, n, _ in rows}
    for ref in sorted(md_refs(markdown) - listed):
        problems.append(
            f"cited in markdown but not in citations.tsv: {ref[0]}:{ref[1]}"
        )
    for path, num, frag in rows:
        file = repo / path
        if not file.is_file():
            problems.append(f"missing file: {path}")
            continue
        lines = file.read_text(errors="replace").splitlines()
        if num > len(lines) or frag not in lines[num - 1]:
            problems.append(f"{path}:{num} does not contain {frag!r}")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    problems = check(
        (ROOT / "THREAT_MODEL.md").read_text(),
        (ROOT / "citations.tsv").read_text(),
        Path(argv[1]),
    )
    for p in problems:
        print("FAIL:", p)
    print(f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
