"""Pure parsing of FRR `show bgp ipv4 unicast <prefix> json` output."""

from __future__ import annotations

from dataclasses import dataclass

# What selectionReason strings mean, in decision-process order (FRR 8.4).
REASON_TEXT = {
    "Only Path": "it is the only path",
    "Weight": "highest weight",
    "Local Pref": "highest local-preference",
    "Local Route": "locally originated beats learned",
    "AS Path": "shortest AS path",
    "Origin": "lowest origin code",
    "MED": "lowest MED",
    "Peer Type": "eBGP preferred over iBGP",
    "IGP Metric": "lowest IGP metric to next hop",
    "Older Path": "oldest path",
    "Router ID": "lowest router ID",
    "Neighbor IP": "lowest neighbor address",
}


@dataclass(frozen=True)
class Path:
    aspath: str
    nexthop: str
    local_pref: int | None
    rpki: str | None
    communities: tuple[str, ...]
    best: bool
    reason: str | None
    peer: str

    @property
    def first_as(self) -> str:
        return self.aspath.split()[0] if self.aspath else ""

    @property
    def length(self) -> int:
        return len(self.aspath.split())


def parse_paths(doc: dict) -> list[Path]:
    """Return every path in the document; an empty dict means no route."""
    out = []
    for p in doc.get("paths", []):
        best = p.get("bestpath", {})
        comm = p.get("community", {}).get("list", [])
        out.append(
            Path(
                aspath=p.get("aspath", {}).get("string", ""),
                nexthop=p["nexthops"][0]["ip"],
                local_pref=p.get("locPrf"),
                rpki=p.get("rpkiValidationState"),
                communities=tuple(comm),
                best=bool(best.get("overall")),
                reason=best.get("selectionReason"),
                peer=p.get("peer", {}).get(
                    "hostname", p.get("peer", {}).get("peerId", "")
                ),
            )
        )
    return out


def best_path(paths: list[Path]) -> Path | None:
    return next((p for p in paths if p.best), None)


def explain(node: str, prefix: str, paths: list[Path]) -> str:
    """One paragraph saying which path won and why, naming each loser's flaw."""
    if not paths:
        return f"{node}: no route to {prefix}"
    win = best_path(paths)
    if win is None:
        return (
            f"{node}: {prefix} has paths but none is selected (next hop unreachable?)"
        )
    lines = [
        f"{node} -> {prefix}: best via {win.peer} ({win.nexthop}), AS path [{win.aspath or 'local'}]"
    ]
    lines[0] += f", local-pref {win.local_pref}" if win.local_pref is not None else ""
    if win.rpki:
        lines[0] += f", RPKI {win.rpki}"
    if win.communities:
        lines[0] += f", communities {' '.join(win.communities)}"
    for p in paths:
        if p is win:
            continue
        lines.append("  lost to " + _why_lost(win, p))
    if len(paths) == 1:
        lines.append("  chosen because it is the only path")
    else:
        why = REASON_TEXT.get(win.reason or "", win.reason or "unknown step")
        lines.append(f"  deciding step: {why}")
    return "\n".join(lines)


def _why_lost(win: Path, p: Path) -> str:
    head = f"{p.peer} [{p.aspath}]"
    if (p.local_pref or 0) != (win.local_pref or 0):
        return f"{head}: local-pref {p.local_pref} < {win.local_pref}"
    if p.length != win.length:
        return f"{head}: AS path length {p.length} > {win.length}"
    return f"{head}: later tie-break ({win.reason})"
