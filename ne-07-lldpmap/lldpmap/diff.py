from __future__ import annotations

from dataclasses import dataclass, field

from lldpmap.topology import Link, Topology


@dataclass
class TopologyDiff:
    devices_added: list[str] = field(default_factory=list)
    devices_removed: list[str] = field(default_factory=list)
    links_added: list[Link] = field(default_factory=list)
    links_removed: list[Link] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(
            self.devices_added
            or self.devices_removed
            or self.links_added
            or self.links_removed
        )

    def report(self, old: Topology, new: Topology) -> str:
        lines = [f"topology diff: {old.taken} -> {new.taken}"]
        if not self.changed:
            return "\n".join(lines + ["no changes"])
        lines += [f"- link removed: {l}" for l in self.links_removed]
        lines += [f"+ link added:   {l}" for l in self.links_added]
        lines += [f"- device gone:  {d}" for d in self.devices_removed]
        lines += [f"+ device new:   {d}" for d in self.devices_added]
        return "\n".join(lines)


def compare(old: Topology, new: Topology) -> TopologyDiff:
    return TopologyDiff(
        devices_added=sorted(set(new.devices) - set(old.devices)),
        devices_removed=sorted(set(old.devices) - set(new.devices)),
        links_added=sorted(new.links - old.links),
        links_removed=sorted(old.links - new.links),
    )
