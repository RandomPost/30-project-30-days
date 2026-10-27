"""The result of a crawl: devices and links, stored as JSON."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERSION = 1


@dataclass(frozen=True, order=True)
class Link:
    """A cable between two (device, port) ends. Ends are sorted, so the same link
    seen from either side is equal."""

    a_dev: str
    a_port: str
    b_dev: str
    b_port: str

    @classmethod
    def of(cls, dev1: str, port1: str, dev2: str, port2: str) -> "Link":
        e1, e2 = sorted([(dev1, port1), (dev2, port2)])
        return cls(e1[0], e1[1], e2[0], e2[1])

    def __str__(self) -> str:
        return f"{self.a_dev}:{self.a_port} <-> {self.b_dev}:{self.b_port}"


@dataclass
class Device:
    name: str
    vendor: str = "frr"
    host: Optional[str] = None  # address used to log in; None if never reached
    crawled: bool = False  # True if we read its own neighbour table
    note: Optional[str] = None  # why it was not crawled


@dataclass
class Topology:
    seed: str
    taken: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    )
    devices: dict[str, Device] = field(default_factory=dict)
    links: set[Link] = field(default_factory=set)

    def to_json(self) -> str:
        doc = {
            "version": VERSION,
            "taken": self.taken,
            "seed": self.seed,
            "devices": [vars(self.devices[n]).copy() for n in sorted(self.devices)],
            "links": [
                {
                    "a": {"device": l.a_dev, "port": l.a_port},
                    "b": {"device": l.b_dev, "port": l.b_port},
                }
                for l in sorted(self.links)
            ],
        }
        return json.dumps(doc, indent=2) + "\n"

    @classmethod
    def from_json(cls, text: str) -> "Topology":
        doc = json.loads(text)
        if doc.get("version") != VERSION:
            raise ValueError(
                f"unsupported topology file version {doc.get('version')!r}"
            )
        topo = cls(seed=doc["seed"], taken=doc["taken"])
        for d in doc["devices"]:
            topo.devices[d["name"]] = Device(**d)
        for l in doc["links"]:
            topo.links.add(
                Link.of(
                    l["a"]["device"], l["a"]["port"], l["b"]["device"], l["b"]["port"]
                )
            )
        return topo


def save(topo: Topology, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(topo.to_json())


def load(path: Path) -> Topology:
    return Topology.from_json(Path(path).read_text())
