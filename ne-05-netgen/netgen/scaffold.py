"""Build a standard site (one FRR router + one IOS L3 switch) from a few answers."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from netgen.loader import SourceError, parse
from netgen.validate import validate


def parse_vlans(spec: str) -> list[tuple[str, int]]:
    """'users=10,voice=20' -> [('users', 10), ('voice', 20)]"""
    out = []
    for part in filter(None, (p.strip() for p in spec.split(","))):
        m = re.fullmatch(r"([A-Za-z0-9_-]+)=(\d+)", part)
        if not m:
            raise SourceError(f"bad VLAN {part!r}; use name=id, e.g. users=10")
        out.append((m.group(1), int(m.group(2))))
    if not out:
        raise SourceError("at least one VLAN is required")
    for i, (name, vid) in enumerate(out):
        if any(vid == v or name == n for n, v in out[:i]):
            raise SourceError(f"VLAN {name}={vid} defined twice")
    return out


def build_site(name: str, number: int, vlans: list[tuple[str, int]]) -> dict:
    """Addressing plan: 10.<number>.0.0/30 uplink, 10.<number>.<n>.0/24 for the nth
    VLAN, loopbacks 10.255.<number>.1 (router) and .2 (switch)."""
    if not 1 <= number <= 254:
        raise SourceError("site number must be 1-254")
    if len(vlans) > 20:
        raise SourceError("at most 20 VLANs per scaffolded site")
    r, sw = f"{name}-r1", f"{name}-sw1"
    sw_ifaces = [
        {
            "name": "GigabitEthernet0/1",
            "description": f"uplink to {r}",
            "ip": f"10.{number}.0.2/30",
            "ospf_area": 0,
        }
    ]
    for idx, (vname, vid) in enumerate(vlans, start=1):
        sw_ifaces.append(
            {
                "name": f"Vlan{vid}",
                "mode": "svi",
                "vlan": vid,
                "ip": f"10.{number}.{idx}.1/24",
                "description": vname,
                "ospf_area": 0,
            }
        )
    for idx, (vname, vid) in enumerate(vlans, start=2):
        sw_ifaces.append(
            {
                "name": f"GigabitEthernet0/{idx}",
                "description": f"{vname} access",
                "mode": "access",
                "vlan": vid,
            }
        )
    sw_ifaces.append(
        {
            "name": "GigabitEthernet0/24",
            "description": "trunk to access point",
            "mode": "trunk",
            "trunk_vlans": [v for _, v in vlans],
        }
    )
    return {
        "name": name,
        "vlans": [{"id": vid, "name": vname} for vname, vid in vlans],
        "devices": [
            {
                "name": r,
                "platform": "frr",
                "role": "router",
                "loopback": f"10.255.{number}.1/32",
                "interfaces": [
                    {
                        "name": "eth1",
                        "description": f"downlink to {sw}",
                        "ip": f"10.{number}.0.1/30",
                        "ospf_area": 0,
                    }
                ],
            },
            {
                "name": sw,
                "platform": "ios",
                "role": "l3-switch",
                "loopback": f"10.255.{number}.2/32",
                "interfaces": sw_ifaces,
            },
        ],
        "links": [{"a": f"{r}:eth1", "b": f"{sw}:GigabitEthernet0/1"}],
    }


def append_site(path: Path, site: dict) -> list[str]:
    """Validate the inventory with `site` added and append it to `path` only if clean.

    Appends as text so comments and layout already in the file survive. Returns the
    list of problems; the file is untouched unless the list is empty."""
    path = Path(path)
    text = path.read_text()
    block = yaml.safe_dump([site], sort_keys=False)
    block = "".join(
        "  " + line if line.strip() else line for line in block.splitlines(True)
    )
    new_text = text if text.endswith("\n") else text + "\n"
    new_text += f"\n  # --- added by netgen scaffold ---\n{block}"
    try:
        problems = validate(parse(new_text))
    except SourceError as exc:
        problems = str(exc).splitlines()
    if not problems:
        path.write_text(new_text)
    return problems
