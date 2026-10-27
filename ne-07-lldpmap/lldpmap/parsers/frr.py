"""FRR-on-Linux neighbour parser (LLDP from the ``lldpd`` daemon).

Parses ``lldpcli show neighbors details -f json``.  Handles lldpd's JSON quirks:
``interface`` is a list of single-key dicts for several neighbours but a plain
dict for one (and absent for none); ``chassis`` is keyed by the neighbour's name;
``mgmt-ip`` may be a string or a list; the same ifname may repeat.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from lldpmap.models import Neighbor

VENDOR = "frr"
NEIGHBOR_COMMAND = "lldpcli show neighbors details -f json"
HOSTNAME_COMMAND = "hostname"


def _strip_domain(name: str) -> str:
    name = name.strip()
    if ":" in name or name.replace(".", "").isdigit() or "." not in name:
        return name  # MAC / IPv4 / IPv6 / already short
    return name.split(".", 1)[0]


def _pick_ip(value: Any) -> Optional[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return None
    addrs = [v for v in value if isinstance(v, str) and v]
    for a in addrs:
        if ":" not in a:
            return a
    return addrs[0] if addrs else None


def _items(interface: Any) -> list[tuple[str, dict]]:
    """Normalise the dict-or-list `interface` value to (ifname, body) pairs."""
    if isinstance(interface, dict):
        interface = [interface]
    if not isinstance(interface, list):
        return []
    out: list[tuple[str, dict]] = []
    for entry in interface:
        if isinstance(entry, dict):
            for ifname, body in entry.items():
                if isinstance(body, dict):
                    out.append((ifname, body))
    return out


def _id_value(node: Any) -> tuple[str, str]:
    if isinstance(node, dict):
        return str(node.get("type") or ""), str(node.get("value") or "")
    return "", ""


def parse_neighbors(text: str) -> list[Neighbor]:
    """Parse ``lldpcli show neighbors details -f json``."""
    if not text or not text.strip():
        return []
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError("not JSON from 'lldpcli show neighbors -f json'") from exc
    if not isinstance(data, dict) or not isinstance(data.get("lldp"), (dict, str)):
        raise ValueError("JSON has no 'lldp' object: not lldpcli output")
    lldp = data["lldp"]
    if not isinstance(lldp, dict):
        return []
    out: list[Neighbor] = []
    for ifname, body in _items(lldp.get("interface")):
        chassis = body.get("chassis")
        if not isinstance(chassis, dict) or not chassis:
            continue
        # Normal shape: {name: {...}}.  Some lldpd versions emit the chassis
        # fields directly ({"id": ..., "descr": ...}) when there is no sysName.
        if "id" in chassis and isinstance(chassis["id"], dict):
            key, cbody = "", chassis
        else:
            key, cbody = next(iter(chassis.items()))
            if not isinstance(cbody, dict):
                cbody = {}
        _, chassis_id = _id_value(cbody.get("id"))
        name = _strip_domain(key or chassis_id)
        port = body.get("port") if isinstance(body.get("port"), dict) else {}
        ptype, pvalue = _id_value(port.get("id"))
        pdescr = port.get("descr")
        if ptype == "mac" and isinstance(pdescr, str) and pdescr:
            remote_port = pdescr
        else:
            remote_port = pvalue or (pdescr if isinstance(pdescr, str) else "")
        desc = cbody.get("descr")
        out.append(
            Neighbor(
                local_port=ifname,
                remote_name=name,
                remote_port=remote_port,
                remote_ip=_pick_ip(cbody.get("mgmt-ip")),
                remote_desc=desc if isinstance(desc, str) and desc else None,
            )
        )
    return out


def parse_hostname(text: str) -> str:
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return _strip_domain(line.split()[0])
    raise ValueError("empty hostname output")
