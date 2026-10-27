"""Cisco IOS / IOS-XE (classic CLI) neighbour parser.

LLDP is parsed from ``show lldp neighbors detail`` (``parse_neighbors``); many Cisco
devices only run CDP, so ``show cdp neighbors detail`` is handled by
``parse_cdp_neighbors`` (command in ``CDP_COMMAND``).
"""

from __future__ import annotations

import re
from typing import Optional

from lldpmap.models import Neighbor

VENDOR = "ios"
NEIGHBOR_COMMAND = "show lldp neighbors detail"
CDP_COMMAND = "show cdp neighbors detail"
HOSTNAME_COMMAND = "show running-config | include ^hostname"

_SEP = re.compile(r"^\s*-{10,}\s*$", re.M)
_MAC_LIKE = re.compile(
    r"^[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}$|^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$"
)
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_NOT_ENABLED = re.compile(r"(lldp|cdp) is not enabled", re.I)


def _strip_domain(name: str) -> str:
    name = name.strip()
    if _IPV4.match(name) or _MAC_LIKE.match(name) or "." not in name:
        return name
    return name.split(".", 1)[0]


def _blocks(text: str) -> list[str]:
    return [b for b in _SEP.split(text.replace("\r\n", "\n")) if b.strip()]


def _field(block: str, label: str) -> Optional[str]:
    m = re.search(r"^[ \t]*" + label + r"[ \t]*:[ \t]*(.*?)[ \t]*$", block, re.M)
    return m.group(1) if m and m.group(1) else None


def _multiline(block: str, label: str) -> Optional[str]:
    """Value of `label:` that may continue on following lines until a blank line."""
    m = re.search(
        r"^[ \t]*" + label + r"[ \t]*:[ \t]*(.*?)\n(.*?)(?:\n[ \t]*\n|\Z)",
        block + "\n",
        re.M | re.S,
    )
    if not m:
        return None
    text = " ".join(x.strip() for x in (m.group(1) + "\n" + m.group(2)).splitlines())
    text = text.strip()
    return text or None


def _pick_ip(addrs: list[tuple[str, str]]) -> Optional[str]:
    for kind, value in addrs:
        if kind == "v4":
            return value
    return addrs[0][1] if addrs else None


def parse_neighbors(text: str) -> list[Neighbor]:
    """Parse ``show lldp neighbors detail``."""
    if not text or not text.strip() or _NOT_ENABLED.search(text):
        return []
    if re.search(r"^\s*Total cdp entries", text, re.I | re.M) or (
        "Local Intf" not in text and "Total entries displayed" not in text
    ):
        raise ValueError("not 'show lldp neighbors detail' output")
    out: list[Neighbor] = []
    for block in _blocks(text):
        local = _field(block, "Local Intf")
        if not local:
            continue
        chassis = _field(block, "Chassis id")
        sysname = _field(block, "System Name")
        port_id = _field(block, "Port id")
        port_desc = _field(block, "Port Description")
        remote_port = port_id
        if port_desc and (not port_id or _MAC_LIKE.match(port_id)):
            remote_port = port_desc
        name = _strip_domain(sysname) if sysname else (chassis or "")
        addrs: list[tuple[str, str]] = []
        for m in re.finditer(r"^[ \t]*(IP|IPV6):[ \t]*(\S+)", block, re.M | re.I):
            addrs.append(("v4" if m.group(1).upper() == "IP" else "v6", m.group(2)))
        desc = _multiline(block, "System Description")
        out.append(
            Neighbor(
                local_port=local,
                remote_name=name,
                remote_port=remote_port or "",
                remote_ip=_pick_ip(addrs),
                remote_desc=desc,
            )
        )
    return out


def parse_cdp_neighbors(text: str) -> list[Neighbor]:
    """Parse ``show cdp neighbors detail``."""
    if not text or not text.strip() or _NOT_ENABLED.search(text):
        return []
    if "Device ID" not in text and not re.search(r"Total cdp entries", text, re.I):
        raise ValueError("not 'show cdp neighbors detail' output")
    out: list[Neighbor] = []
    for block in _blocks(text):
        dev = _field(block, "Device ID")
        if not dev:
            continue
        m = re.search(
            r"^[ \t]*Interface:[ \t]*([^,\n]+?)[ \t]*,[ \t]*Port ID \(outgoing port\):[ \t]*(.*?)[ \t]*$",
            block,
            re.M,
        )
        if not m:
            continue
        addrs: list[tuple[str, str]] = []
        for a in re.finditer(r"^[ \t]*IP(v6)? address:[ \t]*(\S+)", block, re.M | re.I):
            addrs.append(("v6" if a.group(1) else "v4", a.group(2)))
        desc = _multiline(block, "Version")
        if not desc:
            pm = re.search(
                r"^[ \t]*Platform:[ \t]*(.*?),[ \t]*Capabilities:", block, re.M
            )
            desc = pm.group(1).strip() if pm else None
        out.append(
            Neighbor(
                local_port=m.group(1),
                remote_name=_strip_domain(dev),
                remote_port=m.group(2),
                remote_ip=_pick_ip(addrs),
                remote_desc=desc,
            )
        )
    return out


def parse_hostname(text: str) -> str:
    m = re.search(r"^[ \t]*hostname[ \t]+(\S+)", text or "", re.M)
    if not m:
        raise ValueError("no 'hostname' line found")
    return m.group(1)
