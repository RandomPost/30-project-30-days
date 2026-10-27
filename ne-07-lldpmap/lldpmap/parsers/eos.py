"""Arista EOS LLDP parser (text form of ``show lldp neighbors detail``).

The JSON form (``| json``) was not chosen: its schema could not be verified against
Arista documentation, whereas the text layout is documented and stable.
"""

from __future__ import annotations

import re
from typing import Optional

from lldpmap.models import Neighbor

VENDOR = "eos"
NEIGHBOR_COMMAND = "show lldp neighbors detail"
HOSTNAME_COMMAND = "show hostname"

_IFACE_RE = re.compile(
    r"^Interface\s+(\S.*?)\s+detected\s+(\d+)\s+LLDP neighbors?", re.I
)
_NEIGH_RE = re.compile(r"^\s*Neighbor\s+(\S+?)/(.*?),\s+age\b", re.I)
_FIELD_RE = re.compile(r"^\s*(?:-\s+)?([A-Za-z0-9.][A-Za-z0-9. ]*?)\s*:\s*(.*?)\s*$")
_MAC_RE = re.compile(
    r"^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$|^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I
)


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return value.strip()


def _short(name: str) -> str:
    """Strip a domain suffix, but leave MAC addresses and IP literals untouched."""
    if _MAC_RE.match(name) or re.match(r"^[\d.]+$", name) or ":" in name:
        return name
    return name.split(".", 1)[0]


def _build(local_port: str, f: dict, v4: list, v6: list) -> Optional[Neighbor]:
    chassis = _unquote(f.get("chassis id", ""))
    port_id = _unquote(f.get("port id", ""))
    port_desc = _unquote(f.get("port description", ""))
    sysname = _unquote(f.get("system name", ""))
    name = _short(sysname) if sysname else chassis
    if not name:
        return None
    # A MAC-typed port id is useless to humans; prefer the description if there is one.
    if port_desc and (not port_id or _MAC_RE.match(port_id)):
        remote_port = port_desc
    else:
        remote_port = port_id or port_desc
    ip = v4[0] if v4 else (v6[0] if v6 else None)
    desc = _unquote(f.get("system description", "")) or None
    return Neighbor(local_port, name, remote_port, ip, desc)


def parse_neighbors(text: str) -> list[Neighbor]:
    if not text or not text.strip():
        return []
    result: list[Neighbor] = []
    local_port: Optional[str] = None
    saw_header = False
    cur: Optional[dict] = None
    v4: list = []
    v6: list = []
    subtype = ""

    def flush() -> None:
        nonlocal cur, v4, v6
        if cur is not None and local_port is not None:
            n = _build(local_port, cur, v4, v6)
            if n:
                result.append(n)
        cur, v4, v6 = None, [], []

    for line in text.splitlines():
        m = _IFACE_RE.match(line.strip())
        if m:
            flush()
            local_port = m.group(1)
            saw_header = True
            continue
        if local_port is None:
            continue
        m = _NEIGH_RE.match(line)
        if m:
            flush()
            cur = {}
            continue
        if cur is None:
            continue
        m = _FIELD_RE.match(line)
        if not m:
            continue
        key, val = m.group(1).strip().lower(), m.group(2)
        if key == "management address subtype":
            subtype = val.lower()
        elif key == "management address":
            addr = _unquote(val)
            if addr:
                if "ipv6" in subtype or ":" in addr:
                    v6.append(addr)
                elif "ipv4" in subtype or re.match(r"^\d+\.\d+\.\d+\.\d+$", addr):
                    v4.append(addr)
        elif key not in cur:
            cur[key] = val
    flush()
    if not saw_header:
        raise ValueError("not 'show lldp neighbors detail' output from Arista EOS")
    return result


def parse_hostname(text: str) -> str:
    for line in (text or "").splitlines():
        m = re.match(r"^\s*Hostname\s*:\s*(\S+)", line, re.I)
        if m:
            return _short(m.group(1))
    for line in (text or "").splitlines():
        m = re.match(r"^\s*FQDN\s*:\s*(\S+)", line, re.I)
        if m:
            return _short(m.group(1))
    raise ValueError("not 'show hostname' output from Arista EOS")
