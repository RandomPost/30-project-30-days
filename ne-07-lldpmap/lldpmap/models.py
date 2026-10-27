from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Neighbor:
    """One LLDP (or CDP) neighbour as seen from the local device.

    `local_port` is the local interface name exactly as the device prints it.
    `remote_name` is the neighbour's system name (hostname) with any domain suffix
    removed. `remote_port` is the neighbour's port id/description as printed.
    `remote_ip` is the neighbour's management address (IPv4 preferred) or None.
    `remote_desc` is the neighbour's system description (used to guess the vendor)."""

    local_port: str
    remote_name: str
    remote_port: str
    remote_ip: Optional[str] = None
    remote_desc: Optional[str] = None
