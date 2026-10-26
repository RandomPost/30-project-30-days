"""Pydantic schema for the source of truth. Field-level rules only; rules that
need the whole inventory (duplicate IPs, VLAN mismatches) are in validate.py."""

from __future__ import annotations

import ipaddress
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _ipv4_interface(value: str) -> str:
    try:
        iface = ipaddress.IPv4Interface(value)
    except ValueError as exc:
        raise ValueError(
            f"{value!r} is not an IPv4 address with prefix length"
        ) from exc
    if "/" not in str(value):
        raise ValueError(f"{value!r} needs a prefix length, e.g. 10.0.0.1/24")
    return str(iface)


class Vlan(Strict):
    id: int = Field(ge=1, le=4094)
    name: str = Field(pattern=r"^[A-Za-z0-9_-]{1,32}$")


class Interface(Strict):
    name: str
    description: Optional[str] = None
    ip: Optional[str] = None
    mode: Literal["routed", "access", "trunk", "svi"] = "routed"
    vlan: Optional[int] = Field(default=None, ge=1, le=4094)
    trunk_vlans: list[int] = Field(default_factory=list)
    ospf_area: Optional[int] = Field(default=None, ge=0)
    ospf_cost: Optional[int] = Field(default=None, ge=1, le=65535)
    ospf_hello: Optional[int] = Field(default=None, ge=1, le=65535)
    ospf_dead: Optional[int] = Field(default=None, ge=1, le=65535)
    ospf_passive: bool = False
    shutdown: bool = False

    @field_validator("ip")
    @classmethod
    def _ip(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else _ipv4_interface(v)

    @field_validator("trunk_vlans")
    @classmethod
    def _trunk_range(cls, v: list[int]) -> list[int]:
        for vid in v:
            if not 1 <= vid <= 4094:
                raise ValueError(f"VLAN id {vid} out of range 1-4094")
        return sorted(set(v))

    @model_validator(mode="after")
    def _mode_rules(self) -> "Interface":
        if self.mode == "access" and self.vlan is None:
            raise ValueError(f"{self.name}: access port needs 'vlan'")
        if self.mode == "trunk" and not self.trunk_vlans:
            raise ValueError(f"{self.name}: trunk port needs 'trunk_vlans'")
        if self.mode == "svi" and (self.vlan is None or self.ip is None):
            raise ValueError(f"{self.name}: svi needs 'vlan' and 'ip'")
        if self.mode in ("access", "trunk") and self.ip is not None:
            raise ValueError(f"{self.name}: {self.mode} port cannot have an ip")
        if self.mode != "trunk" and self.trunk_vlans:
            raise ValueError(f"{self.name}: 'trunk_vlans' only applies to trunk ports")
        has_ospf_opts = (
            self.ospf_cost or self.ospf_hello or self.ospf_dead or self.ospf_passive
        )
        if has_ospf_opts and self.ospf_area is None:
            raise ValueError(f"{self.name}: ospf options need 'ospf_area'")
        if (self.ospf_hello is None) != (self.ospf_dead is None):
            raise ValueError(f"{self.name}: set ospf_hello and ospf_dead together")
        if self.ospf_hello and self.ospf_dead and self.ospf_dead <= self.ospf_hello:
            raise ValueError(f"{self.name}: ospf_dead must exceed ospf_hello")
        if self.mode in ("routed", "trunk") and self.vlan is not None:
            raise ValueError(f"{self.name}: 'vlan' not allowed on {self.mode} port")
        return self


class Device(Strict):
    name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9-]{0,62}$")
    platform: Literal["ios", "frr"]
    role: str = "router"
    loopback: Optional[str] = None
    interfaces: list[Interface] = Field(default_factory=list)

    @field_validator("loopback")
    @classmethod
    def _lo(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else _ipv4_interface(v)

    @model_validator(mode="after")
    def _unique_ifaces(self) -> "Device":
        names = [i.name for i in self.interfaces]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise ValueError(f"{self.name}: duplicate interface names {dupes}")
        return self


class Link(Strict):
    a: str  # "device:interface"
    b: str

    @field_validator("a", "b")
    @classmethod
    def _end(cls, v: str) -> str:
        if v.count(":") != 1 or not all(v.split(":")):
            raise ValueError(f"link end {v!r} must look like 'device:interface'")
        return v


class Site(Strict):
    name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9-]{0,30}$")
    vlans: list[Vlan] = Field(default_factory=list)
    devices: list[Device]
    links: list[Link] = Field(default_factory=list)


class Inventory(Strict):
    sites: list[Site]
