"""Input validation. Everything a tool accepts passes through here first; pure functions."""

from __future__ import annotations

import ipaddress
import re

DEVICE_RE = re.compile(r"[a-z][a-z0-9-]{0,15}")
CHECK_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")

# Where ping_from may send probes: the lab's own address space only, never the internet.
DEFAULT_TARGET_RANGES = (
    "10.0.0.0/8",
    "172.20.0.0/16",
    "192.0.2.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "198.51.101.0/24",
    "203.0.113.0/24",
    "100.64.0.0/10",
)


class InvalidInput(ValueError):
    """Raised with a message safe to show to the model."""


def device(name: object, allowed: tuple[str, ...]) -> str:
    if not isinstance(name, str) or not DEVICE_RE.fullmatch(name):
        raise InvalidInput("device must be a short lowercase name such as 'cust'")
    if name not in allowed:
        raise InvalidInput(
            f"unknown device '{name}'; known devices: {', '.join(allowed)}"
        )
    return name


def prefix(value: object) -> str:
    """An IPv4 network in canonical CIDR form (host bits must be zero)."""
    if not isinstance(value, str) or len(value) > 18:
        raise InvalidInput("prefix must be an IPv4 CIDR string such as 203.0.113.0/24")
    try:
        net = ipaddress.IPv4Network(value, strict=True)
    except ValueError as e:
        raise InvalidInput(f"bad prefix: {e}") from None
    if str(net) != value:
        raise InvalidInput(f"write the prefix as {net}")
    return str(net)


def target(value: object, ranges: tuple[str, ...] = DEFAULT_TARGET_RANGES) -> str:
    """A single IPv4 address inside the lab address space."""
    if not isinstance(value, str) or len(value) > 15:
        raise InvalidInput("target must be a dotted-quad IPv4 address")
    try:
        addr = ipaddress.IPv4Address(value)
    except ValueError:
        raise InvalidInput(
            "target must be a dotted-quad IPv4 address, not a hostname"
        ) from None
    if str(addr) != value:
        raise InvalidInput(f"write the address as {addr}")
    if addr.is_multicast or addr.is_loopback or addr.is_unspecified:
        raise InvalidInput("multicast, loopback and 0.0.0.0 are not allowed")
    if not any(addr in ipaddress.IPv4Network(r) for r in ranges):
        raise InvalidInput("target is outside the lab address space")
    return value


def check_name(value: object, allowed: tuple[str, ...]) -> str:
    if not isinstance(value, str) or not CHECK_RE.fullmatch(value):
        raise InvalidInput("check name must be lowercase letters, digits and hyphens")
    if value not in allowed:
        raise InvalidInput(f"unknown check '{value}'; available: {', '.join(allowed)}")
    return value
