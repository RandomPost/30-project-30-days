"""Vendor parsers behind one interface. See base.py for the contract."""

from __future__ import annotations

from types import ModuleType
from typing import Optional

from lldpmap.parsers import eos, frr, ios

PARSERS: dict[str, ModuleType] = {m.VENDOR: m for m in (frr, eos, ios)}


def get(vendor: str) -> ModuleType:
    try:
        return PARSERS[vendor]
    except KeyError:
        raise ValueError(
            f"unknown vendor {vendor!r}; choose from {', '.join(sorted(PARSERS))}"
        ) from None


def guess_vendor(description: Optional[str], default: str) -> str:
    """Pick a vendor from an LLDP system description, else `default`."""
    text = (description or "").lower()
    if "arista" in text or "eos" in text.split():
        return "eos"
    if "cisco" in text:
        return "ios"
    return default
