from __future__ import annotations

import difflib
import ipaddress
from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined

from netgen.models import Device, Inventory, Site


def _netmask(cidr: str) -> str:
    return str(ipaddress.IPv4Interface(cidr).netmask)


def _wildcard(cidr: str) -> str:
    return str(ipaddress.IPv4Interface(cidr).hostmask)


def _network(cidr: str) -> str:
    return str(ipaddress.IPv4Interface(cidr).network.network_address)


def _host(cidr: str) -> str:
    return str(ipaddress.IPv4Interface(cidr).ip)


def _env() -> Environment:
    env = Environment(
        loader=PackageLoader("netgen", "templates"),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters.update(
        netmask=_netmask, wildcard=_wildcard, network=_network, host=_host
    )
    return env


def render_device(site: Site, dev: Device) -> str:
    template = _env().get_template(f"{dev.platform}.j2")
    return template.render(site=site, dev=dev)


def render_all(inv: Inventory) -> dict[str, str]:
    """Map '<device>.cfg' to rendered text for every device in the inventory."""
    return {
        f"{dev.name}.cfg": render_device(site, dev)
        for site in inv.sites
        for dev in site.devices
    }


def diff(name: str, old: str | None, new: str) -> str:
    """Unified diff of the last rendered file against the new text ('' if equal)."""
    old_lines = [] if old is None else old.splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(
            old_lines,
            new.splitlines(keepends=True),
            fromfile="/dev/null" if old is None else f"a/{name}",
            tofile=f"b/{name}",
        )
    )


def plan(rendered: dict[str, str], out: Path) -> dict[str, tuple[str, str]]:
    """Compare against files already in `out`. Returns name -> (status, diff text)."""
    result = {}
    for name, text in sorted(rendered.items()):
        path = out / name
        old = path.read_text() if path.exists() else None
        d = diff(name, old, text)
        status = "new" if old is None else ("changed" if d else "unchanged")
        result[name] = (status, d)
    return result
