"""Read one device's neighbour table. The only module that talks to the network."""

from __future__ import annotations

from typing import Protocol

from lldpmap import parsers
from lldpmap.models import Neighbor

DEVICE_TYPES = {"frr": "linux", "eos": "arista_eos", "ios": "cisco_ios"}


class CollectError(Exception):
    """The device could not be read; the message says why in one line."""


class Collector(Protocol):
    def collect(self, host: str, vendor: str) -> tuple[str, list[Neighbor]]:
        """Return (hostname, neighbours) for the device at `host`."""
        ...


def merge(*lists: list[Neighbor]) -> list[Neighbor]:
    seen, out = set(), []
    for lst in lists:
        for n in lst:
            key = (n.local_port, n.remote_name, n.remote_port)
            if key not in seen:
                seen.add(key)
                out.append(n)
    return out


class NetmikoCollector:
    def __init__(self, user: str, password: str, timeout: int = 20):
        self._user, self._password, self._timeout = user, password, timeout

    def collect(self, host: str, vendor: str) -> tuple[str, list[Neighbor]]:
        from netmiko import ConnectHandler
        from netmiko.exceptions import (
            NetmikoAuthenticationException,
            NetmikoTimeoutException,
        )

        parser = parsers.get(vendor)
        try:
            with ConnectHandler(
                device_type=DEVICE_TYPES[vendor],
                host=host,
                username=self._user,
                password=self._password,
                conn_timeout=self._timeout,
                auth_timeout=self._timeout,
            ) as conn:
                run = lambda cmd: conn.send_command(cmd, read_timeout=self._timeout)
                hostname = parser.parse_hostname(run(parser.HOSTNAME_COMMAND))
                neighbors = parser.parse_neighbors(run(parser.NEIGHBOR_COMMAND))
                if hasattr(parser, "CDP_COMMAND"):
                    neighbors = merge(
                        neighbors, parser.parse_cdp_neighbors(run(parser.CDP_COMMAND))
                    )
        except NetmikoAuthenticationException:
            raise CollectError("authentication failed") from None
        except NetmikoTimeoutException:
            raise CollectError(f"timed out connecting to {host}") from None
        except (OSError, ValueError) as exc:
            raise CollectError(f"{host}: {exc}") from None
        return hostname, neighbors
