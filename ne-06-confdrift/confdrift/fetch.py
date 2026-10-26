from __future__ import annotations

from typing import Protocol

from confdrift.config import Device


class FetchError(Exception):
    """A device could not be read; the message says why in one line."""


class Fetcher(Protocol):
    def fetch(self, device: Device) -> str: ...


class NetmikoFetcher:
    def __init__(self, user: str, password: str, timeout: int = 20):
        self._user = user
        self._password = password
        self._timeout = timeout

    def fetch(self, device: Device) -> str:
        # Imported here so unit tests and `intended` work without a network stack.
        from netmiko import ConnectHandler
        from netmiko.exceptions import (
            NetmikoAuthenticationException,
            NetmikoTimeoutException,
        )

        try:
            with ConnectHandler(
                device_type=device.device_type,
                host=device.host,
                port=device.port,
                username=self._user,
                password=self._password,
                conn_timeout=self._timeout,
                auth_timeout=self._timeout,
            ) as conn:
                text = conn.send_command(device.command, read_timeout=self._timeout)
        except NetmikoAuthenticationException:
            raise FetchError("authentication failed") from None
        except NetmikoTimeoutException:
            raise FetchError(
                f"timed out connecting to {device.host}:{device.port}"
            ) from None
        except OSError as exc:
            raise FetchError(f"cannot reach {device.host}: {exc}") from None
        if not text.strip():
            raise FetchError("device returned an empty config")
        return text
