"""TLS checks. `evaluate_tls` is pure; `fetch_tls` does the network handshake."""

from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timezone

from .models import Issue, TlsInfo

OLD_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def evaluate_tls(info: TlsInfo) -> list[Issue]:
    issues = []
    if info.version in OLD_VERSIONS:
        issues.append(
            Issue(
                "TLS version",
                20,
                f"Negotiated {info.version}, which is deprecated",
                "Disable TLS 1.0/1.1 and require TLS 1.2 or newer.",
            )
        )
    if info.days_left < 0:
        issues.append(
            Issue(
                "Certificate",
                100,
                f"Certificate expired {-info.days_left} day(s) ago",
                "Renew the certificate now.",
                fatal=True,
            )
        )
    elif info.days_left < 7:
        issues.append(
            Issue(
                "Certificate",
                25,
                f"Certificate expires in {info.days_left} day(s)",
                "Renew immediately and automate renewal (e.g. ACME).",
            )
        )
    elif info.days_left < 30:
        issues.append(
            Issue(
                "Certificate",
                10,
                f"Certificate expires in {info.days_left} days",
                "Renew soon and automate renewal (e.g. ACME).",
            )
        )
    return issues


async def fetch_tls(host: str, port: int = 443, timeout: float = 10.0) -> TlsInfo:
    """Handshake with full verification; raises on untrusted or unreachable hosts."""
    ctx = ssl.create_default_context()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout
    )
    try:
        obj = writer.get_extra_info("ssl_object")
        cert = obj.getpeercert()
        expires = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc
        )
        days = (expires - datetime.now(timezone.utc)).days
        return TlsInfo(version=obj.version() or "unknown", days_left=days)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
