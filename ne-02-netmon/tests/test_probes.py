import asyncio
import socket

import pytest

from netmon.probes import (
    ICMP_ECHO,
    build_echo,
    checksum,
    icmp_available,
    icmp_probe,
    parse_reply,
    tcp_probe,
)


def test_checksum_known_vector():
    # RFC 1071 example words 0001 f203 f4f5 f6f7 -> checksum 220d
    data = bytes.fromhex("0001f203f4f5f6f7")
    assert checksum(data) == 0x220D


def test_checksum_odd_length_and_verification():
    assert checksum(b"\x01") == checksum(b"\x01\x00")
    pkt = build_echo(0x1234, 7)
    assert checksum(pkt) == 0  # a correct packet checksums to zero


def test_build_and_parse_echo():
    pkt = build_echo(0xBEEF, 42)
    assert parse_reply(pkt) == (ICMP_ECHO, 0xBEEF, 42)


def test_parse_reply_skips_ip_header_and_rejects_runts():
    ip_header = bytes([0x45]) + bytes(19)
    assert parse_reply(ip_header + build_echo(1, 2)) == (ICMP_ECHO, 1, 2)
    assert parse_reply(b"\x00\x01") is None
    assert parse_reply(b"") is None


def test_tcp_probe_success_and_closed_port():
    async def go():
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        ok = await tcp_probe("127.0.0.1", port, 1.0)
        server.close()
        await server.wait_closed()
        refused = await tcp_probe("127.0.0.1", port, 1.0)
        return ok, refused

    ok, refused = asyncio.run(go())
    assert ok.ok and 0 <= ok.latency_ms < 500
    assert not refused.ok and refused.latency_ms is None
    assert refused.error == "ConnectionRefusedError"


def test_tcp_probe_timeout(monkeypatch):
    async def hang(*_a, **_k):
        await asyncio.sleep(10)

    monkeypatch.setattr(asyncio, "open_connection", hang)
    result = asyncio.run(tcp_probe("192.0.2.1", 9, 0.05))
    assert (result.ok, result.error) == (False, "timeout")


def test_tcp_probe_dns_failure_is_a_loss_not_a_crash():
    result = asyncio.run(tcp_probe("no-such-host.invalid", 80, 2.0))
    assert not result.ok and result.error


@pytest.mark.skipif(icmp_available() is not None, reason="ICMP sockets not permitted")
def test_icmp_probe_loopback():
    result = asyncio.run(icmp_probe("127.0.0.1", 1.0))
    assert result.ok and result.latency_ms < 100


def test_icmp_probe_dns_failure():
    result = asyncio.run(icmp_probe("no-such-host.invalid", 1.0))
    assert (result.ok, result.error) == (False, "dns")
