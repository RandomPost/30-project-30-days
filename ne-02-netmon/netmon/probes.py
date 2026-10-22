"""Probes: TCP connect and ICMP echo, both asyncio and both returning a Result."""

from __future__ import annotations

import asyncio
import os
import socket
import struct
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class Result:
    ok: bool
    latency_ms: float | None = None
    error: str | None = None


async def tcp_probe(host: str, port: int, timeout: float) -> Result:
    """Time a full TCP handshake. Any failure (refused, timeout, DNS) counts as loss."""
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except asyncio.TimeoutError:
        return Result(False, None, "timeout")
    except OSError as exc:
        return Result(False, None, exc.__class__.__name__)
    elapsed = (time.perf_counter() - start) * 1000
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return Result(True, elapsed)


ICMP_ECHO, ICMP_ECHO_REPLY = 8, 0


def checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_echo(ident: int, seq: int, payload: bytes = b"netmon-probe!") -> bytes:
    header = struct.pack("!BBHHH", ICMP_ECHO, 0, 0, ident, seq)
    csum = checksum(header + payload)
    return struct.pack("!BBHHH", ICMP_ECHO, 0, csum, ident, seq) + payload


def parse_reply(packet: bytes) -> tuple[int, int, int] | None:
    """(type, ident, seq) of an ICMP message, skipping an IPv4 header if present."""
    if packet and packet[0] >> 4 == 4:  # raw sockets include the IP header
        packet = packet[(packet[0] & 0x0F) * 4 :]
    if len(packet) < 8:
        return None
    kind, _code, _csum, ident, seq = struct.unpack("!BBHHH", packet[:8])
    return kind, ident, seq


def open_icmp_socket() -> socket.socket:
    """Unprivileged ICMP datagram socket if the kernel allows it, else a raw one."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except PermissionError:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setblocking(False)
    return sock


def icmp_available() -> str | None:
    """None if ICMP probes can run here, otherwise a human-readable reason."""
    try:
        open_icmp_socket().close()
    except OSError as exc:
        return (
            f"cannot open an ICMP socket ({exc.strerror}); run as root, set "
            "net.ipv4.ping_group_range, or use tcp: targets"
        )
    return None


_seq = 0


async def icmp_probe(host: str, timeout: float) -> Result:
    global _seq
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, family=socket.AF_INET)
    except socket.gaierror:
        return Result(False, None, "dns")
    addr = infos[0][4][0]
    _seq = (_seq + 1) & 0xFFFF
    seq, ident = _seq, os.getpid() & 0xFFFF
    sock = open_icmp_socket()
    try:
        sock.connect((addr, 0))
        start = time.perf_counter()
        await loop.sock_sendall(sock, build_echo(ident, seq))

        async def wait_reply() -> None:
            while True:
                kind, rid, rseq = parse_reply(await loop.sock_recv(sock, 1024)) or (
                    -1,
                    0,
                    0,
                )
                # Datagram ICMP sockets rewrite the identifier, so match on seq only.
                if kind == ICMP_ECHO_REPLY and rseq == seq:
                    return

        try:
            await asyncio.wait_for(wait_reply(), timeout)
        except asyncio.TimeoutError:
            return Result(False, None, "timeout")
        return Result(True, (time.perf_counter() - start) * 1000)
    except OSError as exc:
        return Result(False, None, exc.__class__.__name__)
    finally:
        sock.close()
