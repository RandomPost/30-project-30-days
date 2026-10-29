#!/usr/bin/env python3
"""A tiny RPKI-to-Router (RTR, RFC 8210) cache that serves a static ROA list.

Enough of the protocol for FRR/rtrlib: answers Reset Query with the full ROA set and
Serial Query with Cache Reset (so the router asks for a full reset). Not a real
validator: there is no certificate validation, the ROAs are whatever roas.json says."""

from __future__ import annotations

import ipaddress
import json
import socketserver
import struct
import sys

SESSION_ID = 4242
SERIAL = 1
REFRESH, RETRY, EXPIRE = 30, 10, 600

SERIAL_QUERY, RESET_QUERY = 1, 2
CACHE_RESPONSE, IPV4_PREFIX, END_OF_DATA, CACHE_RESET = 3, 4, 7, 8


def header(version: int, ptype: int, field: int, length: int) -> bytes:
    return struct.pack("!BBHI", version, ptype, field, length)


def ipv4_prefix_pdu(version: int, prefix: str, max_len: int, asn: int) -> bytes:
    net = ipaddress.ip_network(prefix)
    body = struct.pack(
        "!BBBB4sI", 1, net.prefixlen, max_len, 0, net.network_address.packed, asn
    )
    return header(version, IPV4_PREFIX, 0, 8 + len(body)) + body


def end_of_data_pdu(version: int, session: int, serial: int) -> bytes:
    if version == 0:
        return header(0, END_OF_DATA, session, 12) + struct.pack("!I", serial)
    return header(version, END_OF_DATA, session, 24) + struct.pack(
        "!IIII", serial, REFRESH, RETRY, EXPIRE
    )


def full_dump(version: int, roas: list[dict]) -> bytes:
    out = header(version, CACHE_RESPONSE, SESSION_ID, 8)
    for r in roas:
        out += ipv4_prefix_pdu(version, r["prefix"], r["max_length"], r["asn"])
    return out + end_of_data_pdu(version, SESSION_ID, SERIAL)


def respond(request: bytes, roas: list[dict]) -> bytes | None:
    """The reply for one request PDU, or None if we do not answer it."""
    if len(request) < 8:
        return None
    version, ptype = request[0], request[1]
    if version not in (0, 1):
        return None
    if ptype == RESET_QUERY:
        return full_dump(version, roas)
    if ptype == SERIAL_QUERY:
        return header(version, CACHE_RESET, 0, 8)
    return None


class Handler(socketserver.BaseRequestHandler):
    roas: list[dict] = []

    def handle(self) -> None:
        while True:
            head = self.request.recv(8)
            if len(head) < 8:
                return
            length = struct.unpack("!I", head[4:8])[0]
            rest = self.request.recv(length - 8) if length > 8 else b""
            reply = respond(head + rest, self.roas)
            print(
                f"rtr: {self.client_address[0]} pdu type {head[1]} -> "
                f"{'reply' if reply else 'ignored'}",
                flush=True,
            )
            if reply:
                self.request.sendall(reply)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "/roas.json"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3323
    Handler.roas = json.load(open(path))["roas"]
    print(f"rtr: serving {len(Handler.roas)} ROAs on :{port}", flush=True)
    with Server(("0.0.0.0", port), Handler) as srv:
        srv.serve_forever()


if __name__ == "__main__":
    main()
