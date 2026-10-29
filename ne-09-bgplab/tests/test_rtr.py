"""RTR (RFC 8210) PDU tests for the local validator."""

import importlib.util
import struct
from pathlib import Path as P

spec = importlib.util.spec_from_file_location(
    "rtrd", P(__file__).parents[1] / "rtr" / "rtrd.py"
)
rtrd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rtrd)

ROAS = [{"prefix": "203.0.113.0/24", "max_length": 24, "asn": 65100}]


def pdus(data):
    i, out = 0, []
    while i < len(data):
        v, t, f, n = struct.unpack("!BBHI", data[i : i + 8])
        out.append((t, data[i + 8 : i + n]))
        i += n
    return out


def test_reset_query_returns_cache_response_prefix_and_end_of_data():
    req = rtrd.header(1, rtrd.RESET_QUERY, 0, 8)
    kinds = [t for t, _ in pdus(rtrd.respond(req, ROAS))]
    assert kinds == [rtrd.CACHE_RESPONSE, rtrd.IPV4_PREFIX, rtrd.END_OF_DATA]


def test_prefix_pdu_encodes_roa():
    req = rtrd.header(1, rtrd.RESET_QUERY, 0, 8)
    body = dict(pdus(rtrd.respond(req, ROAS)))[rtrd.IPV4_PREFIX]
    flags, plen, maxlen, _, addr, asn = struct.unpack("!BBBB4sI", body)
    assert (flags, plen, maxlen, addr, asn) == (
        1,
        24,
        24,
        bytes([203, 0, 113, 0]),
        65100,
    )


def test_serial_query_forces_cache_reset():
    req = struct.pack("!BBHII", 1, rtrd.SERIAL_QUERY, rtrd.SESSION_ID, 12, 1)
    assert pdus(rtrd.respond(req, ROAS))[0][0] == rtrd.CACHE_RESET


def test_garbage_is_ignored():
    assert rtrd.respond(b"\x09", ROAS) is None
    assert rtrd.respond(rtrd.header(7, rtrd.RESET_QUERY, 0, 8), ROAS) is None
