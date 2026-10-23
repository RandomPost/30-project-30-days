"""Stream a capture and reduce each packet to a Pkt. Memory stays flat on big files."""

from __future__ import annotations

import contextlib
import gzip
import shutil
import tempfile
from pathlib import Path
from typing import Iterator

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, IPv6, PcapReader
from scapy.layers.inet6 import _ICMPv6, _IPv6ExtHdr

from .models import Dns, Pkt

QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
    10: "NULL",
    65: "HTTPS",
}


def _dns(layer: DNS) -> Dns | None:
    q = layer.qd
    if isinstance(q, list):  # Scapy 2.6+ keeps a list of questions
        q = q[0] if q else None
    if q is None or not hasattr(q, "qname"):
        return None
    name = (
        q.qname.decode("ascii", "replace")
        if isinstance(q.qname, bytes)
        else str(q.qname)
    )
    return Dns(
        qname=name.rstrip(".").lower(),
        qtype=QTYPES.get(q.qtype, str(q.qtype)),
        is_response=bool(layer.qr),
        rcode=int(layer.rcode),
    )


def summarize_packet(p) -> Pkt | None:
    """One Scapy packet -> Pkt, or None for frames with nothing we analyse."""
    ts, length = float(p.time), len(p)
    if p.haslayer(ARP):
        a = p[ARP]
        return Pkt(ts, length, a.psrc, a.pdst, "arp")
    if p.haslayer(IP):
        ip = p[IP]
        src, dst = ip.src, ip.dst
        l3_payload = (ip.len if ip.len is not None else len(ip)) - (ip.ihl or 5) * 4
    elif p.haslayer(IPv6):
        ip = p[IPv6]
        src, dst = ip.src, ip.dst
        l3_payload = ip.plen if ip.plen is not None else len(ip.payload)
    else:
        return Pkt(ts, length, None, None, "other")
    # Look at the layer directly under IP (past IPv6 extension headers), not at any
    # layer anywhere in the frame: an ICMP error quotes the offending packet.
    inner = ip.payload
    while isinstance(inner, _IPv6ExtHdr):
        inner = inner.payload
    if isinstance(inner, TCP):
        return Pkt(
            ts,
            length,
            src,
            dst,
            "tcp",
            inner.sport,
            inner.dport,
            int(inner.flags),
            inner.seq,
            max(0, l3_payload - (inner.dataofs or 5) * 4),
        )
    if isinstance(inner, UDP):
        dns = _dns(inner[DNS]) if inner.haslayer(DNS) else None
        return Pkt(
            ts,
            length,
            src,
            dst,
            "udp",
            inner.sport,
            inner.dport,
            payload=max(0, (inner.len if inner.len is not None else len(inner)) - 8),
            dns=dns,
        )
    if isinstance(inner, ICMP):
        return Pkt(ts, length, src, dst, "icmp", icmp_type=int(inner.type))
    if isinstance(inner, _ICMPv6):
        return Pkt(
            ts, length, src, dst, "icmp6", icmp_type=int(getattr(inner, "type", -1))
        )
    if p.haslayer(IP) and ip.proto == 2:
        return Pkt(ts, length, src, dst, "igmp")
    return Pkt(ts, length, src, dst, "other")


@contextlib.contextmanager
def _opened(path: str):
    """Yield a path Scapy can read, unzipping .gz to a temp file first."""
    if not path.endswith(".gz"):
        yield path
        return
    with tempfile.NamedTemporaryFile(suffix=Path(path[:-3]).suffix, delete=True) as tmp:
        with gzip.open(path, "rb") as src:
            shutil.copyfileobj(src, tmp)
        tmp.flush()
        yield tmp.name


def read_packets(path: str) -> Iterator[Pkt]:
    """Yield a Pkt per packet in a pcap or pcapng file (optionally gzipped)."""
    with _opened(path) as real:
        reader = PcapReader(real)
        try:
            for p in reader:
                pkt = summarize_packet(p)
                if pkt is not None:
                    yield pkt
        finally:
            reader.close()
