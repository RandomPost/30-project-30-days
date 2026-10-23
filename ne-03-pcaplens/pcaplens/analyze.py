"""One-pass statistics over Pkt records. Pure: no Scapy, no I/O."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from .models import ACK, FIN, RCODES, RST, SYN, Pkt

PORT_NAMES = {
    20: "FTP",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    1900: "SSDP",
    3306: "MySQL",
    3389: "RDP",
    5353: "mDNS",
    8080: "HTTP-alt",
}


def protocol_of(p: Pkt) -> str:
    """Application label from well-known ports, else the transport protocol."""
    if p.l4 in ("tcp", "udp"):
        for port in (p.dport, p.sport):
            if port in PORT_NAMES:
                return PORT_NAMES[port]
        return p.l4.upper()
    return {"icmp": "ICMP", "icmp6": "ICMPv6", "arp": "ARP", "igmp": "IGMP"}.get(
        p.l4, "Other"
    )


@dataclass
class HostStats:
    ip: str
    tx_bytes: int = 0
    rx_bytes: int = 0
    tx_packets: int = 0
    rx_packets: int = 0

    @property
    def bytes(self) -> int:
        return self.tx_bytes + self.rx_bytes

    @property
    def packets(self) -> int:
        return self.tx_packets + self.rx_packets


@dataclass
class DnsStats:
    queries: int = 0
    responses: int = 0
    rcodes: Counter = field(default_factory=Counter)  # name -> responses
    qtypes: Counter = field(default_factory=Counter)
    top_names: Counter = field(default_factory=Counter)
    nxdomain_names: Counter = field(default_factory=Counter)
    nx_by_client: Counter = field(default_factory=Counter)
    responses_by_client: Counter = field(default_factory=Counter)

    @property
    def nxdomain_rate(self) -> float:
        return (
            self.rcodes.get("NXDOMAIN", 0) / self.responses if self.responses else 0.0
        )


@dataclass
class TcpStats:
    packets: int = 0
    syns: int = 0  # connection attempts (bare SYN, counted once per flow)
    synacks: int = 0
    resets: int = 0
    retransmissions: int = 0
    out_of_order: int = 0
    reset_pairs: Counter = field(default_factory=Counter)
    retrans_flows: Counter = field(default_factory=Counter)

    @property
    def retransmission_rate(self) -> float:
        return self.retransmissions / self.packets if self.packets else 0.0


@dataclass
class Analysis:
    packets: int = 0
    bytes: int = 0
    start: float | None = None
    end: float | None = None
    hosts: dict[str, HostStats] = field(default_factory=dict)
    conversations: Counter = field(default_factory=Counter)  # (a, b) -> bytes
    conversation_packets: Counter = field(default_factory=Counter)
    protocol_bytes: Counter = field(default_factory=Counter)
    protocol_packets: Counter = field(default_factory=Counter)
    dns: DnsStats = field(default_factory=DnsStats)
    tcp: TcpStats = field(default_factory=TcpStats)
    timeline: list[tuple[float, int, int]] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return (self.end - self.start) if self.start is not None else 0.0

    def top_hosts(self, n: int, by: str = "bytes") -> list[HostStats]:
        return sorted(self.hosts.values(), key=lambda h: (-getattr(h, by), h.ip))[:n]

    def top_conversations(self, n: int) -> list[tuple[tuple[str, str], int, int]]:
        top = sorted(self.conversations.items(), key=lambda kv: (-kv[1], kv[0]))[:n]
        return [(pair, b, self.conversation_packets[pair]) for pair, b in top]


def _flow_key(p: Pkt) -> tuple:
    return (p.src, p.sport, p.dst, p.dport)


def _reverse_key(p: Pkt) -> tuple:
    return (p.dst, p.dport, p.src, p.sport)


class _TcpTracker:
    """Retransmission, reordering and reset accounting per TCP direction."""

    def __init__(self, stats: TcpStats):
        self.stats = stats
        self.seen: dict[tuple, dict[int, int]] = defaultdict(dict)  # dir -> seq -> len
        self.max_seq: dict[tuple, int] = {}
        self.syn_flows: set[tuple] = set()

    def add(self, p: Pkt) -> None:
        s = self.stats
        s.packets += 1
        flags = p.flags or 0
        key = _flow_key(p)
        if flags & RST:
            s.resets += 1
            s.reset_pairs[f"{p.src} -> {p.dst}"] += 1  # RSTs sent, by host pair
        if flags & SYN and flags & ACK:
            s.synacks += 1
        elif flags == SYN and key not in self.syn_flows:
            self.syn_flows.add(key)
            s.syns += 1
        seq = p.seq or 0
        consumes = p.payload > 0 or flags & (SYN | FIN)
        if not consumes or flags & RST:
            return
        length = p.payload or 1  # SYN and FIN each use one sequence number
        known = self.seen[key]
        # A repeat of a segment already seen in this direction is a retransmission. A
        # new segment below the highest sequence so far arrived out of order.
        if seq in known and length <= known[seq]:
            s.retransmissions += 1
            s.retrans_flows[_pretty(p)] += 1
        else:
            if key in self.max_seq and seq < self.max_seq[key]:
                s.out_of_order += 1
            known[seq] = max(length, known.get(seq, 0))
            self.max_seq[key] = max(self.max_seq.get(key, seq), seq)


def _pretty(p: Pkt) -> str:
    return f"{p.src}:{p.sport} -> {p.dst}:{p.dport}"


def analyze(packets: Iterable[Pkt], timeline_buckets: int = 120) -> Analysis:
    a = Analysis()
    tcp = _TcpTracker(a.tcp)
    times: list[tuple[float, int]] = []
    for p in packets:
        a.packets += 1
        a.bytes += p.length
        a.start = p.ts if a.start is None else min(a.start, p.ts)
        a.end = p.ts if a.end is None else max(a.end, p.ts)
        times.append((p.ts, p.length))
        proto = protocol_of(p)
        a.protocol_bytes[proto] += p.length
        a.protocol_packets[proto] += 1
        if p.src and p.dst:
            for ip, tx in ((p.src, True), (p.dst, False)):
                h = a.hosts.setdefault(ip, HostStats(ip))
                if tx:
                    h.tx_bytes += p.length
                    h.tx_packets += 1
                else:
                    h.rx_bytes += p.length
                    h.rx_packets += 1
            pair = tuple(sorted((p.src, p.dst)))
            a.conversations[pair] += p.length
            a.conversation_packets[pair] += 1
        if p.l4 == "tcp":
            tcp.add(p)
        if p.dns is not None:
            _add_dns(a.dns, p)
    a.timeline = _bucket(times, a.start, a.end, timeline_buckets)
    return a


def _add_dns(d: DnsStats, p: Pkt) -> None:
    dns = p.dns
    d.qtypes[dns.qtype] += 1
    if dns.is_response:
        d.responses += 1
        name = RCODES.get(dns.rcode, f"RCODE{dns.rcode}")
        d.rcodes[name] += 1
        d.responses_by_client[p.dst] += 1
        if name == "NXDOMAIN":
            d.nxdomain_names[dns.qname] += 1
            d.nx_by_client[p.dst] += 1
    else:
        d.queries += 1
        d.top_names[dns.qname] += 1


def _bucket(times, start, end, n):
    if not times:
        return []
    width = max(1.0, math.ceil((end - start) / n)) if end > start else 1.0
    pk: Counter = Counter()
    by: Counter = Counter()
    for ts, length in times:
        k = int((ts - start) // width)
        pk[k] += 1
        by[k] += length
    last = max(pk)
    return [(start + k * width, pk[k], by[k]) for k in range(last + 1)]
