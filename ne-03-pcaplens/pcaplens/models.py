"""Plain records shared by the reader, analyses and detectors. No Scapy objects here."""

from __future__ import annotations

from dataclasses import dataclass, field

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


@dataclass(frozen=True)
class Dns:
    qname: str  # lowercase, no trailing dot
    qtype: str  # "A", "TXT", ...
    is_response: bool
    rcode: int


@dataclass(frozen=True)
class Pkt:
    ts: float
    length: int  # bytes on the wire
    src: str | None  # IP address (ARP: protocol address); None for non-IP, non-ARP
    dst: str | None
    l4: str  # "tcp" | "udp" | "icmp" | "icmp6" | "arp" | "other"
    sport: int | None = None
    dport: int | None = None
    flags: int | None = None  # TCP flags
    seq: int | None = None
    payload: int = 0  # TCP/UDP payload bytes
    icmp_type: int | None = None
    dns: Dns | None = None


@dataclass(frozen=True)
class Finding:
    kind: str  # "port-scan" | "ping-sweep" | "dns-tunnel" | "dns-nxdomain" | "tcp-retrans"
    severity: str  # "high" | "medium" | "low"
    subject: str  # who or what: an IP address or a domain
    summary: str
    evidence: dict = field(default_factory=dict)


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}
