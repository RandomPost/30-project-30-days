"""Crafted, deterministic captures for tests and demos. Everything here is synthetic."""

from __future__ import annotations

import base64
import random
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, wrpcap

T0 = 1_700_000_000.0
CLIENT_MAC, SERVER_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02"


def _eth() -> Ether:
    return Ether(src=CLIENT_MAC, dst=SERVER_MAC)


def _stamp(pkt, ts: float):
    pkt.time = ts
    return pkt


def tcp_session(
    client: str,
    server: str,
    sport: int,
    dport: int,
    t: float,
    data: int = 300,
    retransmit_data: bool = False,
) -> list:
    """A normal handshake, one request, one response, and a FIN exchange."""
    c, s = 1000, 5000
    out = [
        _eth()
        / IP(src=client, dst=server)
        / TCP(sport=sport, dport=dport, flags="S", seq=c),
        _eth()
        / IP(src=server, dst=client)
        / TCP(sport=dport, dport=sport, flags="SA", seq=s, ack=c + 1),
        _eth()
        / IP(src=client, dst=server)
        / TCP(sport=sport, dport=dport, flags="A", seq=c + 1, ack=s + 1),
        _eth()
        / IP(src=client, dst=server)
        / TCP(sport=sport, dport=dport, flags="PA", seq=c + 1, ack=s + 1)
        / (b"G" * 100),
    ]
    if retransmit_data:
        out.append(
            _eth()
            / IP(src=client, dst=server)
            / TCP(sport=sport, dport=dport, flags="PA", seq=c + 1, ack=s + 1)
            / (b"G" * 100)
        )
    out += [
        _eth()
        / IP(src=server, dst=client)
        / TCP(sport=dport, dport=sport, flags="PA", seq=s + 1, ack=c + 101)
        / (b"R" * data),
        _eth()
        / IP(src=client, dst=server)
        / TCP(sport=sport, dport=dport, flags="FA", seq=c + 101, ack=s + 1 + data),
        _eth()
        / IP(src=server, dst=client)
        / TCP(sport=dport, dport=sport, flags="FA", seq=s + 1 + data, ack=c + 102),
    ]
    for i, pkt in enumerate(out):
        _stamp(pkt, t + i * 0.01)
    return out


def dns_exchange(
    client: str,
    resolver: str,
    name: str,
    t: float,
    rcode: int = 0,
    qtype: str = "A",
    sport: int = 40000,
) -> list:
    q = (
        _eth()
        / IP(src=client, dst=resolver)
        / UDP(sport=sport, dport=53)
        / DNS(id=sport, rd=1, qd=DNSQR(qname=name, qtype=qtype))
    )
    flat = {"id": sport, "qr": 1, "rd": 1, "ra": 1, "rcode": rcode}
    question = DNSQR(qname=name, qtype=qtype)
    if rcode == 0 and qtype == "A":
        reply = DNS(
            **flat, qd=question, an=DNSRR(rrname=name, type="A", rdata="198.51.100.7")
        )
    else:
        reply = DNS(**flat, qd=question)
    r = _eth() / IP(src=resolver, dst=client) / UDP(sport=53, dport=sport) / reply
    return [_stamp(q, t), _stamp(r, t + 0.02)]


def benign(seed: int = 1) -> list:
    """Three clients browsing, a few DNS lookups (one NXDOMAIN), a ping."""
    rng = random.Random(seed)
    pkts: list = []
    clients = ["192.168.1.20", "192.168.1.21", "192.168.1.22"]
    servers = [("203.0.113.10", 443), ("203.0.113.11", 80), ("203.0.113.12", 443)]
    for i in range(30):
        host, (srv, port) = rng.choice(clients), rng.choice(servers)
        pkts += tcp_session(
            host, srv, 50000 + i, port, T0 + i * 2.0, data=rng.choice([200, 1200, 4000])
        )
    for i, name in enumerate(
        [
            "www.example.com",
            "mail.example.com",
            "cdn.example.net",
            "nothere.example.org",
        ]
    ):
        pkts += dns_exchange(
            clients[0],
            "192.168.1.1",
            name,
            T0 + 5 + i * 7,
            rcode=3 if name.startswith("nothere") else 0,
            sport=41000 + i,
        )
    ping = _eth() / IP(src=clients[1], dst="192.168.1.1") / ICMP(type=8, id=1, seq=1)
    pong = _eth() / IP(src="192.168.1.1", dst=clients[1]) / ICMP(type=0, id=1, seq=1)
    pkts += [_stamp(ping, T0 + 20), _stamp(pong, T0 + 20.001)]
    return pkts


def syn_scan(
    scanner: str = "203.0.113.50",
    target: str = "192.168.1.10",
    ports: int = 200,
    t: float = T0 + 10,
    seed: int = 2,
) -> list:
    """What `nmap -sS` looks like on the wire: bare SYNs to many ports, RST for
    closed ones, SYN-ACK then RST for the few open ones."""
    rng = random.Random(seed)
    open_ports = {22, 80, 139}
    order = list(range(1, ports + 1))
    rng.shuffle(order)
    sport = 54321
    pkts = []
    for i, port in enumerate(order):
        ts = t + i * 0.02
        syn = (
            _eth()
            / IP(src=scanner, dst=target)
            / TCP(sport=sport, dport=port, flags="S", seq=777, window=1024)
        )
        if port in open_ports:
            reply = (
                _eth()
                / IP(src=target, dst=scanner)
                / TCP(sport=port, dport=sport, flags="SA", seq=9000, ack=778)
            )
            rst = (
                _eth()
                / IP(src=scanner, dst=target)
                / TCP(sport=sport, dport=port, flags="R", seq=778)
            )
            pkts += [
                _stamp(syn, ts),
                _stamp(reply, ts + 0.001),
                _stamp(rst, ts + 0.002),
            ]
        else:
            reply = (
                _eth()
                / IP(src=target, dst=scanner)
                / TCP(sport=port, dport=sport, flags="RA", seq=0, ack=778)
            )
            pkts += [_stamp(syn, ts), _stamp(reply, ts + 0.001)]
    return pkts


def host_sweep(
    scanner: str = "203.0.113.60", port: int = 445, hosts: int = 60, t: float = T0 + 12
) -> list:
    """Bare SYNs to one port across a /24 and nobody answering."""
    return [
        _stamp(
            _eth()
            / IP(src=scanner, dst=f"192.168.1.{i}")
            / TCP(sport=44444, dport=port, flags="S", seq=1),
            t + i * 0.05,
        )
        for i in range(1, hosts + 1)
    ]


def dns_tunnel(
    client: str = "192.168.1.30",
    domain: str = "t.tunnel-example.net",
    queries: int = 60,
    t: float = T0 + 15,
    seed: int = 3,
) -> list:
    """TXT queries whose names carry base32 data, like iodine or dnscat2 do."""
    rng = random.Random(seed)
    pkts = []
    for i in range(queries):
        blob = base64.b32encode(rng.randbytes(30)).decode().rstrip("=").lower()
        name = (
            f"{blob[:30]}.{blob[30:]}.{domain}"
            if len(blob) > 30
            else f"{blob}.{domain}"
        )
        pkts += dns_exchange(
            client, "192.168.1.1", name, t + i * 0.3, qtype="TXT", sport=42000 + i
        )
    return pkts


def write(path: str | Path, packets: list) -> str:
    wrpcap(str(path), sorted(packets, key=lambda p: float(p.time)))
    return str(path)


def make_samples(directory: str | Path) -> dict[str, str]:
    """Write benign.pcap, scan.pcap, sweep.pcap, tunnel.pcap and mixed.pcap."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    sets = {
        "benign": benign(),
        "scan": benign() + syn_scan(),
        "sweep": benign() + host_sweep(),
        "tunnel": benign() + dns_tunnel(),
        "mixed": benign() + syn_scan() + host_sweep() + dns_tunnel(),
    }
    return {name: write(d / f"{name}.pcap", pkts) for name, pkts in sets.items()}
