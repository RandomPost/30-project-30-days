import gzip

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, wrpcap

from pcaplens.models import ACK, SYN
from pcaplens.reader import read_packets, summarize_packet


def pkt(layer, ts=1.0):
    p = Ether() / layer
    p.time = ts
    return p


def test_tcp_fields_and_payload_length_ignore_ethernet_padding():
    p = pkt(
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=1234, dport=80, flags="SA", seq=77)
    )
    r = summarize_packet(p)
    assert (r.l4, r.src, r.dst, r.sport, r.dport, r.seq) == (
        "tcp",
        "10.0.0.1",
        "10.0.0.2",
        1234,
        80,
        77,
    )
    assert r.flags == SYN | ACK and r.payload == 0
    data = pkt(IP(src="1.1.1.1", dst="2.2.2.2") / TCP() / (b"x" * 50))
    assert summarize_packet(data).payload == 50


def test_dns_query_and_response_fields():
    q = pkt(
        IP(src="10.0.0.1", dst="10.0.0.9")
        / UDP(sport=5000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="Www.Example.COM.", qtype="AAAA"))
    )
    d = summarize_packet(q).dns
    assert (d.qname, d.qtype, d.is_response) == ("www.example.com", "AAAA", False)
    r = pkt(
        IP(src="10.0.0.9", dst="10.0.0.1")
        / UDP(sport=53, dport=5000)
        / DNS(qr=1, rcode=3, qd=DNSQR(qname="nope.example.com"))
    )
    d = summarize_packet(r).dns
    assert d.is_response and d.rcode == 3 and d.qtype == "A"


def test_icmp_error_quoting_a_packet_is_icmp_not_the_inner_protocol():
    inner = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=53)
    p = pkt(IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=3, code=3) / inner)
    r = summarize_packet(p)
    assert r.l4 == "icmp" and r.icmp_type == 3 and r.dns is None


def test_non_ip_frames_are_kept_as_other():
    assert summarize_packet(Ether(type=0x1234)).l4 == "other"


def test_reads_pcap_and_gzipped_pcap(tmp_path):
    frames = [pkt(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(), ts=i) for i in range(3)]
    plain = tmp_path / "a.pcap"
    wrpcap(str(plain), frames)
    gz = tmp_path / "a.pcap.gz"
    gz.write_bytes(gzip.compress(plain.read_bytes()))
    assert len(list(read_packets(str(plain)))) == 3
    assert [p.ts for p in read_packets(str(gz))] == [0.0, 1.0, 2.0]
