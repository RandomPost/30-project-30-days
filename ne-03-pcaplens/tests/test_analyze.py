import pytest

from pcaplens import samples
from pcaplens.analyze import analyze, protocol_of
from pcaplens.models import Pkt
from pcaplens.reader import read_packets, summarize_packet


def test_totals_and_top_talkers(run):
    pk, a, _ = run["benign"]
    assert a.packets == len(pk) and a.bytes == sum(p.length for p in pk)
    top = a.top_hosts(3, "bytes")
    assert top[0].bytes >= top[1].bytes >= top[2].bytes
    for h in a.hosts.values():
        assert h.bytes == h.tx_bytes + h.rx_bytes
    # Every packet counts once as sent and once as received.
    assert sum(h.tx_bytes for h in a.hosts.values()) == sum(
        h.rx_bytes for h in a.hosts.values()
    )


def test_top_hosts_sort_by_packets_and_conversations(run):
    _, a, _ = run["benign"]
    by_pkts = a.top_hosts(2, "packets")
    assert by_pkts[0].packets >= by_pkts[1].packets
    (pair, nbytes, npk), *_ = a.top_conversations(1)
    assert (
        nbytes == max(a.conversations.values()) and npk == a.conversation_packets[pair]
    )


def test_protocol_breakdown_by_port(run):
    _, a, _ = run["benign"]
    assert a.protocol_packets["HTTPS"] > 0 and a.protocol_packets["HTTP"] > 0
    assert a.protocol_packets["DNS"] == 8 and a.protocol_packets["ICMP"] == 2
    assert sum(a.protocol_bytes.values()) == a.bytes


@pytest.mark.parametrize(
    "p, label",
    [
        (Pkt(0, 1, "a", "b", "tcp", 50000, 22), "SSH"),
        (Pkt(0, 1, "a", "b", "udp", 53, 40000), "DNS"),
        (Pkt(0, 1, "a", "b", "tcp", 50000, 50001), "TCP"),
        (Pkt(0, 1, "a", "b", "icmp6"), "ICMPv6"),
        (Pkt(0, 1, None, None, "other"), "Other"),
    ],
)
def test_protocol_of(p, label):
    assert protocol_of(p) == label


def test_dns_stats_and_nxdomain_rate(run):
    _, a, _ = run["benign"]
    d = a.dns
    assert (d.queries, d.responses) == (4, 4)
    assert d.rcodes["NXDOMAIN"] == 1 and d.rcodes["NOERROR"] == 3
    assert d.nxdomain_rate == pytest.approx(0.25)
    assert d.nxdomain_names == {"nothere.example.org": 1}
    assert d.nx_by_client == {"192.168.1.20": 1}


def test_tcp_clean_traffic_has_no_retransmissions_or_resets(run):
    _, a, _ = run["benign"]
    assert a.tcp.retransmissions == 0 and a.tcp.resets == 0
    assert a.tcp.syns == a.tcp.synacks == 30


def test_retransmission_is_counted_once_and_attributed_to_the_flow():
    pkts = samples.tcp_session(
        "10.0.0.1", "10.0.0.2", 40000, 80, 0, retransmit_data=True
    )
    a = analyze(summarize_packet(p) for p in pkts)
    assert a.tcp.retransmissions == 1
    assert list(a.tcp.retrans_flows) == ["10.0.0.1:40000 -> 10.0.0.2:80"]
    assert a.tcp.retransmission_rate == pytest.approx(1 / a.tcp.packets)


def test_resets_and_syn_counts_from_a_scan(run):
    _, a, _ = run["scan"]
    assert a.tcp.resets == 200  # 197 closed-port RST-ACKs + 3 RSTs from the scanner
    assert a.tcp.reset_pairs["192.168.1.10 -> 203.0.113.50"] == 197
    assert a.tcp.syns - 30 == 200 and a.tcp.synacks - 30 == 3


def test_out_of_order_is_not_a_retransmission():
    def seg(seq, ts):
        return Pkt(ts, 100, "a", "b", "tcp", 1, 2, 0x10, seq, 100)

    a = analyze([seg(1100, 0), seg(1000, 1)])  # the earlier segment arrives second
    assert a.tcp.out_of_order == 1 and a.tcp.retransmissions == 0


def test_timeline_buckets_cover_the_capture(run):
    _, a, _ = run["benign"]
    assert sum(n for _, n, _ in a.timeline) == a.packets
    assert a.timeline[0][0] == a.start


def test_empty_input():
    a = analyze([])
    assert a.packets == 0 and a.duration == 0 and a.timeline == []


def test_known_real_capture_if_downloaded(request):
    from conftest import PUBLIC

    f = PUBLIC / "tcp-rst-diagnostic.pcap"
    if not f.exists():
        pytest.skip("run scripts/fetch-samples.sh")
    a = analyze(read_packets(str(f)))
    assert a.packets == 4 and a.tcp.resets >= 1
