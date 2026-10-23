import pytest

from pcaplens import samples
from pcaplens.analyze import analyze
from pcaplens.detect import Thresholds, detect_all, entropy, split_domain
from pcaplens.models import Pkt
from pcaplens.reader import read_packets, summarize_packet

from conftest import PUBLIC, kinds


def test_benign_traffic_raises_no_findings(run):
    assert run["benign"][2] == []


def test_syn_scan_is_flagged_with_evidence(run):
    findings = run["scan"][2]
    assert kinds(findings) == {("port-scan", "203.0.113.50")}
    f = findings[0]
    assert f.severity == "high"
    e = f.evidence
    assert (e["hosts"], e["ports"], e["probes"]) == (1, 200, 200)
    assert e["open_ports_found"] == [22, 80, 139]  # the SYN-ACKs the scanner provoked
    assert e["answered"] == 200 and e["probe_types"] == ["SYN"]
    assert "192.168.1.10" in f.summary and "200 ports" in f.summary


def test_host_sweep_is_flagged_as_a_sweep(run):
    (f,) = run["sweep"][2]
    assert (f.kind, f.subject) == ("port-scan", "203.0.113.60")
    assert "host sweep on port 445 (60 hosts)" in f.summary


def test_dns_tunnel_is_flagged_with_examples(run):
    (f,) = run["tunnel"][2]
    assert (f.kind, f.subject) == ("dns-tunnel", "tunnel-example.net")
    assert f.evidence["suspicious"] == 60 and f.evidence["clients"] == ["192.168.1.30"]
    assert f.evidence["query_types"] == {"TXT": 60}
    assert all(x.endswith(".t.tunnel-example.net") for x in f.evidence["examples"])


def test_mixed_capture_finds_all_three_and_sorts_by_severity(run):
    findings = run["mixed"][2]
    assert kinds(findings) == {
        ("port-scan", "203.0.113.50"),
        ("port-scan", "203.0.113.60"),
        ("dns-tunnel", "tunnel-example.net"),
    }
    sev = [f.severity for f in findings]
    assert sev == sorted(sev, key=["high", "medium", "low"].index)


def test_slow_scan_outside_the_window_is_not_flagged():
    pkts = [
        Pkt(i * 10.0, 60, "9.9.9.9", "10.0.0.1", "tcp", 5555, 1000 + i, 0x02, 1)
        for i in range(30)
    ]
    a = analyze(pkts)
    assert (
        detect_all(pkts, a, Thresholds(scan_window=30)) == []
    )  # only ~4 probes per 30 s
    assert len(detect_all(pkts, a, Thresholds(scan_window=600))) == 1


def test_busy_client_whose_connections_succeed_is_not_a_scan():
    pkts = []
    for i in range(40):
        pkts.append(
            Pkt(
                i * 0.1,
                60,
                "10.0.0.5",
                f"203.0.113.{i + 1}",
                "tcp",
                40000 + i,
                443,
                0x02,
                1,
            )
        )
        pkts.append(
            Pkt(
                i * 0.1 + 0.01,
                60,
                f"203.0.113.{i + 1}",
                "10.0.0.5",
                "tcp",
                443,
                40000 + i,
                0x12,
                1,
            )
        )
    assert detect_all(pkts, analyze(pkts)) == []


def test_retransmitted_syn_counts_as_one_target():
    pkts = [
        Pkt(i * 0.1, 60, "9.9.9.9", "10.0.0.1", "tcp", 5555, 80, 0x02, 1)
        for i in range(50)
    ]
    assert [f.kind for f in detect_all(pkts, analyze(pkts))] == [
        "tcp-retrans"
    ]  # no scan


@pytest.mark.parametrize("flags, kind", [(0x01, "FIN"), (0x00, "NULL"), (0x29, "XMAS")])
def test_stealth_scan_types_are_recognised(flags, kind):
    pkts = [
        Pkt(i * 0.05, 60, "9.9.9.9", "10.0.0.1", "tcp", 5555, 1000 + i, flags, 1)
        for i in range(30)
    ]
    (f,) = detect_all(pkts, analyze(pkts))
    assert f.evidence["probe_types"] == [kind]


def test_icmp_ping_sweep():
    pkts = [
        Pkt(i * 0.1, 60, "9.9.9.9", f"10.0.0.{i + 1}", "icmp", icmp_type=8)
        for i in range(30)
    ]
    (f,) = detect_all(pkts, analyze(pkts))
    assert f.kind == "ping-sweep" and f.evidence["hosts"] == 30


def test_nxdomain_storm_is_flagged():
    from pcaplens.models import Dns

    pkts = [
        Pkt(
            i,
            80,
            "10.0.0.53",
            "10.0.0.7",
            "udp",
            53,
            4000,
            dns=Dns(f"x{i}.example.org", "A", True, 3),
        )
        for i in range(30)
    ]
    findings = detect_all(pkts, analyze(pkts))
    assert [(f.kind, f.subject) for f in findings] == [("dns-nxdomain", "10.0.0.7")]


def test_retransmission_finding_needs_volume_and_rate():
    pkts = samples.tcp_session(
        "10.0.0.1", "10.0.0.2", 40000, 80, 0, retransmit_data=True
    )
    parsed = [summarize_packet(p) for p in pkts]
    assert detect_all(parsed, analyze(parsed)) == []  # one retransmission is noise
    assert [
        f.kind
        for f in detect_all(
            parsed, analyze(parsed), Thresholds(retrans_min=1, retrans_min_rate=0.01)
        )
    ] == ["tcp-retrans"]


def test_ordinary_long_hostnames_are_not_tunnels():
    from pcaplens.models import Dns

    names = [
        f"{w}-service-region-eu-west.cloudfront-example.net" for w in "abcdefghijklmnop"
    ]
    pkts = [
        Pkt(i, 80, "10.0.0.7", "10.0.0.53", "udp", 4000, 53, dns=Dns(n, "A", False, 0))
        for i, n in enumerate(names)
    ]
    assert detect_all(pkts, analyze(pkts)) == []


def test_entropy_and_domain_splitting():
    assert entropy("") == 0 and entropy("aaaa") == 0
    assert entropy("abcd") == pytest.approx(2.0)
    assert entropy("0123456789abcdef") == pytest.approx(4.0)
    assert split_domain("a.b.example.com") == ("example.com", "a.b")
    assert split_domain("x.example.co.uk") == ("example.co.uk", "x")
    assert split_domain("example.com") is None
    assert split_domain("com") is None


@pytest.mark.skipif(not PUBLIC.exists(), reason="run scripts/fetch-samples.sh")
def test_no_false_positives_on_public_wireshark_captures():
    files = sorted(PUBLIC.glob("*.pcap*"))
    assert files
    for f in files:
        pk = list(read_packets(str(f)))
        assert detect_all(pk, analyze(pk)) == [], f.name


def test_hex_encoded_labels_are_flagged_but_hyphenated_names_are_not():
    import random

    from pcaplens.models import Dns

    rng = random.Random(5)
    hexed = [f"{rng.randbytes(16).hex()}.c2.example-bad.org" for _ in range(15)]
    pkts = [
        Pkt(
            i, 80, "10.0.0.7", "10.0.0.53", "udp", 4000, 53, dns=Dns(n, "TXT", False, 0)
        )
        for i, n in enumerate(hexed)
    ]
    assert [f.kind for f in detect_all(pkts, analyze(pkts))] == ["dns-tunnel"]
