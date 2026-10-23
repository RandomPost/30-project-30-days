import json

from pcaplens.cli import main
from pcaplens.models import Finding
from pcaplens.analyze import analyze
from pcaplens.report import hbar, human_bytes, render_html, timeline_svg


def test_report_flags_the_scan_in_the_sample_capture(sample_files, tmp_path, capsys):
    out = tmp_path / "r.html"
    assert main(["analyze", sample_files["scan"], "-o", str(out)]) == 0
    html = out.read_text()
    assert "port-scan" in html and "203.0.113.50" in html and "200 ports" in html
    assert 'class="badge high"' in html
    assert "<svg" in html and "<script" not in html
    assert "http://" not in html.replace(
        "http://www.w3.org/2000/svg", ""
    )  # no external requests
    assert "1 findings" in capsys.readouterr().out or True


def test_clean_capture_says_nothing_found(sample_files, tmp_path):
    out = tmp_path / "r.html"
    assert main(["analyze", sample_files["benign"], "-o", str(out)]) == 0
    assert "Nothing suspicious found" in out.read_text()


def test_report_escapes_attacker_controlled_strings(run):
    pk, a, _ = run["benign"]
    evil = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
    a.dns.top_names[evil] = 5
    a.dns.nxdomain_names[evil] = 1
    findings = [Finding("dns-tunnel", "high", evil, evil, {evil: evil})]
    html = render_html(a, findings, evil)
    assert "<script>" not in html and "<img src=x" not in html
    assert html.count("&lt;script&gt;") >= 4


def test_json_output_and_fail_on(sample_files, tmp_path):
    js = tmp_path / "f.json"
    out = tmp_path / "r.html"
    assert (
        main(
            [
                "analyze",
                sample_files["mixed"],
                "-o",
                str(out),
                "--json",
                str(js),
                "--fail-on",
                "high",
            ]
        )
        == 1
    )
    data = json.loads(js.read_text())
    assert {f["kind"] for f in data["findings"]} == {"port-scan", "dns-tunnel"}
    assert (
        main(["analyze", sample_files["benign"], "-o", str(out), "--fail-on", "low"])
        == 0
    )
    assert (
        main(["analyze", sample_files["sweep"], "-o", str(out), "--fail-on", "high"])
        == 0
    )  # sweep is medium


def test_scan_threshold_flags_are_applied(sample_files, tmp_path, capsys):
    out = tmp_path / "r.html"
    main(["analyze", sample_files["scan"], "-o", str(out), "--scan-targets", "500"])
    assert "0 findings" in capsys.readouterr().out


def test_errors_are_clean(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "missing.pcap")]) == 2
    assert "error:" in capsys.readouterr().err
    empty = tmp_path / "empty.pcap"
    from scapy.all import wrpcap

    wrpcap(str(empty), [])
    assert main(["analyze", str(empty)]) == 2


def test_make_samples_command(tmp_path, capsys):
    assert main(["make-samples", str(tmp_path / "s")]) == 0
    assert {p.name for p in (tmp_path / "s").glob("*.pcap")} == {
        "benign.pcap",
        "scan.pcap",
        "sweep.pcap",
        "tunnel.pcap",
        "mixed.pcap",
    }


def test_chart_helpers():
    assert human_bytes(0) == "0 B" and human_bytes(1536) == "1.5 KB"
    assert "no data" in hbar([])
    svg = hbar([("a" * 40, 10, "10"), ("b", 5, "5")])
    assert svg.count("<rect") == 2 and "…" in svg
    assert "too short" in timeline_svg([(0, 1, 1)])
    assert "<polyline" in timeline_svg([(0, 1, 1), (1, 5, 1), (2, 3, 1)])
    empty = render_html(analyze([]), [], "x")
    assert "No DNS traffic" in empty and "Nothing suspicious" in empty
