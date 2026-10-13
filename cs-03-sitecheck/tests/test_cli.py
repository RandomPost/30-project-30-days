import httpx

from sitecheck import cli
from sitecheck.checker import check_all
from sitecheck.models import TlsInfo


def test_no_domains_is_usage_error(capsys):
    assert cli.main([]) == 2


def test_reads_domain_file_with_comments(tmp_path):
    f = tmp_path / "d.txt"
    f.write_text("a.test  # primary\n\n# skipped\nb.test\n")
    args = cli.build_parser().parse_args(["c.test", "-f", str(f)])
    assert cli.read_domains(args) == ["c.test", "a.test", "b.test"]


def test_main_writes_reports_and_fail_below(tmp_path, monkeypatch):
    async def fake_tls(domain, timeout):
        return TlsInfo("TLSv1.3", 80)

    transport = httpx.MockTransport(lambda req: httpx.Response(200))

    async def fake_check_all(domains, **kw):
        return await check_all(domains, tls_fetcher=fake_tls, transport=transport, **kw)

    monkeypatch.setattr(cli, "check_all", fake_check_all)
    md, csv_ = tmp_path / "r.md", tmp_path / "r.csv"
    code = cli.main(
        ["x.test", "--md", str(md), "--csv", str(csv_), "--fail-below", "B"]
    )
    assert code == 1  # bare site is below B
    assert "x.test" in md.read_text() and "x.test" in csv_.read_text()
    assert cli.main(["x.test", "--fail-below", "F"]) == 0
