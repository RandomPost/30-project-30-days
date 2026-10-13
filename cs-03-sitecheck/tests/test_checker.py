import asyncio

import httpx
import pytest

from sitecheck.checker import check_all, normalize_domain
from sitecheck.models import TlsInfo
from sitecheck.report import to_csv, to_markdown, to_table

GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
}


def handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    if host == "good.test":
        return httpx.Response(200, headers=GOOD_HEADERS)
    if host == "bare.test":
        return httpx.Response(
            200, headers=[("set-cookie", "sid=1"), ("set-cookie", "t=2; Secure")]
        )
    if host == "slow.test":
        raise httpx.ConnectTimeout("timed out")
    return httpx.Response(404)


async def fake_tls(domain: str, timeout: float) -> TlsInfo:
    if domain == "expired.test":
        return TlsInfo("TLSv1.3", -5)
    if domain == "slow.test":
        raise asyncio.TimeoutError()
    return TlsInfo("TLSv1.3", 80)


def run(domains):
    return asyncio.run(
        check_all(domains, tls_fetcher=fake_tls, transport=httpx.MockTransport(handler))
    )


def by_domain(results):
    return {r.domain: r for r in results}


def test_good_site_gets_a():
    r = by_domain(run(["good.test"]))["good.test"]
    assert (r.grade, r.score, r.issues) == ("A", 100, [])


def test_bare_site_graded_down_with_reasons():
    r = by_domain(run(["bare.test"]))["bare.test"]
    assert r.grade in ("D", "F")
    assert any(i.check == "Cookies" for i in r.issues)
    assert any(i.check == "HSTS" for i in r.issues)


def test_unreachable_site_is_f_with_error():
    r = by_domain(run(["slow.test"]))["slow.test"]
    assert r.grade == "F" and r.error
    assert r.issues[0].check == "Reachability"


def test_expired_cert_is_f_even_with_good_headers():
    r = by_domain(run(["expired.test"]))["expired.test"]
    assert r.grade == "F"


def test_results_keep_input_order_and_normalize():
    results = run(["https://good.test/path", "bare.test"])
    assert [r.domain for r in results] == ["good.test", "bare.test"]
    assert normalize_domain(" HTTP://Example.com/x ") == "example.com"


@pytest.fixture
def results():
    return run(["good.test", "bare.test"])


def test_markdown_report(results):
    md = to_markdown(results)
    assert "| good.test | A | 100 |" in md
    assert "## bare.test" in md and "Fix:" in md


def test_csv_report(results):
    lines = to_csv(results).splitlines()
    assert lines[0] == "domain,grade,score,check,penalty,reason,fix"
    assert lines[1].startswith("good.test,A,100,,0")
    assert any(line.startswith("bare.test") and ",HSTS," in line for line in lines)


def test_table(results):
    assert "good.test" in to_table(results)
