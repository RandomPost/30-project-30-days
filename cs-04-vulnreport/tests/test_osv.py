import httpx
import pytest

from conftest import FakeOsv
from vulnreport.cache import Cache
from vulnreport.models import Dep
from vulnreport.osv import MAX_RETRIES, OsvClient, OsvError

JINJA = Dep("jinja2", "2.4.1", "PyPI")


def client(fake, cache=None, sleeps=None):
    http = httpx.Client(base_url="https://api.osv.dev", transport=fake.transport())
    sleeps = sleeps if sleeps is not None else []
    return OsvClient(cache or Cache(None), http, sleep=sleeps.append), sleeps


def test_batch_query_returns_ids():
    c, _ = client(FakeOsv())
    ids = c.vuln_ids([JINJA, Dep("requests", "2.31.0", "PyPI")])
    assert ids[JINJA] == ["GHSA-test-high-0001", "GHSA-test-mod-0002"]
    assert ids[Dep("requests", "2.31.0", "PyPI")] == []


def test_cache_avoids_second_network_call(tmp_path):
    fake = FakeOsv()
    cache = Cache(tmp_path)
    client(fake, cache)[0].vuln_ids([JINJA])
    first = len(fake.calls)
    client(fake, cache)[0].vuln_ids([JINJA])
    assert len(fake.calls) == first


def test_cache_expires(tmp_path):
    now = [1000.0]
    cache = Cache(tmp_path, ttl=60, clock=lambda: now[0])
    cache.put("k", [1])
    assert cache.get("k") == [1]
    now[0] += 61
    assert cache.get("k") is None


def test_retries_429_honouring_retry_after():
    fake = FakeOsv(fail_first=2, status=429)
    c, sleeps = client(fake)
    assert c.vuln_ids([JINJA])[JINJA]
    assert sleeps == [3.0, 3.0]


def test_backoff_without_retry_after_and_gives_up():
    class Always503(FakeOsv):
        def __call__(self, request):
            self.calls.append((request.method, request.url.path))
            return httpx.Response(503)

    c, sleeps = client(Always503())
    with pytest.raises(OsvError):
        c.vuln_ids([JINJA])
    assert sleeps == [1.0, 2.0, 4.0, 8.0][: MAX_RETRIES - 1]


def test_client_error_is_not_retried():
    fake = FakeOsv()
    c, sleeps = client(fake)
    with pytest.raises(OsvError):
        c.vuln("GHSA-does-not-exist")
    assert sleeps == []
