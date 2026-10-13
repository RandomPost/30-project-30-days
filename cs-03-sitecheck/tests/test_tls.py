from sitecheck.models import TlsInfo
from sitecheck.tls import evaluate_tls


def test_healthy_tls():
    assert evaluate_tls(TlsInfo("TLSv1.3", 90)) == []


def test_old_tls_version():
    (i,) = evaluate_tls(TlsInfo("TLSv1.1", 90))
    assert i.check == "TLS version"


def test_expiry_tiers():
    assert evaluate_tls(TlsInfo("TLSv1.2", 20))[0].penalty == 10
    assert evaluate_tls(TlsInfo("TLSv1.2", 3))[0].penalty == 25


def test_expired_is_fatal():
    (i,) = evaluate_tls(TlsInfo("TLSv1.3", -2))
    assert i.fatal and "2 day(s) ago" in i.reason
