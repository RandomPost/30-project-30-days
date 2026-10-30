import pytest

from labmcp import policy

DEVICES = ("cust", "isp1")


@pytest.mark.parametrize(
    "bad",
    [
        "cust;reboot",
        "cust && id",
        "$(id)",
        "cust\n",
        "../cust",
        "CUST",
        "",
        "x" * 40,
        "cust isp1",
        "-h",
        None,
        7,
        ["cust"],
    ],
)
def test_device_rejects_injection_and_junk(bad):
    with pytest.raises(policy.InvalidInput):
        policy.device(bad, DEVICES)


def test_device_must_be_known():
    with pytest.raises(policy.InvalidInput, match="known devices"):
        policy.device("core1", DEVICES)
    assert policy.device("cust", DEVICES) == "cust"


@pytest.mark.parametrize(
    "bad",
    [
        "203.0.113.0",
        "203.0.113.5/24",
        "203.0.113.0/33",
        "2001:db8::/32",
        "203.0.113.0/24; configure terminal",
        "203.0.113.0/24\nconf t",
        "0203.0.113.0/24",
        "203.0.113.0/24 json",
        "any",
        "",
        5,
    ],
)
def test_prefix_rejects(bad):
    with pytest.raises(policy.InvalidInput):
        policy.prefix(bad)


def test_prefix_accepts_canonical():
    assert policy.prefix("203.0.113.0/24") == "203.0.113.0/24"
    assert policy.prefix("203.0.113.66/32") == "203.0.113.66/32"


@pytest.mark.parametrize(
    "bad",
    [
        "8.8.8.8",
        "1.1.1.1",
        "127.0.0.1",
        "224.0.0.5",
        "0.0.0.0",
        "example.com",
        "10.1.1.1 -f",
        "-f",
        "10.1.1.1;ls",
        "10.1.1.1\n",
        "10.1.1",
        "010.1.1.1",
        "::1",
        "",
        1234,
    ],
)
def test_target_rejects(bad):
    with pytest.raises(policy.InvalidInput):
        policy.target(bad)


@pytest.mark.parametrize(
    "ok", ["10.1.1.1", "172.20.40.11", "203.0.113.66", "198.18.0.1"]
)
def test_target_accepts_lab_addresses(ok):
    assert policy.target(ok) == ok


def test_check_name():
    allowed = ("baseline", "bad-acl-name-typo")
    assert policy.check_name("baseline", allowed) == "baseline"
    for bad in ("../../etc/passwd", "baseline;ls", "nope", "", "BASELINE"):
        with pytest.raises(policy.InvalidInput):
            policy.check_name(bad, allowed)
