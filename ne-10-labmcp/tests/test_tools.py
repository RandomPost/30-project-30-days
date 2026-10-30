import pytest

from labmcp import policy, tools


def test_list_devices(cfg):
    out = tools.list_devices(cfg)
    assert out["cust"]["running"] is True and out["rogue"]["running"] is False


def test_show_routes_sends_only_read_commands(cfg, runner):
    tools.show_routes(cfg, "cust", "198.18.0.0/24")
    assert runner.vtysh_calls == [
        ("cust", "show bgp ipv4 unicast 198.18.0.0/24 json"),
        ("cust", "show ip route 198.18.0.0/24"),
    ]


def test_show_routes_without_prefix(cfg, runner):
    tools.show_routes(cfg, "isp1")
    assert runner.vtysh_calls == [("isp1", "show bgp ipv4 unicast")]


@pytest.mark.parametrize(
    "call",
    [
        lambda c: tools.show_routes(c, "cust; reload"),
        lambda c: tools.show_routes(c, "cust", "1.2.3.0/24; conf t"),
        lambda c: tools.show_interfaces(c, "nope"),
        lambda c: tools.ping_from(c, "cust", "8.8.8.8"),
        lambda c: tools.ping_from(c, "cust", "10.1.1.1 -s 65000"),
        lambda c: tools.get_config_drift(c, "../../etc"),
        lambda c: tools.run_batfish_check(c, "baseline; id"),
    ],
)
def test_bad_input_never_reaches_the_lab(cfg, runner, call):
    with pytest.raises(policy.InvalidInput):
        call(cfg)
    assert runner.vtysh_calls == [] and runner.pings == []


def test_ping_passes_validated_target(cfg, runner):
    tools.ping_from(cfg, "cust", "10.1.1.1")
    assert runner.pings == [("cust", "10.1.1.1")]


def test_config_drift_in_sync_on_real_config(cfg):
    out = tools.get_config_drift(cfg, "cust")
    assert out["in_sync"] and out["drift"] == []


def test_config_drift_unknown_design_file(cfg):
    with pytest.raises(policy.InvalidInput, match="no intended config"):
        tools.get_config_drift(cfg, "isp1")


def test_batfish_unreachable_is_reported_not_raised(cfg):
    cfg.batfish_host = "127.0.0.1"
    out = tools.run_batfish_check(cfg, "bad-acl-name-typo")
    assert out["ran"] is False and "not reachable" in out["error"]


def test_batfish_check_names_come_from_changes_dir(cfg):
    assert cfg.checks() == ("baseline", "bad-acl-name-typo")
