import pytest

from netgen.loader import SourceError, load, parse
from netgen.validate import validate

BASE = """
sites:
- name: s1
  vlans:
  - {id: 10, name: users}
  - {id: 20, name: voice}
  devices:
  - name: s1-sw1
    platform: ios
    interfaces:
    - {name: Gi0/1, mode: access, vlan: 10}
    - {name: Gi0/2, mode: trunk, trunk_vlans: [10, 20]}
    - {name: Vlan10, mode: svi, vlan: 10, ip: 10.1.1.1/24}
  - name: s1-sw2
    platform: ios
    interfaces:
    - {name: Gi0/2, mode: trunk, trunk_vlans: [10, 20]}
    - {name: Gi0/3, ip: 10.1.9.1/30}
  links:
  - {a: "s1-sw1:Gi0/2", b: "s1-sw2:Gi0/2"}
"""


def problems(text):
    return validate(parse(text))


def test_base_is_clean():
    assert problems(BASE) == []


def test_real_source_is_clean():
    from tests.conftest import ROOT

    assert validate(load(ROOT / "data" / "sites.yml")) == []


def test_duplicate_ip_across_devices():
    bad = BASE.replace("10.1.9.1/30", "10.1.1.1/24")
    out = problems(bad)
    assert any(
        "duplicate IP 10.1.1.1" in p and "s1-sw1" in p and "s1-sw2" in p for p in out
    )


def test_duplicate_ip_across_sites():
    other = BASE.replace("s1", "s2")
    text = BASE + other.split("sites:\n", 1)[1]
    out = problems(text)
    assert any("duplicate IP" in p for p in out)


def test_same_subnet_twice_on_one_device():
    bad = BASE.replace(
        "- {name: Vlan10, mode: svi, vlan: 10, ip: 10.1.1.1/24}",
        "- {name: Vlan10, mode: svi, vlan: 10, ip: 10.1.1.1/24}\n"
        "    - {name: Gi0/9, ip: 10.1.1.9/24}",
    )
    assert any("both in 10.1.1.0/24" in p for p in problems(bad))


def test_vlan_not_defined_on_access_port():
    bad = BASE.replace("mode: access, vlan: 10", "mode: access, vlan: 99")
    assert any("VLAN 99" in p and "does not define" in p for p in problems(bad))


def test_trunk_vlan_mismatch_between_link_ends():
    bad = BASE.replace(
        "- {name: Gi0/2, mode: trunk, trunk_vlans: [10, 20]}\n    - {name: Gi0/3",
        "- {name: Gi0/2, mode: trunk, trunk_vlans: [10]}\n    - {name: Gi0/3",
    )
    assert any("trunk VLAN mismatch" in p for p in problems(bad))


def test_mode_mismatch_between_link_ends():
    bad = BASE.replace(
        "- {name: Gi0/2, mode: trunk, trunk_vlans: [10, 20]}\n    - {name: Gi0/3",
        "- {name: Gi0/2, mode: access, vlan: 10}\n    - {name: Gi0/3",
    )
    assert any("mode mismatch" in p for p in problems(bad))


def test_access_vlan_mismatch_between_link_ends():
    bad = BASE.replace(
        '{a: "s1-sw1:Gi0/2", b: "s1-sw2:Gi0/2"}',
        '{a: "s1-sw1:Gi0/1", b: "s1-sw2:Gi0/2"}',
    ).replace(
        "- {name: Gi0/2, mode: trunk, trunk_vlans: [10, 20]}\n    - {name: Gi0/3",
        "- {name: Gi0/2, mode: access, vlan: 20}\n    - {name: Gi0/3",
    )
    assert any("access VLAN mismatch" in p for p in problems(bad))


def test_routed_link_subnet_mismatch():
    text = BASE.replace(
        '- {a: "s1-sw1:Gi0/2", b: "s1-sw2:Gi0/2"}',
        '- {a: "s1-sw1:Gi0/2", b: "s1-sw2:Gi0/2"}',
    )
    text = text.replace(
        "- {name: Gi0/1, mode: access, vlan: 10}", "- {name: Gi0/1, ip: 10.1.5.1/30}"
    )
    text = text.replace(
        "{name: Gi0/3, ip: 10.1.9.1/30}", "{name: Gi0/3, ip: 10.1.6.2/30}"
    )
    text = text.replace(
        "links:\n", 'links:\n  - {a: "s1-sw1:Gi0/1", b: "s1-sw2:Gi0/3"}\n'
    )
    assert any("subnet mismatch" in p for p in problems(text))


def test_link_to_unknown_interface_and_device():
    bad = BASE.replace('s1-sw2:Gi0/2"}', 's1-sw2:Gi0/77"}')
    assert any("not a defined interface" in p for p in problems(bad))
    bad = BASE.replace('s1-sw2:Gi0/2"}', 'ghost:Gi0/2"}')
    assert any("unknown device" in p for p in problems(bad))


def test_duplicate_vlan_id_and_name():
    bad = BASE.replace("{id: 20, name: voice}", "{id: 10, name: voice}")
    assert any("VLAN 10 defined twice" in p for p in problems(bad))
    bad = BASE.replace("{id: 20, name: voice}", "{id: 20, name: users}")
    assert any("VLAN name 'users'" in p for p in problems(bad))


def test_ospf_without_loopback():
    bad = BASE.replace("ip: 10.1.9.1/30}", "ip: 10.1.9.1/30, ospf_area: 0}")
    assert any("no loopback" in p for p in problems(bad))


def test_duplicate_device_name_across_sites():
    other = BASE.replace("name: s1\n", "name: s2\n")
    text = BASE + other.split("sites:\n", 1)[1]
    assert any("duplicate device name 's1-sw1'" in p for p in problems(text))


@pytest.mark.parametrize(
    "old,new,msg",
    [
        ("ip: 10.1.1.1/24", "ip: 10.1.1.1", "prefix length"),
        ("ip: 10.1.1.1/24", "ip: 10.1.1.999/24", "not an IPv4"),
        ("{id: 10, name: users}", "{id: 5000, name: users}", "4094"),
        ("mode: access, vlan: 10", "mode: access", "access port needs"),
        (
            "mode: trunk, trunk_vlans: [10, 20]}\n    - {name: Gi0/3",
            "mode: trunk}\n    - {name: Gi0/3",
            "trunk port needs",
        ),
        (
            "platform: ios\n    interfaces:\n    - {name: Gi0/1",
            "platform: junos\n    interfaces:\n    - {name: Gi0/1",
            "platform",
        ),
    ],
)
def test_schema_errors(old, new, msg):
    assert old in BASE
    with pytest.raises(SourceError) as exc:
        parse(BASE.replace(old, new, 1))
    assert msg in str(exc.value)


def test_unknown_field_rejected():
    with pytest.raises(SourceError, match="Extra inputs"):
        parse(BASE.replace("platform: ios", "platform: ios\n    colour: red", 1))


def test_yaml_syntax_error():
    with pytest.raises(SourceError, match="syntax"):
        parse("sites: [\n")


@pytest.mark.parametrize(
    "extra,msg",
    [
        ("ospf_cost: 5", "need 'ospf_area'"),
        ("ospf_area: 0, ospf_hello: 1", "together"),
        ("ospf_area: 0, ospf_hello: 5, ospf_dead: 3", "must exceed"),
        ("ospf_area: 0, ospf_cost: 0", "greater than or equal to 1"),
    ],
)
def test_ospf_option_rules(extra, msg):
    bad = BASE.replace("ip: 10.1.9.1/30}", "ip: 10.1.9.1/30, " + extra + "}")
    bad = bad.replace(
        "interfaces:\n    - {name: Gi0/2, mode: trunk",
        "loopback: 10.9.9.9/32\n    interfaces:\n    - {name: Gi0/2, mode: trunk",
        2,
    )
    with pytest.raises(SourceError, match=msg):
        parse(bad)
