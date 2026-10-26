from pathlib import Path

import pytest

from netgen import render
from netgen.cli import main
from netgen.loader import load
from netgen.validate import validate

ROOT = Path(__file__).resolve().parent.parent


def run(*args):
    return main([str(a) for a in args])


def test_committed_render_matches_source():
    """rendered/ in the repo must be what the templates produce today."""
    inv = load(ROOT / "data" / "sites.yml")
    plan = render.plan(render.render_all(inv), ROOT / "rendered")
    stale = {n: s for n, (s, _) in plan.items() if s != "unchanged"}
    assert stale == {}


def test_three_sites_render_seven_devices():
    inv = load(ROOT / "data" / "sites.yml")
    assert len(inv.sites) >= 3
    assert len(render.render_all(inv)) == sum(len(s.devices) for s in inv.sites)


def test_ios_output_details():
    inv = load(ROOT / "data" / "sites.yml")
    text = render.render_all(inv)["hq-sw1.cfg"]
    assert "hostname hq-sw1" in text
    assert "vlan 10\n name users\n" in text
    assert "ip address 10.1.1.1 255.255.255.0" in text
    assert "switchport trunk allowed vlan 10,20,30" in text
    assert "network 10.1.1.0 0.0.0.255 area 0" in text


def test_frr_output_details():
    inv = load(ROOT / "data" / "sites.yml")
    text = render.render_all(inv)["hq-r1.cfg"]
    assert "ip address 10.1.0.1/30" in text
    assert "ospf router-id 10.255.1.1" in text
    assert "ip ospf network point-to-point" in text


def test_render_then_diff_is_quiet_then_shows_change(source, tmp_path, capsys):
    out = tmp_path / "out"
    assert run("-s", source, "render", "-o", out, "-q") == 0
    assert len(list(out.glob("*.cfg"))) == 7
    capsys.readouterr()

    assert run("-s", source, "diff", "-o", out, "--check") == 0
    assert "unchanged" in capsys.readouterr().out

    source.write_text(source.read_text().replace("10.1.1.1/24", "10.1.1.254/24"))
    assert run("-s", source, "diff", "-o", out, "--check") == 2
    text = capsys.readouterr().out
    assert "-" in text and "10.1.1.254" in text
    assert "changed   hq-sw1.cfg" in text

    assert run("-s", source, "render", "-o", out, "-q") == 0
    assert "10.1.1.254" in (out / "hq-sw1.cfg").read_text()


def test_dry_run_writes_nothing(source, tmp_path):
    out = tmp_path / "out"
    assert run("-s", source, "render", "-o", out, "--dry-run", "-q") == 0
    assert not out.exists()


def test_invalid_source_blocks_render(source, tmp_path, capsys):
    out = tmp_path / "out"
    source.write_text(source.read_text().replace("10.2.1.1/24", "10.1.1.1/24"))
    assert run("-s", source, "render", "-o", out) == 1
    assert "duplicate IP 10.1.1.1" in capsys.readouterr().err
    assert not out.exists()


def test_validate_command(source, capsys):
    assert run("-s", source, "validate") == 0
    assert "OK: 3 sites, 7 devices" in capsys.readouterr().out


def test_new_site_adds_fourth_site_and_it_renders(source, tmp_path, capsys):
    before = source.read_text()
    assert (
        run(
            "-s",
            source,
            "new-site",
            "--name",
            "branch-north",
            "--number",
            4,
            "--vlans",
            "users=10,voice=20,iot=70",
        )
        == 0
    )
    assert source.read_text().startswith(before)  # existing text untouched
    inv = load(source)
    assert [s.name for s in inv.sites][-1] == "branch-north"
    assert validate(inv) == []

    out = tmp_path / "out"
    assert run("-s", source, "render", "-o", out, "-q") == 0
    assert (out / "branch-north-r1.cfg").exists()
    sw = (out / "branch-north-sw1.cfg").read_text()
    assert "vlan 70\n name iot" in sw
    assert "ip address 10.4.3.1 255.255.255.0" in sw


@pytest.mark.parametrize(
    "args,msg",
    [
        (["--name", "hq", "--number", 9, "--vlans", "users=10"], "duplicate site name"),
        (["--name", "x1", "--number", 1, "--vlans", "users=10"], "duplicate IP"),
        (["--name", "x2", "--number", 9, "--vlans", "users=10x"], "bad VLAN"),
        (["--name", "x3", "--number", 999, "--vlans", "users=10"], "1-254"),
        (["--name", "x4", "--number", 9, "--vlans", "a=10,b=10"], "defined twice"),
        (["--name", "9bad", "--number", 9, "--vlans", "users=10"], "name"),
    ],
)
def test_new_site_refuses_bad_input_and_leaves_file_alone(source, capsys, args, msg):
    before = source.read_text()
    assert run("-s", source, "new-site", *args) == 1
    assert msg in capsys.readouterr().err
    assert source.read_text() == before


def test_frr_ospf_tuning_options(tmp_path):
    from netgen.loader import parse

    inv = parse("""
sites:
- name: t
  devices:
  - name: t-r1
    platform: frr
    loopback: 10.9.9.1/32
    interfaces:
    - {name: eth1, ip: 10.9.0.1/30, ospf_area: 0, ospf_cost: 10, ospf_hello: 1, ospf_dead: 3}
    - {name: eth3, ip: 192.168.9.1/24, ospf_area: 0, ospf_cost: 10, ospf_passive: true}
""")
    text = render.render_all(inv)["t-r1.cfg"]
    eth1 = text.split("interface eth1")[1].split("exit")[0]
    eth3 = text.split("interface eth3")[1].split("exit")[0]
    assert "ip ospf cost 10" in eth1 and "ip ospf hello-interval 1" in eth1
    assert "ip ospf dead-interval 3" in eth1 and "point-to-point" in eth1
    assert "ip ospf passive" in eth3 and "point-to-point" not in eth3
