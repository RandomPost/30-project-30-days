import json

from netplan.cli import main


def test_info_json(capsys):
    assert main(["info", "10.0.0.0/31", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["usable_hosts"] == 2 and data[0]["broadcast"] is None


def test_info_table_mentions_host_bits_note(capsys):
    assert main(["info", "192.168.1.5/24"]) == 0
    out = capsys.readouterr().out
    assert "192.168.1.254" in out and "host bits" in out


def test_vlsm_json_and_file_input(tmp_path, capsys):
    f = tmp_path / "req.txt"
    f.write_text("# comment\nSales=100\nEng=50  # trailing\n")
    assert main(["vlsm", "192.168.10.0/24", "-f", str(f), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [a["subnet"] for a in data["allocations"]] == [
        "192.168.10.0/25",
        "192.168.10.128/26",
    ]
    assert data["free"] == ["192.168.10.192/26"]


def test_vlsm_table(capsys):
    assert main(["vlsm", "192.168.10.0/24", "Sales=100", "Link=2"]) == 0
    out = capsys.readouterr().out
    assert "192.168.10.0/25" in out and "Unallocated space" in out


def test_vlsm_error_exit_code(capsys):
    assert main(["vlsm", "10.0.0.0/30", "a=100"]) == 2
    assert "error:" in capsys.readouterr().err
    assert main(["vlsm", "10.0.0.0/24"]) == 2


def test_overlap_exit_codes(capsys):
    assert main(["overlap", "10.0.0.0/24", "10.0.1.0/24"]) == 0
    assert "no overlaps" in capsys.readouterr().out
    assert main(["overlap", "10.0.0.0/8", "10.1.0.0/16"]) == 1


def test_overlap_from_file_json(tmp_path, capsys):
    f = tmp_path / "subnets.txt"
    f.write_text("a=10.0.0.0/24\nb=10.0.0.128/25\n")
    assert main(["overlap", "-f", str(f), "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data[0]["outer_label"] == "a" and data[0]["inner"] == "10.0.0.128/25"


def test_bad_input_is_a_clean_error(capsys):
    assert main(["info", "not-a-cidr"]) == 2
    assert "invalid network" in capsys.readouterr().err
    assert main(["overlap", "-f", "/nonexistent/file"]) == 2
