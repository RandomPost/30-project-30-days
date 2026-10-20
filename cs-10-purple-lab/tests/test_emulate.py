from __future__ import annotations

import json
from pathlib import Path

import pytest

from purplelab.emulate import SafetyError, check_safety, default_run_id, main, run
from purplelab.techniques import Context, Technique


def test_check_safety_requires_env_var(monkeypatch):
    monkeypatch.delenv("PURPLELAB_LAB", raising=False)
    with pytest.raises(SafetyError, match="PURPLELAB_LAB"):
        check_safety(["target"], ["target"], resolve=lambda h: ["127.0.0.1"])


def test_check_safety_requires_allowlist(monkeypatch):
    monkeypatch.setenv("PURPLELAB_LAB", "1")
    with pytest.raises(SafetyError, match="allowlist"):
        check_safety(["target"], [], resolve=lambda h: ["127.0.0.1"])


def test_check_safety_rejects_public_ip(monkeypatch):
    monkeypatch.setenv("PURPLELAB_LAB", "1")
    with pytest.raises(SafetyError, match="public"):
        check_safety(["evil"], ["evil"], resolve=lambda h: ["8.8.8.8"])


def test_check_safety_rejects_dns_name_resolving_public(monkeypatch):
    monkeypatch.setenv("PURPLELAB_LAB", "1")

    def resolve(host):
        assert host == "example.com"
        return ["93.184.216.34"]

    with pytest.raises(SafetyError, match="public"):
        check_safety(["example.com"], ["example.com"], resolve=resolve)


def test_check_safety_allows_private_and_loopback(monkeypatch):
    monkeypatch.setenv("PURPLELAB_LAB", "1")
    check_safety(
        ["target", "victim"],
        ["target", "victim"],
        resolve=lambda h: ["10.77.0.5"] if h == "target" else ["127.0.0.1"],
    )


def test_default_run_id_format():
    run_id = default_run_id()
    assert len(run_id) == 16
    assert run_id.endswith("Z")
    assert "T" in run_id


def _ok_technique(id_: str) -> Technique:
    return Technique(
        id=id_,
        name=f"name-{id_}",
        tactic="discovery",
        channel="ssh",
        description="",
        run=lambda ctx: "did the thing",
    )


def _failing_technique(id_: str) -> Technique:
    def boom(ctx):
        raise RuntimeError("host unreachable")

    return Technique(
        id=id_,
        name=f"name-{id_}",
        tactic="discovery",
        channel="ssh",
        description="",
        run=boom,
    )


def make_ctx():
    return Context(
        web_base="http://target",
        ssh_host="victim",
        ssh_port=22,
        ssh_user="labuser",
        ssh_password="pw",
        root_password="rootpw",
        ssh=lambda u, p: None,
        http=lambda *a, **k: 200,
        sleep=lambda s: None,
    )


def test_run_writes_jsonl_contract(tmp_path: Path):
    ctx = make_ctx()
    techs = [_ok_technique("T1082")]
    log_path = tmp_path / "emulation.jsonl"
    records = run(ctx, techs, log_path, pause=0, run_id="20261020T120000Z")
    assert len(records) == 1
    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    expected_keys = {
        "run_id",
        "technique_id",
        "name",
        "tactic",
        "start",
        "end",
        "ok",
        "target",
        "detail",
    }
    assert set(record.keys()) == expected_keys
    assert record["ok"] is True
    assert record["run_id"] == "20261020T120000Z"
    assert record["technique_id"] == "T1082"
    assert "+00:00" in record["start"]
    assert "+00:00" in record["end"]


def test_run_isolates_failures_and_continues(tmp_path: Path):
    ctx = make_ctx()
    techs = [_failing_technique("T1082"), _ok_technique("T1033")]
    log_path = tmp_path / "emulation.jsonl"
    records = run(ctx, techs, log_path, pause=0, run_id="r1")
    assert len(records) == 2
    assert records[0]["ok"] is False
    assert "host unreachable" in records[0]["detail"]
    assert records[1]["ok"] is True


def test_run_appends_across_calls(tmp_path: Path):
    ctx = make_ctx()
    log_path = tmp_path / "emulation.jsonl"
    run(ctx, [_ok_technique("T1082")], log_path, pause=0, run_id="r1")
    run(ctx, [_ok_technique("T1033")], log_path, pause=0, run_id="r2")
    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 2


def test_main_list_prints_registry(capsys):
    rc = main(["--list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "T1110.001" in out
    assert "T1053.003" in out


def test_main_refuses_without_lab_env(monkeypatch, tmp_path: Path, capsys):
    monkeypatch.delenv("PURPLELAB_LAB", raising=False)
    log_path = tmp_path / "emulation.jsonl"
    rc = main(
        [
            "--web",
            "http://target",
            "--ssh",
            "victim:22",
            "--user",
            "labuser",
            "--password",
            "pw",
            "--root-password",
            "rootpw",
            "--log",
            str(log_path),
            "--allow",
            "target,victim",
        ]
    )
    assert rc == 1
    assert "refusing to run" in capsys.readouterr().err
    assert not log_path.exists()


def test_main_only_filters_techniques(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("PURPLELAB_LAB", "1")
    monkeypatch.setattr("purplelab.emulate.default_resolve", lambda h: ["127.0.0.1"])
    monkeypatch.setattr("purplelab.emulate.make_http", lambda: (lambda *a, **k: 200))

    def fake_ssh_factory(host, port):
        def factory(user, password):
            class Sess:
                def exec(self, cmd):
                    return 0, ""

                def close(self):
                    pass

            return Sess()

        return factory

    monkeypatch.setattr("purplelab.emulate.make_ssh_factory", fake_ssh_factory)

    log_path = tmp_path / "emulation.jsonl"
    rc = main(
        [
            "--web",
            "http://target",
            "--ssh",
            "victim:22",
            "--user",
            "labuser",
            "--password",
            "pw",
            "--root-password",
            "rootpw",
            "--log",
            str(log_path),
            "--allow",
            "target,victim",
            "--only",
            "T1082,T1033",
            "--pause",
            "0",
        ]
    )
    assert rc == 0
    lines = log_path.read_text().strip().splitlines()
    ids = {json.loads(line)["technique_id"] for line in lines}
    assert ids == {"T1082", "T1033"}
