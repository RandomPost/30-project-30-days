from __future__ import annotations

import json
from pathlib import Path

from purplelab import attack
from purplelab.cli import main
from purplelab.coverage import load_rule_tags
from purplelab.techniques import REGISTRY

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT.parent / "cs-08-minisiem" / "rules"
KNOWN_GAPS = {"T1036.005"}


def test_techniques_command_lists_registry(capsys):
    assert main(["techniques"]) == 0
    out = capsys.readouterr().out
    assert all(tid in out for tid in REGISTRY)


def test_every_registered_technique_is_a_known_attack_id():
    assert set(REGISTRY) <= set(attack.TECHNIQUES)


def test_cs08_rules_cover_every_emulated_technique_except_known_gaps():
    tags = {t for ts in load_rule_tags(str(RULES)).values() for t in ts}
    uncovered = {
        tid for tid in REGISTRY if not any(attack.covers(t, tid) for t in tags)
    }
    assert uncovered == KNOWN_GAPS


def test_committed_reports_show_gap_closed():
    before = json.loads((ROOT / "reports" / "before.json").read_text())
    after = json.loads((ROOT / "reports" / "after.json").read_text())

    def status(rep):
        return {t["id"]: t["status"] for t in rep["techniques"]}

    assert status(before)["T1082"] == "missed"
    assert status(after)["T1082"] == "detected"
    assert after["summary"]["detected"] > before["summary"]["detected"]


def test_diff_command_writes_markdown(tmp_path):
    out = tmp_path / "d.md"
    reports = ROOT / "reports"
    args = ["diff", str(reports / "before.json"), str(reports / "after.json")]
    assert main(args + ["--md", str(out)]) == 0
    assert "T1082" in out.read_text()
