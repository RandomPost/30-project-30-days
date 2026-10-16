import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import scan  # noqa: E402


def result(rule, sev, path="a.py", line=1):
    return {
        "check_id": f"rules.{rule}",
        "path": path,
        "start": {"line": line},
        "extra": {"severity": sev},
    }


def test_summarize_orders_by_severity_and_counts_rules():
    data = {
        "results": [
            result("flask-route-missing-auth", "WARNING", "b.py", 9),
            result("unsafe-yaml-load", "ERROR", "a.py", 3),
            result("unsafe-yaml-load", "ERROR", "a.py", 2),
        ]
    }
    text = scan.summarize(data, Path("repo"))
    assert text.startswith("3 finding(s) in repo")
    assert text.index("a.py:2") < text.index("a.py:3") < text.index("b.py:9")
    assert "2  unsafe-yaml-load" in text


def test_exit_code_threshold():
    warn = {"results": [result("r", "WARNING")]}
    err = {"results": [result("r", "ERROR")]}
    assert scan.exit_code(warn, "warning") == 1
    assert scan.exit_code(warn, "error") == 0
    assert scan.exit_code(err, "error") == 1
    assert scan.exit_code({"results": []}, "warning") == 0


def test_sample_app_has_one_hit_for_every_rule():
    data = scan.run_semgrep(ROOT / "sample_app")
    found = {r["check_id"].split(".")[-1] for r in data["results"]}
    expected = {p.stem for p in (ROOT / "rules").glob("*.yaml")}
    assert found == expected


def test_cli_exit_codes(capsys, tmp_path):
    assert scan.main([str(ROOT / "sample_app")]) == 1
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "ok.py").write_text("print('hi')\n")
    assert scan.main([str(clean)]) == 0
    assert "No findings" in capsys.readouterr().out
