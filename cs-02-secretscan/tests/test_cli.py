import io
import json
import subprocess
import sys

from secretscan import cli
from secretscan.cli import main


def test_scan_finds_secret_and_exits_1(project, capsys):
    assert main(["scan", str(project)]) == 1
    out = capsys.readouterr().out
    assert "config.py:1" in out and "aws-access-key-id" in out


def test_scan_clean_dir_exits_0(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("x = 1\n")
    assert main(["scan", str(tmp_path)]) == 0


def test_allowlist_file_suppresses(project, capsys):
    (project / ".secretscan-allow").write_text("path:*config.py\n")
    assert main(["scan", str(project), "--allowlist-dir", str(project)]) == 0


def test_binary_files_skipped(tmp_path):
    (tmp_path / "b.bin").write_bytes(b"\0AKIA" + b"A" * 16)
    assert main(["scan", str(tmp_path)]) == 0


def hook_event(path):
    return json.dumps({"tool_name": "Write", "tool_input": {"file_path": str(path)}})


def test_claude_hook_reports_to_claude(project, capsys, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project))
    assert cli.cmd_hook(hook_event(project / "config.py")) == 2
    err = capsys.readouterr().err
    assert "possible secret" in err and "environment variable" in err


def test_claude_hook_quiet_for_clean_file_and_odd_input(project, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project))
    assert cli.cmd_hook(hook_event(project / "clean.py")) == 0
    assert cli.cmd_hook("not json") == 0
    assert cli.cmd_hook(json.dumps({"tool_input": {"command": "ls"}})) == 0


def test_hook_via_stdin_entrypoint(project, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project))
    monkeypatch.setattr(sys, "stdin", io.StringIO(hook_event(project / "config.py")))
    assert main(["hook"]) == 2


def git(cwd, *args):
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=False
    )


def test_pre_commit_blocks_secret_and_allows_clean(tmp_path, aws_key, monkeypatch):
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "t@example.com")
    git(tmp_path, "config", "user.name", "t")
    monkeypatch.chdir(tmp_path)
    assert main(["install-hook"]) == 0
    assert (tmp_path / ".git" / "hooks" / "pre-commit").exists()

    env_path = {"PYTHONPATH": str(cli.PRE_COMMIT.parent.parent)}
    import os

    env = {**os.environ, **env_path}

    (tmp_path / "leak.txt").write_text(f"key={aws_key}\n")
    git(tmp_path, "add", "leak.txt")
    blocked = subprocess.run(
        ["git", "commit", "-m", "leak"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=env,
    )
    assert blocked.returncode != 0
    assert "commit blocked" in blocked.stderr

    git(tmp_path, "rm", "-q", "--cached", "leak.txt")
    (tmp_path / "ok.txt").write_text("hello\n")
    git(tmp_path, "add", "ok.txt")
    ok = subprocess.run(
        ["git", "commit", "-m", "ok"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=env,
    )
    assert ok.returncode == 0, ok.stderr
