import pytest
from typer.testing import CliRunner

from taskcli.cli import app

runner = CliRunner()


@pytest.fixture
def run(tmp_path):
    db = str(tmp_path / "cli.db")

    def go(*args):
        return runner.invoke(app, ["--db", db, *args])

    return go


def test_add_ls_done_rm_flow(run):
    assert "added #1: write report" in run("add", "write report").output
    assert "write report" in run("ls").output
    assert "completed #1" in run("done", "1").output
    assert "no tasks" in run("ls").output
    assert "[x] write report" in run("ls", "--all").output
    assert "deleted #1" in run("rm", "1").output


def test_errors_exit_nonzero(run):
    r = run("done", "9")
    assert r.exit_code == 1 and "no task with id 9" in r.output
    assert run("add", "  ").exit_code == 1


def test_db_from_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("TASKCLI_DB", str(tmp_path / "env.db"))
    assert runner.invoke(app, ["add", "from env"]).exit_code == 0
    assert (tmp_path / "env.db").exists()
