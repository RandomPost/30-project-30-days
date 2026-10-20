from __future__ import annotations

import http.server
import threading

import pytest

from purplelab.techniques import (
    REGISTRY,
    Context,
    SshAuthError,
    make_http,
)


class FakeSshSession:
    def __init__(self, log: list[str]):
        self.log = log
        self.closed = False

    def exec(self, cmd: str) -> tuple[int, str]:
        self.log.append(cmd)
        return 0, ""

    def close(self) -> None:
        self.closed = True


def make_fake_ssh(valid_user: str, valid_password: str, command_log: list[str]):
    def factory(user: str, password: str):
        if user != valid_user or password != valid_password:
            raise SshAuthError(f"bad credentials for {user}")
        return FakeSshSession(command_log)

    return factory


def make_fake_http(status_log: list[tuple[str, str]], status: int = 200):
    def http(method: str, url: str, headers=None, data=None) -> int:
        status_log.append((method, url))
        return status

    return http


def make_ctx(ssh_factory=None, http_fn=None, sleeps=None):
    sleeps = sleeps if sleeps is not None else []
    return Context(
        web_base="http://target",
        ssh_host="victim",
        ssh_port=22,
        ssh_user="labuser",
        ssh_password="labpass-not-a-secret",
        root_password="rootpass-not-a-secret",
        ssh=ssh_factory or make_fake_ssh("labuser", "labpass-not-a-secret", []),
        http=http_fn or make_fake_http([]),
        sleep=sleeps.append,
    )


def test_registry_has_14_techniques():
    assert len(REGISTRY) == 14
    assert "T1110.001" in REGISTRY
    assert "T1053.003" in REGISTRY


def test_t1595_002_sends_8_requests_with_scanner_ua():
    log: list[tuple[str, str]] = []
    ctx = make_ctx(http_fn=make_fake_http(log))
    detail = REGISTRY["T1595.002"].run(ctx)
    assert len(log) == 8
    assert "8" in detail


def test_t1595_003_sends_40_distinct_requests():
    log: list[tuple[str, str]] = []
    ctx = make_ctx(http_fn=make_fake_http(log))
    REGISTRY["T1595.003"].run(ctx)
    assert len(log) == 40
    assert len({url for _m, url in log}) == 40


def test_t1190_sends_exploit_payloads():
    log: list[tuple[str, str]] = []
    ctx = make_ctx(http_fn=make_fake_http(log))
    REGISTRY["T1190"].run(ctx)
    urls = [url for _m, url in log]
    assert any("jndi" in u for u in urls)
    assert len(log) == 3


def test_t1110_001_tries_8_wrong_passwords_and_does_not_raise():
    command_log: list[str] = []
    ctx = make_ctx(
        ssh_factory=make_fake_ssh("labuser", "labpass-not-a-secret", command_log)
    )
    detail = REGISTRY["T1110.001"].run(ctx)
    assert "8" in detail


def test_t1110_003_tries_8_usernames_none_valid():
    command_log: list[str] = []
    ctx = make_ctx(
        ssh_factory=make_fake_ssh("labuser", "labpass-not-a-secret", command_log)
    )
    detail = REGISTRY["T1110.003"].run(ctx)
    assert "8" in detail


def test_t1078_logs_in_as_root_and_runs_true():
    command_log: list[str] = []
    ctx = make_ctx(
        ssh_factory=make_fake_ssh("root", "rootpass-not-a-secret", command_log)
    )
    REGISTRY["T1078"].run(ctx)
    assert command_log == ["true"]


def test_connection_error_raises():
    def factory(user, password):
        raise ConnectionRefusedError("nope")

    ctx = make_ctx(ssh_factory=factory)
    with pytest.raises(ConnectionRefusedError):
        REGISTRY["T1082"].run(ctx)


EXPECTED_COMMANDS = {
    "true",
    "uname -a",
    "cat /etc/os-release",
    "hostname",
    "whoami",
    "id",
    "w",
    "ls -la /etc",
    "find /home -maxdepth 2",
    "ps aux",
    "ip addr",
    "ip route",
    "cat /etc/resolv.conf",
    "cat /etc/passwd",
    "getent passwd",
    "cp /bin/sleep /tmp/svchost",
    "/tmp/svchost 1",
    "rm -f /tmp/svchost",
    '(crontab -l 2>/dev/null; echo "* * * * * /bin/true # purplelab") | crontab -',
    "crontab -l | grep -v purplelab | crontab -",
}


def test_all_ssh_commands_are_within_fixed_allowlist():
    command_log: list[str] = []
    log_ref = {"commands": command_log}

    def factory(user, password):
        if user == "root" and password == "rootpass-not-a-secret":
            return FakeSshSession(log_ref["commands"])
        if user == "labuser" and password == "labpass-not-a-secret":
            return FakeSshSession(log_ref["commands"])
        raise SshAuthError("bad creds")

    ctx = make_ctx(ssh_factory=factory)
    for tech in REGISTRY.values():
        if tech.channel == "ssh":
            tech.run(ctx)

    assert set(command_log) <= EXPECTED_COMMANDS
    assert command_log, "expected at least one command to have been issued"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
        if self.path == "/":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def http_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=2)


def test_make_http_real_get_200(http_server):
    http_fn = make_http()
    port = http_server.server_address[1]
    status = http_fn("GET", f"http://127.0.0.1:{port}/")
    assert status == 200


def test_make_http_real_404(http_server):
    http_fn = make_http()
    port = http_server.server_address[1]
    status = http_fn("GET", f"http://127.0.0.1:{port}/missing")
    assert status == 404


def test_make_http_does_not_follow_redirects(http_server):
    http_fn = make_http()
    port = http_server.server_address[1]
    status = http_fn("GET", f"http://127.0.0.1:{port}/redirect")
    assert status == 302


def test_make_http_connection_error_returns_0():
    http_fn = make_http()
    status = http_fn("GET", "http://127.0.0.1:1/")
    assert status == 0
