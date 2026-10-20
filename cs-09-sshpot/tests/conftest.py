from __future__ import annotations

import asyncio
import json
from pathlib import Path

import asyncssh
import pytest

from sshpot import server
from sshpot.config import Config

ROOT = Path(__file__).resolve().parent.parent


class Pot:
    """A running honeypot on a free loopback port plus helpers to talk to it."""

    def __init__(self, acceptor, ctx, cfg, tmp):
        self.acceptor, self.ctx, self.cfg, self.tmp = acceptor, ctx, cfg, tmp
        self.port = acceptor.sockets[0].getsockname()[1]

    async def connect(self, user="root", password="x", **kw):
        opts = dict(
            known_hosts=None,
            client_keys=None,
            preferred_auth="password",
            connect_timeout=10,
        )
        opts.update(kw)
        return await asyncssh.connect(
            "127.0.0.1", self.port, username=user, password=password, **opts
        )

    async def login(self, user="root", password="x"):
        """Get a logged-in connection (burns failed attempts as needed)."""
        for _ in range(self.cfg.accept_after or 1):
            try:
                return await self.connect(user, password)
            except asyncssh.PermissionDenied:
                continue
        raise AssertionError("never got in")

    def events(self, name=None):
        self.ctx.log._fh.flush()
        rows = [json.loads(l) for l in Path(self.cfg.log_path).read_text().splitlines()]
        return [r for r in rows if name is None or r["event"] == name]

    async def settle(self):
        await asyncio.sleep(0.15)


@pytest.fixture
def make_pot(tmp_path):
    started = []

    async def factory(**overrides) -> Pot:
        cfg = Config(
            host="127.0.0.1",
            port=0,
            host_key=str(tmp_path / "hostkey"),
            log_path=str(tmp_path / "log" / "sshpot.jsonl"),
            log_stdout=False,
            accept_after=3,
        )
        for k, v in overrides.items():
            setattr(cfg, k, v)
        acceptor, ctx = await server.start(cfg)
        pot = Pot(acceptor, ctx, cfg, tmp_path)
        started.append(pot)
        return pot

    yield factory
    for pot in started:
        pot.acceptor.close()
        pot.ctx.log.close()
