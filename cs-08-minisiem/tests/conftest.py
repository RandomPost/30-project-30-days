from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from minisiem import sample
from minisiem.db import connect
from minisiem.ingest import guess_source, ingest_file


@pytest.fixture(scope="session")
def rules_dir() -> str:
    return str(ROOT / "rules")


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


def load_logs(conn, directory, attacks: bool, tmp_path):
    out = tmp_path / ("attack" if attacks else "benign")
    for path in sample.generate(str(out), seed=1, with_attacks=attacks):
        ingest_file(conn, path, guess_source(path), 2026)
    return out


@pytest.fixture
def attack_db(tmp_path):
    """A database file holding generated benign + attack logs (events only)."""
    db = tmp_path / "attack.db"
    c = connect(str(db))
    load_logs(c, None, True, tmp_path)
    c.close()
    return str(db)
