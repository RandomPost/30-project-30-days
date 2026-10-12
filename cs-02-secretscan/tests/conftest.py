"""Fake secrets are assembled at runtime so no real-looking key sits in the repo."""

import random
import string

import pytest


def _rand(n: int, alphabet: str, seed: int) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(n))


@pytest.fixture
def aws_key() -> str:
    return "AKIA" + _rand(16, string.ascii_uppercase + string.digits, 1)


@pytest.fixture
def github_token() -> str:
    return "ghp_" + _rand(36, string.ascii_letters + string.digits, 2)


@pytest.fixture
def private_key_header() -> str:
    return "-----BEGIN " + "RSA PRIVATE KEY-----"


@pytest.fixture
def entropy_string() -> str:
    return _rand(40, string.ascii_letters + string.digits, 3)


@pytest.fixture
def project(tmp_path, aws_key):
    """A tiny directory with one secret file and one clean file."""
    (tmp_path / "config.py").write_text(f'KEY = "{aws_key}"\n')
    (tmp_path / "clean.py").write_text("print('hello')\n")
    return tmp_path
