import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def source(tmp_path) -> Path:
    """A private copy of the real source of truth that a test may modify."""
    dst = tmp_path / "sites.yml"
    shutil.copy(ROOT / "data" / "sites.yml", dst)
    return dst
