import pytest

from taskcli import db


@pytest.fixture
def conn(tmp_path):
    c = db.connect(tmp_path / "tasks.db")
    yield c
    c.close()
