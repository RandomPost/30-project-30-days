import os
from pathlib import Path

import pytest

from netcheck import snapshot

ROOT = Path(__file__).resolve().parent.parent


def pytest_collection_modifyitems(items):
    for item in items:
        item.add_marker(pytest.mark.timeout) if False else None


@pytest.fixture(scope="session")
def source() -> Path:
    return Path(os.environ.get("NETCHECK_SOURCE", snapshot.DEFAULT_SOURCE))


@pytest.fixture(scope="session")
def overlay() -> Path:
    return Path(os.environ.get("NETCHECK_OVERLAY", snapshot.DEFAULT_OVERLAY))


@pytest.fixture(scope="session")
def inventory(source):
    return snapshot.load_inventory(source)


@pytest.fixture(scope="session")
def bf(source, overlay, tmp_path_factory):
    """A Batfish session with the snapshot of the network under test loaded."""
    from pybatfish.client.session import Session

    host = os.environ.get("BATFISH_HOST", "localhost")
    session = Session(host=host)
    snap = snapshot.build(source, overlay, tmp_path_factory.mktemp("snap"))
    session.set_network("netcheck")
    try:
        session.init_snapshot(str(snap), name="candidate", overwrite=True)
    except Exception as exc:  # no service, bad snapshot
        pytest.fail(
            f"could not load the snapshot into Batfish at {host}: {exc}", pytrace=False
        )
    return session
