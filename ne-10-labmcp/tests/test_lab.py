"""Against the real NE-09 lab (make up in ne-09-bgplab). Skipped when it is not running."""

import pytest

from labmcp import tools
from labmcp.runner import DockerRunner


def lab_up() -> bool:
    try:
        return DockerRunner().is_running("cust")
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not lab_up(), reason="BGP lab not running")


@pytest.fixture(scope="module")
def real():
    return tools.Config(runner=DockerRunner())


def test_all_devices_running(real):
    assert all(v["running"] for v in tools.list_devices(real).values())


def test_show_routes_has_selection_reason(real):
    assert "selectionReason" in tools.show_routes(real, "cust", "198.18.0.0/24")


def test_ping_inside_lab(real):
    assert "0% packet loss" in tools.ping_from(real, "cust", "10.1.1.1")


def test_no_drift_on_a_healthy_lab(real):
    assert all(tools.get_config_drift(real, d)["in_sync"] for d in real.devices)
