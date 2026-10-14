import json
from pathlib import Path

import httpx
import pytest

FX = Path(__file__).parent / "fixtures"
VULNS = {
    p.name.replace(".json", ""): json.loads(p.read_text())
    for p in FX.glob("vuln_*.json")
}
BY_ID = {v["id"]: v for v in VULNS.values()}
RESULTS = json.loads((FX / "querybatch_results.json").read_text())


class FakeOsv:
    """Serves fixtures shaped like OSV.dev responses and counts calls."""

    def __init__(self, fail_first: int = 0, status: int = 429):
        self.calls: list[tuple[str, str]] = []
        self.fail_first = fail_first
        self.status = status

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path))
        if self.fail_first > 0:
            self.fail_first -= 1
            return httpx.Response(self.status, headers={"retry-after": "3"})
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            results = [
                {"vulns": RESULTS.get(f"{q['package']['name']}@{q['version']}", [])}
                for q in queries
            ]
            return httpx.Response(200, json={"results": results})
        vid = request.url.path.rsplit("/", 1)[-1]
        if vid in BY_ID:
            return httpx.Response(200, json=BY_ID[vid])
        return httpx.Response(404, json={"code": 5, "message": "Bug not found"})

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


@pytest.fixture
def fake_osv() -> FakeOsv:
    return FakeOsv()


@pytest.fixture
def fixtures_dir() -> Path:
    return FX
