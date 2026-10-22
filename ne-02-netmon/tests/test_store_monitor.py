import asyncio
import time

import pytest

from netmon.alerts import Thresholds
from netmon.monitor import Target, format_summary, parse_target, run_monitor
from netmon.probes import Result
from netmon.stats import summarize
from netmon.store import Store


@pytest.fixture
def store(tmp_path):
    s = Store(str(tmp_path / "t.db"))
    yield s
    s.close()


def test_store_roundtrip_and_window(store):
    store.add("a", True, 12.5, ts=100.0)
    store.add("a", False, None, "timeout", ts=200.0)
    store.add("b", True, 3.0, ts=150.0)
    assert store.targets() == ["a", "b"]
    got = store.samples("a", since=0)
    assert [(s.ts, s.ok, s.latency_ms) for s in got] == [
        (100.0, True, 12.5),
        (200.0, False, None),
    ]
    assert len(store.samples("a", since=150)) == 1
    assert store.errors("a", since=0) == {"timeout": 1}


@pytest.mark.parametrize(
    "spec, expected",
    [
        ("1.1.1.1", Target("ping", "1.1.1.1")),
        ("ping:example.com", Target("ping", "example.com")),
        ("8.8.8.8:53", Target("tcp", "8.8.8.8", 53)),
        ("tcp:example.com:443", Target("tcp", "example.com", 443)),
    ],
)
def test_parse_target(spec, expected):
    assert parse_target(spec) == expected
    assert expected.label.startswith(expected.kind)


@pytest.mark.parametrize(
    "bad", ["", "ping:", "tcp:host", "host:abc", "host:0", "host:70000", ":53"]
)
def test_parse_target_rejects_bad_specs(bad):
    with pytest.raises(ValueError):
        parse_target(bad)


def fake_probe(script):
    """A probe returning the scripted results per host, then repeating the last."""
    calls = {}

    async def probe(target, timeout):
        i = calls.get(target.host, 0)
        calls[target.host] = i + 1
        return script[target.host][min(i, len(script[target.host]) - 1)]

    return probe


def test_run_monitor_records_every_probe_and_alerts(store):
    lines = []
    probe = fake_probe(
        {
            "good": [Result(True, 5.0)],
            "bad": [Result(False, None, "timeout")],
        }
    )
    asyncio.run(
        run_monitor(
            [Target("tcp", "good", 1), Target("tcp", "bad", 1)],
            store,
            interval=0.05,
            thresholds=Thresholds(window=5),
            duration=0.6,
            summary_every=0.3,
            probe=probe,
            out=lines.append,
        )
    )
    good = summarize(store.samples("tcp:good:1", 0))
    bad = summarize(store.samples("tcp:bad:1", 0))
    assert good.count >= 6 and good.loss_pct == 0
    assert bad.count >= 6 and bad.loss_pct == 100
    alerts = [l for l in lines if "ALERT" in l]
    assert len(alerts) == 1 and "tcp:bad:1" in alerts[0]  # fires once, not every probe
    assert any(l.startswith("tcp:good:1: ") for l in lines)  # periodic summary
    assert lines[-1].startswith("stopped after")


def test_probe_exception_is_recorded_not_fatal(store):
    async def boom(target, timeout):
        raise RuntimeError("bug in probe")

    asyncio.run(
        run_monitor(
            [Target("tcp", "x", 1)],
            store,
            interval=0.05,
            duration=0.3,
            probe=boom,
            out=lambda _l: None,
        )
    )
    assert store.errors("tcp:x:1", 0) == {
        "probe-error:RuntimeError": store.samples("tcp:x:1", 0).__len__()
    }


def test_stop_does_not_wait_for_a_hung_probe(store):
    async def hang(target, timeout):
        await asyncio.sleep(60)

    started = time.monotonic()

    asyncio.run(
        run_monitor(
            [Target("tcp", "x", 1)],
            store,
            interval=0.1,
            timeout=0.05,
            duration=0.2,
            probe=hang,
            out=lambda _l: None,
        )
    )
    assert time.monotonic() - started < 1.0
    assert store.samples("tcp:x:1", 0) == []  # the cancelled probe is not recorded


def test_format_summary():
    assert format_summary("t", summarize([])) == "t: no samples"
    from netmon.stats import Sample

    out = format_summary("t", summarize([Sample(0, False, None)]))
    assert "no replies" in out
    out = format_summary("t", summarize([Sample(0, True, 10.0), Sample(1, True, 14.0)]))
    assert "avg 12.0 ms" in out and "jitter 4.0 ms" in out
