import sqlite3

import pytest

from netmon.chart import Bucket, bucket_width, bucketize, render_chart
from netmon.cli import main
from netmon.stats import Sample
from netmon.store import Store

PNG = b"\x89PNG\r\n\x1a\n"


def test_bucketize_groups_by_time_and_counts_loss():
    samples = [
        Sample(0, True, 10),
        Sample(5, True, 30),
        Sample(9, False, None),
        Sample(10, True, 50),
    ]
    got = bucketize(samples, width=10)
    assert got[0] == Bucket(0, 3, pytest.approx(100 / 3), 20.0, pytest.approx(29.0))
    assert got[1] == Bucket(10, 1, 0.0, 50.0, 50.0)


def test_bucket_with_only_losses_has_no_latency():
    (b,) = bucketize([Sample(1, False, None), Sample(2, False, None)], width=60)
    assert b.loss_pct == 100.0 and b.median_ms is None and b.p95_ms is None


def test_bucket_width_caps_bucket_count():
    assert bucket_width(24 * 3600, interval_hint=5) == 288  # 300 buckets max
    assert bucket_width(600, interval_hint=5) == 25  # about 5 probes per bucket
    assert bucket_width(10, interval_hint=0.1) == 1.0


def synthetic(now):
    """Two hours of 10 s probes: 'steady' at 20 ms, 'flappy' lost for 30 minutes."""
    steady, flappy = [], []
    for i in range(720):
        ts = now - 7200 + i * 10
        steady.append(Sample(ts, True, 20.0))
        down = 3000 <= i * 10 < 4800
        flappy.append(Sample(ts, not down, None if down else 40.0))
    return {"tcp:steady:1": steady, "tcp:flappy:1": flappy}


def test_render_chart_writes_png(tmp_path):
    out = tmp_path / "c.png"
    render_chart(synthetic(1_800_000_000), str(out), hours=3, now=1_800_000_000)
    data = out.read_bytes()
    assert data.startswith(PNG) and len(data) > 10_000


def test_render_chart_handles_empty_and_all_lost(tmp_path):
    out = tmp_path / "c.png"
    render_chart(
        {"a": [], "b": [Sample(1_000_000_000.0, False, None)]},
        str(out),
        hours=1,
        now=1_000_000_100.0,
    )
    assert out.read_bytes().startswith(PNG)
    with pytest.raises(ValueError):
        render_chart({}, str(out))


def test_cli_run_report_chart_end_to_end(tmp_path, capsys):
    import asyncio
    import threading

    db, png = str(tmp_path / "m.db"), str(tmp_path / "m.png")
    ready, box = threading.Event(), {}

    def serve():
        async def go():
            server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
            box["port"] = server.sockets[0].getsockname()[1]
            box["loop"], box["server"] = asyncio.get_running_loop(), server
            ready.set()
            await server.serve_forever()

        try:
            asyncio.run(go())
        except asyncio.CancelledError:
            pass

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    ready.wait(5)
    target = f"tcp:127.0.0.1:{box['port']}"
    assert (
        main(
            [
                "run",
                target,
                "tcp:127.0.0.1:1",
                "--db",
                db,
                "-i",
                "0.1",
                "-t",
                "0.1",
                "--duration",
                "1",
                "--summary-every",
                "5",
            ]
        )
        == 0
    )
    box["loop"].call_soon_threadsafe(box["server"].close)
    assert main(["report", "--db", db]) == 0
    out = capsys.readouterr().out
    assert target in out and "loss 0%" in out and "loss 100%" in out
    assert "ConnectionRefusedError" in out
    assert main(["chart", "--db", db, "-o", png, "--hours", "1"]) == 0
    assert open(png, "rb").read(8) == PNG
    n = sqlite3.connect(db).execute("SELECT COUNT(*) FROM probes").fetchone()[0]
    assert n >= 10


def test_cli_validation(capsys, tmp_path):
    assert main(["run"]) == 2
    assert (
        main(
            [
                "run",
                "tcp:127.0.0.1:9",
                "-i",
                "1",
                "-t",
                "5",
                "--db",
                str(tmp_path / "x"),
            ]
        )
        == 2
    )
    assert "must not exceed" in capsys.readouterr().err
    assert main(["run", "badhost:xx"]) == 2
    assert main(["report", "--db", str(tmp_path / "empty.db")]) == 1
    assert main(["chart", "--db", str(tmp_path / "empty.db")]) == 2
    s = Store(str(tmp_path / "one.db"))
    s.add("tcp:a:1", True, 1.0)
    s.close()
    assert main(["chart", "--db", str(tmp_path / "one.db"), "--target", "nope"]) == 2
