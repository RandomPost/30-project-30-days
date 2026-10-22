# netmon

Asyncio CLI that probes hosts (ICMP echo and TCP connect), stores results in SQLite, alerts in the
terminal on threshold crossings, and draws a PNG chart per target.

## Layout
- `netmon/probes.py`: `tcp_probe`, `icmp_probe` (datagram ICMP socket, falls back to raw), packet helpers; every failure becomes a `Result`, never an exception
- `netmon/stats.py`: `Sample`, `summarize`, jitter and percentile; pure
- `netmon/alerts.py`: `AlertTracker`, edge-triggered rolling-window alerts; pure
- `netmon/store.py`: SQLite `probes` table
- `netmon/monitor.py`: target parsing, per-target loop, periodic summaries; probes are injectable for tests
- `netmon/chart.py`: bucketing and the matplotlib chart (Agg backend)
- `netmon/cli.py`: `run`, `report`, `chart`
- `tools/flaky_server.py`: dev helper that goes down on a schedule, for checking loss detection against ground truth
- `tests/`: pytest

## Commands
- Install: `pip install -e '.[dev]'`
- Test: `python3 -m pytest`
- Format: `python3 -m black --target-version py310 .`
- Try it: `netmon run 127.0.0.1 tcp:1.1.1.1:443 -i 2 --duration 30 --db t.db && netmon chart --db t.db -o t.png`

## Conventions
- Type hints on all functions; `from __future__ import annotations`; black, 88 cols
- A lost probe is data (`ok=0` plus an error name), not an exception; the loop must survive any probe failure
- Alerts are edge-triggered: one line when a metric crosses, one when it recovers
- Pace the loop on a fixed schedule (`next_at += interval`), not `sleep(interval)` after each probe, so latency does not stretch the interval
- `--timeout` may not exceed `--interval`
- Tests never touch the public internet; use local servers and fake probes
- Never `pkill python3` in the dev shell
