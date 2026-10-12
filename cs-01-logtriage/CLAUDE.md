# logtriage

Python CLI that finds SSH brute-force attempts in Linux auth logs.

## Layout
- `logtriage/parser.py`: log line -> `Failure` (syslog and ISO timestamps)
- `logtriage/detector.py`: group by IP, sliding window, rank -> `Finding`
- `logtriage/report.py`: table and JSON output
- `logtriage/sample.py`: synthetic log generator
- `logtriage/cli.py`: `analyze` and `generate` subcommands
- `tests/`: pytest suite

## Commands
- Install: `pip install -e . pytest black`
- Test: `pytest`
- Format: `black .`
- Try it: `logtriage generate s.log && logtriage analyze s.log --year 2026`

## Conventions
- Type hints on all functions; `from __future__ import annotations`
- Format with black (88 cols); keep functions small and single-purpose
- Parsing and detection stay pure (no I/O); only `cli.py` touches files
- Add a test for every parser or detector change
- Flag rule: failures in window strictly greater than threshold
