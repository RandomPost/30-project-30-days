# vulnreport

Python CLI that reads dependency lockfiles, asks OSV.dev for known vulnerabilities and
reports them by severity with the fixed version. `--fail-on` makes it usable in CI.

## Layout
- `vulnreport/parsers.py`: requirements.txt, poetry.lock, package-lock.json -> `Dep` (pure)
- `vulnreport/severity.py`: CVSS v3 scoring, severity label, fixed versions (pure)
- `vulnreport/osv.py`: OSV client (batch query + record fetch, retry/backoff, cache)
- `vulnreport/cache.py`: JSON file cache with TTL (the only file-writing code besides `cli.py`)
- `vulnreport/scan.py`: deps -> sorted `Finding`s, `--fail-on` threshold logic
- `vulnreport/report.py`: text, Markdown, JSON output
- `vulnreport/cli.py`: argument parsing; exit codes 0 ok, 1 findings at/above `--fail-on`, 2 API error
- `tests/`: pytest suite; `tests/conftest.py` `FakeOsv` serves `tests/fixtures/` via `httpx.MockTransport`

## Commands
- Install: `pip install -e . pytest black`
- Test: `pytest`
- Format: `black .`
- Try it: `vulnreport requirements.txt package-lock.json --fail-on high`

## Conventions
- Type hints on all functions; `from __future__ import annotations`
- Format with black (88 cols); keep functions small and single-purpose
- Parsing, severity and reporting stay pure; only `osv.py`, `cache.py`, `cli.py` do I/O
- Tests never call the live API; add a fixture to `tests/fixtures/` for new API shapes
- Severity: computed CVSS v3 score wins, else the advisory's own label, else UNKNOWN
