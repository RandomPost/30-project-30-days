# minisiem

Mini SIEM: logs -> SQLite `events` -> Sigma-like rules -> `alerts` -> dashboard.

## Layout
- `minisiem/db.py`: schema, `EVENT_FIELDS` (the only fields rules and hunts may use)
- `minisiem/parsers.py`: log line -> normalized event dict (syslog/auth, nginx)
- `minisiem/ingest.py`: lines/files -> events, incremental by byte offset
- `minisiem/rules.py`: YAML rule -> validated SQL WHERE (+ threshold, embedded tests)
- `minisiem/engine.py`: run rules, sliding-window thresholds, idempotent alert upsert
- `minisiem/ruletest.py`: run the sample-line tests embedded in rules
- `minisiem/scheduler.py`: ingest + detect loop
- `minisiem/hunt.py`: read-only SQL runner
- `minisiem/web.py`, `minisiem/static/`: dashboard (stdlib HTTP server, loopback only)
- `minisiem/sample.py`: deterministic benign + attack log generator
- `rules/*.yml`: detections, each with tests; `hunts/*.sql`: example hunts
- `.claude/skills/new-detection/`, `.claude/commands/hunt.md`: project skill and /hunt
- `tests/`: pytest suite (parsers, rules, engine, ingest, end to end, web)

## Commands
- Install: `pip install -e '.[dev]'`
- Test: `python -m pytest` (also `minisiem test-rules`, `minisiem validate`)
- Format: `black .`
- Demo: `minisiem generate out && minisiem schedule --db out/siem.db --logs out --year 2026 --iterations 1 && minisiem serve --db out/siem.db`

## Conventions
- Type hints on all functions; `from __future__ import annotations`; black, 88 cols
- Rules must use `EVENT_FIELDS` names; SQL is built only from validated field names and bound parameters, never from rule values
- Every rule ships tests (one that fires, one that stays quiet); the benign generated logs must raise no alerts
- Add a parser regex test before changing `parsers.py`
- Dashboard JS never uses innerHTML or inline script/style (CSP forbids them; a test checks)
- Keep the server bound to 127.0.0.1 and the hunt runner read-only
