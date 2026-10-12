# secretscan

Python CLI that finds secrets in files, plus two hooks that run it automatically.

## Layout
- `secretscan/rules.py`: regex rules and the entropy check
- `secretscan/scanner.py`: text -> `Finding` (pure, no I/O)
- `secretscan/allowlist.py`: `.secretscan-allow` parsing (pure)
- `secretscan/files.py`: filesystem and git access (the only I/O module besides `cli.py`)
- `secretscan/report.py`: output formatting
- `secretscan/cli.py`: `scan`, `hook`, `install-hook`
- `hooks/pre-commit`: git hook script copied into `.git/hooks`
- `.claude/settings.json`: Claude Code PostToolUse hook config
- `tests/`: pytest suite; fake secrets are built at runtime in `conftest.py`

## Commands
- Install: `pip install -e . pytest black`
- Test: `pytest`
- Format: `black .`
- Scan: `secretscan scan .` / `secretscan scan --staged`
- Install git hook: `secretscan install-hook`

## Conventions
- Type hints on all functions; `from __future__ import annotations`
- Format with black (88 cols); keep functions small and single-purpose
- Never commit anything that looks like a real secret, even in tests: assemble
  fake ones at runtime (see `tests/conftest.py`)
- Add a test for every new rule or hook behaviour
- Claude hook contract: exit 2 + stderr = findings are fed back to Claude
