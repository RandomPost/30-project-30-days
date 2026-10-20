# purplelab

Purple-team lab: emulate ATT&CK techniques, collect telemetry into the CS-08 SIEM, report coverage.

## Layout
- `purplelab/techniques.py`: registry of 14 benign techniques; every network action goes through `Context` so tests use fakes
- `purplelab/emulate.py`: safety guard (`SafetyError`), `run()` writes `emulation.jsonl`, runner CLI
- `purplelab/coverage.py`, `attack.py`: matrix from alerts + emulation windows; Markdown/JSON/diff
- `purplelab/cli.py`: `emulate | coverage | diff | techniques` (imports are lazy; the runner image has no minisiem)
- `lab/`: compose lab. siem/runner build with the repo root as context
- `reports/`: committed before/after output of real lab runs (a test depends on them)
- `PLAN.md`: contracts between the pieces

## Commands
- Install: `pip install -e '.[dev]' -e ../cs-08-minisiem`
- Test: `python3 -m pytest`
- Format: `python3 -m black --target-version py310 .`
- Lab: `lab/run-lab.sh` / `lab/run-lab.sh down` (needs Docker)

## Conventions
- Never weaken the safety guard; new techniques must be benign, bounded, and only run commands listed in the test allowlist
- A new technique needs an entry in `attack.py`, a test, and a rule in CS-08 (or a documented gap)
- Coverage statuses come from live alerts; do not infer detection from rule tags alone
- Adding a detection means editing `../cs-08-minisiem` (rule + embedded tests), then re-running the lab and regenerating `reports/`
- Docker pitfalls: relative paths in compose are relative to `lab/`; image rebuilds are needed for Python changes
