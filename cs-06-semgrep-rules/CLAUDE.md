# cs-06-semgrep-rules

Custom Semgrep rule pack for Python/Flask, developed test-first.

## Layout
- `rules/<rule-id>.yaml`: one rule per file; the filename equals the rule id
- `tests/fixtures/<rule-id>.py`: vulnerable (`# ruleid:`) and safe (`# ok:`) cases
- `tests/test_rules.py`: runs each rule over its fixture and compares flagged lines
- `scripts/scan.py`: runs the whole pack against a target and summarises (also the CI gate)
- `tests/test_scan.py`: tests for the scan script, including the sample app
- `sample_app/app.py`: deliberately vulnerable demo; never deploy

## Commands
- Install: `pip install -e '.[dev]'`
- Test: `pytest` (semgrep is called per fixture, so about 20 seconds)
- Format: `black .`
- Scan: `python scripts/scan.py path/to/repo`

## Conventions
- Test first: write the vulnerable and safe fixtures, see them fail, then write the rule
- Never weaken or delete a fixture to make a rule pass; add cases instead, and say so in the commit
- Every rule needs both `ruleid` and `ok` cases and a CWE in `metadata`
- Rule ids are lowercase-kebab and match the fixture and rule filenames
- Keep messages actionable: say what is wrong and what to do instead
