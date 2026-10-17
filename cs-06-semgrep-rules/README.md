# CS-06: custom Semgrep rules for Python/Flask, built test-first

Six rules, each with vulnerable and safe fixtures, plus a script that runs the whole pack
against any repo and summarises the results.

| Rule | Severity | Detects |
|---|---|---|
| `flask-sql-string-formatting` | ERROR | `execute()` with `%`, `.format`, `+` or an f-string, directly or via a variable built earlier |
| `flask-subprocess-shell-user-input` | ERROR | taint from `request.*` into `subprocess(..., shell=True)`, `os.system`, `os.popen` |
| `unsafe-yaml-load` | ERROR | `yaml.load` / `load_all` without a safe loader, `yaml.unsafe_load` |
| `unsafe-pickle-load` | ERROR | `pickle`, `cPickle`, `dill` loads, `Unpickler`, `shelve.open` |
| `flask-route-missing-auth` | WARNING | `@app.route/get/post/...` handlers without a known auth decorator |
| `hardcoded-jwt-secret` | ERROR | literal keys in `jwt.encode/decode`, secret-like `app.config[...]`, `app.secret_key` |

## Use it
```bash
pip install -e '.[dev]'                  # semgrep + pytest
python scripts/scan.py path/to/repo      # summary by rule and severity
python scripts/scan.py repo --fail-on error --json out.json   # CI gate
semgrep --config rules/ path/to/repo     # or use the rules directly
pytest                                   # fixtures + scan script tests (~20 s)
```
`scan.py` exits 1 when a finding is at or above `--fail-on` (default `warning`), 2 if
Semgrep fails. `sample_app/` is a deliberately vulnerable demo app with one hit per rule.

## How the tests work
Fixtures live in `tests/fixtures/<rule-id>.py` and use Semgrep's annotation style:
`# ruleid: <id>` means the next code line must be flagged, `# ok: <id>` means it must not.
`tests/test_rules.py` runs `rules/<id>.yaml` over its fixture and compares. A fixture without
a rule fails, and a rule without a fixture fails.

## Test-first history (check it with `git log`)
1. `42063f4` fixtures and tests only, no rules: all 7 tests fail.
2. `4cd76f3` the rules: all pass. The tests were not touched in this commit.
3. `15e3c1e` scanning a real third-party Flask app (we45/Vulnerable-Flask-App, commit
   `b6a4f97`) exposed gaps. I added new failing fixtures first (SQL built into a variable,
   custom secret key names, `app.secret_key`), confirmed 2 tests failed, then widened the
   rules. No existing fixture line was changed or removed; those commits only add cases.

## Result on a real repo
Against the third-party app above the pack reports 16 findings: the real SQL injection
(`app/app.py:261`), the unsafe `yaml.load` (`:329`), three hard-coded secrets (`:26-28`) and 11
routes without an auth decorator. Honest caveat on the last group: that app checks tokens
inside each handler, so those 11 are false positives for an app that authenticates in the
function body. The rule only understands decorators. It also does not catch SQL built in
another function or file, or secrets read from a literal in another module.

## Known limits
- `flask-route-missing-auth` is name based: decorators matching `login_required`,
  `jwt_required`, `require_auth`, `token_required`, `public` and similar count as auth. Add your own
  names to the regex in `rules/flask-route-missing-auth.yaml` (and a fixture first). Mark
  intentionally public routes with `@public` or `# nosemgrep: flask-route-missing-auth`.
  In the sample app `/login` is flagged for that reason.
- Taint tracking is intra-file and stops at function boundaries.
