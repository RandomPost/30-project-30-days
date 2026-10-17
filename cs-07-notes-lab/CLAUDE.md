# notes-lab

Flask notes app (SQLite) for a break-and-fix security lab. `main` is the fixed version;
branch `cs-07-vulnerable` keeps the planted flaws.

## Layout
- `notes_lab/app.py`: app factory, routes, CSRF check, security headers
- `notes_lab/templates/`: Jinja templates (autoescaped; every POST form carries `csrf_token`)
- `tests/conftest.py`: `Browser` helper (cookie jar, CSRF token handling), temp-DB app fixture
- `tests/test_regressions.py`: one regression test group per vulnerability
- `SECURITY_FIXES.md`: before/after for each fix

## Commands
- Install: `pip install -e '.[dev]'`
- Test: `pytest`
- Format: `black .`
- Run: `python -m notes_lab.app` (127.0.0.1:5000 only)

## Conventions
- All SQL uses `?` placeholders; never build queries with f-strings
- Never use `|safe` in templates; CSP forbids inline script and style
- Every note query is scoped by `owner_id`; return 404, not 403
- Every state-changing route is POST and gets the global CSRF check
- Add a failing regression test before any security fix
- Keep the bind address at 127.0.0.1 and debug off
