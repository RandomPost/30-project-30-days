# notes-lab (branch `cs-07-vulnerable`)

**A deliberately vulnerable Flask notes app for a local security lab.** It binds to
127.0.0.1 only, runs with debug off, and has five planted flaws:
SQL injection (login and search), stored XSS, CSRF, IDOR and weak (unsalted MD5) password
hashing, plus a hard-coded session secret. **Never deploy it or expose it to a network.**

```bash
pip install -e '.[dev]'
python -m notes_lab.app        # http://127.0.0.1:5000
pytest                         # on this branch the regression tests FAIL, by design
```

The fixed version is on branch `cs-07-fixed` and on `main`; see `SECURITY_FIXES.md` there.
