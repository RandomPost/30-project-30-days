# notes-lab

A small Flask notes app used for a break-and-fix security lab. This is the **fixed**
version. The deliberately vulnerable original is on branch `cs-07-vulnerable`.

It is still a lab app: it binds to 127.0.0.1, runs with debug off, and has no rate
limiting or HTTPS. **Never deploy it or expose it to a network.**

```bash
pip install -e '.[dev]'
python -m notes_lab.app        # http://127.0.0.1:5000
pytest                         # 10 regression tests, one group per vulnerability
```

To see the tests fail first: `git checkout cs-07-vulnerable && pytest` (9 fail, 1 passes).
Each fix, with before and after code, is in [SECURITY_FIXES.md](SECURITY_FIXES.md).

Env vars: `NOTES_LAB_SECRET_KEY` (stable session key; random per start if unset),
`NOTES_LAB_HTTPS=1` (mark the session cookie Secure when serving over TLS).
