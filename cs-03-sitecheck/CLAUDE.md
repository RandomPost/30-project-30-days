# sitecheck

Python CLI that audits TLS and HTTP security headers for sites you own and grades them A-F.

## Layout
- `sitecheck/headers.py`: HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy, cookie flags -> `Issue` (pure)
- `sitecheck/tls.py`: `evaluate_tls` (pure) and `fetch_tls` (handshake, the only raw socket code)
- `sitecheck/scoring.py`: issues -> score and grade (pure)
- `sitecheck/checker.py`: async orchestration; the TLS fetcher and HTTP transport are injectable
- `sitecheck/report.py`: Markdown, CSV and terminal table
- `sitecheck/cli.py`: argument parsing, reads domain files, writes reports
- `tests/`: pytest suite; no test touches the network (mock TLS fetcher + `httpx.MockTransport`)

## Commands
- Install: `pip install -e . pytest black`
- Test: `pytest`
- Format: `black .`
- Try it: `sitecheck example.com -f domains.txt --md report.md --csv report.csv`

## Conventions
- Type hints on all functions; `from __future__ import annotations`
- Format with black (88 cols); keep functions small and single-purpose
- Header analysis and scoring stay pure; network code lives in `tls.py` and `checker.py`
- Every new check needs an `Issue` with a reason and a remediation, plus a test
- Only audit sites you own or have permission to test
- Grades: A >= 90, B >= 80, C >= 70, D >= 60, else F; a `fatal` issue forces F
