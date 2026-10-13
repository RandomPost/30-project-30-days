# sitecheck

Audits the TLS setup and security headers of sites you own, grades each A to F with
reasons and remediation advice, and exports Markdown and CSV. Requests run concurrently
(asyncio + httpx) with a per-request timeout.

```bash
pip install -e .
sitecheck example.com example.org
sitecheck -f domains.txt --md report.md --csv report.csv --fail-below B
```

`domains.txt` takes one domain per line; `#` starts a comment. With `--fail-below B`
the exit code is 1 if any site grades worse than B, so it can gate CI.

## Checks and penalties (score starts at 100)
| Check | Penalty |
|---|---|
| TLS 1.0/1.1 negotiated | -20 |
| Certificate expires < 30 days / < 7 days | -10 / -25 |
| Certificate expired, or site unreachable / untrusted | grade F |
| HSTS missing / max-age under 6 months | -15 / -5 |
| CSP missing / uses `unsafe-inline` or `unsafe-eval` | -20 / -5 |
| X-Frame-Options missing (CSP `frame-ancestors` also satisfies it) | -10 |
| X-Content-Type-Options not `nosniff` | -5 |
| Referrer-Policy missing / leaky (`unsafe-url`) | -5 / -3 |
| Cookie lacks Secure / HttpOnly / SameSite | -5 / -5 / -3 each (capped at -15 total) |

Grades: A >= 90, B >= 80, C >= 70, D >= 60, otherwise F.

Only the front page of each domain is requested, over HTTPS, following redirects.
Certificate verification is on, so an untrusted chain is reported as unreachable.

Tests: `pytest` (fully mocked, no network).
