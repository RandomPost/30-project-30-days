# vulnreport

Reads dependency lockfiles, queries [OSV.dev](https://osv.dev) for known
vulnerabilities, and prints a report grouped by severity with the fixed version for
each finding.

```bash
pip install -e .
vulnreport requirements.txt poetry.lock package-lock.json
vulnreport package-lock.json --fail-on high          # exit 1 on HIGH or CRITICAL
vulnreport requirements.txt --format markdown > report.md
vulnreport requirements.txt --format json
```

Supported inputs: `requirements.txt` (exact `==` pins only, since ranges don't name a
version to check), `poetry.lock`, and `package-lock.json` (lockfile v1, v2 and v3).

## How it works
1. Parse all lockfiles into unique (ecosystem, name, version) triples.
2. `POST /v1/querybatch` (up to 1000 packages per request) returns vulnerability ids.
3. `GET /v1/vulns/{id}` fetches each record for severity and fixed versions.
4. Severity is the computed CVSS v3 base score when the record has a v3 vector
   (>= 9 CRITICAL, >= 7 HIGH, >= 4 MEDIUM, else LOW), otherwise the advisory's own
   label, otherwise UNKNOWN. The fixed version comes from the record's `affected`
   ranges for that exact package.

## Cache and rate limits
Responses are cached as JSON in `.vulnreport-cache/` for 24 hours
(`--cache-ttl-hours`, `--cache-dir`, `--no-cache`). HTTP 429 and 5xx responses (and
network errors) are retried up to 5 times, waiting for `Retry-After` when sent and
using exponential backoff (1s, 2s, 4s, 8s) otherwise.

## Exit codes
`0` ok, `1` a finding at or above `--fail-on` (`critical`, `high`, `medium`, `low`),
`2` the OSV API could not be reached.

## Tests
`pytest`. Tests use `tests/fixtures/` served through a mock HTTP transport; they never
call the live API. The fixtures follow the OSV response schema but were written by hand,
not recorded from live responses, so re-record them (and check the schema against the
current OSV docs) before relying on edge cases.
