---
description: Turn a threat hypothesis into a SQL hunt query against the mini SIEM log store
argument-hint: <hypothesis, e.g. "a login that succeeds right after many failures">
allowed-tools: Bash(minisiem schema:*), Bash(minisiem hunt:*), Bash(ls:*), Write, Read
---

Hunt for: $ARGUMENTS

You are writing a threat-hunting query for this project's log store (SQLite, built by
`minisiem ingest`). Do not guess column names.

1. Run `minisiem schema` and read it. Everything lives in the `events` table
   (normalized from auth, syslog and nginx logs) plus the `alerts` table.
2. Look at `hunts/*.sql` for existing queries in the house style (a comment with the
   hypothesis, then one SELECT). Reuse one if it already answers the question.
3. Restate the hypothesis in one sentence, then name the fields and values that would
   be evidence of it (for example `action = 'login' AND outcome = 'failure'`).
4. Write ONE read-only SELECT to `hunts/<short-slug>.sql`. Start the file with a
   `--` comment holding the hypothesis. Rules for the query:
   - `ts` is ISO-8601 UTC text. Shift it with
     `strftime('%Y-%m-%dT%H:%M:%SZ', ts, '-10 minutes')`.
   - `regexp(pattern, column)` is available and case-insensitive.
   - Aggregate (GROUP BY / HAVING) instead of dumping raw rows; end with ORDER BY.
   - Never interpolate guessed values: look at real values first with a quick
     `SELECT DISTINCT` if unsure.
5. Run it with `minisiem hunt --file hunts/<slug>.sql`. The database is `$SIEM_DB` or
   `siem.db`; add `--db <path>` only if the user's arguments name a database. The
   runner is read-only and rejects anything but a single SELECT. If it errors, fix the
   query and rerun; do not try to work around the runner. If the database is missing,
   look for `*.db` files in the project and `out/`; if there are none, say that the
   store must be built first (`minisiem ingest` then `minisiem detect`) and stop.
6. Report: the hypothesis, the query path, what the rows show (quote the key rows),
   likely benign explanations, and a verdict (supported, not supported, inconclusive).
7. If the hunt found something a rule could catch automatically, suggest turning it
   into a detection with the `new-detection` skill. Do not create the rule unprompted.
