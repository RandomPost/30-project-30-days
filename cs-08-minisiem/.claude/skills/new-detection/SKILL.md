---
name: new-detection
description: Write, test and register a new detection rule in the mini SIEM. Use when asked to "add a detection for X", "write a rule for Y", or to turn a hunt into an alert.
---

# Adding a detection to minisiem

A detection is one YAML file in `rules/` (Sigma-like). It is picked up automatically
by `minisiem detect`, `minisiem schedule` and the dashboard. There is no other
registration step, but the id must be unique. Every rule carries its own tests.

## Steps

1. **Understand the behaviour.** Name the attack technique, the log source that shows
   it (auth, syslog or nginx) and what separates it from normal activity. If you do
   not know what the logged lines look like, find examples in `minisiem/sample.py` or
   in existing rules' `tests:` sections. Do not invent log formats.
2. **Check the fields.** Run `minisiem schema`. Rules may only use those columns
   (`src_ip`, `user`, `action`, `outcome`, `command`, `http_path`, `http_status`,
   `user_agent`, ...). If the log line produces no usable field, the fix is in
   `minisiem/parsers.py` (add a regex plus a test in `tests/test_parsers.py`), not
   a rule that greps `raw`. Prefer `action`/`outcome` over `message`.
3. **Pick the closest existing rule** in `rules/` and copy it:
   - one event is enough: `ssh-root-login.yml`, `user-created.yml`
   - N events in a window from one entity: `ssh-brute-force.yml`
   - N distinct values (spraying): `ssh-password-spraying.yml`
   - payload patterns in web requests: `web-sqli.yml` (paths are URL-decoded)
4. **Write the rule** as `rules/<id>.yml`. The id is lowercase words joined by dashes
   and matches the file name.

```yaml
id: example-rule
title: Short sentence an analyst reads in the dashboard
description: What it detects and why it matters.
severity: medium            # low | medium | high | critical
tags: [attack.credential_access, attack.t1110]
falsepositives: [Known benign cause]
detection:
  selection:                # fields ANDed; a list value means OR
    action: login
    outcome: failure
    user|contains: [admin, root]     # modifiers: contains startswith endswith re gt gte lt lte
  filter:
    src_ip|startswith: '10.'
  condition: selection and not filter   # and / or / not / ( ) / 1 of sel_* / all of sel_*
  threshold:                # optional; omit to alert on every matching event
    group_by: src_ip        # field or list of fields
    count: 8                # events (or distinct values if `distinct` is set)
    window: 5m              # s, m, h or d
    distinct: user          # optional
tests:                      # REQUIRED: at least one firing and one quiet case
  - name: what this case shows
    source: auth            # auth | syslog | nginx
    alerts: 1               # how many alerts this rule must raise on these lines
    lines:
      - 'Oct 18 01:00:00 web01 sshd[900]: Failed password for root from 203.0.113.50 port 51900 ssh2'
```

   Notes: string equality and modifiers are case-insensitive; `re` is a case-insensitive
   regex search; `count: 1` with `group_by` collapses a burst into one alert; use
   single-quoted YAML for regexes so backslashes survive. Test lines are parsed as
   year 2026. Copy line formats from existing rules.
5. **Write the tests first-class.** Include (a) a case that fires, (b) a near miss that
   must stay quiet (just under the threshold, or benign look-alike traffic), and for
   thresholds (c) the same events spread out beyond the window.
6. **Run the checks** from this folder:
   - `minisiem validate` (schema, ids, every rule has a firing and a quiet test)
   - `minisiem test-rules -v` (runs the embedded tests)
   - `pytest` (also checks that the generated attack logs raise every rule and that
     benign traffic raises none)
7. **If it should fire on the demo data**, add a scenario to `attacks()` in
   `minisiem/sample.py`, then confirm: `minisiem generate out && minisiem ingest out/*
   --year 2026 --db out/siem.db && minisiem detect --db out/siem.db`.
   Add the id to `EXPECTED_RULES` in `tests/test_end_to_end.py` (other tests derive counts from the data). Benign traffic from
   `benign()` must still raise nothing.
8. **Report** the rule id, what it detects, the tests added and what you could not
   verify (for example no real-world sample log).

## Pitfalls
- A rule on a NULL column never matches (`NOT` is safe too: NULL counts as false).
- URL-encoded payloads: `http_path` is already decoded (up to 3 rounds).
- Do not loosen a threshold to make a test pass; fix the test data or explain why.
- Rules are trusted input, but a bad regex can be slow on big stores: keep them simple.
