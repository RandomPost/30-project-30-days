# minisiem

A small SIEM in Python and SQLite. It ingests syslog, auth and nginx access logs into
one normalized table, runs Sigma-like YAML detection rules on a schedule, stores alerts,
and serves a dashboard of alerts by severity and over time. It also ships a Claude Code
skill (`new-detection`) and a slash command (`/hunt`).

```bash
pip install -e '.[dev]'
minisiem generate out                       # synthetic benign + attack logs
minisiem schedule --db out/siem.db --logs out --year 2026 --iterations 1
minisiem serve --db out/siem.db             # http://127.0.0.1:8080
```

## What it does

| Step | Command | Notes |
|------|---------|-------|
| Ingest | `minisiem ingest FILE... --type auth\|syslog\|nginx --year 2026` | incremental: remembers the byte offset per file, reads only complete new lines |
| Detect | `minisiem detect` | runs every rule once; re-running is idempotent |
| Schedule | `minisiem schedule --logs DIR --interval 60` | ingest + detect on a loop; reloads rules each tick |
| Alerts | `minisiem alerts [--severity high]` | |
| Dashboard | `minisiem serve --port 8080` | severity bars, hourly timeline, alert table with sample log lines |
| Hunt | `minisiem hunt --sql "SELECT ..."` or `--file hunts/x.sql` | read-only SELECT only |
| Rules | `minisiem validate`, `minisiem test-rules -v` | lint rules, run the sample logs embedded in each rule |

Normalized columns (`minisiem schema`): `ts` (UTC ISO), `source`, `host`, `program`,
`pid`, `message`, `src_ip`, `user`, `action`, `outcome`, `command`, `http_method`,
`http_path` (URL-decoded), `http_status`, `http_bytes`, `user_agent`, `raw`.

## The 14 detections

| Rule | Severity | Fires on |
|------|----------|----------|
| ssh-brute-force | high | 8+ failed SSH logins from one IP in 5 min |
| ssh-password-spraying | high | 5+ distinct accounts failed from one IP in 15 min |
| ssh-root-login | medium | successful SSH login as root |
| sudo-root-shell | medium | sudo used to start a shell |
| sudo-auth-failures | medium | 3+ failed sudo password prompts by a user in 10 min |
| su-failures | medium | 3+ failed `su` by a user in 5 min |
| user-created | high | `useradd` ran |
| cron-persistence | medium | crontab replaced |
| web-sqli | high | SQL injection payload in the decoded request path |
| web-path-traversal | high | `../`, `/etc/passwd`, `win.ini` in the request path |
| web-scanner-user-agent | medium | sqlmap, nikto, nmap, gobuster, ... in the User-Agent |
| web-404-flood | medium | 25+ 404s from one IP in a minute |
| web-login-brute-force | high | 10+ rejected POSTs to a login endpoint in 5 min |
| web-rce-probe | critical | Log4Shell `${jndi:` or Shellshock `() {` |

On the generated attack logs all 14 fire (15 alerts); the benign logs raise none.

## Rule format

```yaml
id: ssh-brute-force
title: SSH brute force from a single IP
severity: high                 # low | medium | high | critical
tags: [attack.t1110.001]
detection:
  selection:                   # field[|modifier]: value or [values]
    action: login              # fields are ANDed, a list means OR
    outcome: failure
  filter:
    src_ip|startswith: '10.'
  condition: selection and not filter    # and / or / not / ( ) / 1 of sel_* / all of sel_*
  threshold:                   # optional
    group_by: src_ip
    count: 8                   # events, or distinct values when `distinct` is set
    window: 5m
tests:                         # sample lines the rule must / must not fire on
  - {name: ..., source: auth, alerts: 1, lines: ['Oct 18 01:00:00 web01 sshd[9]: ...']}
```

Modifiers: `contains startswith endswith re gt gte lt lte`. Matching is case-insensitive.
Field names are checked against the schema and values are bound as SQL parameters, so a
rule file cannot inject SQL. A threshold collapses a continuing attack into one alert
that grows (`event_count`, `last_ts`) instead of re-alerting each run.

## Claude Code skill and command

- `.claude/skills/new-detection/SKILL.md`: how to write, test and register a rule here.
  Try it in a fresh session: "add a detection for sudo editing /etc/sudoers".
- `.claude/commands/hunt.md`: `/hunt <hypothesis>` reads the schema, writes a query to
  `hunts/<slug>.sql`, runs it through the read-only runner and reports a verdict.
  Example hunts are in `hunts/`.

## Security notes

- The dashboard binds to 127.0.0.1 and has no login: do not expose it.
- Logs are attacker-controlled. The page builds its DOM with `textContent` only, a CSP
  forbids inline script and style, and the API returns JSON.
- `minisiem hunt` opens the DB read-only, allows a single SELECT, and stops runaway queries.

## Limits

- No cross-event sequences ("failures then success"); use a hunt for that
  (`hunts/success-after-failures.sql`).
- Syslog lines carry no year (pass `--year`) and are read as UTC. Logs are read from files, not live sockets.
- Rules scan the whole events table each run: fine for a lab, not for millions of rows.
- The sample attack data is synthetic. Parsers follow OpenSSH/sudo/nginx formats but were not run against production logs.

## Command audit telemetry

Lines from a `cmdaudit` syslog program (`user=U src=IP cmd=...`) parse into `command` events,
which six `discovery-*` rules (ATT&CK T1082, T1033, T1083, T1057, T1016, T1087.001) match.
Added in CS-10, where a lab host emits them via an sshd `ForceCommand`.
