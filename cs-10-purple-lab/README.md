# purple-lab

A purple-team lab in docker-compose. A scripted, benign adversary-emulation runner attacks
a web server and an SSH host, their logs flow into the [CS-08 mini SIEM](../cs-08-minisiem/),
and a coverage report says, per MITRE ATT&CK technique, whether the SIEM detected it.

```bash
pip install -e '.[dev]' -e ../cs-08-minisiem
python3 -m pytest                    # 64 tests

lab/run-lab.sh                       # build, attack, wait for the SIEM, write lab/reports/coverage.md
lab/run-lab.sh down                  # remove containers and volumes

purplelab techniques                 # what gets emulated
purplelab coverage --db siem.db --emulation emulation.jsonl --rules ../cs-08-minisiem/rules --md out.md
purplelab diff reports/before.json reports/after.json
```

## The lab

| Service | What it is |
|---|---|
| `target` | nginx serving a static site, combined access log to `/logs/nginx-access.log` |
| `victim` | Ubuntu 24.04 with real sshd, cron, sudo and rsyslog. Weak lab-only accounts. A `ForceCommand` audit shell logs every remote command as a `cmdaudit` line |
| `siem` | CS-08 `minisiem schedule` over the shared `/logs` volume, rules bind-mounted from `cs-08-minisiem/rules` |
| `runner` | `purplelab emulate`, runs on demand (`attack` profile) |

All of it sits on an `internal` network with no route out. The runner also refuses to run
unless `PURPLELAB_LAB=1`, every target is on its allowlist, and every target resolves to a
private or loopback address.

## Emulated techniques

14 techniques, each bounded and benign (see `purplelab/techniques.py`): scanning
(T1595.002, T1595.003), web exploit strings (T1190), SSH password guessing and spraying
(T1110.001, T1110.003), a root login (T1078), six discovery commands (T1082, T1033, T1083,
T1057, T1016, T1087.001), a binary renamed to `svchost` (T1036.005) and a crontab entry
(T1053.003). Every run appends one record per technique with its start and end time.

## How coverage is decided

A technique is **detected** if an alert from a rule tagged with that technique ID (or its
parent) overlaps the time window the technique ran in. Otherwise it is **missed**, with a reason:
`no-telemetry` (no events at all in the window), `no-rule` (nothing maps to it) or
`rule-did-not-fire` (a rule maps to it but stayed quiet). This is measured on live alerts,
not on what the rules claim. The report also lists rules for techniques never emulated.

## Result: closing a gap

First run, with the CS-08 rules as they were ([reports/before.md](reports/before.md)):
**7 of 14 detected.** The six discovery techniques and masquerading were missed with
`no-rule`. The victim's `cmdaudit` lines were being ingested but nothing looked at them.

Then, in CS-08: a `cmdaudit` parser (new `command` event action), six discovery rules with
embedded tests, and a parser test. Second run from a clean volume
([reports/after.md](reports/after.md), [diff](reports/diff.md)): **13 of 14 detected.**
The remaining gap is T1036.005, left open on purpose (see below).

## Layout

- `purplelab/techniques.py`, `emulate.py`: technique registry, runner, safety guard
- `purplelab/coverage.py`, `attack.py`: matrix engine, ATT&CK name table, reports and diff
- `purplelab/cli.py`: `emulate`, `coverage`, `diff`, `techniques`
- `lab/`: compose file, images, `run-lab.sh`
- `reports/`: the committed before/after reports (Markdown and JSON)
- `PLAN.md`: the task list and interface contracts the pieces were built against

## Limits

- T1036.005 is an open gap: no rule looks at execution from `/tmp` under system-like names.
- Detection is only as good as the telemetry: the discovery rules depend on the `cmdaudit`
  ForceCommand, which only sees commands sent over SSH, not what runs inside an interactive shell.
- `sudo-root-shell` and `user-created` are never exercised, so their coverage is unproven.
- Emulated traffic comes from one IP with default-looking user agents; the rules are tuned to
  that, so a quiet, slow adversary would be missed. Windows are matched by time, not by event ids.
- Verified only in a single-host sandbox (Docker with bridge networking), not on a real host.
