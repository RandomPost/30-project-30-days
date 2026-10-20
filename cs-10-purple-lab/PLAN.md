# CS-10 plan: purple-team lab with ATT&CK coverage

Goal: a docker-compose lab where a benign adversary-emulation runner attacks a target
web server and a victim SSH host, their logs flow into the CS-08 mini SIEM, and a
coverage report says, per MITRE ATT&CK technique, whether the SIEM detected it.
Then close at least one gap and show the report change.

## Task list

| # | Task | Owner | Status |
|---|------|-------|--------|
| 1 | Plan + interface contracts (this file) | lead | done |
| 2 | Coverage engine + ATT&CK name table + Markdown/JSON report (`purplelab/coverage.py`, `purplelab/attack.py`) | agent A | done |
| 3 | Technique registry + emulation runner + lab-only safety guard (`purplelab/techniques.py`, `purplelab/emulate.py`) | agent B | done |
| 4 | Docker lab: compose, victim/target/siem/runner images, log pipeline (`lab/`) | agent C | done |
| 5 | CLI, pyproject, integration, README/CLAUDE.md | lead | done |
| 6 | Run the lab end to end, generate the BEFORE report | lead | done |
| 7 | Close a gap in CS-08 (parser + rules + embedded tests), re-run, generate AFTER report | lead | done |
| 8 | Tests green, push, update tracker | lead | done |

Tasks 2, 3, 4 are independent and only meet at the contracts below.

## Contracts

### Emulation log (`emulation.jsonl`, written by the runner, read by coverage)
One JSON object per line, one line per technique execution:
`{"run_id": str, "technique_id": "T1082", "name": str, "tactic": str, "start": ISO8601 UTC with +00:00, "end": ISO8601 UTC with +00:00, "ok": bool, "target": str, "detail": str}`
`ok=false` means the technique could not be executed (e.g. host unreachable); coverage
reports it as `not-run`, never as missed.

### Technique registry (`purplelab/techniques.py`)
```python
@dataclass(frozen=True)
class Technique:
    id: str        # "T1110.001"
    name: str      # ATT&CK name
    tactic: str    # "credential-access"
    channel: str   # "web" | "ssh"
    description: str
    run: Callable[[Context], str]   # returns a short detail string, raises on failure

@dataclass
class Context:
    web_base: str          # "http://target"
    ssh_host: str          # "victim"
    ssh_port: int          # 22
    ssh_user: str; ssh_password: str      # a valid low-priv lab account
    root_password: str                    # lab root password (valid-accounts technique)
    ssh: SshFactory        # callable(user, password) -> SshSession (exec(cmd)->(rc,out), close())
    http: HttpFn           # callable(method, url, headers=None, data=None) -> status int
    sleep: Callable[[float], None]
REGISTRY: dict[str, Technique]  # ordered; techniques below
```
Techniques (all benign, bounded, lab-only):
- T1595.002 Vulnerability Scanning: ~8 requests with a scanner User-Agent (`Nikto/2.5.0`, `sqlmap/1.7`) to common paths
- T1595.003 Wordlist Scanning: ~40 requests for distinct nonexistent paths (404 flood from one IP)
- T1190 Exploit Public-Facing Application: SQLi (`' OR 1=1--`), path traversal (`../../etc/passwd`), `${jndi:ldap://x/a}` strings in query strings (harmless against static nginx)
- T1110.001 Password Guessing: 8 wrong passwords for the lab user over SSH
- T1110.003 Password Spraying: one wrong password against 8 non-existent usernames over SSH
- T1078 Valid Accounts: successful SSH login as `root` with the (weak, lab-only) password, run `true`, exit
- T1082 System Information Discovery: `uname -a`, `cat /etc/os-release`, `hostname`
- T1033 System Owner/User Discovery: `whoami`, `id`, `w`
- T1083 File and Directory Discovery: `ls -la /etc`, `find /home -maxdepth 2`
- T1057 Process Discovery: `ps aux`
- T1016 System Network Configuration Discovery: `ip addr`, `ip route`, `cat /etc/resolv.conf`
- T1087.001 Local Account Discovery: `cat /etc/passwd`, `getent passwd`
- T1036.005 Match Legitimate Name or Location: copy `/bin/sleep` to `/tmp/svchost`, run `/tmp/svchost 1`, remove it
- T1053.003 Cron: install a crontab `* * * * * /bin/true # purplelab` for the lab user, then remove it

Safety guard (`emulate.py`): refuse to run unless `PURPLELAB_LAB=1` is set AND every target host
(web host, ssh host) is in the allowlist (`--allow`, default env `PURPLELAB_ALLOWED_HOSTS`, comma
separated) AND resolves to a private/loopback address. No destructive commands, no external hosts,
hard caps on request counts.

Runner CLI: `purplelab emulate --web http://target --ssh victim:22 --user labuser --password ... --root-password ... --log /logs/emulation.jsonl [--only T1082,T1033] [--allow target,victim] [--pause 1.5]`
(wired by the lead in `cli.py`: agent B exposes `emulate.main(argv) -> int`, `emulate.run(ctx, techniques, log_path, pause, run_id) -> list[dict]`).

### Victim telemetry (what agent C must produce, what the SIEM parses)
Shared volume `logs` mounted at `/logs` in every container. File names matter (CS-08 `guess_source`):
- `/logs/auth.log`: rsyslog, facilities auth+authpriv (sshd, sudo, su, useradd, `cmdaudit`), traditional syslog lines
  `Oct 20 12:00:00 victim sshd[812]: Failed password for ...`
- `/logs/syslog`: rsyslog, everything else (cron, crontab)
- `/logs/nginx-access.log`: nginx combined log format from the target
- `/logs/emulation.jsonl`: the runner log (not parsed as a log source)
- command audit: sshd `ForceCommand /usr/local/bin/audit-shell` logs every remote command with
  `logger -p auth.info -t cmdaudit "user=$USER src=$SSH_CLIENT_IP cmd=$SSH_ORIGINAL_COMMAND"` and then `exec bash -c "$SSH_ORIGINAL_COMMAND"` (bash -l for interactive)
  Resulting line: `Oct 20 12:00:00 victim cmdaudit[901]: user=labuser src=10.77.0.5 cmd=whoami`

Services/names: network `labnet` (internal, no egress), subnet 10.77.0.0/24. Services `target` (nginx), `victim` (ubuntu 24.04
with openssh-server, rsyslog, cron, sudo; accounts `labuser`/`labpass-not-a-secret` and `root`/`rootpass-not-a-secret`),
`siem` (CS-08 `minisiem schedule` over /logs with rules from the bind-mounted `cs-08-minisiem/rules`, db `/data/siem.db`),
`runner` (profile `attack`, runs `purplelab emulate`). `purplelab coverage` runs in the `siem` image.

### Coverage engine (`purplelab/coverage.py`)
```python
load_emulation(path) -> list[Execution]
load_alerts(db_path) -> list[Alert]               # table alerts: rule_id, title, severity, tags (comma sep), first_ts, last_ts, event_count
load_rule_tags(rules_dir) -> dict[str, set[str]]  # rule_id -> {"T1110.001", ...} from tags like attack.t1110.001 (via minisiem.rules.load_rules)
count_events(db_path, start, end) -> int
build_matrix(executions, alerts, rule_tags, event_counter, slack=3.0) -> Matrix
render_markdown(matrix) -> str ; render_json(matrix) -> dict
```
Status per executed technique: `detected` (an alert whose rule is tagged with the technique id, or its parent id, overlaps
[start-slack, end+slack]); else `missed` with a reason: `no-telemetry` (zero events in the window), `no-rule` (no rule maps
to the technique), `rule-did-not-fire` (a rule maps but produced no alert in the window). `ok=false` executions -> `not-run`.
Report also lists rules that map to techniques that were never emulated ("untested detections"), alerts that matched no
technique ("unattributed alerts"), a summary (detected/missed/not-run counts, percent), and a gaps section ordered by tactic.
Markdown report format: title, run id, summary line, table `| Technique | Name | Tactic | Status | Detected by / Reason |`.
