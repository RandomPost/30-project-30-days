# sshpot

A low-interaction SSH honeypot in Python (asyncssh) plus a log analytics CLI.

The honeypot speaks real SSH so scanners and bots engage. It accepts logins, records
credentials, public-key fingerprints, client fingerprints and every command, and answers
from canned text. **There is no shell**: nothing an attacker types is executed, no file
is read or written on their behalf, and the process never opens an outbound connection.
Events are written as JSON lines. It is built to run in a locked-down Docker container.

```bash
pip install -e '.[dev]'
pytest                                   # 59 tests

# run it (locally, no Docker)
sshpot serve --port 2222 --log data/sshpot.jsonl
sshpot simulate --port 2222              # a scripted attacker generates a test session
sshpot analyze data/sshpot.jsonl         # summary (add --json or --md)

# run it hardened in Docker
docker compose up -d --build
scripts/verify-hardening.sh              # builds, runs, proves the hardening, attacks it
```

## What it records (JSON lines)

Every line has `ts` (UTC), `event` and, for connection events, `session`, `src_ip`,
`src_port`.

| event | extra fields |
|-------|--------------|
| `connect` / `disconnect` | duration, attempts, commands, authenticated, reason |
| `client` | `client_version` banner, negotiated cipher/mac/compression, `client_id` (hash of those) |
| `auth` | method, username, password, attempt, success |
| `auth_pubkey` | username, key type, key `fingerprint` (never accepted) |
| `session_open` | channel number, shell or exec, terminal type |
| `command` | channel, input, exit status, cwd, URLs and IPs found in it |
| `forward_attempt` / `listen_attempt` | destination (always refused) |
| `refused`, `session_timeout`, `server_start`, `host_key_not_persisted` | operational events |

Login policy: a pair given with `--accept user:pass` is always let in; otherwise a source
IP gets in on its Nth password try (`--accept-after`, default 3, counted across
connections, because most bots try one password per connection).

The fake shell answers about 23 commands with canned output (`uname`, `id`, `cat /etc/passwd`, `ls`, `cd`,
`wget`/`curl`, `ps`, `free` ...) and accepts about 34 more silently (`chmod`, `rm`, `kill` ...), handles `;`, `&&`, `||`, ignores pipes and redirects, and
answers `wget`/`curl` with a name-resolution failure while recording the URL. Unknown
commands get "command not found".

## Analytics

`sshpot analyze LOG` summarizes top usernames, passwords and credential pairs, source
countries (offline GeoIP), top IPs, client versions, public-key fingerprints, top
commands, command transitions, full command sequences per session, download URLs and
connections per hour.

GeoIP is an offline CSV of `start_ip,end_ip,country_code` (IPv4 and IPv6), the layout of
the free DB-IP "IP to Country Lite" file. `--geoip FILE` loads yours. The bundled
`sshpot/data/geoip-sample.csv` is **demo data only** (documentation ranges mapped to codes
XA to XC) so the tool runs offline; it will report real addresses as `??`.

`sshpot sample out.jsonl` writes a deterministic synthetic log (60 sessions across three
sample countries) for trying the analytics.

## Container hardening

| Control | Where |
|---------|-------|
| Non-root user 10001, no login shell | Dockerfile |
| Read-only root filesystem | `read_only: true` |
| All capabilities dropped (listens on 2222, needs none) | `cap_drop: [ALL]` |
| No privilege gain | `no-new-privileges` |
| Only `/data` is writable (log and host key); `/tmp` is a small `noexec` tmpfs | volume + tmpfs |
| Process, memory and CPU limits | `pids_limit`, `mem_limit`, `cpus` |
| Published on loopback only by default | `127.0.0.1:2222:2222` |
| Log file rotates at 50 MB, session/idle/command/connection limits | app config |

`scripts/verify-hardening.sh` checks these against a real container: read-only rootfs,
capabilities dropped, `CapEff` empty, uid 10001, writes to `/app` and `/etc` fail, writes
to `/data` work, nothing executes from `/tmp`, then it attacks the honeypot over SSH and
analyzes the log it wrote.

### Before you expose it
Do not put this on a network you care about. Use a dedicated host or VLAN, move the real
sshd off port 22 (or map the honeypot to another port), and **block outbound traffic from
the container** (for example a `DOCKER-USER` iptables rule): the honeypot never dials out,
but egress filtering is the backstop if that ever fails. The logs hold attackers' passwords
(and any real ones mistyped by the wrong person), so treat them as sensitive.

## Limits

- Not HASSH: asyncssh does not expose the client's offered algorithm lists, so
  `client_id` hashes the banner plus negotiated algorithms.
- Low interaction by design: no file system state, no downloads, no `sftp`/`scp`.
  Sophisticated attackers can tell it is a honeypot.
- Verification here ran Docker with host networking because the sandbox daemon had no
  bridge network; the compose file's published-port path was not exercised.
- Not exercised against real internet traffic; the analytics were run on logs from the
  scripted attacker and the synthetic generator.
