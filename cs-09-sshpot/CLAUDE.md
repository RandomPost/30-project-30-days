# sshpot

Low-interaction SSH honeypot (asyncssh) + JSONL log analytics, built to run hardened in Docker.

## Layout
- `sshpot/server.py`: asyncssh server; auth policy, event logging, session handling
- `sshpot/fakeshell.py`: pure fake shell (canned output; never executes anything)
- `sshpot/logs.py`: JSONL logger (clipping, rotation)
- `sshpot/analytics.py`: log -> report (text/JSON/Markdown); `sshpot/geoip.py`: offline CSV GeoIP
- `sshpot/sample.py` synthetic logs; `sshpot/simulate.py` scripted attacker; `sshpot/cli.py`
- `Dockerfile`, `docker-compose.yml`, `scripts/verify-hardening.sh`
- `tests/`: pytest (async server tests use real loopback SSH)

## Commands
- Install: `pip install -e '.[dev]'`
- Test: `python -m pytest`
- Format: `black .`
- Demo: `sshpot sample /tmp/s.jsonl && sshpot analyze /tmp/s.jsonl`
- Docker check: `scripts/verify-hardening.sh` (needs a Docker daemon)

## Conventions
- The honeypot must never run a command, spawn a process, open a socket or fetch a URL on an attacker's behalf. `tests/test_fakeshell.py` enforces this with an AST check; add any new module that handles attacker input to it
- Attacker-controlled text is only ever logged as JSON strings (clipped) and shown in reports as inert text (Markdown code spans)
- New fake-shell commands: add a `cmd_<name>` method returning `(output, status, exit)` and a test
- New log events: document the fields in README and handle missing fields in `analytics.py`
- Keep the container non-root, read-only, with no capabilities; do not widen the compose file without updating `tests/test_deploy_and_cli.py`
