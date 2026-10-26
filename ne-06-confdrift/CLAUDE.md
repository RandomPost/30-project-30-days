# confdrift

Backs up router running configs over SSH (Netmiko) into a git repo, one commit per run, and reports drift against the intended config rendered by `ne-05-netgen`.

## Layout
- `confdrift/config.py`: `devices.yml` schema and credentials. Credentials come only from `CONFDRIFT_USER` / `CONFDRIFT_PASSWORD`; the schema rejects any credential-looking key
- `confdrift/fetch.py`: `NetmikoFetcher` (device_type `linux` + `vtysh -c 'show running-config'` for FRR; any Netmiko type and command per device)
- `confdrift/normalize.py`: config -> blocks; `IGNORE` lists FRR header lines; `strip_chrome` drops per-run CLI chatter
- `confdrift/redact.py`: masks secrets before anything is stored or compared
- `confdrift/drift.py`: block-level comparison and the readable report
- `confdrift/store.py`: git repo of `<device>.cfg`; `describe()` writes commit subject/body
- `confdrift/cli.py`: `backup`, `drift` (exit 0 clean, 1 drift, 2 error), `intended`, `log`
- `intended/lab.yml`: netgen source of truth for the NE-04 routers (must match `ne-04-ospf-lab/configs`)
- `lab/`: Dockerfile + entrypoint for an FRR image with sshd; `scripts/lab.sh` brings the NE-04 lab up with it; `scripts/demo.sh` is the end-to-end demo
- `tests/fixtures/`: real `vtysh` output captured from the lab, plus the matching netgen render

## Commands
- Install: `pip install -e ../ne-05-netgen -e '.[dev]'`
- Test: `python3 -m pytest` (no lab needed; a fake fetcher serves the captured configs)
- Format: `python3 -m black --target-version py310 .`

## Conventions
- Tests use a fake `Fetcher`; only `fetch.py` imports Netmiko
- Never log or store a password; redaction runs before write and before compare
- Comparison ignores line order inside a block. Do not use it for ordered lists (ACLs, route-maps) without changing `normalize.canonical`
- Keep commits small; commit message says what changed on which device
