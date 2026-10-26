# confdrift

Back up router configs into git and find out when a router no longer matches what it should be.

```
routers --SSH/Netmiko--> running config --> redact + strip CLI noise --> backups/ (git, 1 commit per run)
                               |
netgen source of truth (NE-05) --> intended config --> compare --> drift report per device
```

- **backup**: logs in to every device in `devices.yml`, saves `<device>.cfg` with secrets masked, makes **one commit per run**. The subject names what changed (`backup: config changed on r1 (+1/-1 lines)`), the body lists the changed lines per device and any device that could not be reached. No change, no commit.
- **drift**: compares each running config with the config [netgen](../ne-05-netgen) renders from the source of truth and prints a readable report per device. Exit code 0 clean, 1 drift, 2 error (so cron or CI can alert).
- **credentials**: only from `CONFDRIFT_USER` and `CONFDRIFT_PASSWORD`. `devices.yml` has no field for them and refuses keys like `password`, `secret`, `token`.

## Try it on the lab
The routers are the NE-04 OSPF lab (needs Docker and containerlab). The lab's stock FRR image has no SSH server, so `lab/Dockerfile` builds one with sshd and the same FRR family (Ubuntu 24.04, FRR 8.4.x).

```
pip install -e ../ne-05-netgen -e '.[dev]'
export LAB_SSH_PASSWORD=$(python3 -c 'import secrets;print(secrets.token_urlsafe(12))')   # throwaway, baked into the lab image only
make lab-up
export CONFDRIFT_USER=netops CONFDRIFT_PASSWORD=$LAB_SSH_PASSWORD
make demo          # drift (clean) -> backup -> manual change on r1 -> drift -> backup -> git diff -> revert
make lab-down
```

`docs/demo.txt` is a real run. The manual change (`ip ospf cost 100` on r1 eth2) shows up three ways:

```
$ python3 -m confdrift drift
r1: DRIFT (2 line(s) differ)
  [interface eth2]
    missing on device: ip ospf cost 10
    unexpected on device: ip ospf cost 100
...
(exit 1)

$ python3 -m confdrift backup
backup: config changed on r1 (+1/-1 lines)

$ git -C backups diff HEAD~1 HEAD
 interface eth2
  ip ospf area 0
- ip ospf cost 10
+ ip ospf cost 100
```

Other commands: `confdrift intended` (print the rendered intended configs), `confdrift log r1` (history of one device).

## How comparison works
Both configs are cut into blocks (a top-level line plus its indented children). Comments, `exit`/`end`, FRR header lines (`frr version`, `log ...`) and secrets are dropped, then each block is compared as a set of lines. Differences are reported as lines missing on the device, lines unexpected on the device, or whole blocks present on one side only, followed by a unified diff. A rotated password is not drift because secrets are masked on both sides.

## Adding a device
Add it to `devices.yml` (`name`, `host`, optional `device_type` / `command` / `port`) and to the netgen source of truth under the same name. For a Cisco IOS device use `device_type: cisco_ios` and `command: show running-config`; the redaction and noise rules already cover common IOS lines, but that path is untested here (see below).

## Verified and not verified
- 40 unit tests pass without a lab. They use real `vtysh show running-config` output from the NE-04 lab as fixtures and a fake fetcher.
- End to end against a live lab, over real SSH with Netmiko 4.8: all three routers compared clean against the netgen render, a manual change was caught as drift and as a git diff, reverting it made drift disappear (`docs/demo.txt`).
- Not tested: real Cisco IOS or any non-FRR device. Netmiko supports them but only `linux` + `vtysh` was run. Redaction patterns were unit-tested on sample lines, not on real device output.
- The lab image was built in a sandbox through mirrors (`mirror.gcr.io`, an apt proxy); `scripts/lab.sh` detects that via `HTTPS_PROXY`. On a normal host it uses Docker Hub. The containerlab binary used here was the patched source build from NE-04 (sandbox-only workaround).
- Netmiko auto-accepts unknown SSH host keys (its default). Fine for a lab; for production pin keys.
- Block comparison ignores line order, so it is wrong for ordered constructs such as ACLs and route-maps.
