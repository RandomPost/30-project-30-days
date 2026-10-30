# labmcp: a read-only MCP server for the network lab

Gives Claude six tools to look at the NE-09 BGP lab (containerlab + FRR) and nothing else.

| Tool | What it does |
|---|---|
| `list_devices()` | lab routers and whether each container runs |
| `show_routes(device, prefix?)` | BGP table, or every path for a prefix as FRR JSON (local-pref, AS path, RPKI state, `selectionReason`) plus the RIB entry |
| `show_interfaces(device)` | interfaces and BGP neighbor summary |
| `ping_from(device, target)` | 3 pings from a router to a lab address |
| `get_config_drift(device)` | running-config vs `ne-09-bgplab/designs/<design>/<device>.conf` |
| `run_batfish_check(name)` | an NE-08 Batfish check: `baseline` or a proposed change from `ne-08-batfish/changes` |

## Why it is safe
- **No free-form input.** Arguments are `device`, `prefix`, `target`, `name`. Devices and check names must be on an allow-list; prefixes must be canonical IPv4 CIDR; ping targets must be bare IPv4 addresses inside the lab's address space (no hostnames, no internet, no flags).
- **Commands are fixed.** vtysh commands are built from templates and must also match a regex allow-list of `show` forms in `runner.py` (defence in depth). `configure`, `clear`, `write`, pipes, newlines and `;` are refused. Nothing runs through a shell.
- Ping uses a fixed count and timeout; outputs are clipped to 20 kB.
- All tools carry `readOnlyHint`. Registered tools are exactly those six (tested).

## Use
```
pip install -e .                    # in a venv with mcp>=1.9,<2
claude mcp add netlab -e DOCKER_HOST=... -- python -m labmcp.server     # or: make register
claude mcp list                     # netlab: Connected
```
Needs the NE-09 lab running (`make up` in `ne-09-bgplab`). Env: `LABMCP_DESIGN` (default `a`), `LABMCP_LAB_DIR`, `LABMCP_BATFISH_DIR`, `BATFISH_HOST`.

## Troubleshooting run (real)
I changed `route-map ISP1-IN` on `cust` from local-pref 200 to 50 without telling Claude, then ran `claude -p` with built-in tools disabled so only the netlab tools were available. It called `list_devices`, `show_routes cust 198.18.0.0/24`, `show_interfaces cust` and `get_config_drift cust`, found local-pref 50 vs 100 as the deciding step and the 200 -> 50 drift, and changed nothing. Full prompt, calls and answer: `docs/fault-run.md`.

## Tests
90 tests pass (`pytest`): input rejection (injection strings, hostnames, public IPs, wrong types), command allow-list (including `configure terminal` smuggling), drift on a real captured `show running-config`, every tool through a real in-memory MCP session; 4 more run against the live lab.

## Not verified / caveats
- `run_batfish_check` is only tested for name validation and the "Batfish not reachable" path; I did not start Batfish, so a passing or failing check was not exercised end to end.
- One fault (a local-pref change) was injected and found; other fault types were not tried.
- The drift normalizer knows the FRR 8.4.1 rewrites seen in this lab (well-known community names, auto sequence numbers, empty `rpki` stanza, route-server `attribute-unchanged`); other FRR versions or features may show false drift.
- Read-only here means no tool changes device config; `docker exec` into containers is still the access path, so protect the Docker socket.
- Prefixes `ping` can reach are limited by address range, not by routing: a target in 10.0.0.0/8 that is not in the lab simply times out.
- stdio transport only, one client; no authentication (it inherits the user's).
