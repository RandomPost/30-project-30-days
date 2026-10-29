# bgplab

Multi-AS BGP policy lab on containerlab + FRR 8.4.1, with pytest checks of the best path on every router.

## Layout
- `bgp-lab.clab.yml`: topology (cust AS65100, isp1 AS65001, isp2 AS65002, rs AS65500, content AS65300, rogue AS65666, ixp bridge, rtr cache)
- `designs/a|b/<node>.conf`: FRR configs per policy design (`DESIGN=a|b`); a = customer prepends, b = ISP2 prepends on an action community
- `rtr/rtrd.py`, `rtr/roas.json`: local RPKI cache speaking RTR (RFC 8210) with static ROAs
- `bgplab/model.py`: pure parsing of `show bgp ipv4 unicast <p> json` + `explain` text (no I/O)
- `bgplab/lab.py`: `docker exec` wrappers, polling (`wait_for`), link up/down; `cli.py`: `bgplab explain|matrix`
- `tests/test_model.py` (real captured JSON in `tests/fixtures`), `tests/test_rtr.py`, `tests/test_policy_lab.py` (needs the lab, marker `lab`, auto-skipped when it is down)
- `docs/`: real outputs and the A/B comparison

## Commands
- `pip install -e . pytest black`; `make up` (wait ~90 s), `make test`, `make down`
- `bgplab explain isp2 203.0.113.0/24`
- Sandbox: `DOCKER_HOST` must point at the running dockerd; images come from mirror.gcr.io when `HTTPS_PROXY` is set

## Conventions
- Tests must pass on both designs: assert path choice and reason, not config text; exact AS paths only where both designs agree
- Never assert right after a change: use `lab.wait_for(converged(...))`
- Failure tests take links down through the `link_down` fixture, which restores them and waits for reconvergence
- Policy changes go in `designs/`; keep node names and IPs stable (tests and fixtures rely on them)
- Format with black (88 cols)
