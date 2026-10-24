# ospf-lab

Containerlab lab: three FRRouting routers in a triangle (OSPF area 0, loopbacks) plus two Alpine hosts, with a Python verifier and a failover demo.

## Layout
- `ospf-lab.clab.yml`: topology (lab name `ospf`, containers `clab-ospf-<node>`)
- `configs/rN/frr.conf`, `configs/daemons`, `configs/vtysh.conf`: bind-mounted into the routers
- `ospflab/topology.py`: names, addresses, links, expected prefixes (must match the YAML and frr.conf)
- `ospflab/checks.py`: pure parsing of `vtysh ... json` and ping output; unit-tested with real captured output in `tests/fixtures/`
- `ospflab/lab.py`: `docker exec` wrappers; `ospflab/cli.py`: verify, show, break, restore, failover
- `docs/failover-demo.txt`: real output of `make failover`

## Commands
- `make up`, `make verify`, `make break`, `make restore`, `make failover`, `make down`, `make test`
- Test: `python3 -m pytest`; format: `python3 -m black --target-version py310 .`

## Conventions
- Keep checks.py free of subprocess calls; the CLI feeds it JSON
- Change an address in three places: YAML, the frr.conf files, topology.py
- If FRR is upgraded, re-capture fixtures (`vtysh -c 'show ip route ospf json'`) and re-run the tests
