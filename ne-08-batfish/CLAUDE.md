# netcheck (ne-08-batfish)

Pre-change validation: build a Batfish snapshot from the netgen source of truth (`ne-05-netgen/data/sites.yml`) plus per-device overlay files, and check policies with pytest. Runs on every pull request via `.github/workflows/ne-08-batfish.yml` (repo root).

## Layout
- `netcheck/snapshot.py`: renders every device IOS-style (Batfish cannot parse FRR flat files), appends `network/overlay/<device>.cfg`, writes `<out>/configs/`
- `netcheck/expect.py`: expectations derived from the source of truth (VLAN subnets by name, router loopbacks) and `trace()`, the one Batfish traceroute helper
- `network/policy.yml`: intent kept OUT of the source of truth (OSPF sessions that must be up)
- `network/overlay/`: what netgen cannot express yet (the guest ACL)
- `tests/test_snapshot.py` (no Batfish) and `tests/test_policies.py` (needs Batfish at `BATFISH_HOST`, default localhost)
- `changes/*.patch`: proposed changes (three bad, one good); `scripts/try-change.sh <patch>` applies one to a scratch copy and runs the policies; `scripts/demo.sh` runs all
- `docker-compose.yml`: the Batfish service; `NETCHECK_SOURCE` / `NETCHECK_OVERLAY` point the suite at a different network

## Commands
- `make up` (Batfish), `make test`, `make try CHANGE=changes/<x>.patch`, `make down`
- Install: `pip install -e ../ne-05-netgen -e .`; format: `python3 -m black --target-version py310 .`

## Conventions
- Test first: a new policy goes into tests/test_policies.py before any config changes; it must fail for the right reason on a bad change (add a patch in `changes/`)
- A policy must not be derived from the thing it checks. OSPF expectations live in policy.yml for that reason
- Isolation tests iterate over VLANs named `guest`; `test_guest_vlans_exist` keeps them from passing vacuously
- If a policy needs ACLs in netgen, add them to netgen and delete the overlay file rather than growing the overlay
