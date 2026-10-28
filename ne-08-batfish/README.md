# netcheck: pre-change validation with Batfish

Validate a network change before it is applied. The configs come from the NE-05 source of truth (`ne-05-netgen/data/sites.yml`, 3 sites, 7 devices). Batfish builds a model of the network from them and a pytest suite asserts policies about it. A GitHub Actions workflow runs the suite on every pull request.

```
sites.yml --netgen--> IOS-style configs + overlay (ACLs) --> Batfish --> pytest policies --> pass / fail on the PR
```

## Policies (written before the code that runs them)
| policy | how it is checked |
|---|---|
| users reach their site's router (management loopback), and hq users reach hq servers | `traceroute` from a host address entering the SVI; must be delivered |
| guest VLAN cannot reach management (`10.255.0.0/16`) or the users VLAN | same trace; must be denied. Fails with the full hop-by-hop trace |
| no forwarding loops | `detectLoops` |
| no undefined references (e.g. ACL named in an interface but not defined) | `undefinedReferences` |
| every config file parses completely | `fileParseStatus` |
| no duplicate IP addresses | `ipOwners(duplicatesOnly=True)` |
| the OSPF sessions listed in `network/policy.yml` are established | `ospfSessionCompatibility` |

Git history shows the order: the first commit is `tests/test_policies.py` with nothing to run it (red), the next adds the snapshot builder and makes it green.

## Run it
```
pip install -e ../ne-05-netgen -e .
make up        # Batfish in Docker (docker compose)
make test      # 16 tests, ~5 s
make try CHANGE=changes/bad-guest-acl-reordered.patch
make down
```

## A change that breaks a policy
`changes/` holds proposed changes as patches. `scripts/try-change.sh` applies one to a scratch copy and runs the policies. Real output is in [docs/demo.txt](docs/demo.txt).

| change | result |
|---|---|
| `bad-guest-acl-reordered`: "tidy" the guest ACL by putting `permit ip any any` first | 2 policies fail: guest can reach management and users |
| `bad-ospf-removed-on-uplink`: drop OSPF from hq-sw1's uplink in the source of truth | 2 fail: hq users cannot reach `10.255.1.1` (`NO_ROUTE`), `hq-r1 <-> hq-sw1` OSPF session not established |
| `bad-acl-name-typo`: `GUEST_IN` instead of `GUEST-IN` | 3 fail: ACL undefined, so nothing filters and both guest policies fail too |
| `good-log-guest-denies`: add `log` to the deny line | all 10 pass |

A failure reads like this:
```
POLICY VIOLATION in branch-east: guest host 10.2.2.50 can reach management address 10.255.2.1
  flow 10.2.2.50 -> 10.255.2.1 entering branch-east-sw1[Vlan50]: ACCEPTED
    hop branch-east-sw1
      RECEIVED: Vlan50
      PERMITTED: GUEST-IN (INGRESS_FILTER)
      FORWARDED: ... Routes: [ospf (Network: 10.255.2.1/32 ...
```

## CI
`.github/workflows/ne-08-batfish.yml` (repo root, because the repo holds many projects) runs on pull requests that touch `ne-05-netgen/**` or `ne-08-batfish/**`. It starts `batfish/allinone` as a service container, waits for it, runs the builder tests and the policy suite, and fails the check with the output above.

## Verified and not verified
- Verified locally with Batfish `allinone` in Docker (pybatfish 2026.09): the 16 tests pass on the current network, and the four changes behave as in the table.
- **The GitHub Actions workflow has not run.** I cannot open a pull request in this environment; I checked that the YAML parses and that the commands in it are the ones I ran locally. Its first real run may need small fixes (action versions, service startup time).
- Batfish cannot parse the FRR flat configs netgen emits for routers, so for analysis every device is rendered IOS-style. The addressing, VLANs and OSPF intent are identical, but the FRR text itself is not what Batfish checked. I tried the Cumulus/FRR layouts briefly and did not get them accepted.
- No BGP checks: nothing in the source of truth configures BGP. The three sites are not connected to each other, so there are no inter-site reachability tests.
- The guest ACL lives in an overlay file because netgen cannot express ACLs; guest isolation is checked for the one site that has a guest VLAN (branch-east), and `test_guest_vlans_exist` fails if no guest VLAN exists.
- "Hosts" are synthetic addresses (`.50` in each subnet) injected at the SVI; there are no real hosts in the model.
