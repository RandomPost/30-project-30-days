# bgplab: multi-AS BGP policy lab

A small internet in containers (containerlab + FRR 8.4.1) to practise routing policy and prove path choice with tests.

```
        AS65001 isp1 ----(10.1.1.0/30)---- cust AS65100 ----(10.1.2.0/30)---- isp2 AS65002
            |                                (dual homed)                          |
            +------------------ IXP LAN 10.99.0.0/24 (bridge `ixp`) ---------------+
                      |                |                 |
                 rs AS65500       content AS65300    rogue AS65666      rtr (RPKI cache, RTR :3323)
```

## Policy implemented
| Goal | Where | How |
|---|---|---|
| Outbound traffic engineering | cust | local-pref 200 from isp1, 100 from isp2 |
| Inbound traffic engineering | cust (A) / isp2 (B) | AS-path prepend towards isp2 so the IXP prefers isp1 |
| Prefix filters | isp1, isp2, cust, rs | customers: only 203.0.113.0/24 (plus RTBH /32s); IXP and RS: bogons denied; peers announce only own prefixes |
| Blackholing | cust, isp1, isp2 | cust tags 203.0.113.66/32 with 65535:666; ISPs set next hop to a discard interface (`rtbh0`), local-pref 500, no-export |
| Origin validation | isp1, isp2, rs | FRR `rpki` + local RTR cache; `invalid` dropped, `valid` local-pref 150, `not found` local-pref 100 |
| Customer preference | isp1, isp2 | customer routes local-pref 300 beat IXP routes (150) even when prepended |

## Run
```
pip install -e . pytest      # sandbox: pip install --ignore-installed pyyaml first if needed
make up                      # DESIGN=b make up for the other design; wait ~90 s (FRR starts slowly)
make test                    # 11 unit tests + 12 lab tests
bgplab matrix                # best path per router
bgplab explain rs 203.0.113.0/24
make down
```

## Why each path wins (real output in `docs/`)
- cust to content (198.18.0.0/24): two equal-length paths, isp1 wins on local-pref 200 vs 100. Lose the isp1 link and isp2 takes over at 100.
- rs to cust (203.0.113.0/24): `65001 65100` beats `65002 65100 65100 65100` on AS-path length. The prepend is the only reason. With the isp1 link down, isp2 is the only path.
- isp2 to cust: its direct customer path (3 hops with prepend) wins over `65001 65100` from the IXP on local-pref 300 vs 150: prepending never moves traffic that an ISP's own customer sends.
- isp1/isp2 to content: only the RS offers it, valid, local-pref 150. rogue's `203.0.113.0/24` and `198.18.0.0/24` are RPKI invalid and never appear on any router.
- `203.0.113.66/32` is RPKI invalid (ROA max length 24) but accepted from the customer on purpose: RTBH is exempt, the customer is the ROA holder. It never reaches the RS.
- `10.66.0.0/16` (customer leak) is dropped by the customers' prefix filter.

## Tests
`tests/test_model.py` parses real `vtysh json` captured from the lab (`tests/fixtures`); `tests/test_rtr.py` checks the RTR PDUs; `tests/test_policy_lab.py` checks best path, reason and next hop under: normal, customer primary link down, backup link down, isp1 IXP port down, both customer links down. Links are restored after each test.
Design comparison: `docs/design-comparison.md` (A and B built in separate git worktrees; both pass the same suite).

## Verified
- All tests pass on design A (23) and on design B (the same lab tests), in a single-host Docker sandbox.
- Hijack, leak and blackhole behaviour, ROV via the real FRR RTR client talking to `rtr/rtrd.py`, RTBH data path installed through a veth discard interface (route shows `via rtbh0`).

## Not verified / caveats
- The RTR server serves a static ROA list: no certificate validation, no real RIR data. It is not a production validator (Routinator/StayRTR would be).
- RTBH uses a veth pair as discard interface because the sandbox kernel has no dummy module; a real router would use a null route. No traffic was sent through it.
- Failover is link-down only (instant carrier loss); silent loss relies on 3/9 s timers, no BFD. No convergence timing was measured beyond "within 90 s".
- If the RTR cache is unreachable, FRR keeps validating with stale data then treats everything as `not found`: hijacks would be accepted. Not exercised.
- FRR 8.4.1 started before the cache was listening may never connect; the lab waits for the cache (clab stages) and `tests/conftest.py` re-adds the cache if needed.
- No IPv6, no iBGP, no multipath. IXP bridge behaves like a switch (no real IXP features).
- Not run on real routers or CI.
