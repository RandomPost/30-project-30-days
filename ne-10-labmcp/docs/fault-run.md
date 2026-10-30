# Fault-injection run: Claude using only the netlab MCP tools

Fault (injected by the operator with `vtysh`, not through MCP, before the run): on `cust`, `route-map ISP1-IN` local-preference changed 200 -> 50, then `clear ip bgp 10.1.1.1 soft in`.

Prompt: *Customer router 'cust' is dual-homed to isp1 and isp2 and is supposed to send traffic to 198.18.0.0/24 via isp1. Someone reports it now goes via isp2. Using ONLY the netlab MCP tools, find out what is wrong and why. Explain your reasoning step by step. Do not change anything.*

Command: `claude -p --tools "" --allowedTools mcp__netlab__...` (built-in tools disabled, so the six MCP tools were the only way to look at the lab).

## Tool calls in order

1. `list_devices` `{}`
1. `show_routes` `{"device": "cust", "prefix": "198.18.0.0/24"}`
1. `show_interfaces` `{"device": "cust"}`
1. `get_config_drift` `{"device": "cust"}`

## Claude's answer (verbatim)

**Cause:** the inbound route-map `ISP1-IN` on `cust` sets local-preference 50 on routes from isp1. The intended config sets 200. That change makes isp1 lose to isp2. I changed nothing.

1. **`cust` prefers isp2.** `show_routes cust 198.18.0.0/24` shows two valid paths with the same AS-path length of 2:
   - Via isp1 (10.1.1.1), path `65001 65300`, **locPrf 50**.
   - Via isp2 (10.1.2.1), path `65002 65300`, **locPrf 100**. This is the best path, with `selectionReason: "Local Pref"`.
   - The RIB entry confirms the result: next hop `10.1.2.1, via eth2`.

2. **Both BGP sessions and the isp1 route are healthy.** `show_interfaces cust` shows both neighbours (10.1.1.1 and 10.1.2.1) established and sending prefixes. isp1's path is valid and accessible, so this isn't an outage. isp1 just loses on local-pref, which BGP compares before AS-path length.

3. **The config drifted.** `get_config_drift cust` compares against `ne-09-bgplab/designs/a/cust.conf` and reports:
   - Intended but not running: `route-map ISP1-IN permit 10: set local-preference 200`.
   - Running but not intended: `set local-preference 50`.

   With 200 for isp1 against 100 for isp2, isp1 would win. At 50 it loses.

4. **Timing.** The isp1 path was last updated at 12:17:04. The isp2 path was last updated at 12:13:28, and the isp1 neighbour has been up about 4 minutes. The RIB entry was updated 26 seconds before the query. This fits a recent edit to `ISP1-IN` followed by a session reset or route refresh. The tools don't show who made the change or when.

**Fix, for you to apply:** restore `set local-preference 200` in `route-map ISP1-IN permit 10` on `cust`, then do a soft inbound refresh from isp1 (`clear ip bgp 10.1.1.1 soft in`). Afterwards, re-run `show_routes` to confirm isp1 is best.

I haven't checked whether the local-pref change was deliberate, for example an approved maintenance. Confirm that before reverting.
