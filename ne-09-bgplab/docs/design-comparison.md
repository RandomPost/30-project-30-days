# Design A vs design B (built in two git worktrees)

Both designs pass the same 23 tests (12 lab tests, normal and failure); only the way
inbound traffic engineering (the prepend towards ISP2) is expressed differs.

| | A: customer prepends | B: ISP2 prepends on an action community |
|---|---|---|
| Customer config | `set as-path prepend 65100 65100` in ISP2-OUT | `set community 65002:3 additive` in ISP2-OUT |
| ISP2 config | nothing extra | community-list + 2 route-map entries (about 6 lines) |
| Path the IXP sees | `65002 65100 65100 65100` | `65002 65002 65002 65100` |
| Needs ISP cooperation | no | yes (a published community) |
| Total config diff vs the other | 0 extra lines on ISPs | +7 lines, -1 line |

Verdict: A is simpler for one customer and one knob: one line, no contract with the ISP, and
the same result for the route server. B pays off when many customers share an ISP or the
ISP wants to own the knob (several actions: prepend 1/2/3, no-export to IXP, set local-pref),
because the customer config then stays a list of tags. B also has one more failure mode:
a mistyped community silently does nothing, whereas a wrong prepend is visible in the
customer's own config. The tests cannot tell the designs apart on purpose: they assert
which path wins and why, not how the config got there.
