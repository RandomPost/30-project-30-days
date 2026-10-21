# netplan

A subnet calculator, VLSM planner and overlap checker for IPv4 and IPv6, built on the
standard library `ipaddress` module with `rich` tables.

```bash
pip install -e '.[dev]'
pytest                                          # 60 tests

netplan info 192.168.1.0/24 2001:db8::/64       # network, broadcast, usable range, mask, wildcard
netplan vlsm 192.168.10.0/24 Sales=100 Eng=50 Mgmt=25 Srv=10 Link=2
netplan vlsm 10.0.0.0/24 -f requirements.txt    # one NAME=HOSTS per line, # comments
netplan overlap 10.0.0.0/8 10.1.0.0/16 192.168.0.0/24   # exit 1 if anything overlaps
```

Every command takes `--json`. Errors exit 2, overlaps exit 1, so it can gate scripts.

## VLSM example (checked by hand, and by a test)

`netplan vlsm 192.168.10.0/24 Sales=100 Eng=50 Mgmt=25 Srv=10 Link=2`

| Name | Hosts | Needs | Subnet | Usable range |
|---|---|---|---|---|
| Sales | 100 | /25 (126 usable) | 192.168.10.0/25 | .1 - .126 |
| Eng | 50 | /26 (62) | 192.168.10.128/26 | .129 - .190 |
| Mgmt | 25 | /27 (30) | 192.168.10.192/27 | .193 - .222 |
| Srv | 10 | /28 (14) | 192.168.10.224/28 | .225 - .238 |
| Link | 2 | /30 (2) | 192.168.10.240/30 | .241 - .242 |

Left over: `192.168.10.244/30` and `192.168.10.248/29` (95.3% used). Requirements are placed
largest first, so every block lands on its own size boundary with no gaps between them.

## Edge cases it handles

- **/31 (IPv4)**: a point-to-point link (RFC 3021). Both addresses are usable, there is no network
  or broadcast address. Shown as 2 usable, broadcast `n/a`.
- **/32 (IPv4)**: one address, usable as a host route. 1 usable.
- **/30**: the classic 2-host link, but only because 2 of its 4 addresses are lost to network and broadcast.
- **VLSM and /31, /32**: by default 1 or 2 hosts get a /30, the conservative choice for gear that
  does not support RFC 3021. `--rfc3021` gives 2 hosts a /31 and 1 host a /32.
- **IPv6**: no broadcast and no wildcard mask. The all-zeros address (Subnet-Router anycast) is reserved,
  so a /64 has 2^64 - 1 usable. /127 (RFC 6164) and /128 behave like /31 and /32. Host counts above 2^53
  are exact, because prefix sizing uses integer bit lengths, not floating-point logs.
- **Host bits in input**: `192.168.1.77/24` is normalised to `192.168.1.0/24`, with a note.
- **Overlaps**: CIDR blocks either nest or are disjoint, so there is no partial overlap; the report says
  `contains` or `duplicate`. IPv4 and IPv6 are never compared.

## Limits

- No supernet/summarisation command; no non-contiguous wildcard masks.
- VLSM sizes by host count only (no growth headroom option); allocation always starts at the parent's first address.
- Table layout is wide (120 columns when piped); use `--json` for scripts.
