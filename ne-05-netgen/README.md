# netgen

Network config generation from a source of truth. Describe sites, devices, interfaces, VLANs and addresses in one YAML file; netgen validates it, renders Cisco IOS-style and FRR configs with Jinja2, and shows a diff against what you rendered last time.

```
data/sites.yml --Pydantic--> checks --Jinja2--> rendered/<device>.cfg
                              (schema + whole-inventory rules)      (+ unified diff vs last render)
```

## Quick start
```
pip install -e '.[dev]'
netgen validate                 # OK: 3 sites, 7 devices
netgen diff                     # what would change (exit 2 with --check if anything)
netgen render                   # shows the diff, then writes changed files to rendered/
netgen new-site --name branch-north --number 4 --vlans users=10,voice=20
python3 -m pytest               # 42 tests
```

The shipped inventory has three sites: `hq` (FRR router, two IOS switches with a trunk between them), `branch-east` and `branch-west` (FRR router plus an IOS L3 switch each). `platform: ios` picks `templates/ios.j2`, `platform: frr` picks `frr.j2`.

## Validation
Schema (Pydantic): optional OSPF tuning per interface (`ospf_cost`, `ospf_hello` + `ospf_dead`, `ospf_passive`, FRR only); VLAN ids 1-4094, IPv4 with prefix length, interface mode rules (access needs `vlan`, trunk needs `trunk_vlans`, SVI needs both plus an IP), unknown fields rejected.

Whole-inventory rules (`netgen/validate.py`):
- the same IP on two interfaces anywhere in the inventory
- two interfaces of one device in the same subnet
- duplicate site or device names; duplicate VLAN id or name within a site
- a port or SVI using a VLAN the site does not define
- link ends that disagree: mode, trunk allowed list, access VLAN, subnet; ends that do not exist or are used twice
- OSPF interface on a device without a loopback (needed for the router-id)

Example (`docs/demo.txt`):
```
data/sites.yml: 3 validation error(s)
  - duplicate IP 10.1.1.1 on hq-sw1 Vlan10, branch-east-sw1 Vlan10
  - hq: hq-sw1 GigabitEthernet0/24 uses VLAN 31, which the site does not define
  - hq: link hq-sw1:GigabitEthernet0/24 <-> hq-sw2:GigabitEthernet0/1: trunk VLAN mismatch ([10, 20, 31] vs [10, 20, 30])
```
Invalid sources are never rendered.

## Diff against the last render
`rendered/` is the last render. `netgen diff` and `netgen render` compare new text with the files there and print `new`, `changed` or `unchanged` per device plus a unified diff for changes. `--check` makes `diff` exit 2 when anything differs, which suits CI.

## /new-site
`.claude/commands/new-site.md` is a Claude Code slash command. Start Claude Code in this folder and type `/new-site`: it lists the used site names and numbers, asks for name, site number and VLANs, runs `netgen new-site`, and renders. `netgen new-site` builds a standard site (one FRR router, one IOS L3 switch, `10.<n>.0.0/30` uplink, a `/24` per VLAN, loopbacks `10.255.<n>.1/.2`), validates the whole file with it added, and only then appends it as text, so comments in `sites.yml` survive. Bad input is refused and the file stays untouched.

## What was and was not verified
- 42 unit tests pass, including: `new-site` adds a 4th site to a copy of the source of truth, the file validates and all four sites render; each validation rule fires on a crafted bad case; `rendered/` matches the templates.
- The three FRR configs were loaded into a real FRR 8.4.1 (`vtysh -f`) and produced no errors. The IOS-style output was **not** checked on real IOS or a simulator; it follows IOS syntax but is unverified there.
- The `/new-site` slash command itself (the Markdown prompt) was written but not run interactively in this build; the command it drives, `netgen new-site`, is what the tests cover.
- Scope: IPv4 only, one OSPF process, `new-site` makes one fixed site shape; other shapes are written in YAML by hand.
