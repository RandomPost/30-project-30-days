# netgen

Config generator: YAML source of truth -> Pydantic schema -> whole-inventory validation -> Jinja2 templates (Cisco IOS-style and FRR) -> files plus a diff against the last render.

## Layout
- `data/sites.yml`: the source of truth (3 sites, 7 devices); `rendered/`: committed output, one `<device>.cfg` each
- `netgen/models.py`: Pydantic models (field and per-interface rules, `extra="forbid"`)
- `netgen/validate.py`: rules that need the whole inventory: duplicate IPs/names, undefined VLANs, link end mismatches (mode, trunk list, access VLAN, subnet), OSPF without loopback
- `netgen/render.py`: Jinja2 environment (StrictUndefined), filters `host/netmask/wildcard/network`, `plan()` and `diff()`
- `netgen/templates/ios.j2`, `frr.j2`: one template per `platform`
- `netgen/scaffold.py`: builds a standard site and appends it to the YAML as text (comments survive) only if the result validates
- `netgen/cli.py`: `validate`, `diff [--check]`, `render [--dry-run] [-q]`, `new-site`
- `.claude/commands/new-site.md`: the `/new-site` slash command; run Claude Code from this folder so it is found

## Commands
- Install: `pip install -e '.[dev]'`; test: `python3 -m pytest`; format: `python3 -m black --target-version py310 .`
- After changing a template or `data/sites.yml`, run `python3 -m netgen render` and commit `rendered/` (a test fails if it is stale)

## Conventions
- New rule: add it to validate.py with a positive and a negative test in tests/test_validate.py
- Templates must not guess: StrictUndefined makes a missing field an error
- `/new-site` must go through `netgen new-site`, never edit sites.yml directly
