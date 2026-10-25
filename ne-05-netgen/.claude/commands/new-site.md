---
description: Add a new site to data/sites.yml (asks for the details, validates, renders)
allowed-tools: Bash(python3 -m netgen:*), Read
---

Add a new site to the source of truth in `data/sites.yml`. Do not edit the YAML by hand: use the `new-site` command, which validates before it writes.

1. Read `data/sites.yml` and list the existing site names and the numbers used in their addresses (`10.<number>.x.x`, loopbacks `10.255.<number>.x`).
2. Ask me, in one message, for:
   - **name**: letters, digits and hyphens, starting with a letter, not already used (e.g. `branch-north`)
   - **site number**: 1-254, not already used. Suggest the lowest free number.
   - **VLANs**: `name=id` pairs, e.g. `users=10,voice=20`. Suggest `users=10,voice=20` if I have no preference.
   Wait for my answer. If I say "defaults", use the suggestions.
3. Run `python3 -m netgen new-site --name <name> --number <number> --vlans <vlans>`.
   - If it refuses, show me the problems and ask what to change. Never work around a validation error by editing the file.
4. Run `python3 -m netgen render` and show the list of new files (not the full diff).
5. Reply with: the site added, the addressing it received (uplink /30, one /24 per VLAN, loopbacks), and the files rendered. Do not commit.
