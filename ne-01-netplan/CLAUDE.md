# netplan

Python CLI: subnet calculator (`info`), VLSM planner (`vlsm`), overlap checker (`overlap`) for IPv4/IPv6.

## Layout
- `netplan/info.py`: `describe(cidr) -> NetworkInfo`, usable-host maths (no iteration over hosts)
- `netplan/vlsm.py`: `prefix_for_hosts`, `plan` (largest first, aligned), `free_blocks`
- `netplan/overlap.py`: sweep-based `find_overlaps`
- `netplan/render.py`: rich tables and JSON-able dicts
- `netplan/cli.py`: argparse; the only module that reads files or sets exit codes
- `tests/`: pytest, one file per module plus CLI

## Commands
- Install: `pip install -e '.[dev]'`
- Test: `python3 -m pytest`
- Format: `python3 -m black --target-version py310 .`
- Try it: `netplan vlsm 192.168.10.0/24 A=100 B=50 C=25`

## Conventions
- Type hints on all functions; `from __future__ import annotations`; format with black (88 cols)
- Never iterate `net.hosts()` in library code: a /64 has 2^64 addresses. Compute counts arithmetically
  (a test compares against `hosts()` only on small blocks)
- No floating point for address maths; use `int.bit_length()`
- Exit codes: 0 ok, 1 overlaps found, 2 bad input
- New behaviour (especially an edge case) gets a test with the reasoning in its docstring
