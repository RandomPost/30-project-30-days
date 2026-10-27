# lldpmap

Crawls a network over LLDP/CDP starting from one seed device, saves the topology as JSON, draws it as an interactive graph, and diffs two runs.

## Layout
- `lldpmap/models.py`: `Neighbor`, the only thing a vendor parser returns
- `lldpmap/parsers/`: one module per vendor behind the contract in `base.py`: `frr.py` (lldpd JSON), `eos.py` (Arista text), `ios.py` (Cisco LLDP and CDP text). `__init__.py` has the registry and `guess_vendor`
- `lldpmap/collect.py`: Netmiko; the only module that touches the network
- `lldpmap/crawl.py`: breadth-first crawl, depth limit, dedupe by hostname
- `lldpmap/topology.py`: `Topology`/`Link`/`Device`, JSON load and save (a `Link` has sorted ends so both directions are equal)
- `lldpmap/diff.py`, `lldpmap/graph.py` (pyvis, self-contained HTML), `lldpmap/cli.py`
- `tests/fixtures/frr-*` are REAL lldpd output from the lab; `eos-*` and `ios-*` are hand-written from documentation (see `ios-README.txt`), not captured
- `lab/`, `scripts/`: the NE-04 lab with an image that has sshd and lldpd; `scripts/demo.sh` is the end-to-end demo; `docs/run/` holds a real run

## Commands
- Install: `pip install -e '.[dev]'`; test: `python3 -m pytest` (no lab needed, a fake collector is used)
- Format: `python3 -m black --target-version py310 .`

## Conventions
- Parsers are pure functions of command output; a new vendor = a new module with the base.py contract, a fixture and tests; register it in `parsers/__init__.py`
- Never trust a hand-written fixture as proof a parser works on a real device; say so in the README
- Credentials only from `LLDPMAP_USER` / `LLDPMAP_PASSWORD`
- Do not split generated HTML with `splitlines()`; the inlined JS contains separator characters that it would corrupt
