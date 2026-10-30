# labmcp

Read-only MCP server (stdio, FastMCP) that exposes the NE-09 BGP lab (`clab-bgp-*` containers) to Claude.

## Layout
- `labmcp/policy.py`: strict input validation (device allow-list, canonical IPv4 prefix, lab-only ping target, check names). Pure.
- `labmcp/runner.py`: the only code that touches the lab. vtysh commands must match `VTYSH_ALLOWED`; `docker exec` is always an argument list, never a shell.
- `labmcp/drift.py`: running-config vs intended config diff (pure; normalizes FRR rewrites)
- `labmcp/tools.py`: the six tools over a `Runner`; `labmcp/server.py`: MCP registration
- `tests/`: `FakeRunner` in `conftest.py` enforces the same allow-list; `test_lab.py` needs the lab and skips otherwise
- `docs/fault-run.md`: real run of Claude finding an injected fault with only these tools

## Commands
- `pip install -e .` (use a clean venv: `mcp>=1.9,<2`; mcp 2.x is not compatible)
- `pytest`; `make register` (= `claude mcp add netlab -- python -m labmcp.server`)

## Conventions
- A new tool must be read-only: add its exact vtysh forms to `VTYSH_ALLOWED`, validate every argument in `policy.py`, mark `readOnlyHint`
- No tool takes a free-form command string; test_server asserts the argument names
- Errors the model should see are `InvalidInput`; keep messages free of paths and secrets
- Format with black (88 cols)
