"""Talk to the real FastMCP server over an in-memory MCP session."""

import asyncio
import json

from mcp.shared.memory import create_connected_server_and_client_session

from labmcp import server

EXPECTED = {
    "list_devices",
    "show_routes",
    "show_interfaces",
    "ping_from",
    "get_config_drift",
    "run_batfish_check",
}


def run(cfg, fn):
    async def go():
        srv = server.build(cfg)
        async with create_connected_server_and_client_session(
            srv._mcp_server
        ) as client:
            return await fn(client)

    return asyncio.run(go())


def test_exactly_six_tools_all_read_only(cfg):
    tools = run(cfg, lambda c: c.list_tools()).tools
    assert {t.name for t in tools} == EXPECTED
    assert all(t.annotations and t.annotations.readOnlyHint for t in tools)


def test_no_tool_takes_a_free_form_command(cfg):
    tools = run(cfg, lambda c: c.list_tools()).tools
    names = {p for t in tools for p in t.inputSchema.get("properties", {})}
    assert names <= {"device", "prefix", "target", "name"}


def test_call_through_protocol(cfg):
    res = run(cfg, lambda c: c.call_tool("list_devices", {}))
    assert json.loads(res.content[0].text)["cust"]["running"] is True


def test_injection_over_protocol_is_an_error_result(cfg, runner):
    res = run(
        cfg,
        lambda c: c.call_tool(
            "show_routes",
            {"device": "cust", "prefix": "1.2.3.0/24; configure terminal"},
        ),
    )
    assert res.isError and runner.vtysh_calls == []
    # an unknown argument is ignored, never executed
    run(
        cfg,
        lambda c: c.call_tool(
            "show_routes", {"device": "cust", "command": "configure terminal"}
        ),
    )
    assert runner.vtysh_calls == [("cust", "show bgp ipv4 unicast")]
