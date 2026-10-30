"""MCP server (stdio). Register: claude mcp add netlab -- python -m labmcp.server"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from . import tools
from .runner import DockerRunner

READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
)


def build(cfg: tools.Config | None = None) -> FastMCP:
    cfg = cfg or tools.Config(runner=DockerRunner())
    mcp = FastMCP("netlab")

    @mcp.tool(annotations=READ_ONLY)
    def list_devices() -> str:
        """List the lab routers and whether each container is running."""
        return tools.dumps(tools.list_devices(cfg))

    @mcp.tool(annotations=READ_ONLY)
    def show_routes(device: str, prefix: str | None = None) -> str:
        """BGP table of a router; with an IPv4 prefix (e.g. 198.18.0.0/24) shows every path
        with local-pref, AS path, RPKI state and why the best one won, plus the RIB entry.
        """
        return tools.show_routes(cfg, device, prefix)

    @mcp.tool(annotations=READ_ONLY)
    def show_interfaces(device: str) -> str:
        """Interface state/addresses and BGP neighbor summary of a router."""
        return tools.show_interfaces(cfg, device)

    @mcp.tool(annotations=READ_ONLY)
    def ping_from(device: str, target: str) -> str:
        """Send 3 pings from a router to an IPv4 address inside the lab address space."""
        return tools.ping_from(cfg, device, target)

    @mcp.tool(annotations=READ_ONLY)
    def get_config_drift(device: str) -> str:
        """Diff a router's running-config against its intended config file."""
        return tools.dumps(tools.get_config_drift(cfg, device))

    @mcp.tool(annotations=READ_ONLY)
    def run_batfish_check(name: str) -> str:
        """Run a Batfish pre-change check by name ('baseline' or a proposed change); needs Batfish running."""
        return tools.dumps(tools.run_batfish_check(cfg, name))

    return mcp


def main() -> None:
    build().run()


if __name__ == "__main__":
    main()
