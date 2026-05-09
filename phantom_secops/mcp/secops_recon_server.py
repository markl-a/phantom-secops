"""MCP server: red-team reconnaissance (nmap wrapper).

Wraps tools/nmap_runner.py without modifying it. The existing
_target_in_lab gate inside nmap_runner remains the authoritative scope
check (defense in depth: phantom-mesh policy says target.lab_only,
plugin itself also enforces).

Run as: python -m phantom_secops.mcp.secops_recon_server
Spawned by phantom-mesh via [[mcp_servers]] block in agents.toml.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Make tools/ importable when run as `python -m phantom_secops.mcp.secops_recon_server`
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import nmap_runner  # noqa: E402

from phantom_secops.mcp._xphantom import xphantom_metadata  # noqa: E402


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="scan_target",
            description=(
                "Run nmap against an in-lab service (e.g. juice-shop, dvwa). "
                "Returns parsed open ports + service versions. "
                "Refuses any target that is not a known lab service."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "lab service name"},
                    "ports":  {"type": "string", "default": "top-1000"},
                },
                "required": ["target"],
            },
            metadata=xphantom_metadata(
                "red",
                ["network.scan.passive", "target.lab_only"],
                read_only=True,
            ),
        ),
    ]


def scan_target_impl(args: dict[str, Any]) -> dict[str, Any]:
    target = args["target"]
    ports = args.get("ports", "top-1000")
    return nmap_runner.run(target=target, ports=ports)


server = Server("secops_recon")


@server.list_tools()
async def _list_tools() -> list[Tool]:
    return tool_definitions()


@server.call_tool()
async def _call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name == "scan_target":
        result = scan_target_impl(arguments)
    else:
        raise ValueError(f"unknown tool: {name}")
    import json
    return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False))]


async def _main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
