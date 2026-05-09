"""MCP server: blue-team log anomaly scanner.

Wraps tools/log_anomaly.scan_log_lines. The pattern matcher is shared
with run_kill_chain.py's blue pipeline.

Run as: python -m phantom_secops.mcp.secops_log_server
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.log_anomaly import scan_log_lines  # noqa: E402

from phantom_secops.mcp._xphantom import xphantom_metadata  # noqa: E402


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="scan_log",
            description=(
                "Scan a log file for known attack patterns "
                "(sqli/traversal/xss/admin/scanner). URL-decodes each "
                "line before matching. Returns alert objects."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path":      {"type": "string", "description": "absolute path to log file"},
                    "max_lines": {"type": "integer", "default": 10000, "minimum": 1},
                    "asset":     {"type": "string", "default": "unknown"},
                },
                "required": ["path"],
            },
            metadata=xphantom_metadata(
                "blue",
                ["read.log_files", "target.localhost_only"],
                read_only=True,
            ),
        ),
    ]


def scan_log_impl(args: dict[str, Any]) -> dict[str, Any]:
    path = Path(args["path"])
    max_lines = int(args.get("max_lines", 10000))
    asset = args.get("asset", "unknown")
    alerts = scan_log_lines(path, max_lines=max_lines, asset=asset)
    return {"alerts": alerts, "scanned": str(path), "max_lines": max_lines}


server = Server("secops_log")


@server.list_tools()
async def _list_tools() -> list[Tool]:
    return tool_definitions()


@server.call_tool()
async def _call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name == "scan_log":
        result = scan_log_impl(arguments)
    else:
        raise ValueError(f"unknown tool: {name}")
    return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False))]


async def _main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
