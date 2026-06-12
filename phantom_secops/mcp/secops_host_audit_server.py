"""MCP server: host security-posture audit (blue / defensive).

Wraps tools/host_audit.audit_host. Read-only — runs only query commands
(firewall state, disk encryption, AV status, listening ports, …) for the
machine it runs on. Never modifies the host.

Run as: python -m phantom_secops.mcp.secops_host_audit_server
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

from tools.host_audit import audit_host  # noqa: E402

from phantom_secops.mcp._xphantom import xphantom_metadata  # noqa: E402


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="audit_host",
            description=(
                "Run read-only security-posture checks on THIS machine "
                "(Windows or macOS): firewall, disk encryption, antivirus / "
                "real-time protection, UAC, listening ports, SIP. Returns "
                "findings tagged pass/warn/fail/unknown with a summary. "
                "Query-only; never changes the host."
            ),
            inputSchema={"type": "object", "properties": {}},
            metadata=xphantom_metadata(
                "blue",
                ["read.host_posture", "target.self_only"],
                read_only=True,
            ),
        ),
    ]


def audit_host_impl(args: dict[str, Any]) -> dict[str, Any]:
    return audit_host()


server = Server("secops_host_audit")


@server.list_tools()
async def _list_tools() -> list[Tool]:
    return tool_definitions()


@server.call_tool()
async def _call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name == "audit_host":
        result = audit_host_impl(arguments)
    else:
        raise ValueError(f"unknown tool: {name}")
    return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False))]


async def _main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
