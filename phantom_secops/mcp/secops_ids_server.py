"""MCP server: host intrusion detection via Sigma rules over Windows event logs.

Wraps tools/ids_scan.scan_intrusions. Read-only — reads recent events from
readable Windows logs (PowerShell Operational, System) and matches bundled
Sigma-style rules for common attacker TTPs (encoded PowerShell, download
cradles, AMSI bypass, credential dumping). Sysmon (admin install) enriches the
source but is not required.

Run as: python -m phantom_secops.mcp.secops_ids_server
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

from tools.ids_scan import scan_intrusions  # noqa: E402

from phantom_secops.mcp._xphantom import xphantom_metadata  # noqa: E402


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="scan_intrusions",
            description=(
                "Host intrusion detection: read recent Windows event-log entries "
                "(PowerShell Operational, System) and match Sigma-style rules for "
                "attacker behaviour (encoded PowerShell, download-and-execute, AMSI "
                "bypass, credential dumping). Returns alerts ordered by level. "
                "Read-only."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "max_events": {
                        "type": "integer",
                        "default": 500,
                        "minimum": 1,
                        "description": "how many recent events per log to inspect",
                    },
                    "max_alerts": {
                        "type": "integer",
                        "default": 25,
                        "minimum": 1,
                        "description": "cap returned alerts (already prioritised)",
                    },
                },
            },
            metadata=xphantom_metadata(
                "blue",
                ["read.event_logs", "target.self_only"],
                read_only=True,
            ),
        ),
    ]


def scan_intrusions_impl(args: dict[str, Any]) -> dict[str, Any]:
    max_events = int(args.get("max_events", 500))
    max_alerts = int(args.get("max_alerts", 25))
    result = scan_intrusions(max_events=max_events)
    # Trim each alert's event Message to keep the payload within token budget.
    trimmed = []
    for a in result["alerts"][:max_alerts]:
        ev = a["event"]
        trimmed.append({
            "title": a["title"],
            "level": a["level"],
            "event_id": ev.get("EventID"),
            "time": ev.get("TimeCreated"),
            "channel": ev.get("Channel"),
            "excerpt": (ev.get("Message") or "")[:200],
        })
    result["alerts"] = trimmed
    return result


server = Server("secops_ids")


@server.list_tools()
async def _list_tools() -> list[Tool]:
    return tool_definitions()


@server.call_tool()
async def _call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name == "scan_intrusions":
        result = scan_intrusions_impl(arguments)
    else:
        raise ValueError(f"unknown tool: {name}")
    return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False))]


async def _main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
