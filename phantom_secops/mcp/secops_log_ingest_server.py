"""MCP server: blue-team polling log scanner (log_ingest wrapper).

Wraps tools/log_ingest.scan_window without modifying it. Where secops_log
(log_anomaly) scans a single named log file on demand, this exposes the
*polling* variant the blue agent calls repeatedly: it sweeps every
reports/lab-logs/*.log, pattern-matches each line, and appends matched alerts
to reports/lab-logs/alerts.jsonl.

This server exists so the otherwise-unreachable scan_window scanner is reachable
from the production phantom-mesh CLI path (registered via `make mesh-mcp-config`,
alongside secops_log) instead of being unit-tested dead code.

Honesty note: scan_window APPENDS to its own alerts journal, so this tool is
NOT read-only (it does not, however, modify the audited host — only its own
output journal). The x-phantom metadata advertises read_only=False truthfully.

Run as: python -m phantom_secops.mcp.secops_log_ingest_server
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

from tools.log_ingest import scan_window  # noqa: E402

from phantom_secops.mcp._xphantom import xphantom_metadata  # noqa: E402


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="scan_window",
            description=(
                "Poll the lab access logs (reports/lab-logs/*.log) for known "
                "attack patterns (sqli/traversal/xss/admin/scanner) and APPEND "
                "matched alerts to reports/lab-logs/alerts.jsonl. Designed to be "
                "called repeatedly by the blue-log-anomaly agent. Returns the "
                "count of alerts emitted and the journal path."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "window_seconds": {"type": "integer", "default": 30, "minimum": 1},
                },
            },
            metadata=xphantom_metadata(
                "blue",
                ["read.log_files", "write.alerts_journal", "target.localhost_only"],
                read_only=False,
            ),
        ),
    ]


def scan_window_impl(args: dict[str, Any]) -> dict[str, Any]:
    window_seconds = int(args.get("window_seconds", 30))
    return scan_window(window_seconds=window_seconds)


server = Server("secops_log_ingest")


@server.list_tools()
async def _list_tools() -> list[Tool]:
    return tool_definitions()


@server.call_tool()
async def _call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name == "scan_window":
        result = scan_window_impl(arguments)
    else:
        raise ValueError(f"unknown tool: {name}")
    return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False))]


async def _main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
