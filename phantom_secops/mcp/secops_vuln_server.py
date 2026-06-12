"""MCP server: dependency / OS-package vulnerability scan (blue / defensive).

Wraps tools/vuln_scan.scan_vulns (Trivy). Read-only — scans a filesystem path
and returns a prioritised, fixable-first CVE queue plus a severity summary. The
agent layer turns the queue into plain-language remediation.

Run as: python -m phantom_secops.mcp.secops_vuln_server
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

from tools.vuln_scan import scan_vulns  # noqa: E402

from phantom_secops.mcp._xphantom import xphantom_metadata  # noqa: E402


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="scan_vulns",
            description=(
                "Scan a filesystem path with Trivy for known-vulnerable OS "
                "packages and language dependencies. Returns findings ordered "
                "by severity (fixable-first) with a summary. Read-only; use it "
                "to triage which CVEs actually matter and draft remediation."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "absolute path to scan (a repo, project, or directory)",
                    },
                    "max_findings": {
                        "type": "integer",
                        "default": 15,
                        "minimum": 1,
                        "description": "cap returned findings (already prioritised, fixable-first)",
                    },
                },
                "required": ["path"],
            },
            metadata=xphantom_metadata(
                "blue",
                ["read.filesystem", "target.self_only"],
                read_only=True,
            ),
        ),
    ]


def scan_vulns_impl(args: dict[str, Any]) -> dict[str, Any]:
    path = args["path"]
    max_findings = int(args.get("max_findings", 15))
    result = scan_vulns(path)
    # Compact each finding (drop the long `title`; the CVE id is enough for the
    # agent to cite and look up) to keep the tool result within the model's
    # per-request token budget.
    result["findings"] = [
        {k: f[k] for k in ("id", "pkg", "installed", "fixed", "severity")}
        for f in result["findings"][:max_findings]
    ]
    return result


server = Server("secops_vuln")


@server.list_tools()
async def _list_tools() -> list[Tool]:
    return tool_definitions()


@server.call_tool()
async def _call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name == "scan_vulns":
        result = scan_vulns_impl(arguments)
    else:
        raise ValueError(f"unknown tool: {name}")
    return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False))]


async def _main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
