"""MCP server: phantom self-audit (internal classification).

Scans phantom-mesh's own agents.toml for hygiene issues:
- providers with literal `api_key = "..."` (vs api_key_env)
- weak / missing [cluster].cluster_secret
- [core] host = 0.0.0.0 (exposed listener)

Read-only. Never echoes secret values in findings.

Run as: python -m phantom_secops.mcp.secops_self_audit_server
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phantom_secops.mcp._xphantom import xphantom_metadata  # noqa: E402

DEFAULT_AGENTS_TOML = Path(os.path.expanduser("~")) / ".phantom-mesh" / "agents.toml"


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="audit_local_config",
            description=(
                "Scan phantom-mesh's own agents.toml for plaintext API keys, "
                "weak cluster_secret, and exposed (0.0.0.0) listeners. "
                "Returns findings without echoing secret values."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "absolute path to agents.toml; defaults to ~/.phantom-mesh/agents.toml",
                    },
                },
            },
            metadata=xphantom_metadata(
                "internal",
                ["read.config.local", "target.self_only"],
                read_only=True,
            ),
        ),
    ]


_PROVIDER_HEADER = re.compile(r"^\[providers\.([^\]]+)\]")
_LITERAL_KEY = re.compile(r'^\s*api_key\s*=\s*"([^"]*)"', re.IGNORECASE)


def audit_impl(args: dict[str, Any]) -> dict[str, Any]:
    path = Path(args.get("path") or DEFAULT_AGENTS_TOML)
    findings: list[dict[str, Any]] = []
    if not path.exists():
        return {"findings": [{"check": "missing_file", "severity": "info",
                              "message": f"agents.toml not present at {path}"}],
                "scanned": str(path)}

    text = path.read_text(encoding="utf-8")
    current_section: str | None = None
    for ln, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current_section = stripped[1:-1]
            continue
        if current_section and current_section.startswith("providers."):
            m = _LITERAL_KEY.match(raw)
            if m:
                key_len = len(m.group(1))
                findings.append({
                    "check": "plaintext_api_key",
                    "severity": "high",
                    "section": current_section,
                    "line": ln,
                    "message": (
                        f"{current_section} uses literal api_key (len={key_len}); "
                        "switch to api_key_env to avoid disk-resident secret"
                    ),
                })
        if current_section == "cluster" and stripped.startswith("cluster_secret"):
            value_match = re.search(r'"([^"]*)"', stripped)
            if value_match:
                if len(value_match.group(1)) < 16:
                    findings.append({
                        "check": "weak_cluster_secret",
                        "severity": "high",
                        "line": ln,
                        "message": f"cluster_secret length={len(value_match.group(1))} < 16",
                    })
        if current_section == "core" and stripped.startswith("host"):
            if '"0.0.0.0"' in stripped or "'0.0.0.0'" in stripped:
                findings.append({
                    "check": "exposed_listener",
                    "severity": "medium",
                    "line": ln,
                    "message": "host = 0.0.0.0 binds all interfaces; consider 127.0.0.1 + Tailscale IP only",
                })
    return {"findings": findings, "scanned": str(path)}


server = Server("secops_self_audit")


@server.list_tools()
async def _list_tools() -> list[Tool]:
    return tool_definitions()


@server.call_tool()
async def _call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name == "audit_local_config":
        result = audit_impl(arguments)
    else:
        raise ValueError(f"unknown tool: {name}")
    return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False))]


async def _main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
