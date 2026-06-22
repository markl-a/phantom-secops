"""Offline, read-only STATIC scanner for the owner's own MCP config.

Phase-1 of secops's MCP-governance pillar. Pure data in -> ranked findings out:
no network, no I/O in the rule logic, no LLM, and it NEVER connects to any MCP
server (it only reads a config file + an optional, owner-supplied tools/list
dump). Mirrors the deterministic, low-false-positive spine of posture_fusion.
"""

from __future__ import annotations

from dataclasses import dataclass

# Common 0..4 severity scale (4 == most urgent), same vocabulary as posture_fusion.
SEVERITY_NAMES = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}


@dataclass(frozen=True)
class Finding:
    """One ranked, plain-language MCP risk from one deterministic rule."""

    severity: int          # 0..4 (4 == most urgent)
    severity_name: str     # critical | high | medium | low | info
    rule_id: str           # e.g. "tool_poisoning"
    server: str            # MCP server name
    tool: str              # tool name, or "-" for a server-level finding
    owasp: str             # OWASP MCP Top 10 category label
    message: str           # plain-language description (no PoC, advice only)


def _finding(severity: int, rule_id: str, server: str, tool: str, owasp: str, message: str) -> Finding:
    return Finding(severity, SEVERITY_NAMES[severity], rule_id, server, tool, owasp, message)


def summarize(findings: list) -> dict:
    counts = {name: 0 for name in SEVERITY_NAMES.values()}
    for f in findings:
        counts[f.severity_name] = counts.get(f.severity_name, 0) + 1
    counts["total"] = len(findings)
    return counts


import json
import tomllib


def _tool_from_def(d: dict) -> dict:
    meta = d.get("metadata") or {}
    return {
        "name": str(d.get("name", "?")),
        "description": str(d.get("description", "")),
        "classification": meta.get("x-phantom.classification"),
        "capabilities": list(meta.get("x-phantom.capabilities") or []),
        "read_only": meta.get("x-phantom.read_only"),
    }


def parse_config(config_path: str, tools_dump: str | None = None) -> dict:
    """Parse a .mcp.json or an agents.toml ([[mcp_servers]]) into the normalized
    shape. Optionally merge an owner-supplied tools/list dump
    ({server_name: [tool_def, ...]}) so tool-level rules can run. Never connects
    to anything — pure file read."""
    raw = open(config_path, "rb").read()
    servers: list[dict] = []
    if config_path.endswith(".json"):
        data = json.loads(raw.decode("utf-8"))
        for name, s in (data.get("mcpServers") or {}).items():
            servers.append({
                "name": str(name), "command": s.get("command"),
                "args": list(s.get("args") or []), "url": s.get("url"),
                "env": dict(s.get("env") or {}), "tools": [],
            })
    else:
        data = tomllib.loads(raw.decode("utf-8"))
        for s in (data.get("mcp_servers") or []):
            servers.append({
                "name": str(s.get("name", "?")), "command": s.get("command"),
                "args": list(s.get("args") or []), "url": s.get("url"),
                "env": dict(s.get("env") or {}), "tools": [],
            })
    if tools_dump:
        dump = json.loads(open(tools_dump, "rb").read().decode("utf-8"))
        by_name = {s["name"]: s for s in servers}
        for sname, defs in dump.items():
            if sname in by_name:
                by_name[sname]["tools"] = [_tool_from_def(d) for d in defs]
    return {"servers": servers}
