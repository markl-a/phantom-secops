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


import ipaddress
import re

# Conservative inline-secret heuristic: long high-entropy-ish tokens / known prefixes.
_SECRET_RE = re.compile(r"(sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|[A-Za-z0-9_\-]{32,})")
_VERSION_RE = re.compile(r"@[0-9]+\.[0-9]+")  # a pinned semver-ish suffix


def rule_unpinned(config: dict) -> list:
    out = []
    for s in config["servers"]:
        cmd = (s.get("command") or "").lower()
        if cmd in ("npx", "uvx", "pipx") or cmd.endswith("/npx"):
            args_joined = " ".join(s.get("args") or [])
            if not _VERSION_RE.search(args_joined):
                out.append(_finding(
                    2, "unpinned_supply_chain", s["name"], "-", "supply-chain",
                    f"server '{s['name']}' fetches code at runtime via {cmd!r} with no pinned "
                    f"version (rug-pull risk; pin a version or vendor the server)",
                ))
    return out


def _is_dangerous_host(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def rule_url_ssrf(config: dict) -> list:
    out = []
    for s in config["servers"]:
        url = s.get("url")
        if not url:
            continue
        m = re.match(r"^[a-z]+://([^/:]+)", url)
        host = m.group(1) if m else ""
        if _is_dangerous_host(host):
            out.append(_finding(
                3, "ssrf", s["name"], "-", "ssrf",
                f"server '{s['name']}' url points at a private/loopback/metadata host "
                f"({host}); confirm this is intended and not an SSRF/exfil path",
            ))
    return out


def rule_secrets(config: dict) -> list:
    out = []
    for s in config["servers"]:
        for k, v in (s.get("env") or {}).items():
            if k.endswith("_ENV"):  # value is an env-var NAME, the safe pattern
                continue
            if isinstance(v, str) and _SECRET_RE.fullmatch(v.strip()):
                out.append(_finding(
                    3, "secret_exposure", s["name"], "-", "secret-exposure",
                    f"server '{s['name']}' env '{k}' appears to inline a secret value; "
                    f"reference an env var (e.g. {k}_ENV) instead of committing the secret",
                ))
    return out
