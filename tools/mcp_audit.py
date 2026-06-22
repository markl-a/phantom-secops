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


# Heuristic keyword sets for the lethal-trifecta legs (conservative; candidate flags).
_PRIVATE_HINTS = ("secret", "credential", "password", "token", "private", "~/.ssh", "keychain", "env")
_UNTRUSTED_HINTS = ("fetch", "url", "web", "untrusted", "scrape", "browse", "email", "inbox")
_EXFIL_HINTS = ("webhook", "egress", "send", "upload", "post", "external", "outbound", "publish")
# Injection markers that should never appear in a benign tool description.
_POISON_RE = re.compile(
    r"(ignore (the )?previous|disregard (all|previous)|exfiltrat|system prompt|"
    r"do not (tell|inform)|secretly|base64|\.ssh|over[- ]?broad)",
    re.IGNORECASE,
)


def _leg(text: str, hints: tuple) -> bool:
    t = text.lower()
    return any(h in t for h in hints)


def rule_capabilities(config: dict) -> list:
    out = []
    for s in config["servers"]:
        for t in s.get("tools") or []:
            if t.get("classification") is None and not t.get("capabilities") and t.get("read_only") is None:
                out.append(_finding(
                    2, "missing_capability_metadata", s["name"], t["name"], "excessive-permissions",
                    f"tool '{t['name']}' has no x-phantom capability metadata; it cannot be "
                    f"governed (add classification/capabilities/read_only)",
                ))
            elif t.get("read_only") is False and not t.get("capabilities"):
                out.append(_finding(
                    1, "missing_capability_metadata", s["name"], t["name"], "excessive-permissions",
                    f"tool '{t['name']}' is write-capable (read_only=false) but declares no "
                    f"capabilities; scope its capabilities explicitly",
                ))
    return out


def rule_tool_poisoning(config: dict) -> list:
    out = []
    for s in config["servers"]:
        for t in s.get("tools") or []:
            blob = f"{t.get('name', '')} {t.get('description', '')}"
            if _POISON_RE.search(blob):
                out.append(_finding(
                    4, "tool_poisoning", s["name"], t["name"], "tool-poisoning",
                    f"tool '{t['name']}' description contains injection/exfiltration-style "
                    f"language; treat the description as hostile and review the server",
                ))
    return out


def rule_lethal_trifecta(config: dict) -> list:
    out = []
    for s in config["servers"]:
        tools = s.get("tools") or []
        blobs = [f"{t.get('name', '')} {t.get('description', '')} {' '.join(t.get('capabilities') or [])}" for t in tools]
        has_private = any(_leg(b, _PRIVATE_HINTS) for b in blobs)
        has_untrusted = any(_leg(b, _UNTRUSTED_HINTS) for b in blobs)
        has_exfil = any(_leg(b, _EXFIL_HINTS) for b in blobs)
        if has_private and has_untrusted and has_exfil:
            out.append(_finding(
                3, "lethal_trifecta", s["name"], "-", "data-exfiltration",
                f"server '{s['name']}' exposes all three legs of the lethal trifecta "
                f"(private-data access + untrusted-input + exfil channel); a prompt "
                f"injection here can steal data — split capabilities across servers/agents",
            ))
    return out
