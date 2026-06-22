"""Offline, read-only STATIC scanner for the owner's own MCP config.

Phase-1 of secops's MCP-governance pillar. Pure data in -> ranked findings out:
no network, no I/O in the rule logic, no LLM, and it NEVER connects to any MCP
server (it only reads a config file + an optional, owner-supplied tools/list
dump). Mirrors the deterministic, low-false-positive spine of posture_fusion.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import tomllib
import urllib.parse
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
    with open(config_path, "rb") as fh:
        raw = fh.read()
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
        with open(tools_dump, "rb") as fh:
            dump = json.loads(fh.read().decode("utf-8"))
        by_name = {s["name"]: s for s in servers}
        for sname, defs in dump.items():
            if sname in by_name:
                by_name[sname]["tools"] = [_tool_from_def(d) for d in defs]
    return {"servers": servers}


# Conservative inline-secret heuristic: known high-confidence secret prefixes only
# (no bare catch-all, which flagged any long opaque config value as a secret).
_SECRET_RE = re.compile(
    r"(sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})"
)
# A pinned version suffix: accepts a major-only pin (@1) or finer (@1.2, @1.2.3),
# but not @latest / @next (non-numeric tag). Matches a numeric dotted run not
# immediately followed by a letter/underscore/dash (which would make it a tag).
_VERSION_RE = re.compile(r"@[0-9]+(\.[0-9]+)*(?![\w-])")


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
        # urlsplit strips [..] brackets / :port and lowercases the host.
        host = urllib.parse.urlsplit(url).hostname or ""
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
_PRIVATE_HINTS = ("secret", "credential", "password", "token", "private", "~/.ssh", "keychain")
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


RULES = [
    rule_tool_poisoning,
    rule_url_ssrf,
    rule_secrets,
    rule_lethal_trifecta,
    rule_capabilities,
    rule_unpinned,
]


def audit_mcp(config: dict) -> dict:
    """Run every deterministic rule and return findings ranked highest-risk-first
    with a stable tiebreak (severity, rule_id, server, tool). No LLM, no I/O."""
    findings: list = []
    for rule in RULES:
        findings.extend(rule(config))
    findings.sort(key=lambda f: (-f.severity, f.rule_id, f.server, f.tool))
    return {"findings": findings, "summary": summarize(findings)}


def render_report(result: dict) -> str:
    findings = result["findings"]
    s = result["summary"]
    lines = [
        "== PRIORITISED MCP RISKS ==",
        "",
        f"servers scanned offline; {s['total']} finding(s): "
        f"{s['critical']} critical, {s['high']} high, {s['medium']} medium, {s['low']} low.",
        "",
        "(read-only static analysis — advice only, never an exploit; mapped to OWASP MCP Top 10)",
        "",
    ]
    if not findings:
        lines.append("- no MCP risks found in the supplied config.")
    else:
        for f in findings:
            scope = f.server if f.tool == "-" else f"{f.server}/{f.tool}"
            lines.append(f"- [{f.severity_name.upper()}] ({f.owasp}) {scope}: {f.message}")
    lines.append("")
    return "\n".join(lines)


def summary_json(result: dict) -> str:
    return json.dumps({
        "summary": result["summary"],
        "findings": [
            {"severity": f.severity, "severity_name": f.severity_name, "rule_id": f.rule_id,
             "server": f.server, "tool": f.tool, "owasp": f.owasp, "message": f.message}
            for f in result["findings"]
        ],
    }, ensure_ascii=False, indent=2)


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mcp_audit", description="offline static MCP/agent security scanner")
    ap.add_argument("config", help="path to .mcp.json or agents.toml")
    ap.add_argument("--tools", help="optional tools/list JSON dump for tool-level rules")
    ap.add_argument("--out", help="write the markdown report here (default: stdout)")
    args = ap.parse_args(argv)
    if not os.path.exists(args.config):
        print(f"error: config not found: {args.config}", file=sys.stderr)
        return 2
    config = parse_config(args.config, tools_dump=args.tools)
    result = audit_mcp(config)
    report = render_report(result)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
        sidecar = os.path.splitext(args.out)[0] + ".summary.json"
        with open(sidecar, "w", encoding="utf-8") as f:
            f.write(summary_json(result))
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
