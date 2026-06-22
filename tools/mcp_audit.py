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
