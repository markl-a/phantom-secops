#!/usr/bin/env python3
"""Translate phantom-secops agent TOML to phantom-mesh [agent.X] fragment.

Input format (this repo's agents/*/*.toml):
    [agent]
    name = "..."
    [[agent.tools]]
    name = "nmap_runner"
    [agent.prompt]
    system = "..."
    [agent.limits]
    max_tool_calls = N

Output format (phantom-mesh agents.toml):
    [agent.<name>]
    provider = "..."
    model    = "..."
    tools    = ["..."]
    instructions = "..."
    [agent.<name>.limits]
    max_tool_calls = N
    [agent.<name>.plugin_policy]   # only if any MCP plugin tool is used
    allowed_capabilities = [...]
    denied_capabilities  = [...]
    classification_max   = "..."
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import tomllib  # py 3.11+
except ImportError:
    import tomli as tomllib  # type: ignore[no-redef]

# Mapping: phantom-secops tool name → (mesh tool name, capability hints, classification)
TOOL_MAP: dict[str, tuple[str, list[str], str]] = {
    "nmap_runner":   ("secops_recon.scan_target", ["network.scan.passive", "target.lab_only"], "red"),
    "log_ingest":    ("secops_log_ingest.scan_window", ["read.log_files", "write.alerts_journal", "target.localhost_only"], "blue"),
    # Phantom-mesh built-ins (no MCP needed)
    "file_read":     ("file_read",  [], "internal"),
    "file_write":    ("file_write", [], "internal"),
    "http_probe":    ("web_fetch",  [], "internal"),
    "dns_enum":      ("web_fetch",  [], "internal"),
}

DEFAULT_PROVIDER = "groq"
DEFAULT_MODEL = "openai/gpt-oss-20b"

CLASS_RANK = {"internal": 0, "blue": 1, "red": 2}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input_toml", type=Path)
    p.add_argument("--provider", default=DEFAULT_PROVIDER)
    p.add_argument("--model", default=DEFAULT_MODEL)
    args = p.parse_args()

    cfg = tomllib.loads(args.input_toml.read_text(encoding="utf-8"))
    agent = cfg.get("agent", {})
    name = agent.get("name") or args.input_toml.stem
    instructions = agent.get("prompt", {}).get("system", "").strip()
    limits = agent.get("limits", {})
    src_tools = agent.get("tools", [])

    mesh_tool_names: list[str] = []
    capability_hints: list[str] = []
    max_classification = "internal"
    saw_unmapped = False

    for t in src_tools:
        tname = t.get("name", "")
        if tname in TOOL_MAP:
            mesh_name, caps, cls = TOOL_MAP[tname]
            mesh_tool_names.append(mesh_name)
            capability_hints.extend(caps)
            if CLASS_RANK[cls] > CLASS_RANK[max_classification]:
                max_classification = cls
        else:
            mesh_tool_names.append(f"# TODO: map {tname}")
            saw_unmapped = True

    # Render
    out: list[str] = [f"[agent.{name}]"]
    out.append(f'provider = "{args.provider}"')
    out.append(f'model    = "{args.model}"')
    tools_repr = ", ".join(f'"{t}"' if not t.startswith("#") else t for t in mesh_tool_names)
    out.append(f"tools    = [{tools_repr}]")
    out.append('instructions = """')
    out.append(instructions)
    out.append('"""')
    if limits:
        out.append("")
        out.append(f"[agent.{name}.limits]")
        for k, v in limits.items():
            if isinstance(v, str):
                out.append(f'{k} = "{v}"')
            else:
                out.append(f"{k} = {v}")

    # plugin_policy block only if any MCP plugin tool is used
    has_mcp_tool = any(t.startswith("secops_") for t in mesh_tool_names if not t.startswith("#"))
    if has_mcp_tool:
        out.append("")
        out.append(f"[agent.{name}.plugin_policy]")
        # de-dup hints, sorted for stability
        unique_caps = sorted(set(capability_hints))
        out.append(f"allowed_capabilities = {unique_caps!r}".replace("'", '"'))
        out.append('denied_capabilities  = ["exec.shell", "network.scan.active", "write.*"]')
        out.append(f'classification_max   = "{max_classification}"')

    print("\n".join(out))
    return 2 if saw_unmapped else 0


if __name__ == "__main__":
    sys.exit(main())
