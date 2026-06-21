"""MCP server: the kill-chain façade.

Exposes the four composite kill-chain steps (recon → vuln_scan → detect →
respond) as MCP tools a phantom-mesh agent calls in sequence. Each call loads
the run's KillChainState from SECOPS_MCP_STATE_FILE, runs one step (delegating
to phantom_secops.killchain via secops_mcp.steps), saves the updated state, and
returns a compact summary the agent reasons over. State lives in the file, not
stdout, because phantom-mesh interleaves tool stdout with its own chatter.

Run as: python -m secops_mcp.server
Spawned by phantom-mesh via an [[mcp_servers]] block (see agents.toml.demo).

Environment:
  SECOPS_MCP_STATE_FILE  cross-turn state path (default reports/_mcp_state.json)
  SECOPS_MCP_MOCK        "1"/"true" → canned data, no docker (CI/demo)
  SECOPS_MCP_OUT_DIR     run dir for artifacts (reports/runs/<ts>/ in the driver)
  SECOPS_MCP_TARGET      default lab target if the recon call omits one

The x-phantom.* classification/capability metadata below is ADVISORY in M1 (the
agent loop honors call-order via StepOrderError); M2 turns it into structural
enforcement (blue agents barred from red tools). See docs/EXECUTION-PLAN.md.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phantom_secops import killchain as kc  # noqa: E402
from phantom_secops.mcp._xphantom import xphantom_metadata  # noqa: E402
from secops_mcp import steps  # noqa: E402
from secops_mcp.state import KillChainState  # noqa: E402


# ─── env-driven run config + state I/O ──────────────────────────────────────

def _state_path() -> str:
    return os.environ.get("SECOPS_MCP_STATE_FILE", str(REPO_ROOT / "reports" / "_mcp_state.json"))


def _env_mock() -> bool:
    return os.environ.get("SECOPS_MCP_MOCK", "").strip().lower() in ("1", "true", "yes")


def _load(state_file: str) -> KillChainState:
    """Load run state and (re)apply run-level env config.

    mock/out_dir are constant for a run, so re-applying them on every load is
    idempotent and keeps a freshly-created state (file absent on the first call)
    correctly configured.
    """
    st = KillChainState.load(state_file)
    st.mock = _env_mock()
    out_dir = os.environ.get("SECOPS_MCP_OUT_DIR")
    if out_dir:
        st.out_dir = out_dir
    return st


# ─── tool implementations (directly unit-testable; no stdio needed) ─────────

def recon_impl(args: dict[str, Any], state_file: str | None = None) -> dict[str, Any]:
    state_file = state_file or _state_path()
    st = _load(state_file)
    st.target = args.get("target") or os.environ.get("SECOPS_MCP_TARGET") or st.target
    try:
        out = steps.recon(st)
    except steps.StepOrderError as e:
        return {"error": str(e)}
    st.save(state_file)
    return out


def vuln_scan_impl(args: dict[str, Any], state_file: str | None = None) -> dict[str, Any]:
    state_file = state_file or _state_path()
    st = _load(state_file)
    try:
        out = steps.vuln_scan(st, severity=args.get("severity", kc.NUCLEI_SEVERITY))
    except steps.StepOrderError as e:
        return {"error": str(e)}
    st.save(state_file)
    return out


def detect_impl(args: dict[str, Any], state_file: str | None = None) -> dict[str, Any]:
    state_file = state_file or _state_path()
    st = _load(state_file)
    try:
        out = steps.detect(st)
    except steps.StepOrderError as e:
        return {"error": str(e)}
    st.save(state_file)
    return out


def respond_impl(args: dict[str, Any], state_file: str | None = None) -> dict[str, Any]:
    state_file = state_file or _state_path()
    st = _load(state_file)
    try:
        out = steps.respond(st)
    except steps.StepOrderError as e:
        return {"error": str(e)}
    st.save(state_file)
    return out


_IMPLS = {
    "recon": recon_impl,
    "vuln_scan": vuln_scan_impl,
    "detect": detect_impl,
    "respond": respond_impl,
}


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="recon",
            description=(
                "Red recon stage. Run nmap (or canned data in mock mode) against an "
                "in-lab service and record open ports. FIRST step of the kill-chain."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "lab service name (default: juice-shop)"},
                },
            },
            metadata=xphantom_metadata(
                "red", ["network.scan.passive", "target.lab_only"], read_only=True,
            ),
        ),
        Tool(
            name="vuln_scan",
            description=(
                "Red vuln-scan stage. Run nuclei against the HTTP endpoints found by "
                "recon. Requires recon to have run first."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "description": "comma-separated nuclei severities"},
                },
            },
            metadata=xphantom_metadata(
                "red", ["network.scan.active", "target.lab_only"], read_only=True,
            ),
        ),
        Tool(
            name="detect",
            description=(
                "Blue detection stage. Ingest lab logs, match anomalies, and triage "
                "into prioritized alert groups. Independent of the red stages."
            ),
            inputSchema={"type": "object", "properties": {}},
            metadata=xphantom_metadata(
                "blue",
                ["read.log_files", "write.alerts_journal", "detect.triage", "target.localhost_only"],
                read_only=False,
            ),
        ),
        Tool(
            name="respond",
            description=(
                "Closeout stage. Compose the prose-only exploit suggestions (never a "
                "runnable PoC), correlate the triaged alerts into actor narratives, and "
                "write the pentest + incident reports with the MTTD metric. Requires "
                "vuln_scan and detect to have run."
            ),
            inputSchema={"type": "object", "properties": {}},
            metadata=xphantom_metadata(
                "internal", ["report.compose", "detect.correlate"], read_only=True,
            ),
        ),
    ]


server = Server("secops_killchain")


@server.list_tools()
async def _list_tools() -> list[Tool]:
    return tool_definitions()


@server.call_tool()
async def _call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    impl = _IMPLS.get(name)
    if impl is None:
        raise ValueError(f"unknown tool: {name}")
    result = impl(arguments)
    return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False))]


async def _main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
