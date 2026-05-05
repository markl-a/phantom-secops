"""MCP protocol smoke tests.

Verifies the FastMCP server registers the expected tool names and resource
templates. Skipped automatically when the `mcp` package is not installed
(e.g. the no-deps demo-mock CI lane).
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import pytest

mcp_pkg = pytest.importorskip("mcp")  # noqa: F841


from phantom_secops.mcp import server  # type: ignore[import-not-found]  # noqa: E402

EXPECTED_TOOLS = {
    "recon_host",
    "vuln_scan_web",
    "scan_logs_for_anomalies",
    "triage_alerts",
    "correlate_threats",
    "suggest_exploit_prose",
    "compose_pentest_report",
    "compose_incident_report",
    "lab_status",
    "lab_up",
    "lab_down",
}


@pytest.mark.asyncio
async def test_server_registers_all_documented_tools() -> None:
    tools = await server.mcp.list_tools()
    names = {t.name for t in tools}
    missing = EXPECTED_TOOLS - names
    extra = names - EXPECTED_TOOLS
    assert not missing, f"missing tools: {missing}"
    assert not extra, f"unexpected tools: {extra}"


@pytest.mark.asyncio
async def test_resource_templates_registered() -> None:
    templates = await server.mcp.list_resource_templates()
    uris = {t.uriTemplate for t in templates}
    assert "phantom-secops://runs/{run_id}/{filename}" in uris
    assert "phantom-secops://mocks/{name}" in uris


@pytest.mark.asyncio
async def test_lab_up_refuses_without_confirm() -> None:
    """Lifecycle invariant: must refuse without confirm=True."""
    result = server.lab_up(confirm=False)
    assert result.get("error") == "lifecycle_action_requires_confirmation"


@pytest.mark.asyncio
async def test_lab_down_refuses_without_confirm() -> None:
    result = server.lab_down(confirm=False)
    assert result.get("error") == "lifecycle_action_requires_confirmation"


@pytest.mark.asyncio
async def test_recon_host_refuses_external_target() -> None:
    result = server.recon_host("scanme.nmap.org")
    assert result.get("error") == "not_a_lab_target"


@pytest.mark.asyncio
async def test_vuln_scan_web_refuses_external_url() -> None:
    result = server.vuln_scan_web("http://example.com/")
    assert result.get("error") == "not_a_lab_target"
