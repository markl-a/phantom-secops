"""Tests for the secops_recon MCP server.

We test the in-process tool implementations directly rather than going
through stdio JSON-RPC — the SDK round-trip adds nothing for unit
testing the policy/scope logic, and bypassing it keeps tests fast.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from phantom_secops.mcp import secops_recon_server


def test_list_tools_includes_xphantom_metadata():
    tools = secops_recon_server.tool_definitions()
    assert any(t.name == "scan_target" for t in tools)
    scan_tool = next(t for t in tools if t.name == "scan_target")
    md = scan_tool.metadata
    assert md["x-phantom.classification"] == "red"
    assert "network.scan.passive" in md["x-phantom.capabilities"]
    assert "target.lab_only" in md["x-phantom.capabilities"]
    assert md["x-phantom.read_only"] is True


def test_scan_valid_lab_target():
    """Mocks nmap_runner to verify the server forwards correctly."""
    fake_result = {"target": "juice-shop", "open_ports": [{"port": 3000, "service": "http"}], "scan_type": "nmap"}
    with patch("phantom_secops.mcp.secops_recon_server.nmap_runner.run", return_value=fake_result):
        out = secops_recon_server.scan_target_impl({"target": "juice-shop"})
    assert out["target"] == "juice-shop"
    assert out["open_ports"][0]["port"] == 3000


def test_scan_external_target_refused_by_existing_lab_gate():
    """nmap_runner already refuses non-lab; verify the MCP server forwards the error JSON."""
    out = secops_recon_server.scan_target_impl({"target": "google.com"})
    assert "error" in out
    assert "not a known lab service" in out["error"]


def test_missing_target_arg_raises():
    with pytest.raises((KeyError, TypeError, ValueError)):
        secops_recon_server.scan_target_impl({})
