"""Tests for the secops_host_audit MCP server.

The server is a thin wrapper over tools.host_audit.audit_host that adds
x-phantom metadata. We test the metadata contract and that the impl forwards
the underlying tool's result, with host_audit mocked so nothing queries the
real OS — fully hermetic.
"""

from __future__ import annotations

from unittest.mock import patch

from phantom_secops.mcp import secops_host_audit_server as srv


def test_list_tools_metadata_is_blue_readonly_self_only():
    tools = srv.tool_definitions()
    assert any(t.name == "audit_host" for t in tools)
    md = next(t for t in tools if t.name == "audit_host").metadata
    assert md["x-phantom.classification"] == "blue"
    assert "read.host_posture" in md["x-phantom.capabilities"]
    assert "target.self_only" in md["x-phantom.capabilities"]
    assert md["x-phantom.read_only"] is True


def test_impl_forwards_audit_result():
    fake = {"platform": "windows", "checks": [], "summary": {"total": 0},
            "elevation": {"elevated": True}}
    with patch.object(srv, "audit_host", return_value=fake) as m:
        out = srv.audit_host_impl({})
    assert out is fake
    m.assert_called_once_with()


def test_input_schema_takes_no_required_args():
    tool = next(t for t in srv.tool_definitions() if t.name == "audit_host")
    assert tool.inputSchema.get("required", []) == []
