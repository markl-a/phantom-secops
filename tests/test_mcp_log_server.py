"""Tests for the secops_log MCP server."""

from __future__ import annotations

from pathlib import Path

import pytest

from phantom_secops.mcp import secops_log_server


def test_list_tools_includes_xphantom_metadata():
    tools = secops_log_server.tool_definitions()
    assert any(t.name == "scan_log" for t in tools)
    md = next(t for t in tools if t.name == "scan_log").metadata
    assert md["x-phantom.classification"] == "blue"
    assert "read.log_files" in md["x-phantom.capabilities"]
    assert md["x-phantom.read_only"] is True


def test_scan_log_on_canned_attack_log(tmp_path: Path):
    # Synthesize a tiny attack log inline rather than depending on lab/mocks/
    log = tmp_path / "test.log"
    log.write_text(
        "203.0.113.5 - - [01/May/2026] \"GET /search?q=%27union%20select%201%2c2--\"\n"
        "203.0.113.5 - - [01/May/2026] \"GET /administration HTTP/1.1\"\n"
        "10.0.0.1 - - [01/May/2026] \"GET /index.html\" benign\n"
    )
    out = secops_log_server.scan_log_impl({"path": str(log), "max_lines": 100, "asset": "test"})
    cats = {a["category"] for a in out["alerts"]}
    assert "sqli" in cats
    assert "admin_path" in cats
    assert all(a["asset"] == "test" for a in out["alerts"])


def test_scan_log_max_lines_honored(tmp_path: Path):
    log = tmp_path / "big.log"
    log.write_text("\n".join(f"203.0.113.{i} GET /admin" for i in range(50)))
    out = secops_log_server.scan_log_impl({"path": str(log), "max_lines": 10})
    assert len(out["alerts"]) == 10


def test_scan_log_missing_file(tmp_path: Path):
    out = secops_log_server.scan_log_impl({"path": str(tmp_path / "nonexistent")})
    assert out["alerts"] == []
