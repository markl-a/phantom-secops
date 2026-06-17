"""Tests for the secops_log_ingest MCP server (blue-team polling log scanner).

This server wraps tools/log_ingest.scan_window, which was fully unit-tested but
unreachable from any production CLI path (no MCP server, and the kill-chain uses
log_anomaly instead). The server makes the scanner reachable through the same
MCP interface as the other blue tools, and these tests prove it end-to-end.

Hermetic: LOG_DIR/ALERTS_FILE are redirected to tmp, so nothing touches the real
reports/ tree and no docker/network is involved.
"""

from __future__ import annotations

import json

from phantom_secops.mcp import secops_log_ingest_server as srv
from tools import log_ingest


def test_list_tools_includes_xphantom_metadata():
    tools = srv.tool_definitions()
    assert any(t.name == "scan_window" for t in tools)
    md = next(t for t in tools if t.name == "scan_window").metadata
    assert md["x-phantom.classification"] == "blue"
    assert "read.log_files" in md["x-phantom.capabilities"]
    assert "target.localhost_only" in md["x-phantom.capabilities"]
    # Honest: scan_window APPENDS matched alerts to its own journal, so the tool
    # is NOT read-only and must advertise that truthfully.
    assert md["x-phantom.read_only"] is False


def test_scan_window_impl_matches_and_writes(monkeypatch, tmp_path):
    log_dir = tmp_path / "lab-logs"
    log_dir.mkdir()
    (log_dir / "juice-shop.log").write_text(
        "203.0.113.5 - - GET /search?q=' union select 1,2--\n"
        "10.0.0.1 - - GET /index.html\n",
        encoding="utf-8",
    )
    alerts_file = log_dir / "alerts.jsonl"
    monkeypatch.setattr(log_ingest, "LOG_DIR", log_dir)
    monkeypatch.setattr(log_ingest, "ALERTS_FILE", alerts_file)

    out = srv.scan_window_impl({"window_seconds": 30})
    assert out["alerts_emitted"] >= 1
    assert out["window_seconds"] == 30
    # The journal must actually be written — proves the scanner ran end-to-end
    # through the MCP wrapper, not just that the function returned a dict.
    lines = [ln for ln in alerts_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert lines
    cats = {json.loads(ln)["category"] for ln in lines}
    assert "sqli" in cats
    assert all(json.loads(ln)["asset"] == "juice-shop" for ln in lines)


def test_scan_window_impl_no_logs_is_graceful(monkeypatch, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(log_ingest, "LOG_DIR", empty)
    monkeypatch.setattr(log_ingest, "ALERTS_FILE", empty / "alerts.jsonl")
    out = srv.scan_window_impl({})
    assert out["alerts_emitted"] == 0
    assert not (empty / "alerts.jsonl").exists()  # clean run writes nothing
