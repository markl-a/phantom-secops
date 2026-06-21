"""Tests for the secops_killchain MCP façade server.

Like the other server tests, these exercise the in-process tool impls directly
rather than the stdio JSON-RPC round-trip. All run in mock mode — no docker, no
provider, no network — so they are CI-safe. They prove the server correctly
threads run state through SECOPS_MCP_STATE_FILE across calls and surfaces
out-of-order calls as agent-readable error JSON.
"""

from __future__ import annotations

import json

import pytest

from secops_mcp import server


@pytest.fixture()
def mock_env(tmp_path, monkeypatch):
    state_file = tmp_path / "state.json"
    monkeypatch.setenv("SECOPS_MCP_MOCK", "1")
    monkeypatch.setenv("SECOPS_MCP_STATE_FILE", str(state_file))
    monkeypatch.setenv("SECOPS_MCP_OUT_DIR", str(tmp_path / "run"))
    return state_file


# ── metadata / x-phantom advertising ────────────────────────────────────────

def test_tool_definitions_expose_four_steps_with_metadata():
    tools = {t.name: t for t in server.tool_definitions()}
    assert set(tools) == {"recon", "vuln_scan", "detect", "respond"}
    assert tools["recon"].metadata["x-phantom.classification"] == "red"
    assert tools["vuln_scan"].metadata["x-phantom.classification"] == "red"
    assert tools["detect"].metadata["x-phantom.classification"] == "blue"
    assert tools["respond"].metadata["x-phantom.classification"] == "internal"
    # every tool advertises a capability list and a read_only flag
    for t in tools.values():
        assert t.metadata["x-phantom.capabilities"]
        assert isinstance(t.metadata["x-phantom.read_only"], bool)


# ── full agent-ordered run drives state across calls ────────────────────────

def test_full_sequence_produces_reports_and_mttd(mock_env):
    assert server.recon_impl({"target": "juice-shop"})["open_ports"] >= 1
    assert "findings" in server.vuln_scan_impl({})
    det = server.detect_impl({})
    assert det["triaged_groups"] >= 1
    resp = server.respond_impl({})
    assert resp["mttd"] == 15  # parity with the direct mock driver
    assert resp["outcome"] == "defender"
    # state file accumulated the whole run
    st = json.loads(mock_env.read_text(encoding="utf-8"))
    assert st["recon"] and st["vuln"] and st["triaged"] and st["reports"]
    # artifacts landed in the run dir
    run_dir = mock_env.parent / "run"
    for name in ("recon.json", "vuln-scan.json", "pentest-report.md",
                 "incident-report.md", "summary.json"):
        assert (run_dir / name).exists(), name


# ── drift guard surfaces as agent-readable error JSON, not a crash ──────────

def test_out_of_order_call_returns_error_json(mock_env):
    out = server.vuln_scan_impl({})  # recon hasn't run
    assert "error" in out and "recon" in out["error"]


def test_respond_before_detect_returns_error_json(mock_env):
    server.recon_impl({"target": "juice-shop"})
    server.vuln_scan_impl({})
    out = server.respond_impl({})  # detect skipped
    assert "error" in out and "detect" in out["error"]


# ── env wiring ──────────────────────────────────────────────────────────────

def test_mock_env_toggles_canned_data(mock_env, monkeypatch):
    # default target from env when the recon arg omits it
    monkeypatch.setenv("SECOPS_MCP_TARGET", "juice-shop")
    out = server.recon_impl({})
    assert out["open_ports"] >= 1


def test_state_file_defaults_when_unset(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPS_MCP_MOCK", "1")
    monkeypatch.delenv("SECOPS_MCP_STATE_FILE", raising=False)
    # passing state_file explicitly keeps the default-path logic from writing
    # into the repo during tests
    sf = str(tmp_path / "explicit.json")
    out = server.recon_impl({"target": "juice-shop"}, state_file=sf)
    assert out["open_ports"] >= 1
    assert (tmp_path / "explicit.json").exists()
