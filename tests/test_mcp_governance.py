"""M2 governance integration: role deny + approval gate at the façade server.

All CI-safe. Deny paths short-circuit BEFORE any step runs, so the live-mode
tests never actually scan; the one "approved → proceed" assertion checks the gate
decision via _govern directly (not the full impl) to avoid touching nmap.
"""

from __future__ import annotations

import json

import pytest

from secops_mcp import server
from secops_mcp.state import KillChainState


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPS_MCP_MOCK", "1")
    monkeypatch.setenv("SECOPS_MCP_STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setenv("SECOPS_MCP_OUT_DIR", str(tmp_path / "run"))
    # make sure no ambient role/approval leaks in from the shell
    monkeypatch.delenv("SECOPS_AGENT_ROLE", raising=False)
    monkeypatch.delenv("SECOPS_MCP_APPROVAL", raising=False)
    return tmp_path


def _gov_log(tmp_path):
    p = tmp_path / "run" / "governance.jsonl"
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


# ── boundary 1: blue ↛ red (structural, no human) ──────────────────────────

def test_blue_role_is_denied_red_tool(env, monkeypatch):
    monkeypatch.setenv("SECOPS_AGENT_ROLE", "blue")
    out = server.recon_impl({"target": "juice-shop"})
    assert out["denied"] is True and out["by"] == "role-policy"
    assert "barred" in out["error"]
    # audit trail recorded the denial
    rec = _gov_log(env)[-1]
    assert rec["decision"] == "denied-role" and rec["tool"] == "recon"


def test_blue_role_may_run_blue_tool(env, monkeypatch):
    monkeypatch.setenv("SECOPS_AGENT_ROLE", "blue")
    out = server.detect_impl({})        # detect is classified blue
    assert "triaged_groups" in out and "denied" not in out


# ── boundary 4: mock / orchestrator auto-allows (M1 behavior) ──────────────

def test_orchestrator_mock_auto_allows_and_audits(env):
    out = server.recon_impl({"target": "juice-shop"})
    assert out["open_ports"] >= 1
    assert _gov_log(env)[-1]["decision"] == "auto-allow"


# ── boundary 2: live red scan needs approval (fail-closed by default) ──────

def test_live_red_scan_denied_without_approval_and_does_not_scan(env, monkeypatch):
    monkeypatch.setenv("SECOPS_MCP_MOCK", "0")          # live
    monkeypatch.setenv("SECOPS_MCP_APPROVAL", "auto-deny")
    out = server.recon_impl({"target": "juice-shop"})
    assert out["denied"] is True and out["by"] == "approval"
    # blocked before the step → no recon recorded in state
    st = KillChainState.load(env / "state.json")
    assert st.recon is None
    assert _gov_log(env)[-1]["decision"] == "denied-approval"


def test_live_red_scan_proceeds_when_auto_allowed(env, monkeypatch):
    monkeypatch.setenv("SECOPS_MCP_MOCK", "0")
    monkeypatch.setenv("SECOPS_AGENT_ROLE", "orchestrator")
    monkeypatch.setenv("SECOPS_MCP_APPROVAL", "auto-allow")
    # check the GATE only (not the full impl) so we don't invoke real nmap
    st = KillChainState(target="juice-shop", mock=False, out_dir=str(env / "run"))
    assert server._govern("recon", st, {}) is None     # proceed
    assert _gov_log(env)[-1]["decision"] == "approved"


# ── boundary 3: live write/journal needs approval ──────────────────────────

def test_live_detect_write_denied_without_approval(env, monkeypatch):
    monkeypatch.setenv("SECOPS_MCP_MOCK", "0")
    monkeypatch.setenv("SECOPS_MCP_APPROVAL", "auto-deny")
    out = server.detect_impl({})         # detect writes a journal (read_only=False)
    assert out["denied"] is True and out["by"] == "approval"


# ── internal read-only respond stays auto-allowed even live ────────────────

def test_live_respond_is_auto_allowed_internal_readonly(env, monkeypatch):
    monkeypatch.setenv("SECOPS_MCP_MOCK", "0")
    monkeypatch.setenv("SECOPS_MCP_APPROVAL", "auto-deny")
    st = KillChainState(target="juice-shop", mock=False, out_dir=str(env / "run"))
    assert server._govern("respond", st, {}) is None   # internal + read_only → no approval
    assert _gov_log(env)[-1]["decision"] == "auto-allow"


# ── approval provider selection from env (channel behavior is unit-tested
#    in test_approval.py; here we only assert the server picks the right one) ──

def test_approval_provider_selection(env, monkeypatch):
    from secops_mcp.approval import AutoApprovalProvider, ManualApprovalProvider

    st = KillChainState(target="juice-shop", mock=False, out_dir=str(env / "run"))

    monkeypatch.setenv("SECOPS_MCP_APPROVAL", "auto-allow")
    assert isinstance(server._approval_provider(st), AutoApprovalProvider)
    assert server._approval_provider(st)._approve is True

    monkeypatch.setenv("SECOPS_MCP_APPROVAL", "manual")
    monkeypatch.setenv("SECOPS_MCP_APPROVAL_DIR", str(env / "approvals"))
    assert isinstance(server._approval_provider(st), ManualApprovalProvider)

    monkeypatch.setenv("SECOPS_MCP_APPROVAL", "auto-deny")
    assert server._approval_provider(st)._approve is False

    monkeypatch.delenv("SECOPS_MCP_APPROVAL", raising=False)  # default = fail-closed
    assert server._approval_provider(st)._approve is False
