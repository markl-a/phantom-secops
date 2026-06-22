"""Tests for the M2 approval providers (no phantom, no real waiting)."""

from __future__ import annotations

import json

from secops_mcp import approve
from secops_mcp.approval import (
    ApprovalRequest,
    AutoApprovalProvider,
    ManualApprovalProvider,
    write_decision,
)

_REQ = ApprovalRequest(action="recon", classification="red", reason="live red-team scan")


# ── AutoApprovalProvider: fail-closed by default ───────────────────────────

def test_auto_denies_by_default():
    d = AutoApprovalProvider().request(_REQ)
    assert d.approved is False and d.via == "auto"


def test_auto_approves_when_explicitly_enabled():
    d = AutoApprovalProvider(approve=True).request(_REQ)
    assert d.approved is True and d.via == "auto"


# ── ManualApprovalProvider: file-based gate ────────────────────────────────

def _provider_with_operator(tmp_path, *, approved: bool, reason: str):
    """Build a provider whose injected sleep simulates the operator dropping a
    decision file during the wait (the realistic flow: decide AFTER pending)."""
    clock = {"t": 0.0}

    def sleep(s):
        write_decision(tmp_path, "recon", approved=approved, reason=reason)
        clock["t"] += s

    return ManualApprovalProvider(tmp_path, timeout_s=5.0, poll_s=0.5,
                                  _clock=lambda: clock["t"], _sleep=sleep)


def test_manual_approves_when_operator_allows(tmp_path):
    d = _provider_with_operator(tmp_path, approved=True, reason="lab is mine").request(_REQ)
    assert d.approved is True and d.via == "manual-file"
    assert d.reason == "lab is mine"
    # the pending file is cleaned up once decided
    assert not (tmp_path / "pending-recon.json").exists()


def test_manual_denies_on_explicit_deny(tmp_path):
    d = _provider_with_operator(tmp_path, approved=False, reason="not now").request(_REQ)
    assert d.approved is False and d.via == "manual-file"


def test_manual_writes_pending_request_for_the_operator(tmp_path):
    # the pending request (what needs approving) must be written and visible to
    # the operator WHILE the provider is blocked. Capture it on the first poll.
    clock = {"t": 0.0}
    captured = {}

    def sleep(s):
        pending = tmp_path / "pending-recon.json"
        if pending.exists() and "data" not in captured:
            captured["data"] = json.loads(pending.read_text(encoding="utf-8"))
        clock["t"] += s

    p = ManualApprovalProvider(tmp_path, timeout_s=1.0, poll_s=0.5,
                               _clock=lambda: clock["t"], _sleep=sleep)
    d = p.request(_REQ)
    assert d.approved is False and d.via == "timeout"
    assert captured["data"]["action"] == "recon"
    assert captured["data"]["classification"] == "red"
    assert captured["data"]["reason"] == "live red-team scan"


def test_manual_times_out_without_blocking(tmp_path):
    clock = {"t": 0.0}
    p = ManualApprovalProvider(
        tmp_path, timeout_s=2.0, poll_s=0.5,
        _clock=lambda: clock["t"],
        _sleep=lambda s: clock.__setitem__("t", clock["t"] + s),
    )
    d = p.request(_REQ)
    assert d.approved is False and d.via == "timeout"


def test_stale_decision_is_ignored(tmp_path):
    # a leftover decision from a prior run must be cleared, then the new request
    # times out rather than reusing the stale allow
    write_decision(tmp_path, "recon", approved=True, reason="OLD")
    clock = {"t": 0.0}
    p = ManualApprovalProvider(
        tmp_path, timeout_s=1.0, poll_s=0.5,
        _clock=lambda: clock["t"],
        _sleep=lambda s: clock.__setitem__("t", clock["t"] + s),
    )
    d = p.request(_REQ)
    assert d.approved is False and d.via == "timeout"


# ── operator CLI ────────────────────────────────────────────────────────────

def test_approve_cli_writes_decision(tmp_path):
    rc = approve.main([str(tmp_path), "recon", "allow", "lab", "is", "mine"])
    assert rc == 0
    data = json.loads((tmp_path / "decision-recon.json").read_text(encoding="utf-8"))
    assert data["approved"] is True and data["reason"] == "lab is mine"


def test_approve_cli_rejects_bad_verdict(tmp_path):
    assert approve.main([str(tmp_path), "recon", "maybe"]) == 2
