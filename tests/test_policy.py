"""Tests for the M2 governance policy (pure, deterministic — no phantom/network)."""

from __future__ import annotations

import pytest

from secops_mcp import policy


# ── role-based structural deny (blue ↛ red) ────────────────────────────────

@pytest.mark.parametrize("role,classification,allowed", [
    ("blue", "red", False),      # the core guarantee
    ("blue", "blue", True),
    ("blue", "internal", True),
    ("red", "blue", False),      # symmetric separation
    ("red", "red", True),
    ("red", "internal", True),
    ("orchestrator", "red", True),   # M1 single agent: no deny
    ("orchestrator", "blue", True),
    ("orchestrator", "internal", True),
])
def test_role_may_call(role, classification, allowed):
    assert policy.role_may_call(role, classification) is allowed


def test_unknown_role_falls_open_to_orchestrator_not_a_surprise_deny():
    # a misspelled/missing role must not silently break M1 — it falls back to the
    # permissive orchestrator set, never to an unexpected block
    assert policy.role_may_call("typo", "red") is True


# ── risk-based approval matrix (the four boundaries) ───────────────────────

def test_mock_always_auto_allows():
    for cls in ("red", "blue", "internal"):
        for ro in (True, False):
            g = policy.evaluate("orchestrator", cls, read_only=ro, mock=True)
            assert g.needs_approval is False


def test_live_write_requires_approval():
    g = policy.evaluate("blue", "blue", read_only=False, mock=False)
    assert g.needs_approval is True


def test_live_red_scan_requires_approval():
    g = policy.evaluate("red", "red", read_only=True, mock=False)
    assert g.needs_approval is True


def test_live_readonly_internal_auto_allows():
    g = policy.evaluate("orchestrator", "internal", read_only=True, mock=False)
    assert g.needs_approval is False


# ── combined Gate ───────────────────────────────────────────────────────────

def test_gate_blocked_by_role_short_circuits_intent():
    g = policy.evaluate("blue", "red", read_only=True, mock=False)
    assert g.blocked_by_role is True
    assert "barred" in g.role_reason


def test_gate_allows_with_approval_when_live_red_and_role_ok():
    g = policy.evaluate("red", "red", read_only=True, mock=False)
    assert g.role_allowed is True
    assert g.needs_approval is True
