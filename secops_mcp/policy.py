"""Governance policy for the kill-chain façade (M2).

phantom-mesh 0.6 has no governor, no approval gating wired to headless runs, and
ignores x-phantom tool metadata entirely (see the survey in docs/EXECUTION-PLAN.md
M2). So enforcement lives HERE, at the façade MCP server — the tool-dispatch point
this repo controls. Two independent, deterministic checks gate every tool call:

  1. Role-based structural deny — an agent's role may only call tools whose
     x-phantom classification is in its allowed set. A blue agent calling a red
     tool is refused outright, no human in the loop: the project's core
     "blue ↛ red" guarantee. The classification advertised in M1 (advisory) is
     now *enforced* in-repo.

  2. Risk-based approval — high-risk calls must be approved before running:
       * mock runs              → auto-allow (offline, no real action)
       * live writes / journal  → require approval (read_only == False)
       * live red-team scans    → require approval (classification == "red")
       * live read-only otherwise → auto-allow
     These map to the four operator-chosen governance boundaries.

Defaults preserve M1: role "orchestrator" may call everything, and mock auto-
allows, so the existing (mock, single-agent) demo behaves identically.
"""

from __future__ import annotations

from dataclasses import dataclass

# Which tool classifications each agent role may invoke. orchestrator is the
# M1 single-agent default (no deny). red/blue are the M2 split: blue is barred
# from red tools (and vice-versa); both may use shared "internal" tools.
ROLE_ALLOWED: dict[str, set[str]] = {
    "orchestrator": {"red", "blue", "internal"},
    "red": {"red", "internal"},
    "blue": {"blue", "internal"},
}

DEFAULT_ROLE = "orchestrator"


def role_may_call(role: str, classification: str) -> bool:
    """True if `role` is permitted to call a tool of `classification`.

    An unknown role falls back to the permissive orchestrator set so a missing/
    misspelled SECOPS_AGENT_ROLE can never silently *block* the M1 demo — it can
    only fail open to the M1 behavior, never fail to a surprising deny.
    """
    allowed = ROLE_ALLOWED.get(role, ROLE_ALLOWED[DEFAULT_ROLE])
    return classification in allowed


def _approval(classification: str, read_only: bool, mock: bool) -> tuple[bool, str]:
    if mock:
        return False, "mock run: no real action, auto-allow"
    if not read_only:
        return True, "live write/journal action requires approval"
    if classification == "red":
        return True, "live red-team scan requires approval"
    return False, "live read-only action, auto-allow"


@dataclass(frozen=True)
class Gate:
    """The combined governance decision for one tool call."""

    role_allowed: bool
    role_reason: str
    needs_approval: bool
    approval_reason: str

    @property
    def blocked_by_role(self) -> bool:
        return not self.role_allowed


def evaluate(role: str, classification: str, *, read_only: bool, mock: bool) -> Gate:
    """Evaluate both governance checks for a tool call. Pure + deterministic."""
    allowed = role_may_call(role, classification)
    role_reason = (
        f"role '{role}' may call '{classification}' tools"
        if allowed
        else f"role '{role}' is structurally barred from '{classification}' tools"
    )
    needs_approval, approval_reason = _approval(classification, read_only, mock)
    return Gate(allowed, role_reason, needs_approval, approval_reason)
