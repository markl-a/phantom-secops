"""Pluggable approval providers for governed tool calls (M2).

When the policy says a tool call needs approval, the server asks an
ApprovalProvider before running it. The provider is the seam where a human (or an
automated policy) says yes/no. M2 ships:

  - AutoApprovalProvider — deterministic, no human. Fail-CLOSED by default
    (denies), so an unattended live run never silently performs a high-risk
    action; `approve=True` is an explicit dev/CI convenience to let live runs
    proceed without a human.
  - ManualApprovalProvider — local/manual gate for the demo. Writes a pending-
    request JSON and BLOCKS polling for an operator decision file, with a
    timeout. The operator approves out of band:
        python -m secops_mcp.approve <request_dir> <action> allow|deny [reason]
    This is the "asks permission" wedge. A future TelegramApprovalProvider plugs
    in behind this same interface (phantom-mesh openclaw is one-way today, so a
    real phone-approval channel is deferred — see docs/EXECUTION-PLAN.md M2).

Pure-Python + injectable timing, so it unit-tests without phantom or a network.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class ApprovalRequest:
    action: str               # tool name, e.g. "recon"
    classification: str       # x-phantom classification, e.g. "red"
    reason: str               # why approval is needed (from policy)
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ApprovalDecision:
    approved: bool
    reason: str
    via: str                  # "auto" | "manual-file" | "timeout"


class ApprovalProvider:
    """Interface: decide whether a high-risk tool call may proceed."""

    def request(self, req: ApprovalRequest) -> ApprovalDecision:  # pragma: no cover
        raise NotImplementedError


class AutoApprovalProvider(ApprovalProvider):
    """Non-interactive. Fail-closed by default (deny); approve=True to auto-grant."""

    def __init__(self, approve: bool = False) -> None:
        self._approve = approve

    def request(self, req: ApprovalRequest) -> ApprovalDecision:
        if self._approve:
            return ApprovalDecision(True, "auto-approved (non-interactive policy)", "auto")
        return ApprovalDecision(
            False,
            "auto-denied: no operator present and auto-allow not enabled",
            "auto",
        )


def _pending_path(request_dir: Path, action: str) -> Path:
    return request_dir / f"pending-{action}.json"


def _decision_path(request_dir: Path, action: str) -> Path:
    return request_dir / f"decision-{action}.json"


class ManualApprovalProvider(ApprovalProvider):
    """File-based manual gate: write a pending request, block until the operator
    drops a decision file (or the timeout elapses).

    Decision file (`decision-<action>.json`): {"approved": bool, "reason": str}.
    Keyed by action name (the kill-chain calls each tool once), so the operator
    always knows which file to create. `_clock`/`_sleep` are injectable for tests.
    """

    def __init__(
        self,
        request_dir: str | Path,
        timeout_s: float = 300.0,
        poll_s: float = 1.0,
        _clock: Callable[[], float] = time.monotonic,
        _sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.request_dir = Path(request_dir)
        self.timeout_s = timeout_s
        self.poll_s = poll_s
        self._clock = _clock
        self._sleep = _sleep

    def request(self, req: ApprovalRequest) -> ApprovalDecision:
        self.request_dir.mkdir(parents=True, exist_ok=True)
        pending = _pending_path(self.request_dir, req.action)
        decision = _decision_path(self.request_dir, req.action)
        # Stale decision from a previous run must not auto-approve this one.
        if decision.exists():
            decision.unlink()
        pending.write_text(
            json.dumps({
                "action": req.action,
                "classification": req.classification,
                "reason": req.reason,
                "detail": req.detail,
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        deadline = self._clock() + self.timeout_s
        while self._clock() < deadline:
            if decision.exists():
                data = json.loads(decision.read_text(encoding="utf-8"))
                pending.unlink(missing_ok=True)
                approved = bool(data.get("approved", False))
                reason = data.get("reason", "operator decision")
                return ApprovalDecision(approved, reason, "manual-file")
            self._sleep(self.poll_s)
        pending.unlink(missing_ok=True)
        return ApprovalDecision(False, f"no operator decision within {self.timeout_s:.0f}s", "timeout")


def write_decision(request_dir: str | Path, action: str, approved: bool, reason: str = "") -> Path:
    """Drop an operator decision file (used by `python -m secops_mcp.approve`)."""
    d = Path(request_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = _decision_path(d, action)
    path.write_text(
        json.dumps({"approved": approved, "reason": reason or ("allow" if approved else "deny")},
                   ensure_ascii=False),
        encoding="utf-8",
    )
    return path
