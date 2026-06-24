"""M2 governance demo — the governed agent loop's guardrails, made visible.

Walks through the four operator-chosen governance boundaries enforced by the
secops_mcp façade. Deterministic: no phantom, no docker, no LLM, no network — so
it runs anywhere and always shows the same thing. The SAME code paths the live
agent loop hits are exercised here directly.

    python scenarios/demo_governance.py      (or: make demo-governed)
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from secops_mcp import server  # noqa: E402
from secops_mcp.approval import ManualApprovalProvider, write_decision  # noqa: E402
from secops_mcp.state import KillChainState  # noqa: E402

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass


def _env(**kw: str) -> None:
    for k in ("SECOPS_AGENT_ROLE", "SECOPS_MCP_APPROVAL", "SECOPS_MCP_MOCK"):
        os.environ.pop(k, None)
    os.environ.update(kw)


def main() -> int:
    run = Path(tempfile.mkdtemp(prefix="secops-gov-demo-"))
    os.environ["SECOPS_MCP_OUT_DIR"] = str(run)
    os.environ["SECOPS_MCP_STATE_FILE"] = str(run / "state.json")

    print("phantom-secops — M2 governed agent loop (no phantom, no docker)\n")

    # [1] blue ↛ red : structural deny, no human
    _env(SECOPS_AGENT_ROLE="blue", SECOPS_MCP_MOCK="1")
    out = server.recon_impl({"target": "juice-shop"})
    print("[1] blue agent → red tool (recon)         expect: structural DENY")
    print(f"    ⛔ {out.get('error')}  (by {out.get('by')})\n")

    # [2] blue → blue : allowed
    out = server.detect_impl({})
    print("[2] blue agent → blue tool (detect)       expect: ALLOW")
    print(f"    ✅ allowed — {out.get('triaged_groups')} triaged groups\n")

    # [3] live red scan, fail-closed (no approval configured)
    _env(SECOPS_AGENT_ROLE="orchestrator", SECOPS_MCP_MOCK="0", SECOPS_MCP_APPROVAL="auto-deny")
    out = server.recon_impl({"target": "juice-shop"})
    print("[3] live red scan, no approval            expect: fail-closed DENY")
    print(f"    ⛔ {out.get('error')}  (by {out.get('by')})\n")

    # [4] live red scan, manual approval: pause → operator allows → resume
    print("[4] live red scan, manual approval        expect: PAUSE → approve → release")
    approvals = run / "approvals"
    # simulate the operator approving while the gate is blocked on the pending file
    def _operator_approves(_secs: float) -> None:
        if (approvals / "pending-recon.json").exists():
            write_decision(approvals, "recon", approved=True, reason="self-authorized lab")
    provider = ManualApprovalProvider(approvals, timeout_s=5.0, poll_s=0.1, _sleep=_operator_approves)
    from secops_mcp.approval import ApprovalRequest
    print("    ⏸  pending-recon.json written; operator runs:")
    print("        python -m secops_mcp.approve <approvals-dir> recon allow")
    dec = provider.request(ApprovalRequest(action="recon", classification="red",
                                           reason="live red-team scan requires approval"))
    print(f"    ✅ released via {dec.via}: {dec.reason} → the real scan would now run\n")

    print("governance.jsonl audit trail:")
    for line in (run / "governance.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        print(f"  - {r['tool']:<10} role={r['role']:<12} {r['decision']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
