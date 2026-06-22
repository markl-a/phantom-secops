"""Operator-side approval CLI for the governed kill-chain (M2).

When a live high-risk tool call is gated by ManualApprovalProvider it writes a
`pending-<action>.json` into the approval dir and blocks. The operator inspects
it and approves/denies:

    python -m secops_mcp.approve <request_dir> <action> allow|deny [reason...]

e.g.  python -m secops_mcp.approve reports/runs/2026-.../approvals recon allow "lab is mine"
"""

from __future__ import annotations

import sys

from secops_mcp.approval import write_decision


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) < 3 or args[2] not in ("allow", "deny"):
        print(__doc__)
        return 2
    request_dir, action, verdict = args[0], args[1], args[2]
    reason = " ".join(args[3:]) if len(args) > 3 else ""
    path = write_decision(request_dir, action, approved=(verdict == "allow"), reason=reason)
    print(f"→ wrote {verdict} decision for '{action}' to {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
