"""Print raw output of each secops tool plus the fused, prioritised action list.

Used by checkup.ps1: it runs ``python lab/_checkup.py <path>`` and feeds the
captured text to the secops agent. The ``== PRIORITISED ACTIONS ==`` block is
produced deterministically by tools.posture_fusion (no LLM) so the unified,
ranked action list exists on the real run even before/without the agent.
"""

from __future__ import annotations

import sys

from tools.host_audit import audit_host
from tools.ids_scan import scan_intrusions
from tools.posture_fusion import fuse_posture
from tools.vuln_scan import scan_vulns


def main(path: str = ".") -> None:
    print("== HOST POSTURE ==")
    h = audit_host()
    print(f"  elevation: {h['elevation']}  summary: {h['summary']}")
    if h.get("hint"):
        print(f"  hint: {h['hint']}")
    for f in h["checks"]:
        print(f"  [{f['status']:7s}] {f['check']:22s} {f['detail'][:68]}")

    print(f"\n== VULNERABILITIES ==  ({path})")
    v = scan_vulns(path)
    print(f"  summary: {v['summary']}  error: {v.get('error', 'none')}")
    for f in v["findings"][:12]:
        fix = f["fixed"] or "(no fix)"
        print(f"  {f['severity']:8s} {f['id']:18s} {f['pkg']} {f['installed']} -> {fix}")

    print("\n== INTRUSION DETECTION ==")
    i = scan_intrusions()
    print(f"  events_read: {i['events_read']}  summary: {i['summary']}")
    for a in i["alerts"][:10]:
        excerpt = (a["event"].get("Message") or "").replace("\n", " ")[:60]
        print(f"  {a['level']:8s} {a['title']}  ::  {excerpt}")

    # Deterministic cross-tool fusion: ONE ranked list, highest risk first.
    print("\n== PRIORITISED ACTIONS ==  (deterministic cross-tool fusion)")
    actions = fuse_posture(h, v, i)
    if not actions:
        print("  (no actionable findings)")
    for n, a in enumerate(actions, 1):
        print(f"  {n:2d}. [{a.severity_name:8s}] {a.tool:10s} {a.action}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
