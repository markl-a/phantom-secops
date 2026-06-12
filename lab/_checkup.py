"""Print raw output of each secops tool — used by checkup.ps1."""

from __future__ import annotations

import sys

from tools.host_audit import audit_host
from tools.vuln_scan import scan_vulns

path = sys.argv[1] if len(sys.argv) > 1 else "."

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
