import sys
from tools.vuln_scan import scan_vulns

path = sys.argv[1] if len(sys.argv) > 1 else "."
r = scan_vulns(path)
print("scanned :", r["scanned"])
print("summary :", r["summary"])
print("error   :", r.get("error", "none"))
for f in r["findings"][:15]:
    fix = f["fixed"] or "(no fix)"
    print(f"  {f['severity']:8s} {f['id']:18s} {f['pkg']} {f['installed']} -> {fix}")
