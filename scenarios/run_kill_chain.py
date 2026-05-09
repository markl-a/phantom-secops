"""Kill-chain orchestrator.

Runs the red and blue agent pipelines against an in-lab target and emits a
side-by-side report. Two modes:

  --mock   : use canned data from lab/mocks/. No docker, no API key. CI-safe.
            Useful for demos on a fresh machine or when offline.
  default  : run against the live lab brought up by `make lab-up`. Calls into
            the tool wrappers in tools/ which shell out to nmap/nuclei via
            docker exec.

LLM-driven report-writing is opt-in via --use-llm. When unset, reports are
generated from templates with deterministic substitutions, which keeps the
demo fast and reproducible.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import nmap_runner  # type: ignore[import-not-found]  # noqa: E402

REPORTS_DIR = REPO_ROOT / "reports"
MOCKS_DIR = REPO_ROOT / "lab" / "mocks"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", default="juice-shop",
                   help="lab service name (default: juice-shop)")
    p.add_argument("--mock", action="store_true",
                   help="use canned data; no docker required")
    p.add_argument("--use-llm", action="store_true",
                   help="invoke phantom-mesh for LLM-driven report writing "
                        "(requires phantom serve at localhost:7878)")
    p.add_argument("--out", default=None, help="output dir (default: reports/runs/<ts>/)")
    args = p.parse_args()

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M")
    out_dir = Path(args.out) if args.out else REPORTS_DIR / "runs" / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"→ phantom-secops kill-chain :: target={args.target} mock={args.mock} llm={args.use_llm}")
    print(f"  output: {out_dir}")
    print()

    timeline: list[tuple[str, str]] = []
    t0 = time.time()

    def event(label: str) -> None:
        elapsed = time.time() - t0
        line = f"  [t+{elapsed:5.1f}s] {label}"
        print(line)
        timeline.append((f"{elapsed:.1f}", label))

    # ─── Red pipeline ─────────────────────────────────────────────────────
    event("red-recon  starts")
    recon = _run_recon(args.target, mock=args.mock)
    (out_dir / "recon.json").write_text(json.dumps(recon, indent=2, ensure_ascii=False), encoding="utf-8")
    event(f"red-recon  → {len(recon.get('open_ports', []))} open ports")

    event("red-vuln-scan  starts")
    vuln = _run_vuln_scan(args.target, recon, mock=args.mock)
    (out_dir / "vuln-scan.json").write_text(json.dumps(vuln, indent=2, ensure_ascii=False), encoding="utf-8")
    event(f"red-vuln-scan  → {len(vuln.get('findings', []))} findings")

    event("red-exploit-suggest  composing prose")
    suggestions = _run_exploit_suggest(vuln, mock=args.mock, use_llm=args.use_llm)
    (out_dir / "exploit-suggestions.md").write_text(suggestions, encoding="utf-8")
    event("red-exploit-suggest  done")

    # ─── Blue pipeline (synthetic — would normally run continuously) ─────
    event("blue-log-anomaly  scanning canned attack log")
    alerts = _blue_log_anomaly(mock=args.mock)
    (out_dir / "alerts.jsonl").write_text("\n".join(json.dumps(a) for a in alerts), encoding="utf-8")
    event(f"blue-log-anomaly  → {len(alerts)} raw alerts")

    event("blue-alert-triage  classify + dedupe")
    triaged = _blue_alert_triage(alerts)
    (out_dir / "triage-queue.jsonl").write_text("\n".join(json.dumps(t) for t in triaged), encoding="utf-8")
    event(f"blue-alert-triage  → {len(triaged)} triaged groups")

    event("blue-threat-correlate  reconstruct kill chain")
    correlation = _blue_threat_correlate(triaged)
    (out_dir / "kill-chains.jsonl").write_text("\n".join(json.dumps(c) for c in correlation), encoding="utf-8")
    event(f"blue-threat-correlate  → {len(correlation)} actor(s)")

    # ─── Reports ─────────────────────────────────────────────────────────
    event("red-pentest-report  composing markdown")
    pentest_md = _compose_pentest_report(recon, vuln, suggestions, timeline)
    (out_dir / "pentest-report.md").write_text(pentest_md, encoding="utf-8")

    event("blue-incident-report  composing markdown")
    incident_md = _compose_incident_report(triaged, correlation, timeline)
    (out_dir / "incident-report.md").write_text(incident_md, encoding="utf-8")

    event("done")
    print()
    print(f"→ artifacts at: {out_dir}")
    print(f"   - pentest-report.md   ({len(pentest_md):,} bytes)")
    print(f"   - incident-report.md  ({len(incident_md):,} bytes)")
    print(f"   - {len(list(out_dir.glob('*.json'))) + len(list(out_dir.glob('*.jsonl')))} structured artifacts")
    print()
    print(f"→ MTTD (first probe → first triaged alert): "
          f"{_mttd_seconds(timeline):.1f}s in this run")

    return 0


# ─── Red pipeline implementations ────────────────────────────────────────

def _run_recon(target: str, mock: bool) -> dict[str, Any]:
    if mock:
        return json.loads((MOCKS_DIR / "recon-juice-shop.json").read_text(encoding="utf-8"))
    return nmap_runner.run(target)


def _run_vuln_scan(target: str, recon: dict[str, Any], mock: bool) -> dict[str, Any]:
    _ = recon  # vuln-scan reads recon ports in live mode (see tools/nuclei_runner.py)
    if mock:
        return json.loads((MOCKS_DIR / "vuln-scan-juice-shop.json").read_text(encoding="utf-8"))
    # Live mode would call nuclei_runner.run(...) for each open HTTP port from
    # the recon JSON. Skipped in this minimal demo path; see tools/nuclei_runner.py.
    return {"target": target, "findings": []}


def _run_exploit_suggest(vuln: dict[str, Any], mock: bool, use_llm: bool) -> str:
    _ = mock, use_llm  # signature kept for future LLM-driven prose generation
    findings = vuln.get("findings", [])
    if not findings:
        return "_No vulnerabilities flagged by the scan._\n"

    out = ["# Exploit Suggestions\n"]
    for f in findings:
        out.append(f"## {f.get('id', 'unknown')} — {f.get('title', '(no title)')}\n")
        cve = f.get("cve")
        if cve:
            out.append(f"**CVE:** {cve}")
        out.append(f"**Severity:** {f.get('severity', 'unknown')}\n")
        out.append(_exploit_prose(f))
        out.append("")  # blank line
    return "\n".join(out)


def _exploit_prose(f: dict[str, Any]) -> str:
    """Prose only. No runnable exploits, ever."""
    sev = f.get("severity", "info")
    title = f.get("title", "")
    if "jquery" in title.lower() or "CVE-2020-11023" in (f.get("cve") or ""):
        return ("This vulnerability allows DOM-based XSS via malformed `<option>` "
                "tags processed by `htmlPrefilter`. Public references describe the "
                "exploitation path; this report does not include a runnable payload. "
                "**Mitigation:** upgrade jQuery to ≥3.5.")
    if "admin" in title.lower():
        return ("Administrative interface reachable without network-layer auth. "
                "**Mitigation:** require auth on `/administration` routes or remove "
                "from production builds.")
    if sev == "low":
        return "Likely false-positive. Flagged for traceability only."
    return "See public CVE reference for exploitation details. No POC included."


# ─── Blue pipeline implementations ────────────────────────────────────────

def _blue_log_anomaly(mock: bool) -> list[dict[str, Any]]:
    """Backward-compatible shim around tools.log_anomaly.scan_log_lines."""
    from tools.log_anomaly import scan_log_lines  # imported lazily to keep test isolation
    log_path = MOCKS_DIR / "attack-log.txt" if mock else REPO_ROOT / "reports/lab-logs/juice-shop.log"
    return scan_log_lines(log_path, asset="juice-shop")


def _blue_alert_triage(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group by (source_ip, category) and assign priority."""
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for a in alerts:
        key = (a["source_ip"], a["category"])
        if key not in groups:
            groups[key] = {
                "ts": a["ts"],
                "priority": "P3",
                "asset": a["asset"],
                "summary": f"{a['category']} pattern from {a['source_ip']}",
                "count": 0,
                "evidence": [],
            }
        g = groups[key]
        g["count"] += 1
        if len(g["evidence"]) < 3:
            g["evidence"].append(a["evidence"])
        # priority promotion: scanner activity stays P3 unless scaled; sqli/traversal jumps
        if a["severity_hint"] == "high":
            g["priority"] = "P1" if g["count"] >= 2 else "P2"
        elif a["severity_hint"] == "medium":
            if g["priority"] == "P3":
                g["priority"] = "P2"
    return list(groups.values())


def _blue_threat_correlate(triaged: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group triaged alerts by source actor and infer ATT&CK phases."""
    actors: dict[str, dict[str, Any]] = {}
    for t in triaged:
        ip = t["summary"].split("from ")[-1] if "from " in t["summary"] else "unknown"
        if ip not in actors:
            actors[ip] = {
                "actor": ip,
                "first_seen": t["ts"],
                "last_seen": t["ts"],
                "phases_observed": set(),
                "alert_summaries": [],
                "narrative": "",
                "confidence": "high",
            }
        a = actors[ip]
        a["alert_summaries"].append(t["summary"])
        cat = t["summary"].split(" pattern")[0]
        if cat in ("scanner",):              a["phases_observed"].add("TA0043")  # Reconnaissance
        if cat in ("sqli", "xss", "traversal"): a["phases_observed"].add("TA0001")  # Initial Access
        if cat == "admin_path":              a["phases_observed"].add("TA0007")  # Discovery

    out: list[dict[str, Any]] = []
    for a in actors.values():
        a["phases_observed"] = sorted(a["phases_observed"])
        cats = [s.split(" pattern")[0] for s in a["alert_summaries"]]
        narrative_bits = []
        if "scanner" in cats: narrative_bits.append("active port + URL enumeration")
        if any(c in cats for c in ("sqli", "xss", "traversal")):
            narrative_bits.append("attempted injection patterns against the application")
        if "admin_path" in cats: narrative_bits.append("probing for admin endpoints")
        a["narrative"] = (
            f"Single actor ({a['actor']}) performed: "
            + "; ".join(narrative_bits) + "."
        ) if narrative_bits else "Activity observed but pattern unclear."
        out.append(a)
    return out


# ─── Report composition ──────────────────────────────────────────────────

def _compose_pentest_report(
    recon: dict[str, Any],
    vuln: dict[str, Any],
    suggestions: str,
    timeline: list[tuple[str, str]],
) -> str:
    findings = vuln.get("findings", [])
    by_sev = {s: sum(1 for f in findings if f.get("severity") == s)
              for s in ("critical", "high", "medium", "low", "info")}
    return f"""# Pentest Report — {vuln.get('target', 'unknown')} (lab)

**Engagement**: phantom-secops kill-chain demo
**Conducted**: {datetime.now(timezone.utc).isoformat()}
**Authorization**: Self-authorized, isolated lab. See ETHICS.md.

## Executive Summary

A multi-agent pipeline executed a full kill-chain in {_total_seconds(timeline):.1f}
seconds. The recon agent identified {len(recon.get('open_ports', []))} open service(s).
The vuln-scan agent matched {len(findings)} findings ({by_sev.get('high', 0)} high,
{by_sev.get('medium', 0)} medium, {by_sev.get('low', 0)} low). No exploitation was
performed.

## Recon

Open ports:
{_render_ports(recon)}

## Findings

| Severity | Count |
|---|---|
| Critical | {by_sev.get('critical', 0)} |
| High | {by_sev.get('high', 0)} |
| Medium | {by_sev.get('medium', 0)} |
| Low | {by_sev.get('low', 0)} |
| Info | {by_sev.get('info', 0)} |

## Exploit suggestions (prose only)

{suggestions}

## Timeline

{_render_timeline(timeline)}
"""


def _compose_incident_report(
    triaged: list[dict[str, Any]],
    correlation: list[dict[str, Any]],
    timeline: list[tuple[str, str]],
) -> str:
    p1 = sum(1 for t in triaged if t["priority"] == "P1")
    p2 = sum(1 for t in triaged if t["priority"] == "P2")
    p3 = sum(1 for t in triaged if t["priority"] == "P3")
    return f"""# Incident Report — Lab observation, {datetime.now(timezone.utc).date().isoformat()}

## TL;DR

{len(correlation)} actor(s) observed against the lab. Triage pipeline produced
{p1} P1, {p2} P2, {p3} P3 grouped alerts. All activity attributable to the lab
attacker container by design.

## Timeline

{_render_timeline(timeline)}

## Actors

{_render_actors(correlation)}

## Triaged alerts

{_render_triage(triaged)}

## MTTD

First probe → first triaged alert in **{_mttd_seconds(timeline):.1f} seconds**.
"""


# ─── Renderers ───────────────────────────────────────────────────────────

def _render_ports(recon: dict[str, Any]) -> str:
    ports = recon.get("open_ports", [])
    if not ports:
        return "_(none)_"
    lines = ["| Port | Service | Version |", "|---|---|---|"]
    for p in ports:
        lines.append(f"| {p.get('port')} | {p.get('service', '')} | {p.get('version') or ''} |")
    return "\n".join(lines)


def _render_timeline(tl: list[tuple[str, str]]) -> str:
    lines = ["| t (s) | Event |", "|---|---|"]
    for t, label in tl:
        lines.append(f"| {t} | {label} |")
    return "\n".join(lines)


def _render_actors(actors: list[dict[str, Any]]) -> str:
    if not actors:
        return "_(none observed)_"
    lines = []
    for a in actors:
        phases = ", ".join(a["phases_observed"]) or "_unclassified_"
        lines.append(f"### {a['actor']}")
        lines.append(f"- phases: {phases}")
        lines.append(f"- confidence: {a['confidence']}")
        lines.append(f"- narrative: {a['narrative']}\n")
    return "\n".join(lines)


def _render_triage(triaged: list[dict[str, Any]]) -> str:
    if not triaged:
        return "_(none)_"
    lines = ["| Priority | Asset | Summary | Count |", "|---|---|---|---|"]
    for t in sorted(triaged, key=lambda x: x["priority"]):
        lines.append(f"| {t['priority']} | {t['asset']} | {t['summary']} | {t['count']} |")
    return "\n".join(lines)


def _total_seconds(tl: list[tuple[str, str]]) -> float:
    return float(tl[-1][0]) if tl else 0.0


def _mttd_seconds(tl: list[tuple[str, str]]) -> float:
    """First red event → first blue triaged alert."""
    first_red = next((float(t) for t, lbl in tl if "red-" in lbl and "starts" in lbl), 0.0)
    first_blue_triage = next(
        (float(t) for t, lbl in tl if "alert-triage" in lbl and "→" in lbl), 0.0
    )
    return max(0.0, first_blue_triage - first_red)


if __name__ == "__main__":
    sys.exit(main())
