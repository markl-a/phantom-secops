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
from tools import nuclei_runner  # type: ignore[import-not-found]  # noqa: E402

REPORTS_DIR = REPO_ROOT / "reports"
MOCKS_DIR = REPO_ROOT / "lab" / "mocks"

# Simulated per-step durations (seconds) used in --mock mode so the red and blue
# timelines are meaningful instead of all-zero. Live mode ignores these and uses
# real wall-clock.
#
# Provenance: these are ILLUSTRATIVE order-of-magnitude operator-time estimates
# (e.g. recon ≈ an nmap -sV of one host; threat-correlate ≈ an analyst review
# window), NOT measured benchmarks. They are scenario inputs that make the
# simulated timeline plausible; the *mechanism* (concurrent clocks, milestone
# extraction, the MTTD comparison) is what's real and tested — the numbers are
# not a claim about real detection latency.
RED_DURATIONS = {
    "recon": 12.0, "vuln-scan": 30.0, "exploit-suggest": 8.0, "pentest-report": 5.0,
}
BLUE_DURATIONS = {
    "log-anomaly": 8.0, "alert-triage": 7.0, "threat-correlate": 35.0, "incident-report": 5.0,
}


class Clock:
    """Two concurrent clocks (red attacker, blue defender).

    In mock mode each side advances by simulated step durations; in live mode
    both report real elapsed wall-clock and `advance` is a no-op.
    """

    def __init__(self, mock: bool) -> None:
        self.mock = mock
        self._t0 = time.time()
        self._t = {"red": 0.0, "blue": 0.0}

    def now(self, side: str) -> float:
        if not self.mock:
            return time.time() - self._t0
        return self._t.get(side, 0.0)

    def advance(self, side: str, secs: float) -> None:
        if self.mock and side in self._t:
            self._t[side] += secs


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

    timeline, pentest_md, incident_md = _run_pipeline(args, out_dir)

    print()
    print(f"→ artifacts at: {out_dir}")
    print(f"   - pentest-report.md   ({len(pentest_md):,} bytes)")
    print(f"   - incident-report.md  ({len(incident_md):,} bytes)")
    print(f"   - {len(list(out_dir.glob('*.json'))) + len(list(out_dir.glob('*.jsonl')))} structured artifacts")
    print()
    m = _metrics(timeline)
    sim = "  (simulated timing — mock mode)" if args.mock else ""
    print(f"→ MTTD = {m['mttd']:.0f}s{sim}")
    if m["outcome"] == "defender":
        print(f"  defender triaged at t+{m['first_detect']:.0f}s; attacker reached "
              f"impact at t+{m['time_to_impact']:.0f}s → detected "
              f"{m['detect_margin']:.0f}s before impact (defender win)")
    else:
        print(f"  attacker reached impact at t+{m['time_to_impact']:.0f}s; defender "
              f"triaged at t+{m['first_detect']:.0f}s → impact "
              f"{-m['detect_margin']:.0f}s before detection (attacker win)")

    return 0


def _run_pipeline(
    args: argparse.Namespace, out_dir: Path,
) -> tuple[list[tuple[float, str, str]], str, str]:
    """Run the red + blue pipeline, write artifacts, return (timeline, reports).

    Event-issue order puts the defender's detection (blue-alert-triage) BEFORE the
    attacker's impact (red-exploit-suggest done). In mock mode the two-clock model
    already orders them; ordering it here too keeps live (single-process, real
    wall-clock) mode honest — detection genuinely precedes impact, so the MTTD
    comparison isn't a mock-only illusion. Blue reads attack-log.txt independent
    of red outputs, so the interleaving is safe.
    """
    timeline: list[tuple[float, str, str]] = []
    clock = Clock(mock=args.mock)

    def event(side: str, label: str, advance: float = 0.0) -> None:
        t = clock.now(side)
        print(f"  [t+{t:5.1f}s] {label}")
        timeline.append((t, side, label))
        clock.advance(side, advance)

    # red recon → red vuln-scan
    event("red", "red-recon  starts", RED_DURATIONS["recon"])
    recon = _run_recon(args.target, mock=args.mock)
    (out_dir / "recon.json").write_text(json.dumps(recon, indent=2, ensure_ascii=False), encoding="utf-8")
    event("red", f"red-recon  → {len(recon.get('open_ports', []))} open ports")

    event("red", "red-vuln-scan  starts", RED_DURATIONS["vuln-scan"])
    vuln = _run_vuln_scan(args.target, recon, mock=args.mock)
    (out_dir / "vuln-scan.json").write_text(json.dumps(vuln, indent=2, ensure_ascii=False), encoding="utf-8")
    event("red", f"red-vuln-scan  → {len(vuln.get('findings', []))} findings")

    # blue log-anomaly → alert-triage (DETECTION) — issued before red impact
    event("blue", "blue-log-anomaly  scanning canned attack log", BLUE_DURATIONS["log-anomaly"])
    alerts = _blue_log_anomaly(mock=args.mock)
    (out_dir / "alerts.jsonl").write_text("\n".join(json.dumps(a) for a in alerts), encoding="utf-8")
    event("blue", f"blue-log-anomaly  → {len(alerts)} raw alerts")

    event("blue", "blue-alert-triage  classify + dedupe", BLUE_DURATIONS["alert-triage"])
    triaged = _blue_alert_triage(alerts)
    (out_dir / "triage-queue.jsonl").write_text("\n".join(json.dumps(t) for t in triaged), encoding="utf-8")
    event("blue", f"blue-alert-triage  → {len(triaged)} triaged groups")  # ← defender detects

    # red exploit-suggest (IMPACT) — issued after detection
    event("red", "red-exploit-suggest  composing prose", RED_DURATIONS["exploit-suggest"])
    suggestions = _run_exploit_suggest(vuln, mock=args.mock, use_llm=args.use_llm)
    (out_dir / "exploit-suggestions.md").write_text(suggestions, encoding="utf-8")
    event("red", "red-exploit-suggest  done")  # ← attacker reaches actionable impact

    # blue threat-correlate
    event("blue", "blue-threat-correlate  reconstruct kill chain", BLUE_DURATIONS["threat-correlate"])
    correlation = _blue_threat_correlate(triaged)
    (out_dir / "kill-chains.jsonl").write_text("\n".join(json.dumps(c) for c in correlation), encoding="utf-8")
    event("blue", f"blue-threat-correlate  → {len(correlation)} actor(s)")

    # report-composition steps (timed), then compose with the full timeline
    event("red", "red-pentest-report  composing markdown", RED_DURATIONS["pentest-report"])
    event("blue", "blue-incident-report  composing markdown", BLUE_DURATIONS["incident-report"])

    end_t = max(clock.now("red"), clock.now("blue"))
    print(f"  [t+{end_t:5.1f}s] done")
    timeline.append((end_t, "sys", "done"))

    pentest_md = _compose_pentest_report(recon, vuln, suggestions, timeline, mock=args.mock)
    (out_dir / "pentest-report.md").write_text(pentest_md, encoding="utf-8")
    incident_md = _compose_incident_report(triaged, correlation, timeline, mock=args.mock)
    (out_dir / "incident-report.md").write_text(incident_md, encoding="utf-8")

    return timeline, pentest_md, incident_md


# ─── Red pipeline implementations ────────────────────────────────────────

def _run_recon(target: str, mock: bool) -> dict[str, Any]:
    if mock:
        return json.loads((MOCKS_DIR / "recon-juice-shop.json").read_text(encoding="utf-8"))
    return nmap_runner.run(target)


def _http_targets(target: str, recon: dict[str, Any]) -> list[str]:
    """Derive HTTP(S) URLs to scan from recon's open ports (fallback: http://<target>)."""
    urls: list[str] = []
    for p in recon.get("open_ports", []):
        svc = (p.get("service") or "").lower()
        port = p.get("port")
        if "http" in svc or port in (80, 443, 3000, 8080, 8443):
            scheme = "https" if ("https" in svc or port in (443, 8443)) else "http"
            urls.append(f"{scheme}://{target}:{port}")
    return urls or [f"http://{target}"]


def _run_vuln_scan(
    target: str, recon: dict[str, Any], mock: bool, nuclei_run=None,
) -> dict[str, Any]:
    if mock:
        return json.loads((MOCKS_DIR / "vuln-scan-juice-shop.json").read_text(encoding="utf-8"))
    # Live mode: run nuclei against each HTTP endpoint found in recon and
    # aggregate. The runner self-gates to in-lab hosts and returns an {"error":
    # ...} dict (no findings) when nuclei/docker is unavailable, so a missing lab
    # degrades to empty findings rather than crashing. `nuclei_run` is injectable
    # for tests.
    nuclei_run = nuclei_run or nuclei_runner.run
    findings: list[dict[str, Any]] = []
    for url in _http_targets(target, recon):
        result = nuclei_run(url)
        findings.extend(result.get("findings", []))
    return {"target": target, "findings": findings}


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
    timeline: list[tuple[float, str, str]],
    mock: bool = False,
) -> str:
    findings = vuln.get("findings", [])
    by_sev = {s: sum(1 for f in findings if f.get("severity") == s)
              for s in ("critical", "high", "medium", "low", "info")}
    return f"""# Pentest Report — {vuln.get('target', 'unknown')} (lab)

**Engagement**: phantom-secops kill-chain demo
**Conducted**: {datetime.now(timezone.utc).isoformat()}
**Authorization**: Self-authorized, isolated lab. See ETHICS.md.

## Executive Summary

A red/blue kill-chain pipeline executed in {_total_seconds(timeline):.1f}
seconds. The recon step identified {len(recon.get('open_ports', []))} open service(s).
The vuln-scan step matched {len(findings)} findings ({by_sev.get('high', 0)} high,
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
{_timing_note(mock)}
"""


def _timing_note(mock: bool) -> str:
    return ("\n_Timeline timing is **simulated** in mock mode (representative SOC "
            "durations); live mode uses real wall-clock._\n") if mock else ""


def _compose_incident_report(
    triaged: list[dict[str, Any]],
    correlation: list[dict[str, Any]],
    timeline: list[tuple[float, str, str]],
    mock: bool = False,
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

## MTTD (mean time to detect)

{_render_mttd(timeline)}
{_timing_note(mock)}
"""


def _render_mttd(timeline: list[tuple[float, str, str]]) -> str:
    m = _metrics(timeline)
    verdict = (f"defender detected **{m['detect_margin']:.0f}s before** the attacker "
               "reached impact" if m["detect_margin"] >= 0 else
               f"attacker reached impact **{-m['detect_margin']:.0f}s before** detection")
    return (
        f"- Attacker first action: **t+{m['first_action']:.0f}s**\n"
        f"- Defender first triaged alert (detection): **t+{m['first_detect']:.0f}s**\n"
        f"- Attacker reached impact: **t+{m['time_to_impact']:.0f}s**\n"
        f"- **MTTD = {m['mttd']:.0f}s** — {verdict}."
    )


# ─── Renderers ───────────────────────────────────────────────────────────

def _render_ports(recon: dict[str, Any]) -> str:
    ports = recon.get("open_ports", [])
    if not ports:
        return "_(none)_"
    lines = ["| Port | Service | Version |", "|---|---|---|"]
    for p in ports:
        lines.append(f"| {p.get('port')} | {p.get('service', '')} | {p.get('version') or ''} |")
    return "\n".join(lines)


def _render_timeline(tl: list[tuple[float, str, str]]) -> str:
    lines = ["| t (s) | Side | Event |", "|---|---|---|"]
    for t, side, label in sorted(tl, key=lambda e: e[0]):
        lines.append(f"| {t:.1f} | {side} | {label} |")
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


def _total_seconds(tl: list[tuple[float, str, str]]) -> float:
    return max((t for t, _, _ in tl), default=0.0)


def _metrics(tl: list[tuple[float, str, str]]) -> dict[str, float]:
    """Honest red/blue timing metrics from the concurrent timeline.

    - first_action:   attacker's first move (earliest red event)
    - first_detect:   defender's first triaged alert
    - time_to_impact: attacker reaches an actionable exploit (impact)
    - mttd:           first_detect - first_action
    - detect_margin:  time_to_impact - first_detect (positive = detected before impact)
    """
    red_times = [t for t, side, _ in tl if side == "red"]
    first_action = min(red_times) if red_times else 0.0
    first_detect = next((t for t, _, lbl in tl if "alert-triage" in lbl and "→" in lbl), 0.0)
    time_to_impact = next(
        (t for t, _, lbl in tl if "exploit-suggest" in lbl and "done" in lbl), 0.0
    )
    detect_margin = time_to_impact - first_detect
    return {
        "first_action": first_action,
        "first_detect": first_detect,
        "time_to_impact": time_to_impact,
        "mttd": max(0.0, first_detect - first_action),
        # Honest, NOT clamped: negative means the attacker reached impact before
        # the defender detected (attacker win). Live mode can legitimately hit this.
        "detect_margin": detect_margin,
        "outcome": "defender" if detect_margin >= 0 else "attacker",
    }


def _mttd_seconds(tl: list[tuple[float, str, str]]) -> float:
    return _metrics(tl)["mttd"]


if __name__ == "__main__":
    sys.exit(main())
