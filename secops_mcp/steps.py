"""Composite kill-chain steps the agent calls as MCP tools.

Each function takes a KillChainState, performs one red or blue stage by
delegating to phantom_secops.killchain (the shared core — never reimplemented
here), emits the SAME timeline events as scenarios.run_kill_chain._run_pipeline,
writes the same per-run artifacts, mutates the state, and returns a compact
summary dict for the agent. The canonical call order is:

    recon → vuln_scan → detect → respond

Under that order the emitted timeline is byte-identical to the direct driver's
(same per-side event sequence, same canned durations), so reports and MTTD match
modulo timestamps — the M1 parity guarantee. Each step refuses to run if a
prerequisite stage hasn't populated state yet; that converges a drifting agent
back onto the canonical order instead of producing a half-built report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from phantom_secops import killchain as kc
from secops_mcp.state import KillChainState


class StepOrderError(RuntimeError):
    """Raised when a step is called before its prerequisite stage has run."""


def _write(state: KillChainState, name: str, text: str) -> None:
    """Write an artifact into the run dir, if one is configured (no-op otherwise)."""
    if not state.out_dir:
        return
    out = Path(state.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / name).write_text(text, encoding="utf-8")


def recon(state: KillChainState) -> dict[str, Any]:
    """Red recon: nmap (or canned) → open ports. First stage, no prerequisites."""
    state.event("red", "red-recon  starts", kc.RED_DURATIONS["recon"])
    result = kc._run_recon(state.target, mock=state.mock)
    state.recon = result
    _write(state, "recon.json", json.dumps(result, indent=2, ensure_ascii=False))
    ports = result.get("open_ports", [])
    state.event("red", f"red-recon  → {len(ports)} open ports")
    return {"open_ports": len(ports),
            "ports": [{"port": p.get("port"), "service": p.get("service")} for p in ports]}


def vuln_scan(state: KillChainState, severity: str = kc.NUCLEI_SEVERITY) -> dict[str, Any]:
    """Red vuln-scan: nuclei (or canned) against recon's HTTP endpoints."""
    if state.recon is None:
        raise StepOrderError("recon must run before vuln_scan")
    state.event("red", "red-vuln-scan  starts", kc.RED_DURATIONS["vuln-scan"])
    result = kc._run_vuln_scan(state.target, state.recon, mock=state.mock, severity=severity)
    state.vuln = result
    _write(state, "vuln-scan.json", json.dumps(result, indent=2, ensure_ascii=False))
    findings = result.get("findings", [])
    state.event("red", f"red-vuln-scan  → {len(findings)} findings")
    out: dict[str, Any] = {"findings": len(findings)}
    if result.get("errors"):
        out["errors"] = result["errors"]
    return out


def detect(state: KillChainState) -> dict[str, Any]:
    """Blue detection: ingest + anomaly → triage. Reads logs independently of red."""
    log_src = "canned attack log" if state.mock else "live lab logs"
    state.event("blue", f"blue-log-anomaly  scanning {log_src}", kc.BLUE_DURATIONS["log-anomaly"])
    out_dir = Path(state.out_dir) if state.out_dir else None
    alerts = kc._blue_log_anomaly(mock=state.mock, out_dir=out_dir)
    state.alerts = alerts
    _write(state, "alerts.jsonl", "\n".join(json.dumps(a) for a in alerts))
    state.event("blue", f"blue-log-anomaly  → {len(alerts)} raw alerts")

    state.event("blue", "blue-alert-triage  classify + dedupe", kc.BLUE_DURATIONS["alert-triage"])
    triaged = kc._blue_alert_triage(alerts)
    state.triaged = triaged
    _write(state, "triage-queue.jsonl", "\n".join(json.dumps(t) for t in triaged))
    state.event("blue", f"blue-alert-triage  → {len(triaged)} triaged groups")

    priorities = {p: sum(1 for t in triaged if t["priority"] == p) for p in ("P1", "P2", "P3")}
    return {"raw_alerts": len(alerts), "triaged_groups": len(triaged), "priorities": priorities}


def respond(state: KillChainState) -> dict[str, Any]:
    """Red exploit-suggest (prose) + blue correlate, then compose both reports.

    This closes the kill-chain: it needs the red vuln results (to suggest) and
    the blue triage queue (to correlate + report), so it refuses to run until
    both vuln_scan and detect have populated state.
    """
    if state.vuln is None:
        raise StepOrderError("vuln_scan must run before respond")
    if state.triaged is None:
        raise StepOrderError("detect must run before respond")

    # red impact — prose only, never a runnable PoC
    state.event("red", "red-exploit-suggest  composing prose", kc.RED_DURATIONS["exploit-suggest"])
    suggestions = kc._run_exploit_suggest(state.vuln, mock=state.mock, use_llm=False)
    state.suggestions = suggestions
    _write(state, "exploit-suggestions.md", suggestions)
    state.event("red", "red-exploit-suggest  done")

    # blue correlation
    state.event("blue", "blue-threat-correlate  reconstruct kill chain", kc.BLUE_DURATIONS["threat-correlate"])
    correlation = kc._blue_threat_correlate(state.triaged)
    state.correlation = correlation
    _write(state, "kill-chains.jsonl", "\n".join(json.dumps(c) for c in correlation))
    state.event("blue", f"blue-threat-correlate  → {len(correlation)} actor(s)")

    # report-composition steps (timed), then compose with the full timeline
    state.event("red", "red-pentest-report  composing markdown", kc.RED_DURATIONS["pentest-report"])
    state.event("blue", "blue-incident-report  composing markdown", kc.BLUE_DURATIONS["incident-report"])
    state.end_event()

    degradations = kc._scan_degradations(state.recon or {}, state.vuln, mock=state.mock)
    pentest_md = kc._compose_pentest_report(
        state.recon or {}, state.vuln, suggestions, state.timeline,
        mock=state.mock, degradations=degradations)
    _write(state, "pentest-report.md", pentest_md)
    incident_md = kc._compose_incident_report(
        state.triaged, correlation, state.timeline,
        mock=state.mock, degradations=degradations)
    _write(state, "incident-report.md", incident_md)
    state.reports = {"pentest": pentest_md, "incident": incident_md}

    metrics = kc._metrics(state.timeline)
    summary = {**metrics, "timeline": [
        {"t": t, "side": side, "label": label}
        for t, side, label in sorted(state.timeline, key=lambda e: e[0])
    ]}
    _write(state, "summary.json", json.dumps(summary, indent=2, ensure_ascii=False))

    return {
        "mttd": metrics["mttd"],
        "outcome": metrics["outcome"],
        "detect_margin": metrics["detect_margin"],
        "actors": len(correlation),
        "degraded": bool(degradations),
        "reports": {"pentest_bytes": len(pentest_md), "incident_bytes": len(incident_md)},
    }
