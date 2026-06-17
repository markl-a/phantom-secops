"""Tests for the kill-chain orchestrator's pipeline internals.

The MTTD timing model is covered by test_kill_chain_timing and the live nuclei
wiring by test_kill_chain_vuln. This file covers the previously-untested logic:
the blue triage/correlate stages, the exploit-suggester prose, recon dispatch,
and report composition. All hermetic — no docker, no network, no real scanning.
"""

from __future__ import annotations

import json

from scenarios import run_kill_chain as rk


# ── blue: alert triage (grouping + priority promotion) ─────────────────────────

def _alert(ip, category, sev, evidence="x"):
    return {
        "ts": "2026-06-17T00:00:00+00:00",
        "source_ip": ip,
        "asset": "juice-shop",
        "category": category,
        "evidence": evidence,
        "severity_hint": sev,
    }


def test_triage_groups_by_ip_and_category():
    alerts = [
        _alert("10.0.0.1", "sqli", "high"),
        _alert("10.0.0.1", "sqli", "high"),
        _alert("10.0.0.2", "scanner", "low"),
    ]
    triaged = rk._blue_alert_triage(alerts)
    keys = {(t["summary"], t["count"]) for t in triaged}
    # two distinct groups: the two sqli from .1 collapse into one count=2 group
    assert ("sqli pattern from 10.0.0.1", 2) in keys
    assert ("scanner pattern from 10.0.0.2", 1) in keys


def test_triage_promotes_high_severity_to_p1_when_repeated():
    alerts = [_alert("10.0.0.1", "sqli", "high"), _alert("10.0.0.1", "sqli", "high")]
    triaged = rk._blue_alert_triage(alerts)
    assert triaged[0]["priority"] == "P1"  # >=2 high-severity hits


def test_triage_single_high_severity_is_p2():
    triaged = rk._blue_alert_triage([_alert("10.0.0.1", "traversal", "high")])
    assert triaged[0]["priority"] == "P2"


def test_triage_medium_severity_is_p2():
    triaged = rk._blue_alert_triage([_alert("10.0.0.1", "xss", "medium")])
    assert triaged[0]["priority"] == "P2"


def test_triage_low_severity_scanner_stays_p3():
    triaged = rk._blue_alert_triage([_alert("10.0.0.2", "scanner", "low")])
    assert triaged[0]["priority"] == "P3"


def test_triage_caps_evidence_at_three():
    alerts = [_alert("10.0.0.1", "sqli", "high", evidence=f"e{i}") for i in range(5)]
    triaged = rk._blue_alert_triage(alerts)
    assert triaged[0]["count"] == 5
    assert len(triaged[0]["evidence"]) == 3  # evidence list is bounded


# ── blue: threat correlation (actor grouping + ATT&CK phases) ──────────────────

def test_correlate_groups_actor_and_infers_phases():
    triaged = [
        {"ts": "t", "summary": "scanner pattern from 10.0.0.9"},
        {"ts": "t", "summary": "sqli pattern from 10.0.0.9"},
        {"ts": "t", "summary": "admin_path pattern from 10.0.0.9"},
    ]
    out = rk._blue_threat_correlate(triaged)
    assert len(out) == 1
    actor = out[0]
    assert actor["actor"] == "10.0.0.9"
    assert "TA0043" in actor["phases_observed"]  # recon (scanner)
    assert "TA0001" in actor["phases_observed"]  # initial access (sqli)
    assert "TA0007" in actor["phases_observed"]  # discovery (admin_path)
    assert "enumeration" in actor["narrative"]
    assert "injection" in actor["narrative"]


def test_correlate_separates_distinct_actors():
    triaged = [
        {"ts": "t", "summary": "sqli pattern from 10.0.0.1"},
        {"ts": "t", "summary": "scanner pattern from 10.0.0.2"},
    ]
    out = rk._blue_threat_correlate(triaged)
    assert {a["actor"] for a in out} == {"10.0.0.1", "10.0.0.2"}


def test_correlate_unknown_actor_when_no_ip():
    out = rk._blue_threat_correlate([{"ts": "t", "summary": "weird summary no marker"}])
    assert out[0]["actor"] == "unknown"
    assert out[0]["narrative"]  # always a non-empty narrative string


def test_correlate_empty_input():
    assert rk._blue_threat_correlate([]) == []


# ── red: exploit suggester (prose only, never a runnable payload) ──────────────

def test_exploit_suggest_empty_findings():
    out = rk._run_exploit_suggest({"findings": []}, mock=True, use_llm=False)
    assert "No vulnerabilities" in out


def test_exploit_suggest_renders_each_finding():
    vuln = {"findings": [
        {"id": "tpl-1", "title": "jQuery XSS", "cve": "CVE-2020-11023", "severity": "medium"},
        {"id": "tpl-2", "title": "Admin panel exposed", "severity": "high"},
    ]}
    out = rk._run_exploit_suggest(vuln, mock=True, use_llm=False)
    assert "tpl-1" in out and "tpl-2" in out
    assert "CVE-2020-11023" in out


def test_exploit_prose_never_emits_runnable_payload():
    # The whole ethics contract: prose only, no POC/payload markers.
    for f in (
        {"title": "jQuery XSS", "cve": "CVE-2020-11023", "severity": "medium"},
        {"title": "Admin interface", "severity": "high"},
        {"title": "Something low", "severity": "low"},
        {"title": "Generic", "severity": "high"},
    ):
        prose = rk._exploit_prose(f)
        assert "Mitigation" in prose or "No POC" in prose or "false-positive" in prose
        # No shell, no curl, no obvious payload scaffolding.
        lowered = prose.lower()
        for marker in ("curl ", "<script>", "; rm ", "powershell -enc"):
            assert marker not in lowered


def test_exploit_prose_jquery_mitigation():
    prose = rk._exploit_prose({"title": "jQuery thing", "cve": "CVE-2020-11023"})
    assert "upgrade jQuery" in prose


def test_exploit_prose_low_severity_marked_likely_fp():
    assert "false-positive" in rk._exploit_prose({"title": "x", "severity": "low"}).lower()


# ── red: recon dispatch (mock reads fixture, no docker) ────────────────────────

def test_run_recon_mock_reads_fixture():
    recon = rk._run_recon("juice-shop", mock=True)
    assert "open_ports" in recon
    assert isinstance(recon["open_ports"], list)


# ── report composition (deterministic markdown) ────────────────────────────────

def test_compose_pentest_report_has_sections_and_counts():
    recon = {"open_ports": [{"port": 3000, "service": "http", "version": "Express"}]}
    vuln = {"target": "juice-shop", "findings": [
        {"id": "a", "title": "t", "severity": "high"},
        {"id": "b", "title": "t", "severity": "low"},
    ]}
    timeline = [(0.0, "red", "start"), (50.0, "sys", "done")]
    md = rk._compose_pentest_report(recon, vuln, "_suggestions_", timeline, mock=True)
    assert "# Pentest Report" in md
    assert "## Recon" in md
    assert "| High | 1 |" in md
    assert "| Low | 1 |" in md
    assert "simulated" in md  # mock timing note present


def test_compose_incident_report_counts_priorities():
    triaged = [
        {"priority": "P1", "asset": "a", "summary": "s", "count": 2},
        {"priority": "P2", "asset": "a", "summary": "s", "count": 1},
    ]
    correlation = [{"actor": "10.0.0.1", "phases_observed": ["TA0001"],
                    "confidence": "high", "narrative": "n"}]
    tl = [(0.0, "red", "red-recon  starts"),
          (15.0, "blue", "blue-alert-triage  → 2 triaged groups"),
          (50.0, "red", "red-exploit-suggest  done")]
    md = rk._compose_incident_report(triaged, correlation, tl, mock=True)
    assert "1 actor(s)" in md
    assert "1 P1, 1 P2, 0 P3" in md
    assert "MTTD = 15s" in md


def test_render_ports_empty():
    assert rk._render_ports({"open_ports": []}) == "_(none)_"


def test_render_actors_empty():
    assert rk._render_actors([]) == "_(none observed)_"


# ── end-to-end mock pipeline writes valid artifacts ────────────────────────────

def test_full_mock_pipeline_writes_parseable_artifacts(tmp_path):
    import argparse
    args = argparse.Namespace(target="juice-shop", mock=True, use_llm=False, out=None)
    timeline, pentest, incident = rk._run_pipeline(args, tmp_path)
    assert pentest and incident
    # recon.json / vuln-scan.json must be valid JSON
    json.loads((tmp_path / "recon.json").read_text(encoding="utf-8"))
    json.loads((tmp_path / "vuln-scan.json").read_text(encoding="utf-8"))
    # alerts.jsonl must be line-delimited JSON
    for line in (tmp_path / "alerts.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            json.loads(line)
