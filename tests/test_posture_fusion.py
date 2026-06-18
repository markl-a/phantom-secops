"""Tests for tools.posture_fusion — deterministic cross-tool ranking.

Feeds canned findings (the exact dict shapes the three scanners return) through
fuse_posture() and proves the normalisation, cross-tool ranking, host-status
filtering and determinism contracts. No LLM, no network.
"""

from __future__ import annotations

from tools.posture_fusion import Action, fuse_posture


# Canned findings in the exact shapes audit_host()/scan_vulns()/scan_intrusions()
# return. host has a high FAIL, a medium WARN, and a high-severity PASS that must
# be dropped (a passing check is not an action even though its severity is high).
HOST = {
    "checks": [
        {"check": "firewall_profiles", "status": "fail", "severity": "high", "detail": "all profiles off"},
        {"check": "listening_ports", "status": "warn", "severity": "medium", "detail": "port 22 open"},
        {"check": "uac_enabled", "status": "pass", "severity": "high", "detail": "UAC is on"},
    ],
    "summary": {"pass": 1, "warn": 1, "fail": 1, "unknown": 0, "skipped": 0, "total": 3},
}
VULN = {
    "findings": [
        {"id": "CVE-2024-0001", "pkg": "openssl", "installed": "1.0", "fixed": "1.1",
         "severity": "CRITICAL", "title": "rce"},
        {"id": "CVE-2024-0002", "pkg": "zlib", "installed": "1.2", "fixed": "",
         "severity": "LOW", "title": "minor"},
    ],
    "summary": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 1, "UNKNOWN": 0, "total": 2, "fixable": 1},
}
IDS = {
    "alerts": [
        {"title": "Brute force login", "level": "critical", "event": {"Message": "many failures"}},
        {"title": "Port scan", "level": "low", "event": {"Message": "sequential probes"}},
    ],
    "summary": {"critical": 1, "high": 0, "medium": 0, "low": 1, "informational": 0, "total": 2},
}


def test_fuse_spans_all_three_tools():
    actions = fuse_posture(HOST, VULN, IDS)
    assert {a.tool for a in actions} == {"host_audit", "vuln_scan", "ids_scan"}


def test_passing_host_check_is_excluded():
    actions = fuse_posture(HOST, VULN, IDS)
    assert all(a.id != "uac_enabled" for a in actions)
    # exactly the two actionable host checks survive
    host_ids = {a.id for a in actions if a.tool == "host_audit"}
    assert host_ids == {"firewall_profiles", "listening_ports"}


def test_highest_risk_first_across_tools():
    actions = fuse_posture(HOST, VULN, IDS)
    pos = {a.id: idx for idx, a in enumerate(actions)}
    # the three high-risk items (CRITICAL vuln, critical ids, high host fail)...
    high = [pos["CVE-2024-0001"], pos["Brute force login"], pos["firewall_profiles"]]
    # ...all rank before every low-severity item.
    low = [pos["CVE-2024-0002"], pos["Port scan"]]
    assert max(high) < min(low)
    # top two are the two severity-4 items (the CRITICAL vuln and critical ids alert)
    assert actions[0].severity == 4 and actions[1].severity == 4


def test_severity_is_normalised_onto_common_scale():
    actions = fuse_posture(HOST, VULN, IDS)
    by_id = {a.id: a for a in actions}
    assert by_id["CVE-2024-0001"].severity == 4 and by_id["CVE-2024-0001"].severity_name == "critical"
    assert by_id["Brute force login"].severity == 4
    assert by_id["firewall_profiles"].severity == 3 and by_id["firewall_profiles"].severity_name == "high"
    assert by_id["listening_ports"].severity == 2
    assert by_id["Port scan"].severity == 1 and by_id["CVE-2024-0002"].severity == 1


def test_deterministic_tiebreak_vuln_before_ids():
    # The two severity-4 items tie on severity; the tool tiebreak puts vuln_scan
    # (order 0) before ids_scan (order 1), every time.
    actions = fuse_posture(HOST, VULN, IDS)
    assert actions[0].tool == "vuln_scan" and actions[1].tool == "ids_scan"


def test_determinism_repeated_runs_identical():
    first = fuse_posture(HOST, VULN, IDS)
    second = fuse_posture(HOST, VULN, IDS)
    assert first == second
    assert all(isinstance(a, Action) for a in first)


def test_each_action_carries_source_tool_and_plain_language():
    for a in fuse_posture(HOST, VULN, IDS):
        assert a.tool in {"host_audit", "vuln_scan", "ids_scan"}
        assert a.action and isinstance(a.action, str)
