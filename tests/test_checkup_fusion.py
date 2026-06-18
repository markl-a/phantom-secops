"""End-to-end test: the fused, ranked action list is surfaced through the REAL
checkup entry point (lab/_checkup.py), not just fuse_posture() in isolation.

checkup.ps1 runs ``python lab/_checkup.py <path>`` and captures its stdout; this
test loads that exact module, mocks the three scanners to return canned findings
(hermetic — no docker/network/Trivy/event-log), calls its main() and asserts the
printed ``== PRIORITISED ACTIONS ==`` block (1) spans all three tools, (2) is
ordered highest-risk-first across tools and (3) is deterministic on re-run.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_CHECKUP_PATH = Path(__file__).resolve().parent.parent / "lab" / "_checkup.py"


def _load_checkup():
    spec = importlib.util.spec_from_file_location("secops_checkup", _CHECKUP_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Canned findings in the exact shapes the three scanners return. host has a high
# FAIL, a medium WARN and a high-severity PASS (the PASS must not become an
# action). vuln has a CRITICAL + a LOW; ids has a critical + a low alert.
HOST = {
    "elevation": {"elevated": True},
    "summary": {"pass": 1, "warn": 1, "fail": 1, "unknown": 0, "skipped": 0, "total": 3},
    "checks": [
        {"check": "firewall_profiles", "status": "fail", "severity": "high", "detail": "all profiles off"},
        {"check": "listening_ports", "status": "warn", "severity": "medium", "detail": "port 22 open"},
        {"check": "uac_enabled", "status": "pass", "severity": "high", "detail": "UAC is on"},
    ],
}
VULN = {
    "summary": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 1, "UNKNOWN": 0, "total": 2, "fixable": 1},
    "findings": [
        {"id": "CVE-2024-0001", "pkg": "openssl", "installed": "1.0", "fixed": "1.1",
         "severity": "CRITICAL", "title": "rce"},
        {"id": "CVE-2024-0002", "pkg": "zlib", "installed": "1.2", "fixed": "",
         "severity": "LOW", "title": "minor"},
    ],
}
IDS = {
    "events_read": 42,
    "summary": {"critical": 1, "high": 0, "medium": 0, "low": 1, "informational": 0, "total": 2},
    "alerts": [
        {"title": "Brute force login", "level": "critical", "event": {"Message": "many failures"}},
        {"title": "Port scan", "level": "low", "event": {"Message": "sequential probes"}},
    ],
}


def _run_checkup_capture(capsys) -> str:
    """Run the real entry point with mocked scanners; return its full stdout."""
    mod = _load_checkup()
    mod.audit_host = lambda *a, **k: HOST
    mod.scan_vulns = lambda *a, **k: VULN
    mod.scan_intrusions = lambda *a, **k: IDS
    mod.main(".")
    return capsys.readouterr().out


def _action_lines(out: str) -> list[str]:
    """Extract the numbered lines of the == PRIORITISED ACTIONS == block."""
    assert "== PRIORITISED ACTIONS ==" in out, "fused action list not emitted by checkup"
    section = out.split("== PRIORITISED ACTIONS ==", 1)[1]
    return [ln for ln in section.splitlines() if ln.strip()[:1].isdigit() and "." in ln]


def test_checkup_emits_fused_list_spanning_all_three_tools(capsys):
    lines = _action_lines(_run_checkup_capture(capsys))
    blob = "\n".join(lines)
    assert "host_audit" in blob and "vuln_scan" in blob and "ids_scan" in blob
    # the passing host check never appears as an action
    assert "uac_enabled" not in blob


def test_checkup_orders_highest_risk_first_across_tools(capsys):
    lines = _action_lines(_run_checkup_capture(capsys))

    def idx(token: str) -> int:
        for n, ln in enumerate(lines):
            if token in ln:
                return n
        raise AssertionError(f"{token!r} not found in fused action list")

    high = [idx("CVE-2024-0001"), idx("Brute force login"), idx("firewall_profiles")]
    low = [idx("CVE-2024-0002"), idx("Port scan")]
    assert max(high) < min(low), f"high-risk items did not rank first: {lines}"
    # the very first two ranked items are the two critical (sev-4) findings
    assert "critical" in lines[0] and "critical" in lines[1]


def test_checkup_fused_list_is_deterministic(capsys):
    first = _action_lines(_run_checkup_capture(capsys))
    second = _action_lines(_run_checkup_capture(capsys))
    assert first == second and len(first) == 6
