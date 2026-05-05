"""Tests for the blue-team pipeline functions in phantom_secops.core.

These tests cover the pattern matchers without needing a live lab.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from phantom_secops import core  # type: ignore[import-not-found]


def test_log_anomaly_emits_alerts_from_canned_log() -> None:
    result = core.scan_logs_for_anomalies(source="mock")
    alerts = result["alerts"]
    assert len(alerts) > 5, "canned log should produce multiple alerts"
    categories = {a["category"] for a in alerts}
    # The canned log includes scanner UA, traversal, sqli, xss, admin path probes
    assert "scanner" in categories
    assert "traversal" in categories
    assert "sqli" in categories
    assert "xss" in categories
    assert "admin_path" in categories


def test_triage_promotes_high_severity_to_p1_after_count() -> None:
    alerts = [
        {"ts": "t", "source_ip": "1.1.1.1", "asset": "x", "category": "sqli",
         "evidence": "...", "severity_hint": "high"},
        {"ts": "t", "source_ip": "1.1.1.1", "asset": "x", "category": "sqli",
         "evidence": "...", "severity_hint": "high"},
    ]
    triaged = core.triage_alerts(alerts)["triaged"]
    assert len(triaged) == 1
    assert triaged[0]["priority"] == "P1"
    assert triaged[0]["count"] == 2


def test_triage_does_not_promote_lone_low_severity() -> None:
    alerts = [
        {"ts": "t", "source_ip": "1.1.1.1", "asset": "x", "category": "scanner",
         "evidence": "...", "severity_hint": "low"},
    ]
    triaged = core.triage_alerts(alerts)["triaged"]
    assert len(triaged) == 1
    assert triaged[0]["priority"] == "P3"


def test_threat_correlate_groups_by_actor() -> None:
    triaged = [
        {"ts": "t", "priority": "P3", "asset": "x",
         "summary": "scanner pattern from 9.9.9.9", "count": 5, "evidence": []},
        {"ts": "t", "priority": "P2", "asset": "x",
         "summary": "sqli pattern from 9.9.9.9", "count": 1, "evidence": []},
        {"ts": "t", "priority": "P3", "asset": "x",
         "summary": "scanner pattern from 8.8.8.8", "count": 2, "evidence": []},
    ]
    actors = core.correlate_threats(triaged)["actors"]
    actor_ips = {c["actor"] for c in actors}
    assert actor_ips == {"9.9.9.9", "8.8.8.8"}
    nine = next(c for c in actors if c["actor"] == "9.9.9.9")
    # 9.9.9.9 has both scanner (TA0043) and sqli (TA0001)
    assert "TA0043" in nine["phases_observed"]
    assert "TA0001" in nine["phases_observed"]
