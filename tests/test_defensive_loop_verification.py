from __future__ import annotations

from phantom_secops.defensive_loop import _analysis, _timeline, _verification


def _finding(
    finding_id: str,
    severity: str,
    *,
    schema_version: int = 1,
    read_only: bool = True,
    active_scan: bool = False,
    has_runnable_poc: bool = False,
) -> dict:
    return {
        "schema_version": schema_version,
        "id": finding_id,
        "category": "host_posture",
        "severity": severity,
        "title": f"title-{finding_id}",
        "description": f"description-{finding_id}",
        "evidence": {"source": "synthetic_fixture", "artifact": "fixture", "locator": "loc"},
        "recommended_action": f"action-{finding_id}",
        "read_only": read_only,
        "active_scan": active_scan,
        "has_runnable_poc": has_runnable_poc,
    }


def test_analysis_ranks_by_severity_then_id_tie_break():
    findings = [
        _finding("F-Z", "critical"),
        _finding("F-M", "high"),
        _finding("F-A", "critical"),
    ]

    analysis = _analysis(findings)

    assert [action["finding_id"] for action in analysis["top_actions"]] == [
        "F-A",
        "F-Z",
        "F-M",
    ]


def test_analysis_severity_counts():
    findings = [
        _finding("F-1", "critical"),
        _finding("F-2", "critical"),
        _finding("F-3", "high"),
    ]

    analysis = _analysis(findings)

    assert analysis["severity_counts"] == {
        "critical": 2,
        "high": 1,
        "medium": 0,
        "low": 0,
        "info": 0,
    }


def _verify(findings: list[dict]) -> dict:
    timeline = _timeline(findings)
    analysis = _analysis(findings)
    return _verification(findings, timeline, analysis)


def test_verification_ok_true_for_well_formed_findings():
    findings = [_finding("F-1", "critical"), _finding("F-2", "high")]

    verification = _verify(findings)

    assert verification["ok"] is True
    assert all(verification["checks"].values())


def test_verification_ok_false_on_duplicate_ids():
    findings = [_finding("F-1", "critical"), _finding("F-1", "high")]

    verification = _verify(findings)

    assert verification["checks"]["finding_ids_unique"] is False
    assert verification["ok"] is False


def test_verification_ok_false_on_active_scan():
    findings = [_finding("F-1", "critical", active_scan=True)]

    verification = _verify(findings)

    assert verification["checks"]["no_active_scanning"] is False
    assert verification["ok"] is False


def test_verification_ok_false_on_runnable_poc():
    findings = [_finding("F-1", "critical", has_runnable_poc=True)]

    verification = _verify(findings)

    assert verification["checks"]["no_runnable_poc"] is False
    assert verification["ok"] is False


def test_verification_ok_false_on_not_read_only():
    findings = [_finding("F-1", "critical", read_only=False)]

    verification = _verify(findings)

    assert verification["checks"]["read_only"] is False
    assert verification["ok"] is False


def test_verification_ok_false_on_wrong_schema_version():
    findings = [_finding("F-1", "critical", schema_version=2)]

    verification = _verify(findings)

    assert verification["checks"]["finding_schema_version"] is False
    assert verification["ok"] is False
