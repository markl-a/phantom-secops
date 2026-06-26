from __future__ import annotations

import json
from pathlib import Path

from phantom_secops import reasoning_scenario
from phantom_secops.evidence_playbook import FORBIDDEN_MARKERS


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_reasoning_scenario_writes_read_only_bundle(tmp_path: Path, capsys) -> None:
    out = tmp_path / "scenario"

    assert reasoning_scenario.main(["--out", str(out)]) == 0
    manifest_path = Path(capsys.readouterr().out.strip())
    assert manifest_path == out / "manifest.json"

    manifest = _read_json(manifest_path)
    reasoning = _read_json(out / "reasoning-report.json")
    hypotheses = _read_json(out / "kill-chain-hypotheses.json")
    playbook = _read_json(out / "playbook-review.json")
    audit = _read_json(out / "audit-summary.json")
    summary = (out / "summary.md").read_text(encoding="utf-8")

    assert manifest["schema_version"] == 1
    assert manifest["mode"] == "hermetic_read_only_reasoning_scenario"
    assert manifest["synthetic_only"] is True
    assert manifest["active_scanning"] is False
    assert manifest["external_network"] is False
    assert manifest["exploit_poc"] is False
    assert manifest["writes_to_host"] is False
    assert manifest["read_only"] is True
    assert manifest["actions_executed"] is False
    assert manifest["source_bundles"] == {
        "defensive_loop": "defensive-loop/manifest.json",
        "evidence_playbook": "evidence-playbook/manifest.json",
    }
    assert manifest["artifacts"] == {
        "audit_summary": "audit-summary.json",
        "hypotheses": "kill-chain-hypotheses.json",
        "playbook_review": "playbook-review.json",
        "reasoning_report": "reasoning-report.json",
        "summary": "summary.md",
    }

    assert (out / "defensive-loop" / "manifest.json").exists()
    assert (out / "evidence-playbook" / "manifest.json").exists()

    assert reasoning["mode"] == "read_only_kill_chain_reasoning"
    assert reasoning["finding_count"] == 3
    assert reasoning["evidence_count"] == 3
    assert reasoning["hypothesis_count"] == 2
    assert reasoning["readiness"] == {
        "evidence_linked": True,
        "hypotheses_ranked": True,
        "playbook_reviewed": True,
        "metadata_audit_ready": True,
        "read_only": True,
        "no_executed_actions": True,
    }
    assert reasoning["boundaries"]["active_response"] == "not_enabled"
    assert reasoning["boundaries"]["external_scanning"] == "not_enabled"
    assert reasoning["boundaries"]["exploit_generation"] == "not_supported"

    assert hypotheses["mode"] == "synthetic_kill_chain_hypotheses"
    assert [item["hypothesis_id"] for item in hypotheses["hypotheses"]] == [
        "H-001",
        "H-002",
    ]
    assert all(item["read_only"] is True for item in hypotheses["hypotheses"])
    assert all(item["actionable_as_advice_only"] is True for item in hypotheses["hypotheses"])

    assert playbook["mode"] == "read_only_playbook_review"
    assert playbook["actions_executed"] == []
    assert playbook["operator_action_required_count"] == 3
    assert playbook["writes_to_host"] is False
    assert playbook["external_network"] is False

    assert audit["mode"] == "metadata_only_reasoning_audit"
    assert audit["event_count"] == 5
    assert audit["raw_log_retained"] is False
    assert audit["host_data_retained"] is False
    assert audit["payload_retained"] is False
    assert audit["command_text_retained"] is False
    assert "Read-only reasoning scenario" in summary


def test_reasoning_scenario_is_deterministic_and_has_no_active_content(
    tmp_path: Path,
    capsys,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"

    assert reasoning_scenario.main(["--out", str(first)]) == 0
    capsys.readouterr()
    assert reasoning_scenario.main(["--out", str(second)]) == 0
    capsys.readouterr()

    files = (
        "manifest.json",
        "reasoning-report.json",
        "kill-chain-hypotheses.json",
        "playbook-review.json",
        "audit-summary.json",
        "summary.md",
        "defensive-loop/analysis.json",
        "evidence-playbook/playbook-simulation.json",
    )
    for rel in files:
        assert (first / rel).read_text(encoding="utf-8") == (second / rel).read_text(
            encoding="utf-8"
        )

    exported_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in first.rglob("*")
        if path.is_file()
    ).lower()
    forbidden = (*FORBIDDEN_MARKERS, "payload command", "reverse shell", "auto-remediate")
    assert all(term.lower() not in exported_text for term in forbidden)
