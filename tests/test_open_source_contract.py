from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_readme_documents_defensive_loop_and_safe_defaults():
    text = _read("README.md")

    assert "phantom_secops.defensive_loop" in text
    assert "phantom_secops.evidence_playbook" in text
    assert "phantom_secops.reasoning_scenario" in text
    assert "findings.jsonl" in text
    assert "evidence-pack.json" in text
    assert "playbook-simulation.json" in text
    assert "reasoning-report.json" in text
    assert "kill-chain-hypotheses.json" in text
    assert "docs/REASONING_SCENARIO.md" in text
    assert "timeline.json" in text
    assert "no active scanning" in text.lower()
    assert "No runnable PoC" in text


def test_public_demo_documents_p2_finding_timeline_contract():
    text = _read("docs/PUBLIC_DEMO.md")

    assert "Hermetic Defensive Workbench Loop" in text
    assert "findings.jsonl" in text
    assert "timeline.json" in text
    assert "analysis.json" in text
    assert "verification.json" in text
    assert "Hermetic Evidence Pack And Playbook Simulation" in text
    assert "evidence-pack.json" in text
    assert "playbook-simulation.json" in text
    assert "decision-log.jsonl" in text
    assert "reasoning-report.json" in text
    assert "kill-chain-hypotheses.json" in text
    assert "playbook-review.json" in text
    assert "audit-summary.json" in text
    assert "active_scanning=false" in text
    assert "exploit_poc=false" in text
    assert "actions_executed=false" in text


def test_readiness_records_p3_reasoning_scenario_evidence():
    text = _read("docs/OPEN_SOURCE_READINESS.md")

    assert "P3 hermetic read-only reasoning scenario verified" in text
    assert "python -m phantom_secops.defensive_loop --out <temp>" in text
    assert "python -m phantom_secops.evidence_playbook --out <temp>" in text
    assert "python -m phantom_secops.reasoning_scenario --out <temp>" in text
    assert "finding/timeline schema" in text
    assert "evidence pack/playbook" in text


def test_reasoning_scenario_doc_documents_read_only_boundary():
    text = _read("docs/REASONING_SCENARIO.md")

    assert "hermetic_read_only_reasoning_scenario" in text
    assert "reasoning-report.json" in text
    assert "kill-chain-hypotheses.json" in text
    assert "playbook-review.json" in text
    assert "audit-summary.json" in text
    assert "active_scanning" in text
    assert "external_network" in text
    assert "exploit_poc" in text
    assert "writes_to_host" in text
    assert "actions_executed" in text
