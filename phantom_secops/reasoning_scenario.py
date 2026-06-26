"""Hermetic read-only kill-chain reasoning scenario for public OSS demos."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from phantom_secops.defensive_loop import write_defensive_demo_loop
from phantom_secops.evidence_playbook import write_evidence_playbook_bundle


SCHEMA_VERSION = 1

PUBLIC_ARTIFACTS = {
    "audit_summary": "audit-summary.json",
    "hypotheses": "kill-chain-hypotheses.json",
    "playbook_review": "playbook-review.json",
    "reasoning_report": "reasoning-report.json",
    "summary": "summary.md",
}


@dataclass(frozen=True)
class ReasoningScenarioBundle:
    out_dir: Path
    artifacts: dict[str, str]


def write_reasoning_scenario(out_dir: str | Path) -> ReasoningScenarioBundle:
    """Write a deterministic read-only reasoning scenario bundle."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    defensive = write_defensive_demo_loop(out_path / "defensive-loop")
    evidence = write_evidence_playbook_bundle(out_path / "evidence-playbook")

    findings = _read_jsonl(defensive.out_dir / "findings.jsonl")
    analysis = _load_json(defensive.out_dir / "analysis.json")
    evidence_pack = _load_json(evidence.out_dir / "evidence-pack.json")
    playbook = _load_json(evidence.out_dir / "playbook-simulation.json")

    hypotheses = _hypotheses(findings)
    playbook_review = _playbook_review(playbook)
    reasoning = _reasoning_report(findings, evidence_pack, hypotheses, playbook_review)
    audit = _audit_summary(reasoning)

    _dump_json(out_path / "reasoning-report.json", reasoning)
    _dump_json(out_path / "kill-chain-hypotheses.json", hypotheses)
    _dump_json(out_path / "playbook-review.json", playbook_review)
    _dump_json(out_path / "audit-summary.json", audit)
    (out_path / "summary.md").write_text(_summary_md(reasoning, analysis), encoding="utf-8")

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "mode": "hermetic_read_only_reasoning_scenario",
        "synthetic_only": True,
        "active_scanning": False,
        "external_network": False,
        "exploit_poc": False,
        "writes_to_host": False,
        "read_only": True,
        "actions_executed": False,
        "source_bundles": {
            "defensive_loop": "defensive-loop/manifest.json",
            "evidence_playbook": "evidence-playbook/manifest.json",
        },
        "artifacts": PUBLIC_ARTIFACTS,
    }
    _dump_json(out_path / "manifest.json", manifest)
    return ReasoningScenarioBundle(out_dir=out_path, artifacts=dict(PUBLIC_ARTIFACTS))


def _hypotheses(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {finding["id"]: finding for finding in findings}
    items = [
        {
            "schema_version": SCHEMA_VERSION,
            "hypothesis_id": "H-001",
            "title": "Synthetic exposure and hardening gap may increase defensive priority.",
            "supporting_findings": ["F-001", "F-003"],
            "severity": "critical",
            "confidence": "medium",
            "reasoning": (
                "The synthetic dependency finding and host posture gap should be "
                "handled before lower-priority advisory work."
            ),
            "read_only": True,
            "actionable_as_advice_only": True,
        },
        {
            "schema_version": SCHEMA_VERSION,
            "hypothesis_id": "H-002",
            "title": "Synthetic identity signal needs operator review.",
            "supporting_findings": ["F-002"],
            "severity": by_id.get("F-002", {}).get("severity", "critical"),
            "confidence": "medium",
            "reasoning": (
                "The synthetic brute-force pattern is evidence for review, not an "
                "instruction to take automated response."
            ),
            "read_only": True,
            "actionable_as_advice_only": True,
        },
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "synthetic_kill_chain_hypotheses",
        "hypotheses": items,
    }


def _playbook_review(playbook: dict[str, Any]) -> dict[str, Any]:
    steps = playbook.get("steps") or []
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "read_only_playbook_review",
        "step_count": len(steps),
        "operator_action_required_count": sum(
            1 for step in steps if step.get("operator_action_required") is True
        ),
        "decisions": [
            {
                "finding_id": step.get("finding_id", ""),
                "decision": step.get("decision", ""),
                "execution": step.get("execution", ""),
                "read_only": True,
            }
            for step in steps
        ],
        "actions_executed": [],
        "writes_to_host": False,
        "external_network": False,
        "active_scanning": False,
    }


def _reasoning_report(
    findings: list[dict[str, Any]],
    evidence_pack: dict[str, Any],
    hypotheses: dict[str, Any],
    playbook_review: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "read_only_kill_chain_reasoning",
        "finding_count": len(findings),
        "evidence_count": int(evidence_pack.get("evidence_count") or 0),
        "hypothesis_count": len(hypotheses["hypotheses"]),
        "readiness": {
            "evidence_linked": int(evidence_pack.get("evidence_count") or 0) == len(findings),
            "hypotheses_ranked": bool(hypotheses["hypotheses"]),
            "playbook_reviewed": playbook_review["step_count"] == len(findings),
            "metadata_audit_ready": True,
            "read_only": True,
            "no_executed_actions": playbook_review["actions_executed"] == [],
        },
        "boundaries": {
            "active_response": "not_enabled",
            "external_scanning": "not_enabled",
            "exploit_generation": "not_supported",
            "host_mutation": "not_supported",
        },
    }


def _audit_summary(reasoning: dict[str, Any]) -> dict[str, Any]:
    events = [
        "source_bundles_built",
        "findings_loaded",
        "hypotheses_ranked",
        "playbook_reviewed",
        "artifacts_written",
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "metadata_only_reasoning_audit",
        "event_count": len(events),
        "events": events,
        "finding_count": reasoning["finding_count"],
        "hypothesis_count": reasoning["hypothesis_count"],
        "raw_log_retained": False,
        "host_data_retained": False,
        "payload_retained": False,
        "command_text_retained": False,
        "actions_executed": False,
    }


def _summary_md(reasoning: dict[str, Any], analysis: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Read-only reasoning scenario",
            "",
            "This bundle ranks synthetic defensive hypotheses and reviews tabletop playbook decisions.",
            "It performs no active scanning, contacts no external systems, writes no host changes, and includes no runnable proof of concept.",
            "",
            f"- Findings: {reasoning['finding_count']}",
            f"- Hypotheses: {reasoning['hypothesis_count']}",
            f"- Source verdict: {analysis.get('verdict', '')}",
            "- Execution: advice only",
            "",
        ]
    )


def _load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError(f"{path.name} must contain a JSON object")
    return raw


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _dump_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phantom-secops-reasoning-scenario")
    parser.add_argument("--out", required=True, help="directory to write the scenario bundle")
    args = parser.parse_args(argv)

    try:
        bundle = write_reasoning_scenario(args.out)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(str(bundle.out_dir / "manifest.json") + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
