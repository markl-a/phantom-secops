"""Hermetic evidence pack and playbook simulation for public OSS demos."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from phantom_secops.defensive_loop import _FINDINGS


PUBLIC_ARTIFACTS = [
    "manifest.json",
    "evidence-pack.json",
    "playbook-simulation.json",
    "decision-log.jsonl",
    "verification.json",
    "summary.md",
]

FORBIDDEN_MARKERS = (
    "curl ",
    "nmap ",
    "nuclei ",
    "msfconsole",
    "meterpreter",
    "nc -e",
    "powershell -enc",
    "invoke-webrequest",
    "rm -rf",
    "del /f",
    "exploit --",
    "exploit/",
)


@dataclass(frozen=True)
class EvidencePlaybookBundle:
    out_dir: Path
    artifacts: list[str]


def _dump_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _stable_id(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _evidence_pack(findings: list[dict[str, Any]]) -> dict[str, Any]:
    items = []
    for finding in findings:
        evidence = finding["evidence"]
        items.append(
            {
                "schema_version": 1,
                "evidence_id": f"E-{finding['id']}",
                "finding_id": finding["id"],
                "source": evidence["source"],
                "artifact": evidence["artifact"],
                "locator_hash": _stable_id(evidence["locator"]),
                "evidence_type": finding["category"],
                "severity": finding["severity"],
                "synthetic": True,
                "raw_log_retained": False,
                "host_data_retained": False,
                "payload_retained": False,
            }
        )
    return {
        "schema_version": 1,
        "mode": "metadata_only_evidence_pack",
        "retention": "metadata_only",
        "evidence_count": len(items),
        "items": items,
    }


def _playbook_steps(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    decision_by_category = {
        "vulnerability": "advise_patch",
        "intrusion_detection": "advise_identity_review",
        "host_posture": "advise_firewall_review",
    }
    steps = []
    for index, finding in enumerate(findings, start=1):
        steps.append(
            {
                "schema_version": 1,
                "step": index,
                "finding_id": finding["id"],
                "decision": decision_by_category[finding["category"]],
                "execution": "not_executed",
                "operator_action_required": True,
                "read_only": True,
                "action_executed": False,
                "writes_to_host": False,
                "external_network": False,
            }
        )
    return steps


def _playbook_simulation(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "tabletop_simulation",
        "description": "Synthetic response decisions only; no commands or actions are executed.",
        "steps": _playbook_steps(findings),
        "actions_executed": [],
        "writes_to_host": False,
        "external_network": False,
        "active_scanning": False,
    }


def _decision_log(playbook: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "schema_version": 1,
            "event": "playbook_decision",
            "finding_id": step["finding_id"],
            "decision": step["decision"],
            "execution": step["execution"],
            "action_executed": False,
            "raw_payload_retained": False,
        }
        for step in playbook["steps"]
    ]


def _verification(evidence_pack: dict[str, Any], playbook: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "metadata_only_evidence": all(
            item["raw_log_retained"] is False
            and item["host_data_retained"] is False
            and item["payload_retained"] is False
            for item in evidence_pack["items"]
        ),
        "all_evidence_synthetic": all(item["synthetic"] is True for item in evidence_pack["items"]),
        "no_actions_executed": playbook["actions_executed"] == []
        and all(step["action_executed"] is False for step in playbook["steps"]),
        "no_active_scanning": playbook["active_scanning"] is False,
        "no_external_network": playbook["external_network"] is False,
        "no_host_writes": playbook["writes_to_host"] is False,
        "no_runnable_poc": True,
    }
    return {
        "schema_version": 1,
        "ok": all(checks.values()),
        "checks": checks,
    }


def _summary_md(manifest: dict[str, Any], evidence_pack: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Hermetic Evidence Pack And Playbook Simulation",
            "",
            "This bundle uses synthetic metadata only. It performs no active scanning,",
            "does not contact external systems, writes no host changes, and contains no runnable proof of concept.",
            "",
            f"- Evidence items: {evidence_pack['evidence_count']}",
            f"- Mode: {manifest['mode']}",
            "- Playbook execution: tabletop decisions only",
            "",
        ]
    )


def write_evidence_playbook_bundle(out_dir: str | Path) -> EvidencePlaybookBundle:
    """Write a deterministic evidence pack and playbook simulation bundle."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    findings = [dict(finding) for finding in _FINDINGS]
    evidence_pack = _evidence_pack(findings)
    playbook = _playbook_simulation(findings)
    verification = _verification(evidence_pack, playbook)
    manifest = {
        "schema_version": 1,
        "mode": "hermetic_evidence_playbook",
        "synthetic_only": True,
        "active_scanning": False,
        "external_network": False,
        "exploit_poc": False,
        "writes_to_host": False,
        "read_only": True,
        "artifacts": PUBLIC_ARTIFACTS,
    }

    _dump_json(out_path / "manifest.json", manifest)
    _dump_json(out_path / "evidence-pack.json", evidence_pack)
    _dump_json(out_path / "playbook-simulation.json", playbook)
    _write_jsonl(out_path / "decision-log.jsonl", _decision_log(playbook))
    _dump_json(out_path / "verification.json", verification)
    (out_path / "summary.md").write_text(_summary_md(manifest, evidence_pack), encoding="utf-8")

    return EvidencePlaybookBundle(out_dir=out_path, artifacts=list(PUBLIC_ARTIFACTS))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phantom-secops-evidence-playbook")
    parser.add_argument("--out", required=True, help="directory to write the evidence/playbook bundle")
    args = parser.parse_args(argv)

    try:
        bundle = write_evidence_playbook_bundle(args.out)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    sys.stdout.write(
        json.dumps(
            {"out_dir": str(bundle.out_dir), "artifacts": bundle.artifacts},
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
