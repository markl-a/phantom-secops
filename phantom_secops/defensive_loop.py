"""Deterministic defensive workbench artifact loop for public OSS demos."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PUBLIC_ARTIFACTS = [
    "manifest.json",
    "findings.jsonl",
    "timeline.json",
    "analysis.json",
    "verification.json",
    "summary.md",
]

_FINDINGS = [
    {
        "schema_version": 1,
        "id": "F-001",
        "category": "vulnerability",
        "severity": "critical",
        "title": "Synthetic fixable dependency CVE",
        "description": "A synthetic package finding demonstrates fix-first prioritisation.",
        "evidence": {
            "source": "synthetic_fixture",
            "artifact": "mock-vuln-scan",
            "locator": "pkg=openssl installed=1.0 fixed=1.1",
        },
        "recommended_action": "Upgrade the synthetic package to the fixed version.",
        "read_only": True,
        "active_scan": False,
        "has_runnable_poc": False,
    },
    {
        "schema_version": 1,
        "id": "F-002",
        "category": "intrusion_detection",
        "severity": "critical",
        "title": "Synthetic brute-force login pattern",
        "description": "A synthetic IDS alert demonstrates alert triage without reading host logs.",
        "evidence": {
            "source": "synthetic_fixture",
            "artifact": "mock-ids-alert",
            "locator": "event_family=auth-failures",
        },
        "recommended_action": "Review synthetic account lockout and MFA posture.",
        "read_only": True,
        "active_scan": False,
        "has_runnable_poc": False,
    },
    {
        "schema_version": 1,
        "id": "F-003",
        "category": "host_posture",
        "severity": "high",
        "title": "Synthetic firewall posture gap",
        "description": "A synthetic host posture item demonstrates hardening guidance.",
        "evidence": {
            "source": "synthetic_fixture",
            "artifact": "mock-host-audit",
            "locator": "firewall_profiles=off",
        },
        "recommended_action": "Enable host firewall profiles in the synthetic checklist.",
        "read_only": True,
        "active_scan": False,
        "has_runnable_poc": False,
    },
]

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class DefensiveDemoBundle:
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


def _timeline(findings: list[dict[str, Any]]) -> dict[str, Any]:
    ids = [finding["id"] for finding in findings]
    return {
        "schema_version": 1,
        "clock": "synthetic_relative_seconds",
        "events": [
            {
                "t": 0.0,
                "phase": "checkup",
                "actor": "defensive-loop",
                "event": "load synthetic host/vuln/ids posture fixture",
                "finding_ids": ids,
            },
            {
                "t": 1.0,
                "phase": "verify",
                "actor": "defensive-loop",
                "event": "validate finding schema and no-active-scan invariants",
                "finding_ids": ids,
            },
            {
                "t": 2.0,
                "phase": "analyze",
                "actor": "defensive-loop",
                "event": "rank defensive actions and write public artifact bundle",
                "finding_ids": ids,
            },
        ],
    }


def _analysis(findings: list[dict[str, Any]]) -> dict[str, Any]:
    ranked = sorted(
        findings,
        key=lambda finding: (-_SEVERITY_ORDER[finding["severity"]], finding["id"]),
    )
    return {
        "schema_version": 1,
        "verdict": "defensive_actions_ready",
        "finding_count": len(findings),
        "severity_counts": {
            severity: sum(1 for finding in findings if finding["severity"] == severity)
            for severity in ("critical", "high", "medium", "low", "info")
        },
        "top_actions": [
            {
                "finding_id": finding["id"],
                "severity": finding["severity"],
                "action": finding["recommended_action"],
            }
            for finding in ranked
        ],
        "no_active_scanning": True,
        "no_runnable_poc": True,
    }


def _verification(
    findings: list[dict[str, Any]],
    timeline: dict[str, Any],
    analysis: dict[str, Any],
) -> dict[str, Any]:
    known_ids = {finding["id"] for finding in findings}
    referenced_ids = {
        finding_id
        for event in timeline["events"]
        for finding_id in event.get("finding_ids", [])
    }
    checks = {
        "finding_schema_version": all(finding.get("schema_version") == 1 for finding in findings),
        "finding_ids_unique": len(known_ids) == len(findings),
        "timeline_schema_version": timeline.get("schema_version") == 1,
        "timeline_references_known_findings": referenced_ids <= known_ids and bool(referenced_ids),
        "analysis_schema_version": analysis.get("schema_version") == 1,
        "no_active_scanning": all(finding.get("active_scan") is False for finding in findings),
        "no_runnable_poc": all(finding.get("has_runnable_poc") is False for finding in findings),
        "read_only": all(finding.get("read_only") is True for finding in findings),
    }
    return {
        "schema_version": 1,
        "ok": all(checks.values()),
        "checks": checks,
    }


def write_defensive_demo_loop(out_dir: str | Path) -> DefensiveDemoBundle:
    """Write a hermetic defensive checkup/verify/analyze artifact bundle."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    findings = [dict(finding) for finding in _FINDINGS]
    timeline = _timeline(findings)
    analysis = _analysis(findings)
    verification = _verification(findings, timeline, analysis)
    manifest = {
        "schema_version": 1,
        "mode": "hermetic_defensive_workbench_loop",
        "synthetic_only": True,
        "active_scanning": False,
        "external_network": False,
        "exploit_poc": False,
        "writes_to_host": False,
        "read_only": True,
        "artifacts": PUBLIC_ARTIFACTS,
    }

    _dump_json(out_path / "manifest.json", manifest)
    _write_jsonl(out_path / "findings.jsonl", findings)
    _dump_json(out_path / "timeline.json", timeline)
    _dump_json(out_path / "analysis.json", analysis)
    _dump_json(out_path / "verification.json", verification)
    (out_path / "summary.md").write_text(
        "\n".join(
            [
                "# Hermetic Defensive Workbench Demo",
                "",
                "This bundle uses synthetic findings only. It performs no active scanning,",
                "does not contact external systems, writes no host changes, and contains no runnable PoC.",
                "",
                f"- Findings: {len(findings)}",
                f"- Verdict: {analysis['verdict']}",
                f"- Verification OK: {verification['ok']}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return DefensiveDemoBundle(out_dir=out_path, artifacts=list(PUBLIC_ARTIFACTS))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phantom-secops-defensive-loop")
    parser.add_argument("--out", required=True, help="directory to write the defensive demo bundle")
    args = parser.parse_args(argv)

    try:
        bundle = write_defensive_demo_loop(args.out)
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
