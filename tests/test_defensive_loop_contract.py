from __future__ import annotations

import json
from pathlib import Path

from phantom_secops.defensive_loop import PUBLIC_ARTIFACTS, write_defensive_demo_loop


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_defensive_loop_writes_manifest_findings_timeline_and_analysis(tmp_path: Path):
    bundle = write_defensive_demo_loop(tmp_path / "bundle")

    assert bundle.out_dir == tmp_path / "bundle"
    for name in PUBLIC_ARTIFACTS:
        assert (bundle.out_dir / name).exists(), name

    manifest = _read_json(bundle.out_dir / "manifest.json")
    assert manifest["schema_version"] == 1
    assert manifest["mode"] == "hermetic_defensive_workbench_loop"
    assert manifest["synthetic_only"] is True
    assert manifest["active_scanning"] is False
    assert manifest["external_network"] is False
    assert manifest["exploit_poc"] is False
    assert manifest["writes_to_host"] is False
    assert manifest["artifacts"] == PUBLIC_ARTIFACTS

    findings = _read_jsonl(bundle.out_dir / "findings.jsonl")
    assert len(findings) == 3
    assert {finding["id"] for finding in findings} == {"F-001", "F-002", "F-003"}
    assert all(finding["schema_version"] == 1 for finding in findings)
    assert all(finding["read_only"] is True for finding in findings)
    assert all(finding["active_scan"] is False for finding in findings)
    assert all(finding["has_runnable_poc"] is False for finding in findings)
    assert all(finding["evidence"]["source"] == "synthetic_fixture" for finding in findings)

    timeline = _read_json(bundle.out_dir / "timeline.json")
    assert timeline["schema_version"] == 1
    assert timeline["events"][0]["phase"] == "checkup"
    assert timeline["events"][1]["phase"] == "verify"
    assert timeline["events"][2]["phase"] == "analyze"
    assert timeline["events"][2]["finding_ids"] == ["F-001", "F-002", "F-003"]

    analysis = _read_json(bundle.out_dir / "analysis.json")
    assert analysis["schema_version"] == 1
    assert analysis["verdict"] == "defensive_actions_ready"
    assert analysis["finding_count"] == 3
    assert analysis["top_actions"][0]["finding_id"] == "F-001"

    verification = _read_json(bundle.out_dir / "verification.json")
    assert verification["schema_version"] == 1
    assert verification["ok"] is True
    assert verification["checks"]["no_active_scanning"] is True
    assert verification["checks"]["no_runnable_poc"] is True
    assert verification["checks"]["timeline_references_known_findings"] is True


def test_defensive_loop_public_artifacts_do_not_contain_active_scan_payloads(tmp_path: Path):
    bundle = write_defensive_demo_loop(tmp_path / "bundle")
    forbidden = ["curl ", "nmap ", "nuclei ", "msfconsole", "nc -e", "powershell -enc"]

    for name in PUBLIC_ARTIFACTS:
        text = (bundle.out_dir / name).read_text(encoding="utf-8").lower()
        for marker in forbidden:
            assert marker not in text, f"{marker!r} appears in {name}"


def test_defensive_loop_public_artifacts_are_deterministic(tmp_path: Path):
    first = write_defensive_demo_loop(tmp_path / "first")
    second = write_defensive_demo_loop(tmp_path / "second")

    for name in PUBLIC_ARTIFACTS:
        assert (first.out_dir / name).read_text(encoding="utf-8") == (
            second.out_dir / name
        ).read_text(encoding="utf-8"), name
