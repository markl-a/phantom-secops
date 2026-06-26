from __future__ import annotations

import json
from pathlib import Path

from phantom_secops.evidence_playbook import (
    FORBIDDEN_MARKERS,
    PUBLIC_ARTIFACTS,
    write_evidence_playbook_bundle,
)


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_evidence_playbook_bundle_writes_read_only_artifacts(tmp_path: Path):
    bundle = write_evidence_playbook_bundle(tmp_path / "bundle")

    assert bundle.out_dir == tmp_path / "bundle"
    for name in PUBLIC_ARTIFACTS:
        assert (bundle.out_dir / name).exists(), name

    manifest = _read_json(bundle.out_dir / "manifest.json")
    assert manifest["schema_version"] == 1
    assert manifest["mode"] == "hermetic_evidence_playbook"
    assert manifest["synthetic_only"] is True
    assert manifest["active_scanning"] is False
    assert manifest["external_network"] is False
    assert manifest["exploit_poc"] is False
    assert manifest["writes_to_host"] is False
    assert manifest["read_only"] is True
    assert manifest["artifacts"] == PUBLIC_ARTIFACTS

    evidence = _read_json(bundle.out_dir / "evidence-pack.json")
    assert evidence["schema_version"] == 1
    assert evidence["evidence_count"] == 3
    assert evidence["retention"] == "metadata_only"
    assert all(item["synthetic"] is True for item in evidence["items"])
    assert all(item["raw_log_retained"] is False for item in evidence["items"])
    assert {item["finding_id"] for item in evidence["items"]} == {"F-001", "F-002", "F-003"}

    playbook = _read_json(bundle.out_dir / "playbook-simulation.json")
    assert playbook["schema_version"] == 1
    assert playbook["mode"] == "tabletop_simulation"
    assert playbook["actions_executed"] == []
    assert playbook["writes_to_host"] is False
    assert playbook["external_network"] is False
    assert [step["decision"] for step in playbook["steps"]] == [
        "advise_patch",
        "advise_identity_review",
        "advise_firewall_review",
    ]
    assert all(step["execution"] == "not_executed" for step in playbook["steps"])

    verification = _read_json(bundle.out_dir / "verification.json")
    assert verification["ok"] is True
    assert verification["checks"]["metadata_only_evidence"] is True
    assert verification["checks"]["no_actions_executed"] is True
    assert verification["checks"]["no_active_scanning"] is True
    assert verification["checks"]["no_runnable_poc"] is True


def test_evidence_playbook_decision_log_is_metadata_only(tmp_path: Path):
    bundle = write_evidence_playbook_bundle(tmp_path / "bundle")

    decisions = _read_jsonl(bundle.out_dir / "decision-log.jsonl")

    assert [entry["decision"] for entry in decisions] == [
        "advise_patch",
        "advise_identity_review",
        "advise_firewall_review",
    ]
    assert all(entry["schema_version"] == 1 for entry in decisions)
    assert all(entry["raw_payload_retained"] is False for entry in decisions)
    assert all(entry["action_executed"] is False for entry in decisions)
    assert all("command" not in entry for entry in decisions)
    assert all("payload" not in entry for entry in decisions)


def test_evidence_playbook_public_artifacts_do_not_contain_active_content(
    tmp_path: Path,
):
    bundle = write_evidence_playbook_bundle(tmp_path / "bundle")

    for name in PUBLIC_ARTIFACTS:
        text = (bundle.out_dir / name).read_text(encoding="utf-8").lower()
        for marker in FORBIDDEN_MARKERS:
            assert marker not in text, f"{marker!r} appears in {name}"


def test_evidence_playbook_bundle_is_deterministic(tmp_path: Path):
    first = write_evidence_playbook_bundle(tmp_path / "first")
    second = write_evidence_playbook_bundle(tmp_path / "second")

    for name in PUBLIC_ARTIFACTS:
        assert (first.out_dir / name).read_text(encoding="utf-8") == (
            second.out_dir / name
        ).read_text(encoding="utf-8"), name
