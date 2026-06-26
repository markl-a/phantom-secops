"""Unit tests for the goal verification helpers."""

from __future__ import annotations

import importlib.util
import subprocess
import json
import sys
from pathlib import Path


def _load_verifier():
    path = Path(__file__).resolve().parent.parent / "scripts" / "goal_verification.py"
    spec = importlib.util.spec_from_file_location("goal_verification", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gv = _load_verifier()


def _load_goal_model_runner():
    path = Path(__file__).resolve().parent.parent / "scripts" / "run_goal_model_runner.py"
    spec = importlib.util.spec_from_file_location("run_goal_model_runner", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _seed_killchain_run(root: Path, *, include_governance: bool = False) -> None:
    root.mkdir(parents=True, exist_ok=True)
    summary = {
        "first_action": 0.0,
        "first_detect": 15.0,
        "time_to_impact": 50.0,
        "mttd": 15.0,
        "detect_margin": 35.0,
        "outcome": "defender",
        "timeline": [
            {"t": 0.0, "side": "red", "label": "red-recon starts"},
            {"t": 12.0, "side": "blue", "label": "blue-log"},
        ],
    }
    files = {
        "summary.json": summary,
        "recon.json": {"open_ports": [{"port": 443}]},
        "vuln-scan.json": {"findings": []},
        "alerts.jsonl": '{"x":1}\n',
        "triage-queue.jsonl": '{"x":"y"}\n',
        "kill-chains.jsonl": '{"x":"z"}\n',
        "exploit-suggestions.md": "This is prose only.\nUpgrade dependencies and restrict exposure.\n",
        "pentest-report.md": "# Pentest\n",
        "incident-report.md": "# Incident\n",
    }
    for name, content in files.items():
        p = root / name
        if name.endswith(".json"):
            p.write_text(json.dumps(content, indent=2), encoding="utf-8")
        else:
            p.write_text(content, encoding="utf-8")
    if include_governance:
        (root / "governance.jsonl").write_text(
            '{"tool":"recon","decision":"auto-allow"}\n',
            encoding="utf-8",
        )


def test_validate_kill_chain_artifacts_accepts_clean_input(tmp_path):
    run = tmp_path / "run"
    _seed_killchain_run(run)
    out = gv.validate_kill_chain_artifacts(run)
    assert out["ok"] is True
    assert out["summary"]["outcome"] == "defender"
    assert out["check"]["timeline_len"] == 2
    assert "signature" in out["check"]


def test_validate_kill_chain_artifacts_reports_missing_artifacts(tmp_path):
    run = tmp_path / "run"
    _seed_killchain_run(run)
    (run / "incident-report.md").unlink()
    out = gv.validate_kill_chain_artifacts(run)
    assert out["ok"] is False
    assert any("missing required artifact: incident-report.md" in e for e in out["errors"])


def test_validate_kill_chain_artifacts_accepts_governance_log_alias(tmp_path):
    run = tmp_path / "run"
    _seed_killchain_run(run, include_governance=True)
    (run / "governance.jsonl").rename(run / "governance.log")
    out = gv.validate_kill_chain_artifacts(run)
    assert out["ok"] is True
    assert out["check"]["governance_count"] == 1
    assert out["check"]["governance_path"].endswith("governance.log")


def test_validate_kill_chain_artifacts_flags_payload_text(tmp_path):
    run = tmp_path / "run"
    _seed_killchain_run(run)
    (run / "exploit-suggestions.md").write_text("Try: curl https://evil\n", encoding="utf-8")
    out = gv.validate_kill_chain_artifacts(run)
    assert out["ok"] is False
    assert any("payload-like" in e for e in out["errors"])


def test_parse_checkup_actions_is_stable():
    sample = """
== HOST POSTURE ==
== VULNERABILITIES ==
== INTRUSION DETECTION ==
== PRIORITISED ACTIONS ==
  1. [critical] vuln_scan CVE-2024-0001
  2. [high] host_audit firewall
  3. [medium] ids_scan brute-force
"""
    actions = gv.parse_checkup_prioritised_actions(sample)
    assert len(actions) == 3
    assert actions[0]["order"] == 1
    assert actions[0]["severity"] == "critical"


def test_validate_checkup_output_require_sections():
    sample_ok = """
== HOST POSTURE ==
== VULNERABILITIES ==
== INTRUSION DETECTION ==
== PRIORITISED ACTIONS ==
  1. [critical] vuln_scan CVE-2024-0001
"""
    out = gv.validate_checkup_output(sample_ok)
    assert out["ok"] is True
    assert out["check"]["action_count"] == 1

    sample_bad = "== HOST POSTURE ==\n== VULNERABILITIES ==\n"
    out2 = gv.validate_checkup_output(sample_bad)
    assert out2["ok"] is False
    assert any("missing section" in e for e in out2["errors"])


def test_compare_model_signatures_flags_differences():
    base = {
        "mttd": 15.0,
        "outcome": "defender",
        "detect_margin": 35.0,
        "time_to_impact": 50.0,
        "first_detect": 15.0,
        "first_action": 0.0,
        "timeline_len": 6,
    }
    other = dict(base)
    other["detect_margin"] = 20.0
    out = gv.compare_model_signatures({"codex": base, "claude": base, "hermes": other})
    assert out["ok"] is False
    assert any("hermes" in item["right"] for item in out["mismatches"])


def test_run_model_probe_defaults_to_dry_run_when_unset(tmp_path):
    out = tmp_path / "model"
    base = {"ok": True, "summary": {"mttd": 15}}
    res = gv.run_model_probe("codex", "killchain", out, target="juice-shop", checkup_path=".", baseline=base)
    assert res["status"] == "dry-run"
    assert res["result"] == base


def test_run_governed_smoke_emits_expected_decisions(tmp_path):
    out = tmp_path / "governance"
    result = gv.run_governed_smoke(out)
    assert result["ok"] is True
    assert "denied-role" in result.get("decision_values", [])
    assert "denied-approval" in result.get("decision_values", [])
    assert len(result.get("decisions", [])) >= 2
    assert result["governance_log"].endswith("governance.log")


def test_run_goal_model_runner_produces_killchain_artifacts(tmp_path):
    script = Path(__file__).resolve().parent.parent / "scripts" / "run_goal_model_runner.py"
    out = tmp_path / "model-out"
    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--model",
            "codex",
            "--scenario",
            "killchain",
            "--out_dir",
            str(out),
            "--target",
            "juice-shop",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert (out / "summary.json").exists()
    assert (out / "incident-report.md").exists()


def test_run_goal_model_runner_mesh_passes_provider(monkeypatch, tmp_path):
    run_goal_model_runner = _load_goal_model_runner()
    out = tmp_path / "model-out"

    captured = {}

    def fake_run(cmd, env=None):
        captured["cmd"] = cmd
        captured["env"] = env
        return 0, "", ""

    monkeypatch.setattr(run_goal_model_runner, "_run", fake_run)
    rc = run_goal_model_runner.main([
        "--model",
        "codex",
        "--scenario",
        "killchain",
        "--out_dir",
        str(out),
        "--target",
        "juice-shop",
        "--mesh",
        "--provider",
        "mesh-provider",
    ])
    assert rc == 0
    assert "--driver" in captured["cmd"]
    assert captured["cmd"][captured["cmd"].index("--driver") + 1] == "mesh"
    assert captured["env"]["PHANTOM_PROVIDER"] == "mesh-provider"
    assert captured["env"]["SECOPS_MCP_MOCK"] == "1"


def test_parse_args_accepts_mesh_and_provider():
    args = gv.parse_args(["--mesh", "--provider", "myprovider", "--models", "codex"])
    assert args.mesh is True
    assert args.provider == "myprovider"
    assert args.models == "codex"


def test_parse_args_accepts_require_parity():
    args = gv.parse_args(["--require-parity", "--require-governance"])
    assert args.require_parity is True
    assert args.require_governance is True


def test_main_returns_failure_when_strict_parity_required(monkeypatch, tmp_path):
    def fake(*args, **kwargs):
        return {
            "killchain": {"ok": True},
            "checkup": {"ok": True},
            "governance": {"ok": True},
            "model_compare": {
                "killchain": {"ok": False},
                "checkup": {"ok": True},
            },
        }

    monkeypatch.setattr(gv, "run_full_verification", fake)
    code = gv.main(["--out", str(tmp_path / "v"), "--require-parity"])
    assert code == 1


def test_main_returns_success_when_parity_not_required(monkeypatch, tmp_path):
    def fake(*args, **kwargs):
        return {
            "killchain": {"ok": True},
            "checkup": {"ok": True},
            "governance": {"ok": True},
            "model_compare": {
                "killchain": {"ok": False},
                "checkup": {"ok": True},
            },
        }

    monkeypatch.setattr(gv, "run_full_verification", fake)
    code = gv.main(["--out", str(tmp_path / "v")])
    assert code == 0


def test_run_kill_chain_mesh_sets_driver_and_provider(monkeypatch, tmp_path):
    captured = {}

    def fake(cmd, env=None):
        captured["cmd"] = cmd
        captured["env"] = env
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(gv, "_run_subprocess", fake)
    gv.run_kill_chain(tmp_path, target="juice-shop", driver="mesh", phantom_provider="provider-x")

    assert "--driver" in captured["cmd"]
    assert captured["cmd"][-2:] == ["--driver", "mesh"]
    assert captured["env"]["PHANTOM_PROVIDER"] == "provider-x"
    assert captured["env"]["SECOPS_MCP_MOCK"] == "1"


def test_run_full_verification_writes_audit_summary(monkeypatch, tmp_path):
    baseline_kill = {
        "ok": True,
        "summary": {
            "mttd": 15.0,
            "outcome": "defender",
            "detect_margin": 35.0,
            "first_detect": 15.0,
            "time_to_impact": 50.0,
            "timeline": [{"t": 0.0, "side": "red", "label": "start"}],
        },
        "artifact": {
            "summary.json": {"exists": True},
        },
        "check": {"signature": "abc", "governance_count": 0},
    }

    monkeypatch.setattr(gv, "run_kill_chain", lambda *args, **kwargs: subprocess.CompletedProcess(args=(), returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(gv, "validate_kill_chain_artifacts", lambda *args, **kwargs: baseline_kill)
    monkeypatch.setattr(
        gv,
        "run_checkup",
        lambda path: subprocess.CompletedProcess(args=(), returncode=0, stdout="== HOST POSTURE ==\n== VULNERABILITIES ==\n== INTRUSION DETECTION ==\n== PRIORITISED ACTIONS ==",
                                        stderr=""),
    )
    monkeypatch.setattr(
        gv,
        "run_governed_smoke",
        lambda out_dir: {"ok": True, "decisions": [{"decision": "denied-role"}, {"decision": "denied-approval"}],
                         "decision_values": ["denied-role", "denied-approval"], "governance_log": str(out_dir / "governance.log")},
    )

    out = gv.run_full_verification(tmp_path / "out", target="juice-shop", path=".", models=("codex",), require_governance=True)
    manifest = gv._read_json(out / "goal-manifest.json")

    assert manifest["audit_summary"]["killchain"]["mttd"] == 15.0
    assert manifest["audit_summary"]["killchain"]["outcome"] == "defender"
    assert manifest["audit_summary"]["killchain"]["detect_margin"] == 35.0
    assert manifest["run"]["mesh"] is False
    assert manifest["audit_summary"]["governance_log"].endswith("governance.log")
    assert manifest["audit_summary"]["mode"] == "direct"
    assert (out / "cross-model-comparison.json").exists()


def test_run_full_verification_records_mesh_metadata(monkeypatch, tmp_path):
    baseline_kill = {
        "ok": True,
        "summary": {
            "mttd": 15.0,
            "outcome": "defender",
            "detect_margin": 35.0,
            "first_detect": 15.0,
            "time_to_impact": 50.0,
            "timeline": [{"t": 0.0, "side": "red", "label": "start"}],
        },
        "artifact": {
            "summary.json": {"exists": True},
        },
        "check": {"signature": "abc", "governance_count": 0},
    }

    monkeypatch.setattr(
        gv,
        "run_kill_chain",
        lambda *args, **kwargs: subprocess.CompletedProcess(args=(), returncode=0, stdout="", stderr="")
    )
    monkeypatch.setattr(gv, "validate_kill_chain_artifacts", lambda *args, **kwargs: baseline_kill)
    monkeypatch.setattr(
        gv,
        "run_checkup",
        lambda path: subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout="== HOST POSTURE ==\n== VULNERABILITIES ==\n== INTRUSION DETECTION ==\n== PRIORITISED ACTIONS ==",
            stderr=""
        ),
    )
    monkeypatch.setattr(
        gv,
        "run_governed_smoke",
        lambda out_dir: {"ok": True, "decisions": [{"decision": "denied-role"}, {"decision": "denied-approval"}],
                         "decision_values": ["denied-role", "denied-approval"],
                         "governance_log": str(out_dir / "governance.log")},
    )

    out = gv.run_full_verification(
        tmp_path / "out",
        target="juice-shop",
        path=".",
        models=("codex",),
        require_governance=True,
        use_mesh=True,
        phantom_provider="mesh-provider",
    )
    manifest = gv._read_json(out / "goal-manifest.json")

    assert manifest["run"]["mesh"] is True
    assert manifest["run"]["provider"] == "mesh-provider"
    assert manifest["audit_summary"]["mode"] == "mesh"
    assert manifest["audit_summary"]["provider"] == "mesh-provider"


def test_build_checkup_signature_counts_actions():
    base = {"ok": True, "actions": [
        {"order": 1, "severity": "critical", "tool": "ids_scan", "action": "stop"},
        {"order": 2, "severity": "medium", "tool": "host_audit", "action": "fix"},
    ], "check": {"action_digest": "abc"}, "sections": {
        "== HOST POSTURE ==": True,
        "== VULNERABILITIES ==": True,
        "== INTRUSION DETECTION ==": True,
        "== PRIORITISED ACTIONS ==": True,
    }}
    sig = gv.build_checkup_signature(base)
    assert sig["action_count"] == 2
    assert sig["top_severity"] == "critical"
    assert sig["ok"] is True


def test_scenario_models_compare_killchain_and_checkup(tmp_path):
    kill = tmp_path / "k"
    check = tmp_path / "c"

    baseline_kill = {"summary": {"mttd": 15, "outcome": "defender", "detect_margin": 35, "time_to_impact": 50,
                                 "first_detect": 15, "first_action": 0, "timeline": [{"t":0, "side":"red","label":"a"}]},
                     "ok": True, "check": {}, "artifact": {}}
    baseline_check = {"ok": True, "actions": [{"order": 1, "severity": "critical", "tool": "vuln_scan", "action": "a"}], "check": {"action_digest": "x"}, "sections": {}}

    kr, kc = gv.run_scenario_models(("codex", "claude"), "killchain", kill, target="juice-shop", path=".", baseline=baseline_kill)
    cr, cc = gv.run_scenario_models(("codex", "claude"), "checkup", check, target="juice-shop", path=".", baseline=baseline_check)

    assert kr["codex"]["status"] == "dry-run"
    assert kr["claude"]["status"] == "dry-run"
    assert kc["ok"] is True
    assert cc["ok"] is True
