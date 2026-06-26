"""Goal-level verification utilities for phantom-secops objectives.

Goals
1) Run kill-chain and checkup flows in mock/local mode.
2) Emit a fixed-schema manifest for CI/manual review.
3) Compare multiple model outputs (codex/claude/hermes by default) and report deltas.
4) Keep a safe dry-run path when model runners are not configured.

This module is intentionally side-effect-light and test-friendly:
- core validation helpers are pure functions.
- subprocess-backed execution is behind explicit helper functions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
RUN_SUMMARY_REQUIRED_KEYS = ("mttd", "outcome", "detect_margin", "first_detect", "time_to_impact", "timeline")
RUN_SUMMARY_TIMELINE_KEYS = ("t", "side", "label")
KILLCHAIN_ARTIFACTS = (
    "summary.json",
    "recon.json",
    "vuln-scan.json",
    "alerts.jsonl",
    "triage-queue.jsonl",
    "kill-chains.jsonl",
    "exploit-suggestions.md",
    "pentest-report.md",
    "incident-report.md",
)
CHECKUP_SECTIONS = (
    "== HOST POSTURE ==",
    "== VULNERABILITIES ==",
    "== INTRUSION DETECTION ==",
    "== PRIORITISED ACTIONS ==",
)
MODELS_DEFAULT = ("codex", "claude", "hermes")
GOVERNANCE_FILES = ("governance.jsonl", "governance.log")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_text(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_json_lines(path: Path) -> list[dict[str, Any]]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        out.append(json.loads(line))
    return out


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _safe_timeline_check(timeline: Any) -> tuple[bool, list[str], dict[str, Any]]:
    if not isinstance(timeline, list):
        return False, ["timeline must be a list"], {}
    issues: list[str] = []
    for idx, item in enumerate(timeline):
        if not isinstance(item, dict):
            issues.append(f"timeline[{idx}] must be an object")
            continue
        missing = [k for k in RUN_SUMMARY_TIMELINE_KEYS if k not in item]
        if missing:
            issues.append(f"timeline[{idx}] missing keys: {','.join(sorted(missing))}")
    if not issues:
        return True, issues, {"timeline_len": len(timeline)}
    return False, issues, {"timeline_len": len(timeline)}


def _first_governance_file(run_dir: Path) -> Path | None:
    for name in GOVERNANCE_FILES:
        p = run_dir / name
        if p.exists():
            return p
    return None


def _line_contains_payload(text: str) -> bool:
    lowered = text.lower()
    markers = ("curl ", "<script>", "; rm ", "powershell -enc", "nc -e", "msfconsole")
    return any(m in lowered for m in markers)


def validate_kill_chain_artifacts(run_dir: Path, *, require_governance: bool = False) -> dict[str, Any]:
    """Validate fixed artifacts for a single kill-chain run."""
    out: dict[str, Any] = {
        "ok": True,
        "timestamp": _now_iso(),
        "run_dir": str(run_dir),
        "errors": [],
        "warnings": [],
        "artifact": {},
        "summary": {},
        "check": {},
    }

    run_dir = run_dir.resolve()
    if not run_dir.exists():
        out["ok"] = False
        out["errors"].append(f"run_dir missing: {run_dir}")
        return out

    for name in KILLCHAIN_ARTIFACTS:
        p = run_dir / name
        if not p.exists():
            out["ok"] = False
            out["errors"].append(f"missing required artifact: {name}")
            out["artifact"][name] = {"required": True, "exists": False}
        else:
            digest = _sha256_bytes(p.read_bytes())
            out["artifact"][name] = {"required": True, "exists": True, "sha256": digest}

    summary_path = run_dir / "summary.json"
    if summary_path.exists():
        try:
            summary = _read_json(summary_path)
        except (OSError, json.JSONDecodeError) as exc:
            out["ok"] = False
            out["errors"].append(f"summary.json parse failed: {exc}")
            summary = {}
        out["summary"] = summary
        for key in RUN_SUMMARY_REQUIRED_KEYS:
            if key not in summary:
                out["ok"] = False
                out["errors"].append(f"summary.json missing key: {key}")
        if isinstance(summary.get("timeline"), list):
            timeline_ok, timeline_issues, info = _safe_timeline_check(summary["timeline"])
            if not timeline_ok:
                out["ok"] = False
                out["errors"].extend(timeline_issues)
            out["check"].update(info)
        else:
            out["check"]["timeline_len"] = 0
        for key in ("mttd", "detect_margin", "time_to_impact", "first_detect", "first_action"):
            if key in summary and not isinstance(summary[key], (int, float)):
                out["ok"] = False
                out["errors"].append(f"summary.{key} must be numeric")
        if summary.get("outcome") not in ("defender", "attacker"):
            out["ok"] = False
            out["errors"].append("summary.outcome must be 'defender' or 'attacker'")
    else:
        out["ok"] = False
        out["errors"].append("summary.json missing")

    exploit = run_dir / "exploit-suggestions.md"
    if exploit.exists():
        if _line_contains_payload(exploit.read_text(encoding="utf-8")):
            out["ok"] = False
            out["errors"].append("exploit-suggestions.md contains payload-like markers")
    else:
        out["ok"] = False
        out["errors"].append("exploit-suggestions.md missing (prose-only contract cannot be checked)")

    gov_path = _first_governance_file(run_dir)
    if gov_path is not None:
        try:
            decisions = _read_json_lines(gov_path)
        except (OSError, json.JSONDecodeError) as exc:
            out["ok"] = False
            out["errors"].append(f"governance.jsonl parse failed: {exc}")
            decisions = []
        out["check"]["governance_count"] = len(decisions)
        out["check"]["governance_path"] = str(gov_path)
        out["check"]["governance_decision_types"] = sorted(
            {d.get("decision") for d in decisions if isinstance(d, dict) and "decision" in d}
        )
        out["check"]["governance_sha256"] = _sha256_text([d for d in decisions])
    else:
        out["check"]["governance_count"] = 0
        out["check"]["governance_sha256"] = None
        if require_governance:
            out["ok"] = False
            out["errors"].append("governance audit file missing but required")
        else:
            out["warnings"].append("governance audit file not generated by this run path")

    out["check"]["signature"] = _sha256_text({
        "summary": {k: out["summary"].get(k) for k in RUN_SUMMARY_REQUIRED_KEYS},
        "artifacts": sorted(
            name for name in KILLCHAIN_ARTIFACTS if out["artifact"].get(name, {}).get("exists")
        ),
    })
    return out


def parse_checkup_prioritised_actions(text: str) -> list[dict[str, Any]]:
    """Extract only the numbered lines under the PRIORITISED ACTIONS section."""
    action_re = re.compile(r"^\s*(\d+)\.\s+\[([^\]]+)\]\s+([^\s]+)\s+(.+?)\s*$")
    actions: list[dict[str, Any]] = []
    in_block = False
    for line in text.splitlines():
        if line.strip() == "== PRIORITISED ACTIONS ==" or line.startswith("== PRIORITISED ACTIONS =="):
            in_block = True
            continue
        if in_block:
            if not line.strip():
                continue
            m = action_re.match(line)
            if not m:
                # block ended or non-action content; ignore
                continue
            actions.append({
                "order": int(m.group(1)),
                "severity": m.group(2).strip(),
                "tool": m.group(3).strip(),
                "action": m.group(4).strip(),
            })
    return actions


def validate_checkup_output(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        "ok": True,
        "timestamp": _now_iso(),
        "errors": [],
        "warnings": [],
        "sections": {},
        "actions": [],
        "check": {},
    }
    for sec in CHECKUP_SECTIONS:
        if sec in text:
            out["sections"][sec] = True
        else:
            out["ok"] = False
            out["errors"].append(f"missing section: {sec}")
            out["sections"][sec] = False
    actions = parse_checkup_prioritised_actions(text)
    out["actions"] = actions
    out["check"]["action_count"] = len(actions)
    out["check"]["action_digest"] = _sha256_text(actions)
    if actions:
        # stable ranking signal: non-empty action list must preserve first-action intent
        severities = [a["severity"].strip().lower() for a in actions[:3]]
        if "critical" not in severities[:3] and "high" not in severities[:3]:
            out["warnings"].append(
                "unexpected checkup ranking: top-3 actions do not include any high/critical item"
            )
    return out


def _run_subprocess(cmd: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(REPO_ROOT),
        env=env,
    )


def run_kill_chain_mock(out_dir: Path, target: str = "juice-shop") -> subprocess.CompletedProcess[str]:
    return run_kill_chain(out_dir, target=target, driver="direct")


def run_kill_chain(out_dir: Path, target: str = "juice-shop", *, driver: str = "direct", phantom_provider: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run kill-chain either direct or mesh driver."""
    cmd = [sys.executable, str(REPO_ROOT / "scenarios" / "run_kill_chain.py"), "--mock", "--target", target, "--out", str(out_dir)]
    if driver == "mesh":
        cmd.extend(["--driver", "mesh"])
    env = os.environ.copy()
    if driver == "mesh":
        env["SECOPS_MCP_MOCK"] = "1"
    if phantom_provider and phantom_provider.strip():
        env["PHANTOM_PROVIDER"] = phantom_provider
    return _run_subprocess(cmd, env=env)


def run_checkup(path: str) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(REPO_ROOT / "lab" / "_checkup.py"), path]
    return _run_subprocess(cmd, env=os.environ.copy())


def run_governed_smoke(out_dir: Path) -> dict[str, Any]:
    """Run the M2 policy gate (mock + live-guard denied path) and validate audit output."""
    from secops_mcp import server

    _orig = {k: os.environ.get(k) for k in (
        "SECOPS_AGENT_ROLE",
        "SECOPS_MCP_MOCK",
        "SECOPS_MCP_APPROVAL",
        "SECOPS_MCP_STATE_FILE",
        "SECOPS_MCP_OUT_DIR",
    )}

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        os.environ["SECOPS_MCP_OUT_DIR"] = str(out_dir)
        os.environ["SECOPS_MCP_STATE_FILE"] = str(out_dir / "state.json")

        # [1] blue → red (structural deny)
        os.environ["SECOPS_AGENT_ROLE"] = "blue"
        os.environ["SECOPS_MCP_MOCK"] = "1"
        blue_recon = server.recon_impl({"target": "juice-shop"})

        # [2] blue → blue (allow in mock)
        blue_detect = server.detect_impl({})

        # [3] live red tool, fail-closed no approval
        os.environ["SECOPS_AGENT_ROLE"] = "orchestrator"
        os.environ["SECOPS_MCP_MOCK"] = "0"
        os.environ["SECOPS_MCP_APPROVAL"] = "auto-deny"
        live_recon = server.recon_impl({"target": "juice-shop"})

        gov_path = _first_governance_file(out_dir)
        if gov_path is None:
            return {
                "ok": False,
                "scenario": "governance-smoke",
                "errors": ["governance audit file was not written"],
            }
        if gov_path.name != "governance.log":
            (out_dir / "governance.log").write_text(gov_path.read_text(encoding="utf-8"), encoding="utf-8")
        decisions = _read_json_lines(gov_path)
        errors: list[str] = []
        # Expected invariants for a complete gate demo run.
        decision_values = [d.get("decision") for d in decisions if isinstance(d, dict)]
        for needle in ("denied-role", "denied-approval"):
            if needle not in decision_values:
                errors.append(f"missing governance decision '{needle}'")
        return {
            "ok": len(errors) == 0,
            "scenario": "governance-smoke",
            "governance_file": str(gov_path),
            "governance_log": str(out_dir / "governance.log"),
            "decisions": decisions,
            "decision_values": decision_values,
            "errors": errors,
            "blue_recon": blue_recon,
            "blue_detect": blue_detect,
            "live_recon": live_recon,
        }
    finally:
        for k, v in _orig.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def run_model_probe(
    model: str,
    scenario: str,
    out_dir: Path,
    *,
    target: str,
    checkup_path: str,
    baseline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one model probe.

    If no explicit runner is configured for `model`, return a dry-run copy of the
    baseline result so the comparison pipeline still executes and emits artifacts.
    """
    env_name = f"GOAL_MODEL_RUNNER_{model.upper()}"
    runner = os.environ.get(env_name, "").strip()
    if not runner:
        return {
            "model": model,
            "status": "dry-run",
            "reason": f"{env_name} not set",
            "result": baseline,
        }

    if scenario == "killchain":
        cmd = shlex.split(
            runner.format(
                repo=str(REPO_ROOT),
                out_dir=str(out_dir),
                target=target,
                path=checkup_path,
                scenario=scenario,
            )
        )
        proc = _run_subprocess(cmd, env=os.environ.copy())
        run_result = validate_kill_chain_artifacts(out_dir, require_governance=False)
        return {
            "model": model,
            "status": "ok" if proc.returncode == 0 and run_result["ok"] else "failed",
            "code": proc.returncode,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-4000:],
            "result": run_result if run_result["ok"] else None,
        }
    if scenario == "checkup":
        cmd = shlex.split(
            runner.format(
                repo=str(REPO_ROOT),
                out_dir=str(out_dir),
                target=target,
                path=checkup_path,
                scenario=scenario,
            )
        )
        proc = _run_subprocess(cmd, env=os.environ.copy())
        out_path = out_dir / "checkup.txt"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(proc.stdout, encoding="utf-8")
        if proc.returncode != 0:
            return {
                "model": model,
                "status": "failed",
                "code": proc.returncode,
                "stdout": proc.stdout[-4000:],
                "stderr": proc.stderr[-4000:],
                "result": None,
            }
        check = validate_checkup_output(proc.stdout)
        return {
            "model": model,
            "status": "ok" if check["ok"] else "failed",
            "code": 0,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-4000:],
            "result": check,
        }
    return {"model": model, "status": "unsupported", "result": None}


def compare_model_signatures(models: dict[str, dict[str, Any]], *, fields: Iterable[str] | None = None) -> dict[str, Any]:
    fields = tuple(fields or ("mttd", "outcome", "detect_margin", "time_to_impact", "first_detect", "first_action", "timeline_len"))
    names = sorted(models)
    if not names:
        return {"ok": True, "base": None, "fields": list(fields), "mismatches": [], "matrix": {}}
    base_name = names[0]
    base = models[base_name]
    out: dict[str, Any] = {
        "ok": True,
        "base": base_name,
        "fields": list(fields),
        "mismatches": [],
        "matrix": {},
    }
    for name in names[1:]:
        cur = models[name]
        misses: list[str] = []
        for key in fields:
            if base.get(key) != cur.get(key):
                misses.append(f"{key}: {base_name}={base.get(key)!r} vs {name}={cur.get(key)!r}")
        if misses:
            out["ok"] = False
            out["mismatches"].append({"left": base_name, "right": name, "diff": misses})
        out["matrix"][name] = {"mismatch_count": len(misses)}
    out["matrix"][base_name] = {"mismatch_count": 0}
    return out


def build_kill_chain_signature(result: dict[str, Any]) -> dict[str, Any]:
    summary = result.get("summary", {})
    return {
        "mttd": summary.get("mttd"),
        "outcome": summary.get("outcome"),
        "detect_margin": summary.get("detect_margin"),
        "time_to_impact": summary.get("time_to_impact"),
        "first_detect": summary.get("first_detect"),
        "first_action": summary.get("first_action"),
        "timeline_len": len(summary.get("timeline", []) or []),
        "timeline_sha256": _sha256_text(summary.get("timeline", [])),
        "governance_count": result.get("check", {}).get("governance_count", 0),
        "governance_sha256": result.get("check", {}).get("governance_sha256"),
        "artifact_signature": result.get("check", {}).get("signature"),
        "artifact_count": sum(1 for item in result.get("artifact", {}).values() if item.get("exists")),
        "ok": result.get("ok", False),
    }


def build_checkup_signature(result: dict[str, Any]) -> dict[str, Any]:
    actions = result.get("actions", [])
    severities = [a.get("severity") for a in actions]
    return {
        "ok": result.get("ok", False),
        "action_count": len(actions),
        "top_action": actions[0] if actions else None,
        "top_severity": severities[0] if severities else None,
        "action_digest": result.get("check", {}).get("action_digest"),
        "sections": result.get("sections", {}),
    }


def run_scenario_models(models: tuple[str, ...], scenario: str, out_root: Path, *, target: str, path: str, baseline: dict[str, Any], require_governance: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    scenario_results: dict[str, Any] = {}
    for model in models:
        model_run_dir = out_root / model
        res = run_model_probe(model, scenario, model_run_dir, target=target, checkup_path=path, baseline=baseline)
        if res.get("status") == "dry-run" and baseline is not None:
            # Keep per-model signatures comparable even when no external runner is configured.
            res["result"] = baseline
        if scenario == "killchain" and require_governance and res.get("result") and not res["result"].get("check", {}).get("governance_count"):
            res["status"] = "warn"
            res.setdefault("warnings", []).append("governance not emitted by this model run")
        scenario_results[model] = res

    signatures = {}
    for model, item in scenario_results.items():
        payload = item.get("result") or {}
        signatures[model] = (
            build_kill_chain_signature(payload)
            if scenario == "killchain"
            else build_checkup_signature(payload)
        )
    compare_fields = (
        ("mttd", "outcome", "detect_margin", "time_to_impact", "first_detect", "first_action", "timeline_len")
        if scenario == "killchain"
        else ("ok", "action_count", "top_severity", "action_digest", "sections")
    )
    compare_payload = compare_model_signatures(signatures, fields=compare_fields)
    return scenario_results, compare_payload


def run_full_verification(
    out: Path,
    *,
    target: str,
    path: str,
    models: tuple[str, ...],
    require_governance: bool,
    use_mesh: bool = False,
    phantom_provider: str | None = None,
) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    killchain_dir = out / "killchain"
    checkup_dir = out / "checkup"
    governance_dir = out / "governance"
    checkup_dir.mkdir(parents=True, exist_ok=True)
    governance_dir.mkdir(parents=True, exist_ok=True)

    kill_proc = run_kill_chain(
        killchain_dir,
        target=target,
        driver="mesh" if use_mesh else "direct",
        phantom_provider=phantom_provider,
    )
    # Baseline kill-chain here is mock direct-mode (no secops_mcp governance
    # gate). Governance coverage is validated separately by run_governed_smoke.
    kill_validation = validate_kill_chain_artifacts(killchain_dir, require_governance=False)
    kill_validation["process"] = {
        "returncode": kill_proc.returncode,
        "stderr_tail": kill_proc.stderr[-1000:],
    }
    if kill_proc.returncode != 0:
        kill_validation["errors"].append("kill-chain command failed")

    checkup_proc = run_checkup(path)
    checkup_out_path = checkup_dir / "checkup.txt"
    checkup_out_path.write_text(checkup_proc.stdout, encoding="utf-8")
    checkup_validation = validate_checkup_output(checkup_proc.stdout)
    checkup_validation["process"] = {
        "returncode": checkup_proc.returncode,
        "stderr_tail": checkup_proc.stderr[-1000:],
    }
    if checkup_proc.returncode != 0:
        checkup_validation["errors"].append("checkup command failed")

    governance_result = run_governed_smoke(governance_dir)
    governance_log = governance_result.get("governance_log", str((governance_dir / "governance.log")))
    governance_validation = {
        "ok": governance_result.get("ok", False),
        "result": governance_result,
        "decision_count": len(governance_result.get("decisions", [])),
        "decision_values": governance_result.get("decision_values", []),
        "governance_log": governance_log,
    }

    baseline_signature = build_kill_chain_signature(kill_validation)
    checkup_signature = build_checkup_signature(checkup_validation)

    model_results_kill, compare_kill = run_scenario_models(
        models, "killchain", out / "models" / "killchain", target=target,
        path=path, baseline=kill_validation, require_governance=require_governance,
    )
    model_results_check, compare_check = run_scenario_models(
        models, "checkup", out / "models" / "checkup", target=target,
        path=path, baseline=checkup_validation,
    )

    compare_payload = {
        "killchain": compare_kill,
        "checkup": compare_check,
    }

    audit_summary = {
        "out_dir": str(out),
        "mode": "mesh" if use_mesh else "direct",
        "target": target,
        "checkup_path": str(Path(path)),
        "killchain": {
            "mttd": baseline_signature.get("mttd"),
            "outcome": baseline_signature.get("outcome"),
            "detect_margin": baseline_signature.get("detect_margin"),
            "summary_signature": baseline_signature.get("artifact_signature"),
        },
        "governance_log": governance_validation.get("governance_log"),
        "provider": phantom_provider,
    }

    out_payload = {
        "goal": "phantom-secops baseline verification",
        "timestamp": _now_iso(),
        "target": target,
        "checkup_path": str(Path(path)),
        "out_dir": str(out),
        "run": {
            "mesh": use_mesh,
            "provider": phantom_provider,
        },
        "audit_summary": audit_summary,
        "killchain": kill_validation,
        "checkup": checkup_validation,
        "governance": governance_validation,
        "killchain_signature": baseline_signature,
        "checkup_signature": checkup_signature,
        "models": {
            "killchain": model_results_kill,
            "checkup": model_results_check,
        },
        "model_compare": compare_payload,
    }

    _write_json(out / "goal-manifest.json", out_payload)
    _write_json(out / "killchain-validation.json", {
        "timestamp": out_payload["timestamp"],
        "target": target,
        "validation": kill_validation,
    })
    _write_json(out / "checkup-validation.json", {
        "timestamp": out_payload["timestamp"],
        "path": str(path),
        "validation": checkup_validation,
    })
    _write_json(out / "governance-validation.json", {
        "timestamp": out_payload["timestamp"],
        "target": target,
        "validation": governance_validation,
    })
    _write_json(out / "cross-model-comparison.json", compare_payload)

    return out


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", default=str(REPO_ROOT / "reports" / "verification"), help="output directory")
    p.add_argument("--target", default="juice-shop", help="kill-chain target")
    p.add_argument("--path", default=".", help="checkup scan path")
    p.add_argument(
        "--models",
        default=",".join(MODELS_DEFAULT),
        help="comma-separated model labels to compare",
    )
    p.add_argument(
        "--require-governance",
        action="store_true",
        help="treat missing governance audit trail as verification failure",
    )
    p.add_argument(
        "--require-parity",
        action="store_true",
        help="fail when cross-model killchain/checkup signatures diverge",
    )
    p.add_argument(
        "--mesh",
        action="store_true",
        help="run kill-chain baseline via phantom-mesh driver (--driver mesh)",
    )
    p.add_argument("--provider", default="", help="PHANTOM provider used for mesh runs")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    models = tuple(x.strip().lower() for x in args.models.split(",") if x.strip())
    if not models:
        models = MODELS_DEFAULT

    out = Path(args.out) / _now_iso().replace(":", "-").split(".")[0]
    out = run_full_verification(
        out,
        target=args.target,
        path=args.path,
        models=models,
        require_governance=args.require_governance,
        use_mesh=args.mesh,
        phantom_provider=args.provider or None,
    )
    report = _read_json(out / "goal-manifest.json") if isinstance(out, Path) else out

    print(f"[DONE] goal verification complete -> {out}")
    print(f"   kill-chain ok: {report['killchain']['ok']}")
    print(f"   checkup ok  : {report['checkup']['ok']}")
    print(f"   governance  : {report['governance']['ok']}")
    print(f"   cross-model : "
          f"k={report['model_compare']['killchain'].get('ok', True)} "
          f"c={report['model_compare']['checkup'].get('ok', True)}")
    if not (report["killchain"]["ok"] and report["checkup"]["ok"] and report["governance"]["ok"]):
        return 1
    if args.require_parity and (
            not report["model_compare"]["killchain"].get("ok", True)
            or not report["model_compare"]["checkup"].get("ok", True)
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
