"""Run goal_verification with a strict preflight for parity model runners."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFIER = REPO_ROOT / "scripts" / "goal_verification.py"
PARITY_MODELS_DEFAULT = ("codex", "claude", "hermes")
MODEL_ENV_PREFIX = "GOAL_MODEL_RUNNER_"


def _parse_models(argv: list[str]) -> list[str]:
    if "--models" not in argv:
        return list(PARITY_MODELS_DEFAULT)
    idx = argv.index("--models")
    if idx + 1 >= len(argv):
        print("--models requires a comma-separated value", file=sys.stderr)
        return []
    return [m.strip() for m in argv[idx + 1].split(",") if m.strip()]


def _require_model_runners(models: list[str]) -> int:
    missing = [m for m in models if not os.environ.get(f"{MODEL_ENV_PREFIX}{m.upper()}", "").strip()]
    if not missing:
        return 0
    print("strict parity 模式要求模型 runner，未設定：")
    for item in missing:
        env_name = f"{MODEL_ENV_PREFIX}{item.upper()}"
        print(f"  - {item}: ${env_name}")
    print("請先設定 GOAL_MODEL_RUNNER_* 環境變數再重跑（例如 run_goal_model_runner.py）。")
    return 1


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "-h" in argv or "--help" in argv:
        return subprocess.call([sys.executable, str(VERIFIER), *argv])

    if "--require-parity" in argv:
        models = _parse_models(argv)
        if not models:
            return 2
        rc = _require_model_runners(models)
        if rc != 0:
            return rc

    proc = subprocess.run([sys.executable, str(VERIFIER), *argv])
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
