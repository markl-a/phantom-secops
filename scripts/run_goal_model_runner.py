"""Cross-model goal verification runner stub used by GOAL_MODEL_RUNNER_* templates.

It normalises kill-chain and checkup execution for codex / claude / hermes
comparisons. In kill-chain mode, this runs mock pipeline by default for
reproducible, offline-safe smoke. In mesh mode it delegates to the same command
as `make demo-mock-mesh` (requires phantom-mesh and provider envs), useful once
phantom-mesh is ready.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run(cmd: list[str], env: dict[str, str] | None = None) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT), env=env, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def run_killchain(out_dir: Path, target: str, provider: str | None = None, mesh: bool = False) -> int:
    cmd = [sys.executable, str(REPO_ROOT / "scenarios" / "run_kill_chain.py"), "--mock", "--target", target, "--out", str(out_dir)]
    if mesh:
        cmd.extend(["--driver", "mesh"])
    env = os.environ.copy()
    if provider and provider.strip():
        env["PHANTOM_PROVIDER"] = provider
    if mesh:
        # Mesh path must explicitly avoid write-on-write surprises and preserve
        # governance policy behavior for smoke runs.
        env["SECOPS_MCP_MOCK"] = "1"
    code, stdout, stderr = _run(cmd, env=env)
    if stdout:
        print(stdout, end="")
    if stderr:
        print(stderr, end="", file=sys.stderr)
    return code


def run_checkup(path: str) -> int:
    cmd = [sys.executable, str(REPO_ROOT / "lab" / "_checkup.py"), path]
    code, stdout, stderr = _run(cmd, env=os.environ.copy())
    if stdout:
        print(stdout, end="")
    if stderr:
        print(stderr, end="", file=sys.stderr)
    return code


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--model", required=True, help="model tag used by runner routing, e.g. codex")
    p.add_argument("--scenario", choices=("killchain", "checkup"), required=True, help="scenario to execute")
    p.add_argument("--out_dir", required=True, help="output directory for scenario artifacts")
    p.add_argument("--target", default="juice-shop", help="kill-chain target")
    p.add_argument("--path", default=".", help="checkup scan path")
    p.add_argument("--repo", default=str(REPO_ROOT), help="unused compatibility placeholder for command templates")
    p.add_argument("--mesh", action="store_true", help="use phantom-mesh driver for kill-chain")
    p.add_argument("--provider", default="", help="PHANTOM provider to pass when mesh is used")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.scenario == "killchain":
        provider = (args.provider or os.environ.get("PHANTOM_PROVIDER", "")).strip()
        return run_killchain(out_dir=out_dir, target=args.target, provider=provider or None, mesh=args.mesh)
    if args.scenario == "checkup":
        return run_checkup(args.path)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
