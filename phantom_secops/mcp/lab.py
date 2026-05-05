"""Lab lifecycle + status helpers for the MCP server.

Wraps `docker compose` operations behind a small typed surface. Lifecycle
operations (`up`, `down`) require explicit `confirm=True` per the frozen
contract in docs/MCP-INTERFACE.md.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
LAB_NETWORK = "secops-lab"
LAB_SERVICES = ("juice-shop", "dvwa", "dvwa-db", "attacker", "log-collector")


def status() -> dict[str, Any]:
    """Report docker lab health. No side effects."""
    network_present = _network_exists()
    services = []
    for name in LAB_SERVICES:
        state, health = _service_state(name)
        services.append({"name": name, "state": state, "health": health})
    return {"network_present": network_present, "services": services}


def up(confirm: bool) -> dict[str, Any]:
    if confirm is not True:
        return _refuse_unconfirmed()
    return _compose_run(["up", "-d"])


def down(confirm: bool) -> dict[str, Any]:
    if confirm is not True:
        return _refuse_unconfirmed()
    # Note: `-v` removes volumes but never touches reports/runs/ (which is bind-mounted
    # into log-collector but the host directory persists).
    return _compose_run(["down", "-v"])


# ─── Internals ───────────────────────────────────────────────────────────

def _refuse_unconfirmed() -> dict[str, Any]:
    return {
        "error": "lifecycle_action_requires_confirmation",
        "message": "lifecycle tools must be called with confirm=True",
    }


def _compose_run(args: list[str]) -> dict[str, Any]:
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
            capture_output=True, text=True, timeout=300,
        )
    except FileNotFoundError:
        return {"error": "tool_nonzero_exit", "message": "docker not on PATH"}
    except subprocess.TimeoutExpired:
        return {"error": "tool_timeout", "message": "docker compose exceeded 300s"}

    log = (result.stdout + result.stderr)[-2048:]
    return {"ok": result.returncode == 0, "log": log}


def _network_exists() -> bool:
    try:
        result = subprocess.run(
            ["docker", "network", "inspect", LAB_NETWORK],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _service_state(name: str) -> tuple[str, str]:
    """Return (state, health) for a compose service."""
    container = f"secops-{name}"
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format",
             "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
             container],
            capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ("absent", "none")

    if result.returncode != 0:
        return ("absent", "none")
    parts = result.stdout.strip().split("|", 1)
    state = parts[0] if parts else "absent"
    health = parts[1] if len(parts) > 1 else "none"
    if state not in ("running", "exited", "absent"):
        state = "exited"  # paused, restarting, dead → coalesce to exited for reporting
    return (state, health)
