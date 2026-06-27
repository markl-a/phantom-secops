from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

from phantom_secops import __version__


ROOT = Path(__file__).resolve().parents[1]


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_pyproject_metadata_matches_public_release_gate() -> None:
    project = _pyproject()["project"]

    assert project["name"] == "phantom-secops"
    assert project["version"] == __version__ == "0.1.0a0"
    assert project["license"] == "Apache-2.0"
    assert project["requires-python"] == ">=3.10"
    assert project["authors"]
    assert "Topic :: Security" in project["classifiers"]
    assert "Homepage" in project["urls"]
    assert project["dependencies"] == []


def test_console_entrypoints_are_declared_for_read_only_public_surface() -> None:
    scripts = _pyproject()["project"]["scripts"]

    assert scripts["phantom-secops"] == "phantom_secops.cli:main"
    assert scripts["phantom-secops-defensive-loop"] == "phantom_secops.defensive_loop:main"
    assert scripts["phantom-secops-evidence-playbook"] == "phantom_secops.evidence_playbook:main"
    assert scripts["phantom-secops-reasoning-scenario"] == "phantom_secops.reasoning_scenario:main"
    assert all("scenarios.run_kill_chain" not in target for target in scripts.values())


def test_top_level_cli_help_is_available_without_external_services() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "phantom_secops.cli", "--help"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert "defensive-loop" in result.stdout
    assert "active scanning" in result.stdout

