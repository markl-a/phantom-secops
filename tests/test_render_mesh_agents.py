"""Tests for the agents/ → phantom-mesh agents.toml renderer."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "render-mesh-agents.py"


def run(args: list[str]) -> tuple[int, str]:
    result = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)
    return result.returncode, result.stdout + result.stderr


def test_renders_red_recon_with_plugin_policy(tmp_path: Path):
    src = tmp_path / "recon.toml"
    src.write_text(
        '[agent]\n'
        'name = "red-recon"\n'
        '[[agent.tools]]\n'
        'name = "nmap_runner"\n'
        '[[agent.tools]]\n'
        'name = "file_write"\n'
        '[agent.prompt]\n'
        'system = "You are a red-team agent."\n'
        '[agent.limits]\n'
        'max_tool_calls = 12\n'
    )
    rc, out = run([str(src)])
    assert rc == 0, out
    assert "[agent.red-recon]" in out
    assert "secops_recon.scan_target" in out
    assert "file_write" in out
    assert "[agent.red-recon.plugin_policy]" in out
    assert "network.scan.passive" in out
    assert "target.lab_only" in out
    assert 'classification_max   = "red"' in out


def test_unknown_tool_emits_todo_and_exit_2(tmp_path: Path):
    src = tmp_path / "x.toml"
    src.write_text(
        '[agent]\n'
        'name = "x"\n'
        '[[agent.tools]]\n'
        'name = "unmapped_tool"\n'
        '[agent.prompt]\n'
        'system = "x"\n'
    )
    rc, out = run([str(src)])
    assert rc == 2
    assert "TODO: map unmapped_tool" in out


def test_blue_alert_triage_renders_blue_classification(tmp_path: Path):
    src = tmp_path / "triage.toml"
    src.write_text(
        '[agent]\n'
        'name = "blue-alert-triage"\n'
        '[[agent.tools]]\n'
        'name = "file_read"\n'
        '[[agent.tools]]\n'
        'name = "file_write"\n'
        '[agent.prompt]\n'
        'system = "Tier-1 SOC analyst."\n'
    )
    rc, out = run([str(src)])
    assert rc == 0, out
    assert "[agent.blue-alert-triage]" in out
    # No MCP plugin tools used → no plugin_policy needed.
    assert "[agent.blue-alert-triage.plugin_policy]" not in out
