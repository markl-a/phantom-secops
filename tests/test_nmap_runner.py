"""Tests for the nmap_runner tool wrapper.

The wrapper must refuse non-lab targets (defense-in-depth: even if an agent
prompt tries to pivot to a real-world host, the tool layer says no).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import nmap_runner  # type: ignore[import-not-found]


def test_refuses_non_lab_target() -> None:
    result = nmap_runner.run("scanme.nmap.org")
    assert "error" in result, "external target must be refused"
    assert "lab_services" in result, "error response must list allowed services"


def test_accepts_lab_targets(monkeypatch) -> None:
    """Confirm a lab target passes the gate, hermetically (docker stubbed out)."""
    # Stub subprocess so the test never touches docker regardless of host setup;
    # simulate docker-not-present. The gate should pass (no 'refusing to scan'),
    # and run() should surface a structured error rather than raising.
    def _no_docker(*a, **k):
        raise FileNotFoundError(2, "docker not found")

    monkeypatch.setattr(subprocess, "run", _no_docker)
    result = nmap_runner.run("juice-shop")
    refused = ("error" in result
               and isinstance(result.get("error"), str)
               and "refusing to scan" in result["error"])
    assert not refused, "lab target should pass the gate"


def test_docker_missing_returns_error_dict(monkeypatch) -> None:
    """docker binary absent -> structured error, never an unhandled exception."""
    def _no_docker(*a, **k):
        raise FileNotFoundError(2, "docker not found")

    monkeypatch.setattr(subprocess, "run", _no_docker)
    result = nmap_runner.run("juice-shop")
    assert "error" in result
    assert "open_ports" not in result


def test_timeout_returns_error_dict(monkeypatch) -> None:
    def _timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="nmap", timeout=120)

    monkeypatch.setattr(subprocess, "run", _timeout)
    result = nmap_runner.run("juice-shop")
    assert "error" in result
    assert "timeout" in result["error"].lower()


def test_parses_open_ports_from_xml(monkeypatch) -> None:
    xml = (
        '<?xml version="1.0"?><nmaprun><host><ports>'
        '<port protocol="tcp" portid="3000">'
        '<state state="open"/>'
        '<service name="http" product="Node.js Express" version="4"/>'
        '</port>'
        '<port protocol="tcp" portid="22">'
        '<state state="closed"/><service name="ssh"/>'
        '</port>'
        '</ports></host></nmaprun>'
    )

    def _fake(*a, **k):
        return subprocess.CompletedProcess(args=a, returncode=0, stdout=xml, stderr="")

    monkeypatch.setattr(subprocess, "run", _fake)
    result = nmap_runner.run("juice-shop")
    assert "error" not in result
    assert result["open_ports"] == [
        {"port": 3000, "protocol": "tcp", "service": "http",
         "version": "Node.js Express 4"},
    ]


def test_known_lab_services_includes_juice_shop() -> None:
    services = nmap_runner._known_lab_services()
    assert "juice-shop" in services
    assert "dvwa" in services
