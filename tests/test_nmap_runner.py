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


# ── command-construction safety (no shell injection via scan_type / ports) ─────

def test_scan_type_injection_is_refused(monkeypatch) -> None:
    """A scan_type carrying shell metacharacters must NEVER reach subprocess.

    The command is built into a `bash -c` string; an unvalidated scan_type like
    '-sV; rm -rf /' would inject. The gate must reject it before any spawn.
    """
    def _boom(*a, **k):
        raise AssertionError("subprocess must not run for an injected scan_type")

    monkeypatch.setattr(subprocess, "run", _boom)
    result = nmap_runner.run("juice-shop", scan_type="-sV; echo PWNED")
    assert "error" in result
    assert "scan_type" in result["error"].lower()


def test_scan_type_with_backticks_refused(monkeypatch) -> None:
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no spawn")))
    result = nmap_runner.run("juice-shop", scan_type="-sV `whoami`")
    assert "error" in result


def test_valid_scan_types_pass_gate(monkeypatch) -> None:
    """Known-good nmap scan flags must still be accepted."""
    sent = {}

    def _fake(cmd, *a, **k):
        sent["cmd"] = cmd
        return subprocess.CompletedProcess(args=cmd, returncode=0,
                                           stdout="<nmaprun></nmaprun>", stderr="")

    monkeypatch.setattr(subprocess, "run", _fake)
    for st in ("-sV", "-sT", "-sS -sV", "-A", "-sV -Pn"):
        result = nmap_runner.run("juice-shop", scan_type=st)
        assert "error" not in result, f"{st!r} should be accepted"
        # the scan_type must appear verbatim in the built command
        assert st in " ".join(sent["cmd"])


def test_ports_injection_is_refused(monkeypatch) -> None:
    """ports is shlex-quoted, but an obviously hostile value should be rejected
    rather than relying on quoting alone (defense in depth)."""
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no spawn")))
    result = nmap_runner.run("juice-shop", ports="80; rm -rf /")
    assert "error" in result
    assert "ports" in result["error"].lower()
