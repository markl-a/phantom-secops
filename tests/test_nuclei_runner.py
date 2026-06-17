"""Tests for the nuclei_runner tool wrapper.

Like nmap_runner, this is a red-team tool that must be self-gated to in-lab
hosts (defense-in-depth: even a compromised/misled agent prompt cannot point it
at a real-world host). It must also degrade gracefully — returning a structured
error dict, never raising — when docker/nuclei is unavailable, because the
kill-chain orchestrator relies on that contract to keep running offline.

All tests are hermetic: subprocess is stubbed, nothing touches docker/network.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools import nuclei_runner  # type: ignore[import-not-found]


# ── lab-only gate ──────────────────────────────────────────────────────────────

def test_accepts_lab_host_urls() -> None:
    assert nuclei_runner._is_lab_url("http://juice-shop:3000")
    assert nuclei_runner._is_lab_url("http://dvwa")
    assert nuclei_runner._is_lab_url("https://metasploitable:8080/path")


def test_refuses_plain_external_url() -> None:
    assert not nuclei_runner._is_lab_url("http://scanme.nmap.org")


def test_refuses_external_url_with_lab_name_in_path() -> None:
    """A lab service name appearing in the path/query must NOT open the gate.

    Substring matching would let an attacker-controlled host through, e.g.
    http://evil.example.com/?next=juice-shop — the gate must key on the host.
    """
    assert not nuclei_runner._is_lab_url("http://evil.example.com/?next=juice-shop")
    assert not nuclei_runner._is_lab_url("http://juice-shop.evil.example.com/")
    assert not nuclei_runner._is_lab_url("http://10.0.0.5/dvwa")


def test_run_refuses_external_target_without_subprocess(monkeypatch) -> None:
    def _boom(*a, **k):  # subprocess must never be reached for a refused target
        raise AssertionError("subprocess.run should not be called for refused target")

    monkeypatch.setattr(subprocess, "run", _boom)
    result = nuclei_runner.run("http://evil.example.com/?x=juice-shop")
    assert "error" in result
    assert "refusing to scan" in result["error"]
    assert "allowed_hosts" in result


# ── graceful degradation when docker/nuclei is missing ─────────────────────────

def test_run_returns_error_dict_when_docker_missing(monkeypatch) -> None:
    """docker binary absent -> structured error, never an unhandled exception.

    The kill-chain orchestrator documents and depends on this contract.
    """
    def _no_docker(*a, **k):
        raise FileNotFoundError(2, "The system cannot find the file specified")

    monkeypatch.setattr(subprocess, "run", _no_docker)
    result = nuclei_runner.run("http://juice-shop:3000")
    assert "error" in result
    assert result.get("findings", []) == [] or "findings" not in result


def test_run_handles_timeout(monkeypatch) -> None:
    def _timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="nuclei", timeout=120)

    monkeypatch.setattr(subprocess, "run", _timeout)
    result = nuclei_runner.run("http://juice-shop:3000")
    assert "error" in result
    assert "timeout" in result["error"].lower()


# ── JSONL parsing ──────────────────────────────────────────────────────────────

def test_run_parses_jsonl_findings(monkeypatch) -> None:
    jsonl = (
        '{"template-id":"CVE-2021-1234","matched-at":"http://juice-shop:3000/x",'
        '"info":{"name":"Example RCE","severity":"high",'
        '"classification":{"cve-id":["CVE-2021-1234"]}}}\n'
        '\n'  # blank line is skipped
        'not-json-garbage\n'  # malformed line is skipped, not fatal
        '{"template-id":"tech-detect","matched-at":"http://juice-shop:3000",'
        '"info":{"name":"Tech","severity":"info"}}\n'
    )

    def _fake(*a, **k):
        return subprocess.CompletedProcess(args=a, returncode=0, stdout=jsonl, stderr="")

    monkeypatch.setattr(subprocess, "run", _fake)
    result = nuclei_runner.run("http://juice-shop:3000")
    assert "error" not in result
    findings = result["findings"]
    assert len(findings) == 2
    assert findings[0]["id"] == "CVE-2021-1234"
    assert findings[0]["cve"] == "CVE-2021-1234"
    assert findings[0]["severity"] == "high"
    assert findings[1]["cve"] is None


# ── _extract_cve ───────────────────────────────────────────────────────────────

def test_extract_cve_list() -> None:
    info = {"classification": {"cve-id": ["CVE-2020-0001", "CVE-2020-0002"]}}
    assert nuclei_runner._extract_cve(info) == "CVE-2020-0001"


def test_extract_cve_string() -> None:
    assert nuclei_runner._extract_cve({"classification": {"cve-id": "CVE-2020-9999"}}) == "CVE-2020-9999"


def test_extract_cve_absent() -> None:
    assert nuclei_runner._extract_cve({}) is None
    assert nuclei_runner._extract_cve({"classification": {"cve-id": []}}) is None
