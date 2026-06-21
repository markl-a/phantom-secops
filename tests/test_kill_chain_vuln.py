"""Tests for the live vuln-scan wiring (nuclei) in the kill-chain orchestrator.

The orchestrator's live path is exercised with an injected nuclei runner, so the
wiring is tested without docker; the actual live run stays gated on the lab.
"""

from __future__ import annotations

import scenarios.run_kill_chain as rk
from scenarios.run_kill_chain import _http_targets, _run_vuln_scan


def test_http_targets_picks_http_ports():
    recon = {"open_ports": [
        {"port": 3000, "service": "http"},
        {"port": 22, "service": "ssh"},
    ]}
    urls = _http_targets("juice-shop", recon)
    assert "http://juice-shop:3000" in urls
    assert all(":22" not in u for u in urls)


def test_http_targets_https_scheme():
    recon = {"open_ports": [{"port": 443, "service": "https"}]}
    assert _http_targets("dvwa", recon) == ["https://dvwa:443"]


def test_http_targets_fallback_when_no_http():
    recon = {"open_ports": [{"port": 22, "service": "ssh"}]}
    assert _http_targets("juice-shop", recon) == ["http://juice-shop"]


def test_run_vuln_scan_live_aggregates_nuclei_findings():
    recon = {"open_ports": [{"port": 3000, "service": "http"}]}
    calls = []

    def fake_nuclei(url):
        calls.append(url)
        return {"target": url, "findings": [{"id": "tpl-1", "severity": "high"}]}

    out = _run_vuln_scan("juice-shop", recon, mock=False, nuclei_run=fake_nuclei)
    assert calls == ["http://juice-shop:3000"]
    assert len(out["findings"]) == 1
    assert out["findings"][0]["id"] == "tpl-1"


def test_run_vuln_scan_live_tolerates_runner_error():
    recon = {"open_ports": [{"port": 3000, "service": "http"}]}
    out = _run_vuln_scan("juice-shop", recon, mock=False,
                         nuclei_run=lambda url: {"error": "nuclei not installed"})
    assert out["findings"] == []          # error → no findings, no crash


def test_run_vuln_scan_mock_reads_canned_fixture():
    out = _run_vuln_scan("juice-shop", {}, mock=True)
    assert "findings" in out and len(out["findings"]) > 0


def test_run_vuln_scan_threads_severity_to_default_runner(monkeypatch):
    """--severity must reach the real nuclei runner so a target with lower-
    severity fingerprintable issues (e.g. dvwa) isn't forced to the default."""
    captured = {}

    def _capture(url, **kw):
        captured.update(kw)
        return {"target": url, "findings": []}

    monkeypatch.setattr(rk.nuclei_runner, "run", _capture)
    recon = {"open_ports": [{"port": 3000, "service": "http"}]}
    _run_vuln_scan("juice-shop", recon, mock=False, severity="medium,high,critical")
    assert captured.get("severity") == "medium,high,critical"
