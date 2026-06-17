"""Honest-degradation tests for the kill-chain live path.

When docker/nmap/nuclei are unavailable the runners return {"error": ...}. The
orchestrator must NOT fake-green: the console and the written reports have to
flag the run as DEGRADED / INCOMPLETE rather than emitting a clean-looking
"0 open ports / 0 findings" report indistinguishable from a real clean scan.

All hermetic: the runners are injected to simulate the missing-tool case, so no
docker/network is touched.
"""

from __future__ import annotations

import argparse

import scenarios.run_kill_chain as rk


def _err_recon(*a, **k):
    return {"error": "could not launch docker: [Errno 2] No such file or directory",
            "target": "juice-shop"}


def _err_nuclei(url, *a, **k):
    return {"error": "could not launch docker: [Errno 2] No such file or directory",
            "target": url}


# ── _run_vuln_scan must surface per-endpoint errors, not silently drop them ─────

def test_run_vuln_scan_live_surfaces_runner_errors():
    recon = {"open_ports": [{"port": 3000, "service": "http"}]}
    out = rk._run_vuln_scan("juice-shop", recon, mock=False, nuclei_run=_err_nuclei)
    assert out["findings"] == []           # still no findings, no crash
    assert out.get("errors")               # ...but the failure is recorded
    assert any("docker" in e for e in out["errors"])


def test_run_vuln_scan_live_no_errors_key_when_healthy():
    recon = {"open_ports": [{"port": 3000, "service": "http"}]}
    out = rk._run_vuln_scan(
        "juice-shop", recon, mock=False,
        nuclei_run=lambda url: {"target": url, "findings": [{"id": "x", "severity": "high"}]},
    )
    assert out["findings"]
    assert not out.get("errors")           # healthy scan reports no degradation


# ── reports must flag a degraded run; a healthy one must not (no false alarm) ────

def test_degraded_live_pipeline_reports_are_not_fake_green(tmp_path, monkeypatch):
    monkeypatch.setattr(rk.nmap_runner, "run", _err_recon)
    monkeypatch.setattr(rk.nuclei_runner, "run", _err_nuclei)
    args = argparse.Namespace(target="juice-shop", mock=False, use_llm=False, out=None)
    _timeline, pentest, incident = rk._run_pipeline(args, tmp_path)

    assert "DEGRADED" in pentest
    assert "INCOMPLETE" in pentest.upper()
    # The actual tool error must be visible, not hidden behind a clean 0-count.
    assert "docker" in pentest.lower() or "unavailable" in pentest.lower()
    # Incident report (the run as a whole) is flagged degraded too.
    assert "DEGRADED" in incident


def test_healthy_live_pipeline_reports_have_no_degraded_banner(tmp_path, monkeypatch):
    monkeypatch.setattr(rk.nmap_runner, "run",
                        lambda *a, **k: {"target": "juice-shop",
                                         "open_ports": [{"port": 3000, "service": "http"}]})
    monkeypatch.setattr(rk.nuclei_runner, "run",
                        lambda url, *a, **k: {"target": url,
                                              "findings": [{"id": "t", "severity": "low"}]})
    args = argparse.Namespace(target="juice-shop", mock=False, use_llm=False, out=None)
    _timeline, pentest, incident = rk._run_pipeline(args, tmp_path)
    assert "DEGRADED" not in pentest
    assert "DEGRADED" not in incident


# ── end-to-end through the real CLI entrypoint: graceful + honest ───────────────

def test_main_live_degrades_honestly_when_tools_missing(capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(rk.nmap_runner, "run", _err_recon)
    monkeypatch.setattr(rk.nuclei_runner, "run", _err_nuclei)
    # No --mock => live path; --out keeps artifacts in tmp.
    monkeypatch.setattr("sys.argv", ["run_kill_chain.py", "--out", str(tmp_path)])

    rc = rk.main()
    assert rc == 0                                   # missing tools degrade, never crash

    out = capsys.readouterr().out
    assert "DEGRADED" in out                         # console honestly flags it
    pentest = (tmp_path / "pentest-report.md").read_text(encoding="utf-8")
    assert "DEGRADED" in pentest and "INCOMPLETE" in pentest.upper()
