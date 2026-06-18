"""Anti-fake-green proof: the kill-chain orchestrator GENUINELY runs
tools.log_ingest.scan_window in its blue path.

log_ingest was previously dead code from run_kill_chain.py's perspective: the
orchestrator's blue path called log_anomaly.scan_log_lines, and scan_window was
only reachable through the standalone MCP server. These are END-TO-END scenario
tests that run the whole mock pipeline via _run_pipeline and prove (a) scan_window
is actually called, (b) it journals its findings into the run dir, and (c) those
findings flow into the blue alert stream that triage consumes -- proven via the
`scanner_ua` category, which ONLY log_ingest emits (log_anomaly uses `scanner`).
They are NOT scan_window-in-isolation tests.
"""

from __future__ import annotations

import argparse
import json

from scenarios import run_kill_chain as rk
from tools import log_ingest


def _alerts(path):
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def test_kill_chain_blue_path_exercises_log_ingest_scan_window(tmp_path, monkeypatch):
    calls: list[dict] = []
    real = log_ingest.scan_window

    def spy(*args, **kwargs):
        calls.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(log_ingest, "scan_window", spy)

    args = argparse.Namespace(target="juice-shop", mock=True, use_llm=False, out=None)
    rk._run_pipeline(args, tmp_path)

    # (a) the orchestrator actually called scan_window during the run
    assert calls, "kill-chain blue path must call log_ingest.scan_window (no longer dead code)"

    # (b) scan_window journaled its findings into the run dir
    journal = tmp_path / "ingest-journal.jsonl"
    assert journal.exists(), "scan_window must write its per-run journal"
    journal_alerts = _alerts(journal)
    assert journal_alerts, "the ingest journal must contain alerts"

    # (c) its output flows into the blue alert stream that triage consumes.
    # `scanner_ua` is emitted ONLY by log_ingest (log_anomaly uses `scanner`),
    # so finding it in the merged alerts proves scan_window's output reached blue.
    alerts = _alerts(tmp_path / "alerts.jsonl")
    assert any(a["category"] == "scanner_ua" for a in alerts), \
        "log_ingest.scan_window output (scanner_ua) must appear in the blue alerts"
    assert any(a["category"] == "scanner_ua" for a in journal_alerts)


def test_mock_pipeline_log_ingest_is_deterministic(tmp_path, monkeypatch):
    """Same fixtures -> identical ingest journal across runs (mock determinism).

    Compares the category sequence (the alert `ts` is wall-clock and intentionally
    excluded), so a green here means the wiring did not introduce nondeterminism.
    """
    def run(name):
        d = tmp_path / name
        d.mkdir()
        args = argparse.Namespace(target="juice-shop", mock=True, use_llm=False, out=None)
        rk._run_pipeline(args, d)
        return [a["category"] for a in _alerts(d / "ingest-journal.jsonl")]

    first = run("r1")
    second = run("r2")
    assert first and first == second, "ingest journal categories must be identical run-to-run"
