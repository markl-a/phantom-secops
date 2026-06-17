"""Tests for tools.log_ingest — the blue-team polling log scanner.

log_ingest reads *.log files under LOG_DIR, pattern-matches each line, and
appends alert JSONL to ALERTS_FILE. These tests redirect both paths to a tmp
dir so nothing touches the repo's real reports/ tree — fully hermetic, no
network, no real log tailing.
"""

from __future__ import annotations

import json

from tools import log_ingest


def _redirect(monkeypatch, tmp_path):
    log_dir = tmp_path / "lab-logs"
    log_dir.mkdir()
    alerts_file = log_dir / "alerts.jsonl"
    monkeypatch.setattr(log_ingest, "LOG_DIR", log_dir)
    monkeypatch.setattr(log_ingest, "ALERTS_FILE", alerts_file)
    return log_dir, alerts_file


def test_extract_ip_from_access_log_line():
    assert log_ingest._extract_ip("203.0.113.7 - - [x] GET /") == "203.0.113.7"
    assert log_ingest._extract_ip("no ip here") == "unknown"


def test_scan_window_no_logs_emits_nothing(monkeypatch, tmp_path):
    _redirect(monkeypatch, tmp_path)
    result = log_ingest.scan_window()
    assert result["alerts_emitted"] == 0


def test_scan_window_matches_sqli_and_writes_jsonl(monkeypatch, tmp_path):
    log_dir, alerts_file = _redirect(monkeypatch, tmp_path)
    (log_dir / "juice-shop.log").write_text(
        "203.0.113.7 - - GET /rest/products?q=1' UNION SELECT password FROM users\n"
        "198.51.100.2 - - GET /index.html\n",
        encoding="utf-8",
    )
    result = log_ingest.scan_window()
    assert result["alerts_emitted"] == 1
    lines = [json.loads(l) for l in alerts_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 1
    a = lines[0]
    assert a["category"] == "sqli"
    assert a["source_ip"] == "203.0.113.7"
    assert a["asset"] == "juice-shop"
    assert a["severity_hint"] == "high"


def test_scan_window_detects_traversal_and_xss(monkeypatch, tmp_path):
    log_dir, _ = _redirect(monkeypatch, tmp_path)
    (log_dir / "dvwa.log").write_text(
        "10.0.0.1 - - GET /page?file=../../etc/passwd\n"
        "10.0.0.2 - - GET /search?q=<script>alert(1)</script>\n",
        encoding="utf-8",
    )
    result = log_ingest.scan_window()
    assert result["alerts_emitted"] == 2


def test_scan_window_appends_across_calls(monkeypatch, tmp_path):
    log_dir, alerts_file = _redirect(monkeypatch, tmp_path)
    (log_dir / "x.log").write_text("1.1.1.1 - GET /admin\n", encoding="utf-8")
    log_ingest.scan_window()
    log_ingest.scan_window()
    lines = [l for l in alerts_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 2  # second call appends, does not truncate


def test_scan_window_only_reads_last_500_lines(monkeypatch, tmp_path):
    log_dir, _ = _redirect(monkeypatch, tmp_path)
    benign = "\n".join("10.0.0.9 - - GET /ok" for _ in range(600))
    attack = "10.0.0.9 - - GET /admin\n"
    (log_dir / "big.log").write_text(benign + "\n" + attack, encoding="utf-8")
    result = log_ingest.scan_window()
    # only the last 500 lines are inspected; the attack is within that window
    assert result["alerts_emitted"] == 1


def test_scan_window_scanner_ua_is_low(monkeypatch, tmp_path):
    log_dir, alerts_file = _redirect(monkeypatch, tmp_path)
    (log_dir / "y.log").write_text('8.8.8.8 - - GET / "Mozilla nikto/2.1"\n', encoding="utf-8")
    log_ingest.scan_window()
    a = json.loads(alerts_file.read_text(encoding="utf-8").strip())
    assert a["category"] == "scanner_ua"
    assert a["severity_hint"] == "low"


def test_scan_window_does_not_create_alerts_file_when_clean(monkeypatch, tmp_path):
    log_dir, alerts_file = _redirect(monkeypatch, tmp_path)
    (log_dir / "clean.log").write_text("1.2.3.4 - - GET /home\n", encoding="utf-8")
    log_ingest.scan_window()
    assert not alerts_file.exists()  # no alerts => no file written
