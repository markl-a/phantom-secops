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


def test_scan_window_detects_url_encoded_xss(monkeypatch, tmp_path):
    # An attacker can trivially URL-encode the payload to evade raw-line matching.
    # The scanner must URL-decode before matching (as tools.log_anomaly does), or
    # the blue path silently misses the attack. Regression guard for that gap.
    log_dir, alerts_file = _redirect(monkeypatch, tmp_path)
    (log_dir / "enc.log").write_text(
        "9.9.9.9 - - GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E\n",
        encoding="utf-8",
    )
    result = log_ingest.scan_window()
    assert result["alerts_emitted"] == 1
    a = json.loads(alerts_file.read_text(encoding="utf-8").strip())
    assert a["category"] == "xss"
    assert a["severity_hint"] == "medium"
    # evidence keeps the raw (still-encoded) line as it actually appeared in the log
    assert "%3Cscript%3E" in a["evidence"]


def test_scan_window_detects_url_encoded_sqli_and_traversal(monkeypatch, tmp_path):
    log_dir, _ = _redirect(monkeypatch, tmp_path)
    (log_dir / "enc2.log").write_text(
        # union%20select  and  ..%2f..%2fetc encodings
        "9.9.9.9 - - GET /rest?q=union%20select%20password%20from%20users\n"
        "8.8.8.8 - - GET /file?p=%2e%2e%2f%2e%2e%2fwinini\n",
        encoding="utf-8",
    )
    result = log_ingest.scan_window()
    assert result["alerts_emitted"] == 2


def test_scan_window_plain_text_attack_still_detected(monkeypatch, tmp_path):
    # Decoding must not regress detection of un-encoded payloads.
    log_dir, _ = _redirect(monkeypatch, tmp_path)
    (log_dir / "plain.log").write_text(
        "7.7.7.7 - - GET /page?file=../../etc/passwd\n", encoding="utf-8"
    )
    result = log_ingest.scan_window()
    assert result["alerts_emitted"] == 1


def test_scan_window_detects_plus_encoded_sqli(monkeypatch, tmp_path):
    # `+`=space is the standard application/x-www-form-urlencoded evasion. plain
    # unquote leaves `+` literal, so the whitespace-bearing sqli pattern misses
    # `id=1+or+1=1`; only unquote_plus reconstructs `1 or 1=1`. Regression guard.
    log_dir, alerts_file = _redirect(monkeypatch, tmp_path)
    (log_dir / "plus.log").write_text(
        "9.9.9.9 - - GET /rest/products?id=1+or+1=1\n", encoding="utf-8",
    )
    result = log_ingest.scan_window()
    assert result["alerts_emitted"] == 1
    a = json.loads(alerts_file.read_text(encoding="utf-8").strip())
    assert a["category"] == "sqli"
