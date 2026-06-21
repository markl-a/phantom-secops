"""log_ingest tool wrapper for the blue-log-anomaly agent.

Tails Juice Shop / DVWA access logs, applies pattern matchers, and emits
JSONL alerts. Designed to be called repeatedly by the agent in a polling loop.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

LOG_DIR = Path(__file__).resolve().parent.parent / "reports" / "lab-logs"
ALERTS_FILE = LOG_DIR / "alerts.jsonl"

# Lightweight signature patterns. Real systems use much more, but this is the
# demo set — easy to read, easy to extend.
PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("traversal",  re.compile(r"(\.\./|%2e%2e|\.\.\\)"), "high"),
    ("sqli",       re.compile(r"(\bunion\b.*\bselect\b|or\s+1=1|sleep\(\d)", re.I), "high"),
    ("xss",        re.compile(r"(<script|onerror=|javascript:)", re.I), "medium"),
    ("admin_path", re.compile(r"/(admin|wp-admin|phpmyadmin|\.git/|\.env|server-status)"), "medium"),
    ("scanner_ua", re.compile(r"(nikto|nmap|sqlmap|nuclei|burpsuite|wpscan)", re.I), "low"),
]


def scan_window(
    window_seconds: int = 30,
    *,
    log_dir: Path | None = None,
    alerts_file: Path | None = None,
    write: bool = True,
) -> dict[str, Any]:  # noqa: ARG001  (window_seconds kept for caller API compatibility)
    """Read recent log lines, emit alerts to the alerts journal.

    `log_dir` / `alerts_file` default to the module-level LOG_DIR / ALERTS_FILE
    (resolved at call time so existing monkeypatch-based tests keep working).
    Callers such as the kill-chain orchestrator pass their own paths to scan a
    fixture dir and journal into a per-run file. `write=False` scans in memory
    without touching disk. The returned dict also carries the matched `alerts`
    so a caller can feed them straight into triage without re-reading the journal.
    """
    scan_dir = LOG_DIR if log_dir is None else Path(log_dir)
    journal = ALERTS_FILE if alerts_file is None else Path(alerts_file)
    alerts: list[dict[str, Any]] = []

    for log_file in scan_dir.glob("*.log"):
        if not log_file.exists():
            continue
        # Quick last-N-lines read; for production use rotating tail offsets.
        try:
            recent_lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()[-500:]
        except OSError:
            continue

        for line in recent_lines:
            # URL-decode before matching so percent-encoded payloads (e.g.
            # %3Cscript%3E, union%20select, %2e%2e%2f) are detected. Without this
            # an attacker trivially evades the raw-line patterns by URL-encoding —
            # the sibling matcher tools.log_anomaly already decodes; this aligns
            # log_ingest (which the kill-chain blue path runs) with it.
            # unquote_plus (not unquote) so the form-encoding `+`=space variant
            # (e.g. `?id=1+or+1=1`) decodes to `1 or 1=1` and is caught too.
            decoded = unquote_plus(line)
            for category, pattern, severity_hint in PATTERNS:
                m = pattern.search(line) or pattern.search(decoded)
                if not m:
                    continue
                alerts.append({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "source_ip": _extract_ip(line),
                    "asset": log_file.stem,
                    "category": category,
                    "evidence": line[:300],
                    "severity_hint": severity_hint,
                })

    if write and alerts:
        journal.parent.mkdir(parents=True, exist_ok=True)
        with journal.open("a", encoding="utf-8") as out:
            for a in alerts:
                out.write(json.dumps(a, ensure_ascii=False) + "\n")

    return {
        "alerts_emitted": len(alerts),
        "alerts_file": str(journal),
        "window_seconds": window_seconds,
        "alerts": alerts,
    }


def _extract_ip(line: str) -> str:
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})", line)
    return m.group(1) if m else "unknown"
