"""URL-decoded pattern matcher for log lines.

Extracted from scenarios/run_kill_chain.py so it can be wrapped as an
MCP tool without importing the full kill-chain orchestrator.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

PATTERNS: list[tuple[str, str, str]] = [
    ("traversal",  r"(\.\./|\.\.\\|/etc/passwd)",                              "high"),
    ("sqli",       r"(\bunion\b.*\bselect\b|\bor\s+1\s*=\s*1\b|\bsleep\s*\(\d)", "high"),
    ("xss",        r"(<script|onerror\s*=|javascript:)",                      "medium"),
    ("admin_path", r"/(administration|admin|wp-admin|\.git/|\.env|server-status)", "medium"),
    ("scanner",    r"(nikto|nmap|sqlmap|nuclei|burpsuite|wpscan)",            "low"),
]


def scan_log_lines(log_path: Path, max_lines: int = 10000, asset: str = "unknown") -> list[dict[str, Any]]:
    """Pattern-match a log file. Returns one alert dict per matching line.

    URL-decodes each line before matching so percent-encoded payloads are
    detected. Stops after `max_lines` lines.
    """
    if not log_path.exists():
        return []
    alerts: list[dict[str, Any]] = []
    text = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[:max_lines]
    for line in text:
        # unquote_plus so `+`-encoded spaces (form-encoding) decode like %20 —
        # otherwise `?id=1+or+1=1` evades the whitespace-bearing sqli pattern.
        decoded = unquote_plus(line)
        for category, pat, sev in PATTERNS:
            if re.search(pat, decoded, re.I):
                ip_m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})", line)
                alerts.append({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "source_ip": ip_m.group(1) if ip_m else "unknown",
                    "asset": asset,
                    "category": category,
                    "evidence": line[:200],
                    "severity_hint": sev,
                })
                break
    return alerts
