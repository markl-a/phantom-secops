"""nuclei tool wrapper for the red-vuln-scan agent.

Runs nuclei inside the secops-attacker container with the public template
catalogue. Returns matched template IDs + severity for the agent to reason over.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from phantom_secops.mcp import safety  # noqa: E402

ATTACKER_CONTAINER = "secops-attacker"


def run(target_url: str, severity: str = "low,medium,high,critical", timeout_s: int = 90) -> dict[str, Any]:
    """Run nuclei against a lab URL. Returns parsed findings."""
    if not safety.is_lab_url(target_url):
        return {
            "error": f"refusing to scan '{target_url}' — must point at an in-lab host",
            "allowed_hosts": list(safety.KNOWN_LAB_SERVICES),
        }

    # nuclei JSONL output (-jsonl) — one finding per line.
    cmd = [
        "docker", "exec", ATTACKER_CONTAINER,
        "bash", "-c",
        # Note: 'nuclei' may not be preinstalled in the kali base; install on
        # first run or pre-bake the image. For the demo, fall back gracefully.
        f"command -v nuclei >/dev/null 2>&1 || "
        f"go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest >/dev/null 2>&1 || true; "
        f"nuclei -u {shlex.quote(target_url)} -severity {shlex.quote(severity)} "
        f"-jsonl -silent -timeout {timeout_s} 2>/dev/null",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 30)
    except subprocess.TimeoutExpired:
        return {"error": f"nuclei scan exceeded {timeout_s + 30}s timeout", "target": target_url}

    findings: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = finding.get("info", {})
        findings.append({
            "id": finding.get("template-id"),
            "cve": _extract_cve(info),
            "severity": info.get("severity"),
            "title": info.get("name"),
            "evidence": finding.get("matched-at"),
            "tool": "nuclei",
            "raw": json.dumps(finding)[:400],
        })

    return {
        "target": target_url,
        "findings": findings,
    }


def _extract_cve(info: dict[str, Any]) -> str | None:
    classification = info.get("classification") or {}
    cves = classification.get("cve-id") or []
    if isinstance(cves, list) and cves:
        return cves[0]
    if isinstance(cves, str):
        return cves
    return None
