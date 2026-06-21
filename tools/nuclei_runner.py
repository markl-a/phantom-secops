"""nuclei tool wrapper for the red-vuln-scan agent.

Runs nuclei inside the secops-attacker container with the public template
catalogue. Returns matched template IDs + severity for the agent to reason over.
"""

from __future__ import annotations

import json
import shlex
import subprocess
from typing import Any
from urllib.parse import urlsplit

ATTACKER_CONTAINER = "secops-attacker"

# Authoritative scope: only these hosts may be scanned. Keyed on the URL's
# hostname (exact match), never a substring of the whole URL — otherwise a host
# like evil.example.com/?next=juice-shop would slip through the gate.
LAB_HOSTS = ("juice-shop", "dvwa", "dvwa-db", "metasploitable", "attacker")


def run(
    target_url: str,
    severity: str = "low,medium,high,critical",
    timeout_s: int = 90,
    request_timeout_s: int = 10,
) -> dict[str, Any]:
    """Run nuclei against a lab URL. Returns parsed findings.

    `timeout_s` is the subprocess wall-clock budget (the hard kill). It is NOT
    the same as nuclei's own `-timeout`, which is the *per-request* connection
    timeout, controlled separately by `request_timeout_s`.
    """
    if not _is_lab_url(target_url):
        return {
            "error": f"refusing to scan '{target_url}' — must point at an in-lab host",
            "allowed_hosts": list(LAB_HOSTS),
        }

    # Coerce + clamp both timeouts so a non-int can't be interpolated raw into the
    # `bash -c` string (defense-in-depth alongside shlex.quote on the other args)
    # and a pathological value can't set an absurd subprocess timeout.
    try:
        timeout_s = int(timeout_s)
    except (TypeError, ValueError):
        return {"error": f"invalid timeout_s {timeout_s!r}; expected an integer", "target": target_url}
    timeout_s = max(1, min(timeout_s, 600))

    # nuclei's `-timeout` is the PER-REQUEST connection timeout (default 10s), NOT
    # the total scan budget. A real end-to-end run exposed the bug of passing the
    # whole wall-clock budget here: every slow/hanging request then waited for the
    # full budget, so the scan never finished and got killed mid-catalogue,
    # reporting a misleading "0 findings". Keep the per-request value small and
    # independent of the subprocess wall-clock guard above.
    try:
        request_timeout_s = int(request_timeout_s)
    except (TypeError, ValueError):
        return {"error": f"invalid request_timeout_s {request_timeout_s!r}; expected an integer", "target": target_url}
    request_timeout_s = max(1, min(request_timeout_s, 60))

    # nuclei JSONL output (-jsonl) — one finding per line.
    cmd = [
        "docker", "exec", ATTACKER_CONTAINER,
        "bash", "-c",
        # Note: 'nuclei' may not be preinstalled in the kali base; install on
        # first run or pre-bake the image. For the demo, fall back gracefully.
        f"command -v nuclei >/dev/null 2>&1 || "
        f"go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest >/dev/null 2>&1 || true; "
        f"nuclei -u {shlex.quote(target_url)} -severity {shlex.quote(severity)} "
        f"-jsonl -silent -timeout {request_timeout_s} 2>/dev/null",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 30)
    except subprocess.TimeoutExpired:
        return {"error": f"nuclei scan exceeded {timeout_s + 30}s timeout", "target": target_url}
    except OSError as exc:
        # docker binary missing / not on PATH (the offline case) — degrade to a
        # structured error so the kill-chain keeps running rather than crashing.
        return {"error": f"could not launch docker: {exc}", "target": target_url}

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


def _is_lab_url(url: str) -> bool:
    """True only if the URL's hostname is exactly a known lab service.

    Matching the hostname (not the raw URL) closes a gate-bypass where a lab
    service name in the path/query/subdomain of an external host would pass.
    """
    # urlsplit needs a scheme to populate .hostname; add a default if absent.
    parsed = urlsplit(url if "://" in url else f"//{url}", scheme="http")
    return parsed.hostname in LAB_HOSTS


def _extract_cve(info: dict[str, Any]) -> str | None:
    classification = info.get("classification") or {}
    cves = classification.get("cve-id") or []
    if isinstance(cves, list) and cves:
        return cves[0]
    if isinstance(cves, str):
        return cves
    return None
