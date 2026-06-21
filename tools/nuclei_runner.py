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
    #
    # `timeout_s` is the subprocess wall-clock guard. `request_timeout_s` is
    # nuclei's PER-REQUEST connection timeout (default 10s) — a real end-to-end
    # run exposed the bug of passing the whole wall-clock budget here: every
    # slow/hanging request then waited for the full budget, so the scan never
    # finished and got killed mid-catalogue, reporting a misleading "0 findings".
    timeout_s, err = _coerce_int(timeout_s, "timeout_s", 1, 600)
    if err:
        return {"error": err, "target": target_url}
    request_timeout_s, err = _coerce_int(request_timeout_s, "request_timeout_s", 1, 60)
    if err:
        return {"error": err, "target": target_url}

    # nuclei JSONL output (-jsonl) — one finding per line. nuclei is pre-baked
    # into the attacker image (see Dockerfile.attacker), so we invoke it directly
    # — no runtime `go install` fallback, which the image has no Go toolchain for
    # anyway and whose `|| true` would silently mask a missing binary as a clean
    # "0 findings" scan (the exact false-green this tool exists to avoid).
    cmd = [
        "docker", "exec", ATTACKER_CONTAINER,
        "bash", "-c",
        f"nuclei -u {shlex.quote(target_url)} -severity {shlex.quote(severity)} "
        f"-jsonl -silent -timeout {request_timeout_s}",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 30)
    except subprocess.TimeoutExpired as exc:
        # Don't discard partial output: nuclei streams JSONL findings as it scans,
        # so a run killed at the wall-clock budget may already have real findings
        # in exc.stdout. Surface them alongside the timeout note rather than a
        # misleading empty result.
        out: dict[str, Any] = {
            "error": f"nuclei scan exceeded {timeout_s + 30}s timeout", "target": target_url,
        }
        partial = _parse_findings(exc.stdout) if isinstance(exc.stdout, str) else []
        if partial:
            out["findings"] = partial
        return out
    except OSError as exc:
        # docker binary missing / not on PATH (the offline case) — degrade to a
        # structured error so the kill-chain keeps running rather than crashing.
        return {"error": f"could not launch docker: {exc}", "target": target_url}

    # A missing nuclei binary (or a docker/exec failure) produces no stdout and a
    # non-zero exit. Surface it as an error rather than returning empty findings,
    # which would read as a clean scan. nuclei exits 0 on a successful scan even
    # with zero matches, so this only trips on a genuine failure to run.
    if result.returncode != 0 and not result.stdout.strip():
        return {
            "error": f"nuclei did not run (exit {result.returncode}): "
                     f"{result.stderr.strip()[:300] or 'no output'}",
            "target": target_url,
        }

    return {
        "target": target_url,
        "findings": _parse_findings(result.stdout),
    }


def _coerce_int(value: Any, name: str, lo: int, hi: int) -> tuple[int | None, str | None]:
    """Coerce `value` to an int clamped to [lo, hi].

    Returns (clamped_int, None) on success or (None, error_message) if `value`
    isn't int-like — so a non-int can never be interpolated raw into the
    `bash -c` string. Shared by the two timeout parameters.
    """
    try:
        v = int(value)
    except (TypeError, ValueError):
        return None, f"invalid {name} {value!r}; expected an integer"
    return max(lo, min(v, hi)), None


def _parse_findings(stdout: str) -> list[dict[str, Any]]:
    """Parse nuclei JSONL stdout (one finding per line) into compact findings.

    Tolerant of blank/garbage lines. Reused by both the normal path and the
    timeout path (which parses whatever nuclei streamed before being killed).
    """
    findings: list[dict[str, Any]] = []
    for line in stdout.splitlines():
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
    return findings


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
