"""Dependency / OS-package vulnerability scanning via Trivy.

Thin wrapper that runs Trivy through an injected ``run(args) -> CmdResult``
callable, normalises its JSON into findings, and prioritises them so the noisy
CVE list becomes an ordered, fixable-first queue. The LLM agent layer turns that
queue into plain-language remediation; this module is the deterministic part.
"""

from __future__ import annotations

import json
from typing import Callable

from tools.host_audit import CmdResult, _default_run

Run = Callable[[list], CmdResult]

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def parse_trivy(text: str) -> list[dict]:
    """Normalise Trivy JSON into a flat list of finding dicts."""
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return []
    findings: list[dict] = []
    for result in data.get("Results") or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities") or []:
            fixed = v.get("FixedVersion") or ""
            findings.append({
                "id": v.get("VulnerabilityID", ""),
                "pkg": v.get("PkgName", ""),
                "installed": v.get("InstalledVersion", ""),
                "fixed": fixed,
                "severity": (v.get("Severity") or "UNKNOWN").upper(),
                "title": v.get("Title", ""),
                "fixable": bool(fixed),
                "target": target,
            })
    return findings


def prioritize(findings: list[dict]) -> list[dict]:
    """Order findings by severity (desc) then fixable-first."""
    return sorted(
        findings,
        key=lambda f: (_SEVERITY_RANK.get(f.get("severity", "UNKNOWN"), 0),
                       1 if f.get("fixable") else 0),
        reverse=True,
    )


def _summary(findings: list[dict]) -> dict:
    counts = {s: 0 for s in _SEVERITY_RANK}
    fixable = 0
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        if f["fixable"]:
            fixable += 1
    counts["total"] = len(findings)
    counts["fixable"] = fixable
    return counts


def scan_vulns(path: str = ".", run: Run | None = None) -> dict:
    """Run Trivy over `path` and return prioritised, summarised findings."""
    # Trivy on a real codebase can take minutes — allow far more than the
    # default 30s used for quick host-posture commands.
    run = run or (lambda args: _default_run(args, timeout=600))
    r = run(["trivy", "fs", "--quiet", "--scanners", "vuln", "--format", "json", path])
    if r.code != 0:
        return {
            "scanned": path,
            "findings": [],
            "summary": _summary([]),
            "error": (r.err.strip() or r.out.strip() or f"trivy exited {r.code}")[:300],
        }
    findings = prioritize(parse_trivy(r.out))
    return {"scanned": path, "findings": findings, "summary": _summary(findings)}
