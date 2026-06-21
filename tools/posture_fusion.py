"""Deterministic cross-tool endpoint-posture fusion.

Pillar-2 ships three independent scanners — ``audit_host()`` (host posture),
``scan_vulns()`` (CVEs) and ``scan_intrusions()`` (IDS alerts) — each with its
own severity vocabulary and each sorted only *within* its own output. The
README promises these are "unified into one prioritised, plain-language action
list", but until now that unification was done **only** by the LLM agent in
``checkup.ps1``. There was no deterministic combiner.

This module is that deterministic combiner. :func:`fuse_posture` normalises the
three vocabularies onto one common 0..4 scale and emits a single ranked list of
:class:`Action` items, highest risk first, with a stable deterministic tiebreak
``(severity, tool, id)``. No LLM, no network, no I/O — pure data in, ranked data
out.
"""

from __future__ import annotations

from dataclasses import dataclass

# Common 0..4 severity scale (4 == most urgent) and its display names.
SEVERITY_NAMES = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}

# Each tool's native severity vocabulary mapped onto the common 0..4 scale.
_VULN_SEVERITY = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
_IDS_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
_HOST_SEVERITY = {"high": 3, "medium": 2, "low": 1, "info": 0}

# Only failing/warning host checks are actionable; a passing/unknown/skipped
# check is informational and never becomes an action item.
_HOST_ACTIONABLE = {"fail", "warn"}

# Deterministic tiebreak among tools at equal normalised severity.
_TOOL_ORDER = {"vuln_scan": 0, "ids_scan": 1, "host_audit": 2}


def _sev_key(value, default: str) -> str:
    """Normalise a severity/level/status value to a lookup key string.

    Scanner findings normally carry string severities, but a malformed or
    externally-sourced finding (e.g. a Trivy JSON quirk) may carry an int, None
    or other type. The fusion step is the trusted deterministic spine — it must
    *degrade*, never crash with AttributeError on `.upper()`/`.lower()`. A
    missing/None/empty value falls back to ``default``; everything else is
    stringified so the dict lookup simply misses and maps to severity 0.
    """
    if value is None or value == "":
        return default
    return str(value)


@dataclass(frozen=True)
class Action:
    """One ranked, plain-language remediation item from a single source tool."""

    severity: int  # common 0..4 scale (4 == most urgent)
    severity_name: str  # critical | high | medium | low | info
    tool: str  # host_audit | vuln_scan | ids_scan
    id: str  # stable identifier within the source tool
    action: str  # plain-language recommended action


def _host_actions(host_findings: dict) -> list[Action]:
    actions: list[Action] = []
    for check in host_findings.get("checks", []):
        status = check.get("status", "")
        if status not in _HOST_ACTIONABLE:
            continue
        sev = _HOST_SEVERITY.get(_sev_key(check.get("severity"), "info"), 0)
        name = str(check.get("check", "?"))
        actions.append(
            Action(
                severity=sev,
                severity_name=SEVERITY_NAMES[sev],
                tool="host_audit",
                id=name,
                action=f"Harden host: {name} ({status}) - {check.get('detail', '')}",
            )
        )
    return actions


def _vuln_actions(vuln_findings: dict) -> list[Action]:
    actions: list[Action] = []
    for f in vuln_findings.get("findings", []):
        sev = _VULN_SEVERITY.get(_sev_key(f.get("severity"), "UNKNOWN").upper(), 0)
        vid = str(f.get("id", "?"))
        pkg = f.get("pkg", "?")
        fixed = f.get("fixed")
        if fixed:
            action = f"Update {pkg} {f.get('installed', '?')} -> {fixed} to fix {vid}"
        else:
            action = f"Patch {vid} in {pkg} (no fix available yet)"
        actions.append(
            Action(
                severity=sev,
                severity_name=SEVERITY_NAMES[sev],
                tool="vuln_scan",
                id=vid,
                action=action,
            )
        )
    return actions


def _ids_actions(ids_alerts: dict) -> list[Action]:
    actions: list[Action] = []
    for a in ids_alerts.get("alerts", []):
        sev = _IDS_SEVERITY.get(_sev_key(a.get("level"), "informational"), 0)
        title = str(a.get("title", "?"))
        actions.append(
            Action(
                severity=sev,
                severity_name=SEVERITY_NAMES[sev],
                tool="ids_scan",
                id=title,
                action=f"Investigate intrusion: {title}",
            )
        )
    return actions


def fuse_posture(host_findings: dict, vuln_findings: dict, ids_alerts: dict) -> list[Action]:
    """Combine the three scanners' findings into ONE ranked action list.

    Highest normalised severity first; ties broken deterministically by
    ``(tool order, id)``. Python's sort is stable, so items sharing the full
    key keep their original (already-deterministic) input order.
    """
    actions = _host_actions(host_findings) + _vuln_actions(vuln_findings) + _ids_actions(ids_alerts)
    actions.sort(key=lambda a: (-a.severity, _TOOL_ORDER.get(a.tool, 9), a.id))
    return actions
