"""A small Sigma-style detection engine over Windows event logs (host IDS).

"Don't build the engine, build the brain": this evaluates Sigma-format detection
rules against events read from the Windows event log. It supports a practical
subset of the Sigma `detection` spec — named selection blocks, the common field
modifiers (contains/startswith/endswith/re), and conditions of the form
`selection`, `a and not b`, `a or b`, `1 of x_*`, `all of x_*`.

Without Sysmon installed (which needs admin) the richest source is the
PowerShell Operational log (Event 4104 script-block text) — readable without
elevation and where a lot of real attacker activity shows up.
"""

from __future__ import annotations

import json
import re
from typing import Callable

from tools.host_audit import CmdResult, _default_run, _ps

Run = Callable[[list], CmdResult]

_LEVEL_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}


# ── Sigma matching ────────────────────────────────────────────────────────────

def _cmp(actual, expected, mod: str | None) -> bool:
    if mod is None:
        if actual == expected:
            return True
        return str(actual).lower() == str(expected).lower()
    a, e = str(actual).lower(), str(expected).lower()
    if mod == "contains":
        return e in a
    if mod == "startswith":
        return a.startswith(e)
    if mod == "endswith":
        return a.endswith(e)
    if mod == "re":
        try:
            return re.search(str(expected), str(actual), re.IGNORECASE) is not None
        except re.error:
            return False
    return False


def _match_field(key: str, expected, event: dict) -> bool:
    field, mod = (key.split("|", 1) + [None])[:2] if "|" in key else (key, None)
    actual = event.get(field)
    if actual is None:
        return False
    candidates = expected if isinstance(expected, list) else [expected]
    return any(_cmp(actual, e, mod) for e in candidates)


def _match_block(block: dict, event: dict) -> bool:
    return all(_match_field(k, v, event) for k, v in block.items())


def _eval_condition(cond: str, blocks: dict) -> bool:
    cond = (cond or "selection").strip()
    m = re.fullmatch(r"(1|all)\s+of\s+(.+)", cond)
    if m:
        quant, pat = m.group(1), m.group(2).strip()
        if pat == "them":
            names = list(blocks)
        elif pat.endswith("*"):
            names = [n for n in blocks if n.startswith(pat[:-1])]
        else:
            names = [n for n in blocks if n == pat]
        vals = [blocks[n] for n in names]
        return any(vals) if quant == "1" else (bool(vals) and all(vals))
    expr = cond
    for name in sorted(blocks, key=len, reverse=True):
        expr = re.sub(rf"\b{re.escape(name)}\b", str(blocks[name]), expr)
    # any leftover identifier that isn't a known keyword/literal → unmatched block
    expr = re.sub(r"\b(?!True\b|False\b|and\b|or\b|not\b)[A-Za-z_]\w*\b", "False", expr)
    try:
        return bool(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 — sanitised booleans only
    except Exception:  # noqa: BLE001
        return False


def match_event(detection: dict, event: dict) -> bool:
    """True if a Sigma `detection` block matches an event dict."""
    blocks = {name: _match_block(blk, event)
              for name, blk in detection.items() if name != "condition"}
    return _eval_condition(detection.get("condition", "selection"), blocks)


# ── Bundled rules (common Windows / PowerShell attacker TTPs) ──────────────────

BUNDLED_RULES: list[dict] = [
    {
        "title": "Mimikatz / credential dumping indicators",
        "level": "critical",
        "detection": {
            "selection": {"Message|contains": [
                "mimikatz", "sekurlsa", "Invoke-Mimikatz", "logonpasswords",
                "lsadump", "DumpCreds"]},
            "condition": "selection",
        },
    },
    {
        # Download method AND in-memory exec together — the classic cradle. Kept
        # tight (exec = iex/invoke-expression only) to avoid firing on the many
        # legit scripts that use `&(` or `icm`.
        "title": "PowerShell download-and-execute cradle",
        "level": "high",
        "detection": {
            "selection_net": {"Message|contains": [
                "downloadstring", "downloadfile", "downloaddata", "net.webclient",
                "invoke-webrequest", "start-bitstransfer"]},
            "selection_exec": {"Message|contains": ["iex", "invoke-expression"]},
            # Exclude PowerShell module manifests (.psd1) — they always carry
            # ModuleVersion and routinely mention web types + Invoke-Expression.
            "filter_manifest": {"Message|contains": ["moduleversion"]},
            "condition": "selection_net and selection_exec and not filter_manifest",
        },
    },
    {
        "title": "Encoded / obfuscated PowerShell command",
        "level": "high",
        "detection": {
            "selection": {"Message|contains": [
                "-enc ", "-encodedcommand", "frombase64string", "-e jab", "-ec "]},
            "condition": "selection",
        },
    },
    {
        "title": "AMSI bypass attempt",
        "level": "high",
        "detection": {
            "selection": {"Message|contains": [
                "amsiInitFailed", "amsiutils", "amsicontext",
                "System.Management.Automation.AmsiUtils"]},
            "condition": "selection",
        },
    },
    {
        "title": "Suspicious execution-policy / hidden-window launch",
        "level": "medium",
        "detection": {
            "selection": {"Message|contains": [
                "-windowstyle hidden", "-w hidden", "executionpolicy bypass",
                "-ep bypass", "-nop -", "-noprofile -enc"]},
            "condition": "selection",
        },
    },
]


# ── Orchestration ─────────────────────────────────────────────────────────────

def scan_events(events: list[dict], rules: list[dict]) -> list[dict]:
    """Match every rule against every event; return alerts, highest level first."""
    alerts = []
    for ev in events:
        for rule in rules:
            if match_event(rule["detection"], ev):
                alerts.append({
                    "title": rule["title"],
                    "level": rule.get("level", "medium"),
                    "event": ev,
                })
    alerts.sort(key=lambda a: _LEVEL_RANK.get(a["level"], 0), reverse=True)
    return alerts


def read_events(run: Run,
                log: str = "Microsoft-Windows-PowerShell/Operational",
                max_events: int = 500) -> list[dict]:
    """Read recent events from a Windows log into field dicts via Get-WinEvent."""
    cmd = _ps(
        f"Get-WinEvent -FilterHashtable @{{LogName='{log}'}} -MaxEvents {int(max_events)} "
        "-ErrorAction SilentlyContinue | Select-Object "
        "@{n='EventID';e={$_.Id}}, "
        "@{n='TimeCreated';e={$_.TimeCreated.ToString('o')}}, "
        "@{n='Channel';e={$_.LogName}}, Message | ConvertTo-Json -Depth 3"
    )
    r = run(cmd)
    if r.code != 0 or not r.out.strip():
        return []
    try:
        data = json.loads(r.out)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        return [data]
    return data if isinstance(data, list) else []


def _alert_summary(alerts: list[dict]) -> dict:
    counts = {lvl: 0 for lvl in _LEVEL_RANK}
    for a in alerts:
        counts[a["level"]] = counts.get(a["level"], 0) + 1
    counts["total"] = len(alerts)
    return counts


def scan_intrusions(run: Run | None = None,
                    logs: list[str] | None = None,
                    max_events: int = 500) -> dict:
    """Read recent events from the given logs and match the bundled Sigma rules."""
    run = run or (lambda args: _default_run(args, timeout=120))
    logs = logs or ["Microsoft-Windows-PowerShell/Operational", "System"]
    events: list[dict] = []
    for log in logs:
        events.extend(read_events(run, log=log, max_events=max_events))
    alerts = scan_events(events, BUNDLED_RULES)
    return {
        "alerts": alerts,
        "summary": _alert_summary(alerts),
        "scanned_logs": logs,
        "events_read": len(events),
    }
