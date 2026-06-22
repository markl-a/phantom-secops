from tools.mcp_audit import Finding, SEVERITY_NAMES, summarize


def test_finding_is_frozen_with_expected_fields():
    f = Finding(severity=4, severity_name="critical", rule_id="r", server="s",
                tool="t", owasp="tool-poisoning", message="m")
    assert (f.severity, f.rule_id, f.owasp) == (4, "r", "tool-poisoning")
    assert SEVERITY_NAMES[4] == "critical" and SEVERITY_NAMES[0] == "info"


def test_summarize_counts_by_severity_name():
    fs = [
        Finding(4, "critical", "a", "s", "t", "o", "m"),
        Finding(2, "medium", "b", "s", "t", "o", "m"),
        Finding(4, "critical", "c", "s", "t", "o", "m"),
    ]
    s = summarize(fs)
    assert s["total"] == 3 and s["critical"] == 2 and s["medium"] == 1 and s["low"] == 0
