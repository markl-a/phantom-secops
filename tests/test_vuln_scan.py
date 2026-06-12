"""Tests for tools.vuln_scan — parse + prioritise Trivy output.

The scanner is invoked through an injected ``run(args) -> CmdResult`` callable,
so these tests use canned Trivy JSON and never shell out.
"""

from __future__ import annotations

from tools.host_audit import CmdResult
from tools.vuln_scan import parse_trivy, prioritize, scan_vulns


TRIVY_JSON = """
{
  "Results": [
    {
      "Target": "package-lock.json",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2021-1111", "PkgName": "lodash",
         "InstalledVersion": "4.17.0", "FixedVersion": "4.17.21",
         "Severity": "HIGH", "Title": "Prototype pollution"},
        {"VulnerabilityID": "CVE-2020-2222", "PkgName": "minimist",
         "InstalledVersion": "1.2.0", "FixedVersion": "",
         "Severity": "CRITICAL", "Title": "RCE"},
        {"VulnerabilityID": "CVE-2019-3333", "PkgName": "left-pad",
         "InstalledVersion": "1.0.0", "FixedVersion": "1.1.0",
         "Severity": "LOW", "Title": "DoS"}
      ]
    }
  ]
}
"""


def fixed_run(out="", code=0, err=""):
    return lambda args: CmdResult(code=code, out=out, err=err)


def test_parse_trivy_extracts_findings():
    fs = parse_trivy(TRIVY_JSON)
    assert len(fs) == 3
    f = next(x for x in fs if x["id"] == "CVE-2021-1111")
    assert f["pkg"] == "lodash"
    assert f["installed"] == "4.17.0"
    assert f["fixed"] == "4.17.21"
    assert f["severity"] == "CRITICAL" or f["severity"] == "HIGH"  # preserved
    assert f["severity"] == "HIGH"
    assert f["target"] == "package-lock.json"


def test_parse_trivy_marks_fixable():
    fs = {x["id"]: x for x in parse_trivy(TRIVY_JSON)}
    assert fs["CVE-2021-1111"]["fixable"] is True
    assert fs["CVE-2020-2222"]["fixable"] is False  # no FixedVersion


def test_parse_trivy_handles_null_vulnerabilities():
    fs = parse_trivy('{"Results":[{"Target":"x","Vulnerabilities":null}]}')
    assert fs == []


def test_parse_trivy_handles_empty():
    assert parse_trivy("{}") == []


def test_prioritize_orders_by_severity_then_fixable():
    fs = prioritize(parse_trivy(TRIVY_JSON))
    assert fs[0]["id"] == "CVE-2020-2222"   # CRITICAL first
    assert fs[-1]["id"] == "CVE-2019-3333"  # LOW last


def test_prioritize_fixable_wins_tie():
    items = [
        {"id": "A", "severity": "HIGH", "fixable": False},
        {"id": "B", "severity": "HIGH", "fixable": True},
    ]
    out = prioritize(items)
    assert out[0]["id"] == "B"  # same severity, fixable first


def test_scan_vulns_summarises():
    r = scan_vulns("somepath", run=fixed_run(out=TRIVY_JSON))
    assert r["summary"]["CRITICAL"] == 1
    assert r["summary"]["HIGH"] == 1
    assert r["summary"]["LOW"] == 1
    assert r["summary"]["total"] == 3
    assert r["summary"]["fixable"] == 2
    assert r["findings"][0]["severity"] == "CRITICAL"  # prioritised


def test_scan_vulns_reports_scanner_error():
    r = scan_vulns("somepath", run=fixed_run(out="", code=1, err="trivy not found"))
    assert "error" in r
    assert r["findings"] == []
