"""Tests for the secops_vuln MCP server.

The wrapper adds x-phantom metadata and, importantly, compacts the underlying
Trivy result to a token-budget-friendly shape (drops long titles, caps findings
at max_findings). scan_vulns is mocked so Trivy is never invoked — hermetic.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from phantom_secops.mcp import secops_vuln_server as srv


def _finding(i, sev="HIGH"):
    return {"id": f"CVE-{i}", "pkg": f"pkg{i}", "installed": "1.0", "fixed": "1.1",
            "severity": sev, "title": "a very long title " * 10, "fixable": True,
            "target": "package-lock.json"}


def test_metadata_is_blue_readonly():
    md = next(t for t in srv.tool_definitions() if t.name == "scan_vulns").metadata
    assert md["x-phantom.classification"] == "blue"
    assert md["x-phantom.read_only"] is True


def test_impl_compacts_findings_and_drops_title():
    fake = {"scanned": "/x", "summary": {"total": 3},
            "findings": [_finding(1), _finding(2), _finding(3)]}
    with patch.object(srv, "scan_vulns", return_value=fake):
        out = srv.scan_vulns_impl({"path": "/x"})
    # title is dropped; only the compact keys survive
    assert set(out["findings"][0].keys()) == {"id", "pkg", "installed", "fixed", "severity"}
    assert "title" not in out["findings"][0]


def test_impl_caps_findings_at_max():
    fake = {"scanned": "/x", "summary": {"total": 30},
            "findings": [_finding(i) for i in range(30)]}
    with patch.object(srv, "scan_vulns", return_value=fake):
        out = srv.scan_vulns_impl({"path": "/x", "max_findings": 5})
    assert len(out["findings"]) == 5


def test_impl_default_max_findings_is_15():
    fake = {"scanned": "/x", "summary": {"total": 40},
            "findings": [_finding(i) for i in range(40)]}
    with patch.object(srv, "scan_vulns", return_value=fake):
        out = srv.scan_vulns_impl({"path": "/x"})
    assert len(out["findings"]) == 15


def test_impl_forwards_path_to_scanner():
    fake = {"scanned": "/proj", "summary": {}, "findings": []}
    with patch.object(srv, "scan_vulns", return_value=fake) as m:
        srv.scan_vulns_impl({"path": "/proj"})
    m.assert_called_once_with("/proj")


def test_impl_requires_path():
    with pytest.raises(KeyError):
        srv.scan_vulns_impl({})
