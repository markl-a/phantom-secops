"""Tests for the secops_ids MCP server.

The wrapper adds x-phantom metadata and trims each alert's event payload
(caps alerts at max_alerts, truncates the Message excerpt). scan_intrusions is
mocked so no Windows event log is read — hermetic on every platform.
"""

from __future__ import annotations

from unittest.mock import patch

from phantom_secops.mcp import secops_ids_server as srv


def _alert(i, level="high"):
    return {
        "title": f"rule-{i}",
        "level": level,
        "event": {
            "EventID": 4104,
            "TimeCreated": "2026-06-17T00:00:00",
            "Channel": "PS",
            "Message": "x" * 1000,  # long message must be truncated
        },
    }


def test_metadata_is_blue_readonly_event_logs():
    md = next(t for t in srv.tool_definitions() if t.name == "scan_intrusions").metadata
    assert md["x-phantom.classification"] == "blue"
    assert "read.event_logs" in md["x-phantom.capabilities"]
    assert md["x-phantom.read_only"] is True


def test_impl_trims_event_to_excerpt():
    fake = {"alerts": [_alert(1)], "summary": {"total": 1},
            "scanned_logs": ["PS"], "events_read": 1}
    with patch.object(srv, "scan_intrusions", return_value=fake):
        out = srv.scan_intrusions_impl({})
    a = out["alerts"][0]
    assert set(a.keys()) == {"title", "level", "event_id", "time", "channel", "excerpt"}
    assert len(a["excerpt"]) == 200  # Message truncated to 200 chars
    assert a["event_id"] == 4104


def test_impl_caps_alerts_at_max():
    fake = {"alerts": [_alert(i) for i in range(50)], "summary": {"total": 50},
            "scanned_logs": ["PS"], "events_read": 50}
    with patch.object(srv, "scan_intrusions", return_value=fake):
        out = srv.scan_intrusions_impl({"max_alerts": 10})
    assert len(out["alerts"]) == 10


def test_impl_forwards_max_events():
    fake = {"alerts": [], "summary": {"total": 0}, "scanned_logs": [], "events_read": 0}
    with patch.object(srv, "scan_intrusions", return_value=fake) as m:
        srv.scan_intrusions_impl({"max_events": 123})
    m.assert_called_once_with(max_events=123)


def test_impl_handles_missing_message_gracefully():
    fake = {"alerts": [{"title": "t", "level": "high", "event": {"EventID": 1}}],
            "summary": {"total": 1}, "scanned_logs": ["PS"], "events_read": 1}
    with patch.object(srv, "scan_intrusions", return_value=fake):
        out = srv.scan_intrusions_impl({})
    assert out["alerts"][0]["excerpt"] == ""  # absent Message -> empty excerpt, no crash
