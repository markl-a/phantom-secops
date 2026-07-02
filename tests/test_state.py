from __future__ import annotations

import json

from secops_mcp.state import KillChainState


class TestKillChainState:
    def test_fresh_state_defaults(self):
        s = KillChainState()
        assert s.target == "juice-shop"
        assert s.mock is True
        assert s.clock == {"red": 0.0, "blue": 0.0}
        assert s.timeline == []
        assert s.recon is None
        assert s.vuln is None
        assert s.alerts is None

    def test_now_returns_clock_for_side(self):
        s = KillChainState()
        assert s.now("red") == 0.0
        assert s.now("blue") == 0.0

    def test_advance_increments_clock(self):
        s = KillChainState()
        s.advance("red", 10.0)
        assert s.clock["red"] == 10.0
        s.advance("red", 5.0)
        assert s.clock["red"] == 15.0

    def test_event_records_timestamp_before_advance(self):
        s = KillChainState()
        t = s.event("red", "scan start", advance=10.0)
        assert t == 0.0
        assert s.clock["red"] == 10.0
        assert s.timeline == [[0.0, "red", "scan start"]]

    def test_event_multiple_advances(self):
        s = KillChainState()
        s.event("blue", "start", advance=5.0)
        s.event("blue", "mid", advance=3.0)
        s.event("blue", "end", advance=2.0)
        assert s.clock["blue"] == 10.0
        assert len(s.timeline) == 3
        assert s.timeline[0][0] == 0.0
        assert s.timeline[1][0] == 5.0
        assert s.timeline[2][0] == 8.0

    def test_save_load_round_trip(self, tmp_path):
        p = tmp_path / "state.json"
        s = KillChainState(target="test-target", mock=False)
        s.advance("red", 42.0)
        s.event("blue", "event-1", advance=7.0)
        s.save(p)
        assert p.exists()
        loaded = KillChainState.load(p)
        assert loaded.target == "test-target"
        assert loaded.mock is False
        assert loaded.clock == {"red": 42.0, "blue": 7.0}
        assert loaded.timeline == [[0.0, "blue", "event-1"]]

    def test_all_artifact_fields_persist_after_save_load(self, tmp_path):
        p = tmp_path / "state.json"
        s = KillChainState(
            target="example.com",
            mock=False,
            out_dir="/tmp/out",
            clock={"red": 1.0, "blue": 2.0},
            timeline=[[0.0, "red", "start"]],
            recon={"status": "done"},
            vuln={"findings": []},
            suggestions="fix x",
            alerts=[{"msg": "alert-1"}],
            triaged=[{"id": 1}],
            correlation=[{"rule": "r1"}],
            reports={"pentest": "# report"},
        )
        s.save(p)
        loaded = KillChainState.load(p)
        assert loaded.target == "example.com"
        assert loaded.clock == {"red": 1.0, "blue": 2.0}
        assert loaded.recon == {"status": "done"}
        assert loaded.vuln == {"findings": []}
        assert loaded.suggestions == "fix x"
        assert loaded.alerts == [{"msg": "alert-1"}]
        assert loaded.triaged == [{"id": 1}]
        assert loaded.correlation == [{"rule": "r1"}]
        assert loaded.reports == {"pentest": "# report"}

    def test_load_missing_file_returns_fresh_default(self, tmp_path):
        p = tmp_path / "nonexistent.json"
        s = KillChainState.load(p)
        assert isinstance(s, KillChainState)
        assert s.target == "juice-shop"
        assert s.clock == {"red": 0.0, "blue": 0.0}

    def test_end_event_appends_at_max_clock(self):
        s = KillChainState()
        s.advance("red", 10.0)
        s.advance("blue", 20.0)
        s.end_event()
        assert s.timeline[-1] == [20.0, "sys", "done"]
