"""Tests for the kill-chain timing model — the MTTD signature must be meaningful.

In mock mode the orchestrator uses simulated per-step durations on two concurrent
clocks (red attacker, blue defender) so the side-by-side mean-time-to-detect is a
real, non-zero number instead of 0.0s.
"""

from __future__ import annotations

from scenarios.run_kill_chain import Clock, _metrics, RED_DURATIONS, BLUE_DURATIONS


def test_clock_mock_tracks_sides_independently():
    c = Clock(mock=True)
    assert c.now("red") == 0.0
    c.advance("red", 12.0)
    assert c.now("red") == 12.0
    assert c.now("blue") == 0.0          # advancing red must not move blue


def test_clock_live_ignores_advance_and_uses_wallclock():
    c = Clock(mock=False)
    c.advance("red", 100.0)              # simulated advance is a no-op in live mode
    assert c.now("red") < 1.0            # only real (tiny) elapsed time counts


# A synthetic concurrent timeline: (t_seconds, side, label).
SYN_TL = [
    (0.0, "red", "red-recon  starts"),
    (12.0, "red", "red-recon  → 1 open ports"),
    (8.0, "blue", "blue-log-anomaly  → 21 raw alerts"),
    (15.0, "blue", "blue-alert-triage  → 5 triaged groups"),
    (50.0, "red", "red-exploit-suggest  done"),
]


def test_metrics_identify_the_right_milestones():
    m = _metrics(SYN_TL)
    assert m["first_action"] == 0.0      # attacker's first move
    assert m["first_detect"] == 15.0     # defender's first triaged alert
    assert m["time_to_impact"] == 50.0   # attacker reaches impact
    assert m["mttd"] == 15.0             # detect - first_action
    assert m["detect_margin"] == 35.0    # impact - detect (detected before impact)


def test_mock_mttd_is_nonzero():
    # The whole point of the change: mock mode must not report MTTD 0.0s.
    assert _metrics(SYN_TL)["mttd"] > 0


def test_configured_durations_detect_before_impact():
    # The defender's triage must land before the attacker's impact, or the demo lies.
    blue_detect = BLUE_DURATIONS["log-anomaly"] + BLUE_DURATIONS["alert-triage"]
    red_impact = (RED_DURATIONS["recon"] + RED_DURATIONS["vuln-scan"]
                  + RED_DURATIONS["exploit-suggest"])
    assert blue_detect < red_impact


def test_metrics_empty_timeline_is_safe():
    m = _metrics([])
    assert m["mttd"] == 0.0
    assert m["time_to_impact"] == 0.0
