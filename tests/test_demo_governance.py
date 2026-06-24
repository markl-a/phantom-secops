"""Smoke test: the M2 governance demo runs end-to-end and exits clean."""

from __future__ import annotations

import scenarios.demo_governance as demo


def test_governance_demo_runs(capsys):
    rc = demo.main()
    assert rc == 0
    out = capsys.readouterr().out
    # the four boundaries are all demonstrated
    assert "structurally barred from 'red'" in out   # [1] blue ↛ red
    assert "triaged groups" in out                    # [2] blue → blue allowed
    assert "fail-closed" in out or "auto-denied" in out  # [3] live no-approval
    assert "released via manual-file" in out          # [4] approval pause→resume
    assert "governance.jsonl audit trail" in out
