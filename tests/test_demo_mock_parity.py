"""M1 parity: the agent-loop façade must produce output equivalent to the
deterministic direct driver.

Both front-ends import the SAME step logic from phantom_secops.killchain, so in
mock mode (no docker, no LLM, no network — fully CI-safe) the façade-driven run,
called in canonical order, should match scenarios.run_kill_chain._run_pipeline:
byte-identical recon/vuln artifacts and timeline, equal MTTD, and reports equal
modulo the wall-clock timestamps each run stamps in.

This is the structural parity the agent loop later relies on: this test proves
the façade STEPS are faithful; the live `phantom exec` agent run (which calls
these same steps as MCP tools) is validated separately as a manual gate, since
it needs a provider key + the phantom binary.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import pytest

from phantom_secops import killchain as kc
from scenarios.run_kill_chain import _run_pipeline
from secops_mcp import steps
from secops_mcp.state import KillChainState
from secops_mcp.steps import StepOrderError

# Each run stamps datetime.now() into alerts, correlation, and report headers, so
# raw output differs run-to-run. Strip ISO timestamps (then bare dates) to a
# placeholder before comparing — everything else must match exactly.
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\+\d{2}:\d{2}|Z)?")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _strip_ts(text: str) -> str:
    return _DATE.sub("<DATE>", _TS.sub("<TS>", text))


def _drive_facade(out_dir: Path) -> KillChainState:
    st = KillChainState(target="juice-shop", mock=True, out_dir=str(out_dir))
    steps.recon(st)
    steps.vuln_scan(st)
    steps.detect(st)
    steps.respond(st)
    return st


def _drive_direct(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)  # main() does this before _run_pipeline
    args = argparse.Namespace(
        target="juice-shop", mock=True, use_llm=False,
        out=str(out_dir), severity=kc.NUCLEI_SEVERITY,
    )
    return _run_pipeline(args, out_dir)


# ── headline parity: MTTD + timeline ───────────────────────────────────────

def test_timeline_is_byte_identical(tmp_path):
    """The two independent per-side clocks make the timeline order- and
    duration-deterministic, so under canonical call order it matches exactly."""
    direct_tl, _, _ = _drive_direct(tmp_path / "direct")
    facade = _drive_facade(tmp_path / "facade")
    assert [list(e) for e in direct_tl] == facade.timeline


def test_mttd_metrics_match(tmp_path):
    direct_tl, _, _ = _drive_direct(tmp_path / "direct")
    facade = _drive_facade(tmp_path / "facade")
    assert kc._metrics(direct_tl) == kc._metrics(facade.timeline)


# ── artifact parity ─────────────────────────────────────────────────────────

def test_recon_and_vuln_json_byte_identical(tmp_path):
    a, b = tmp_path / "direct", tmp_path / "facade"
    _drive_direct(a)
    _drive_facade(b)
    for name in ("recon.json", "vuln-scan.json"):
        assert (a / name).read_text(encoding="utf-8") == (b / name).read_text(encoding="utf-8"), name


def test_reports_match_modulo_timestamps(tmp_path):
    a, b = tmp_path / "direct", tmp_path / "facade"
    _, pentest_a, incident_a = _drive_direct(a)
    facade = _drive_facade(b)
    assert _strip_ts(pentest_a) == _strip_ts(facade.reports["pentest"])
    assert _strip_ts(incident_a) == _strip_ts(facade.reports["incident"])


def test_triage_and_correlation_match_modulo_timestamps(tmp_path):
    a, b = tmp_path / "direct", tmp_path / "facade"
    _drive_direct(a)
    _drive_facade(b)
    for name in ("triage-queue.jsonl", "kill-chains.jsonl"):
        assert _strip_ts((a / name).read_text(encoding="utf-8")) == \
               _strip_ts((b / name).read_text(encoding="utf-8")), name


def test_summary_json_metrics_match_modulo_timestamps(tmp_path):
    a, b = tmp_path / "direct", tmp_path / "facade"
    # The direct driver writes summary.json from main(), not _run_pipeline, so
    # derive the direct summary the same way for an apples-to-apples compare.
    direct_tl, _, _ = _drive_direct(a)
    facade = _drive_facade(b)
    direct_metrics = kc._metrics(direct_tl)
    facade_summary = json.loads((b / "summary.json").read_text(encoding="utf-8"))
    for k in ("mttd", "outcome", "detect_margin", "first_detect", "time_to_impact"):
        assert facade_summary[k] == direct_metrics[k], k


# ── drift guard: out-of-order calls are refused ─────────────────────────────

def test_vuln_scan_before_recon_is_refused():
    st = KillChainState(mock=True)
    with pytest.raises(StepOrderError):
        steps.vuln_scan(st)


def test_respond_before_detect_is_refused():
    st = KillChainState(mock=True)
    steps.recon(st)
    steps.vuln_scan(st)
    with pytest.raises(StepOrderError):
        steps.respond(st)  # detect hasn't run → no triage queue to report on


# ── permanent guardrail: prose-only exploit suggester survives the façade ───

def test_facade_exploit_suggestions_stay_prose_only(tmp_path):
    """The ethics red line (has_runnable_poc never true) must hold THROUGH the new
    wrapper layer, not just at _exploit_prose: a façade that accidentally enriched
    suggestions with a payload would be a regression this catches."""
    facade = _drive_facade(tmp_path / "facade")
    prose = facade.suggestions
    assert prose, "respond must have produced exploit suggestions"
    lowered = prose.lower()
    for marker in ("curl ", "<script>", "; rm ", "powershell -enc", "msfconsole", "nc -e"):
        assert marker not in lowered, marker
    # the on-disk artifact the agent/demo surfaces carries the identical guarantee
    disk = (tmp_path / "facade" / "exploit-suggestions.md").read_text(encoding="utf-8")
    assert disk == prose


# ── state persistence round-trips across (simulated) agent turns ────────────

def test_state_save_load_roundtrip(tmp_path):
    sf = tmp_path / "state.json"
    st = KillChainState(target="juice-shop", mock=True, out_dir=str(tmp_path))
    steps.recon(st)
    st.save(sf)
    # next "turn": reload from disk and continue
    st2 = KillChainState.load(sf)
    assert st2.recon == st.recon
    assert st2.timeline == st.timeline
    assert st2.clock == st.clock
    steps.vuln_scan(st2)  # continues cleanly from restored state
    assert st2.vuln is not None
