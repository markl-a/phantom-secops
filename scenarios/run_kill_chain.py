"""Kill-chain orchestrator — the deterministic "direct" driver.

Runs the red and blue agent pipelines against an in-lab target and emits a
side-by-side report. Two modes:

  --mock   : use canned data from lab/mocks/. No docker, no API key. CI-safe.
            Useful for demos on a fresh machine or when offline.
  default  : run against the live lab brought up by `make lab-up`. Calls into
            the tool wrappers in tools/ which shell out to nmap/nuclei via
            docker exec.

LLM-driven report-writing is opt-in via --use-llm. When unset, reports are
generated from templates with deterministic substitutions, which keeps the
demo fast and reproducible.

The red/blue STEP logic (recon, vuln-scan, triage, correlate, report
composition, metrics) lives in `phantom_secops.killchain` so the phantom-mesh
agent-loop façade (secops_mcp/) can drive the identical implementation — this
module is just the argparse + two-clock timeline that sequences those steps.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Shared kill-chain core. Imported (not redefined) so the agent-loop façade and
# this direct driver run byte-identical step logic — the M1 parity guarantee.
# The tool-runner MODULES are re-exported too (nmap_runner / nuclei_runner) so
# existing tests that monkeypatch `run_kill_chain.nmap_runner.run` keep working;
# they patch the shared module object, which killchain resolves at call time.
from phantom_secops.killchain import (  # noqa: E402,F401  (F401: several are re-exports for tests)
    NUCLEI_SEVERITY,
    _blue_alert_triage,
    _blue_log_anomaly,
    _blue_threat_correlate,
    _compose_incident_report,
    _compose_pentest_report,
    _dedupe_alerts,
    _exploit_prose,
    _http_targets,
    _metrics,
    _render_actors,
    _render_mttd,
    _render_ports,
    _run_exploit_suggest,
    _run_recon,
    _run_vuln_scan,
    _scan_degradations,
    nmap_runner,
    nuclei_runner,
)

REPORTS_DIR = REPO_ROOT / "reports"


def _reconfigure_console_utf8() -> None:
    """Force UTF-8 on the console streams.

    Windows consoles default to a legacy code page (cp950 / cp1252) that can't
    encode the status glyphs the pipeline prints (→, ⚠), so output crashes with
    UnicodeEncodeError. This runs at IMPORT time — not just inside main() —
    because the pipeline functions (`_run_pipeline` / `event`) are imported and
    called directly by tests and other entrypoints that never go through main();
    fixing it only in main() would leave those callers crashing on a legacy
    code page. No-op where reconfigure is unavailable (e.g. captured streams).
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass


_reconfigure_console_utf8()

# Simulated per-step durations (seconds) used in --mock mode so the red and blue
# timelines are meaningful instead of all-zero. Live mode ignores these and uses
# real wall-clock.
#
# Provenance: these are ILLUSTRATIVE order-of-magnitude operator-time estimates
# (e.g. recon ≈ an nmap -sV of one host; threat-correlate ≈ an analyst review
# window), NOT measured benchmarks. They are scenario inputs that make the
# simulated timeline plausible; the *mechanism* (concurrent clocks, milestone
# extraction, the MTTD comparison) is what's real and tested — the numbers are
# not a claim about real detection latency.
RED_DURATIONS = {
    "recon": 12.0, "vuln-scan": 30.0, "exploit-suggest": 8.0, "pentest-report": 5.0,
}
BLUE_DURATIONS = {
    "log-anomaly": 8.0, "alert-triage": 7.0, "threat-correlate": 35.0, "incident-report": 5.0,
}


class Clock:
    """Two concurrent clocks (red attacker, blue defender).

    In mock mode each side advances by simulated step durations; in live mode
    both report real elapsed wall-clock and `advance` is a no-op.
    """

    def __init__(self, mock: bool) -> None:
        self.mock = mock
        self._t0 = time.time()
        self._t = {"red": 0.0, "blue": 0.0}

    def now(self, side: str) -> float:
        if not self.mock:
            return time.time() - self._t0
        return self._t.get(side, 0.0)

    def advance(self, side: str, secs: float) -> None:
        if self.mock and side in self._t:
            self._t[side] += secs


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", default="juice-shop",
                   help="lab service name (default: juice-shop)")
    p.add_argument("--mock", action="store_true",
                   help="use canned data; no docker required")
    p.add_argument("--use-llm", action="store_true",
                   help="invoke phantom-mesh for LLM-driven report writing "
                        "(requires phantom serve at localhost:7878)")
    p.add_argument("--out", default=None, help="output dir (default: reports/runs/<ts>/)")
    p.add_argument("--severity", default=NUCLEI_SEVERITY,
                   help=f"comma-separated nuclei severities for the live vuln-scan "
                        f"(default: {NUCLEI_SEVERITY}). Widen (e.g. "
                        f"'medium,high,critical') for targets with nuclei-"
                        f"fingerprintable lower-severity issues like dvwa.")
    args = p.parse_args()

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M")
    out_dir = Path(args.out) if args.out else REPORTS_DIR / "runs" / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"→ phantom-secops kill-chain :: target={args.target} mock={args.mock} llm={args.use_llm}")
    print(f"  output: {out_dir}")
    print()

    timeline, pentest_md, incident_md = _run_pipeline(args, out_dir)

    print()
    print(f"→ artifacts at: {out_dir}")
    print(f"   - pentest-report.md   ({len(pentest_md):,} bytes)")
    print(f"   - incident-report.md  ({len(incident_md):,} bytes)")
    print(f"   - {len(list(out_dir.glob('*.json'))) + len(list(out_dir.glob('*.jsonl')))} structured artifacts")
    print()
    m = _metrics(timeline)
    (out_dir / "summary.json").write_text(json.dumps({**m, "timeline": [{"t": t, "side": side, "label": label} for t, side, label in sorted(timeline, key=lambda e: e[0])]}, indent=2, ensure_ascii=False), encoding="utf-8")
    sim = "  (simulated timing — mock mode)" if args.mock else ""
    print(f"→ MTTD = {m['mttd']:.0f}s{sim}")
    if m["outcome"] == "defender":
        print(f"  defender triaged at t+{m['first_detect']:.0f}s; attacker reached "
              f"impact at t+{m['time_to_impact']:.0f}s → detected "
              f"{m['detect_margin']:.0f}s before impact (defender win)")
    else:
        print(f"  attacker reached impact at t+{m['time_to_impact']:.0f}s; defender "
              f"triaged at t+{m['first_detect']:.0f}s → impact "
              f"{-m['detect_margin']:.0f}s before detection (attacker win)")

    return 0


def _run_pipeline(
    args: argparse.Namespace, out_dir: Path,
) -> tuple[list[tuple[float, str, str]], str, str]:
    """Run the red + blue pipeline, write artifacts, return (timeline, reports).

    Event-issue order puts the defender's detection (blue-alert-triage) BEFORE the
    attacker's impact (red-exploit-suggest done). In mock mode the two-clock model
    already orders them; ordering it here too keeps live (single-process, real
    wall-clock) mode honest — detection genuinely precedes impact, so the MTTD
    comparison isn't a mock-only illusion. Blue reads attack-log.txt independent
    of red outputs, so the interleaving is safe.
    """
    timeline: list[tuple[float, str, str]] = []
    clock = Clock(mock=args.mock)

    def event(side: str, label: str, advance: float = 0.0) -> None:
        t = clock.now(side)
        print(f"  [t+{t:5.1f}s] {label}")
        timeline.append((t, side, label))
        clock.advance(side, advance)

    # red recon → red vuln-scan
    event("red", "red-recon  starts", RED_DURATIONS["recon"])
    recon = _run_recon(args.target, mock=args.mock)
    (out_dir / "recon.json").write_text(json.dumps(recon, indent=2, ensure_ascii=False), encoding="utf-8")
    event("red", f"red-recon  → {len(recon.get('open_ports', []))} open ports")

    event("red", "red-vuln-scan  starts", RED_DURATIONS["vuln-scan"])
    vuln = _run_vuln_scan(args.target, recon, mock=args.mock,
                          severity=getattr(args, "severity", NUCLEI_SEVERITY))
    (out_dir / "vuln-scan.json").write_text(json.dumps(vuln, indent=2, ensure_ascii=False), encoding="utf-8")
    event("red", f"red-vuln-scan  → {len(vuln.get('findings', []))} findings")

    # blue log-anomaly → alert-triage (DETECTION) — issued before red impact.
    # Honesty: in live mode the blue side reads the REAL collected lab logs (where
    # the live nmap/nuclei traffic actually shows up), not the canned fixture —
    # so the label must not claim "canned" when it isn't.
    log_src = "canned attack log" if args.mock else "live lab logs"
    event("blue", f"blue-log-anomaly  scanning {log_src}", BLUE_DURATIONS["log-anomaly"])
    alerts = _blue_log_anomaly(mock=args.mock, out_dir=out_dir)
    (out_dir / "alerts.jsonl").write_text("\n".join(json.dumps(a) for a in alerts), encoding="utf-8")
    event("blue", f"blue-log-anomaly  → {len(alerts)} raw alerts")

    event("blue", "blue-alert-triage  classify + dedupe", BLUE_DURATIONS["alert-triage"])
    triaged = _blue_alert_triage(alerts)
    (out_dir / "triage-queue.jsonl").write_text("\n".join(json.dumps(t) for t in triaged), encoding="utf-8")
    event("blue", f"blue-alert-triage  → {len(triaged)} triaged groups")  # ← defender detects

    # red exploit-suggest (IMPACT) — issued after detection
    event("red", "red-exploit-suggest  composing prose", RED_DURATIONS["exploit-suggest"])
    suggestions = _run_exploit_suggest(vuln, mock=args.mock, use_llm=args.use_llm)
    (out_dir / "exploit-suggestions.md").write_text(suggestions, encoding="utf-8")
    event("red", "red-exploit-suggest  done")  # ← attacker reaches actionable impact

    # blue threat-correlate
    event("blue", "blue-threat-correlate  reconstruct kill chain", BLUE_DURATIONS["threat-correlate"])
    correlation = _blue_threat_correlate(triaged)
    (out_dir / "kill-chains.jsonl").write_text("\n".join(json.dumps(c) for c in correlation), encoding="utf-8")
    event("blue", f"blue-threat-correlate  → {len(correlation)} actor(s)")

    # report-composition steps (timed), then compose with the full timeline
    event("red", "red-pentest-report  composing markdown", RED_DURATIONS["pentest-report"])
    event("blue", "blue-incident-report  composing markdown", BLUE_DURATIONS["incident-report"])

    end_t = max(clock.now("red"), clock.now("blue"))
    print(f"  [t+{end_t:5.1f}s] done")
    timeline.append((end_t, "sys", "done"))

    # Honesty gate: if any live scanner could not run (docker/nmap/nuclei
    # missing), flag the run as DEGRADED on the console and in both reports
    # rather than emitting a clean-looking "0 findings" result.
    degradations = _scan_degradations(recon, vuln, mock=args.mock)
    if degradations:
        print()
        print("  ⚠ DEGRADED RUN — one or more scanners could not run; results are "
              "INCOMPLETE (not a clean result):")
        for d in degradations:
            print(f"    - {d}")

    pentest_md = _compose_pentest_report(recon, vuln, suggestions, timeline,
                                         mock=args.mock, degradations=degradations)
    (out_dir / "pentest-report.md").write_text(pentest_md, encoding="utf-8")
    incident_md = _compose_incident_report(triaged, correlation, timeline,
                                           mock=args.mock, degradations=degradations)
    (out_dir / "incident-report.md").write_text(incident_md, encoding="utf-8")

    return timeline, pentest_md, incident_md


if __name__ == "__main__":
    sys.exit(main())
