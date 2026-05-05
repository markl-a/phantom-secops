"""Kill-chain orchestrator (Python reference implementation).

Runs the red and blue agent pipelines against an in-lab target and emits a
side-by-side report. This is one of three ways to drive the same workflow:

  1. This script              — deterministic Python, CI-safe.
  2. MCP server               — phantom_secops.mcp.server, callable by any MCP client.
  3. phantom-mesh workflow    — agents/{red,blue}/*.toml + scenarios/*.workflow.toml.

All three call into phantom_secops.core for the actual logic.

Modes:
  --mock   : use canned data from lab/mocks/. No docker, no API key. CI-safe.
  default  : run against the live lab brought up by `make lab-up`.

LLM-driven prose is opt-in via --use-llm (Phase 3 — currently a no-op).
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

from phantom_secops import core  # noqa: E402
from phantom_secops.llm import get_provider  # noqa: E402

REPORTS_DIR = REPO_ROOT / "reports"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", default="juice-shop",
                   help="lab service name (default: juice-shop)")
    p.add_argument("--mock", action="store_true",
                   help="use canned data; no docker required")
    p.add_argument("--use-llm", action="store_true",
                   help="invoke an LLM provider for prose generation. "
                        "Provider chosen via PHANTOM_SECOPS_LLM env var "
                        "(none, anthropic, phantom_mesh).")
    p.add_argument("--llm", default=None,
                   help="explicit provider name (overrides PHANTOM_SECOPS_LLM)")
    p.add_argument("--out", default=None, help="output dir (default: reports/runs/<ts>/)")
    args = p.parse_args()

    provider = get_provider(args.llm) if args.use_llm else None

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M")
    out_dir = Path(args.out) if args.out else REPORTS_DIR / "runs" / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    llm_label = provider.name if provider else "none"
    print(f"→ phantom-secops kill-chain :: target={args.target} mock={args.mock} llm={llm_label}")
    print(f"  output: {out_dir}")
    print()

    timeline: list[tuple[str, str]] = []
    t0 = time.time()

    def event(label: str) -> None:
        elapsed = time.time() - t0
        line = f"  [t+{elapsed:5.1f}s] {label}"
        print(line)
        timeline.append((f"{elapsed:.1f}", label))

    # ─── Red pipeline ─────────────────────────────────────────────────────
    event("red-recon  starts")
    recon = core.run_recon(args.target, mock=args.mock)
    (out_dir / "recon.json").write_text(json.dumps(recon, indent=2, ensure_ascii=False), encoding="utf-8")
    event(f"red-recon  → {len(recon.get('open_ports', []))} open ports")

    event("red-vuln-scan  starts")
    vuln = core.run_vuln_scan(args.target, recon, mock=args.mock)
    (out_dir / "vuln-scan.json").write_text(json.dumps(vuln, indent=2, ensure_ascii=False), encoding="utf-8")
    event(f"red-vuln-scan  → {len(vuln.get('findings', []))} findings")

    event("red-exploit-suggest  composing prose")
    suggest = core.suggest_exploit_prose(
        vuln.get("findings", []),
        use_llm=args.use_llm,
        provider=provider,
    )
    (out_dir / "exploit-suggestions.md").write_text(suggest["markdown"], encoding="utf-8")
    event("red-exploit-suggest  done")

    # ─── Blue pipeline ────────────────────────────────────────────────────
    event("blue-log-anomaly  scanning canned attack log")
    anomaly = core.scan_logs_for_anomalies(source="mock" if args.mock else "lab_logs")
    alerts = anomaly["alerts"]
    (out_dir / "alerts.jsonl").write_text("\n".join(json.dumps(a) for a in alerts), encoding="utf-8")
    event(f"blue-log-anomaly  → {len(alerts)} raw alerts")

    event("blue-alert-triage  classify + dedupe")
    triage = core.triage_alerts(alerts)
    triaged = triage["triaged"]
    (out_dir / "triage-queue.jsonl").write_text("\n".join(json.dumps(t) for t in triaged), encoding="utf-8")
    event(f"blue-alert-triage  → {len(triaged)} triaged groups")

    event("blue-threat-correlate  reconstruct kill chain")
    correlation = core.correlate_threats(triaged)
    actors = correlation["actors"]
    (out_dir / "kill-chains.jsonl").write_text("\n".join(json.dumps(c) for c in actors), encoding="utf-8")
    event(f"blue-threat-correlate  → {len(actors)} actor(s)")

    # ─── Reports ─────────────────────────────────────────────────────────
    event("red-pentest-report  composing markdown")
    pentest = core.compose_pentest_report(recon, vuln, suggest["markdown"], timeline)
    (out_dir / "pentest-report.md").write_text(pentest["markdown"], encoding="utf-8")

    event("blue-incident-report  composing markdown")
    incident = core.compose_incident_report(triaged, actors, timeline)
    (out_dir / "incident-report.md").write_text(incident["markdown"], encoding="utf-8")

    event("done")
    print()
    print(f"→ artifacts at: {out_dir}")
    print(f"   - pentest-report.md   ({pentest['byte_size']:,} bytes)")
    print(f"   - incident-report.md  ({incident['byte_size']:,} bytes)")
    print(f"   - {len(list(out_dir.glob('*.json'))) + len(list(out_dir.glob('*.jsonl')))} structured artifacts")
    print()
    print(f"→ MTTD (first probe → first triaged alert): "
          f"{incident['mttd_seconds']:.1f}s in this run")

    return 0


if __name__ == "__main__":
    sys.exit(main())
