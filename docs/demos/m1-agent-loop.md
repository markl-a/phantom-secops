# M1 demo — an LLM agent drives the kill-chain by itself

**What this shows:** the same red/blue SOC kill-chain that `make demo-mock` runs
as a deterministic Python pipeline, but here driven by a **phantom-mesh LLM
agent loop**. The agent (Cerebras `gpt-oss-120b`) decides to call the
`secops_mcp` façade tools — `recon → vuln_scan → detect → respond` — one per
stage, and the run produces the identical MTTD metric and reports as the
deterministic driver (parity is enforced by `tests/test_demo_mock_parity.py`).

This is the M1 milestone of [`docs/EXECUTION-PLAN.md`](../EXECUTION-PLAN.md):
the headline demo is now genuinely *agentic*, not a hardcoded sequence.

## Run it

```bash
make demo-mock-mesh
# = python scenarios/run_kill_chain.py --target juice-shop --mock --driver mesh
```

Prereqs: the `phantom` CLI on PATH and `CEREBRAS_API_KEY` exported. Everything
else is canned (`--mock`) — no docker, no scanning, fully reproducible and
offline-safe. To record an actual screencast for a portfolio/talk:

```bash
asciinema rec m1-agent-loop.cast -c "make demo-mock-mesh"
```

## Captured run (phantom 0.6.0-rc.1 + Cerebras gpt-oss-120b)

The agent picked the four tools in the correct order, once each, with no drift:

```
[tool] secops_kc_recon {"target":"juice-shop"}
[done] secops_kc_recon → {"open_ports": 1, "ports": [{"port": 3000, "service": "http"}]}
[tool] secops_kc_vuln_scan {"severity":"high,medium"}
[done] secops_kc_vuln_scan → {"findings": 5}
[tool] secops_kc_detect {}
[done] secops_kc_detect → {"raw_alerts": 42, "triaged_groups": 6, "priorities": {"P1": 2, "P2": 2, "P3": 2}}
[tool] secops_kc_respond {}
[done] secops_kc_respond → {"mttd": 15.0, "outcome": "defender", "detect_margin": 35.0, "actors": 1, "degraded": false, ...}
```

The driver then reads the agent-produced state back and reports the headline
metric — **the canonical, deterministic source of truth**:

```
→ MTTD = 15s  (simulated timing — mock mode)
  defender triaged at t+15s; attacker reached impact at t+50s → detected 35s before impact (defender win)
```

> Honesty note: the agent also emits free-text narration after the tool calls
> (e.g. it may round "15s" to "minutes" or paraphrase the report filenames).
> That prose is illustrative only — every *fact* in this demo (MTTD, priorities,
> findings, timeline) comes from the deterministic tool outputs and the written
> reports, never from the LLM's narration. The exploit suggester stays
> prose-only (`has_runnable_poc` is never true).

## Resulting incident report (excerpt)

The agent-driven run wrote the same artifacts the direct driver does, into the
run dir (`recon.json`, `vuln-scan.json`, `alerts.jsonl`, `triage-queue.jsonl`,
`kill-chains.jsonl`, `exploit-suggestions.md`, `pentest-report.md`,
`incident-report.md`, `summary.json`):

```markdown
# Incident Report — Lab observation, 2026-06-21

## TL;DR

1 actor(s) observed against the lab. Triage pipeline produced
2 P1, 2 P2, 2 P3 grouped alerts. All activity attributable to the lab
attacker container by design.

## Timeline

| t (s) | Side | Event |
|---|---|---|
| 0.0  | red  | red-recon  starts |
| 0.0  | blue | blue-log-anomaly  scanning canned attack log |
| 8.0  | blue | blue-log-anomaly  → 42 raw alerts |
| 8.0  | blue | blue-alert-triage  classify + dedupe |
| 12.0 | red  | red-recon  → 1 open ports |
| 12.0 | red  | red-vuln-scan  starts |
| 15.0 | blue | blue-alert-triage  → 6 triaged groups |   ← detection
| ...  | ...  | ... |
| 50.0 | red  | red-exploit-suggest  done |                ← impact
| 55.0 | sys  | done |
```

Detection (t+15s) precedes impact (t+50s) → **MTTD = 15s, detected 35s before
impact**, byte-identical to `make demo-mock` modulo wall-clock timestamps.

## How parity is guaranteed (not luck)

Both drivers import the same step logic from `phantom_secops/killchain.py`. The
timeline uses two independent per-side clocks with fixed step durations, so each
side's event times depend only on that side's own event sequence — independent
of how the agent interleaves red and blue tool calls. Under the canonical call
order the timeline is therefore byte-identical to the direct driver, making the
MTTD and reports match by construction. See `tests/test_demo_mock_parity.py`.
