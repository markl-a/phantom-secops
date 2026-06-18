> ARCHIVED 2026-06-19 — frozen historical snapshot; current status lives in /ROADMAP.md

# Completion plan — original purpose (purpose A)

> Living plan + progress log for the autonomous effort to *complete* phantom-secops'
> original purpose: a credible, honest, portfolio-grade demonstration that phantom-mesh
> runs a red/blue secops pipeline with a **meaningful mean-time-to-detect (MTTD)**
> comparison. Updated as phases land.

## Definition of done

1. **MTTD is real and meaningful** — not the current `0.0s`. Attacker time-to-impact
   vs defender time-to-detect, with honest (clearly-labelled) timing.
2. **Reliable mock-first demo** plus at least one working **live** path against the docker lab.
3. **Honest verification** — README/docs claims match the code; WIP (nuclei) finished or scoped out.
4. **Polished presentation** — README/DECISIONS/talk-track (done) + a runnable demo walkthrough.
5. *(Stretch, not required for "done")* full phantom-mesh agent-loop orchestration; the
   cross-repo x-phantom Rust enforcer.

## Phases

| # | Phase | Solo? | Gate |
|---|---|---|---|
| 0 | Grounded gap audit (workflow) | yes | accurate gap map produced |
| 1 | **Make MTTD real** (realistic mock timeline, honest impact-vs-detect) | yes | mock run shows a meaningful MTTD; TDD green |
| 2 | Live path hardening (docker lab: recon + one scan) | needs docker | `make lab-up && make demo` green, or nuclei honestly scoped out |
| 3 | True phantom-mesh agent orchestration (live mode v2) | needs LLM quota | ≥2 agents run via phantom-mesh end-to-end |
| 4 | Polish + demo artifact (DEMO walkthrough, docs aligned) | yes | 30s pitch + two runnable demos |
| 5 | *(stretch)* x-phantom Rust enforcer (cross-repo) | needs phantom-mesh repo | optional |

Recommended order: **1 → 4 → 2 → 3 → 5**. Minimum viable "done" = 1 + 4 (+ honest scoping of 2/3).

## Operating rules (autonomous)

- One branch (`feat/complete-original-purpose`), TDD, commit at green checkpoints, one evolving PR.
- Each phase verified against the gate before moving on; failures get diagnosed/fixed or honestly scoped out.
- Human gates: docker readiness, admin steps, LLM quota/keys, and **merge-to-main decisions**.
- Anchored by [[project-charter]] — this run targets A (the external north star).

## Progress log

- **Phase 0** — started: launched parallel gap-audit workflow (run map of kill-chain timeline/MTTD,
  the 8 agents + render script, live/docker path, claims-vs-reality).
- **Phase 1 — DONE.** Made MTTD real. Root cause: `event()` stamped wall-clock, so mock steps
  (≈0ms) all landed at t+0.0s → MTTD 0.0s, and red/blue ran sequentially. Fix: a two-clock model
  (`Clock`) with simulated per-step durations (`RED_DURATIONS`/`BLUE_DURATIONS`) on concurrent
  red/blue clocks; honest `_metrics()` (first_action, first_detect, time_to_impact, mttd,
  detect_margin); timeline now interleaved + sorted; reports show the comparison, labelled
  "simulated" in mock mode. Result: **MTTD 15s, detected 35s before impact**. 6 new tests,
  full suite 102 passing.
- **Gap audit (workflow) — DONE.** 4 parallel readers + synthesis, verified against the live
  repo. Confirmed Phase 1 already shipped; re-scoped the remaining work as G1–G7.
- **G1 (live-mode honesty) — DONE.** The real hollow spot: live mode ran red then blue
  sequentially, so wall-clock detection landed after impact → negative margin → the live demo
  silently contradicted the mock story. Extracted testable `_run_pipeline()`, reordered
  detection before impact, made `_metrics` return an un-clamped `detect_margin` + `outcome`
  (defender/attacker win); printout honest in both modes. +3 tests, suite 105 passing.
- **G4 (duration provenance) — DONE.** Comment marks durations as illustrative estimates, not
  benchmarks.
- **G3 (doc honesty) — DONE.** Fixed: README "phantom-mesh agents run" overclaim (it's a
  deterministic Python orchestrator; MCP-ready, mesh is next), the fabricated "NVD mirror +
  LLM prose" talk-track answer (the suggester is templated; `--use-llm` is a stub), the stale
  walkthrough timeline (now matches the real MTTD demo), and the ARCHITECTURE "live Nuclei
  ~60s bottleneck" claim (nuclei not wired; live vuln-scan is a stub).
- **Phase 4 (demo walkthrough) — DONE.** `docs/DEMO.md`.
- **G2 (live nuclei) — BLOCKED:** docker not running on this machine. Honestly scoped in docs
  as the live-mode milestone. Needs the user to start docker.
- **G5/G6/G7 (render gaps, full mesh orchestration, LLM prose) — DEFERRED** (post-portfolio,
  need cross-repo / LLM quota).

**Status: the done-line (G1 + G3 + G4, + Phase 1 + Phase 4) is met — the MTTD signature is
real and honest in both modes and the docs are truthful.** Remaining items need docker (G2)
or are explicitly post-portfolio (G5–G7).
- **Verification (workflow) — DONE.** 3 lens-diverse adversarial reviewers (correctness /
  honesty / tests) + synthesis. Verdict: **no blockers, correctness a clean bill of health,
  MTTD mechanism correct.** Two should-fix doc items (README diagram + talk-track still listed
  unimplemented dnsrecon/subfinder/nikto) and high-value display tests recommended.
- **G2 (nuclei wiring) — code DONE (live run still gated on docker).** Wired
  `_run_vuln_scan` to call `tools/nuclei_runner.py` per HTTP endpoint from recon (injectable
  for tests; degrades to empty on runner error). Added `_http_targets`. 6 new tests. The live
  end-to-end run still needs `make lab-up` (docker) to verify.
- **Verification follow-ups — DONE.** Fixed the README/talk-track/ARCHITECTURE tool-list
  honesty (nuclei now wired-but-unverified; dnsrecon/subfinder/nikto marked planned/no
  runner). Added display-layer tests locking the report-honesty contract (`_render_mttd`
  defender+attacker win, `main()` narrative via capsys). Full suite **114 passing**.

**Loop pause point:** every solo, non-gated item toward the Definition of Done is complete.
What remains is gated on **docker** (verify the live kill-chain end-to-end, G2's last mile)
or is **post-portfolio** (G5–G7: render gaps, full phantom-mesh orchestration, LLM prose),
plus the **merge of PR #10** (user's call). Pausing per the operating rules.
