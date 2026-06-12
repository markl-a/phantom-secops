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
