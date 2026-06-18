# Documentation index

Single navigation entry for phantom-secops docs. Every tracked document is listed once with
a one-line description and its authority (what it is the source of truth for).

## Start here

| Doc | What it covers | Authority |
|---|---|---|
| [/README.md](../README.md) | Front door: positioning, the two pillars, quick start, links | Project overview |
| [/ROADMAP.md](../ROADMAP.md) | Shipped / In progress / Planned-next, date-stamped | ⭐ **status — single source of truth** |
| [/ETHICS.md](../ETHICS.md) | Scope, legality, legal-targets-only, responsible-use | ⭐ ethics & safety scope |

## Design & decisions

| Doc | What it covers | Authority |
|---|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Engine + agent layering, multi-agent rationale, `x-phantom` model, perf notes | ⭐ architecture |
| [DECISIONS.md](DECISIONS.md) | Nine `context → decision → why → trade-off` records (wrap-don't-build, injectable runners, low-FP, honest-degradation, read-only…) | ⭐ engineering decisions |
| [L2-INTEGRATION-PLAN.md](L2-INTEGRATION-PLAN.md) | Proposed plan to drive the kill-chain through phantom-mesh agent loops (planned-next; `secops_mcp/` façade not yet built) | L2 design reference |

## Demo & narrative

| Doc | What it covers | Authority |
|---|---|---|
| [DEMO.md](DEMO.md) | Two-demo walkthrough script (red/blue MTTD; endpoint self-check) — what to run, what to point out | ⭐ demo script |
| [INTERVIEW-TALK-TRACK.md](INTERVIEW-TALK-TRACK.md) | 30s pitch + likely Q&A for security-engineering interviews | Presentation notes |

## Reference (elsewhere in the repo)

| Doc | What it covers | Authority |
|---|---|---|
| [/lab/README.md](../lab/README.md) | Lab targets (Juice Shop, DVWA, Metasploitable), images/licenses, healthcheck troubleshooting, network isolation | ⭐ lab targets |
| [/scenarios/full-kill-chain.md](../scenarios/full-kill-chain.md) | The full red/blue kill-chain scenario (pipelines, expected timeline, side-by-side) | Scenario reference |
| [/reports/sample-incident-report.md](../reports/sample-incident-report.md) | Sample blue-team incident report output | Sample artifact |
| [/reports/sample-pentest-report.md](../reports/sample-pentest-report.md) | Sample red-team pentest report output | Sample artifact |

## Archive

Superseded and dated dev-logs live in [`_archive/`](_archive/). They are frozen historical
snapshots — **do not treat them as current status**; [/ROADMAP.md](../ROADMAP.md) is the live
status source.

| Doc | Why archived |
|---|---|
| [_archive/STATUS.md](_archive/STATUS.md) | Dated status snapshot (2026-05-10) — superseded by ROADMAP.md |
| [_archive/COMPLETION-PLAN.md](_archive/COMPLETION-PLAN.md) | Frozen progress log for the "original purpose" effort (G1–G7); outcome folded into ROADMAP.md |
| [_archive/L2-TODO.md](_archive/L2-TODO.md) | Dated 2-evening checklist for the unbuilt `secops_mcp/` L2 façade |
| [_archive/2026-05-04-phantom-mesh-integration-spec.md](_archive/2026-05-04-phantom-mesh-integration-spec.md) | Day-1 integration design; shipped differently (7 MCP servers, no `secops_mcp/` façade) |
| [_archive/2026-05-04-phantom-mesh-integration-plan-draft.md](_archive/2026-05-04-phantom-mesh-integration-plan-draft.md) | Early draft of the above spec |
