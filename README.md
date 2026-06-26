# phantom-secops

> A **read-only, plain-text, governed** security-operations "brain" built on top of my own
> multi-agent runtime, [phantom-mesh](https://github.com/markl-a/phantom-mesh).
> The thesis in one line: **don't build the engine — build the brain.** Wrap mature, battle-tested
> scanners (Trivy / Nmap / Nuclei / Sigma) and put the value in the agent layer that
> *orchestrates, correlates, and explains* their output. The LLM triages; it never exploits.

[![Powered by phantom-mesh](https://img.shields.io/badge/powered%20by-phantom--mesh-purple)](https://github.com/markl-a/phantom-mesh)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-200%2B%20passing-brightgreen.svg)](#why-its-credible-engineering-rigor)
[![Read-only](https://img.shields.io/badge/posture-read--only%20%2F%20advise--only-blue.svg)](ETHICS.md)

📖 **Full bilingual deep-dive** (positioning · roadmap · OSS landscape · engineering decisions): **[docs/phantom-secops.md](docs/phantom-secops.md)** &nbsp;|&nbsp; ⚖️ **Legal / ethical boundaries:** [ETHICS.md](ETHICS.md)

---

## It does two things

### 🔴🔵 Pillar 1 — a red/blue SOC concept demo
An **attack** pipeline (recon → vuln-scan → exploit-suggest → report) and a **defense** pipeline
(log-anomaly → triage → correlate → incident-report) run **in parallel** against an isolated,
intentionally-vulnerable lab, on two clocks that both start at *t=0*. The headline metric is the
one a SOC actually measures — **Mean Time To Detect (MTTD)**:

```
→ MTTD = 15s   (defender win)
  defender triaged the activity at t+15s; attacker reached impact at t+50s
  → detected 35s before impact
```

The metric is **honest in both directions**: if detection lands *after* impact, the report says so
(attacker win). In mock mode the per-step timing is explicitly labelled `simulated`; live mode uses
real wall-clock. Every run also writes machine-readable `summary.json` + interleaved timeline +
ATT&CK phases + P1/P2/P3 queue.

### 🛡️ Pillar 2 — a local-first endpoint self-check I actually run daily
Read-only inspection of *this* machine — host posture, dependency CVEs, host intrusion detection —
merged by a **deterministic, no-LLM fusion step** and then synthesized by an LLM agent into **one
prioritised, plain-language action list**. Data never leaves the machine. A real run on my own box
surfaced **864 fixable CVEs** in a sister project plus an AV real-time-protection gap, and the agent
returned exact upgrade versions in fix-first order.

```powershell
.\checkup.ps1                              # one shot: tests + every engine + deterministic fusion + AI report
.\checkup.ps1 -Path D:\Projects\my-app     # scan a specific project for CVEs
```

---

## Quickstart

This repo is intentionally published as a source-checkout tool for now, not as
an installable Python package. The official public entrypoints are:

- `python scenarios/run_kill_chain.py --target juice-shop --mock` for the
  CI-safe red/blue demo with no Docker and no API key.
- `python -m pytest -q` for the deterministic test suite.
- `python scripts/run_goal.py --out reports/verification` for the verification
  pack.
- `python -m phantom_secops.defensive_loop --out reports/defensive-demo` for
  the hermetic defensive finding/timeline artifact loop.
- `python -m phantom_secops.evidence_playbook --out reports/evidence-playbook`
  for the hermetic evidence pack and tabletop playbook simulation.
- `.\checkup.ps1` on Windows for the local endpoint self-check.
- `make ...` targets on Unix-like shells as shortcuts over the Python scripts.

Live lab targets and mesh/LLM paths are opt-in. The default public demo path is
mock/read-only and does not scan external systems.

```bash
# Demo 1 — red/blue kill-chain + MTTD  (~1s, no Docker, no API key)
make demo-mock        # or: python scenarios/run_kill_chain.py --target juice-shop --mock

# Demo 1 (live) — real nmap + nuclei against the Docker lab
make lab-up && make demo && make lab-down

# Goal verification pack (mock kill-chain + checkup + governance smoke + model diff)
make verify-goal

# P2 hermetic defensive workbench loop: no active scanning, no Docker, no PoC
python -m phantom_secops.defensive_loop --out reports/defensive-demo

# P2 evidence pack + playbook simulation: metadata-only, no actions executed
python -m phantom_secops.evidence_playbook --out reports/evidence-playbook

# Cross-model smoke for codex/claude/hermes (optional)
# Set GOAL_MODEL_RUNNER_<MODEL> to a command template and rerun:
# GOAL_MODEL_RUNNER_CODEX="python scripts/run_goal_model_runner.py --model codex --scenario {scenario} --out_dir {out_dir} --target {target} --path {path}"
# GOAL_MODEL_RUNNER_CLAUDE="python scripts/run_goal_model_runner.py --model claude --scenario {scenario} --out_dir {out_dir} --target {target} --path {path}"
# GOAL_MODEL_RUNNER_HERMES="python scripts/run_goal_model_runner.py --model hermes --scenario {scenario} --out_dir {out_dir} --target {target} --path {path}"
# Make kill-chain output identical while models are still unavailable:
# make verify-goal
# make verify-goal-strict

# For strict audits (governance required + cross-model parity required):
make verify-goal-strict

# When phantom-mesh becomes usable, switch runners to mesh mode per model:
# GOAL_MODEL_RUNNER_CODEX="python scripts/run_goal_model_runner.py --model codex --mesh --scenario {scenario} --out_dir {out_dir} --target {target} --path {path}"
# make verify-goal-mesh

# Verify — full deterministic test suite (no real scanning in CI)
python -m pytest -q
```

Artifacts land in `reports/verification/<ts>/`:
- `killchain/` baseline run: `incident-report.md`, `pentest-report.md`, `summary.json`
- `checkup/checkup.txt`: checkup text artifact
- `governance/` governance decisions: `governance.jsonl` and `governance.log`
- `goal-manifest.json` with stable fields:
  - `run` (`mesh` + `provider`)
  - `killchain_signature` / `checkup_signature`
  - `models` outcomes
  - `model_compare` (`killchain` and `checkup`)
  - `governance` block (`decision_count`, `decision_values`, audit file)
- `audit_summary` with `killchain.mttd / outcome / detect_margin` and `governance_log`

P2 defensive-loop artifacts land in the directory passed to
`python -m phantom_secops.defensive_loop --out <dir>`:
- `findings.jsonl` with schema version 1 defensive findings.
- `timeline.json` with checkup -> verify -> analyze events.
- `analysis.json` with ranked defensive actions.
- `verification.json` with no-active-scan and no-runnable-PoC checks.
- `manifest.json` recording `active_scanning=false`, `external_network=false`,
  `exploit_poc=false`, and `writes_to_host=false`.

P2 evidence/playbook artifacts land in the directory passed to
`python -m phantom_secops.evidence_playbook --out <dir>`:
- `evidence-pack.json` with metadata-only synthetic evidence references.
- `playbook-simulation.json` with tabletop decisions and no executed actions.
- `decision-log.jsonl` with metadata-only response decisions.
- `verification.json` with no-action/no-scan/no-PoC checks.
- `manifest.json` recording `active_scanning=false`, `external_network=false`,
  `exploit_poc=false`, `writes_to_host=false`, and `read_only=true`.

P3 read-only reasoning artifacts land in the directory passed to
`python -m phantom_secops.reasoning_scenario --out <dir>`:
- `reasoning-report.json` with finding/evidence counts and read-only readiness.
- `kill-chain-hypotheses.json` with synthetic advice-only hypotheses.
- `playbook-review.json` with tabletop decision review and no executed actions.
- `audit-summary.json` with metadata-only audit events.
- `manifest.json` recording `active_scanning=false`, `external_network=false`,
  `exploit_poc=false`, `writes_to_host=false`, `read_only=true`, and
  `actions_executed=false`.

Full P3 contract: [docs/REASONING_SCENARIO.md](docs/REASONING_SCENARIO.md).

---

## The moat: read-only + governed MCP orchestration + LLM-as-triager

These boundaries **are the product**, not limitations:

- **Read-only / plain-text output.** The exploit-suggester emits *prose only* — `has_runnable_poc`
  is permanently `false`. Endpoint tools are read-only and self-scoped. It **advises**; it never
  changes your system.
- **Governed MCP orchestration.** Every tool is tagged with `x-phantom.{classification, capabilities,
  read_only}` capability metadata (e.g. `blue` / `read.host_posture` / `target.self_only`) — the hook
  for the per-agent policy enforcer in phantom-mesh, paired with its governor + phone-approval plane.
- **LLM as explainer / triager only.** Mirroring what actually works in production (Semgrep Assistant,
  Corgea, Socket): deterministic engines find facts, the LLM ranks / dedupes / explains. The
  deterministic core (`posture_fusion`) contains **no LLM** — it's the trustworthy spine.

Why this niche? The open-source offensive-agent space is a crowded gold-rush toward *fully autonomous
exploitation* (Strix, CAI, PentAGI). The **blue-team + endpoint-hygiene + governed-MCP** lane is far
less crowded — and the leading generic security-MCP bundles are *ungoverned and now archived*. The
gap is exactly **governance + a capability/policy model + a read-only posture**. See the full
landscape analysis in [docs/phantom-secops.md](docs/phantom-secops.md#開源生態與方向).

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                       phantom-mesh runtime                          │
│   LLM provider routing · tool-calling loop · cost tracking ·        │
│   inter-agent message passing · governor + phone-approval plane     │
└─────────────┬───────────────────────────────────┬──────────────────┘
        ┌─────▼────────┐                    ┌───────▼──────┐
        │  RED agents  │   (TOML-defined)   │  BLUE agents │
        └─────┬────────┘                    └───────┬──────┘
        ┌─────▼────────┐                    ┌───────▼──────┐
        │ tool wrappers│  injectable runner │ tool wrappers│
        │  (Python)    │  + x-phantom tags  │  (Python)    │
        └─────┬────────┘                    └───────┬──────┘
   docker exec│ into attacker        docker socket  │ → log volume
        ┌─────▼──────────────────────────────────── ▼──────┐
        │              secops-lab docker network            │
        │   juice-shop · dvwa · metasploitable  (targets)   │
        │   attacker (nmap/nuclei) · log-collector          │
        └───────────────────────────────────────────────────┘
```

**8 engine modules**, each a pure module behind an *injectable command runner* (so OS-touching logic
is unit-tested with canned output — zero real scanning in CI):

| Capability | Engine | MCP tool |
|---|---|---|
| Host posture (firewall / disk encryption / AV / UAC / ports / SIP) | native OS queries | `secops_host_audit` |
| Dependency / OS-package CVEs (prioritised, fixable-first) | **Trivy** | `secops_vuln` |
| Host intrusion detection (encoded PowerShell, download cradles, AMSI bypass…) | small **Sigma** engine over Windows event logs | `secops_ids` |
| Config self-audit (phantom-mesh `agents.toml` hygiene) | native | `secops_self_audit` |
| Lab recon / log-anomaly (Pillar-1 tools, also exposed) | nmap / pattern matcher | `secops_recon`, `secops_log` |

The deterministic spine `posture_fusion.fuse_posture` merges `host_audit` + `vuln_scan` + `ids_scan`
into a single ranked action list (normalized severity, highest-risk-first, stable tiebreak,
plain-language, **no LLM**), wired into the real `checkup.ps1`.

---

## Why it's credible (engineering rigor)

- **200+ passing tests**, all behind injectable runners — no real scanning in the test suite.
  CI in `.github/workflows/ci.yml`.
- **Honest degradation, never a false alarm.** Checks that need admin return `unknown` + a
  "re-run as administrator" hint, not a false `fail`. A missing scanner in a live run shows a
  **DEGRADED** banner instead of a clean-looking "0 findings".
- **Low false-positives over coverage.** An IDS rule that flagged a *signed Microsoft module manifest*
  as a download-cradle was tightened to 0 noise on 800 events. I deliberately **don't** stack 300+ CIS
  checks — for a personal machine that's alert fatigue, not security.
- **Feed-don't-rescan.** Deterministic findings are handed to the agent once; letting it re-scan a
  large repo timed out and falsely reported "no findings" while the log had 864.
- **Security hardening of the tooling itself.** `eval()` → a safe-AST boolean evaluator, nmap
  shell-injection patched, nuclei lab-gate fixed from a substring bypass to exact-hostname matching.

---

## Deliberate non-goals (permanent red lines, not future work)

| ⛔ Red line | Why |
|---|---|
| No runnable PoC / exploit | `has_runnable_poc` is always `false`; the suggester emits prose only. This line **is the product**. |
| No external scanning | Lab targets are localhost / Docker-overlay only; endpoint tools are read-only and self-scoped. |
| No auto-remediation | Every tool advises, never changes your system. Until a human-in-the-loop approval model exists, you act — by design. |
| No autonomy drift | The gravity of this field is "let it self-exploit." Every step that way *erases* the niche and *adds* legal surface. |
| No "autonomous 0-day" headline chasing | That's frontier-lab + heavy-compute territory, not a solo Apache project's goal. |

Full legal scoping: [ETHICS.md](ETHICS.md). Engineering decisions: [docs/phantom-secops.md](docs/phantom-secops.md).
