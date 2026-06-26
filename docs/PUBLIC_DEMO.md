# Public Demo Contract

`phantom-secops` public demos must remain read-only, governed, and safe by
default. They may use mock data, synthetic fixtures, or an isolated intentionally
vulnerable lab only when the user explicitly opts in.

## Hermetic Defensive Workbench Loop

The P2 default artifact path is the Hermetic Defensive Workbench Loop:

```powershell
python -m phantom_secops.defensive_loop --out <bundle-dir>
```

This path does not run nmap, nuclei, Trivy, IDS log readers, Docker, external
network calls, exploit tooling, or host mutation. It writes a deterministic
synthetic checkup -> verify -> analyze bundle.

Bundle artifacts:

- `manifest.json`: schema version, mode, safety flags, and artifact list.
- `findings.jsonl`: schema version 1 defensive findings.
- `timeline.json`: checkup, verify, and analyze events with finding IDs.
- `analysis.json`: ranked defensive actions and severity counts.
- `verification.json`: contract checks for schema, references, no active scan,
  no runnable PoC, and read-only behavior.
- `summary.md`: short human-readable summary.

`manifest.json` must include `active_scanning=false`,
`external_network=false`, `exploit_poc=false`, `writes_to_host=false`, and
`synthetic_only=true`.

## Other Public Paths

- `python scenarios/run_kill_chain.py --target juice-shop --mock` is CI-safe and
  uses mock data.
- `python scripts/run_goal.py --out <temp> --path .` writes a verification pack.
- `python -m phantom_secops.evidence_playbook --out <bundle-dir>` writes a
  metadata-only evidence pack and tabletop playbook simulation.
- `python -m pytest -q` runs the deterministic test suite.
- `.\checkup.ps1` is a local endpoint check and may expose host details; do not
  treat its output as a public fixture.

## Hermetic Evidence Pack And Playbook Simulation

The second P2 artifact path expands the defensive workbench without adding
active behavior:

```powershell
python -m phantom_secops.evidence_playbook --out <bundle-dir>
```

This path does not run scanners, exploit tooling, Docker, shell commands,
external network calls, or host mutation. It writes metadata-only synthetic
evidence references and tabletop response decisions.

Bundle artifacts:

- `manifest.json`: schema version, mode, safety flags, and artifact list.
- `evidence-pack.json`: metadata-only synthetic evidence references.
- `playbook-simulation.json`: tabletop decisions with no executed actions.
- `decision-log.jsonl`: metadata-only response decisions.
- `verification.json`: contract checks for metadata-only evidence, no executed
  actions, no active scan, no host writes, and no runnable PoC.
- `summary.md`: short human-readable summary.

`manifest.json` must include `active_scanning=false`,
`external_network=false`, `exploit_poc=false`, `writes_to_host=false`,
`read_only=true`, and `synthetic_only=true`.

## P3 Read-only Reasoning Scenario

The P3 reasoning scenario combines the defensive workbench bundle with the
evidence/playbook bundle and writes advice-only hypotheses plus a playbook
review:

```powershell
python -m phantom_secops.reasoning_scenario --out <bundle-dir>
```

Bundle artifacts:

- `manifest.json`: schema version, mode, safety flags, source bundle references,
  and artifact map.
- `reasoning-report.json`: finding/evidence counts and read-only readiness.
- `kill-chain-hypotheses.json`: synthetic defensive hypotheses.
- `playbook-review.json`: tabletop decision review with no executed actions.
- `audit-summary.json`: metadata-only event summary.
- `summary.md`: human-readable summary.

`manifest.json` must include `active_scanning=false`,
`external_network=false`, `exploit_poc=false`, `writes_to_host=false`,
`read_only=true`, `actions_executed=false`, and `synthetic_only=true`.

This path does not run scanners, exploit tooling, Docker, shell commands,
external network calls, host mutation, or response actions.

## Safety Boundary

Public artifacts must not contain runnable exploit payloads, external targets,
customer host data, secrets, or active scan instructions. The project can
recommend defensive action, but it must not exploit, mutate, or scan third-party
systems by default.
