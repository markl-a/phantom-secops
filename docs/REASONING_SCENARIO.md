# Hermetic Read-only Reasoning Scenario

`phantom-secops` P3 adds a deterministic read-only reasoning scenario. It
combines the P2 defensive workbench bundle with the P2 evidence/playbook bundle,
then writes ranked hypotheses, a playbook review, and a metadata-only audit
summary.

Run it from a source checkout:

```powershell
python -m phantom_secops.reasoning_scenario --out <bundle-dir>
```

## Artifact Contract

The bundle writes these top-level files:

- `manifest.json`: schema version, mode, safety flags, source bundle references,
  and artifact map.
- `reasoning-report.json`: finding/evidence counts, readiness flags, and
  unsupported boundaries.
- `kill-chain-hypotheses.json`: synthetic read-only defensive hypotheses.
- `playbook-review.json`: tabletop decision review with no executed actions.
- `audit-summary.json`: metadata-only event summary.
- `summary.md`: short human-readable summary.

It also writes these source bundles:

- `defensive-loop/`: the P2 hermetic defensive workbench bundle.
- `evidence-playbook/`: the P2 evidence pack and tabletop playbook bundle.

`manifest.json` must include:

```json
{
  "schema_version": 1,
  "mode": "hermetic_read_only_reasoning_scenario",
  "synthetic_only": true,
  "active_scanning": false,
  "external_network": false,
  "exploit_poc": false,
  "writes_to_host": false,
  "read_only": true,
  "actions_executed": false
}
```

## Boundary

This scenario is advice-only. It performs no active scanning, contacts no
external systems, writes no host changes, executes no actions, and includes no
runnable proof of concept. Audit artifacts are metadata-only and must not retain
raw logs, host data, payloads, shell commands, or customer data.
