# M2 demo — a governed agent loop that refuses and asks permission

**What this shows:** the M1 agent-driven kill-chain, now **governed**. Two
guarantees enforced at the `secops_mcp` façade (the tool-dispatch point this repo
controls, because phantom-mesh 0.6 enforces none of this — it ignores x-phantom
metadata and wires no approval gate to headless runs):

1. **`blue ↛ red` structural deny** — a blue (defender) agent is refused red-team
   tools outright, no human in the loop.
2. **Risk-based approval gate** — live scans and live writes must be approved
   before they run; mock and read-only calls auto-allow.

This is the M2 milestone of [`docs/EXECUTION-PLAN.md`](../EXECUTION-PLAN.md):
*agentic security that asks permission.*

## The four governance boundaries (deterministic, no phantom/docker)

```bash
make demo-governed     # = python scenarios/demo_governance.py
```

```
[1] blue agent → red tool (recon)         expect: structural DENY
    ⛔ role 'blue' is structurally barred from 'red' tools  (by role-policy)

[2] blue agent → blue tool (detect)       expect: ALLOW
    ✅ allowed — 6 triaged groups

[3] live red scan, no approval            expect: fail-closed DENY
    ⛔ approval denied: auto-denied: no operator present and auto-allow not enabled  (by approval)

[4] live red scan, manual approval        expect: PAUSE → approve → release
    ⏸  pending-recon.json written; operator runs:
        python -m secops_mcp.approve <approvals-dir> recon allow
    ✅ released via manual-file: self-authorized lab → the real scan would now run

governance.jsonl audit trail:
  - recon      role=blue         denied-role
  - detect     role=blue         auto-allow
  - recon      role=orchestrator denied-approval
```

## blue ↛ red, validated through the REAL agent loop

Running a **blue-role** agent against the live phantom-mesh loop (mock data, so
no scanning), the agent's very first red-tool call is refused by the façade and
the refusal is both returned to the model and audit-logged:

```bash
PHANTOM_SECOPS_ROOT=$PWD SECOPS_AGENT_ROLE=blue SECOPS_MCP_MOCK=1 \
SECOPS_MCP_STATE_FILE=reports/_run/state.json SECOPS_MCP_OUT_DIR=reports/_run \
phantom exec --config secops-demo.toml --agent killchain \
    "You are the BLUE defender. Call secops_kc_recon first."
```

```
[tool] secops_kc_recon {"target":"juice-shop"}
[done] secops_kc_recon → {"error": "role 'blue' is structurally barred from 'red' tools", "denied": true, "by": "role-policy"}
```

The model then reports, in its own words:

> I'm unable to run the `secops_kc_recon` tool because, as a BLUE defender, I
> don't have permission to execute red-team actions.

And the audit trail (`governance.jsonl`):

```json
{"tool": "recon", "role": "blue", "classification": "red", "mock": true, "decision": "denied-role", "reason": "role 'blue' is structurally barred from 'red' tools"}
```

## How approval works (and what's deferred)

A high-risk live call asks an `ApprovalProvider` before running:

- **`AutoApprovalProvider`** — non-interactive, **fail-closed** by default
  (denies); `auto-allow` lets unattended live runs proceed. Used in CI.
- **`ManualApprovalProvider`** — file-based local gate: writes
  `pending-<action>.json` and **blocks** until the operator drops a decision via
  `python -m secops_mcp.approve <dir> <action> allow|deny`, then continues. This
  is the pause→approve→resume mechanism boundary (2)/(3) require.

Selected per run with `SECOPS_MCP_APPROVAL={auto-deny,auto-allow,manual}` and
`SECOPS_AGENT_ROLE={orchestrator,red,blue}`.

> Deferred honestly: the **phone** channel specifically (Telegram via
> phantom-mesh openclaw) is not built — openclaw is one-way dispatch today, not
> an approve/deny flow (see the M2 survey in EXECUTION-PLAN). A
> `TelegramApprovalProvider` plugs in behind the same `ApprovalProvider`
> interface when that lands. Today the pause/resume gate is proven via the
> manual file provider.

## Where enforcement lives (and why)

`secops_mcp/policy.py` (the governor) + `secops_mcp/approval.py` (the channels)
+ `secops_mcp/server.py` `_govern()` (the gate, run before every tool). It's
in-repo by design: phantom-mesh can't enforce x-phantom yet, so the façade does.
M4 moves this to a cross-repo Rust enforcer in phantom-mesh — the moat — at which
point the same policy becomes usable by *any* MCP security tool, not just this one.
