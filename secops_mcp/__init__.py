"""Agent-loop façade for the phantom-secops kill-chain.

Exposes the red/blue kill-chain steps (implemented once in
`phantom_secops.killchain`) as a small set of composite MCP tools that a
phantom-mesh agent calls in sequence — turning the deterministic Python
orchestrator (`scenarios/run_kill_chain.py`) into a genuine agent-driven loop
WITHOUT forking the step logic. Both front-ends share one implementation, so
the agent-driven output stays parity-equivalent to the direct driver (M1).

Nothing here is autonomous or stateful beyond a per-run JSON file, and the
exploit-suggester remains prose-only (has_runnable_poc never true). See
ETHICS.md.
"""
