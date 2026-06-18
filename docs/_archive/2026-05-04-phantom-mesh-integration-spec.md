> ARCHIVED 2026-06-19 — frozen historical snapshot; current status lives in /ROADMAP.md
>
> Superseded: the MCP layer shipped as seven servers under `phantom_secops/mcp/`
> (not the three named here), and the `x-phantom` enforcer is still planned-next.

# phantom-secops ⇄ phantom-mesh integration (day-1 design)

**Date:** 2026-05-04
**Author:** Z13 session
**Time budget:** 6.5h, target ship 13:00 same day
**Status:** approved by user §1–§4, ready for implementation plan

## 1. Goals

Make phantom-secops actually run as a phantom-mesh-driven multi-agent system,
replacing today's deterministic `run_kill_chain.py` orchestrator with phantom-mesh
agent loops calling MCP plugins.

Three plugins ship today, one per "hat" of the dual-use suite:

| Plugin | Hat | Wraps | Caps |
|---|---|---|---|
| `secops_recon_server` | red | existing `tools/nmap_runner.py` (lab-only gate intact) | `network.scan.passive`, `target.lab_only` |
| `secops_log_server` | blue | `_blue_log_anomaly()` extracted from `run_kill_chain.py` to `tools/log_anomaly.py` | `read.log_files`, `target.localhost_only` |
| `secops_self_audit_server` | internal | NEW (~50 LOC) — scans phantom's own `agents.toml` | `read.config.local`, `target.self_only` |

phantom-mesh ships one extension: `core/src/mcp_client.rs` gains an
`x-phantom.*` metadata-aware capability enforcer (~150 LOC + tests) that
matches each tool call against per-agent `plugin_policy` declared in
`agents.toml`.

## 2. Non-goals (day-1)

- Plugin signing / supply-chain verification.
- Per-call rate limiting (existing `[agent.X].limits.max_tool_calls` is
  the only governor).
- Cross-plugin call correlation in audit.
- Wrapping `nuclei_runner.py` (status: WIP in phantom-secops).
- Android worker deployment (needs Termux per memory; cross-day).
- Replacing `run_kill_chain.py` mock-mode (kept for offline/CI; new
  phantom-mesh path is the live mode).

## 3. Architecture

```
┌──────────────────────────────────────────────────────────────┐
│           phantom-mesh (D:/Projects/phantom-mesh-private)    │
│   core/src/mcp_client.rs                                     │
│      + x-phantom capability enforcer (NEW)                   │
│   ~/.phantom-mesh/agents.toml on mac-coord:                  │
│      [[mcp_servers]] entries → spawn phantom-secops servers  │
│      [agent.X.plugin_policy] declares allow/deny rules       │
└────────┬───────────────────────────────────────┬─────────────┘
         │ stdio JSON-RPC                         │
┌────────▼───────────────────────────────────────▼─────────────┐
│          phantom-secops (D:/Projects/phantom-secops)         │
│   mcp/                                  ← NEW                │
│     secops_recon_server.py                                   │
│     secops_log_server.py                                     │
│     secops_self_audit_server.py                              │
│   tools/  (existing) + log_anomaly.py extracted              │
│   agents/ (existing TOMLs as canonical "what each does" doc) │
│   scripts/render-mesh-agents.py  ← NEW                       │
│   scenarios/run_kill_chain.py    (kept; mock-mode unchanged) │
└──────────────────────────────────────────────────────────────┘
```

## 4. Plugin contract

Each MCP server's `tools/list` response embeds three optional fields per
tool, namespaced under `x-phantom.*` to avoid clashing with vanilla MCP
semantics:

```json
{
  "name": "scan_target",
  "description": "nmap top-1000 scan against an in-lab service name.",
  "inputSchema": { ... },
  "x-phantom.classification": "red",
  "x-phantom.capabilities": ["network.scan.passive", "target.lab_only"],
  "x-phantom.read_only": true
}
```

- `classification` ∈ `{"internal", "blue", "red"}`. Ordering:
  `internal < blue < red`.
- `capabilities`: array of dotted glob-friendly strings. Conventions:
  - `read.*` — read-only capabilities (`read.config.local`,
    `read.log_files`, `read.process_list`, …).
  - `network.scan.passive` / `network.scan.active`.
  - `target.<scope>` — declarative target restriction
    (`target.lab_only`, `target.localhost_only`, `target.self_only`,
    `target.tailscale_peers_only`, `target.rfc1918_only`).
  - `exec.shell`, `write.*` — kept reserved; no day-1 plugin uses them.
- `read_only`: convenience boolean for default-allow logic
  (see §6.4).

A tool that omits all three fields is treated as **vanilla MCP** —
policy enforcer is skipped entirely (backward compatibility with
existing MCP servers like filesystem).

## 5. agents.toml extension

New optional `plugin_policy` table per agent:

```toml
[agent.master]
provider = "groq"
model    = "openai/gpt-oss-20b"   # tool-use-capable; per cluster memory 2026-05-03
tools    = ["shell", "file_read", "file_write", "web_fetch"]

[agent.master.plugin_policy]
allowed_capabilities = [
  "read.*",
  "network.scan.passive",
  "target.localhost_only",
  "target.self_only",
  "target.lab_only",
]
denied_capabilities = ["exec.shell", "network.scan.active", "write.*"]
classification_max  = "red"  # day-1 demo permissive; production master = "blue"
```

- `allowed_capabilities` — every cap a tool declares must match at least
  one entry (glob). Empty array = nothing allowed.
- `denied_capabilities` — explicit deny wins over allow.
- `classification_max` — tool's classification must be ≤ this.

For day-1 we ship one permissive policy on `master` (so the demo can
exercise all three plugins). Production deployment should split into
`auditor` (internal-only), `blue-triage` (blue-only), `red-recon`
(red, with target-scope restrictions).

New `[[mcp_servers]]` entries point at phantom-secops:

```toml
[[mcp_servers]]
name    = "secops_recon"
command = "python"
args    = ["-m", "phantom_secops.mcp.secops_recon_server"]
cwd     = "${PHANTOM_SECOPS_ROOT}"
env     = { PYTHONPATH = "${PHANTOM_SECOPS_ROOT}" }

[[mcp_servers]]
name    = "secops_log"
command = "python"
args    = ["-m", "phantom_secops.mcp.secops_log_server"]
cwd     = "${PHANTOM_SECOPS_ROOT}"

[[mcp_servers]]
name    = "secops_self_audit"
command = "python"
args    = ["-m", "phantom_secops.mcp.secops_self_audit_server"]
cwd     = "${PHANTOM_SECOPS_ROOT}"
```

`${PHANTOM_SECOPS_ROOT}` is resolved by the deploying script (§9
`make mesh-sync`) to the actual checkout path on the target host
(mac-coord: `/Users/<account>/Projects/phantom-secops` or wherever
the user clones it). phantom-mesh's existing `[[mcp_servers]]`
loader already expands `${ENV_VAR}` patterns in `cwd`, `args`, and
`env` values.

## 6. Data flow

### 6.1 Startup

1. `phantom serve` reads `agents.toml`.
2. For each `[[mcp_servers]]`: `mcp_client.rs::McpClient::spawn` (existing).
3. JSON-RPC `initialize` → `tools/list`.
4. For each tool, parse `x-phantom.*` from the tool object. Persist into
   the global registry keyed `(server_name, tool_name)`.
5. Tools with malformed metadata (e.g. unknown `classification`) are
   logged at WARN and skipped — they don't appear in the agent's
   tool list.

### 6.2 Per-call

```
agent loop                        mcp_client.rs (NEW logic)         child plugin
──────────                        ─────────────────────────         ────────────
  call_tool(server, tool, args) ─►  policy_enforce():
                                      (a) lookup x-phantom fields
                                      (b) if absent → vanilla allow
                                      (c) if agent has no plugin_policy
                                          → fail-closed unless
                                          (classification=internal AND
                                           read_only AND
                                           all caps match `read.*`)
                                      (d) classification ≤ max?
                                      (e) every cap glob-matches an
                                          allowed_capabilities entry?
                                      (f) any cap matches denied? → deny
                                      ┌──────────────────┐
                                      ▼ deny             ▼ allow
                                  {error:                forward JSON-RPC
                                    code:                tools/call → child
                                    "policy_denied",     ▼
                                    denied:[…],          child internal
                                    classification:"red"} scope check
                                      ▼                  (defense-in-depth)
                                  audit jsonl append    ▼
                                                       run, return JSON
                                      ▲                  ▼
                                      └─── audit jsonl ──┘
                                              │
   ◄──────────────────────────────────────────┘
```

### 6.3 Audit log

Path: `~/.phantom-mesh/data/secops-audit.jsonl`. One JSON line per
`tools/call` decision:

```json
{
  "ts": "2026-05-04T07:13:42Z",
  "agent": "master",
  "plugin": "secops_recon",
  "tool": "scan_target",
  "input_hash": "sha256:ab12...",
  "classification": "red",
  "capabilities": ["network.scan.passive", "target.lab_only"],
  "decision": "allow",
  "duration_ms": 83
}
```

`input_hash` (not raw input) prevents the audit log from becoming a
secondary leakage channel for any sensitive tool args in future plugins.

### 6.4 Default policy (no `plugin_policy` configured)

| Tool x-phantom state | Decision |
|---|---|
| No x-phantom fields at all | allow (vanilla MCP backward compat) |
| Has x-phantom, classification=`internal` AND read_only=true AND every cap matches `read.*` | allow |
| Anything else with x-phantom | **deny** + WARN log "agent X has no plugin_policy; tool Y was denied" |

Rationale: fail-closed is the right default for a sec-ops contract, but
self-audit-style read-only inspection should not be blocked by the
absence of an opt-in policy.

## 7. The three plugins

Each plugin is `python -m phantom_secops.mcp.<server_name>` runnable
standalone. Uses official `mcp` Python SDK (`pip install mcp`).

### 7.1 `secops_recon_server`

Wraps `tools/nmap_runner.py` (no changes to that file).

Tools exposed:

- `scan_target(target: str, ports: str = "top-1000")` — calls
  `nmap_runner.run`. The existing `_target_in_lab` gate is preserved
  (defense-in-depth: phantom-mesh policy says target.lab_only, plugin
  itself also enforces).

x-phantom metadata: `classification=red`, `capabilities=["network.scan.passive", "target.lab_only"]`, `read_only=true` (nmap doesn't write to target).

### 7.2 `secops_log_server`

First step is to extract `_blue_log_anomaly()` from
`scenarios/run_kill_chain.py` into `tools/log_anomaly.py` so the MCP
server can import it cleanly (and so existing `run_kill_chain.py`
keeps working unchanged — it just imports from the new location).

Tools exposed:

- `scan_log(path: str, max_lines: int = 10000)` — runs the URL-decoded
  pattern matcher (sqli/traversal/xss/admin/scanner) over the file,
  returns alerts JSON.

x-phantom: `classification=blue`, `capabilities=["read.log_files", "target.localhost_only"]`, `read_only=true`.

### 7.3 `secops_self_audit_server`

NEW, ~50 LOC. Scans phantom's own `~/.phantom-mesh/agents.toml` for:
- providers with `api_key = "..."` literal (vs `api_key_env = "..."`).
- `[cluster].cluster_secret` length < 16 chars or absent.
- `[core].host = "0.0.0.0"` listeners (CGNAT-exposed).
- MCP servers whose `command` resolves outside `$HOME` (untrusted path).

Tools exposed:

- `audit_local_config()` — returns findings JSON (severity tagged).

x-phantom: `classification=internal`, `capabilities=["read.config.local", "target.self_only"]`, `read_only=true`.

## 8. phantom-mesh side: `mcp_client.rs` changes

Estimated ~150 LOC + tests. Touches one file (`core/src/mcp_client.rs`).

1. Extend the per-tool struct held in `McpRegistry` with optional
   `x_phantom: Option<XPhantomMetadata>` (parsed at `tools/list` time).
2. Add `mod policy` with the enforcer:
   `fn check(agent_policy: Option<&AgentPluginPolicy>, tool_meta: Option<&XPhantomMetadata>) -> PolicyDecision`.
3. Modify `call_tool` to invoke `policy::check` before the JSON-RPC
   forward; on deny, return synthetic `{"error": {...}}` without
   touching the child.
4. Append an audit-log entry on every `call_tool` (allow or deny). Path
   resolved via existing `dirs_dir()` helper.
5. New `[agent.X.plugin_policy]` schema in `core/src/config.rs`
   (`AgentConfig`).

Five Rust unit tests:
- `test_classification_ordering`
- `test_capability_glob_match`
- `test_deny_overrides_allow`
- `test_no_xphantom_is_vanilla`
- `test_fail_closed_when_xphantom_no_policy`

Plus one integration test using a fake echo MCP server with synthetic
`tools/list` metadata.

## 9. agents/ render script

`scripts/render-mesh-agents.py`: takes a phantom-secops agent TOML
(`agents/red/recon.toml`) and outputs a phantom-mesh `[agent.X]`
fragment.

Input (existing phantom-secops format):
```toml
[agent]
name = "red-recon"
[[agent.tools]]
name = "nmap_runner"
[agent.prompt]
system = """You are a red-team reconnaissance agent..."""
[agent.limits]
max_tool_calls = 12
```

Output (phantom-mesh format):
```toml
[agent.red-recon]
provider     = "groq"                       # default; --provider overrides
model        = "openai/gpt-oss-20b"          # default; --model overrides
tools        = ["secops_recon.scan_target", "file_write"]   # tool names map: nmap_runner → secops_recon.scan_target
instructions = """You are a red-team reconnaissance agent..."""
[agent.red-recon.limits]
max_tool_calls = 12

[agent.red-recon.plugin_policy]              # derived from tool capabilities
allowed_capabilities = ["network.scan.passive", "target.lab_only"]
denied_capabilities  = ["exec.shell", "network.scan.active", "write.*"]
classification_max   = "red"
```

Mapping table (script-internal):
- `nmap_runner` → `secops_recon.scan_target`
- `log_ingest` (when wrapped) → `secops_log.scan_log`
- `file_read` / `file_write` → phantom-mesh built-ins (no MCP)
- Unmapped tool name → render as comment `# TODO: map <name>` with WARN exit code 2

Day-1 only renders `red/recon.toml` and `blue/alert-triage.toml`,
manually-verified. Other 6 agents render later.

`Makefile` target `mesh-sync`: substitutes `${PHANTOM_SECOPS_ROOT}` and
appends rendered fragment(s) to mac-coord's `~/.phantom-mesh/agents.toml`
after manual diff review (`make mesh-sync DRY_RUN=1` first).

## 10. Error handling

| Failure | Behavior |
|---|---|
| Plugin process spawn failure | Existing mcp_client.rs supervision: log error, phantom continues without that plugin |
| Plugin crashes mid-call | Existing per-request timeout in `McpClient::call_tool` reaps; error to agent loop; respawn on next call |
| Plugin returns invalid JSON | mcp_client.rs JSON parse fails; error to agent; audit decision=`plugin_error` |
| `tools/list` x-phantom metadata malformed | Tool not registered; WARN log; other tools unaffected |
| Agent calls denied tool | `{"error":{"code":"policy_denied","denied_capability":...}}`; agent can adapt |
| Plugin self-rejects bad target (e.g. nmap on google.com) | Plugin returns error JSON; mcp_client.rs forwards; audit log records reason |
| Audit log write fails | WARN log, decision still applied (audit must not block dispatch) |

## 11. Testing

**phantom-secops (Python, pytest):**
- `tests/test_mcp_recon_server.py`: tools/list metadata shape; valid lab target; refused external target.
- `tests/test_mcp_log_server.py`: parses mock attack log; honors `max_lines`.
- `tests/test_mcp_self_audit_server.py`: detects plaintext key, weak cluster_secret, 0.0.0.0 binding.

**phantom-mesh (Rust, cargo test):**
- 5 unit tests in `mcp_client.rs::tests` (listed §8).
- 1 integration test with fake echo MCP server.

**End-to-end smoke (manual, run on Mac coord):**
1. Apply agents.toml additions on mac-coord.
2. Restart `phantom serve`.
3. From Z13 over Tailscale + HMAC, POST `/rpc/task/assign` three times:
   - `"recon juice-shop"` → expect `secops_recon.scan_target` invoked.
   - `"summarize alerts in lab/mocks/attack-log.txt"` → expect `secops_log.scan_log`.
   - `"audit my own agents.toml for plaintext keys"` → expect `secops_self_audit.audit_local_config`.
4. `tail -n 5 ~/.phantom-mesh/data/secops-audit.jsonl` should show 3 `decision="allow"` lines.

## 12. 6.5h implementation timeline

| Slot | Work | Repo |
|---|---|---|
| 06:40–08:00 (1.3h) | This spec + commit | phantom-secops |
| 08:00–08:15 | Self-review + user approval | — |
| 08:15–09:30 (1.25h) | Three MCP servers + unit tests (parallel scaffolds) | phantom-secops |
| 09:30–10:30 (1h) | `mcp_client.rs` x-phantom enforcer + 5 tests + config schema | phantom-mesh-private |
| 10:30–11:00 (0.5h) | `scripts/render-mesh-agents.py`; render red-recon + blue-alert-triage | phantom-secops |
| 11:00–12:00 (1h) | Mac-coord agents.toml apply + restart phantom + 3 plugin smoke | mac coord (live) |
| 12:00–12:45 (0.75h) | Two PRs (mesh + secops) | both repos |
| 12:45–13:00 (0.25h) | Buffer / SESSION_RESUME notes | — |

## 13. Risk register

| Risk | Mitigation |
|---|---|
| `mcp` PyPI SDK API has shifted recently | Pin version in `requirements-dev.txt`; if breaks day-of, fall back to hand-rolled stdio JSON-RPC (~30 LOC; the protocol is small) |
| mac-coord phantom restart drops cluster heartbeat with ROG / others | nohup-detach pattern from 2026-05-03 SMOKE used; downtime <10s |
| Tool-use model on master agent emits malformed tool_calls (per 2026-05-03 memory) | Use `groq/openai/gpt-oss-20b` not llama-3.3 default |
| Mac-coord agents.toml misedit bricks daemon | Same `.bak.smoke-2026-05-04` backup pattern as 2026-05-03 SMOKE |
| `run_kill_chain.py` import path breaks when `_blue_log_anomaly` extracted | Re-export from old location for backward compat: `from tools.log_anomaly import _blue_log_anomaly` |

## 14. Open question (deferred to v2)

When agent A calls plugin P which triggers another agent B (cluster
RPC), the audit trail today only records A→P. Cross-call correlation
(linking A's call to B's resulting calls) would need a trace_id flowing
through cluster RPC. Out of scope day-1.
