> ARCHIVED 2026-06-19 — 內容已併入 docs/phantom-secops.md;此為歷史版本。

# L2 Integration Plan: phantom-secops × phantom-mesh

**Status:** drafted 2026-05-10, target completion 5/14 evening + 5/15 evening (~5h total).

**Goal:** make phantom-secops's red/blue agents run on phantom-mesh's runtime via MCP, while preserving the deterministic `make demo-mock` output (recruiters can clone + run with no API keys).

---

## Current state

- Existing 10-tool MCP server lives at `phantom_secops/mcp/server.py` (FastMCP). **Keep this** as the rich interface for direct MCP clients (Claude Code, Cursor).
- `make demo-mock` runs `python3 scenarios/run_kill_chain.py --target juice-shop --mock`, calling `phantom_secops.core.{run_recon, run_vuln_scan, ...}` directly. No LLM in mock mode.
- Mock fixtures live in `lab/mocks/*.json`.
- Existing red/blue agent TOMLs at `agents/{red,blue}/*.toml` are documentation, not orchestrator-driven.
- LLM abstraction at `phantom_secops/llm/` has 4 providers; `phantom_mesh_provider.py` (HTTP-against-`phantom serve`) becomes redundant after this work — mark `# DEPRECATED` in this PR, delete next release.

---

## Architecture

```
make demo-mock-mesh
  ↓
scenarios/run_kill_chain.py --driver=mesh --mock
  ↓ (per turn: red recon, exploit, blue detect, respond)
subprocess.run(["phantom", "repl", "--agent", "red_team",
                "-c", "Run recon and call secops_recon, then stop."],
               env={SECOPS_MCP_MOCK=1, SECOPS_MCP_STATE_FILE=/tmp/state.json})
  ↓
phantom-mesh agent loop (config: ./agents.toml.demo)
  ↓ tool dispatch via [[mcp_servers]] config
secops_mcp.server (stdio MCP, 4 tools)
  ↓ delegates to phantom_secops.core + reads/writes
state.json (single source of truth between turns)
```

State exchange via JSON file — NOT stdout parsing — because `phantom repl -c` stdout
has ANSI + cost lines that are fragile to parse.

---

## File-level changes

### New files

| Path | Purpose |
|---|---|
| `secops_mcp/__init__.py` | Package marker; re-exports `main` |
| `secops_mcp/server.py` | FastMCP stdio server, **4 tools only**: `recon`, `exploit`, `detect`, `respond` |
| `secops_mcp/state.py` | `load_state(path) → dict`, `save_state(path, dict)`, `default_state()` |
| `secops_mcp/determinism.py` | Reads `SECOPS_MCP_MOCK`, `SECOPS_MCP_STATE_FILE`; thin layer for canned data |
| `agents.toml.demo` | Complete phantom-mesh config for one-command demos (project-local) |
| `agents.toml.snippet` | Paste-in fragment for users' existing phantom-mesh configs |
| `docs/L2-INTEGRATION.md` | User-facing guide: install snippet, run demo through phantom-mesh |
| `tests/test_secops_mcp_tools.py` | Unit tests for 4 tools, deterministic output assertions |
| `tests/test_demo_mock_parity.py` | Golden-file diff: legacy demo-mock vs mesh demo-mock |

### Modified files

| Path | Change |
|---|---|
| `Makefile` | Add `secops-mcp-serve` + `demo-mock-mesh`; **leave `demo-mock` unchanged** for parity |
| `scenarios/run_kill_chain.py` | Add `--driver={direct,mesh}` flag (default `direct`); when `mesh`, replace `core.X(...)` calls with `subprocess.run(["phantom", "repl", "--agent", X, "-c", ...])` |
| `README.md` | Add "Drive via phantom-mesh" section pointing at snippet |

### Deprecated (keep in v1, remove next release)

| Path | Action |
|---|---|
| `phantom_secops/llm/phantom_mesh_provider.py` | Add `# DEPRECATED — use secops_mcp + phantom-mesh [[mcp_servers]]` |

---

## 4 MCP tools (the L2 surface)

Each tool sets `mock=True` when `SECOPS_MCP_MOCK=1` and reads/writes state via `SECOPS_MCP_STATE_FILE`.

```python
# Sketch — actual signatures match phantom_secops.core
@mcp.tool
def recon(target: str) -> dict:
    """Sweep ports + service detection. Wraps core.run_recon."""
    state = load_state()
    state["recon"] = core.run_recon(target, mock=is_mock())
    save_state(state)
    return {"open_ports": ..., "services": ..., "state_version": state["version"]}

@mcp.tool
def exploit(findings_id: str | None = None) -> dict:
    """Wraps core.run_vuln_scan + core.suggest_exploit_prose.
    Safety invariant: has_runnable_poc is ALWAYS False."""
    ...

@mcp.tool
def detect(source: str = "mock") -> dict:
    """Composite: scan_logs_for_anomalies + triage_alerts + correlate_threats."""
    ...

@mcp.tool
def respond(actors_id: str | None = None) -> dict:
    """Wraps core.compose_incident_report + core.compose_pentest_report."""
    ...
```

---

## `agents.toml.snippet` (paste at end of user's config)

```toml
[[mcp_servers]]
name    = "secops"
command = "python3"
args    = ["-m", "secops_mcp.server"]
env     = { SECOPS_MCP_MOCK = "1", SECOPS_MCP_STATE_FILE = "/tmp/secops_state.json" }

[agent.red_team]
provider = "anthropic"
model    = "claude-sonnet-4-6"
tools    = ["secops_recon", "secops_exploit", "file_write"]
instructions = """
You are a red-team operator inside an isolated security research lab.
Workflow: call secops_recon(target), then secops_exploit(). Persist artifacts.
Hard rules: only the configured lab targets; never produce runnable PoCs.
"""

[agent.blue_team]
provider = "anthropic"
model    = "claude-sonnet-4-6"
tools    = ["secops_detect", "secops_respond", "file_write"]
instructions = """
You are a SOC analyst. Call secops_detect(), then secops_respond() to draft
the incident report. Be decisive — P1 means wake the on-call.
"""
```

Tool names follow phantom-mesh's `<server_name>_<tool>` convention (declared `name = "secops"` → `secops_recon`).

---

## Risks + mitigations

| Risk | Mitigation |
|---|---|
| **LLM non-determinism** in `phantom repl` (biggest risk) | (a) Tight scripted prompts: "Call X, then stop." minimizes variance. (b) Parity test compares semantic fields (port counts, MTTD seconds, key strings), NOT byte-exact diff |
| `phantom` not on PATH | Orchestrator checks `PHANTOM_BIN` env first, falls back to `shutil.which("phantom")`, errors clearly if neither |
| `mcp` Python package missing | Mirror existing `phantom_secops/mcp/server.py` ImportError guard with install hint |
| `agents.toml` location | Ship `agents.toml.demo` as a complete file (not just snippet); orchestrator passes `--config ./agents.toml.demo` |
| Tool name prefixing untested | Probe with `phantom repl --agent red_team -c "list your tools"` before finalizing snippet |
| Schema drift between direct + mesh paths | Single `state.py` schema-validation function called by both |

---

## Test strategy

**Goal:** `make demo-mock` (direct path, unchanged) and `make demo-mock-mesh` (new mesh path) produce equivalent output.

`tests/test_demo_mock_parity.py`:
1. Run both makes, output to `/tmp/legacy/` and `/tmp/mesh/`.
2. Pure-function output files (`recon.json`, `vuln-scan.json`, `alerts.jsonl`, `triage-queue.jsonl`, `kill-chains.jsonl`): **byte-for-byte equality required**.
3. Generated reports (`pentest-report.md`, `incident-report.md`): strip `[t+…s]` timestamps + `agent_name` byline, then assert remaining content matches via `difflib`.
4. CI gate: must pass before merge.

Manual check:
```bash
diff -r /tmp/legacy /tmp/mesh \
  --ignore-matching-lines='^\[t+.*s\]' \
  --ignore-matching-lines='^_Generated by.*$'
```

Plus port `tests/test_no_runnable_poc.py` invariant onto `secops_mcp.server.exploit` output — safety invariant must survive the wrapper layer.

---

## Execution order (when you sit down to do this)

1. (30 min) Create `secops_mcp/` skeleton: `__init__.py`, `state.py`, `determinism.py`. Write 4 stub tools that just touch the state file and return canned data.
2. (1 h) Copy mock data flow from `phantom_secops/mcp/server.py` into `secops_mcp/server.py`'s 4 tools. Run `python -m secops_mcp.server` standalone to confirm it starts.
3. (30 min) Write `agents.toml.demo`. Run `phantom repl --config ./agents.toml.demo --agent red_team -c "list your tools"`; confirm `secops_recon`, `secops_exploit` show up.
4. (1.5 h) Refactor `scenarios/run_kill_chain.py` with `--driver=mesh`. Drive 4 turns via subprocess + state file.
5. (1 h) Write `tests/test_demo_mock_parity.py`. Iterate on prompt instructions until parity passes.
6. (30 min) Update `Makefile`, `README.md`, deprecate `phantom_mesh_provider.py`.

Total: ~5h. Two evenings (5/14 + 5/15) if you have 2-3h focused blocks.
