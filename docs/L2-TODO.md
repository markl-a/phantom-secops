# L2 Integration — TODO Checklist (5 h, 2 evenings)

Companion to [`L2-INTEGRATION-PLAN.md`](L2-INTEGRATION-PLAN.md). The plan
is the *what* and *why*; this file is the **15 concrete checkboxes** you
tick off in two evening sessions.

Recommended split: **5/14 evening (2.5 h)** = steps 1-3, **5/15 evening
(2.5 h)** = steps 4-7. Numbered in execution order — earlier steps
unblock later ones.

---

## 5/14 — evening (~2.5 h)

### Step 1 · Skeleton (~30 min)

- [ ] `mkdir secops_mcp && touch secops_mcp/__init__.py`
- [ ] Write `secops_mcp/state.py` with `load_state(path)`, `save_state(path, dict)`, `default_state()`. Schema:
      ```python
      {"target": str, "phase": str, "version": int,
       "recon": dict|None, "exploit": dict|None,
       "detect": dict|None, "respond": dict|None}
      ```
- [ ] Write `secops_mcp/determinism.py`:
      ```python
      def is_mock() -> bool: return os.getenv("SECOPS_MCP_MOCK") == "1"
      def state_path() -> Path: return Path(os.getenv("SECOPS_MCP_STATE_FILE", "/tmp/secops_state.json"))
      ```
- [ ] `python -c "from secops_mcp import state; state.save_state('/tmp/x.json', state.default_state())"` round-trips successfully.

### Step 2 · MCP server with 4 tools (~1 h)

- [ ] Copy `phantom_secops/mcp/server.py` skeleton (the FastMCP boilerplate + ImportError guard) into `secops_mcp/server.py`.
- [ ] Register exactly 4 tools:
      ```python
      @mcp.tool
      def recon(target: str) -> dict: ...
      @mcp.tool
      def exploit(findings_id: str | None = None) -> dict: ...
      @mcp.tool
      def detect(source: str = "mock") -> dict: ...
      @mcp.tool
      def respond(actors_id: str | None = None) -> dict: ...
      ```
- [ ] Each tool body: `state = load_state(state_path()); state[<tool>] = core.X(...mock=is_mock()); save_state(state_path(), state)`. Wrap `core.X` calls so existing `phantom_secops.core` functions are reused — no logic duplication.
- [ ] Add `if __name__ == "__main__": main()` so `python -m secops_mcp.server` boots the stdio server.
- [ ] Verify standalone: `SECOPS_MCP_MOCK=1 SECOPS_MCP_STATE_FILE=/tmp/s.json python -m secops_mcp.server` starts without error.

### Step 3 · agents.toml + probe (~1 h)

- [ ] Write `agents.toml.snippet` (paste-fragment).
- [ ] Write `agents.toml.demo` (complete file — `[core]` + `[providers.anthropic]` + the snippet content). This is what `make demo-mock-mesh` will use via `--config ./agents.toml.demo`.
- [ ] Manually probe tool naming:
      ```bash
      phantom repl --config ./agents.toml.demo --agent red_team -c "list your tools"
      ```
      Expected: `secops_recon`, `secops_exploit` appear in tools list. If they show as `secops/recon` or just `recon`, fix the snippet's `name = "secops"` field accordingly.
- [ ] Run a single tool through phantom-mesh:
      ```bash
      phantom repl --config ./agents.toml.demo --agent red_team \
                   -c "Call secops_recon with target=juice-shop, then stop."
      ```
      Verify: `/tmp/secops_state.json` is populated with a `recon` key. If yes, **L2 fundamentals work** → close the laptop, you're done for tonight.

---

## 5/15 — evening (~2.5 h)

### Step 4 · Orchestrator refactor (~1.5 h)

- [ ] Add `--driver={direct,mesh}` argparse flag to `scenarios/run_kill_chain.py`. Default `direct`.
- [ ] When `mesh`, replace each direct `core.X(...)` call with:
      ```python
      env = {**os.environ,
             "SECOPS_MCP_MOCK": "1",
             "SECOPS_MCP_STATE_FILE": str(state_path)}
      subprocess.run(
          [PHANTOM_BIN, "repl", "--config", "./agents.toml.demo",
           "--agent", agent_name, "-c", PROMPT],
          env=env, check=True, capture_output=True,
      )
      ```
      where `PHANTOM_BIN = os.environ.get("PHANTOM_BIN") or shutil.which("phantom")` — error clearly if neither.
- [ ] After each subprocess, `state = load_state(state_path); assert state[<expected_key>]`.
- [ ] Pull `pentest_report` and `incident_report` from final state, write to disk under existing filenames so artifact layout matches `--driver=direct`.
- [ ] Add `make demo-mock-mesh` Makefile target invoking `python3 scenarios/run_kill_chain.py --target juice-shop --mock --driver=mesh`.

### Step 5 · Parity test (~30 min)

- [ ] Write `tests/test_demo_mock_parity.py`:
      ```python
      def test_legacy_vs_mesh_outputs_match():
          subprocess.run(["make", "demo-mock", "OUT=/tmp/legacy"], check=True)
          subprocess.run(["make", "demo-mock-mesh", "OUT=/tmp/mesh"], check=True)
          # Pure-fn outputs: byte-for-byte
          for f in ["recon.json", "vuln-scan.json", "alerts.jsonl",
                    "triage-queue.jsonl", "kill-chains.jsonl"]:
              assert open(f"/tmp/legacy/{f}").read() == open(f"/tmp/mesh/{f}").read(), f
          # Reports: ignore timestamp + agent-byline lines
          legacy = strip_volatile(open("/tmp/legacy/pentest-report.md").read())
          mesh   = strip_volatile(open("/tmp/mesh/pentest-report.md").read())
          assert legacy == mesh
      ```
- [ ] Iterate on the prompts in `agents.toml.demo` until parity passes. Hint: tighten instructions to "Call X then stop. Do not commentate." — non-determinism shrinks fast.
- [ ] Port `tests/test_no_runnable_poc.py` invariant onto `secops_mcp.server.exploit` output.

### Step 6 · Deprecate redundant code (~15 min)

- [ ] Add `# DEPRECATED — use secops_mcp + phantom-mesh [[mcp_servers]] instead. Will be removed next release.` to `phantom_secops/llm/phantom_mesh_provider.py`.
- [ ] Don't delete it — keep one release for migration window.

### Step 7 · README + STATUS update (~30 min)

- [ ] Add a **"Drive via phantom-mesh"** section to `README.md` between *Quick start* and *MCP server* sections. Show the 3-line invocation:
      ```bash
      cp agents.toml.demo ~/.phantom-mesh/agents.toml.demo
      cd phantom-secops && make demo-mock-mesh
      ```
- [ ] Update `STATUS.md`'s "What's planned" table — flip the L2 row from "🚧 5/14 - 5/15" to "✅ shipped".
- [ ] Commit + push:
      ```bash
      git add secops_mcp/ scenarios/run_kill_chain.py Makefile \
              agents.toml.demo agents.toml.snippet \
              tests/test_demo_mock_parity.py \
              README.md STATUS.md \
              docs/L2-INTEGRATION.md
      git commit -m "feat: L2 integration with phantom-mesh runtime via MCP"
      git push
      ```
- [ ] Update phantom-mesh's `/projects` dashboard if needed: secops tile demo_cmd was already `make demo-mock` — leave as-is (legacy path stays primary). Add a follow-up issue for switching to `make demo-mock-mesh` once parity test is reliable in CI.

---

## What can go wrong (+ mitigations)

| Symptom | Fix |
|---|---|
| `secops_recon` not in tool list | `name = "secops"` in `[[mcp_servers]]` typo'd; or phantom version too old (need `mcp_client` parser updates from 0.4.0+) |
| `phantom repl -c` hangs | Agent isn't terminating; tighten the `-c` prompt to end with "...then stop." |
| Parity test fails on byte-level | Expected: LLM non-determinism. Use `strip_volatile` helper to drop timestamps + agent-bylines before diff |
| Subprocess returns rc=2 with empty output | `phantom` not on PATH inside the spawned env. Set `PHANTOM_BIN` env var explicitly |
| `state.json` write race | Add file lock around `save_state`; turns are sequential so this is rarely needed but free insurance |

---

## Success criterion

When all 7 steps tick:

```bash
$ make demo-mock-mesh
... (red_team agent calls secops_recon → state.json gets recon block)
... (red_team agent calls secops_exploit → state.json gets exploit block)
... (blue_team agent calls secops_detect → state.json gets detect block)
... (blue_team agent calls secops_respond → final state with both reports)
✓ ran in ~95s (vs. ~88s for legacy demo-mock)
✓ outputs match legacy demo-mock at semantic level
✓ no API keys required
```

phantom-secops is now driven by phantom-mesh. The story for the 5/20
demo video gains a real runtime-integration narrative beyond just
"two repos exist". Recruiter asks "how do they connect?" → you point
at `agents.toml.demo` + `secops_mcp/server.py` + 1 minute of
explanation.
