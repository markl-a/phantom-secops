# L2 Integration — TODO Checklist (~5 h, 2 evenings)

Companion to [`L2-INTEGRATION-PLAN.md`](L2-INTEGRATION-PLAN.md). **Revised 2026-05-11** after re-surveying actual phantom-secops code state.

The earlier draft assumed `phantom_secops.core` module with direct
callable functions — that's not how the codebase looks today. The
real structure is three independent MCP servers under
`phantom_secops/mcp/`, plus direct function calls in
`scenarios/run_kill_chain.py` importing from `tools/`. This TODO
reflects the **actual code paths**.

Recommended split: **5/14 evening (2.5 h)** = steps 1-3,
**5/15 evening (2.5 h)** = steps 4-7. Numbered in execution order.

---

## Key changes from the original L2 plan

1. **No `phantom_secops.core` module** — three independent MCP servers
   live in `phantom_secops/mcp/`:
   - `secops_recon_server.py` → tool `scan_target(target, ports)`
   - `secops_log_server.py` → tool `scan_log(path, max_lines, asset)`
   - `secops_self_audit_server.py` → tool `audit_local_config(path)`
2. Mock data lives in `lab/mocks/{recon-juice-shop.json,
   vuln-scan-juice-shop.json, attack-log.txt}`.
3. The direct path (`make demo-mock`) calls functions in
   `scenarios/run_kill_chain.py` that import from `tools/` —
   NOT from a unified `phantom_secops.core`.
4. **L2 façade should be a NEW `secops_mcp/` at REPO ROOT** (sibling
   to `phantom_secops/`), orchestrating the three existing servers +
   adding shared state. Don't modify `phantom_secops/mcp/`; keep it
   available for direct Claude Code / Cursor use.

---

## 5/14 — evening (~2.5 h)

### Step 1 · Skeleton (~30 min)

- [ ] `mkdir secops_mcp && touch secops_mcp/__init__.py`
- [ ] Write `secops_mcp/state.py`:
  ```python
  from pathlib import Path
  import json

  def default_state() -> dict:
      return {
          "target": "", "phase": "init", "version": 1,
          "recon": None, "exploit": None,
          "detect": None, "respond": None,
      }

  def load_state(path: Path) -> dict:
      if not path.exists(): return default_state()
      return json.loads(path.read_text())

  def save_state(path: Path, state: dict) -> None:
      tmp = path.with_suffix(".tmp")
      tmp.write_text(json.dumps(state, indent=2))
      tmp.replace(path)
  ```
- [ ] Write `secops_mcp/determinism.py`:
  ```python
  import os
  from pathlib import Path

  def is_mock() -> bool:
      return os.getenv("SECOPS_MCP_MOCK") == "1"

  def state_path() -> Path:
      return Path(os.getenv("SECOPS_MCP_STATE_FILE", "/tmp/secops_state.json"))
  ```
- [ ] Smoke-test:
  ```bash
  python -c "from secops_mcp.state import default_state, save_state, load_state; \
             from pathlib import Path; \
             p = Path('/tmp/x.json'); s = default_state(); \
             save_state(p, s); assert load_state(p) == s; \
             print('OK')"
  ```

### Step 2 · MCP server with 4 tools (~1 h)

- [ ] Write `secops_mcp/server.py` (FastMCP, stdio):
  ```python
  #!/usr/bin/env python3
  """secops_l2 MCP server — thin orchestration façade over phantom_secops
  + tools/. Exposes 4 tools (recon/exploit/detect/respond) that share a
  JSON state file so phantom-mesh agents can drive a kill-chain
  step-by-step."""
  import os, sys, json
  from pathlib import Path
  from mcp.server.fastmcp import FastMCP   # mcp>=1.0 ships this

  REPO_ROOT = Path(__file__).resolve().parent.parent
  sys.path.insert(0, str(REPO_ROOT))   # so `from tools...` resolves

  from secops_mcp.state import load_state, save_state, default_state
  from secops_mcp.determinism import is_mock, state_path

  MOCKS = REPO_ROOT / "lab" / "mocks"
  mcp = FastMCP("secops_l2")

  def _load_mock(name: str):
      return json.loads((MOCKS / name).read_text())

  @mcp.tool
  def recon(target: str) -> dict:
      """Red: nmap-style port + service discovery."""
      state = load_state(state_path())
      state["target"] = target
      state["phase"] = "recon"
      state["recon"] = (
          _load_mock("recon-juice-shop.json")
          if is_mock() else
          # Real path: call tools.nmap_runner.run(target)
          {}  # placeholder
      )
      save_state(state_path(), state)
      return state["recon"]

  @mcp.tool
  def exploit(target: str | None = None) -> dict:
      """Red: vuln-scan + prose explanation. has_runnable_poc=False always."""
      state = load_state(state_path())
      state["phase"] = "exploit"
      state["exploit"] = (
          _load_mock("vuln-scan-juice-shop.json")
          if is_mock() else
          {}
      )
      # Invariant: never produce runnable PoC
      if isinstance(state["exploit"], dict):
          state["exploit"]["has_runnable_poc"] = False
      save_state(state_path(), state)
      return state["exploit"]

  @mcp.tool
  def detect() -> dict:
      """Blue: log anomaly + triage + threat correlation."""
      state = load_state(state_path())
      state["phase"] = "detect"
      if is_mock():
          # Read attack-log + mock-detect canned alerts
          state["detect"] = {
              "alerts": [],     # populate from attack-log.txt
              "triaged": [],
              "kill_chains": [],
          }
      save_state(state_path(), state)
      return state["detect"]

  @mcp.tool
  def respond() -> dict:
      """Blue: compose incident + pentest reports from state."""
      state = load_state(state_path())
      state["phase"] = "respond"
      state["respond"] = {
          "incident_report_md": "[mock] incident report",
          "pentest_report_md":  "[mock] pentest report",
          "mttd_seconds":       0,
      }
      save_state(state_path(), state)
      return state["respond"]

  def main():
      mcp.run()

  if __name__ == "__main__":
      main()
  ```
- [ ] Test standalone:
  ```bash
  SECOPS_MCP_MOCK=1 SECOPS_MCP_STATE_FILE=/tmp/s.json \
      python -m secops_mcp.server
  # Server starts stdio loop. Send: {"jsonrpc":"2.0","id":1,"method":"initialize",...}
  ```

### Step 3 · agents.toml.demo + first probe (~1 h)

- [ ] Write `agents.toml.demo` at repo root:
  ```toml
  [core]
  host = "127.0.0.1"
  port = 8765

  [providers.anthropic]
  type        = "anthropic"
  api_key_env = "ANTHROPIC_API_KEY"

  [[mcp_servers]]
  name    = "secops_l2"
  command = "python3"
  args    = ["-m", "secops_mcp.server"]
  env     = { SECOPS_MCP_MOCK = "1", SECOPS_MCP_STATE_FILE = "/tmp/secops_state.json" }

  [agent.red_team]
  provider = "anthropic"
  model    = "claude-sonnet-4-6"
  tools    = ["secops_l2_recon", "secops_l2_exploit"]
  instructions = """
  You are a red-team operator. Workflow:
  1. Call secops_l2_recon(target="juice-shop"), then
  2. Call secops_l2_exploit(target="juice-shop"), then
  3. Stop. No commentary.
  Hard rules: never produce runnable PoCs.
  """

  [agent.blue_team]
  provider = "anthropic"
  model    = "claude-sonnet-4-6"
  tools    = ["secops_l2_detect", "secops_l2_respond"]
  instructions = """
  You are a SOC analyst. Workflow:
  1. Call secops_l2_detect(), then
  2. Call secops_l2_respond(), then
  3. Stop. Be decisive.
  """
  ```
- [ ] Probe tool naming (do tools list correctly?):
  ```bash
  phantom repl --config ./agents.toml.demo --agent red_team \
               -c "list your tools" 2>&1 | head -20
  ```
  Expected: `secops_l2_recon`, `secops_l2_exploit` in the list. If
  they appear as `secops_l2/recon` or just `recon`, adjust the
  `name = "secops_l2"` field per phantom-mesh's `<server>_<tool>`
  prefix convention.
- [ ] Drive one tool through phantom-mesh end-to-end:
  ```bash
  phantom repl --config ./agents.toml.demo --agent red_team \
               -c "Call secops_l2_recon(target='juice-shop'), then stop."
  cat /tmp/secops_state.json
  ```
  Expected: state file has `"recon": { ... }` populated from mock JSON.

  **If this works, L2 fundamentals are confirmed.** Close laptop, done for tonight.

---

## 5/15 — evening (~2.5 h)

### Step 4 · Orchestrator refactor (~1.5 h)

- [ ] Add `--driver={direct,mesh}` flag to `scenarios/run_kill_chain.py`
  (default `direct` — preserves current behavior):
  ```python
  parser.add_argument("--driver", choices=["direct", "mesh"], default="direct")
  ```
- [ ] When `mesh`, replace each `tools.{nmap_runner, log_anomaly, ...}`
  call with a subprocess to `phantom repl`:
  ```python
  PHANTOM_BIN = os.environ.get("PHANTOM_BIN") or shutil.which("phantom")
  if not PHANTOM_BIN:
      raise SystemExit("phantom not on PATH; set PHANTOM_BIN or install phantom-mesh")

  if args.driver == "mesh":
      state_file = out_dir / "secops_state.json"
      env = {
          **os.environ,
          "SECOPS_MCP_MOCK": "1" if args.mock else "0",
          "SECOPS_MCP_STATE_FILE": str(state_file),
      }
      # Red turns
      subprocess.run(
          [PHANTOM_BIN, "repl", "--config", "./agents.toml.demo",
           "--agent", "red_team",
           "-c", "Call secops_l2_recon(target='juice-shop'), then stop."],
          env=env, check=True, capture_output=True,
      )
      subprocess.run(
          [PHANTOM_BIN, "repl", "--config", "./agents.toml.demo",
           "--agent", "red_team",
           "-c", "Call secops_l2_exploit(target='juice-shop'), then stop."],
          env=env, check=True, capture_output=True,
      )
      # Blue turns
      subprocess.run(
          [PHANTOM_BIN, "repl", "--config", "./agents.toml.demo",
           "--agent", "blue_team",
           "-c", "Call secops_l2_detect(), then secops_l2_respond(), then stop."],
          env=env, check=True, capture_output=True,
      )
      state = json.loads(state_file.read_text())
      recon, exploit  = state["recon"],  state["exploit"]
      detect, respond = state["detect"], state["respond"]
  else:
      # Direct path (unchanged)
      recon   = _direct_recon(args.target, mock=args.mock)
      exploit = _direct_exploit(args.target, recon, mock=args.mock)
      detect  = _direct_detect(args.mock)
      respond = _direct_respond(...)
  ```
- [ ] Make sure artifact writing (`recon.json`, `vuln-scan.json`,
  `pentest-report.md`, `incident-report.md`) is shared between both
  drivers — extract to a helper:
  ```python
  def _write_artifacts(out_dir, recon, exploit, detect, respond):
      (out_dir / "recon.json").write_text(json.dumps(recon, indent=2))
      ...
  ```
- [ ] Add `make demo-mock-mesh` Makefile target:
  ```makefile
  demo-mock-mesh:
  	python3 scenarios/run_kill_chain.py --target juice-shop --mock --driver=mesh
  ```

### Step 5 · Parity test (~30 min)

- [ ] Write `tests/test_demo_mock_parity.py`:
  ```python
  import json, re, subprocess
  from pathlib import Path

  def _strip_volatile(text: str) -> str:
      text = re.sub(r"\[t\+[0-9.]+s\]", "[t+XXs]", text)
      text = re.sub(r"_Generated by .*", "_Generated by X", text)
      return text

  def test_legacy_vs_mesh_byte_for_byte_pure_fns(tmp_path):
      legacy = tmp_path / "legacy"
      mesh   = tmp_path / "mesh"
      subprocess.run(["make", "demo-mock",      f"OUT={legacy}"], check=True)
      subprocess.run(["make", "demo-mock-mesh", f"OUT={mesh}"],   check=True)

      for f in ["recon.json", "vuln-scan.json"]:
          legacy_j = json.loads((legacy / f).read_text())
          mesh_j   = json.loads((mesh / f).read_text())
          assert legacy_j == mesh_j, f"{f} drift"

  def test_legacy_vs_mesh_reports_match_after_strip(tmp_path):
      legacy = tmp_path / "legacy"
      mesh   = tmp_path / "mesh"
      subprocess.run(["make", "demo-mock",      f"OUT={legacy}"], check=True)
      subprocess.run(["make", "demo-mock-mesh", f"OUT={mesh}"],   check=True)

      for f in ["pentest-report.md", "incident-report.md"]:
          a = _strip_volatile((legacy / f).read_text())
          b = _strip_volatile((mesh   / f).read_text())
          assert a == b, f"{f} semantic drift"
  ```
- [ ] If parity fails, tighten the `instructions` in `agents.toml.demo`
  to be more deterministic ("call X, then stop, no commentary").
- [ ] Port `tests/test_no_runnable_poc.py` invariant onto the
  `secops_mcp.server.exploit` output path.

### Step 6 · Deprecate redundant code (~15 min)

- [ ] Add to `phantom_secops/llm/phantom_mesh_provider.py`:
  ```python
  # DEPRECATED 2026-05-15 — use secops_mcp + phantom-mesh [[mcp_servers]] instead.
  # The new L2 façade dispatches via subprocess + JSON state file
  # rather than HTTP. Keep this around for one release; remove next.
  ```
- [ ] Don't delete the file yet — gives one-release migration window.

### Step 7 · README + STATUS + commit (~30 min)

- [ ] Add to `README.md` between *Quick start* and *MCP server*:
  ```markdown
  ## Drive via phantom-mesh (L2 integration)

  `make demo-mock` (direct path) runs the kill-chain by importing
  `tools/` functions directly — fastest, no LLM.

  `make demo-mock-mesh` (L2 path) orchestrates the same kill-chain
  through phantom-mesh agents that call the `secops_l2` MCP server:

      cp agents.toml.demo ~/.phantom-mesh/agents.toml.demo
      cd phantom-secops && make demo-mock-mesh

  Both produce equivalent artifacts on the same mock fixtures.
  L2 path takes ~95s vs ~88s for direct — overhead is phantom-mesh
  startup + agent loop. The point is to demonstrate the runtime
  decoupling, not to be faster.
  ```
- [ ] Update `STATUS.md` "What's planned" table — flip the L2 row
  from `🚧 5/14 - 5/15` to `✅ shipped 2026-05-15`.
- [ ] Commit + push:
  ```bash
  git add secops_mcp/ scenarios/run_kill_chain.py Makefile \
          agents.toml.demo agents.toml.snippet \
          tests/test_demo_mock_parity.py \
          README.md STATUS.md \
          docs/L2-INTEGRATION.md
  git commit -m "feat: L2 integration with phantom-mesh runtime via secops_l2 MCP façade"
  git push
  ```

---

## What can go wrong

| Symptom | Fix |
|---|---|
| Tool names show as `secops_l2/recon` not `secops_l2_recon` | Phantom uses underscore prefix per `<server>_<tool>`. Check `name = "secops_l2"` in `[[mcp_servers]]` matches the prefix convention |
| `phantom repl -c` hangs | Tighten prompt: "...then stop. No commentary." Add `--max-rounds 3` |
| Parity test JSON diffs | Expected on LLM-driven paths. Use semantic diff (key presence, MTTD ≥ 0) not byte-exact |
| `/tmp/secops_state.json` not written | Check subprocess env: `SECOPS_MCP_MOCK=1` and `SECOPS_MCP_STATE_FILE=...` must propagate |
| `import tools.X` from `secops_mcp/server.py` fails | sys.path.insert(0, str(REPO_ROOT)) at top of server.py — REPO_ROOT must be `phantom-secops/`, not `phantom-secops/secops_mcp/` |
| `phantom` not on PATH | Orchestrator uses `PHANTOM_BIN` env or `shutil.which("phantom")`. Error clearly if neither |
| `mcp` package missing | `pip install 'mcp[cli]>=1.0'` — already in requirements-dev.txt |

---

## Success criterion

When all 7 steps tick:

```bash
$ make demo-mock-mesh
[phantom-mesh starts]
[red_team agent: call secops_l2_recon → /tmp/secops_state.json updated]
[red_team agent: call secops_l2_exploit → state updated again]
[blue_team agent: call secops_l2_detect → detect block added]
[blue_team agent: call secops_l2_respond → respond block + reports written]
✓ recon.json + vuln-scan.json byte-exact vs legacy
✓ pentest-report.md + incident-report.md equivalent after stripping
  timestamps + Generated-by lines
✓ no API keys needed (SECOPS_MCP_MOCK=1)
✓ ran in ~95-100s (legacy: ~88s; overhead is phantom-mesh startup)
✓ test_no_runnable_poc.py still passes against mesh output
```

The story now reads: "phantom-mesh drives phantom-secops agents
through a thin MCP façade (`secops_l2`), keeping mock-mode
deterministic and decoupling the orchestration runtime from the
tool implementations. Same artifacts. Same safety invariants. New
narrative for the demo video: cross-process agent dispatch with
real LLM in the loop."
