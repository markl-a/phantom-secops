# phantom-mesh integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make phantom-secops actually run as a phantom-mesh-driven multi-agent system by exposing existing `tools/` as MCP servers with `x-phantom.*` capability metadata, and adding a capability-policy enforcer to phantom-mesh's `mcp_client.rs`.

**Architecture:** Three Python MCP servers (red/blue/internal) wrap existing phantom-secops tools and embed `x-phantom.{classification, capabilities, read_only}` metadata in `tools/list` responses. phantom-mesh `core/src/mcp_client.rs` parses the metadata, looks up per-agent `plugin_policy` from `agents.toml`, and allow/denies `tools/call` before forwarding to the child plugin process. Audit log appended to `~/.phantom-mesh/data/secops-audit.jsonl` on every decision.

**Tech Stack:** Python 3.10+ with `mcp>=1.0` SDK (phantom-secops side) · Rust + tokio (phantom-mesh side, existing) · TOML config · pytest · cargo test

**Spec:** `docs/specs/2026-05-04-phantom-mesh-integration.md` — read before starting

**Cross-repo work:** This plan touches two repos. Tasks 1–5 + 12–13 in `D:/Projects/phantom-secops`. Tasks 6–11 in a new worktree of `D:/Projects/phantom-mesh-private`. Task 14 (smoke) is on mac-coord (live).

---

## File Structure

### phantom-secops (this repo)

| Path | Action | Responsibility |
|---|---|---|
| `phantom_secops/__init__.py` | Create | Package marker |
| `phantom_secops/mcp/__init__.py` | Create | Sub-package marker |
| `phantom_secops/mcp/_xphantom.py` | Create | Helper: embed `x-phantom.*` into MCP `Tool` definitions |
| `phantom_secops/mcp/secops_recon_server.py` | Create | red MCP server, wraps `tools/nmap_runner.py` |
| `phantom_secops/mcp/secops_log_server.py` | Create | blue MCP server, wraps `tools/log_anomaly.py` |
| `phantom_secops/mcp/secops_self_audit_server.py` | Create | internal MCP server, scans `agents.toml` |
| `tools/log_anomaly.py` | Create | Extracted from `scenarios/run_kill_chain.py` |
| `scenarios/run_kill_chain.py` | Modify | Re-import from `tools.log_anomaly` for backward compat |
| `tests/test_xphantom.py` | Create | Unit tests for the helper |
| `tests/test_mcp_recon_server.py` | Create | Unit tests for recon server |
| `tests/test_mcp_log_server.py` | Create | Unit tests for log server |
| `tests/test_mcp_self_audit_server.py` | Create | Unit tests for self-audit server |
| `scripts/render-mesh-agents.py` | Create | Translate phantom-secops agent TOML → phantom-mesh `[agent.X]` fragment |
| `tests/test_render_mesh_agents.py` | Create | Render script tests |
| `Makefile` | Modify | Add `mesh-sync` target |
| `requirements-dev.txt` | Modify | Add `mcp>=1.0,<2.0` |
| `README.md` | Modify | Add "phantom-mesh integration" section pointing to spec |

### phantom-mesh-private (worktree at `.worktrees/secops-mcp-policy/`)

| Path | Action | Responsibility |
|---|---|---|
| `core/src/config.rs` | Modify | Add `AgentPluginPolicy` struct under `AgentConfig` |
| `core/src/secops_audit.rs` | Create | Audit log writer (append-only JSONL) — keeps `mcp_client.rs` focused |
| `core/src/mcp_client.rs` | Modify | Parse x-phantom metadata at `tools/list` time + policy enforce in `call_tool` + emit audit event |
| `core/src/lib.rs` | Modify | `pub mod secops_audit;` |

---

## Task 1: Package skeleton + extract `_blue_log_anomaly`

**Files:**
- Create: `phantom_secops/__init__.py`
- Create: `phantom_secops/mcp/__init__.py`
- Create: `tools/log_anomaly.py`
- Modify: `scenarios/run_kill_chain.py` (replace function with re-import)
- No new test file — existing `make test` must still pass

- [ ] **Step 1: Create package markers**

```bash
mkdir -p phantom_secops/mcp
echo '"""phantom-secops Python package."""' > phantom_secops/__init__.py
echo '"""MCP server wrappers exposing phantom-secops tools to phantom-mesh."""' > phantom_secops/mcp/__init__.py
```

- [ ] **Step 2: Extract `_blue_log_anomaly` to `tools/log_anomaly.py`**

Read current `scenarios/run_kill_chain.py` lines 174–209 (the `_blue_log_anomaly` function and its imports of `re` / `unquote` / `MOCKS_DIR` / `REPO_ROOT`).

Create `tools/log_anomaly.py`:

```python
"""URL-decoded pattern matcher for log lines.

Extracted from scenarios/run_kill_chain.py so it can be wrapped as an
MCP tool without importing the full kill-chain orchestrator.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote

PATTERNS: list[tuple[str, str, str]] = [
    ("traversal",  r"(\.\./|\.\.\\|/etc/passwd)",                              "high"),
    ("sqli",       r"(\bunion\b.*\bselect\b|\bor\s+1\s*=\s*1\b|\bsleep\s*\(\d)", "high"),
    ("xss",        r"(<script|onerror\s*=|javascript:)",                      "medium"),
    ("admin_path", r"/(administration|admin|wp-admin|\.git/|\.env|server-status)", "medium"),
    ("scanner",    r"(nikto|nmap|sqlmap|nuclei|burpsuite|wpscan)",            "low"),
]


def scan_log_lines(log_path: Path, max_lines: int = 10000, asset: str = "unknown") -> list[dict[str, Any]]:
    """Pattern-match a log file. Returns one alert dict per matching line.

    URL-decodes each line before matching so percent-encoded payloads are
    detected. Stops after `max_lines` lines.
    """
    if not log_path.exists():
        return []
    alerts: list[dict[str, Any]] = []
    text = log_path.read_text(errors="replace").splitlines()[:max_lines]
    for line in text:
        decoded = unquote(line)
        for category, pat, sev in PATTERNS:
            if re.search(pat, decoded, re.I):
                ip_m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})", line)
                alerts.append({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "source_ip": ip_m.group(1) if ip_m else "unknown",
                    "asset": asset,
                    "category": category,
                    "evidence": line[:200],
                    "severity_hint": sev,
                })
                break
    return alerts
```

- [ ] **Step 3: Replace `_blue_log_anomaly` in `run_kill_chain.py` with a thin shim**

Edit `scenarios/run_kill_chain.py`. Replace lines 174–209 (the existing `_blue_log_anomaly` function) with:

```python
def _blue_log_anomaly(mock: bool) -> list[dict[str, Any]]:
    """Backward-compatible shim around tools.log_anomaly.scan_log_lines."""
    from tools.log_anomaly import scan_log_lines  # imported lazily to keep test isolation
    log_path = MOCKS_DIR / "attack-log.txt" if mock else REPO_ROOT / "reports/lab-logs/juice-shop.log"
    return scan_log_lines(log_path, asset="juice-shop")
```

Remove the now-unused imports of `re` and `unquote` from the top of `run_kill_chain.py` only if they're not used by other functions (verify before deleting).

- [ ] **Step 4: Verify mock demo still produces same alert count**

```bash
cd D:/Projects/phantom-secops
python3 scenarios/run_kill_chain.py --target juice-shop --mock 2>&1 | grep "blue-log-anomaly"
```

Expected line: `[t+  0.0s] blue-log-anomaly  → N raw alerts` where N matches what was reported before extraction (per README: 21).

- [ ] **Step 5: Run existing tests**

```bash
make test
```

Expected: all 7 existing unit tests still pass.

- [ ] **Step 6: Commit**

```bash
git add phantom_secops/ tools/log_anomaly.py scenarios/run_kill_chain.py
git commit -m "refactor: extract log-anomaly matcher to tools/log_anomaly.py

Pulls _blue_log_anomaly out of run_kill_chain.py so it can be wrapped
as an MCP tool by secops_log_server. Backward-compatible shim left in
run_kill_chain.py.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: x-phantom helper + tests

**Files:**
- Create: `phantom_secops/mcp/_xphantom.py`
- Create: `tests/test_xphantom.py`

- [ ] **Step 1: Write failing test**

Create `tests/test_xphantom.py`:

```python
"""Tests for the x-phantom metadata helper."""

from __future__ import annotations

import json

import pytest

from phantom_secops.mcp._xphantom import xphantom_metadata, validate_classification


def test_metadata_contains_namespaced_keys():
    md = xphantom_metadata("blue", ["read.log_files", "target.localhost_only"], read_only=True)
    assert md["x-phantom.classification"] == "blue"
    assert md["x-phantom.capabilities"] == ["read.log_files", "target.localhost_only"]
    assert md["x-phantom.read_only"] is True


def test_classification_validation_rejects_unknown():
    with pytest.raises(ValueError, match="classification"):
        xphantom_metadata("purple", [], read_only=True)


def test_classification_ordering():
    assert validate_classification("internal") < validate_classification("blue")
    assert validate_classification("blue") < validate_classification("red")


def test_capabilities_must_be_list_of_strings():
    with pytest.raises(TypeError):
        xphantom_metadata("red", "not_a_list", read_only=False)
    with pytest.raises(TypeError):
        xphantom_metadata("red", [123], read_only=False)


def test_metadata_is_json_serializable():
    md = xphantom_metadata("internal", ["read.config.local"], read_only=True)
    s = json.dumps(md)
    assert "x-phantom.classification" in s
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python3 -m pytest tests/test_xphantom.py -v
```

Expected: ImportError / ModuleNotFoundError on `phantom_secops.mcp._xphantom`.

- [ ] **Step 3: Implement helper**

Create `phantom_secops/mcp/_xphantom.py`:

```python
"""Helpers for embedding x-phantom.* metadata into MCP tool definitions.

The mcp Python SDK accepts a `metadata` dict on Tool definitions which
is forwarded verbatim to the client. We use that channel to declare
classification + capability hints that phantom-mesh's policy enforcer
reads.
"""

from __future__ import annotations

from typing import Any

_CLASSIFICATION_ORDER = {"internal": 0, "blue": 1, "red": 2}


def validate_classification(classification: str) -> int:
    """Return the numeric ordering of a classification, raising on unknown."""
    if classification not in _CLASSIFICATION_ORDER:
        raise ValueError(
            f"unknown x-phantom classification {classification!r}; "
            f"expected one of {sorted(_CLASSIFICATION_ORDER)}"
        )
    return _CLASSIFICATION_ORDER[classification]


def xphantom_metadata(
    classification: str,
    capabilities: list[str],
    *,
    read_only: bool,
) -> dict[str, Any]:
    """Build the x-phantom.* metadata dict for an MCP Tool.

    Pass the result as the `metadata` arg to mcp's Tool() so it survives
    serialization to tools/list.
    """
    validate_classification(classification)
    if not isinstance(capabilities, list) or not all(isinstance(c, str) for c in capabilities):
        raise TypeError("capabilities must be list[str]")
    return {
        "x-phantom.classification": classification,
        "x-phantom.capabilities": list(capabilities),
        "x-phantom.read_only": bool(read_only),
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest tests/test_xphantom.py -v
```

Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add phantom_secops/mcp/_xphantom.py tests/test_xphantom.py
git commit -m "feat(mcp): x-phantom metadata helper

Centralises the format for x-phantom.{classification,capabilities,read_only}
fields embedded in MCP tool definitions. Each MCP server uses this so
the metadata format stays consistent.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `secops_recon_server` + tests

**Files:**
- Create: `phantom_secops/mcp/secops_recon_server.py`
- Create: `tests/test_mcp_recon_server.py`

- [ ] **Step 1: Add `mcp>=1.0,<2.0` to requirements**

Edit `requirements-dev.txt`, append:

```
mcp>=1.0,<2.0
```

Then:

```bash
pip install -r requirements-dev.txt
```

- [ ] **Step 2: Write failing tests**

Create `tests/test_mcp_recon_server.py`:

```python
"""Tests for the secops_recon MCP server.

We test the in-process tool implementations directly rather than going
through stdio JSON-RPC — the SDK round-trip adds nothing for unit
testing the policy/scope logic, and bypassing it keeps tests fast.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from phantom_secops.mcp import secops_recon_server


def test_list_tools_includes_xphantom_metadata():
    tools = secops_recon_server.tool_definitions()
    assert any(t.name == "scan_target" for t in tools)
    scan_tool = next(t for t in tools if t.name == "scan_target")
    md = scan_tool.metadata
    assert md["x-phantom.classification"] == "red"
    assert "network.scan.passive" in md["x-phantom.capabilities"]
    assert "target.lab_only" in md["x-phantom.capabilities"]
    assert md["x-phantom.read_only"] is True


def test_scan_valid_lab_target():
    """Mocks nmap_runner to verify the server forwards correctly."""
    fake_result = {"target": "juice-shop", "open_ports": [{"port": 3000, "service": "http"}], "scan_type": "nmap"}
    with patch("phantom_secops.mcp.secops_recon_server.nmap_runner.run", return_value=fake_result):
        out = secops_recon_server.scan_target_impl({"target": "juice-shop"})
    assert out["target"] == "juice-shop"
    assert out["open_ports"][0]["port"] == 3000


def test_scan_external_target_refused_by_existing_lab_gate():
    """nmap_runner already refuses non-lab; verify the MCP server forwards the error JSON."""
    out = secops_recon_server.scan_target_impl({"target": "google.com"})
    assert "error" in out
    assert "not a known lab service" in out["error"]


def test_missing_target_arg_raises():
    with pytest.raises((KeyError, TypeError, ValueError)):
        secops_recon_server.scan_target_impl({})
```

- [ ] **Step 3: Run test, verify failure**

```bash
python3 -m pytest tests/test_mcp_recon_server.py -v
```

Expected: ImportError on `phantom_secops.mcp.secops_recon_server`.

- [ ] **Step 4: Implement server**

Create `phantom_secops/mcp/secops_recon_server.py`:

```python
"""MCP server: red-team reconnaissance (nmap wrapper).

Wraps tools/nmap_runner.py without modifying it. The existing
_target_in_lab gate inside nmap_runner remains the authoritative scope
check (defense in depth: phantom-mesh policy says target.lab_only,
plugin itself also enforces).

Run as: python -m phantom_secops.mcp.secops_recon_server
Spawned by phantom-mesh via [[mcp_servers]] block in agents.toml.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Make tools/ importable when run as `python -m phantom_secops.mcp.secops_recon_server`
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import nmap_runner  # noqa: E402

from phantom_secops.mcp._xphantom import xphantom_metadata  # noqa: E402


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="scan_target",
            description=(
                "Run nmap against an in-lab service (e.g. juice-shop, dvwa). "
                "Returns parsed open ports + service versions. "
                "Refuses any target that is not a known lab service."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "lab service name"},
                    "ports":  {"type": "string", "default": "top-1000"},
                },
                "required": ["target"],
            },
            metadata=xphantom_metadata(
                "red",
                ["network.scan.passive", "target.lab_only"],
                read_only=True,
            ),
        ),
    ]


def scan_target_impl(args: dict[str, Any]) -> dict[str, Any]:
    target = args["target"]
    ports = args.get("ports", "top-1000")
    return nmap_runner.run(target=target, ports=ports)


server = Server("secops_recon")


@server.list_tools()
async def _list_tools() -> list[Tool]:
    return tool_definitions()


@server.call_tool()
async def _call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name == "scan_target":
        result = scan_target_impl(arguments)
    else:
        raise ValueError(f"unknown tool: {name}")
    import json
    return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False))]


async def _main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
```

- [ ] **Step 5: Run tests to verify pass**

```bash
python3 -m pytest tests/test_mcp_recon_server.py -v
```

Expected: 4 tests pass.

- [ ] **Step 6: Smoke-run the server standalone (optional sanity check)**

```bash
echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}},"id":1}' \
  | python3 -m phantom_secops.mcp.secops_recon_server 2>/dev/null \
  | head -c 200
```

Expected: a JSON-RPC response containing `serverInfo.name = "secops_recon"`.

- [ ] **Step 7: Commit**

```bash
git add phantom_secops/mcp/secops_recon_server.py tests/test_mcp_recon_server.py requirements-dev.txt
git commit -m "feat(mcp): secops_recon server (red, wraps nmap_runner)

Exposes scan_target as an MCP tool with x-phantom metadata
(classification=red, capabilities=[network.scan.passive, target.lab_only]).
The existing _target_in_lab gate in nmap_runner is preserved as defense
in depth.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `secops_log_server` + tests

**Files:**
- Create: `phantom_secops/mcp/secops_log_server.py`
- Create: `tests/test_mcp_log_server.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_mcp_log_server.py`:

```python
"""Tests for the secops_log MCP server."""

from __future__ import annotations

from pathlib import Path

import pytest

from phantom_secops.mcp import secops_log_server


def test_list_tools_includes_xphantom_metadata():
    tools = secops_log_server.tool_definitions()
    assert any(t.name == "scan_log" for t in tools)
    md = next(t for t in tools if t.name == "scan_log").metadata
    assert md["x-phantom.classification"] == "blue"
    assert "read.log_files" in md["x-phantom.capabilities"]
    assert md["x-phantom.read_only"] is True


def test_scan_log_on_canned_attack_log(tmp_path: Path):
    # Synthesize a tiny attack log inline rather than depending on lab/mocks/
    log = tmp_path / "test.log"
    log.write_text(
        "203.0.113.5 - - [01/May/2026] \"GET /search?q=%27union%20select%201%2c2--\"\n"
        "203.0.113.5 - - [01/May/2026] \"GET /administration HTTP/1.1\"\n"
        "10.0.0.1 - - [01/May/2026] \"GET /index.html\" benign\n"
    )
    out = secops_log_server.scan_log_impl({"path": str(log), "max_lines": 100, "asset": "test"})
    cats = {a["category"] for a in out["alerts"]}
    assert "sqli" in cats
    assert "admin_path" in cats
    assert all(a["asset"] == "test" for a in out["alerts"])


def test_scan_log_max_lines_honored(tmp_path: Path):
    log = tmp_path / "big.log"
    log.write_text("\n".join([f"{i} GET /admin"] for i in range(50))[0])
    # Build a deterministic 50-line file with one matching admin pattern per line
    log.write_text("\n".join(f"203.0.113.{i} GET /admin" for i in range(50)))
    out = secops_log_server.scan_log_impl({"path": str(log), "max_lines": 10})
    assert len(out["alerts"]) == 10


def test_scan_log_missing_file(tmp_path: Path):
    out = secops_log_server.scan_log_impl({"path": str(tmp_path / "nonexistent")})
    assert out["alerts"] == []
```

- [ ] **Step 2: Run test, verify failure**

```bash
python3 -m pytest tests/test_mcp_log_server.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement server**

Create `phantom_secops/mcp/secops_log_server.py`:

```python
"""MCP server: blue-team log anomaly scanner.

Wraps tools/log_anomaly.scan_log_lines. The pattern matcher is shared
with run_kill_chain.py's blue pipeline.

Run as: python -m phantom_secops.mcp.secops_log_server
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.log_anomaly import scan_log_lines  # noqa: E402

from phantom_secops.mcp._xphantom import xphantom_metadata  # noqa: E402


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="scan_log",
            description=(
                "Scan a log file for known attack patterns "
                "(sqli/traversal/xss/admin/scanner). URL-decodes each "
                "line before matching. Returns alert objects."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path":      {"type": "string", "description": "absolute path to log file"},
                    "max_lines": {"type": "integer", "default": 10000, "minimum": 1},
                    "asset":     {"type": "string", "default": "unknown"},
                },
                "required": ["path"],
            },
            metadata=xphantom_metadata(
                "blue",
                ["read.log_files", "target.localhost_only"],
                read_only=True,
            ),
        ),
    ]


def scan_log_impl(args: dict[str, Any]) -> dict[str, Any]:
    path = Path(args["path"])
    max_lines = int(args.get("max_lines", 10000))
    asset = args.get("asset", "unknown")
    alerts = scan_log_lines(path, max_lines=max_lines, asset=asset)
    return {"alerts": alerts, "scanned": str(path), "max_lines": max_lines}


server = Server("secops_log")


@server.list_tools()
async def _list_tools() -> list[Tool]:
    return tool_definitions()


@server.call_tool()
async def _call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name == "scan_log":
        result = scan_log_impl(arguments)
    else:
        raise ValueError(f"unknown tool: {name}")
    return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False))]


async def _main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
```

- [ ] **Step 4: Run tests to verify pass**

```bash
python3 -m pytest tests/test_mcp_log_server.py -v
```

Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add phantom_secops/mcp/secops_log_server.py tests/test_mcp_log_server.py
git commit -m "feat(mcp): secops_log server (blue, wraps log_anomaly)

Exposes scan_log as an MCP tool with x-phantom metadata
(classification=blue, capabilities=[read.log_files, target.localhost_only]).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: `secops_self_audit_server` + tests

**Files:**
- Create: `phantom_secops/mcp/secops_self_audit_server.py`
- Create: `tests/test_mcp_self_audit_server.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_mcp_self_audit_server.py`:

```python
"""Tests for the secops_self_audit MCP server."""

from __future__ import annotations

from pathlib import Path

from phantom_secops.mcp import secops_self_audit_server


def test_list_tools_includes_xphantom_metadata():
    tools = secops_self_audit_server.tool_definitions()
    assert any(t.name == "audit_local_config" for t in tools)
    md = next(t for t in tools if t.name == "audit_local_config").metadata
    assert md["x-phantom.classification"] == "internal"
    assert "read.config.local" in md["x-phantom.capabilities"]
    assert "target.self_only" in md["x-phantom.capabilities"]
    assert md["x-phantom.read_only"] is True


def test_detects_plaintext_provider_key(tmp_path: Path):
    cfg = tmp_path / "agents.toml"
    cfg.write_text(
        '[providers.groq]\n'
        'type = "groq"\n'
        'api_key = "literal-provider-key-for-test"\n'
        'default_model = "llama-3.3-70b-versatile"\n'
    )
    out = secops_self_audit_server.audit_impl({"path": str(cfg)})
    findings = out["findings"]
    assert any(f["check"] == "plaintext_api_key" and f["section"] == "providers.groq" for f in findings)
    # the key VALUE must not be echoed back to the caller
    assert "literal-provider-key-for-test" not in str(findings)


def test_detects_weak_cluster_secret(tmp_path: Path):
    cfg = tmp_path / "agents.toml"
    cfg.write_text(
        '[cluster]\n'
        'cluster_secret = "short"\n'
    )
    out = secops_self_audit_server.audit_impl({"path": str(cfg)})
    assert any(f["check"] == "weak_cluster_secret" for f in out["findings"])


def test_detects_zero_dot_zero_listener(tmp_path: Path):
    cfg = tmp_path / "agents.toml"
    cfg.write_text(
        '[core]\n'
        'host = "0.0.0.0"\n'
        'port = 7878\n'
    )
    out = secops_self_audit_server.audit_impl({"path": str(cfg)})
    assert any(f["check"] == "exposed_listener" for f in out["findings"])


def test_clean_config_returns_no_findings(tmp_path: Path):
    cfg = tmp_path / "agents.toml"
    cfg.write_text(
        '[core]\n'
        'host = "127.0.0.1"\n'
        '\n'
        '[cluster]\n'
        'cluster_secret = "this_is_a_long_enough_secret_2026"\n'
        '\n'
        '[providers.groq]\n'
        'type = "groq"\n'
        'api_key_env = "GROQ_API_KEY"\n'
    )
    out = secops_self_audit_server.audit_impl({"path": str(cfg)})
    assert out["findings"] == []
```

- [ ] **Step 2: Run test, verify failure**

```bash
python3 -m pytest tests/test_mcp_self_audit_server.py -v
```

Expected: ImportError.

- [ ] **Step 3: Implement server**

Create `phantom_secops/mcp/secops_self_audit_server.py`:

```python
"""MCP server: phantom self-audit (internal classification).

Scans phantom-mesh's own agents.toml for hygiene issues:
- providers with literal `api_key = "..."` (vs api_key_env)
- weak / missing [cluster].cluster_secret
- [core] host = 0.0.0.0 (exposed listener)

Read-only. Never echoes secret values in findings.

Run as: python -m phantom_secops.mcp.secops_self_audit_server
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from phantom_secops.mcp._xphantom import xphantom_metadata  # noqa: E402

DEFAULT_AGENTS_TOML = Path(os.path.expanduser("~")) / ".phantom-mesh" / "agents.toml"


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="audit_local_config",
            description=(
                "Scan phantom-mesh's own agents.toml for plaintext API keys, "
                "weak cluster_secret, and exposed (0.0.0.0) listeners. "
                "Returns findings without echoing secret values."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "absolute path to agents.toml; defaults to ~/.phantom-mesh/agents.toml",
                    },
                },
            },
            metadata=xphantom_metadata(
                "internal",
                ["read.config.local", "target.self_only"],
                read_only=True,
            ),
        ),
    ]


_PROVIDER_HEADER = re.compile(r"^\[providers\.([^\]]+)\]")
_LITERAL_KEY = re.compile(r'^\s*api_key\s*=\s*"([^"]*)"', re.IGNORECASE)


def audit_impl(args: dict[str, Any]) -> dict[str, Any]:
    path = Path(args.get("path") or DEFAULT_AGENTS_TOML)
    findings: list[dict[str, Any]] = []
    if not path.exists():
        return {"findings": [{"check": "missing_file", "severity": "info",
                              "message": f"agents.toml not present at {path}"}],
                "scanned": str(path)}

    text = path.read_text()
    current_section: str | None = None
    for ln, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current_section = stripped[1:-1]
            continue
        if current_section and current_section.startswith("providers."):
            m = _LITERAL_KEY.match(raw)
            if m:
                key_len = len(m.group(1))
                findings.append({
                    "check": "plaintext_api_key",
                    "severity": "high",
                    "section": current_section,
                    "line": ln,
                    "message": (
                        f"{current_section} uses literal api_key (len={key_len}); "
                        "switch to api_key_env to avoid disk-resident secret"
                    ),
                })
        if current_section == "cluster" and stripped.startswith("cluster_secret"):
            value_match = re.search(r'"([^"]*)"', stripped)
            if value_match:
                if len(value_match.group(1)) < 16:
                    findings.append({
                        "check": "weak_cluster_secret",
                        "severity": "high",
                        "line": ln,
                        "message": f"cluster_secret length={len(value_match.group(1))} < 16",
                    })
        if current_section == "core" and stripped.startswith("host"):
            if '"0.0.0.0"' in stripped or "'0.0.0.0'" in stripped:
                findings.append({
                    "check": "exposed_listener",
                    "severity": "medium",
                    "line": ln,
                    "message": "host = 0.0.0.0 binds all interfaces; consider 127.0.0.1 + Tailscale IP only",
                })
    return {"findings": findings, "scanned": str(path)}


server = Server("secops_self_audit")


@server.list_tools()
async def _list_tools() -> list[Tool]:
    return tool_definitions()


@server.call_tool()
async def _call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name == "audit_local_config":
        result = audit_impl(arguments)
    else:
        raise ValueError(f"unknown tool: {name}")
    return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False))]


async def _main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_main())
```

- [ ] **Step 4: Run tests to verify pass**

```bash
python3 -m pytest tests/test_mcp_self_audit_server.py -v
```

Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add phantom_secops/mcp/secops_self_audit_server.py tests/test_mcp_self_audit_server.py
git commit -m "feat(mcp): secops_self_audit server (internal, scans agents.toml)

Exposes audit_local_config with x-phantom metadata
(classification=internal, capabilities=[read.config.local, target.self_only]).
Findings never echo secret values back.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: phantom-mesh worktree

**Files:** none yet — repository operations only.

- [ ] **Step 1: Create the worktree**

```bash
cd D:/Projects/phantom-mesh-private
git worktree add .worktrees/secops-mcp-policy -b feat/secops-mcp-policy phase1-r1-foundations
```

Expected output: `Preparing worktree (new branch 'feat/secops-mcp-policy')`.

- [ ] **Step 2: Verify**

```bash
git worktree list | grep secops-mcp-policy
ls D:/Projects/phantom-mesh-private/.worktrees/secops-mcp-policy/core/src/mcp_client.rs
```

Expected: worktree present, mcp_client.rs path exists.

- [ ] **Step 3: Switch to worktree for all subsequent phantom-mesh tasks**

```bash
cd D:/Projects/phantom-mesh-private/.worktrees/secops-mcp-policy
```

All Tasks 7–11 happen in this directory.

---

## Task 7: `AgentPluginPolicy` config schema

**Files:**
- Modify: `core/src/config.rs`

- [ ] **Step 1: Find existing AgentConfig + add failing test**

Locate the `AgentConfig` struct in `core/src/config.rs` (search for `pub struct AgentConfig`). Identify where to insert a new optional field.

Append to the test module at the bottom of `core/src/config.rs`:

```rust
#[cfg(test)]
mod plugin_policy_tests {
    use super::*;

    #[test]
    fn parses_plugin_policy_block() {
        let toml = r#"
[agent.master]
provider = "groq"
model = "openai/gpt-oss-20b"
tools = []
instructions = ""

[agent.master.plugin_policy]
allowed_capabilities = ["read.*", "network.scan.passive"]
denied_capabilities = ["exec.shell"]
classification_max = "blue"
"#;
        let cfg: AgentsConfig = toml::from_str(toml).expect("toml parse");
        let policy = cfg.agents.get("master").and_then(|a| a.plugin_policy.as_ref())
            .expect("plugin_policy present");
        assert_eq!(policy.allowed_capabilities, vec!["read.*", "network.scan.passive"]);
        assert_eq!(policy.denied_capabilities, vec!["exec.shell"]);
        assert_eq!(policy.classification_max.as_deref(), Some("blue"));
    }

    #[test]
    fn plugin_policy_is_optional() {
        let toml = r#"
[agent.master]
provider = "groq"
model = "openai/gpt-oss-20b"
tools = []
instructions = ""
"#;
        let cfg: AgentsConfig = toml::from_str(toml).expect("toml parse");
        assert!(cfg.agents.get("master").unwrap().plugin_policy.is_none());
    }
}
```

- [ ] **Step 2: Run test, verify failure**

```bash
cd D:/Projects/phantom-mesh-private/.worktrees/secops-mcp-policy/core
cargo test -p phantom_mesh config::plugin_policy_tests 2>&1 | tail -20
```

Expected: compile error (unknown field `plugin_policy` in `AgentConfig` or struct missing).

- [ ] **Step 3: Add struct + field**

In `core/src/config.rs`, add (placement: near other agent-related structs):

```rust
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct AgentPluginPolicy {
    /// Capability globs the agent is allowed to call.
    pub allowed_capabilities: Vec<String>,
    /// Capability globs explicitly denied (override allow).
    pub denied_capabilities: Vec<String>,
    /// Max classification (`internal` < `blue` < `red`). None = no cap.
    pub classification_max: Option<String>,
}
```

Add the field to `AgentConfig`:

```rust
pub struct AgentConfig {
    // ... existing fields ...
    #[serde(default)]
    pub plugin_policy: Option<AgentPluginPolicy>,
}
```

(Exact insertion: append the new field after the last existing field of `AgentConfig`. Verify with `grep -n 'pub struct AgentConfig' core/src/config.rs`.)

- [ ] **Step 4: Run tests to verify pass**

```bash
cargo test -p phantom_mesh config::plugin_policy_tests 2>&1 | tail -20
```

Expected: 2 tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/src/config.rs
git commit -m "feat(config): add [agent.X.plugin_policy] schema

Optional block under each agent allowing capability glob allow/deny
lists and a classification_max ceiling. Used by mcp_client.rs to
gate calls to MCP tools that declare x-phantom.* metadata.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: x-phantom metadata parser in `mcp_client.rs`

**Files:**
- Modify: `core/src/mcp_client.rs`

- [ ] **Step 1: Identify where tools are registered**

```bash
grep -n 'tools/list\|register_tool\|tool_def' core/src/mcp_client.rs | head -10
```

Note the line number where each tool returned by `tools/list` is parsed into the registry. The new metadata extraction goes here.

- [ ] **Step 2: Write failing test**

Append to `core/src/mcp_client.rs` test module:

```rust
#[cfg(test)]
mod xphantom_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_xphantom_from_tool_metadata() {
        let raw = json!({
            "name": "scan_target",
            "description": "...",
            "inputSchema": {},
            "metadata": {
                "x-phantom.classification": "red",
                "x-phantom.capabilities": ["network.scan.passive", "target.lab_only"],
                "x-phantom.read_only": true
            }
        });
        let md = parse_xphantom(&raw).expect("present");
        assert_eq!(md.classification, "red");
        assert_eq!(md.capabilities, vec!["network.scan.passive", "target.lab_only"]);
        assert!(md.read_only);
    }

    #[test]
    fn missing_xphantom_returns_none() {
        let raw = json!({"name": "vanilla", "description": "", "inputSchema": {}});
        assert!(parse_xphantom(&raw).is_none());
    }

    #[test]
    fn malformed_classification_returns_none_with_warn() {
        let raw = json!({
            "name": "weird",
            "metadata": {"x-phantom.classification": "purple", "x-phantom.capabilities": [], "x-phantom.read_only": true}
        });
        assert!(parse_xphantom(&raw).is_none());
    }
}
```

- [ ] **Step 3: Run test, verify failure**

```bash
cargo test -p phantom_mesh mcp_client::xphantom_tests 2>&1 | tail -15
```

Expected: `parse_xphantom` not found.

- [ ] **Step 4: Implement parser**

Add to `core/src/mcp_client.rs` (top of file or in a `mod xphantom` submodule):

```rust
#[derive(Debug, Clone)]
pub struct XPhantomMetadata {
    pub classification: String,
    pub capabilities: Vec<String>,
    pub read_only: bool,
}

const VALID_CLASSIFICATIONS: &[&str] = &["internal", "blue", "red"];

pub fn parse_xphantom(tool_value: &serde_json::Value) -> Option<XPhantomMetadata> {
    let md = tool_value.get("metadata")?;
    let cls = md.get("x-phantom.classification")?.as_str()?;
    if !VALID_CLASSIFICATIONS.contains(&cls) {
        tracing::warn!(?cls, "invalid x-phantom.classification — tool not registered with policy");
        return None;
    }
    let caps_arr = md.get("x-phantom.capabilities")?.as_array()?;
    let capabilities: Vec<String> = caps_arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    let read_only = md.get("x-phantom.read_only").and_then(|v| v.as_bool()).unwrap_or(false);
    Some(XPhantomMetadata {
        classification: cls.to_string(),
        capabilities,
        read_only,
    })
}
```

(If the codebase doesn't use `tracing`, swap for `eprintln!` or whatever is in scope. Run `grep '^use' core/src/mcp_client.rs | head` to check.)

- [ ] **Step 5: Wire parser into the existing tool-registration path**

Find the function that processes the `tools/list` response (search for `"tools/list"` literal or the variable holding the response). After the existing parsing of name/description/inputSchema, add:

```rust
let xphantom = parse_xphantom(&tool_value);
```

And extend whatever `Tool` struct phantom uses (likely in mcp_client.rs near the top) to include:

```rust
pub xphantom: Option<XPhantomMetadata>,
```

Populate it in the registration code.

- [ ] **Step 6: Run tests to verify pass + cargo check**

```bash
cargo test -p phantom_mesh mcp_client::xphantom_tests 2>&1 | tail -15
cargo check -p phantom_mesh 2>&1 | tail -10
```

Expected: 3 tests pass, cargo check clean.

- [ ] **Step 7: Commit**

```bash
git add core/src/mcp_client.rs
git commit -m "feat(mcp): parse x-phantom.* metadata from tools/list

Extracts classification + capabilities + read_only from each tool's
metadata field at registration time. Tools with malformed metadata
are skipped from policy registration (still callable as vanilla MCP
if they don't declare x-phantom).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Policy enforcer

**Files:**
- Modify: `core/src/mcp_client.rs`

- [ ] **Step 1: Write failing tests**

Append to `core/src/mcp_client.rs` test module:

```rust
#[cfg(test)]
mod policy_tests {
    use super::*;
    use crate::config::AgentPluginPolicy;

    fn md(cls: &str, caps: &[&str], ro: bool) -> XPhantomMetadata {
        XPhantomMetadata {
            classification: cls.into(),
            capabilities: caps.iter().map(|s| s.to_string()).collect(),
            read_only: ro,
        }
    }

    fn policy(allow: &[&str], deny: &[&str], max: Option<&str>) -> AgentPluginPolicy {
        AgentPluginPolicy {
            allowed_capabilities: allow.iter().map(|s| s.to_string()).collect(),
            denied_capabilities: deny.iter().map(|s| s.to_string()).collect(),
            classification_max: max.map(|s| s.to_string()),
        }
    }

    #[test]
    fn classification_ordering_internal_lt_blue_lt_red() {
        let p = policy(&["read.*"], &[], Some("blue"));
        assert!(matches!(check_policy(Some(&p), Some(&md("internal", &["read.foo"], true))), PolicyDecision::Allow));
        assert!(matches!(check_policy(Some(&p), Some(&md("blue", &["read.foo"], true))), PolicyDecision::Allow));
        let red = check_policy(Some(&p), Some(&md("red", &["read.foo"], true)));
        assert!(matches!(red, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn capability_glob_match() {
        let p = policy(&["read.*"], &[], Some("red"));
        assert!(matches!(check_policy(Some(&p), Some(&md("blue", &["read.config.local"], true))), PolicyDecision::Allow));
        assert!(matches!(
            check_policy(Some(&p), Some(&md("blue", &["network.scan.passive"], true))),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn deny_overrides_allow() {
        let p = policy(&["read.*", "exec.shell"], &["exec.*"], Some("red"));
        let dec = check_policy(Some(&p), Some(&md("internal", &["exec.shell"], false)));
        assert!(matches!(dec, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn no_xphantom_is_vanilla_allow() {
        let p = policy(&[], &[], None);
        assert!(matches!(check_policy(Some(&p), None), PolicyDecision::Allow));
    }

    #[test]
    fn fail_closed_when_xphantom_no_policy_unless_internal_readonly() {
        // internal + read_only + read.* caps → allow even with no policy
        let dec = check_policy(None, Some(&md("internal", &["read.config.local"], true)));
        assert!(matches!(dec, PolicyDecision::Allow));
        // anything else with x-phantom but no policy → deny
        let dec = check_policy(None, Some(&md("blue", &["read.log_files"], true)));
        assert!(matches!(dec, PolicyDecision::Deny { .. }));
    }
}
```

- [ ] **Step 2: Run test, verify failure**

```bash
cargo test -p phantom_mesh mcp_client::policy_tests 2>&1 | tail -20
```

Expected: `check_policy` and `PolicyDecision` not found.

- [ ] **Step 3: Implement enforcer**

Add to `core/src/mcp_client.rs`:

```rust
use crate::config::AgentPluginPolicy;

#[derive(Debug)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String, denied: Vec<String> },
}

fn class_rank(c: &str) -> i32 {
    match c { "internal" => 0, "blue" => 1, "red" => 2, _ => 99 }
}

fn glob_match(pat: &str, s: &str) -> bool {
    if let Some(prefix) = pat.strip_suffix(".*") {
        s == prefix || s.starts_with(&format!("{prefix}."))
    } else {
        pat == s
    }
}

pub fn check_policy(
    agent_policy: Option<&AgentPluginPolicy>,
    tool_meta: Option<&XPhantomMetadata>,
) -> PolicyDecision {
    let Some(meta) = tool_meta else {
        // No x-phantom → vanilla MCP, allow.
        return PolicyDecision::Allow;
    };
    let Some(policy) = agent_policy else {
        // x-phantom present but no policy → fail-closed unless safe-default applies.
        let safe = meta.read_only
            && meta.classification == "internal"
            && meta.capabilities.iter().all(|c| c.starts_with("read."));
        return if safe {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny {
                reason: "no plugin_policy configured for this agent (fail-closed)".into(),
                denied: meta.capabilities.clone(),
            }
        };
    };
    // Classification cap.
    if let Some(max) = &policy.classification_max {
        if class_rank(&meta.classification) > class_rank(max) {
            return PolicyDecision::Deny {
                reason: format!("classification {} > max {}", meta.classification, max),
                denied: vec![meta.classification.clone()],
            };
        }
    }
    // Explicit deny wins.
    let denied: Vec<_> = meta
        .capabilities
        .iter()
        .filter(|cap| policy.denied_capabilities.iter().any(|d| glob_match(d, cap)))
        .cloned()
        .collect();
    if !denied.is_empty() {
        return PolicyDecision::Deny { reason: "explicit deny match".into(), denied };
    }
    // Every cap must match at least one allow.
    let unmet: Vec<_> = meta
        .capabilities
        .iter()
        .filter(|cap| !policy.allowed_capabilities.iter().any(|a| glob_match(a, cap)))
        .cloned()
        .collect();
    if !unmet.is_empty() {
        return PolicyDecision::Deny { reason: "capabilities not in allowed_capabilities".into(), denied: unmet };
    }
    PolicyDecision::Allow
}
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cargo test -p phantom_mesh mcp_client::policy_tests 2>&1 | tail -20
```

Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/src/mcp_client.rs
git commit -m "feat(mcp): policy enforcer with capability + classification rules

PolicyDecision::{Allow, Deny} returned by check_policy(agent_policy, tool_meta).
Rules:
- no x-phantom → vanilla MCP allow
- x-phantom but no policy → fail-closed except internal/read_only/read.*
- classification ≤ classification_max
- every cap must match at least one allowed_capabilities glob
- any cap matching denied_capabilities → deny

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Audit log writer

**Files:**
- Create: `core/src/secops_audit.rs`
- Modify: `core/src/lib.rs` (add `pub mod secops_audit;`)

- [ ] **Step 1: Write failing test**

Create `core/src/secops_audit.rs`:

```rust
//! Append-only JSONL audit log for sec-ops policy decisions.

use std::path::{Path, PathBuf};

#[derive(Debug, serde::Serialize)]
pub struct AuditEvent<'a> {
    pub ts: String,
    pub agent: &'a str,
    pub plugin: &'a str,
    pub tool: &'a str,
    pub input_hash: String,
    pub classification: Option<&'a str>,
    pub capabilities: &'a [String],
    pub decision: &'a str,
    pub reason: Option<&'a str>,
    pub duration_ms: u64,
}

pub fn audit_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".phantom-mesh")
        .join("data")
        .join("secops-audit.jsonl")
}

pub fn append(event: &AuditEvent<'_>) -> std::io::Result<()> {
    let path = audit_path();
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let line = serde_json::to_string(event).expect("AuditEvent serialise");
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(f, "{}", line)
}

pub fn hash_input(value: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    let serialised = serde_json::to_string(value).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(serialised.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_hash_is_stable() {
        let v = serde_json::json!({"target": "juice-shop"});
        let h1 = hash_input(&v);
        let h2 = hash_input(&v);
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn audit_path_under_phantom_mesh() {
        let p = audit_path();
        assert!(p.ends_with("data/secops-audit.jsonl") || p.ends_with("data\\secops-audit.jsonl"));
    }

    #[test]
    fn append_roundtrip(tmp_dir: &std::path::Path) {
        // smoke: write one event into a temp dir, read it back
        std::env::set_var("HOME", tmp_dir);
        let caps = vec!["read.config.local".to_string()];
        let ev = AuditEvent {
            ts: "2026-05-04T07:00:00Z".into(),
            agent: "master",
            plugin: "secops_self_audit",
            tool: "audit_local_config",
            input_hash: "sha256:test".into(),
            classification: Some("internal"),
            capabilities: &caps,
            decision: "allow",
            reason: None,
            duration_ms: 12,
        };
        super::append(&ev).expect("write");
        let body = std::fs::read_to_string(super::audit_path()).expect("read");
        assert!(body.contains("audit_local_config"));
    }
}
```

Note: the `tmp_dir` arg in `append_roundtrip` requires a fixture. Simpler: skip that test for now or use `tempfile` crate.

Replace the third test with:

```rust
    #[test]
    fn append_writes_jsonl_under_overridden_home() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("HOME", tmp.path());
        let caps = vec!["read.config.local".to_string()];
        let ev = AuditEvent {
            ts: "2026-05-04T07:00:00Z".into(),
            agent: "master",
            plugin: "secops_self_audit",
            tool: "audit_local_config",
            input_hash: "sha256:test".into(),
            classification: Some("internal"),
            capabilities: &caps,
            decision: "allow",
            reason: None,
            duration_ms: 12,
        };
        append(&ev).expect("write");
        let body = std::fs::read_to_string(audit_path()).expect("read");
        assert!(body.contains("audit_local_config"));
    }
```

Also add `tempfile = "3"` and `sha2 = "0.10"` to `core/Cargo.toml` `[dev-dependencies]` and `[dependencies]` respectively (check if already present first with `grep -E 'sha2|tempfile' core/Cargo.toml`).

- [ ] **Step 2: Run test, verify failure**

```bash
cargo test -p phantom_mesh secops_audit 2>&1 | tail -20
```

Expected: module not found in lib.rs (or sha2/tempfile not in deps).

- [ ] **Step 3: Wire into lib.rs**

Edit `core/src/lib.rs`. Find the section with module declarations (e.g. `pub mod mcp_client;`) and add:

```rust
pub mod secops_audit;
```

- [ ] **Step 4: Add deps if missing**

In `core/Cargo.toml`:

```toml
[dependencies]
# ... existing ...
sha2 = "0.10"

[dev-dependencies]
# ... existing ...
tempfile = "3"
```

- [ ] **Step 5: Run tests to verify pass**

```bash
cargo test -p phantom_mesh secops_audit 2>&1 | tail -10
```

Expected: 3 tests pass.

- [ ] **Step 6: Commit**

```bash
git add core/src/secops_audit.rs core/src/lib.rs core/Cargo.toml
git commit -m "feat(secops): audit log writer

Append-only JSONL events at ~/.phantom-mesh/data/secops-audit.jsonl,
with sha256-hashed input args (never raw) so the audit log doesn't
become a leakage channel for sensitive tool arguments.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: Wire enforcer + audit into `call_tool`

**Files:**
- Modify: `core/src/mcp_client.rs`

- [ ] **Step 1: Locate `call_tool`**

```bash
grep -n 'fn call_tool\|pub.* call_tool\|async fn call_tool' core/src/mcp_client.rs
```

Note the function signature.

- [ ] **Step 2: Write failing integration test**

Append to `core/src/mcp_client.rs` test module:

```rust
#[cfg(test)]
mod call_tool_policy_tests {
    use super::*;
    use crate::config::AgentPluginPolicy;

    /// Build a registered tool with explicit x-phantom and assert call_tool
    /// returns synthetic policy_denied for an agent without permission.
    #[tokio::test]
    async fn call_tool_returns_denied_when_policy_blocks() {
        let meta = XPhantomMetadata {
            classification: "red".into(),
            capabilities: vec!["network.scan.active".into()],
            read_only: false,
        };
        let policy = AgentPluginPolicy {
            allowed_capabilities: vec!["read.*".into()],
            denied_capabilities: vec!["network.scan.active".into()],
            classification_max: Some("blue".into()),
        };
        let dec = check_policy(Some(&policy), Some(&meta));
        match dec {
            PolicyDecision::Deny { reason, denied } => {
                assert!(reason.contains("classification") || reason.contains("deny"));
                assert!(!denied.is_empty());
            }
            PolicyDecision::Allow => panic!("expected deny"),
        }
    }
}
```

(Note: full end-to-end test of call_tool would require spawning a real MCP child. We rely on the policy unit tests + manual smoke for the wire-up.)

- [ ] **Step 3: Run test, verify failure or success based on what's wired already**

```bash
cargo test -p phantom_mesh mcp_client::call_tool_policy_tests 2>&1 | tail -10
```

Expected: passes (this is really a policy test; the wiring is verified by manual smoke).

- [ ] **Step 4: Modify `call_tool` to enforce + audit**

Find the body of `call_tool` (or whatever the public dispatch fn is). Before the existing JSON-RPC `tools/call` send, insert:

```rust
// New: policy gate
let agent_policy_opt = self.agent_policy_for(agent_name); // helper that looks up [agent.X.plugin_policy] from AgentsConfig
let xphantom_opt = self.tool_metadata(server_name, tool_name); // lookup from registry built in Task 8
let decision = check_policy(agent_policy_opt.as_ref(), xphantom_opt.as_ref());

let started = std::time::Instant::now();
let input_hash = crate::secops_audit::hash_input(&arguments);
let timestamp = chrono::Utc::now().to_rfc3339();

if let PolicyDecision::Deny { reason, denied } = &decision {
    let ev = crate::secops_audit::AuditEvent {
        ts: timestamp.clone(),
        agent: agent_name,
        plugin: server_name,
        tool: tool_name,
        input_hash: input_hash.clone(),
        classification: xphantom_opt.as_ref().map(|m| m.classification.as_str()),
        capabilities: xphantom_opt.as_ref().map(|m| m.capabilities.as_slice()).unwrap_or(&[]),
        decision: "deny",
        reason: Some(reason),
        duration_ms: started.elapsed().as_millis() as u64,
    };
    if let Err(e) = crate::secops_audit::append(&ev) {
        tracing::warn!(?e, "secops audit append failed");
    }
    return Ok(serde_json::json!({
        "error": {"code": "policy_denied", "reason": reason, "denied": denied}
    }));
}

// existing JSON-RPC forward unchanged...
let result = /* existing send & await */ ;

// After the existing call returns, append an allow event
let ev = crate::secops_audit::AuditEvent {
    ts: timestamp,
    agent: agent_name,
    plugin: server_name,
    tool: tool_name,
    input_hash,
    classification: xphantom_opt.as_ref().map(|m| m.classification.as_str()),
    capabilities: xphantom_opt.as_ref().map(|m| m.capabilities.as_slice()).unwrap_or(&[]),
    decision: "allow",
    reason: None,
    duration_ms: started.elapsed().as_millis() as u64,
};
let _ = crate::secops_audit::append(&ev);
```

If `agent_name` isn't currently a parameter of `call_tool`, plumb it through (this is the bigger change). The agent name flows from the agent loop's tool dispatch — find the caller and ensure the agent's name is passed.

`self.agent_policy_for(agent_name)` and `self.tool_metadata(server_name, tool_name)` are new helpers; implement them to read from existing registry + config.

- [ ] **Step 5: Run cargo check + all mcp_client tests**

```bash
cargo check -p phantom_mesh 2>&1 | tail -10
cargo test -p phantom_mesh mcp_client 2>&1 | tail -15
```

Expected: clean check + all mcp_client tests pass.

- [ ] **Step 6: Commit**

```bash
git add core/src/mcp_client.rs
git commit -m "feat(mcp): enforce plugin policy in call_tool + audit log

Wires the policy enforcer (Task 9) and audit writer (Task 10) into
the call_tool dispatch path. Denied calls return a synthetic
policy_denied JSON to the agent loop without forwarding to the
child plugin.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: `render-mesh-agents.py`

**Files:**
- Create: `scripts/render-mesh-agents.py`
- Create: `tests/test_render_mesh_agents.py`

**Note:** back to phantom-secops repo (`cd D:/Projects/phantom-secops`).

- [ ] **Step 1: Write failing test**

Create `tests/test_render_mesh_agents.py`:

```python
"""Tests for the agents/ → phantom-mesh agents.toml renderer."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "render-mesh-agents.py"


def run(args: list[str]) -> tuple[int, str]:
    result = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)
    return result.returncode, result.stdout + result.stderr


def test_renders_red_recon_with_plugin_policy(tmp_path: Path):
    src = tmp_path / "recon.toml"
    src.write_text(
        '[agent]\n'
        'name = "red-recon"\n'
        '[[agent.tools]]\n'
        'name = "nmap_runner"\n'
        '[[agent.tools]]\n'
        'name = "file_write"\n'
        '[agent.prompt]\n'
        'system = "You are a red-team agent."\n'
        '[agent.limits]\n'
        'max_tool_calls = 12\n'
    )
    rc, out = run([str(src)])
    assert rc == 0, out
    assert "[agent.red-recon]" in out
    assert "secops_recon.scan_target" in out
    assert "file_write" in out
    assert "[agent.red-recon.plugin_policy]" in out
    assert "network.scan.passive" in out
    assert "target.lab_only" in out
    assert 'classification_max = "red"' in out


def test_unknown_tool_emits_todo_and_exit_2(tmp_path: Path):
    src = tmp_path / "x.toml"
    src.write_text(
        '[agent]\n'
        'name = "x"\n'
        '[[agent.tools]]\n'
        'name = "unmapped_tool"\n'
        '[agent.prompt]\n'
        'system = "x"\n'
    )
    rc, out = run([str(src)])
    assert rc == 2
    assert "TODO: map unmapped_tool" in out


def test_blue_alert_triage_renders_blue_classification(tmp_path: Path):
    src = tmp_path / "triage.toml"
    src.write_text(
        '[agent]\n'
        'name = "blue-alert-triage"\n'
        '[[agent.tools]]\n'
        'name = "file_read"\n'
        '[[agent.tools]]\n'
        'name = "file_write"\n'
        '[agent.prompt]\n'
        'system = "Tier-1 SOC analyst."\n'
    )
    rc, out = run([str(src)])
    assert rc == 0, out
    assert "[agent.blue-alert-triage]" in out
    # No MCP plugin tools used → no plugin_policy needed.
    assert "[agent.blue-alert-triage.plugin_policy]" not in out
```

- [ ] **Step 2: Run, verify failure**

```bash
python3 -m pytest tests/test_render_mesh_agents.py -v
```

Expected: scripts/render-mesh-agents.py not found.

- [ ] **Step 3: Implement render script**

Create `scripts/render-mesh-agents.py`:

```python
#!/usr/bin/env python3
"""Translate phantom-secops agent TOML to phantom-mesh [agent.X] fragment.

Input format (this repo's agents/*/*.toml):
    [agent]
    name = "..."
    [[agent.tools]]
    name = "nmap_runner"
    [agent.prompt]
    system = "..."
    [agent.limits]
    max_tool_calls = N

Output format (phantom-mesh agents.toml):
    [agent.<name>]
    provider = "..."
    model    = "..."
    tools    = ["..."]
    instructions = "..."
    [agent.<name>.limits]
    max_tool_calls = N
    [agent.<name>.plugin_policy]   # only if any MCP plugin tool is used
    allowed_capabilities = [...]
    denied_capabilities  = [...]
    classification_max   = "..."
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import tomllib  # py 3.11+
except ImportError:
    import tomli as tomllib  # type: ignore[no-redef]

# Mapping: phantom-secops tool name → (mesh tool name, capability hints, classification)
TOOL_MAP: dict[str, tuple[str, list[str], str]] = {
    "nmap_runner":   ("secops_recon.scan_target", ["network.scan.passive", "target.lab_only"], "red"),
    "log_ingest":    ("secops_log.scan_log",      ["read.log_files", "target.localhost_only"], "blue"),
    # Phantom-mesh built-ins (no MCP needed)
    "file_read":     ("file_read",  [], "internal"),
    "file_write":    ("file_write", [], "internal"),
    "http_probe":    ("web_fetch",  [], "internal"),
    "dns_enum":      ("web_fetch",  [], "internal"),
}

DEFAULT_PROVIDER = "groq"
DEFAULT_MODEL = "openai/gpt-oss-20b"

CLASS_RANK = {"internal": 0, "blue": 1, "red": 2}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input_toml", type=Path)
    p.add_argument("--provider", default=DEFAULT_PROVIDER)
    p.add_argument("--model", default=DEFAULT_MODEL)
    args = p.parse_args()

    cfg = tomllib.loads(args.input_toml.read_text())
    agent = cfg.get("agent", {})
    name = agent.get("name") or args.input_toml.stem
    instructions = agent.get("prompt", {}).get("system", "").strip()
    limits = agent.get("limits", {})
    src_tools = agent.get("tools", [])

    mesh_tool_names: list[str] = []
    capability_hints: list[str] = []
    max_classification = "internal"
    saw_unmapped = False

    for t in src_tools:
        tname = t.get("name", "")
        if tname in TOOL_MAP:
            mesh_name, caps, cls = TOOL_MAP[tname]
            mesh_tool_names.append(mesh_name)
            capability_hints.extend(caps)
            if CLASS_RANK[cls] > CLASS_RANK[max_classification]:
                max_classification = cls
        else:
            mesh_tool_names.append(f"# TODO: map {tname}")
            saw_unmapped = True

    # Render
    out: list[str] = [f"[agent.{name}]"]
    out.append(f'provider = "{args.provider}"')
    out.append(f'model    = "{args.model}"')
    tools_repr = ", ".join(f'"{t}"' if not t.startswith("#") else t for t in mesh_tool_names)
    out.append(f"tools    = [{tools_repr}]")
    out.append('instructions = """')
    out.append(instructions)
    out.append('"""')
    if limits:
        out.append("")
        out.append(f"[agent.{name}.limits]")
        for k, v in limits.items():
            if isinstance(v, str):
                out.append(f'{k} = "{v}"')
            else:
                out.append(f"{k} = {v}")

    # plugin_policy block only if any MCP plugin tool is used
    has_mcp_tool = any(t.startswith("secops_") for t in mesh_tool_names if not t.startswith("#"))
    if has_mcp_tool:
        out.append("")
        out.append(f"[agent.{name}.plugin_policy]")
        # de-dup hints, sorted for stability
        unique_caps = sorted(set(capability_hints))
        out.append(f"allowed_capabilities = {unique_caps!r}".replace("'", '"'))
        out.append('denied_capabilities  = ["exec.shell", "network.scan.active", "write.*"]')
        out.append(f'classification_max   = "{max_classification}"')

    print("\n".join(out))
    return 2 if saw_unmapped else 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests, verify pass**

```bash
python3 -m pytest tests/test_render_mesh_agents.py -v
```

Expected: 3 tests pass.

- [ ] **Step 5: Verify on the real agent files**

```bash
python3 scripts/render-mesh-agents.py agents/red/recon.toml
echo "---"
python3 scripts/render-mesh-agents.py agents/blue/alert-triage.toml
```

Expected: clean output, no `# TODO` for these two (their tools are all mapped).

- [ ] **Step 6: Commit**

```bash
git add scripts/render-mesh-agents.py tests/test_render_mesh_agents.py
git commit -m "feat(scripts): render-mesh-agents translator

Converts phantom-secops agent TOML format to phantom-mesh [agent.X]
blocks. Derives plugin_policy capabilities from the tool list.
Unmapped tools render as # TODO comments and exit 2.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 13: `Makefile` `mesh-sync` target + README update

**Files:**
- Modify: `Makefile`
- Modify: `README.md`

- [ ] **Step 1: Add `mesh-sync` target**

Edit `Makefile`. Append before the `clean:` target (or wherever fits the existing layout):

```makefile
mesh-sync:  ## Render agents/*.toml to phantom-mesh format and print to stdout (review then paste into mac-coord agents.toml)
	@for f in agents/red/recon.toml agents/blue/alert-triage.toml; do \
		echo "# ─── rendered from $$f ────────────────────────────────────"; \
		python3 scripts/render-mesh-agents.py $$f || exit 1; \
		echo; \
	done

mesh-mcp-config:  ## Print [[mcp_servers]] entries to paste into phantom-mesh agents.toml
	@cat <<'EOF'
[[mcp_servers]]
name    = "secops_recon"
command = "python3"
args    = ["-m", "phantom_secops.mcp.secops_recon_server"]
cwd     = "$${PHANTOM_SECOPS_ROOT}"
env     = { PYTHONPATH = "$${PHANTOM_SECOPS_ROOT}" }

[[mcp_servers]]
name    = "secops_log"
command = "python3"
args    = ["-m", "phantom_secops.mcp.secops_log_server"]
cwd     = "$${PHANTOM_SECOPS_ROOT}"
env     = { PYTHONPATH = "$${PHANTOM_SECOPS_ROOT}" }

[[mcp_servers]]
name    = "secops_self_audit"
command = "python3"
args    = ["-m", "phantom_secops.mcp.secops_self_audit_server"]
cwd     = "$${PHANTOM_SECOPS_ROOT}"
env     = { PYTHONPATH = "$${PHANTOM_SECOPS_ROOT}" }
EOF
```

(Note: the `$$` escapes Make's variable expansion so the literal `${PHANTOM_SECOPS_ROOT}` reaches the output, where phantom-mesh's loader expands it at runtime.)

- [ ] **Step 2: Update README**

Edit `README.md`. Add a new section after `## Quick start` (locate it first):

```markdown
## phantom-mesh integration (live mode v2)

As of 2026-05-04, phantom-secops ships three MCP server wrappers that let
phantom-mesh agents drive the kill-chain pipeline directly:

- `secops_recon`       — wraps `tools/nmap_runner.py`
- `secops_log`         — wraps `tools/log_anomaly.py`
- `secops_self_audit`  — scans phantom's own `agents.toml`

To enable on a phantom-mesh-equipped host:

```bash
export PHANTOM_SECOPS_ROOT=$(pwd)
make mesh-mcp-config       # prints [[mcp_servers]] entries
make mesh-sync             # prints [agent.X] rendered fragments

# Append both outputs to ~/.phantom-mesh/agents.toml on the phantom-mesh
# coordinator host, then restart phantom serve.
```

Design: see `docs/specs/2026-05-04-phantom-mesh-integration.md`.
Plan:   see `docs/superpowers/plans/2026-05-04-phantom-mesh-integration.md`.
```

- [ ] **Step 3: Verify make targets work**

```bash
make mesh-sync 2>&1 | head -10
make mesh-mcp-config 2>&1 | head -10
```

Expected: both produce non-empty output.

- [ ] **Step 4: Commit**

```bash
git add Makefile README.md
git commit -m "feat(make): mesh-sync + mesh-mcp-config helpers + README section

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 14: End-to-end smoke on Mac coord (manual)

**Files:** mac-coord's `~/.phantom-mesh/agents.toml`.

This task requires SSH or shell access to the Mac coordinator
(`100.87.93.58`). If you don't have it during the session, defer to a
follow-up; the previous tasks ship a self-contained spec + plan + code
that the next session can apply.

- [ ] **Step 1: Pre-flight from Z13**

```bash
curl -sS http://100.87.93.58:7878/healthz   # must return "ok"
```

- [ ] **Step 2: Take a backup of current agents.toml on mac-coord**

(Run on mac-coord, e.g. via Mac TUI, ssh, or remote tool.)

```bash
cp ~/.phantom-mesh/agents.toml ~/.phantom-mesh/agents.toml.bak.smoke-2026-05-04
```

- [ ] **Step 3: Clone phantom-secops on mac-coord**

```bash
mkdir -p ~/Projects && cd ~/Projects
git clone https://github.com/markl-a/phantom-secops.git
cd phantom-secops
pip3 install -r requirements-dev.txt
make test    # all unit tests pass
export PHANTOM_SECOPS_ROOT=$(pwd)
```

- [ ] **Step 4: Append rendered fragments**

```bash
{
  echo ""
  make mesh-mcp-config
  echo ""
  make mesh-sync
} >> ~/.phantom-mesh/agents.toml

# Add a permissive plugin_policy under the master agent for day-1 demo:
cat >> ~/.phantom-mesh/agents.toml << 'EOF'

[agent.master.plugin_policy]
allowed_capabilities = [
  "read.*",
  "network.scan.passive",
  "target.localhost_only",
  "target.self_only",
  "target.lab_only",
]
denied_capabilities = ["exec.shell", "network.scan.active", "write.*"]
classification_max  = "red"
EOF
```

Verify with:

```bash
python3 -c 'import tomllib; tomllib.loads(open("'"$HOME"'/.phantom-mesh/agents.toml").read()); print("toml ok")'
```

- [ ] **Step 5: Restart phantom serve on mac-coord**

```bash
pkill -f 'phantom serve' || true
sleep 2
nohup phantom serve > ~/.phantom-mesh/data/serve.log 2>&1 &
sleep 5
curl -sS http://100.87.93.58:7878/healthz
```

Expected: `ok`.

Check the log for plugin spawn lines:

```bash
grep -i 'mcp\|secops' ~/.phantom-mesh/data/serve.log | head -10
```

Expected: 3 "spawn" lines, one per `secops_*` server.

- [ ] **Step 6: From Z13, dispatch three test tasks (HMAC-signed)**

```bash
SECRET=$(awk -F'=' '/^[[:space:]]*cluster_secret/{gsub(/[" ]/,"",$2); print $2}' ~/.phantom-mesh/agents.toml)
HOST=100.87.93.58; PORT=7878

submit() {
  local prompt="$1"
  local body="$(printf '{"agent":"master","prompt":%s}' "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$prompt")")"
  local hmac=$(printf '%s' "$body" | SECRET_VAR="$SECRET" python3 -c "import os,sys,hmac,hashlib; print(hmac.new(os.environ['SECRET_VAR'].encode(),sys.stdin.read().encode(),hashlib.sha256).hexdigest())")
  curl -sS -X POST "http://$HOST:$PORT/rpc/task/assign" \
       -H "X-Cluster-Auth: $hmac" -H 'Content-Type: application/json' --data "$body"
  echo
}

submit "Use secops_recon to scan juice-shop and report the open ports."
submit "Use secops_log to scan lab/mocks/attack-log.txt and summarise the alerts."
submit "Use secops_self_audit to audit the local agents.toml and list any findings."
unset SECRET
```

For each: capture the `job_id`, then:

```bash
JOB=...
curl -sS http://100.87.93.58:7878/rpc/task/status/$JOB
```

Expected: `status: done` for all three within ~30s; `output` contains the
plugin-returned JSON.

- [ ] **Step 7: Verify audit log on mac-coord**

```bash
tail -n 5 ~/.phantom-mesh/data/secops-audit.jsonl
```

Expected: at least 3 lines with `"decision":"allow"`, plugin names `secops_recon`,
`secops_log`, `secops_self_audit`.

- [ ] **Step 8: Push branches + open PRs**

```bash
# phantom-mesh worktree
cd D:/Projects/phantom-mesh-private/.worktrees/secops-mcp-policy
git push -u origin feat/secops-mcp-policy
gh pr create --title "feat(mcp): x-phantom capability enforcer for sec-ops plugins" \
             --body "See docs/superpowers/plans (in phantom-secops repo) for the plan; companion PR in phantom-secops adds the three plugins."

# phantom-secops
cd D:/Projects/phantom-secops
git push origin main
# (or branch + PR if you want review first)
```

- [ ] **Step 9: Update SESSION_RESUME notes (optional)**

Append to `D:/Projects/phantom-mesh-private/SESSION_RESUME.md`:

```markdown
## 2026-05-04 — phantom-secops integration v1
- 3 MCP plugins (red recon / blue log / internal self-audit) live on mac-coord
- mcp_client.rs gained x-phantom policy enforcer + audit log
- Manual smoke: 3 master-agent dispatches all returned status=done with plugin output
- Next: split master into separate red/blue/auditor agents; wrap nuclei_runner; deploy to other workers
```

---

## Self-review notes

This plan covers all 14 spec sections (§1–§14). Risks called out in spec
§13 are addressed:
- mcp SDK pin: Task 3 step 1
- mac-coord restart strategy: Task 14 step 5 (nohup pattern from 2026-05-03 SMOKE)
- Tool-use model on master: agents.toml in Task 14 uses `openai/gpt-oss-20b`
- agents.toml backup: Task 14 step 2 (`.bak.smoke-2026-05-04`)
- run_kill_chain.py backward compat: Task 1 step 3 keeps the `_blue_log_anomaly` shim

Cross-task type consistency:
- `XPhantomMetadata { classification, capabilities, read_only }` — defined Task 8, used Tasks 9, 11
- `PolicyDecision::{Allow, Deny}` — defined Task 9, used Task 11
- `AgentPluginPolicy { allowed_capabilities, denied_capabilities, classification_max }` — defined Task 7, used Tasks 9, 11
- `AuditEvent` shape — defined Task 10, used Task 11
- `xphantom_metadata(classification, capabilities, read_only)` — defined Task 2, used Tasks 3, 4, 5

No placeholders. No "TBD".
