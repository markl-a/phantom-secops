# Integrations

phantom-secops is designed to be **runtime-agnostic**: the actual logic lives in `phantom_secops/core.py` and is exposed through the MCP server in `phantom_secops/mcp/server.py`. Anything that speaks MCP can drive the same kill-chain that `make demo` drives.

This document tracks every supported integration, its current state, and the minimal config needed to use it.

## Status overview

| Adapter | State | Driving file |
|---|---|---|
| Python reference (`make demo`) | ✅ Stable | `scenarios/run_kill_chain.py` |
| MCP stdio server | ✅ Stable | `phantom_secops/mcp/server.py` |
| Claude Code | ✅ Stable | `.mcp.json` + `.claude/agents/secops-runner.md` |
| phantom-mesh TOML | 🟡 Documented; runtime pending | `agents/{red,blue}/*.toml` |
| Cursor / Continue | 🟡 Compatible via MCP; not actively tested | (config below) |
| OpenAI Agents SDK | 🟡 Compatible via MCP; not actively tested | (config below) |
| LangGraph | 🟡 Compatible via MCP; not actively tested | (config below) |

✅ = working today. 🟡 = should work but the integration is documentation-only and not part of CI.

## Why MCP, not bespoke per-runtime adapters

Three failure modes pushed us here:

1. The original plan was to call phantom-mesh directly from `run_kill_chain.py`. phantom-mesh's HTTP API isn't published yet (binary closed-source until June 2026), so committing to that schedule would block everything else.
2. Without a stable protocol, every new runtime (Cursor, OpenAI Agents, etc.) needs its own adapter. That's `O(N)` work per tool change.
3. MCP is supported by Anthropic, OpenAI, Cursor, Continue, and on phantom-mesh's roadmap. One server, many clients.

The cost: we don't get phantom-mesh's cross-provider cost tracking out of the box. That's an acceptable loss — see `docs/ARCHITECTURE.md` for the tradeoff.

## 1. Python reference (deterministic, CI-safe)

```bash
make demo-mock        # canned data, ~1 second, no docker, no API key
make demo             # against the live lab (requires `make lab-up` first)
```

This path bypasses MCP entirely and calls `phantom_secops.core.*` directly. It's the reference implementation for what every other adapter should produce. CI uses this lane.

## 2. MCP stdio server (for any MCP client)

```bash
make mcp-serve        # python3 -m phantom_secops.mcp.server, stdio transport
```

The server registers 11 tools and 2 resource schemes — see `docs/MCP-INTERFACE.md` for the frozen contract. To inspect the surface interactively:

```bash
make mcp-dev          # opens the MCP inspector (requires `mcp[cli]`)
```

## 3. Claude Code

The repo ships an `.mcp.json` so Claude Code picks up the server automatically when opened in this working directory.

```json
{
  "mcpServers": {
    "phantom-secops": {
      "command": "python3",
      "args": ["-m", "phantom_secops.mcp.server"],
      "env": {"PYTHONPATH": "${workspaceFolder}"}
    }
  }
}
```

The repo also ships a project-scoped subagent at `.claude/agents/secops-runner.md`. To drive a full kill-chain inside Claude Code:

```
> use the secops-runner subagent to run a kill-chain against juice-shop
```

The subagent enforces the same lab-target gate, never invents exploit payloads, and refuses lifecycle operations without explicit confirmation — these are properties of the MCP layer, not the prompt. See the subagent file for its workflow.

## 4. phantom-mesh

The agent configs in `agents/red/*.toml` and `agents/blue/*.toml` reference the MCP server via:

```toml
[mcp]
servers = ["phantom-secops"]

[[agent.tools]]
name        = "recon_host"
server      = "phantom-secops"
description = "..."
```

**Important caveat.** The exact format of MCP references in phantom-mesh TOML is **provisional**. phantom-mesh's `phantom-tools` crate (Phase 1 of their public source release) is expected mid-May 2026, and the runtime crate (Phase 2, late May 2026) will pin the syntax for MCP server references. When that lands, this section and all eight TOMLs may need a small migration.

Until then, treat `agents/**/*.toml` as documentation: they describe what each agent should do and what tools it should call, but the runtime path through these configs hasn't been wired up. The Python reference orchestrator and the MCP server are the runnable surfaces today.

## 5. Cursor

Cursor reads `.cursor/mcp.json` (project-level) or `~/.cursor/mcp.json` (user-level). Use the same shape as `.mcp.json`:

```json
{
  "mcpServers": {
    "phantom-secops": {
      "command": "python3",
      "args": ["-m", "phantom_secops.mcp.server"]
    }
  }
}
```

Then in Composer, ask "scan juice-shop for vulnerabilities and produce a pentest report" — Cursor will discover the 11 tools.

## 6. Continue

Add to `~/.continue/config.yaml`:

```yaml
mcpServers:
  - name: phantom-secops
    command: python3
    args: ["-m", "phantom_secops.mcp.server"]
```

## 7. OpenAI Agents SDK

The OpenAI Agents SDK supports MCP servers as tool sources. Minimal example:

```python
from agents import Agent
from agents.mcp import MCPServerStdio

server = MCPServerStdio(
    params={"command": "python3", "args": ["-m", "phantom_secops.mcp.server"]},
)

agent = Agent(
    name="secops-runner",
    instructions="(see .claude/agents/secops-runner.md for the full prompt)",
    mcp_servers=[server],
)
```

The same hard rules from the Claude Code subagent apply — that prompt is portable.

## 8. LangGraph

Use `langchain-mcp-adapters` to wrap the server:

```python
from langchain_mcp_adapters.client import MultiServerMCPClient

client = MultiServerMCPClient({
    "phantom-secops": {
        "command": "python3",
        "args": ["-m", "phantom_secops.mcp.server"],
        "transport": "stdio",
    }
})
tools = await client.get_tools()
# pass `tools` to your LangGraph node as usual.
```

---

## Adding a new adapter

1. Don't write a new server. Use the MCP one.
2. Reuse the prompt at `.claude/agents/secops-runner.md` — it's intentionally MCP-tool-name-driven, not Claude-Code-specific. The hard rules and workflow port directly.
3. If your runtime needs a different transport (HTTP/SSE rather than stdio), the FastMCP server in `phantom_secops/mcp/server.py` supports both — pass `--transport=streamable-http` to switch.
4. Add a row to the status table at the top of this file.
5. If your runtime uncovers a bug or a missing piece in the MCP interface, fix it in `docs/MCP-INTERFACE.md` first (frozen-contract change → SemVer bump), then in the server, then in every adapter. The four-place migration is unavoidable but rare.
