# phantom-secops

> **Multi-agent SecOps research playground — runtime-agnostic.**
> Cooperating red/blue agents drive recon, triage, correlation, and reporting against an isolated lab. The tool layer is exposed as an MCP server, so [phantom-mesh](https://github.com/markl-a/phantom-mesh), Claude Code, Cursor, OpenAI Agents SDK, or any MCP-compatible runtime can drive the same workflow.

[![Powered by phantom-mesh](https://img.shields.io/badge/powered%20by-phantom--mesh-purple)](https://github.com/markl-a/phantom-mesh)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Lab](https://img.shields.io/badge/targets-OWASP%20Juice%20Shop%20%7C%20DVWA-orange)](docker-compose.yml)

---

## What it does (60 seconds)

Two sets of agents run in parallel against an intentionally vulnerable target (OWASP Juice Shop, DVWA, Metasploitable) running in a Docker lab:

```
RED TEAM (attack simulation)              BLUE TEAM (defensive ops)
─────────────────────────────             ─────────────────────────────
Recon ── Nmap                             Log Anomaly ── pattern match
   │                                          │
   ▼                                          ▼
Vuln Scan ── Nuclei                       Alert Triage ── group + prioritize
   │                                          │
   ▼                                          ▼
Exploit Suggest ── prose only             Threat Correlate ── kill chain
   │                                          │
   ▼                                          ▼
Pentest Report ─── markdown out           Incident Report ── exec summary
```

Both teams produce markdown reports. The interesting part is the **side-by-side comparison**: how long it took the attacker to reach impact vs. how long the defender took to detect — a metric that maps directly to MTTD (mean time to detect) used in real SOCs.

---

## Why this exists

phantom-secops is structured around three principles:

1. **XDR is multi-source correlation by nature.** Trend Vision One™, Microsoft Defender XDR, and CrowdStrike Falcon all cross-reference signals from endpoint + network + identity + cloud. Mapping each source to an agent and letting them coordinate via a shared protocol is a clean fit.
2. **Pentest workflows are sequential pipelines that branch.** Recon results feed vuln scanning, which feeds exploit suggestion. Each step is an agent with a tool budget.
3. **Tools should be runtime-agnostic.** The 11 SecOps tools (recon, scan, triage, correlate, …) are exposed as an [MCP server](docs/MCP-INTERFACE.md). phantom-mesh, Claude Code, Cursor, OpenAI Agents SDK — any MCP client drives the same workflow with the same safety guarantees.

This is a **research playground** — not a production tool, not a 0-day weapon, not a service offering.

---

## Quick start — three paths

### Path 1: Mock mode (deterministic, no docker, no API key)

```bash
git clone https://github.com/markl-a/phantom-secops
cd phantom-secops
make demo-mock
```

Runs the full red/blue pipeline on canned data in <1 second. CI uses this lane. Output:

```
→ phantom-secops kill-chain :: target=juice-shop mock=True llm=none
  [t+  0.0s] red-recon          → 1 open ports
  [t+  0.0s] red-vuln-scan      → 5 findings
  [t+  0.0s] red-exploit-suggest done
  [t+  0.0s] blue-log-anomaly   → 21 raw alerts
  [t+  0.0s] blue-alert-triage  → 5 triaged groups
  [t+  0.0s] blue-threat-correlate → 1 actor(s)
```

### Path 2: Claude Code via MCP

The repo ships a [`.mcp.json`](.mcp.json) and a [project-scoped subagent](.claude/agents/secops-runner.md). Open the directory in Claude Code:

```
> use the secops-runner subagent to run a kill-chain against juice-shop
```

The subagent calls the same 11 MCP tools that the Python orchestrator does, with the same safety gates (lab targets only, prose-only exploit text, lifecycle confirmation).

### Path 3: phantom-mesh / other runtimes

Each agent in `agents/{red,blue}/*.toml` declares its MCP tools via:

```toml
[mcp]
servers = ["phantom-secops"]

[[agent.tools]]
name        = "recon_host"
server      = "phantom-secops"
description = "..."
```

phantom-mesh's MCP integration is being staged for May–June 2026 (Phase 1–2 source release). Until that lands, the TOML configs are documentation — but the underlying MCP server (`make mcp-serve`) works today and is callable by any other MCP client.

See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) for Cursor, Continue, OpenAI Agents SDK, and LangGraph examples.

---

## With LLM-driven prose

```bash
# Anthropic provider
PHANTOM_SECOPS_LLM=anthropic ANTHROPIC_API_KEY=sk-... \
  python3 scenarios/run_kill_chain.py --mock --use-llm

# phantom-mesh HTTP provider (requires `phantom serve`)
PHANTOM_SECOPS_LLM=phantom_mesh \
  python3 scenarios/run_kill_chain.py --mock --use-llm
```

LLM output is validated against the same forbidden-pattern set (`safety.is_safe_prose`) used by the test suite. If the model attempts to inject runnable shell content, the call falls back to deterministic templates and the `has_runnable_poc: false` invariant stays intact.

---

## Live mode — against the docker lab

```bash
make lab-up                # Juice Shop + DVWA on private docker network
make demo                  # full kill-chain
make lab-down              # tear down
```

Lab targets bind only to the private docker network — **never to the host or the internet** (see [`docker-compose.yml`](docker-compose.yml)). All `Makefile` targets are listed via `make help`.

---

## Repo layout

```
phantom-secops/
├── docker-compose.yml             # isolated lab (Juice Shop, DVWA, Metasploitable)
├── phantom_secops/
│   ├── core.py                    # runtime-agnostic red/blue pipeline functions
│   ├── llm/                       # LLM provider abstraction (anthropic, phantom_mesh, none)
│   └── mcp/
│       ├── server.py              # FastMCP server — 11 tools, 2 resources
│       ├── safety.py              # lab-target gate + prose safety validator
│       └── lab.py                 # docker compose lifecycle helpers
├── scenarios/
│   └── run_kill_chain.py          # Python reference orchestrator (CI-safe)
├── agents/
│   ├── red/                       # attack-side agent configs (TOML, phantom-mesh format)
│   └── blue/                      # defense-side agent configs
├── tools/                         # legacy thin wrappers (call into attacker container)
│   ├── nmap_runner.py
│   ├── nuclei_runner.py
│   └── log_ingest.py
├── tests/                         # 32 tests — pipeline, safety, MCP protocol, LLM invariant
├── lab/                           # docs + canned mock data for each target
├── scenarios/                     # markdown scenarios runnable by phantom-mesh
├── reports/                       # sample output reports (anonymized)
├── docs/
│   ├── ARCHITECTURE.md
│   ├── MCP-INTERFACE.md           # frozen contract — names, schemas, safety gates
│   ├── INTEGRATIONS.md            # how to plug in each runtime
│   └── INTERVIEW-TALK-TRACK.md
├── .mcp.json                      # Claude Code MCP server config
├── .claude/agents/secops-runner.md  # Claude Code subagent
├── ETHICS.md                      # legal/ethical framing — read first
└── LICENSE
```

---

## Status

| Component | State |
|---|---|
| Docker compose lab (Juice Shop, DVWA) | ✅ syntax verified, runs |
| Mock-mode end-to-end demo (`make demo-mock`) | ✅ runnable on any machine, <1 s |
| MCP server (`make mcp-serve`) | ✅ 11 tools / 2 resources, stdio + http transport |
| Claude Code adapter (`.mcp.json` + subagent) | ✅ working |
| LLM provider abstraction (anthropic / phantom_mesh / none) | ✅ working, with safety validation |
| Recon agent (Nmap orchestration) | ✅ with lab-target gate |
| Vuln scan agent (Nuclei wrapper) | ⚙️ wrapper done; live integration WIP |
| Exploit suggester (CVE → POC text) | ✅ template + LLM-driven, `has_runnable_poc: false` invariant enforced |
| Blue team log-anomaly + triage + correlation | ✅ working |
| Side-by-side red/blue report (pentest + incident markdown) | ✅ working |
| Tests (`make test`) | ✅ 32 tests passing |
| phantom-mesh runtime integration | 🟡 TOML configs aligned; awaits phantom-tools / phantom-runtime release (May–June 2026) |
| Live-mode kill-chain (against running docker lab) | ⚙️ partial — recon path works; nuclei path needs container with nuclei pre-installed |

---

## Ethics & legality

**Read [ETHICS.md](ETHICS.md) before use.**

Short version:
- All targets in this lab are legally distributed, intentionally vulnerable applications maintained for security research and education (OWASP Juice Shop, DVWA, Metasploitable).
- All tools used (Nmap, Nuclei, Nikto) are legitimate, publicly available defensive research tools.
- The `suggest_exploit_prose` MCP tool **only generates POC descriptions in text form** — `has_runnable_poc: false` is asserted by the test suite. It does not generate or execute weaponized exploits.
- The lab runs on an isolated docker network — never on a public network or third-party system.

---

## Related projects

- 🌟 [phantom-mesh](https://github.com/markl-a/phantom-mesh) — The multi-agent runtime that originally inspired this repo.
- 📖 [GarageSwarm](https://github.com/markl-a/GarageSwarm) — Python predecessor of phantom-mesh.

## License

Apache-2.0
