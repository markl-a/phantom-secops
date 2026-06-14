# Architecture

## Layers

```
┌────────────────────────────────────────────────────────────────────┐
│                         phantom-mesh runtime                        │
│  ─────────────────────────────────────────────────────────────────  │
│  - LLM provider routing (multi-provider fallback)                   │
│  - Tool calling loop (TOML-defined tools)                           │
│  - Cost tracking                                                    │
│  - Inter-agent message passing                                      │
└─────────────┬──────────────────────────────────┬───────────────────┘
              │                                  │
        ┌─────▼────────┐                  ┌──────▼───────┐
        │  RED steps   │                  │  BLUE steps  │
        │ (determinist.│                  │ (determinist.│
        │  pipeline)   │                  │  pipeline)   │
        └─────┬────────┘                  └──────┬───────┘
              │                                  │
        ┌─────▼────────┐                  ┌──────▼───────┐
        │ Tool wrappers│                  │ Tool wrappers│
        │ (Python,     │                  │ (Python,     │
        │  call into   │                  │  read logs / │
        │  attacker    │                  │  emit alerts)│
        │  container)  │                  │              │
        └─────┬────────┘                  └──────┬───────┘
              │                                  │
              │  (docker exec into attacker)     │  (docker socket → log volume)
              ▼                                  ▼
┌────────────────────────────────────────────────────────────────────┐
│                       secops-lab docker network                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  juice-shop  │  │     dvwa     │  │ metasploitab │  (targets)   │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │   attacker   │  │log-collector │  │   dvwa-db    │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
└────────────────────────────────────────────────────────────────────┘
```

## Why phantom-mesh

The project is built on phantom-mesh, the agent runtime. Note the split: the
**endpoint self-check (Pillar 1)** runs as a real LLM agent on this runtime,
while the **red/blue kill-chain (Pillar 2)** is today a deterministic Python
orchestrator — driving it from phantom-mesh agent loops is a future milestone.
The runtime gives us:

- **Tool-calling loop** — tools are exposed as MCP servers + Python wrappers,
  consumed by the endpoint agent. No bespoke agent harness to maintain.
- **Provider fallback** — if Groq rate-limits during a long run, the endpoint
  agent silently moves to Anthropic / OpenRouter / a local MLX model. Useful
  when a demo needs to be reliable in a live setting.
- **Cost tracking** — an agent run reports tokens / cost, which lets us compare
  "what does an analysis cost in API calls" honestly.
- **File-based handoff** — in the kill-chain, recon JSON written to `reports/`
  is picked up by the vuln-scan step via a plain file read, not a bespoke
  message bus. Simple, observable, durable.

## Why split the kill-chain into phases

Two reasons. (Honest framing: today these phases are functions in one
deterministic process, not separate agents — the split is a design choice that
maps onto the future LLM-agent-per-phase milestone.)

**Domain reason.** Real SOCs split work across roles: T1 analyst (triage),
T2 (correlation), incident commander (report). Modeling those roles as pipeline
phases maps well to existing operational language. A pentest engagement also
splits recon → scanning → exploitation → reporting, with different specialists
per phase.

**Future-LLM reason.** Each phase has different tool access patterns and
different cost/latency characteristics. Recon is I/O-heavy and would benefit
from a larger context window; exploit-suggest is text-heavy and would suit a
smaller, faster model. Keeping phases separate now means that when they become
real agent loops, each can be sized independently instead of bloating one
mega-agent.

## Comparison to a monolithic LLM-driven scanner

You could imagine a single "security agent" that reads a target URL and emits a
report. We tried this in early prototypes. The failure modes were:

1. **Tool-call sprawl.** A single agent tried to do everything in one chain
   — recon, scan, exploit suggestion, report — and ran out of context window.
2. **Lost intermediate state.** When the agent retried after a tool failure, it
   re-did recon from scratch.
3. **No defensive narrative.** A single attack-side chain had no defender's
   perspective to compare against, which is the most interesting part of this
   demo.

Splitting into discrete phases with explicit handoff via the file system fixed
all three — and is why the kill-chain is structured as a deterministic pipeline
of steps today.

## Multi-source correlation

The blue side mirrors how XDR products work: multiple specialized analyzers
each looking at one signal source, with a correlation step that joins them.
This isn't novel — it's the same pattern as Trend Vision One, Microsoft
Defender XDR, Falcon NG-SIEM. The novelty here is making the pattern
*observable* and *modifiable* via TOML configs, instead of buried inside a
SaaS console.

## Performance notes

The **mock** demo (`make demo-mock`) runs in well under a second — it reads
canned recon/vuln/log fixtures, and the timeline it prints uses *simulated*
per-step durations (see `RED_DURATIONS`/`BLUE_DURATIONS` in
`scenarios/run_kill_chain.py`), which is what makes the MTTD comparison
meaningful without waiting on real scans.

**Live mode** (`make lab-up && make demo`) wires real tools: recon (nmap via
`tools/nmap_runner.py`) and vuln-scan (`tools/nuclei_runner.py`, called per HTTP
endpoint derived from the recon output, kept serial so the attacker's request
pattern stays plausible to the blue team). It has **not been verified
end-to-end on this machine** — that needs the docker lab up — and `dnsrecon /
subfinder / nikto` from the conceptual diagram have no runners yet. So the mock
demo remains the reliable, full-story path; live verification is the milestone.
