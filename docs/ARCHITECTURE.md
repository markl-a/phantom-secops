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
        │  RED agents  │                  │  BLUE agents │
        │  (TOML-cfgd) │                  │  (TOML-cfgd) │
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

The runtime gives us:

- **Tool-calling loop** — agents are written as TOML configs + Python tool
  wrappers. No bespoke agent harness to maintain per project.
- **Provider fallback** — if Groq rate-limits during a long scenario, the run
  silently moves to Anthropic / OpenRouter / a local MLX model. Useful when a
  demo needs to be reliable in a live setting.
- **Cost tracking** — each agent run reports tokens / cost, which lets us
  compare "what does a full kill-chain analysis cost in API calls" honestly.
- **Inter-agent context** — recon JSON written to `reports/` is picked up by
  vuln-scan via a `file_read` tool call, not via a bespoke message bus. Simple,
  observable, durable.

## Why split into so many agents

Two reasons.

**Domain reason.** Real SOCs split work across roles: T1 analyst (triage),
T2 (correlation), incident commander (report). Modeling those roles as agents
maps well to existing operational language. A pentest engagement also splits
recon → scanning → exploitation → reporting, with different specialists per
phase.

**LLM reason.** Each phase has different tool access patterns and different
cost/latency characteristics. Recon is I/O-heavy and benefits from a larger
context window. Exploit-suggest is text-heavy and benefits from a smaller, faster
model. Mixing them in one mega-agent causes prompt bloat and degraded reasoning
at each step.

## Comparison to a monolithic LLM-driven scanner

You could imagine a single "security agent" that reads a target URL and emits a
report. We tried this in early prototypes. The failure modes were:

1. **Tool-call sprawl.** A single agent tried to do everything in one chain
   — recon, scan, exploit suggestion, report — and ran out of context window.
2. **Lost intermediate state.** When the agent retried after a tool failure, it
   re-did recon from scratch.
3. **No defensive narrative.** A single attack-side agent had no defender's
   perspective to compare against, which is the most interesting part of this
   demo.

Splitting into role-specific agents with explicit handoff via the file system
fixed all three.

## Multi-source correlation = multi-agent

The blue side mirrors how XDR products work: multiple specialized analyzers
each looking at one signal source, with a correlator agent that joins them.
This isn't novel — it's the same pattern as Trend Vision One, Microsoft
Defender XDR, Falcon NG-SIEM. The novelty here is making the pattern
*observable* and *modifiable* via TOML configs, instead of buried inside a
SaaS console.

## Performance notes

The full kill-chain demo runs in ~60s on a M2 Mac. The bottleneck is Nuclei
(~40s of that), not the agents. The phantom-mesh tool-calling overhead is in
single-digit seconds across the whole run.

We chose to keep Nuclei serial because parallelism would change the request
pattern visible to the blue team in unrealistic ways — it's important that
the attacker's pattern looks plausible.
