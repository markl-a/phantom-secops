# Interview talk track

Notes for talking about phantom-secops in a security-engineering interview.
Trend Micro, CrowdStrike, Palo Alto, etc.

## Elevator pitch (30 seconds)

> "I built a runtime-agnostic SecOps research platform. Eleven tools — recon,
> vuln-scan, log triage, correlation, report composition — are exposed as an
> MCP server with a frozen contract and a centralised safety gate. The same
> server is driven today by a Python orchestrator, by Claude Code via a
> project subagent, and by phantom-mesh agents through TOML configs. Red and
> blue pipelines run in parallel against an isolated lab and produce
> side-by-side reports, so you can quantify mean-time-to-detect against a
> known attack pattern. It's not a production tool — it's a research
> playground that demonstrates how XDR-style multi-source correlation maps
> cleanly onto a multi-agent architecture, *without* coupling the workflow
> to any single agent runtime."

## Likely questions

### "Is this legal?"

Short answer: yes, with a caveat. All targets are intentionally vulnerable
applications maintained for security education (OWASP Juice Shop, DVWA,
Metasploitable). All tools are widely deployed defensive research tools
(Nmap, Nuclei, Nikto). The lab runs on an isolated docker network with no
host port exposure by default. The exploit-suggester tool only produces
prose — there's a `has_runnable_poc: false` invariant on its output that's
asserted by the test suite and re-validated against any LLM-augmented prose
before it ships. See ETHICS.md for full scoping.

### "What's the value over a single LLM agent that does it all?"

Three things. **Context window** — splitting phases keeps each agent's prompt
focused. **Cost/latency tuning** — smaller model for prose-heavy steps, larger
for tool-heavy steps. **Operational mapping** — real SOCs and red teams
already split work across roles, so the architecture mirrors how the work is
done.

### "Why MCP as the foundation, not phantom-mesh directly?"

Two practical reasons. (1) phantom-mesh's binary is closed-source until June
2026, so committing to their HTTP API now would block on their release
schedule. (2) Even once it ships, a tools-as-MCP-server design lets phantom-
mesh, Claude Code, Cursor, OpenAI Agents, Continue, and LangGraph all drive
the same workflow without per-runtime adapters. Writing the SecOps logic once
and getting six runtimes for free is a clear win for a research playground
that's also a demo target for interviews.

The cost: losing phantom-mesh's cross-provider cost tracking out of the box.
For this scope, that's acceptable. Token-usage logging can live in the MCP
server if needed.

### "How does this differ from MSF / Cobalt Strike / Burp Suite Pro?"

This isn't an offensive tool. It's an **orchestration layer** that makes
existing tools cooperate via natural-language agents. The LLM doesn't write
exploits — it routes between standard scanners, parses their output, and
composes reports. Think "GitHub Actions for security workflows, but agents
write the steps."

### "What's the safety story for the LLM-augmented path?"

Three layers.

1. **Tool-name level**: the prose generator is called `suggest_exploit_prose`
   — the suffix makes the constraint visible to every caller.
2. **Output invariant**: every call returns `has_runnable_poc: false`.
   `tests/test_no_runnable_poc.py` asserts this for the deterministic path,
   and the LLM path validates the *generated* text against the same
   forbidden-pattern set (`safety.is_safe_prose`) before merging it in.
3. **Fallback**: if the validator rejects the LLM output, or the provider is
   unreachable, the call silently falls back to a deterministic template.
   The pipeline never blocks on a failed LLM call.

Tests cover a malicious provider that tries to inject a curl command — the
output gets dropped and the markdown stays clean.

### "Where's the lab-target gate enforced?"

Centralised in `phantom_secops/mcp/safety.py`. Both the MCP boundary
(`recon_host`, `vuln_scan_web` refuse non-lab inputs and return
`error: not_a_lab_target`) **and** the legacy tool wrappers (`tools/nmap_runner.py`)
import the same `is_lab_service()` function. Defense-in-depth: a bad
TOML, a misbehaving LLM, or a direct call to the wrapper all hit the same
list. Six unit tests in `tests/test_safety.py` lock the whitelist.

### "What's the false-positive rate of the alert-triage agent?"

I haven't run it long enough to give a calibrated number. On the demo
scenarios I have, it correctly promotes scanner activity to P2 within 15s of
recon starting and doesn't escalate to P1 until vuln-scan starts probing
endpoints. I'd want to validate this against a real alert dataset before
claiming a real number.

### "How does this scale?"

Agents are stateless between handoffs (state lives on the file system as run
artifacts under `reports/runs/<ts>/`, addressable through MCP resources at
`phantom-secops://runs/<ts>/<file>`). You could run multiple lab instances
on a single host, or shard across a cluster. Once phantom-mesh ships its
distributed execution layer (Phase 3 — early June 2026), the same agent
TOMLs can run across the mesh.

### "Walk me through the kill-chain demo."

Three paths to demo. Pick whichever fits the conversation:

**Mock mode** (no docker, deterministic): `make demo-mock` — finishes in
under a second. Shows the structure: 21 raw alerts → 5 triaged groups → 1
correlated actor.

**Claude Code path**: open the repo in Claude Code, ask the `secops-runner`
subagent to run a kill-chain. Same 11 MCP tools, but you get to *see* the
agent reasoning over the artifacts in real time. Good for interviewers who
want to see agent UX.

**Live lab**: `make lab-up && make demo`. Full Nmap → Nuclei chain against
Juice Shop. Slower (~60s) but the artifacts include real scan output. Good
for interviewers who want to see actual tool integration.

The point is that **detection lag is small when the analysis pipeline runs
concurrently with the attack** — which is what real SOC tooling tries to do.

### "What would you build next?"

In priority order:

1. **Real alert dataset replay.** Use a public CTF dataset (CTF-d archives,
   MISP feeds) to validate the triage agent's calibration.
2. **Containment actions.** Right now the blue side observes and reports.
   Next step is enabling guarded response actions (block IP, isolate
   container) with human-in-the-loop approval — those become new MCP tools
   under a `lifecycle` safety class.
3. **Multi-host correlation.** Run the same demo against a 3-host lab where
   the actor pivots between hosts; check whether `correlate_threats`
   stitches the chain end-to-end.
4. **Real phantom-mesh runtime.** Once `phantom-tools` (mid May) and
   `phantom-runtime` (late May) ship, wire the TOML configs to the live
   runtime and add a phantom-mesh CI lane.

### "How do you keep the LLM from hallucinating CVE numbers?"

Two checks. The exploit-suggester only references CVEs that appear in the
vuln-scan tool's output — it can't pull a CVE out of thin air. Beyond that,
the prose validator catches any output containing executable shell content,
and the deterministic fallback path is grounded in `vuln-scan-juice-shop.json`
(or live nuclei output). If the LLM names a CVE in the prose, that CVE is
already in the source data — otherwise the fallback kicks in.

## Don't say

- "This finds 0-days" (it doesn't, and the claim is a red flag).
- "This is better than [commercial product]" (it isn't — it's a research
  demo).
- "I built this in a weekend" (the framework took months — say that).
- Any claim about real-world adversaries (you have no telemetry to back it).
