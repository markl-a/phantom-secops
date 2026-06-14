# phantom-secops

> A local-first **endpoint-security agent**: a read-only toolchain that checks
> *this* machine — host posture, dependency CVEs, host intrusion signals — and
> uses one LLM agent to turn the raw findings into a single prioritised,
> plain-language action list. Built to run on
> [phantom-mesh](https://github.com/markl-a/phantom-mesh), my agent runtime.
>
> It also ships a smaller **SOC concept demo** (a red/blue kill-chain
> *simulation*) — see [Pillar 2](#pillar-2--soc-concept-demo-redblue-kill-chain-simulation).

[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-114%20passing-brightgreen.svg)](tests/)

---

## What this is (and isn't)

The idea behind both parts is **"don't build the engine, build the brain":** wrap
mature, battle-tested security tools (Trivy, a Sigma matcher, native OS queries)
and let an LLM agent orchestrate, correlate, and explain. The differentiation is
the agent + MCP-tool layer, not a re-implemented scanner.

This does **not** claim production SOC automation, multi-agent red-vs-blue
combat, 0-day discovery, or third-party scanning. Everything is **self-only or
lab-only** and **read-only** — it advises, it never changes your system. See
[ETHICS.md](ETHICS.md).

---

## Pillar 1 — Local-first endpoint self-check (the real, daily-driver part)

A read-only toolchain that checks *this* machine and uses **one LLM agent**
(running on phantom-mesh, with provider fallback) to fold the raw findings into a
single prioritised report. Data never leaves the machine.

Six tools, each exposed as its own MCP server (one tool per server, stdio
JSON-RPC):

| Capability | Engine | MCP server / tool |
|---|---|---|
| Host security posture (firewall, disk encryption, AV, UAC, ports, SIP) | native OS queries | `secops_host_audit` / `audit_host` |
| Dependency / OS-package CVEs (prioritised, fixable-first) | **Trivy** | `secops_vuln` / `scan_vulns` |
| Host intrusion signals (encoded PowerShell, cradles, AMSI bypass…) | a small **Sigma** engine over Windows event logs | `secops_ids` / `scan_intrusions` |
| Config self-audit (phantom-mesh `agents.toml` hygiene) | native | `secops_self_audit` / `audit_local_config` |
| Lab recon (also used by Pillar 2) | nmap | `secops_recon` / `scan_target` |
| Log-anomaly pattern match (also used by Pillar 2) | pattern matcher | `secops_log` / `scan_log` |

```powershell
.\checkup.ps1                              # one command: tests + every tool + AI report
.\checkup.ps1 -Path D:\Projects\my-app     # scan a specific project for CVEs
.\checkup.ps1 -SkipTests -SkipAgent        # raw tool output only, no LLM call
```

A Windows scheduled task can run it daily and log to `reports/checkup/`. On the
author's machine a run surfaced **864 fixable CVEs** in a sibling project plus an
AV real-time-protection gap; the agent then produced exact upgrade versions and a
prioritised fix order.

> The `secops_recon` / `secops_log` tools are shared with Pillar 2 — that's why
> the demo and the endpoint check can use the same engines. The endpoint tools
> (`host_audit`, `vuln`, `ids`, `self_audit`) are the ones that actually run on
> *this* machine through the agent.

### The capability model (`x-phantom`)

Each MCP tool tags itself with `x-phantom.{classification, capabilities, read_only}`
(e.g. `blue` / `read.host_posture` / `target.self_only`). This is the hook for a
per-agent policy enforcer in phantom-mesh — so a blue-team agent could be denied
red-team tools — and it's how every tool advertises that it is read-only and
self-scoped. The metadata is emitted and unit-tested here; the phantom-mesh-side
enforcer that consumes it is not part of this repo.

---

## Pillar 2 — SOC concept demo (red/blue kill-chain *simulation*)

A side-by-side red (attack) and blue (defense) pipeline runs against an
intentionally vulnerable target (OWASP Juice Shop, DVWA, Metasploitable) in a
Docker lab, and emits a **mean-time-to-detect (MTTD)** comparison.

**This is a single deterministic Python orchestrator** (`scenarios/run_kill_chain.py`),
**not** a multi-agent system. The `agents/*.toml` files describe agent *roles* and
the tools are exposed over MCP, so driving the pipeline from real phantom-mesh
agent loops is a future milestone — but today the pipeline is plain Python
functions in one process, with templated (not LLM-written) reports.

```
RED (attack simulation)                   BLUE (defensive ops)
─────────────────────────────             ─────────────────────────────
Recon ── nmap                             Log Anomaly ── pattern match
   │                                          │            over a canned log
   ▼                                          ▼
Vuln Scan ── nuclei (live-mode only)      Alert Triage ── classify + dedupe
   │                                          │
   ▼                                          ▼
Exploit Suggest ── templated prose        Threat Correlate ── kill-chain
   │                  (no runnable POC)        │                reconstruction
   ▼                                          ▼
Pentest Report ─── markdown out           Incident Report ── markdown out
```

The interesting part is the **side-by-side comparison**: attacker time-to-impact
vs. defender time-to-detect. In mock mode (**simulated, illustrative SOC timing —
clearly labelled in the output, not measured benchmarks**) the defender triages
at **t+15s** while the attacker reaches impact at **t+50s** → **MTTD 15s,
detected 35s before impact**. The *mechanism* (two concurrent clocks, milestone
extraction, the MTTD comparison) is real and tested; the per-step durations are
scenario inputs, not real detection latencies.

```bash
make demo-mock      # full red/blue pipeline on canned data, <1s, no docker/keys
make lab-up && make demo && make lab-down   # live, against the docker lab
```

> **Honesty notes.**
> - The reports are **templated**, not LLM-written. The `--use-llm` flag exists
>   on `run_kill_chain.py` but is a **no-op stub** — it's parsed and threaded
>   through the signature for a future LLM-driven report writer, and changes
>   nothing today (`_run_exploit_suggest` ignores it). The exploit-suggester is
>   deterministic prose keyed off scan findings, so it structurally cannot invent
>   a CVE.
> - **Mock mode is the path that's verified end-to-end here.** Live mode wires
>   nmap recon and a nuclei vuln-scan (nuclei self-installs in the lab container
>   on first run), but the live path has not been verified end-to-end in this
>   repo — it needs the docker lab up. The diagram's *dnsrecon / subfinder /
>   nikto* are conceptual (no runners; nikto is in the lab image but not invoked).

---

## Architecture

```
        ┌───────────────────────────────────────────────┐
        │  LLM agent (phantom-mesh runtime)             │
        │  provider fallback · tool-calling loop        │
        └───────────────┬───────────────────────────────┘
                        │  MCP (stdio JSON-RPC) + x-phantom policy metadata
   ┌────────────────────┼────────────────────────────────────────┐
   ▼            ▼        ▼          ▼            ▼            ▼
host_audit  vuln(Trivy) ids(Sigma) self_audit  recon(nmap)  log
   └─── each: tools/<x>.py (pure, injectable runner) + one MCP server wrapper ───┘
```

Every tool is a pure Python module with an **injectable command runner**, so the
logic is unit-tested with canned output and never touches the real OS in tests.
Each MCP server is a thin wrapper that adds the `x-phantom` metadata. Full design
notes: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) ·
key engineering decisions: [docs/DECISIONS.md](docs/DECISIONS.md).

---

## Verification

- `python -m pytest -q` → **114 passing** here. Covers matchers, parsers,
  prioritisation, the Sigma engine, the MTTD timing model, the MCP server
  wrappers, and elevation/encoding edge cases — all via injected runners, no real
  scanning in tests.
- `make demo-mock` → red/blue pipeline on canned data, deterministic, <1s.
- `.\checkup.ps1` → live endpoint check + AI report on Windows.

Step-by-step walkthrough for both demos: [docs/DEMO.md](docs/DEMO.md).

---

## Engineering decisions worth a look

Short version (full writeup in [docs/DECISIONS.md](docs/DECISIONS.md)):

- **Injectable runners everywhere** so OS-touching tools are still unit-testable.
- **Low false-positives over coverage** — tuned out an IDS rule that fired on a
  *signed Microsoft module manifest*; deliberately did **not** bolt on 300+ CIS
  checks that would be alert-fatigue noise for a personal machine.
- **Honest degradation** — a check that needs admin returns `unknown` with a
  "re-run as Administrator" hint, never a false `fail`.
- **Read-only by design** — suggest, never auto-remediate (keeps the
  trust/liability bar low).

---

## Ethics & legality

**Read [ETHICS.md](ETHICS.md) first.** All lab targets are intentionally-vulnerable
apps maintained for security education; all tools are legitimate public research
tools; the exploit-suggester emits prose only; the endpoint tools are read-only
and self-only.

## Related

- 🌟 [phantom-mesh](https://github.com/markl-a/phantom-mesh) — the agent runtime this is built on.

## License

Apache-2.0
