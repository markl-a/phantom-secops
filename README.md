# phantom-secops

> A security-operations project built on my own multi-agent runtime,
> [phantom-mesh](https://github.com/markl-a/phantom-mesh). It does **two** things:
>
> 1. **A SOC-concept demo** — red and blue team agents run in parallel against an
>    isolated vulnerable lab and produce a side-by-side **mean-time-to-detect** comparison.
> 2. **A real local-first endpoint self-check** — read-only host posture, dependency
>    CVEs, and host intrusion detection on *this* machine, unified by an LLM agent into
>    one prioritised, plain-language action list.

[![Powered by phantom-mesh](https://img.shields.io/badge/powered%20by-phantom--mesh-purple)](https://github.com/markl-a/phantom-mesh)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](tests/)

---

## What this demonstrates

Both pillars run on the same idea — **"don't build the engine, build the brain":** wrap
mature, battle-tested security tools and let LLM agents orchestrate, correlate, and
explain. The differentiation is the agent layer, not a re-implemented scanner.

| Pillar | What it shows |
|---|---|
| **SOC concept demo** (red/blue lab) | I understand how SOC work decomposes — recon→scan→exploit-suggest on one side, log-anomaly→triage→correlate on the other — and can quantify it with MTTD, the metric real SOCs care about. |
| **Endpoint self-check tool** | I can wrap real engines (Trivy, a Sigma matcher, native OS queries), build an MCP plugin suite with a capability model, drive it from an agent, and ship something I actually run daily. |

Neither claims production SOC automation, 0-day discovery, or third-party scanning.
Everything is lab-only or self-only and **read-only** — it advises, it never changes your
system. See [ETHICS.md](ETHICS.md).

---

## Pillar 1 — SOC concept demo (red/blue lab)

Two agent pipelines — red (attack) and blue (defense) — run against an intentionally
vulnerable target (OWASP Juice Shop, DVWA, Metasploitable) in a Docker lab. Today they're
driven by a deterministic Python orchestrator (`run_kill_chain.py`); the same tools are
also exposed as MCP servers, so driving the pipeline from phantom-mesh agent loops is the
next milestone (the endpoint tool in Pillar 2 already runs through the agent).

```
RED TEAM (attack simulation)              BLUE TEAM (defensive ops)
─────────────────────────────             ─────────────────────────────
Recon ── Nmap, dnsrecon, subfinder        Alert Triage ── classify SIEM
   │                                          │             alerts, dedupe
   ▼                                          ▼
Vuln Scan ── Nuclei, Nikto                Log Anomaly ── baseline +
   │                                          │            outlier detect
   ▼                                          ▼
Exploit Suggest ── CVE matcher,           Threat Correlate ── kill chain
   │                  POC text only           │                reconstruction
   ▼                                          ▼
Pentest Report ─── markdown out           Incident Report ── exec summary
```

The interesting part is the **side-by-side comparison**: attacker time-to-impact vs.
defender time-to-detect — i.e. **MTTD**. In the mock demo (simulated, representative
SOC timing) the defender triages the activity at **t+15s** while the attacker only
reaches impact at **t+50s** — **MTTD 15s, detected 35s before impact**.

```bash
make demo-mock      # full red/blue pipeline on canned data, <1s, no docker/keys
make lab-up && make demo && make lab-down   # live, against the docker lab
```

> Honesty note: mock timing is **simulated** (clearly labelled in the output). Live mode is
> partial — nmap recon is real, but the nuclei vuln-scan step isn't wired yet, so live
> findings are currently empty. The mock demo tells the full story; the live path is a
> hardening milestone.

---

## Pillar 2 — Local-first endpoint self-check

A read-only, local toolchain that checks *this* machine and uses an LLM agent to turn
raw findings into one prioritised report. Data never leaves the machine.

| Capability | Engine | MCP tool |
|---|---|---|
| Host security posture (firewall, disk encryption, AV, UAC, ports, SIP) | native OS queries | `secops_host_audit` |
| Dependency / OS-package CVEs (prioritised, fixable-first) | **Trivy** | `secops_vuln` |
| Host intrusion detection (encoded PowerShell, cradles, AMSI bypass…) | a small **Sigma** engine over Windows event logs | `secops_ids` |
| Config self-audit (phantom-mesh `agents.toml` hygiene) | native | `secops_self_audit` |
| Lab recon / log-anomaly (Pillar 1 tools, also exposed) | nmap / pattern matcher | `secops_recon`, `secops_log` |

```powershell
.\checkup.ps1                              # one command: tests + every tool + AI report
.\checkup.ps1 -Path D:\Projects\my-app     # scan a specific project for CVEs
```

A Windows scheduled task can run it daily and log to `reports/checkup/`. A real run on
the author's machine surfaced **864 fixable CVEs** in a sibling project and an AV
real-time-protection gap, then the agent produced exact upgrade versions and a
prioritised fix order.

### The capability model (`x-phantom`)

Each MCP tool tags itself with `x-phantom.{classification, capabilities, read_only}`
(e.g. `blue` / `read.host_posture` / `target.self_only`). This is the hook for a
per-agent policy enforcer in phantom-mesh — so a blue-team agent can be denied red-team
tools — and it's how every tool here advertises that it is read-only and self-scoped.

---

## Architecture

```
        ┌───────────────────────────────────────────────┐
        │  LLM agent (phantom-mesh runtime)             │
        │  provider fallback · tool-calling loop        │
        └───────────────┬───────────────────────────────┘
                        │  MCP (stdio JSON-RPC) + x-phantom policy
   ┌────────────────────┼────────────────────────────────────────┐
   ▼            ▼        ▼          ▼            ▼            ▼
host_audit  vuln(Trivy) ids(Sigma) self_audit  recon(nmap)  log
   └─────────── each: tools/<x>.py (pure, TDD'd) + an MCP server wrapper ───┘
```

Every tool is a pure Python module with an **injectable command runner**, so the logic
is unit-tested with canned output and never touches the real OS in tests. The MCP server
is a thin wrapper that adds the `x-phantom` metadata. Full design notes:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) ·
key engineering decisions: [docs/DECISIONS.md](docs/DECISIONS.md).

---

## Verification

- `python -m pytest -q` → all green (run it; the suite grows as features land). Covers
  matchers, parsers, prioritisation, the Sigma engine, and elevation/encoding edge cases
  — all via injected runners, no real scanning in tests.
- `make demo-mock` → red/blue pipeline on canned data.
- `.\checkup.ps1` → live endpoint check + AI report on Windows.

Step-by-step walkthrough for both demos: [docs/DEMO.md](docs/DEMO.md).

---

## Engineering decisions worth a look

Short version (full writeup in [docs/DECISIONS.md](docs/DECISIONS.md)):

- **Injectable runners everywhere** so OS-touching tools are still unit-testable.
- **Low false-positives over coverage** — tuned out an IDS rule that fired on a *signed
  Microsoft module manifest*; deliberately did **not** bolt on 300+ CIS checks that would
  be alert-fatigue noise for a personal machine.
- **Honest degradation** — a check that needs admin returns `unknown` with a "re-run as
  Administrator" hint, never a false `fail`.
- **Read-only by design** — suggest, never auto-remediate (keeps the trust/liability bar low).

---

## Ethics & legality

**Read [ETHICS.md](ETHICS.md) first.** All lab targets are intentionally-vulnerable apps
maintained for security education; all tools are legitimate public research tools; the
exploit-suggester emits prose only; the endpoint tools are read-only and self-only.

## Related

- 🌟 [phantom-mesh](https://github.com/markl-a/phantom-mesh) — the agent runtime this is built on.

## License

Apache-2.0
