# phantom-secops

> **Multi-agent security operations platform powered by [phantom-mesh](https://github.com/markl-a/phantom-mesh).**
> Cooperating agents handle both defensive ops (alert triage, log anomaly, threat correlation) and red-team simulation (recon, vuln scan, POC suggestion) in an isolated lab.

[![Powered by phantom-mesh](https://img.shields.io/badge/powered%20by-phantom--mesh-purple)](https://github.com/markl-a/phantom-mesh)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Lab](https://img.shields.io/badge/targets-OWASP%20Juice%20Shop%20%7C%20DVWA-orange)](docker-compose.yml)

---

## What it does (60 seconds)

Two sets of phantom-mesh agents run in parallel against an intentionally vulnerable target (OWASP Juice Shop, DVWA, Metasploitable) running in a Docker compose lab:

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

Both teams produce markdown reports. The interesting part is the **side-by-side comparison**: how long it took the attacker to reach impact vs. how long the defender took to detect — a metric that maps directly to MTTD (mean time to detect) used in real SOCs.

---

## Why this exists

phantom-mesh's multi-agent runtime is well-suited to security operations because:

1. **XDR is multi-source correlation by nature.** Trend Vision One™, Microsoft Defender XDR, CrowdStrike Falcon all cross-reference signals from endpoint + network + identity + cloud. Mapping each source to an agent and letting them coordinate via phantom-mesh is a clean fit.
2. **Pentest workflows are sequential pipelines that branch.** Recon results feed vuln scanning, which feeds exploit suggestion. Each step is an agent with a tool budget.
3. **LLM-assisted triage reduces alert fatigue.** The blue-team agents demonstrate this in a small, observable way.

This repo is a **research playground** — not a production tool, not a 0-day weapon, not a service offering.

---

## Quick start

### Mock mode — no docker, no API key, runs anywhere in <1 second

```bash
git clone https://github.com/markl-a/phantom-secops
cd phantom-secops
make demo-mock
```

Output:
```
→ phantom-secops kill-chain :: target=juice-shop mock=True
  [t+  0.0s] red-recon          → 1 open ports
  [t+  0.0s] red-vuln-scan      → 5 findings (1 medium, 2 low, ...)
  [t+  0.0s] red-exploit-suggest done
  [t+  0.0s] blue-log-anomaly   → 21 raw alerts
  [t+  0.0s] blue-alert-triage  → 5 triaged groups
  [t+  0.0s] blue-threat-correlate → 1 actor(s)
  [t+  0.0s] done

→ artifacts: reports/runs/<ts>/{pentest-report.md, incident-report.md,
                                recon.json, vuln-scan.json,
                                alerts.jsonl, triage-queue.jsonl,
                                kill-chains.jsonl, exploit-suggestions.md}
```

This runs the full red/blue agent pipeline on canned data. Use it to
explore the artifact shapes and the report templates without bringing up
docker. Tests run via `make test` (7 unit tests covering pattern matchers
and triage logic).

### Live mode — against the docker lab

```bash
make lab-up                # bring up Juice Shop + DVWA on the private docker network
make demo                  # full kill-chain against the live lab
make lab-down              # tear down

# Optional: with phantom-mesh LLM-driven prose
phantom serve &            # phantom-mesh HTTP API at :7878
make demo  # runner picks it up if phantom is reachable
```

The lab targets are bound to a private docker network. They are **not exposed
to your host or the internet** (see `docker-compose.yml`). All `Makefile`
targets are listed via `make help`.

---

## Repo layout

```
phantom-secops/
├── docker-compose.yml          # isolated lab (Juice Shop, DVWA, Metasploitable)
├── agents/
│   ├── red/                    # attack-side agent configs (TOML, phantom format)
│   │   ├── recon.toml
│   │   ├── vuln-scan.toml
│   │   ├── exploit-suggest.toml
│   │   └── pentest-report.toml
│   └── blue/                   # defense-side agent configs
│       ├── alert-triage.toml
│       ├── log-anomaly.toml
│       ├── threat-correlate.toml
│       └── incident-report.toml
├── tools/                      # phantom tool wrappers (Python)
│   ├── nmap_runner.py
│   ├── nuclei_runner.py
│   └── log_ingest.py
├── lab/                        # docs for each target's setup
├── scenarios/                  # markdown scenarios runnable by phantom
│   ├── full-kill-chain.md
│   └── alert-triage-demo.md
├── reports/                    # sample output reports (anonymized)
├── docs/
│   ├── ARCHITECTURE.md
│   └── INTERVIEW-TALK-TRACK.md
├── ETHICS.md                   # legal/ethical framing — read first
└── LICENSE
```

---

## Status

| Component | State |
|---|---|
| Docker compose lab (Juice Shop, DVWA) | ✅ syntax verified, runs |
| Mock-mode end-to-end demo (`make demo-mock`) | ✅ runnable on any machine, <1s |
| Recon agent (Nmap orchestration) | ✅ working with lab-target gate |
| Vuln scan agent (Nuclei wrapper) | ⚙️ wrapper done; live integration WIP |
| Exploit suggester (CVE → POC text) | ✅ template-driven prose; LLM-driven opt-in via `--use-llm` |
| Blue team log-anomaly (URL-decoded pattern matchers) | ✅ working, 7 unit tests pass |
| Blue team triage + correlation (group by actor + ATT&CK phase) | ✅ working |
| Side-by-side red/blue report (pentest + incident markdown) | ✅ working |
| Tests (`make test`) | ✅ 7 unit tests passing |
| Live-mode kill-chain (against running docker lab) | ⚙️ partial — recon path works; nuclei path needs container with nuclei pre-installed |

---

## Ethics & legality

**Read [ETHICS.md](ETHICS.md) before use.**

Short version:
- All targets in this lab are legally distributed, intentionally vulnerable applications maintained for security research and education (OWASP Juice Shop, DVWA, Metasploitable).
- All tools used (Nmap, Nuclei, Nikto) are legitimate, publicly available defensive research tools.
- The Exploit Suggester agent **only generates POC descriptions in text form**. It does not generate or execute weaponized exploits.
- The lab runs on an isolated docker network — never on a public network or third-party system.

---

## Related projects

- 🌟 [phantom-mesh](https://github.com/markl-a/phantom-mesh) — The agent runtime this depends on.
- 📖 [GarageSwarm](https://github.com/markl-a/GarageSwarm) — Python predecessor of phantom-mesh.

## License

Apache-2.0
