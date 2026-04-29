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

```bash
git clone https://github.com/markl-a/phantom-secops
cd phantom-secops

# 1. Bring up the isolated lab (Juice Shop + DVWA on a private docker network)
docker compose up -d

# 2. Make sure phantom is installed (see https://github.com/markl-a/phantom-mesh)
phantom --version

# 3. Run the full kill-chain scenario
phantom run scenarios/full-kill-chain.md

# 4. Inspect the reports
ls reports/
```

The lab targets are bound to a private docker network. They are **not exposed to your host or the internet**.

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
| Docker compose lab (Juice Shop, DVWA) | ✅ working |
| Recon agent (Nmap orchestration) | ✅ working |
| Vuln scan agent (Nuclei) | ⚙️ in progress |
| Exploit suggester (CVE → POC text) | 🚧 design done, code WIP |
| Blue team alert triage | ⚙️ in progress |
| Side-by-side red/blue report | 🚧 design done |
| End-to-end kill-chain demo | 🚧 D-day target: 2026-05-05 |

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
