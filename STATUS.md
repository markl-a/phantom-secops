# Status

**Phase: 🟡 Public Alpha — opened 2026-05-10**

This repo went public alpha as part of the [phantom-mesh ecosystem](https://github.com/markl-a/phantom-mesh) launch on 2026-05-20. It is *not* yet a polished product — but it is **demonstrably runnable end-to-end** in mock mode (`make demo-mock`, <1s, zero external deps).

## What works today (2026-05-10)

| Component | State |
|---|---|
| `make demo-mock` (deterministic kill-chain run) | ✅ runs in <1s, no Docker, no API keys |
| `make demo` (live OWASP Juice Shop + DVWA via Docker) | 🟡 wired (nmap + nuclei); not verified end-to-end here (needs Docker) |
| MCP servers (6 servers under `phantom_secops/mcp/`, one tool each: host_audit, vuln, ids, self_audit, recon, log) | ✅ accept `phantom mcp add` / Claude Code |
| Red pipeline (recon → vuln-scan → exploit-prose → pentest report) | ✅ deterministic Python orchestrator, canned mock fixtures; reports templated, **not** LLM-written (`--use-llm` is a no-op stub) |
| Blue pipeline (log-anomaly → triage → correlate → incident report) | ✅ same (deterministic, templated) |
| Cross-side MTTD timeline rendering | ✅ markdown out + JSON for chart consumers (mock timing is simulated, not measured) |
| Vision-LLM screenshot judge | n/a (this repo is text-only; see [phantom-mobile](https://github.com/markl-a/phantom-mobile) for vision use) |

## What's planned

| | When | Where |
|---|---|---|
| L2 integration with phantom-mesh runtime (the deterministic red/blue pipeline becomes phantom-mesh agent loops driven via MCP) | 5/14 - 5/15 | [`docs/L2-INTEGRATION-PLAN.md`](docs/L2-INTEGRATION-PLAN.md) |
| HTML report from `make demo-mock` (Streamlit + Plotly timeline) | post-5/20 | [Issue tracker](https://github.com/markl-a/phantom-secops/issues) |
| Self-healing: when target version changes, agent re-pathfinds via LLM | post-5/20 | research |
| Kubernetes-based lab (replace docker-compose) | post-5/20 | research |

## Hard rules (these never change)

1. **The exploit-suggester ships prose only — never runnable exploits.** It's the deterministic `_exploit_prose` / `_run_exploit_suggest` in `scenarios/run_kill_chain.py`, which emits text keyed off scan findings (no payloads, no POC).
2. **Recon / vuln-scan runners refuse non-lab targets** (`_target_in_lab` in `tools/nmap_runner.py`; the nuclei runner returns an error for out-of-lab URLs). No external scanning without an explicit code change.
3. **No customer / internal-network data is ever ingested.** This is a research playground, not an MDR product.

## Why "alpha" not "beta"

- Test coverage is via injected runners (114 tests passing); no real-OS scanning is exercised in tests.
- Live-mode against the Docker lab is wired but not verified end-to-end here, and has no CI gating yet.
- The 4-week runway between 2026-05-10 and "is this useful for real?" is ahead, not behind.
- Naming, CLI args, MCP tool names may shift before we hit beta. Pin to a specific commit if you depend on this.

If you find a bug or run into setup friction, [open an issue](https://github.com/markl-a/phantom-secops/issues) — fast turnaround during the alpha window.
