> ARCHIVED 2026-06-19 — frozen historical snapshot; current status lives in /ROADMAP.md

# Status

**Phase: 🟡 Public Alpha — opened 2026-05-10**

This repo went public alpha as part of the [phantom-mesh ecosystem](https://github.com/markl-a/phantom-mesh) launch on 2026-05-20. It is *not* yet a polished product — but it is **demonstrably runnable end-to-end** in mock mode (`make demo-mock`, <1s, zero external deps).

## What works today (2026-05-10)

| Component | State |
|---|---|
| `make demo-mock` (deterministic kill-chain run) | ✅ runs in <1s, no Docker, no API keys |
| `make demo` (live OWASP Juice Shop + DVWA via Docker) | ✅ tested locally; Docker required |
| MCP server (`phantom_secops/mcp/server.py`, 10 tools) | ✅ accepts `phantom mcp add` / Claude Code |
| Red-team agents (recon → vuln-scan → exploit-prose → pentest report) | ✅ canned mock fixtures + opt-in real LLM |
| Blue-team agents (log-anomaly → triage → correlate → incident report) | ✅ same |
| Cross-side MTTD timeline rendering | ✅ markdown out + JSON for chart consumers |
| Vision-LLM screenshot judge | n/a (this repo is text-only; see [phantom-mobile](https://github.com/markl-a/phantom-mobile) for vision use) |

## What's planned

| | When | Where |
|---|---|---|
| L2 integration with phantom-mesh runtime (red/blue agents become phantom-mesh agents driven via MCP) | 5/14 - 5/15 | [`docs/L2-INTEGRATION-PLAN.md`](docs/L2-INTEGRATION-PLAN.md) |
| HTML report from `make demo-mock` (Streamlit + Plotly timeline) | post-5/20 | [Issue tracker](https://github.com/markl-a/phantom-secops/issues) |
| Self-healing: when target version changes, agent re-pathfinds via LLM | post-5/20 | research |
| Kubernetes-based lab (replace docker-compose) | post-5/20 | research |

## Hard rules (these never change)

1. **`has_runnable_poc` is always `false`** in `exploit` tool output — we ship prose explanations, not runnable exploits, even in private mode. Tested by `tests/test_no_runnable_poc.py`.
2. **Lab targets are deny-listed everywhere except `localhost` / Docker overlay.** No external scanning is possible without explicit code change + opt-in.
3. **No customer / internal-network data is ever ingested.** This is a research playground, not an MDR product.

## Why "alpha" not "beta"

- Test coverage is moderate (62% line coverage on `phantom_secops/core`).
- Live-mode against the Docker lab passes locally but doesn't have CI gating yet.
- The 4-week runway between 2026-05-10 and "is this useful for real?" is ahead, not behind.
- Naming, CLI args, MCP tool names may shift before we hit beta. Pin to a specific commit if you depend on this.

If you find a bug or run into setup friction, [open an issue](https://github.com/markl-a/phantom-secops/issues) — fast turnaround during the alpha window.
