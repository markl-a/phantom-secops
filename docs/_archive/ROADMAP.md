> ARCHIVED 2026-06-19 — 內容已併入 docs/phantom-secops.md;此為歷史版本。

# Roadmap

> **Single source of truth for project status.** README and docs link here instead of
> carrying their own status lists. Last updated **2026-06-19**.
>
> Phase: **Public Alpha** — demonstrably runnable end-to-end in mock mode
> (`make demo-mock`, <1s, no Docker, no API keys). Not yet a polished product.
> Naming, CLI args, and MCP tool names may still shift; pin to a commit if you depend on this.

phantom-secops has two pillars (see [README.md](README.md)): a red/blue **SOC concept demo**
with a mean-time-to-detect (MTTD) comparison, and a local-first **endpoint self-check** tool.
Status below is grounded in merged commits on `main`.

## Shipped

**Pillar 1 — red/blue SOC demo**

- Deterministic mock kill-chain (`make demo-mock`) — red (recon → vuln-scan → exploit-suggest
  → pentest-report) and blue (log-anomaly → triage → correlate → incident-report) run on two
  concurrent clocks; runs in <1s with no Docker and no API keys.
- **Real, meaningful MTTD** — a two-clock model with simulated per-step durations replaced the
  earlier `0.0s`; mock run shows **MTTD 15s, detected 35s before impact**, honestly labelled
  "simulated" in mock mode. Metric is honest in both directions (defender win / attacker win).
- Machine-readable run metrics — the real run writes `summary.json` (MTTD, outcome,
  detect_margin, time_to_impact + sorted timeline) for chart consumers.
- `log_ingest.scan_window` genuinely wired into the orchestrator's blue path (was previously
  dead code), journalled and merged into triage/correlate.
- Live-mode honesty — when Docker / nmap / nuclei are missing, live mode shows a **DEGRADED**
  banner instead of fake-greening; live `nmap` recon and per-endpoint `nuclei` vuln-scan are
  wired in code.

**Pillar 2 — local-first endpoint self-check**

- One-command self-scan (`checkup.ps1`) — runs the toolchain plus an LLM agent that unifies
  findings into one prioritised report; a Windows scheduled task can run it daily.
- Tool engines (each a pure Python module with an injectable command runner, unit-tested with
  canned output): `host_audit`, `vuln_scan` (Trivy), `ids_scan` (Sigma over Windows event
  logs), `log_anomaly`, `log_ingest`, `nmap_runner`, `nuclei_runner`, `posture_fusion`.
- **Deterministic cross-tool posture fusion** — `posture_fusion.fuse_posture` combines
  host_audit + vuln_scan + ids_scan findings into ONE ranked action list (normalized severity,
  highest-risk-first, stable tiebreak, plain-language, **no LLM**), wired into the real
  `checkup.ps1` path ("== PRIORITISED ACTIONS ==").

**MCP surface**

- Seven MCP servers under `phantom_secops/mcp/`: `secops_host_audit`, `secops_ids`,
  `secops_log_ingest`, `secops_log`, `secops_recon`, `secops_self_audit`, `secops_vuln`.
- `x-phantom` capability metadata (`classification` / `capabilities` / `read_only`) on each
  tool — the hook for per-agent policy enforcement; every tool advertises read-only + self/lab
  scope.
- `make mesh-sync` / `make mesh-mcp-config` render agent/MCP config for pasting into a
  phantom-mesh `agents.toml`.

**Hardening & robustness**

- Security pass: replaced `eval()` in the Sigma condition matcher with a safe AST boolean
  evaluator (closes DoS/escape), closed an nmap shell-injection in command build (scan_type /
  ports validation), clamped the nuclei timeout, and bounded IDS condition length
  (RecursionError/MemoryError caught).
- Closed an nuclei lab-gate substring bypass (substring → exact hostname match); graceful
  degradation when Docker is missing.
- Honest degradation — checks needing Administrator return `unknown` with a "re-run elevated"
  hint, never a false `fail`.
- Encoding robustness on non-US (cp950) Windows — capture bytes, decode UTF-8 with
  replacement, ASCII-safe diagnostic output.
- Test suite green (**202 passing** as of commit `833919c`), all via injected runners — no real
  scanning in tests. CI workflow at `.github/workflows/ci.yml`.

## In progress

- **Live mode end-to-end verification (gap "G2").** Live `nmap` recon and per-endpoint `nuclei`
  vuln-scan are wired in code but **have not been verified end-to-end on this machine** — that
  needs `make lab-up` (the Docker lab running). The mock demo remains the reliable, full-story
  path; live verification is the current hardening milestone.

## Planned-next

- **L2: drive the kill-chain through phantom-mesh agent loops.** Today Pillar 1 is driven by a
  deterministic Python orchestrator (`scenarios/run_kill_chain.py`); the same tools are exposed
  as MCP servers, so running the red/blue pipeline as phantom-mesh agents is the next milestone.
  Design notes: [docs/L2-INTEGRATION-PLAN.md](docs/L2-INTEGRATION-PLAN.md) (the proposed
  `secops_mcp/` façade in that plan is **not yet built**; the dated checklist companion is
  archived at [docs/_archive/L2-TODO.md](docs/_archive/L2-TODO.md)).
- HTML report from the mock run (timeline visualization for chart consumers).
- Wire the conceptual `dnsrecon` / `subfinder` / `nikto` runners (currently in diagrams only;
  nikto is installed in the lab image but not yet invoked).
- LLM-written exploit prose (the suggester is templated today; `--use-llm` is a stub) with
  CVE grounding against a local NVD record.
- Cross-repo `x-phantom` Rust policy enforcer in phantom-mesh's `mcp_client.rs`.

## Out of scope (by design)

These are permanent boundaries, not future work — see [ETHICS.md](ETHICS.md) and
[docs/DECISIONS.md](docs/DECISIONS.md):

- No runnable exploits — `has_runnable_poc` is always `false`; the suggester emits prose only.
- No external scanning — lab targets are deny-listed everywhere except localhost / the Docker
  overlay; the endpoint tools are read-only and self-only.
- No auto-remediation — every tool advises, none changes your system.
- No customer / internal-network data ingestion. Not a production MDR/pentest product.
