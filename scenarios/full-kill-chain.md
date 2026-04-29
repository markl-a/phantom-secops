# Scenario: Full kill chain vs. parallel defense

This scenario runs the entire red-blue pipeline against OWASP Juice Shop in the
isolated lab. Both teams' phantom-mesh agents run concurrently. At the end, the
two reports are placed side-by-side and the timeline is annotated.

## Goal

Demonstrate end-to-end multi-agent security automation with measurable MTTD
(mean time to detect) — a metric defenders care about.

## Targets

- `juice-shop` (OWASP Juice Shop) at `juice-shop:3000` inside the `secops-lab`
  docker network.

## Pre-flight

```bash
docker compose up -d
docker compose ps      # confirm juice-shop and dvwa are healthy
docker exec secops-attacker bash -c "command -v nmap && command -v nikto"
```

If any check fails, see `lab/README.md` for troubleshooting.

## Execution plan

The orchestrator launches two parallel agent pipelines.

### Red pipeline (sequential)

1. `red-recon` → produces `reports/recon-juice-shop-<ts>.json`
2. `red-vuln-scan` → reads recon JSON, produces `reports/vuln-juice-shop-<ts>.json`
3. `red-exploit-suggest` → produces `reports/exploit-suggestions-<ts>.md`
4. `red-pentest-report` → produces `reports/pentest-report-<ts>.md`

### Blue pipeline (continuous + sequential terminator)

Continuous (started at t=0, runs throughout):

- `blue-log-anomaly` → tails Juice Shop access logs, emits to
  `reports/lab-logs/alerts.jsonl` as suspicious patterns appear.
- `blue-alert-triage` → consumes alerts.jsonl, writes triage-queue.jsonl.
- `blue-threat-correlate` → consumes triage queue, writes kill-chains.jsonl.

Terminator (run after red pipeline completes, ~10s grace period):

- `blue-incident-report` → produces `reports/incident-report-<ts>.md`.

## Expected timeline (rough, single laptop)

| Time | Red                                   | Blue                                  |
|------|----------------------------------------|----------------------------------------|
| t+0  | recon starts, nmap -sV against target  | log-anomaly listening                  |
| t+10s| recon writes JSON                      | first scanner alerts (port scan noise) |
| t+15s| vuln-scan starts, nuclei templates run | triage flags scanner activity          |
| t+45s| vuln-scan writes findings              | triage promotes to P2                  |
| t+50s| exploit-suggest writes prose           | correlate links recon→vuln-scan actor  |
| t+60s| pentest-report finalized               | incident-report ready                  |

So the attacker reaches the "pentest report" milestone in ~60s, and the
defender reaches the "incident report" milestone in roughly the same window.
This is the measurement we want to surface: detection lag is small when the
defender has multi-agent log analysis running concurrently — not because the
defender is fast, but because the analysis pipeline is parallelized.

## Side-by-side comparison

After both reports finish, run:

```bash
phantom-secops compare \
  reports/pentest-report-<ts>.md \
  reports/incident-report-<ts>.md
```

This produces `reports/comparison-<ts>.md` with the timeline aligned and the
attacker's findings cross-referenced to the defender's IoCs.

## Cleanup

```bash
docker compose down -v
```
