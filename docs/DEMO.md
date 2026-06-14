# Demo walkthrough

Two short demos, both runnable on a laptop. Use these as the script when showing the
project. Each step lists **what to run** and **what to point out**.

---

## Demo 1 — Red/blue SOC pipeline + MTTD (≈2 min, no docker, no keys)

```bash
make demo-mock        # or: python scenarios/run_kill_chain.py --target juice-shop --mock
```

What to point out:

1. **It runs both pipelines concurrently.** Red (recon → vuln-scan → exploit-suggest →
   pentest-report) and blue (log-anomaly → triage → correlate → incident-report) advance on
   two clocks that both start at t=0.
2. **The MTTD line is the headline:**
   ```
   → MTTD = 15s  (simulated timing — mock mode)
     defender triaged the activity at t+15s; attacker reached impact at t+50s
     → detected 35s before impact
   ```
   This is the metric real SOCs optimise — *did we detect before impact, and by how much?*
   The timing is honestly labelled **simulated** in mock mode (live mode uses real wall-clock).
3. **Open the artifacts** in `reports/runs/<ts>/`:
   - `incident-report.md` — the interleaved timeline (red and blue events sorted by time),
     the reconstructed actor with ATT&CK phases, the triaged P1/P2/P3 queue, and the MTTD
     breakdown.
   - `pentest-report.md` — recon, findings by severity, prose-only exploit suggestions.

Talking point: *"The same deterministic orchestrator drives both sides; the value
is the side-by-side timing, which is exactly how a SOC measures itself."*

---

## Demo 2 — Local endpoint self-check + AI triage (Windows)

```powershell
.\checkup.ps1                 # runs every tool + an LLM agent that unifies the findings
```

What to point out:

1. **Host posture** — firewall / disk-encryption / AV / UAC / ports, with honest `unknown`
   for checks that need admin (and a "re-run elevated" hint) rather than false `fail`.
2. **Vulnerabilities** — Trivy, prioritised fixable-first. On a real project this surfaced
   **864 fixable CVEs** with exact upgrade versions.
3. **Intrusion detection** — a small Sigma engine over the PowerShell event log. To show a
   live true positive, run a benign command containing an attacker signature, then re-run:
   ```powershell
   powershell -NoProfile -Command "Write-Output 'demo: Invoke-Mimikatz sekurlsa::logonpasswords'"
   .\checkup.ps1 -SkipTests
   ```
   The IDS flags it **critical** (mimikatz indicators). Requires Script Block Logging enabled.
4. **The AI report** — one prioritised, plain-language action list combining all of the above,
   data never leaving the machine.

Talking point: *"This is the 'real tool' half — it wraps mature engines (Trivy, a Sigma
matcher, native queries) and the agent turns raw findings into something I act on. I run it
daily via a scheduled task."*

---

## If asked "show me the engineering"

- `python -m pytest -q` — the suite is green and runs in seconds with **no real scanning**
  (every OS-touching tool uses an injectable command runner).
- [docs/DECISIONS.md](DECISIONS.md) — the judgment calls (false-positive tuning, honest
  degradation, feed-don't-rescan, read-only by design).
- [docs/ARCHITECTURE.md](ARCHITECTURE.md) — the engine + agent layering and the `x-phantom`
  capability model.
