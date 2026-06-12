# Interview talk track

Notes for talking about phantom-secops in a security-engineering interview.
Trend Micro, CrowdStrike, Palo Alto, etc.

## Elevator pitch (30 seconds)

> "I built a security-ops project on my own multi-agent runtime that does two
> things. One: a red/blue **SOC concept demo** — attack and defense agents run
> in parallel against an isolated lab and I quantify **mean-time-to-detect**,
> the metric SOCs care about. Two: a real **local-first endpoint self-check** I
> actually run daily — read-only host posture, dependency CVEs via Trivy, and
> host intrusion detection with a small Sigma engine, all unified by an LLM
> agent into one prioritised, plain-language fix list, with the data never
> leaving the machine. The thesis across both is *don't build the engine, build
> the brain* — wrap mature tools, put the value in the agent layer."

## The endpoint tool, concretely (if they want the "real" one)

> "It's a Python toolchain — each tool is a pure module with an injectable
> command runner, so the OS-touching logic is unit-tested with canned output
> (96 tests, no real scanning in CI). Each is wrapped as an MCP server tagged
> with an `x-phantom` capability label (classification / capabilities /
> read_only), which is the hook for per-agent policy enforcement. One command,
> `checkup.ps1`, runs them all and an agent synthesises the report; a scheduled
> task runs it daily. A real run found 864 fixable CVEs in one of my projects
> and an AV gap, and the agent gave exact upgrade versions."

## Likely questions

### "Is this legal?"

Short answer: yes, with a caveat. All targets are intentionally vulnerable
applications maintained for security education (OWASP Juice Shop, DVWA,
Metasploitable). All tools are widely deployed defensive research tools
(Nmap, Nuclei, Nikto). The lab runs on an isolated docker network with no
host port exposure by default. The exploit-suggester agent only produces
prose, not runnable code. See ETHICS.md for full scoping.

### "What's the value over a single LLM agent that does it all?"

Three things. **Context window** — splitting phases keeps each agent's prompt
focused. **Cost/latency tuning** — smaller model for prose-heavy steps, larger
for tool-heavy steps. **Operational mapping** — real SOCs and red teams already
split work across roles, so the architecture mirrors how the work is done.

### "How does this differ from MSF / Cobalt Strike / Burp Suite Pro?"

This isn't an offensive tool. It's an **orchestration layer** that makes
existing tools cooperate via natural-language agents. The LLM doesn't write
exploits — it routes between standard scanners, parses their output, and
composes reports. Think "GitHub Actions for security workflows, but agents
write the steps."

### "Why phantom-mesh and not LangChain / AutoGen / CrewAI?"

Honest answer: I built phantom-mesh because the existing frameworks have
deployment friction I didn't want — Python runtime requirements, single-host
designs, opinionated about LLM providers. Phantom-mesh ships as a single Rust
binary, runs cross-platform (Mac, Linux, Windows, Android, iOS), supports
provider fallback out of the box, and uses TOML configs that are diff-friendly.
For a security context, the single-binary delivery is genuinely useful —
analysts can ship the runtime to an air-gapped lab without dragging in a
Python ecosystem.

### "What's the false-positive rate of the alert-triage agent?"

I haven't run it long enough to give a calibrated number. On the demo
scenarios I have, it correctly promotes scanner activity to P2 within 15s of
recon starting and doesn't escalate to P1 until vuln-scan starts probing
endpoints. I'd want to validate this against a real alert dataset before
claiming a real number.

### "How does this scale?"

The agents are stateless between handoffs (state lives on the file system).
You could run multiple lab instances on a single host, or shard across a
cluster — phantom-mesh already supports distributed execution via its mesh
feature. I haven't tested that for security workloads yet.

### "Walk me through the kill-chain demo."

Run `python scenarios/run_kill_chain.py --mock` (or `make demo-mock`) and walk
the printed timeline + the two reports in `reports/runs/<ts>/`. The timing in
mock mode is **simulated** (clearly labelled) so the comparison is meaningful;
the milestones:

1. t+0s: red recon starts, blue log-anomaly starts (two concurrent clocks).
2. t+8s: blue surfaces its first scanner alerts.
3. **t+15s: blue triage groups the activity — first detection (MTTD = 15s).**
4. t+50s: red exploit-suggest finishes — the attacker reaches actionable impact.
5. End: the incident report names the actor + ATT&CK phases + P1/P2/P3 queue;
   the pentest report lists findings + prose-only mitigations.

The headline: **the defender detected the activity 35s before the attacker
reached impact (a defender win)**. The metric is honest in both directions — if
detection lands after impact, the report says so (attacker win). That "did we
detect before impact, and by how much" question is exactly what a SOC measures.

### "What would you build next?"

In priority order:

1. Real alert dataset replay. Use a public CTF dataset (CTF-d archives, MISP
   feeds) to validate the triage agent's calibration.
2. Containment actions. Right now the blue side observes and reports. Next
   step is enabling guarded response actions (block IP, isolate container)
   with human-in-the-loop approval.
3. Multi-host correlation. Run the same demo against a 3-host lab where the
   actor pivots between hosts, see if threat-correlate stitches the chain.

### "How do you keep the LLM from hallucinating CVE numbers?"

Honest answer: **today the exploit-suggester doesn't use an LLM at all** — it's
templated prose keyed off the scan findings (`_run_exploit_suggest` /
`_exploit_prose`), so it structurally can't invent a CVE: it only emits text for
findings the scanner actually produced. The `--use-llm` flag is a stub, not
wired. *If* I add LLM-written prose, the grounding plan is the same constraint —
only reference CVEs present in the scan output — plus a lookup against a local
NVD record so any CVE the model names is verified or flagged "unverified". I'd
rather say "it's templated" than claim an NVD mirror I haven't built.

### "Tell me about a tricky bug or a judgment call." (they always ask this)

Pick one from [DECISIONS.md](DECISIONS.md); the strongest are:

- **The false positive.** "My IDS flagged a *signed Microsoft module manifest*
  as a download-and-execute cradle — it mentions a web type and Invoke-Expression
  in its text. I tightened the rule and added a manifest filter, and went from 5
  false alerts to 0 on 800 events. It's a good example of why low-false-positive
  beats high-coverage for a tool people actually run."
- **The honest `unknown`.** "BitLocker needs admin; run unelevated it returned
  empty. I made it report `unknown` with a re-run-as-admin hint instead of a
  false `fail` — a wrong 'your disk is unencrypted' erodes trust in every other
  finding."
- **The double-scan.** "The daily check-up scanned once deterministically and
  the agent re-scanned via its own tool call; on a big repo the agent's scan
  timed out and it reported 'no findings' while the log showed 864. I fixed it
  by feeding the captured findings to the agent instead of letting it re-scan."

### "Why not just use Wazuh / osquery / Vanta?"

Different niche. Wazuh/osquery are server + agent-fleet platforms for SOC teams;
Vanta is cloud compliance SaaS. This is the opposite end: **local-first,
read-only, single-operator, data-never-leaves-the-machine**, with an AI layer
that unifies several engines' output. It's not competing with them — it fills
the "one person wants to check their own machine without standing up infra" gap.

## Don't say

- "This finds 0-days" (it doesn't, and the claim is a red flag).
- "This is better than [commercial product]" (it isn't — it's a research demo).
- "I built this in a weekend" (the framework took months — say that).
- Any claim about real-world adversaries (you have no telemetry to back it).
