> ARCHIVED 2026-06-19 — 內容已併入 docs/phantom-secops.md;此為歷史版本。

# Key engineering decisions

Short decision records for the choices that shaped this project. Each is
`context → decision → why → trade-off`. These are the things worth talking
through in a review or interview.

---

## 1. Don't build engines — wrap them, orchestrate with an agent

**Context.** Building a credible scanner (AV, vuln DB, IDS) from scratch is a
multi-year effort and a worse result than existing OSS.
**Decision.** Wrap mature engines — **Trivy** (CVEs), a **Sigma** matcher over
Windows event logs (IDS), native OS queries (posture) — and put the value in the
**LLM orchestration layer** that correlates and explains across them.
**Why.** The durable differentiation at the security×AI intersection is the
"brain" (triage, correlation, plain-language remediation), not a re-implemented
engine. Models are commoditised; integration + judgment is not.
**Trade-off.** Inherit the engines' updates for free, but depend on them being
installed — real deployment friction, only partly solved by single-binary
runtime delivery.

## 2. Injectable command runner so OS-touching code stays unit-testable

**Context.** Posture/IDS/vuln tools shell out to PowerShell, Trivy, Get-WinEvent
— normally untestable without the real OS.
**Decision.** Every tool takes a `run(args) -> CmdResult` callable; production
uses a real subprocess runner, tests inject canned output.
**Why.** 96 tests run anywhere in <2s with zero real scanning, and the parsing
logic is pinned independent of the host.
**Trade-off.** The thin I/O boundary itself (the real runner) is only
smoke-tested, not unit-tested — an accepted, well-understood gap.

## 3. Low false-positives over coverage

**Context.** More rules/checks = more findings, but a self-use tool dies of
alert fatigue.
**Decision (a).** The IDS first flagged a **signed Microsoft PowerShell module
manifest** as a "download-and-execute cradle" (it mentions a web type and
`Invoke-Expression` in its text). Tightened the rule (exec = `iex` /
`invoke-expression` only) and added a manifest filter → 800 events, 0 noise.
**Decision (b).** Deliberately did **not** wrap a 300+ check CIS baseline
(HardeningKitty) for the personal-use build — most of those checks are
enterprise-policy nitpicks that would bury the handful that matter on a personal
machine.
**Why.** For self-use, a trustworthy short report beats an exhaustive noisy one.
**Trade-off.** Lower raw coverage; the CIS breadth is the right move *later*, if
the project pivots to a compliance product.

## 4. Honest degradation, never a false alarm

**Context.** Some checks (BitLocker, full Defender state) need Administrator;
run unelevated they return nothing useful.
**Decision.** Detect elevation; a check that can't be determined returns
`unknown` (not `fail`) and the report adds a "re-run as Administrator" hint.
BitLocker specifically: only `Off` → `fail`; empty/unelevated → `unknown`.
**Why.** A false "your disk is unencrypted" is worse than an honest "couldn't
check" — it erodes trust in every other finding.
**Trade-off.** The unelevated daily run is less complete; accepted, with a clear
path to a fuller picture.

## 5. Encoding robustness on a non-US Windows

**Context.** On a zh-TW Windows, localized PowerShell error text arrives in
cp950; decoding as the locale codec raised, turning a normal command into a
spurious failure, and naive UTF-8 decoding produced mojibake.
**Decision.** Capture bytes, decode UTF-8 with replacement, and for the
"reason" strings keep only printable ASCII (the diagnostic value — cmdlet name,
path — is ASCII; the localized prose is noise).
**Why.** Correctness shouldn't depend on system locale.
**Trade-off.** Non-ASCII detail in error reasons is dropped; acceptable for a
status field.

## 6. Feed findings to the agent — don't let it re-scan

**Context.** The daily check-up scanned once deterministically *and* the agent
re-scanned via its own tool call. On a large repo the agent's re-scan timed out
at the MCP layer, so the AI report wrongly said "scan unavailable" while the log
showed 864 real findings.
**Decision.** Capture the deterministic findings once and pass them to the agent
with "use this data, do not re-scan."
**Why.** One scan, fast, and the AI report reflects reality.
**Trade-off.** The agent can't independently choose to scan a different target
in that flow — fine for a fixed daily check-up.

## 7. Read-only by design

**Context.** Auto-remediation (apply a patch, change a firewall rule) is where
the real risk and liability live.
**Decision.** Every tool is read-only; the agent suggests and explains, never
changes the system.
**Why.** Keeps the trust bar low enough to actually run daily, and is the honest
scope for an unattended tool.
**Trade-off.** The user does the fixing — but that's the right boundary until
there's a human-in-the-loop approval model.

## 8. Provider reality: pick what actually works, fall back gracefully

**Context.** Free LLM tiers are the real bottleneck — Groq's 8k TPM rejects the
tool-augmented request (413); llama-3.3 loops on tool calls; some keys had no
credits (401/402).
**Decision.** Primary = **Cerebras `gpt-oss-120b`** (fast, generous free tier,
clean non-looping tool calls), with Groq/Gemini fallback, and compact tool
output to stay within per-request budgets. Keys referenced via `api_key_env`
only — never inlined (the self-audit tool flags inlined keys).
**Why.** Reliability of the agent loop is a product property, not an afterthought.
**Trade-off.** Tied to a specific model's availability; mitigated by the
provider fallback chain.

## 9. Separate "proof of capability" from "a tool I use"

**Context.** The project drifted between a phantom-mesh showcase (lab red/blue
demo) and a real endpoint tool that scans the author's actual machine.
**Decision.** Name them as distinct purposes and keep both — the lab demo proves
SOC-concept understanding; the endpoint tool proves real engineering — rather
than letting one quietly distort the other.
**Why.** Conflated purposes cause wasted, re-done work; explicit purposes keep
each design honest.
**Trade-off.** Two stories to maintain instead of one.
