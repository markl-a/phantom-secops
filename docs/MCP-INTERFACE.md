# MCP Interface — phantom-secops

> Frozen contract. The MCP server, phantom-mesh adapter, Claude Code subagent, and the Python reference orchestrator all depend on the names, schemas, and safety gates documented here. Changes to anything below are breaking and require updating all four call sites in lockstep.
>
> Surface: **11 tools, 2 resource schemes**.

## Server identity

| Field | Value |
|---|---|
| MCP server name | `phantom-secops` |
| Tools / Resources | 11 / 2 |
| Transport | `stdio` (primary) and `http` (optional, for remote agents) |
| Protocol version | MCP 2025-06-18 |
| Required runtime | Python ≥3.11, Docker (only for `active_in_lab` and `lifecycle` tools) |

## Naming convention

`{verb}_{object}[_{qualifier}]`, snake_case, all lowercase. The qualifier is mandatory when the verb has multiple safety profiles (e.g. `lab_up_confirm`).

The 11 tools below are grouped by **safety class**, not by red/blue. Mixing red/blue in the same server is intentional — agents shouldn't have to know which "side" a tool belongs to; they just call it.

---

## Safety classes

| Class | Means | Tools require user/agent confirmation? |
|---|---|---|
| `read_only` | No network egress, no filesystem writes outside `reports/runs/<ts>/` | No |
| `active_in_lab` | Probes a target inside the `secops-lab` docker network | No (gated by lab-network check) |
| `lifecycle` | Brings up/tears down the docker lab | **Yes** — must pass `confirm: true` |

Every `active_in_lab` tool **must** call `safety.assert_lab_target(target)` before doing anything. The check is centralised in `mcp/safety.py` and validates against the hard-coded list `{juice-shop, dvwa, dvwa-db, metasploitable, attacker}`. Any other value returns an `ErrorOutput` with `code="not_a_lab_target"`.

---

## Tool catalogue

### 1. `recon_host` — `active_in_lab`

Scans an in-lab host with nmap (top 1000 ports + service version). Wraps `tools/nmap_runner.py`.

```ts
input: {
  target: "juice-shop" | "dvwa" | "dvwa-db" | "metasploitable" | "attacker",
  ports?: "top-1000" | string,   // default "top-1000"; explicit list e.g. "80,443,3306"
  scan_type?: string,             // default "-sV"
}

output: {
  target: string,
  open_ports: Array<{
    port: number,
    protocol: string,        // "tcp" | "udp"
    service: string,         // "http", "mysql", ...
    version: string | null,  // "Apache 2.4.41" or null
  }>,
  scan_type: "nmap",
}

// or, on error:
output: { error: string, target?: string, lab_services?: string[] }
```

**Side effects**: shells `docker exec` into `secops-attacker`. No filesystem writes.
**Latency budget**: 120 s timeout enforced inside the wrapper.

---

### 2. `vuln_scan_web` — `active_in_lab`

Runs nuclei against an in-lab HTTP target. Wraps `tools/nuclei_runner.py`.

```ts
input: {
  target_url: string,         // must contain a lab service hostname
  severity?: string,          // CSV; default "low,medium,high,critical"
  timeout_s?: number,         // default 90
}

output: {
  target: string,
  findings: Array<{
    id: string | null,         // nuclei template-id
    cve: string | null,
    severity: "info" | "low" | "medium" | "high" | "critical" | null,
    title: string | null,
    evidence: string | null,   // matched-at URL
    tool: "nuclei",
    raw: string,               // truncated raw JSON, ≤400 chars
  }>,
}
```

**Side effects**: shells `docker exec` into `secops-attacker`; on first run installs nuclei via `go install`.
**Latency budget**: `timeout_s + 30` s.

---

### 3. `scan_logs_for_anomalies` — `read_only`

Pattern-matches access logs to produce raw alerts. Logic from `_blue_log_anomaly` in `run_kill_chain.py:174`.

```ts
input: {
  source?: "lab_logs" | "mock",   // default "lab_logs"; "mock" reads lab/mocks/attack-log.txt
  log_path?: string,              // override; absolute path inside repo
}

output: {
  alerts: Array<{
    ts: string,                   // ISO8601 UTC
    source_ip: string,            // IPv4 or "unknown"
    asset: string,                // "juice-shop" | "dvwa" | ...
    category: "traversal" | "sqli" | "xss" | "admin_path" | "scanner",
    evidence: string,             // raw log line, ≤200 chars
    severity_hint: "low" | "medium" | "high",
  }>,
  source: string,                  // resolved log file path
}
```

**Side effects**: none. URL-decodes each line before pattern-matching (the existing implementation does this).

---

### 4. `triage_alerts` — `read_only`

Groups raw alerts by `(source_ip, category)` and assigns priority. Logic from `_blue_alert_triage`.

```ts
input: {
  alerts: Array<Alert>,           // shape from scan_logs_for_anomalies.alerts[]
}

output: {
  triaged: Array<{
    ts: string,
    priority: "P1" | "P2" | "P3",
    asset: string,
    summary: string,              // "<category> pattern from <ip>"
    count: number,
    evidence: string[],           // up to 3 sample lines
  }>,
}
```

**Promotion rules** (frozen):
- `severity_hint=high` → P2 by default; P1 once `count ≥ 2`
- `severity_hint=medium` → promote P3 → P2
- `severity_hint=low` → stays P3

---

### 5. `correlate_threats` — `read_only`

Joins triaged alerts into per-actor narratives with ATT&CK phase tags. Logic from `_blue_threat_correlate`.

```ts
input: {
  triaged: Array<TriagedGroup>,   // shape from triage_alerts.triaged[]
}

output: {
  actors: Array<{
    actor: string,                  // source IP
    first_seen: string,             // ISO8601
    last_seen: string,
    phases_observed: string[],      // e.g. ["TA0001", "TA0043"]
    alert_summaries: string[],
    narrative: string,              // human-readable English summary
    confidence: "low" | "medium" | "high",
  }>,
}
```

**Phase mapping** (frozen):
- `scanner` → `TA0043` (Reconnaissance)
- `sqli`, `xss`, `traversal` → `TA0001` (Initial Access)
- `admin_path` → `TA0007` (Discovery)

---

### 6. `suggest_exploit_prose` — `read_only`

Generates **text-only** exploit explanations from vuln-scan findings. **Never returns runnable payloads.** This is the safety-critical tool — its name carries `_prose` to make the constraint visible to every caller.

```ts
input: {
  findings: Array<Finding>,        // shape from vuln_scan_web.findings[]
  use_llm?: boolean,                // default false; when true, calls LLMProvider for prose
}

output: {
  markdown: string,                  // full markdown document, "# Exploit Suggestions\n..."
  has_runnable_poc: false,           // INVARIANT: always false; checked by tests
}
```

**Hard constraints** (enforced by `tests/test_no_runnable_poc.py`):
- Output must not contain shell commands, curl invocations, payload strings, or template strings that would execute if pasted.
- The string `has_runnable_poc: false` is a load-bearing assertion; do not change.

---

### 7. `compose_pentest_report` — `read_only`

Renders the red-team-side markdown report.

```ts
input: {
  recon: ReconOutput,              // from recon_host
  vuln: VulnScanOutput,            // from vuln_scan_web
  exploit_suggestions_md: string,  // from suggest_exploit_prose.markdown
  timeline: Array<[string, string]>, // [[t_seconds, label], ...]
}

output: {
  markdown: string,
  byte_size: number,
}
```

---

### 8. `compose_incident_report` — `read_only`

Renders the blue-team-side markdown report.

```ts
input: {
  triaged: Array<TriagedGroup>,
  actors: Array<Actor>,            // from correlate_threats
  timeline: Array<[string, string]>,
}

output: {
  markdown: string,
  byte_size: number,
  mttd_seconds: number,            // first red event → first triaged alert
}
```

---

### 9. `lab_status` — `read_only`

Reports docker lab health. Wraps `docker compose ps` in JSON form.

```ts
input: {}   // no parameters

output: {
  network_present: boolean,        // is "secops-lab" network up?
  services: Array<{
    name: "juice-shop" | "dvwa" | "dvwa-db" | "attacker" | "log-collector",
    state: "running" | "exited" | "absent",
    health: "healthy" | "unhealthy" | "starting" | "none",
  }>,
}
```

**Side effects**: reads docker state; does not modify.

---

### 10. `lab_up` — `lifecycle`

Brings up the isolated docker lab.

```ts
input:  { confirm: true }
output: { ok: boolean, log: string }   // log = last 2 KB of docker compose output
```

Idempotent. Calling without `confirm: true` returns `{ error: "lifecycle_action_requires_confirmation" }` and does nothing.

### 11. `lab_down` — `lifecycle`

Tears down the docker lab. Removes containers and volumes; **never** touches the `reports/runs/` directory on the host.

```ts
input:  { confirm: true }
output: { ok: boolean, log: string }
```

Same confirmation requirement as `lab_up`. Both lifecycle tools are intended for interactive callers (Claude Code, phantom-mesh dispatch with a human-authored prompt) — CI lanes should use `make lab-up` / `make lab-down` directly rather than going through MCP.

---

## Resources

Resources are read-only artifacts the agent can fetch by URI without invoking a tool.

### `phantom-secops://runs/{run_id}/{filename}`

```
run_id      = ISO timestamp dir name, e.g. "2026-05-05-1430"
filename    ∈ { recon.json, vuln-scan.json, alerts.jsonl, triage-queue.jsonl,
                kill-chains.jsonl, exploit-suggestions.md,
                pentest-report.md, incident-report.md }
```

`run_id="latest"` resolves to the newest run dir at fetch time.

### `phantom-secops://mocks/{name}`

```
name ∈ { recon-juice-shop.json, vuln-scan-juice-shop.json, attack-log.txt }
```

---

## Error model

Every tool returns either its success shape or a flat error envelope:

```ts
{
  error: string,                   // short code, snake_case
  message?: string,                // human-readable detail
  context?: object,                // tool-specific extras
}
```

Frozen error codes:

| Code | Meaning |
|---|---|
| `not_a_lab_target` | Target is not in the lab service whitelist |
| `lab_network_down` | `secops-lab` docker network is not up |
| `tool_timeout` | Underlying CLI exceeded its budget |
| `tool_nonzero_exit` | Underlying CLI returned non-zero |
| `parse_failed` | Output could not be parsed (e.g. malformed nmap XML) |
| `lifecycle_action_requires_confirmation` | Lifecycle tool called without `confirm: true` |
| `bad_input` | Input failed schema validation |

---

## Versioning

This document is version `1.0.0`. The MCP server reports the same version in its handshake. Adapters may pin to a major version.

- **Patch** bumps: docs-only, schema-additive (new optional input fields, new optional output fields).
- **Minor** bumps: new tools, new error codes, new resources.
- **Major** bumps: any rename, removal, type change, or safety-class change.

Major bumps require updating: `mcp/server.py`, `mcp/schemas.py`, `agents/red/*.toml`, `agents/blue/*.toml`, `.claude/agents/secops-runner.md`, `scenarios/run_kill_chain.py`, and this file — in the same PR.
