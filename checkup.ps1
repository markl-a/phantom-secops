<#
.SYNOPSIS
  One-click local security check-up for this machine, powered by the secops agent.

.DESCRIPTION
  Runs, in order:
    1. the full unit-test suite (pytest)
    2. each tool directly (host posture + vulnerability scan) — raw results
    3. the secops agent — AI-synthesised, prioritised action list combining both

  Everything is local and read-only. Provider keys are loaded from your User
  environment, falling back to the keys .env file; they are never printed.

.EXAMPLE
  .\checkup.ps1
  .\checkup.ps1 -Path D:\Projects\my-app      # scan a different project for CVEs
  .\checkup.ps1 -SkipTests -SkipAgent         # raw tool output only (no LLM call)
#>
[CmdletBinding()]
param(
    [string]$Path     = "$PSScriptRoot\lab\vuln-demo",
    [string]$KeysFile = "$env:USERPROFILE\Desktop\llm-keys.env",
    [switch]$SkipTests,
    [switch]$SkipAgent
)

$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot

function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

# ── 1. Environment ────────────────────────────────────────────────────────────
$env:PYTHONPATH = $repo
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
            [Environment]::GetEnvironmentVariable("Path", "User")

foreach ($k in @("CEREBRAS_API_KEY", "GROQ_API_KEY", "GEMINI_API_KEY")) {
    $v = [Environment]::GetEnvironmentVariable($k, "User")
    if (-not $v -and (Test-Path $KeysFile)) {
        $m = Select-String -Path $KeysFile -Pattern "^$k=(.+)$" | Select-Object -First 1
        if ($m) { $v = $m.Matches[0].Groups[1].Value }
    }
    if ($v) { Set-Item "env:$k" $v }
}

$trivy = Get-Command trivy -ErrorAction SilentlyContinue
Section "Environment"
Write-Host ("  python : " + (Get-Command python).Source)
Write-Host ("  trivy  : " + $(if ($trivy) { $trivy.Source } else { "NOT FOUND — vuln scan will be skipped by the tool" }))
Write-Host ("  cerebras key: " + $(if ($env:CEREBRAS_API_KEY) { "loaded" } else { "(missing)" }))

# ── 2. Unit tests ─────────────────────────────────────────────────────────────
if (-not $SkipTests) {
    Section "Unit tests (pytest)"
    python -m pytest -q
    if ($LASTEXITCODE -ne 0) { Write-Host "  tests FAILED — aborting" -ForegroundColor Red; exit 1 }
}

# ── 3. Each tool, raw ─────────────────────────────────────────────────────────
Section "Tool output (host posture + vulnerabilities)"
python "$repo\lab\_checkup.py" $Path

# ── 4. Agent — AI-synthesised report ──────────────────────────────────────────
if (-not $SkipAgent) {
    Section "Agent report (AI-prioritised)"
    $prompt = "Check this computer's security posture and scan $Path for " +
              "vulnerabilities. Give me ONE prioritised action list, most urgent " +
              "first, combining both — include exact fix versions for any CVEs."
    $prompt | phantom exec --config "$repo\secops-agent.toml" --agent secops --quiet
}

Write-Host "`n=== check-up complete ===" -ForegroundColor Green
