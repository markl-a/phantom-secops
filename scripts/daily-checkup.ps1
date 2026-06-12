<#
.SYNOPSIS
  Unattended daily wrapper around checkup.ps1 — writes a dated log and prunes old ones.
  Invoked by the "PhantomSecops-DailyCheckup" scheduled task.

.PARAMETER ScanPath
  Project/directory scanned for dependency CVEs. Defaults to your main project;
  edit this default (or the scheduled task argument) to point elsewhere.
#>
[CmdletBinding()]
param(
    [string]$ScanPath = "D:\Projects\phantom-mesh-private"
)

$ErrorActionPreference = "Stop"
$repo   = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $repo "reports\checkup"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$log   = Join-Path $logDir "checkup_$stamp.log"

# Run the full check-up (skip unit tests — those are for development), merging
# every stream and writing UTF-8 (Windows PowerShell's *>> defaults to UTF-16).
& (Join-Path $repo "checkup.ps1") -SkipTests -Path $ScanPath *>&1 |
    Out-File -FilePath $log -Encoding utf8

# Keep 30 days of logs.
Get-ChildItem $logDir -Filter "checkup_*.log" -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
    Remove-Item -Force -ErrorAction SilentlyContinue
