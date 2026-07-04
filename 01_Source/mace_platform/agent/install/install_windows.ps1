# UnifiedSec MACE Endpoint Agent (UMEA) — Windows installer (Scheduled Task)
# Requires: PowerShell 5.1+ as Administrator, Python 3.11+
[CmdletBinding()]
param(
  [string]$Prefix       = "C:\Program Files\MACE-Agent",
  [string]$IngestUrl    = $env:MACE_INGEST_URL,
  [int]   $IntervalMin  = 30
)
if (-not $IngestUrl) { $IngestUrl = "https://ingest.unifiedsec.local/agent" }
$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Re-launching as Administrator..."
  Start-Process powershell -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$PSCommandPath -Verb RunAs
  exit
}

Write-Host "▶ Installing UMEA to $Prefix"
New-Item -ItemType Directory -Path $Prefix -Force | Out-Null
$Src = Resolve-Path (Join-Path $PSScriptRoot "..")
Copy-Item -Recurse -Force $Src (Join-Path $Prefix "agent_module")

$BatPath = Join-Path $Prefix "mace-agent.cmd"
@"
@echo off
set PYTHONPATH=$Prefix\agent_module\..
python -m mace_platform.agent.cli %*
"@ | Out-File -FilePath $BatPath -Encoding ASCII -Force

# Scheduled task
$Action  = New-ScheduledTaskAction -Execute $BatPath -Argument "post --url $IngestUrl"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Trigger2 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMin)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "UnifiedSec MACE Agent" -Action $Action -Trigger @($Trigger,$Trigger2) -Principal $Principal -Force | Out-Null

Write-Host "▶ First scan..."
& $BatPath scan --summary
Write-Host "✓ Installed. Task: 'UnifiedSec MACE Agent'. Logs: Event Viewer → TaskScheduler."
