param(
  [int]$IntervalSeconds = 300,
  [int]$MinDelayMs = 2500,
  [int]$MaxDelayMs = 6000,
  [int]$BatchSize = 800,
  [int]$BatchCooldownMs = 1200000,
  [int]$WafCooldownMs = 7200000,
  [int]$MaxWafRetries = 24,
  [int]$NetworkCooldownMs = 900000,
  [int]$MaxNetworkRetries = 12,
  [int]$CrashCooldownMs = 1800000
)

$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$StateDir = Join-Path $Root "data\build\state"
$LogDir = Join-Path $Root "data\build\logs"
$LogFile = Join-Path $LogDir "flk_watchdog.log"
$RunScript = Join-Path $Root "data\build\run_flk_unattended.ps1"
$RunPidFile = Join-Path $StateDir "flk_unattended.pid"

New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Write-WatchLog {
  param([string]$Message)
  "$(Get-Date -Format o) $Message" | Tee-Object -FilePath $LogFile -Append
}

function Test-RunProcess {
  if (-not (Test-Path $RunPidFile)) {
    return $false
  }
  try {
    $runPid = [int](Get-Content $RunPidFile)
  } catch {
    return $false
  }
  $process = Get-Process -Id $runPid -ErrorAction SilentlyContinue
  return $null -ne $process
}

function Start-RunProcess {
  $proc = Start-Process -FilePath "powershell" -ArgumentList @(
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    $RunScript,
    "-MinDelayMs",
    "$MinDelayMs",
    "-MaxDelayMs",
    "$MaxDelayMs",
    "-BatchSize",
    "$BatchSize",
    "-BatchCooldownMs",
    "$BatchCooldownMs",
    "-WafCooldownMs",
    "$WafCooldownMs",
    "-MaxWafRetries",
    "$MaxWafRetries",
    "-NetworkCooldownMs",
    "$NetworkCooldownMs",
    "-MaxNetworkRetries",
    "$MaxNetworkRetries",
    "-CrashCooldownMs",
    "$CrashCooldownMs"
  ) -WindowStyle Hidden -PassThru
  $proc.Id | Set-Content -Encoding ASCII $RunPidFile
  Write-WatchLog "started flk unattended pid=$($proc.Id)"
}

Write-WatchLog "watchdog started intervalSeconds=$IntervalSeconds"

while ($true) {
  try {
    if (-not (Test-RunProcess)) {
      Write-WatchLog "flk unattended not running; starting"
      Start-RunProcess
    }
  } catch {
    Write-WatchLog "watchdog error: $($_.Exception.Message)"
  }
  Start-Sleep -Seconds $IntervalSeconds
}
