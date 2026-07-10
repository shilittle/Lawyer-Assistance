param(
  [int]$MinDelayMs = 2500,
  [int]$MaxDelayMs = 6000,
  [int]$BatchSize = 800,
  [int]$BatchCooldownMs = 1200000,
  [int]$WafCooldownMs = 5400000,
  [int]$MaxWafRetries = 16,
  [int]$NetworkCooldownMs = 900000,
  [int]$MaxNetworkRetries = 12,
  [int]$CrashCooldownMs = 1800000,
  [int]$Limit = 0,
  [switch]$Visible
)

$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$LogDir = Join-Path $Root "data\build\logs"
$LogFile = Join-Path $LogDir "flk_unattended.log"
$NodeExe = "<NODE_EXE>"
$NodeModules = "<NODE_MODULES>"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Set-Location $Root
$env:NODE_PATH = $NodeModules

function Write-RunLog {
  param([string]$Message)
  $line = "$(Get-Date -Format o) $Message"
  $line | Tee-Object -FilePath $LogFile -Append
}

function Get-CacheCounts {
  $details = (Get-ChildItem "data\build\cache\flk\details" -Filter *.json -ErrorAction SilentlyContinue | Measure-Object).Count
  $documents = @(Get-ChildItem "data\build\cache\flk\documents" -File -ErrorAction SilentlyContinue)
  $docx = @($documents | Where-Object { $_.Extension -eq ".docx" }).Count
  $doc = @($documents | Where-Object { $_.Extension -eq ".doc" }).Count
  $pdf = @($documents | Where-Object { $_.Extension -eq ".pdf" }).Count
  $missing = (Get-ChildItem "data\build\cache\flk\missing_text" -Filter *.json -ErrorAction SilentlyContinue | Measure-Object).Count
  [pscustomobject]@{
    details = $details
    textFiles = $docx + $doc + $pdf
    docx = $docx
    doc = $doc
    pdf = $pdf
    missingText = $missing
    remaining = 29689 - $details
  } | ConvertTo-Json -Compress
}

Write-RunLog "FLK unattended hydrate started. headless=$(!$Visible) minDelayMs=$MinDelayMs maxDelayMs=$MaxDelayMs batchSize=$BatchSize"

while ($true) {
  Write-RunLog "cache $(Get-CacheCounts)"

  $args = @(
    "data\build\browser_hydrate_flk.cjs",
    "--min-delay-ms", "$MinDelayMs",
    "--max-delay-ms", "$MaxDelayMs",
    "--batch-size", "$BatchSize",
    "--batch-cooldown-ms", "$BatchCooldownMs",
    "--waf-cooldown-ms", "$WafCooldownMs",
    "--max-waf-retries", "$MaxWafRetries",
    "--network-cooldown-ms", "$NetworkCooldownMs",
    "--max-network-retries", "$MaxNetworkRetries",
    "--missing-retry-ms", "604800000"
  )
  if (-not $Visible) {
    $args += "--headless"
  }
  if ($Limit -gt 0) {
    $args += @("--limit", "$Limit")
  }

  & $NodeExe @args 2>&1 | Tee-Object -FilePath $LogFile -Append
  $exitCode = $LASTEXITCODE
  Write-RunLog "hydrate process exited code=$exitCode cache $(Get-CacheCounts)"

  if ($exitCode -eq 0) {
    Write-RunLog "FLK unattended hydrate complete."
    break
  }

  Write-RunLog "cooling down after process exit for ${CrashCooldownMs}ms"
  Start-Sleep -Milliseconds $CrashCooldownMs
}
