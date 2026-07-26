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
  [string]$NodeExe = $env:LAWYER_ASSISTANCE_NODE_EXE,
  [string]$NodeModules = $env:LAWYER_ASSISTANCE_NODE_MODULES,
  [switch]$Visible
)

$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$LogDir = Join-Path $Root "data\build\logs"
$LogFile = Join-Path $LogDir "flk_unattended.log"

if ([string]::IsNullOrWhiteSpace($NodeExe)) {
  $nodeCommand = Get-Command node.exe -ErrorAction SilentlyContinue
  if ($null -eq $nodeCommand) {
    $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
  }

  if ($null -ne $nodeCommand) {
    $NodeExe = $nodeCommand.Source
  }
}

if ([string]::IsNullOrWhiteSpace($NodeExe) -or -not (Test-Path -LiteralPath $NodeExe -PathType Leaf)) {
  throw "Node.js executable not found. Install Node.js or pass -NodeExe <path>."
}
$NodeExe = (Resolve-Path -LiteralPath $NodeExe).Path

if ([string]::IsNullOrWhiteSpace($NodeModules)) {
  $nodeModulesCandidates = @(
    (Join-Path (Split-Path $NodeExe -Parent) "node_modules"),
    (Join-Path $Root "node_modules")
  )
  $NodeModules = $nodeModulesCandidates |
    Where-Object { Test-Path -LiteralPath (Join-Path $_ "playwright") -PathType Container } |
    Select-Object -First 1
}

if ([string]::IsNullOrWhiteSpace($NodeModules) -or -not (Test-Path -LiteralPath (Join-Path $NodeModules "playwright") -PathType Container)) {
  throw "A node_modules directory containing Playwright was not found. Pass -NodeModules <path>."
}
$NodeModules = (Resolve-Path -LiteralPath $NodeModules).Path

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
