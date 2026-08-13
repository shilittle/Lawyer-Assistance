[CmdletBinding()]
param(
  [ValidateSet("Preflight", "Run", "Cleanup")][string]$Mode = "Preflight",
  [ValidateSet("All")][string]$Check = "All",
  [AllowEmptyString()][string]$CodeSigningThumbprint = $env:LAWYER_ASSISTANCE_CODE_SIGNING_THUMBPRINT,
  [AllowEmptyString()][string]$UpdaterPrivateKeyPath = "",
  [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "release_common.ps1")

$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$exitCodes = Get-LawyerAssistanceReleaseExitCodes
if ([string]::IsNullOrWhiteSpace($UpdaterPrivateKeyPath)) {
  $UpdaterPrivateKeyPath = Join-Path $projectRoot ".release-secrets\lawyer-assistance-updater.key"
}
$UpdaterPrivateKeyPath = [IO.Path]::GetFullPath($UpdaterPrivateKeyPath)

function Write-ReleaseResult {
  param([string]$ResultCode, [string]$Message)
  Write-Output "[$ResultCode] $Message"
}

try {
  if ($Mode -ceq "Cleanup") {
    $cleanup = Remove-LawyerAssistanceFixedReleaseOutputs -ProjectRoot $projectRoot
    Write-ReleaseResult $cleanup.ResultCode "Only the fixed generated release outputs were removed; source files, release credentials, and unrelated files were preserved."
    exit $cleanup.ExitCode
  }

  if ($Mode -ceq "Preflight") {
    $adapters = New-LawyerAssistanceProductionReleaseAdapters
    $preflight = Invoke-LawyerAssistanceReleasePreflightCore `
      -ProjectRoot $projectRoot `
      -CodeSigningThumbprint $CodeSigningThumbprint `
      -UpdaterPrivateKeyPath $UpdaterPrivateKeyPath `
      -TimestampUrl $TimestampUrl `
      -Adapters $adapters
    Write-ReleaseResult $preflight.ResultCode "The exact 0.4.0 main commit, immutable tags, final legal/notices, CI closure, and signing credentials passed."
    exit $exitCodes.Success
  }

  $signedBuildScript = Join-Path $projectRoot "apps\desktop\scripts\build_signed_release.ps1"
  $powerShell = Join-Path $PSHOME "powershell.exe"
  if (-not (Test-Path -LiteralPath $powerShell -PathType Leaf)) {
    $powerShell = (Get-Process -Id $PID).Path
  }
  & $powerShell -NoProfile -ExecutionPolicy Bypass -File $signedBuildScript `
    -CodeSigningThumbprint $CodeSigningThumbprint `
    -UpdaterPrivateKeyPath $UpdaterPrivateKeyPath `
    -TimestampUrl $TimestampUrl
  $signedBuildExitCode = Resolve-LawyerAssistanceSignedBuildExitCode $LASTEXITCODE
  if ($signedBuildExitCode -ne $exitCodes.Success) {
    if ($signedBuildExitCode -eq $exitCodes.SignedBuildFailed -and $LASTEXITCODE -ne $exitCodes.SignedBuildFailed) {
      [Console]::Error.WriteLine("[REL-SIGNED-BUILD-FAILED] The signed release build failed unexpectedly.")
    }
    exit $signedBuildExitCode
  }
  Write-ReleaseResult "REL-SIGNED-BUILD-OK" "The signed release build completed; downstream allowlist and server-readback gates remain mandatory."
  exit $exitCodes.Success
} catch {
  $failure = Get-LawyerAssistanceReleaseFailure $_
  if ($null -eq $failure) {
    if ($Mode -ceq "Run") {
      [Console]::Error.WriteLine("[REL-SIGNED-BUILD-FAILED] The signed release build failed unexpectedly.")
      exit $exitCodes.SignedBuildFailed
    }
    [Console]::Error.WriteLine("[REL-UNEXPECTED-FAILURE] The release preflight failed unexpectedly.")
    exit $exitCodes.RepositoryInvalid
  }
  [Console]::Error.WriteLine("[$($failure.ResultCode)] $($failure.Message)")
  exit $failure.ExitCode
}
