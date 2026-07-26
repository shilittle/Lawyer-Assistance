[CmdletBinding()]
param(
  [ValidateSet("Preflight", "Run", "Cleanup")][string]$Mode = "Preflight",
  [ValidateSet("All", "Authenticode", "Updater")][string]$Check = "All",
  [string]$CodeSigningThumbprint = $env:LAWYER_ASSISTANCE_CODE_SIGNING_THUMBPRINT,
  [string]$UpdaterPrivateKeyPath = "",
  [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ExitCodes = @{
  Success = 0
  UnsupportedPlatform = 10
  RepositoryInvalid = 11
  CertificateMissing = 20
  ThumbprintMissing = 21
  CertificateInvalid = 22
  UpdaterKeyMissing = 30
  UpdaterPasswordMissing = 31
  WorktreeDirty = 40
  SignedBuildFailed = 50
  VerificationFailed = 51
  CleanupFailed = 60
}

function Stop-Stable([string]$ResultCode, [int]$ExitCode, [string]$Message) {
  [Console]::Error.WriteLine("[$ResultCode] $Message")
  exit $ExitCode
}

function Write-Stable([string]$ResultCode, [string]$Message) {
  Write-Output "[$ResultCode] $Message"
}

function Test-IsAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($env:OS -cne "Windows_NT") {
  Stop-Stable "REL-PLATFORM-UNSUPPORTED" $ExitCodes.UnsupportedPlatform "Windows is required."
}

$ProjectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$SignedBuildScript = Join-Path $ProjectRoot "apps\desktop\scripts\build_signed_release.ps1"
$TauriConfigPath = Join-Path $ProjectRoot "apps\desktop\src-tauri\tauri.conf.json"
if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot ".git")) -or
    -not (Test-Path -LiteralPath $SignedBuildScript -PathType Leaf) -or
    -not (Test-Path -LiteralPath $TauriConfigPath -PathType Leaf)) {
  Stop-Stable "REL-REPOSITORY-INVALID" $ExitCodes.RepositoryInvalid "Run this checked-in script from its repository location."
}

if ([string]::IsNullOrWhiteSpace($UpdaterPrivateKeyPath)) {
  $UpdaterPrivateKeyPath = Join-Path $ProjectRoot ".release-secrets\lawyer-assistance-updater.key"
}
$UpdaterPrivateKeyPath = [IO.Path]::GetFullPath($UpdaterPrivateKeyPath)

$isAdministrator = Test-IsAdministrator
Write-Stable "REL-ADMIN-CHECK" ("elevated=" + $isAdministrator.ToString().ToLowerInvariant() + "; elevation is observed but is not by itself a signing prerequisite")

function Get-UsableCodeSigningCertificates {
  return @(Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.HasPrivateKey -and $_.NotBefore -le (Get-Date) -and $_.NotAfter -gt (Get-Date) })
}

function Assert-AuthenticodeCredential {
  $certificates = @(Get-UsableCodeSigningCertificates)
  if ($certificates.Count -eq 0) {
    Stop-Stable "REL-AUTH-CERT-NONE" $ExitCodes.CertificateMissing "No currently valid code-signing certificate with a readable private key exists in CurrentUser/My or LocalMachine/My."
  }
  if ([string]::IsNullOrWhiteSpace($CodeSigningThumbprint)) {
    Stop-Stable "REL-AUTH-THUMBPRINT-REQUIRED" $ExitCodes.ThumbprintMissing "Set LAWYER_ASSISTANCE_CODE_SIGNING_THUMBPRINT to the selected certificate thumbprint."
  }
  $normalized = $CodeSigningThumbprint.Replace(" ", "").ToUpperInvariant()
  if ($normalized -notmatch '^[0-9A-F]{40}$') {
    Stop-Stable "REL-AUTH-THUMBPRINT-INVALID" $ExitCodes.CertificateInvalid "The selected thumbprint is not a 40-character SHA-1 certificate thumbprint."
  }
  $selected = @($certificates | Where-Object { $_.Thumbprint -ceq $normalized })
  if ($selected.Count -ne 1) {
    Stop-Stable "REL-AUTH-CERT-NOT-FOUND" $ExitCodes.CertificateInvalid "The selected current certificate with a readable private key was not found."
  }
  $script:CodeSigningThumbprint = $normalized
  Write-Stable "REL-AUTH-CERT-OK" "A current code-signing certificate and readable private key were found; no thumbprint was printed."
}

function Assert-UpdaterCredential {
  if (-not (Test-Path -LiteralPath $UpdaterPrivateKeyPath -PathType Leaf)) {
    Stop-Stable "REL-UPDATER-KEY-MISSING" $ExitCodes.UpdaterKeyMissing "The updater private-key file is absent."
  }
  $keyItem = Get-Item -LiteralPath $UpdaterPrivateKeyPath
  if ($keyItem.Length -le 0) {
    Stop-Stable "REL-UPDATER-KEY-MISSING" $ExitCodes.UpdaterKeyMissing "The updater private-key file is empty."
  }
  if ([string]::IsNullOrWhiteSpace($env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD)) {
    Stop-Stable "REL-UPDATER-PASSWORD-MISSING" $ExitCodes.UpdaterPasswordMissing "TAURI_SIGNING_PRIVATE_KEY_PASSWORD is absent."
  }
  Write-Stable "REL-UPDATER-CREDENTIAL-OK" "The updater key file and password variable are present; their contents were not read or printed by this preflight."
}

function Assert-CleanWorktree {
  & git -C $ProjectRoot diff --quiet --ignore-submodules --
  if ($LASTEXITCODE -ne 0) {
    Stop-Stable "REL-WORKTREE-DIRTY" $ExitCodes.WorktreeDirty "Tracked unstaged changes exist."
  }
  & git -C $ProjectRoot diff --cached --quiet --ignore-submodules --
  if ($LASTEXITCODE -ne 0) {
    Stop-Stable "REL-WORKTREE-DIRTY" $ExitCodes.WorktreeDirty "Tracked staged changes exist."
  }
  $untracked = @(& git -C $ProjectRoot ls-files --others --exclude-standard)
  if ($LASTEXITCODE -ne 0 -or $untracked.Count -gt 0) {
    Stop-Stable "REL-WORKTREE-DIRTY" $ExitCodes.WorktreeDirty "Untracked files exist."
  }
  Write-Stable "REL-WORKTREE-CLEAN" "The release commit has a clean worktree."
}

function Get-ReleasePaths {
  $config = Get-Content -LiteralPath $TauriConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
  $version = [string]$config.version
  if ($version -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') {
    Stop-Stable "REL-REPOSITORY-INVALID" $ExitCodes.RepositoryInvalid "The Tauri version is invalid."
  }
  $releaseDir = Join-Path $ProjectRoot "target\x86_64-pc-windows-msvc\release"
  return [pscustomobject][ordered]@{
    Version = $version
    Executable = Join-Path $releaseDir "lawyer-assistance.exe"
    Installer = Join-Path $releaseDir "bundle\nsis\Lawyer Assistance_${version}_x64-setup.exe"
    InstallerSignature = Join-Path $releaseDir "bundle\nsis\Lawyer Assistance_${version}_x64-setup.exe.sig"
    Latest = Join-Path $ProjectRoot "dist\latest.json"
    Portable = Join-Path $ProjectRoot "dist\Lawyer-Assistance_${version}_windows-x86_64-portable.zip"
    PortableChecksum = Join-Path $ProjectRoot "dist\Lawyer-Assistance_${version}_windows-x86_64-portable.zip.sha256"
    SigningConfig = Join-Path $ProjectRoot ".release-secrets\tauri.code-signing.conf.json"
    PortableStage = Join-Path $ProjectRoot "dist\Lawyer-Assistance-portable-x86_64"
  }
}

function Remove-ExactReleaseOutputs {
  $paths = Get-ReleasePaths
  try {
    foreach ($path in @($paths.Executable, $paths.Installer, $paths.InstallerSignature, $paths.Latest, $paths.Portable, $paths.PortableChecksum, $paths.SigningConfig)) {
      if (Test-Path -LiteralPath $path -PathType Leaf) {
        Remove-Item -LiteralPath $path -Force
      }
    }
    if (Test-Path -LiteralPath $paths.PortableStage -PathType Container) {
      $resolvedStage = [IO.Path]::GetFullPath($paths.PortableStage)
      $expectedStage = [IO.Path]::GetFullPath((Join-Path $ProjectRoot "dist\Lawyer-Assistance-portable-x86_64"))
      if (-not $resolvedStage.Equals($expectedStage, [StringComparison]::OrdinalIgnoreCase)) {
        Stop-Stable "REL-CLEANUP-FAILED" $ExitCodes.CleanupFailed "The portable staging path did not match the fixed repository path."
      }
      Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
    Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY -ErrorAction SilentlyContinue
    Write-Stable "REL-CLEANUP-OK" "Only fixed generated release outputs and transient signing configuration were removed; source and secret-key files were preserved."
  } catch {
    Stop-Stable "REL-CLEANUP-FAILED" $ExitCodes.CleanupFailed "Cleanup of fixed generated release outputs failed."
  }
}

function Assert-SignedOutputs {
  $paths = Get-ReleasePaths
  foreach ($path in @($paths.Executable, $paths.Installer, $paths.InstallerSignature, $paths.Latest, $paths.Portable, $paths.PortableChecksum)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
      Stop-Stable "REL-VERIFY-ARTIFACT-MISSING" $ExitCodes.VerificationFailed "A required signed-release artifact is missing."
    }
  }
  foreach ($path in @($paths.Executable, $paths.Installer)) {
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
      Stop-Stable "REL-VERIFY-AUTHENTICODE-FAILED" $ExitCodes.VerificationFailed "An executable Authenticode signature is not valid."
    }
  }
  $expectedHash = (Get-FileHash -LiteralPath $paths.Portable -Algorithm SHA256).Hash.ToLowerInvariant()
  $checksumText = (Get-Content -LiteralPath $paths.PortableChecksum -Raw -Encoding UTF8).Trim()
  if ($checksumText -cne "$expectedHash  $([IO.Path]::GetFileName($paths.Portable))") {
    Stop-Stable "REL-VERIFY-CHECKSUM-FAILED" $ExitCodes.VerificationFailed "The portable checksum does not match the archive."
  }
  $latest = Get-Content -LiteralPath $paths.Latest -Raw -Encoding UTF8 | ConvertFrom-Json
  $expectedUrl = "https://github.com/shilittle/Lawyer-Assistance/releases/download/v$($paths.Version)/Lawyer.Assistance_$($paths.Version)_x64-setup.exe"
  if ([string]$latest.version -cne $paths.Version -or
      [string]::IsNullOrWhiteSpace([string]$latest.platforms.'windows-x86_64'.signature) -or
      [string]$latest.platforms.'windows-x86_64'.url -cne $expectedUrl) {
    Stop-Stable "REL-VERIFY-UPDATER-METADATA-FAILED" $ExitCodes.VerificationFailed "latest.json is not bound to the exact version, asset, and updater signature."
  }
  if (Test-Path -LiteralPath $paths.SigningConfig) {
    Remove-Item -LiteralPath $paths.SigningConfig -Force
  }
  Write-Stable "REL-VERIFY-OK" "Authenticode, updater metadata, required artifacts, and portable SHA-256 passed."
}

if ($Mode -ceq "Cleanup") {
  Remove-ExactReleaseOutputs
  exit $ExitCodes.Success
}

if ($Check -in @("All", "Authenticode")) {
  Assert-AuthenticodeCredential
}
if ($Check -in @("All", "Updater")) {
  Assert-UpdaterCredential
}
Write-Stable "REL-PREFLIGHT-OK" "Selected credential checks passed."

if ($Mode -ceq "Preflight") {
  exit $ExitCodes.Success
}
if ($Check -cne "All") {
  Stop-Stable "REL-REPOSITORY-INVALID" $ExitCodes.RepositoryInvalid "Run mode requires -Check All."
}

Assert-CleanWorktree
try {
  & $SignedBuildScript -CodeSigningThumbprint $CodeSigningThumbprint -UpdaterPrivateKeyPath $UpdaterPrivateKeyPath -TimestampUrl $TimestampUrl
  if ($LASTEXITCODE -ne 0) {
    Stop-Stable "REL-SIGNED-BUILD-FAILED" $ExitCodes.SignedBuildFailed "The signed release script returned a nonzero exit code."
  }
} catch {
  Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY -ErrorAction SilentlyContinue
  Stop-Stable "REL-SIGNED-BUILD-FAILED" $ExitCodes.SignedBuildFailed "The signed release script failed; run -Mode Cleanup before retrying."
}

Assert-SignedOutputs
Write-Stable "REL-COMPLETE" "Signed Windows installer, updater metadata/signature, and signed portable package are verified."
exit $ExitCodes.Success
