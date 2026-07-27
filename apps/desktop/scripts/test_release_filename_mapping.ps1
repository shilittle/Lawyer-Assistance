$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "release_filenames.ps1")

$filenames = Get-LawyerAssistanceReleaseFilenames -Version "0.2.1"
if ($filenames.SignedArtifact -cne "Lawyer Assistance_0.2.1_x64-setup.exe") {
  throw "The signed installer filename mapping changed unexpectedly"
}
if ($filenames.GitHubAsset -cne "Lawyer.Assistance_0.2.1_x64-setup.exe") {
  throw "The GitHub asset filename mapping changed unexpectedly"
}
if ($filenames.SignedArtifact -ceq $filenames.GitHubAsset) {
  throw "The signed and GitHub filenames must remain distinct"
}

foreach ($validVersion in @("0.0.0", "1.2.3-alpha.1", "1.2.3+build.01", "1.2.3-rc.1+build.7")) {
  Get-LawyerAssistanceReleaseFilenames -Version $validVersion | Out-Null
}

foreach ($invalidVersion in @(
  "",
  "v0.2.1",
  "0.2",
  "0.2.1/other",
  "01.2.3",
  "1.02.3",
  "1.2.03",
  "1.2.3-a..b",
  "1.2.3-01"
)) {
  $rejected = $false
  try {
    Get-LawyerAssistanceReleaseFilenames -Version $invalidVersion | Out-Null
  } catch {
    $rejected = $true
  }
  if (-not $rejected) {
    throw "Invalid release version was accepted: '$invalidVersion'"
  }
}

$ProjectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\.."))
foreach ($releaseScript in @(
  "build_portable_release.ps1",
  "build_unsigned_installer_release.ps1",
  "build_signed_release.ps1"
)) {
  $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot $releaseScript) -Raw -Encoding UTF8
  foreach ($required in @(
    "lawyer-assistance-mcp",
    "Invoke-LawyerAssistanceFreshMcpReleaseBuild",
    "Assert-LawyerAssistanceMcpReleaseBinary",
    "LAWYER_ASSISTANCE_MCP_RELEASE_SHA256",
    "compiled-release-sha256",
    "mcpEvidence",
    "mcpBinary"
  )) {
    if (-not $source.Contains($required)) {
      throw "$releaseScript does not enforce MCP sibling release evidence: $required"
    }
  }
}
$mcpReleaseSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot "mcp_sidecar_release.ps1") -Raw -Encoding UTF8
foreach ($requiredFreshBuildFragment in @(
  "cargo clean --release --locked --offline --target",
  "--package legal-mcp",
  "cargo build --release --locked --offline --target",
  "--bin lawyer-assistance-mcp"
)) {
  if (-not $mcpReleaseSource.Contains($requiredFreshBuildFragment)) {
    throw "MCP release build does not enforce fresh package output: $requiredFreshBuildFragment"
  }
}
$desktopBuildSource = Get-Content -LiteralPath (Join-Path $ProjectRoot "apps\desktop\src-tauri\build.rs") -Raw -Encoding UTF8
if (-not $desktopBuildSource.Contains("cargo:rerun-if-env-changed=LAWYER_ASSISTANCE_MCP_RELEASE_SHA256")) {
  throw "Desktop build does not bind rebuilds to the MCP release trust anchor"
}
foreach ($installerScript in @("build_unsigned_installer_release.ps1", "build_signed_release.ps1")) {
  $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot $installerScript) -Raw -Encoding UTF8
  if (-not $source.Contains('externalBin = @("binaries/lawyer-assistance-mcp")')) {
    throw "$installerScript does not configure the fixed Tauri externalBin sibling"
  }
}

$parseFailures = @()
foreach ($script in @(
  "release_filenames.ps1",
  "build_latest_json.ps1",
  "release_file_ops.ps1",
  "mcp_sidecar_release.ps1",
  "build_portable_release.ps1",
  "build_unsigned_installer_release.ps1",
  "build_signed_release.ps1",
  "test_release_filename_mapping.ps1"
)) {
  $tokens = $null
  $errors = $null
  [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot $script),
    [ref]$tokens,
    [ref]$errors
  ) | Out-Null
  if ($errors.Count -gt 0) {
    $parseFailures += "$script`: $($errors -join '; ')"
  }
}
if ($parseFailures.Count -gt 0) {
  throw "Release PowerShell AST validation failed: $($parseFailures -join ' | ')"
}

Write-Output "release filename mapping and PowerShell AST validation passed"
