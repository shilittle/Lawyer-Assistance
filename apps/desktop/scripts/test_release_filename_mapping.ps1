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

$ProjectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\.."))
$formalFilenames = Get-LawyerAssistanceFormalReleaseFilenames -ProjectRoot $ProjectRoot
if ($formalFilenames.Version -cne "0.4.0" -or
    $formalFilenames.SignedArtifact -cne "Lawyer Assistance_0.4.0_x64-setup.exe" -or
    $formalFilenames.GitHubAsset -cne "Lawyer.Assistance_0.4.0_x64-setup.exe" -or
    $formalFilenames.AppAssets.Count -ne 12 -or
    $formalFilenames.LocalAppAssets.Count -ne 6 -or
    $formalFilenames.AppAssets[0] -cne $formalFilenames.GitHubAsset -or
    $formalFilenames.AppAssets[11] -cne "lawyer-assistance-mcp-v0.4.0-aarch64-apple-darwin.tar.gz.sha256") {
  throw "The frozen formal App asset filename mapping changed unexpectedly"
}
$expectedFormalAssets = @(
  "Lawyer.Assistance_0.4.0_x64-setup.exe",
  "Lawyer.Assistance_0.4.0_x64-setup.exe.sha256",
  "Lawyer.Assistance_0.4.0_x64-setup.exe.sig",
  "latest.json",
  "Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip",
  "Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip.sha256",
  "lawyer-assistance-mcp-v0.4.0-x86_64-pc-windows-msvc.zip",
  "lawyer-assistance-mcp-v0.4.0-x86_64-pc-windows-msvc.zip.sha256",
  "lawyer-assistance-mcp-v0.4.0-x86_64-unknown-linux-gnu.tar.gz",
  "lawyer-assistance-mcp-v0.4.0-x86_64-unknown-linux-gnu.tar.gz.sha256",
  "lawyer-assistance-mcp-v0.4.0-aarch64-apple-darwin.tar.gz",
  "lawyer-assistance-mcp-v0.4.0-aarch64-apple-darwin.tar.gz.sha256"
)
for ($index = 0; $index -lt $expectedFormalAssets.Count; $index++) {
  if ($formalFilenames.AppAssets[$index] -cne $expectedFormalAssets[$index]) {
    throw "The frozen formal App asset order changed at index $index"
  }
}
if ([IO.Path]::GetFullPath($formalFilenames.StagingDirectory) -cne
    [IO.Path]::GetFullPath((Join-Path $ProjectRoot "dist\release-v0.4.0\app"))) {
  throw "The fixed local App release staging directory changed unexpectedly"
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

$signedBuildSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot "build_signed_release.ps1") -Raw -Encoding UTF8
foreach ($requiredSignedBuildFragment in @(
  "Invoke-LawyerAssistanceFormalVersionGate -Root `$ProjectRoot",
  "Invoke-LawyerAssistanceReleasePreflightCore",
  "New-LawyerAssistanceProductionReleaseAdapters",
  '$CodeSigningThumbprint = $directPreflight.CodeSigningThumbprint',
  "Resolve-LawyerAssistanceSignedBuildFailure",
  'exit $failure.ExitCode',
  "-McpBinaryPath `$expectedMcpExecutable",
  "Assert-LawyerAssistanceTimestampedAuthenticode",
  "Test-LawyerAssistanceRfc3161Authenticode",
  "tsp = `$true",
  "StagingDirectory",
  "Install-LawyerAssistanceCreateNewIndependentFile",
  "FileMode]::CreateNew",
  "latest.json and detached updater signature differ",
  "exact independent copy of the signed Tauri installer bytes",
  "must retain the Tauri local-space installer filename",
  "must contain exactly six files"
)) {
  if (-not $signedBuildSource.Contains($requiredSignedBuildFragment)) {
    throw "Signed release assembly contract is missing: $requiredSignedBuildFragment"
  }
}
$signedBuildTokens = $null
$signedBuildErrors = $null
$signedBuildAst = [Management.Automation.Language.Parser]::ParseFile(
  (Join-Path $PSScriptRoot "build_signed_release.ps1"),
  [ref]$signedBuildTokens,
  [ref]$signedBuildErrors
)
if ($signedBuildErrors.Count -gt 0) {
  throw "Signed build AST could not be inspected: $($signedBuildErrors -join '; ')"
}
$signedBuildParameterNames = @($signedBuildAst.ParamBlock.Parameters | ForEach-Object {
  $_.Name.VariablePath.UserPath
})
foreach ($forbiddenParameter in @("Adapters", "Bypass", "SkipPreflight")) {
  if ($signedBuildParameterNames -contains $forbiddenParameter) {
    throw "Signed build exposed a forbidden bypass seam: $forbiddenParameter"
  }
}
$thumbprintParameter = @($signedBuildAst.ParamBlock.Parameters | Where-Object {
  $_.Name.VariablePath.UserPath -ceq "CodeSigningThumbprint"
})
if ($thumbprintParameter.Count -ne 1 -or
    $thumbprintParameter[0].Extent.Text -match 'ValidatePattern') {
  throw "Signed build must delegate thumbprint normalization to the full production preflight"
}
$preflightCommands = @($signedBuildAst.FindAll({
  param($node)
  $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -ceq "Invoke-LawyerAssistanceReleasePreflightCore"
}, $true))
if ($preflightCommands.Count -ne 1 -or
    -not $preflightCommands[0].Extent.Text.Contains("New-LawyerAssistanceProductionReleaseAdapters") -or
    -not $signedBuildSource.Contains('$CodeSigningThumbprint = $directPreflight.CodeSigningThumbprint')) {
  throw "Signed build does not perform exactly one full production preflight before using its normalized thumbprint"
}
$wrapperSource = Get-Content -LiteralPath (Join-Path $ProjectRoot "scripts\release\release_preflight.ps1") -Raw -Encoding UTF8
if ($wrapperSource -notmatch '(?s)if \(\$Mode -ceq "Preflight"\).*Invoke-LawyerAssistanceReleasePreflightCore' -or
    $wrapperSource -notmatch '(?s)\$signedBuildScript.*build_signed_release\.ps1.*& \$powerShell' -or
    $wrapperSource -notmatch 'Resolve-LawyerAssistanceSignedBuildExitCode') {
  throw "Release wrapper does not preserve the nonrecursive preflight/build exit-code contract"
}
$wrapperTokens = $null
$wrapperErrors = $null
$wrapperAst = [Management.Automation.Language.Parser]::ParseFile(
  (Join-Path $ProjectRoot "scripts\release\release_preflight.ps1"),
  [ref]$wrapperTokens,
  [ref]$wrapperErrors
)
$wrapperPreflightCommands = @($wrapperAst.FindAll({
  param($node)
  $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -ceq "Invoke-LawyerAssistanceReleasePreflightCore"
}, $true))
if ($wrapperErrors.Count -gt 0 -or $wrapperPreflightCommands.Count -ne 1) {
  throw "Release wrapper must delegate Run to signed build without a second preflight or recursion"
}

$approvedMcpHarnessPath = Join-Path $ProjectRoot "scripts\test-standalone-approved-mcp.ps1"
$approvedMcpHarnessSource = Get-Content -LiteralPath $approvedMcpHarnessPath -Raw -Encoding UTF8
$approvedMcpHarnessTokens = $null
$approvedMcpHarnessErrors = $null
$approvedMcpHarnessAst = [Management.Automation.Language.Parser]::ParseFile(
  $approvedMcpHarnessPath,
  [ref]$approvedMcpHarnessTokens,
  [ref]$approvedMcpHarnessErrors
)
if ($approvedMcpHarnessErrors.Count -gt 0) {
  throw "Approved MCP E2E harness AST could not be inspected: $($approvedMcpHarnessErrors -join '; ')"
}
$qualificationTestName = "approved_mcp::standalone_binary_tests::explicit_binary_qualification_canary_is_fail_closed"
$fullSessionTestName = "approved_mcp::standalone_binary_tests::app_approval_to_real_stdio_and_http_binary_is_fail_closed"
foreach ($requiredHarnessFragment in @(
  "`$qualificationTestName = '$qualificationTestName'",
  "`$fullSessionTestName = '$fullSessionTestName'",
  '$testName = if ($usingExplicitBinary) { $qualificationTestName } else { $fullSessionTestName }',
  'Assert-McpBinaryUnchanged -Candidate $binaryPath -ExpectedSha256 $binarySha256',
  'release-external-stdio-http-qualification-canary',
  'MCP_STANDALONE_APPROVED_E2E_TEST='
)) {
  if (-not $approvedMcpHarnessSource.Contains($requiredHarnessFragment)) {
    throw "Approved MCP explicit-binary E2E contract is missing: $requiredHarnessFragment"
  }
}
$testNameAssignments = @($approvedMcpHarnessAst.FindAll({
  param($node)
  $node -is [Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left.Extent.Text -ceq '$testName'
}, $true))
$testLoops = @($approvedMcpHarnessAst.FindAll({
  param($node)
  $node -is [Management.Automation.Language.ForEachStatementAst] -and
    $node.Variable.VariablePath.UserPath -ceq 'testName'
}, $true))
if ($testNameAssignments.Count -ne 1 -or $testLoops.Count -ne 0) {
  throw "Approved MCP E2E harness must select exactly one namespace-compatible test"
}
$selectionText = $testNameAssignments[0].Extent.Text
if ($selectionText.IndexOf('$qualificationTestName', [StringComparison]::Ordinal) -lt 0 -or
    $selectionText.IndexOf('$fullSessionTestName', [StringComparison]::Ordinal) -lt 0) {
  throw "Approved MCP E2E selection must isolate release qualification from the feature-bound full session"
}
$harnessCargoSteps = @($approvedMcpHarnessAst.FindAll({
  param($node)
  $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -ceq 'Invoke-CargoStep' -and
    $node.Extent.Text.Contains('MCP_E2E_TEST_FAILED')
}, $true))
$harnessHashChecks = @($approvedMcpHarnessAst.FindAll({
  param($node)
  $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -ceq 'Assert-McpBinaryUnchanged'
}, $true))
if ($harnessCargoSteps.Count -ne 1 -or $harnessHashChecks.Count -ne 2) {
  throw "The selected approved MCP exact test must run once between before/after binary identity checks"
}
$cargoOffset = $harnessCargoSteps[0].Extent.StartOffset
$hashOffsets = @($harnessHashChecks | ForEach-Object { $_.Extent.StartOffset } | Sort-Object)
if ($hashOffsets[0] -ge $cargoOffset -or $hashOffsets[1] -le $cargoOffset) {
  throw "The selected approved MCP exact test must remain between its two binary identity checks"
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
