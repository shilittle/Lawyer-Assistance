param(
  [Parameter(Mandatory = $true)][AllowEmptyString()][string]$CodeSigningThumbprint,
  [string]$UpdaterPrivateKeyPath = "$PSScriptRoot\..\..\..\.release-secrets\lawyer-assistance-updater.key",
  [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "release_filenames.ps1")
. (Join-Path $PSScriptRoot "release_file_ops.ps1")
. (Join-Path $PSScriptRoot "mcp_sidecar_release.ps1")
$ProjectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\.."))
. (Join-Path $ProjectRoot "scripts\release\release_common.ps1")
$exitCodes = Get-LawyerAssistanceReleaseExitCodes

function Assert-CleanGitWorktree([string]$Root, [string]$Message) {
  & git -C $Root diff --quiet --ignore-submodules --
  if ($LASTEXITCODE -ne 0) { throw $Message }
  & git -C $Root diff --cached --quiet --ignore-submodules --
  if ($LASTEXITCODE -ne 0) { throw $Message }
  $untracked = @(& git -C $Root ls-files --others --exclude-standard)
  if ($LASTEXITCODE -ne 0 -or $untracked.Count -gt 0) { throw $Message }
}

function Invoke-LawyerAssistanceFormalVersionGate(
  [string]$Root,
  [AllowEmptyString()][string]$McpBinaryPath = ""
) {
  $arguments = @(
    (Join-Path $Root "scripts\check_release_contract.py"),
    "--root", $Root,
    "--contract", (Join-Path $Root "scripts\release\release-contract-v0.4.0.json"),
    "--mode", "formal"
  )
  if (-not [string]::IsNullOrWhiteSpace($McpBinaryPath)) {
    $arguments += @("--mcp-binary", [IO.Path]::GetFullPath($McpBinaryPath))
  }
  & python @arguments | Out-Host
  if ($LASTEXITCODE -ne 0) {
    if ([string]::IsNullOrWhiteSpace($McpBinaryPath)) {
      throw "The direct signed build requires the exact formal repository version contract"
    }
    throw "The built MCP binary failed the exact formal version contract"
  }
}

function Assert-LawyerAssistanceTimestampedAuthenticode([string]$Path) {
  $resolved = [IO.Path]::GetFullPath($Path)
  if (-not (Test-LawyerAssistanceRfc3161Authenticode `
      -Path $resolved `
      -ExpectedSignerThumbprint $CodeSigningThumbprint `
      -SignToolPath $signtool.FullName)) {
    throw "A valid Authenticode signature and RFC3161 timestamp are required: $resolved"
  }
}

function Install-LawyerAssistanceCreateNewIndependentFile(
  [string]$Source,
  [string]$Destination
) {
  $sourcePath = [IO.Path]::GetFullPath($Source)
  $destinationPath = [IO.Path]::GetFullPath($Destination)
  if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    throw "Release staging source is missing: $sourcePath"
  }
  if ($sourcePath.Equals($destinationPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Release staging source and destination must be distinct"
  }
  if (Test-Path -LiteralPath $destinationPath) {
    throw "Release staging is create-new and refuses an existing path: $destinationPath"
  }

  $sourceStream = $null
  $destinationStream = $null
  try {
    $sourceStream = [IO.File]::Open(
      $sourcePath,
      [IO.FileMode]::Open,
      [IO.FileAccess]::Read,
      [IO.FileShare]::Read
    )
    $destinationStream = [IO.File]::Open(
      $destinationPath,
      [IO.FileMode]::CreateNew,
      [IO.FileAccess]::Write,
      [IO.FileShare]::None
    )
    $sourceStream.CopyTo($destinationStream, 4MB)
    $destinationStream.Flush($true)
  } finally {
    if ($null -ne $destinationStream) { $destinationStream.Dispose() }
    if ($null -ne $sourceStream) { $sourceStream.Dispose() }
  }
  Assert-LawyerAssistanceSingleLinkFile $destinationPath
  $sourceHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
  $destinationHash = (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash
  if ($sourceHash -cne $destinationHash -or
      (Get-Item -LiteralPath $sourcePath).Length -ne (Get-Item -LiteralPath $destinationPath).Length) {
    throw "Release staging did not preserve the exact source bytes: $destinationPath"
  }
}

function Write-LawyerAssistanceCreateNewUtf8File([string]$Path, [string]$Text) {
  $resolved = [IO.Path]::GetFullPath($Path)
  if (Test-Path -LiteralPath $resolved) {
    throw "Release staging is create-new and refuses an existing path: $resolved"
  }
  $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
  $stream = $null
  try {
    $stream = [IO.File]::Open(
      $resolved,
      [IO.FileMode]::CreateNew,
      [IO.FileAccess]::Write,
      [IO.FileShare]::None
    )
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
  } finally {
    if ($null -ne $stream) { $stream.Dispose() }
  }
  Assert-LawyerAssistanceSingleLinkFile $resolved
}

try {
  $UpdaterPrivateKeyPath = [IO.Path]::GetFullPath($UpdaterPrivateKeyPath)
  $directPreflight = Invoke-LawyerAssistanceReleasePreflightCore `
    -ProjectRoot $ProjectRoot `
    -CodeSigningThumbprint $CodeSigningThumbprint `
    -UpdaterPrivateKeyPath $UpdaterPrivateKeyPath `
    -TimestampUrl $TimestampUrl `
    -Adapters (New-LawyerAssistanceProductionReleaseAdapters)
  if ($directPreflight.ResultCode -cne "REL-PREFLIGHT-OK") {
    throw "The direct signed build did not pass the complete production release preflight"
  }
  $CodeSigningThumbprint = $directPreflight.CodeSigningThumbprint
  $formalReleaseFilenames = Get-LawyerAssistanceFormalReleaseFilenames -ProjectRoot $ProjectRoot
  Invoke-LawyerAssistanceFormalVersionGate -Root $ProjectRoot

$configPath = Join-Path $PSScriptRoot "..\src-tauri\tauri.conf.json"
$config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
$Repository = "shilittle/Lawyer-Assistance"
$expectedLatestUrl = "https://github.com/$Repository/releases/latest/download/latest.json"
$runtimeUpdaterPath = Join-Path $ProjectRoot "apps\desktop\src-tauri\src\commands\updater.rs"
$runtimeUpdater = Get-Content -LiteralPath $runtimeUpdaterPath -Raw -Encoding UTF8
if (@($config.plugins.updater.endpoints).Count -ne 1 -or
    [string]$config.plugins.updater.endpoints[0] -ne $expectedLatestUrl -or
    -not $runtimeUpdater.Contains($expectedLatestUrl)) {
  throw "Release repository must match the fixed runtime updater repository $Repository"
}
$version = [string]$config.version
$productName = [string]$config.productName
$releaseFilenames = $formalReleaseFilenames
if ($version -cne $releaseFilenames.Version) {
  throw "The signed build version must be exact $($releaseFilenames.Version)"
}
if ($productName -cne "Lawyer Assistance") {
  throw "The signed release product name must remain Lawyer Assistance"
}
if (([string](Get-Content -LiteralPath (Join-Path $ProjectRoot "apps\desktop\package.json") -Raw | ConvertFrom-Json).version) -ne $version -or
    ([string](Get-Content -LiteralPath (Join-Path $ProjectRoot "package.json") -Raw | ConvertFrom-Json).version) -ne $version) {
  throw "Root, desktop and Tauri versions must match $version"
}
if (-not (Test-Path -LiteralPath $UpdaterPrivateKeyPath -PathType Leaf)) { throw "Updater private key not found" }
if ([string]::IsNullOrWhiteSpace($env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD)) {
  throw "TAURI_SIGNING_PRIVATE_KEY_PASSWORD must be supplied by the release secret store"
}

Assert-CleanGitWorktree $ProjectRoot "Signed releases must be built from a clean Git worktree"
$commit = (& git -C $ProjectRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') { throw "Unable to resolve release commit" }
$sourceDateEpoch = (& git -C $ProjectRoot show -s --format=%ct HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceDateEpoch -notmatch '^\d+$') { throw "Unable to resolve release commit timestamp" }
$distDir = Join-Path $ProjectRoot "dist"
New-Item -ItemType Directory -Path $distDir -Force | Out-Null
$latestPath = Join-Path $distDir "latest.json"
$portableZip = Join-Path $distDir "Lawyer-Assistance_${version}_windows-x86_64-portable.zip"
foreach ($staleArtifact in @($latestPath, $portableZip, "$portableZip.sha256")) {
  if (Test-Path -LiteralPath $staleArtifact -PathType Leaf) {
    Remove-Item -LiteralPath $staleArtifact -Force
  }
}

$certificate = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
  Where-Object { $_.Thumbprint -eq $CodeSigningThumbprint -and $_.HasPrivateKey } |
  Select-Object -First 1
if (-not $certificate) { throw "No code-signing certificate with a private key matches thumbprint $CodeSigningThumbprint" }
if ($certificate.NotAfter -le (Get-Date)) { throw "Code-signing certificate has expired" }

$signingConfigPath = Join-Path $ProjectRoot ".release-secrets\tauri.code-signing.conf.json"
$signingConfig = [ordered]@{
  bundle = [ordered]@{
    externalBin = @("binaries/lawyer-assistance-mcp")
    windows = [ordered]@{
      certificateThumbprint = $CodeSigningThumbprint.ToUpperInvariant()
      digestAlgorithm = "sha256"
      timestampUrl = $TimestampUrl
      tsp = $true
    }
  }
}
[IO.File]::WriteAllText($signingConfigPath, ($signingConfig | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))

$tauri = Join-Path $ProjectRoot "apps\desktop\node_modules\.bin\tauri.cmd"
if (-not (Test-Path -LiteralPath $tauri -PathType Leaf)) { throw "Tauri CLI is not installed" }
$releaseDir = Join-Path $ProjectRoot "target\x86_64-pc-windows-msvc\release"
$nsisDir = Join-Path $releaseDir "bundle\nsis"
$expectedInstaller = Join-Path $nsisDir "${productName}_${version}_x64-setup.exe"
$expectedSignature = "$expectedInstaller.sig"
$expectedExecutable = Join-Path $releaseDir "lawyer-assistance.exe"
$mcpPaths = Get-LawyerAssistanceMcpReleasePaths $ProjectRoot
$expectedMcpExecutable = [string]$mcpPaths.ReleaseBinary
$tauriMcpSidecar = [string]$mcpPaths.TauriSidecar
$frontendKeep = Join-Path $ProjectRoot "apps\desktop\frontend-dist\.gitkeep"
foreach ($stale in @($expectedExecutable, $expectedMcpExecutable, $tauriMcpSidecar, $expectedInstaller, $expectedSignature)) {
  if (Test-Path -LiteralPath $stale -PathType Leaf) { Remove-Item -LiteralPath $stale -Force }
}
$buildStartedAt = (Get-Date).ToUniversalTime()
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Filter signtool.exe -Recurse -ErrorAction Stop |
  Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "signtool.exe was not found" }
$tauriSigningEnvironment = Get-LawyerAssistanceEnvironmentSnapshot @(
  "TAURI_SIGNING_PRIVATE_KEY",
  "TAURI_SIGNING_PRIVATE_KEY_PASSWORD"
)
$env:TAURI_SIGNING_PRIVATE_KEY = Get-Content -LiteralPath $UpdaterPrivateKeyPath -Raw
$previousSourceDateEpoch = $env:SOURCE_DATE_EPOCH
$previousMcpReleaseSha256 = $env:LAWYER_ASSISTANCE_MCP_RELEASE_SHA256
$env:SOURCE_DATE_EPOCH = $sourceDateEpoch
$releaseLocationPushed = $false
try {
  Invoke-LawyerAssistanceFreshMcpReleaseBuild $ProjectRoot
  ConvertTo-LawyerAssistanceIndependentMcpBinary $expectedMcpExecutable
  Invoke-LawyerAssistanceFormalVersionGate -Root $ProjectRoot -McpBinaryPath $expectedMcpExecutable
  & $signtool.FullName sign /sha1 $CodeSigningThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $expectedMcpExecutable | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "MCP Authenticode signing failed" }
  $mcpReleaseSha256 = (Get-FileHash -LiteralPath $expectedMcpExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($mcpReleaseSha256 -notmatch '^[0-9a-f]{64}$') { throw "MCP release trust anchor is invalid" }
  $env:LAWYER_ASSISTANCE_MCP_RELEASE_SHA256 = $mcpReleaseSha256
  Install-LawyerAssistanceMcpTauriSidecar $expectedMcpExecutable $tauriMcpSidecar
  Push-Location (Join-Path $ProjectRoot "apps\desktop")
  $releaseLocationPushed = $true
  & $tauri build --config $signingConfigPath
  if ($LASTEXITCODE -ne 0) { throw "Tauri signed build failed with exit code $LASTEXITCODE" }
} finally {
  if ($releaseLocationPushed) {
    Pop-Location
  }
  Restore-LawyerAssistanceFrontendPlaceholder $frontendKeep
  Restore-LawyerAssistanceEnvironmentSnapshot $tauriSigningEnvironment
  if ($null -eq $previousSourceDateEpoch) {
    Remove-Item Env:SOURCE_DATE_EPOCH -ErrorAction SilentlyContinue
  } else {
    $env:SOURCE_DATE_EPOCH = $previousSourceDateEpoch
  }
  if ($null -eq $previousMcpReleaseSha256) {
    Remove-Item Env:LAWYER_ASSISTANCE_MCP_RELEASE_SHA256 -ErrorAction SilentlyContinue
  } else {
    $env:LAWYER_ASSISTANCE_MCP_RELEASE_SHA256 = $previousMcpReleaseSha256
  }
  Remove-LawyerAssistanceMcpTauriSidecar $tauriMcpSidecar
}

$installer = Get-Item -LiteralPath $expectedInstaller -ErrorAction SilentlyContinue
$appExe = Get-Item -LiteralPath $expectedExecutable -ErrorAction SilentlyContinue
$signature = Get-Item -LiteralPath $expectedSignature -ErrorAction SilentlyContinue
$buildCompletedAt = (Get-Date).ToUniversalTime()
if (-not $appExe -or -not $installer -or -not $signature) {
  throw "Signed executable, installer or updater signature was not generated"
}
if ($installer.Name -cne $releaseFilenames.SignedArtifact) {
  throw "Tauri generated an unexpected signed installer filename: $($installer.Name)"
}
foreach ($artifact in @($appExe, $installer, $signature, (Get-Item -LiteralPath $expectedMcpExecutable -ErrorAction SilentlyContinue))) {
  if (-not $artifact) { throw "Signed MCP release binary was not generated" }
  if ($artifact.LastWriteTimeUtc -lt $buildStartedAt.AddSeconds(-2) -or
      $artifact.LastWriteTimeUtc -gt $buildCompletedAt.AddSeconds(5)) {
    throw "Release output is outside this build invocation: $($artifact.FullName)"
  }
}
$productVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($appExe.FullName).ProductVersion
$normalizedProductVersion = if ($productVersion -match '^(\d+\.\d+\.\d+)\.0$') { $Matches[1] } else { $productVersion }
if ($normalizedProductVersion -ne $version) {
  throw "Executable ProductVersion '$productVersion' does not match $version"
}
$mcpEvidence = Assert-LawyerAssistanceMcpReleaseBinary `
  $expectedMcpExecutable $version ([DateTimeOffset]$buildStartedAt) ([DateTimeOffset]$buildCompletedAt)
if ([string]$mcpEvidence.sha256 -ne $mcpReleaseSha256) {
  throw "Packaged MCP binary differs from the trust anchor compiled into the App"
}
foreach ($artifact in @($appExe, $installer, (Get-Item -LiteralPath $expectedMcpExecutable))) {
  & $signtool.FullName verify /pa /all /v $artifact.FullName | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "Authenticode verification failed: $($artifact.FullName)" }
  Assert-LawyerAssistanceTimestampedAuthenticode $artifact.FullName
}

$portableProvenancePath = Join-Path $ProjectRoot ".release-secrets\portable-build-$([Guid]::NewGuid().ToString('N')).json"
$portableProvenance = [ordered]@{
  formatVersion = 1
  commit = $commit
  sourceDateEpoch = $sourceDateEpoch
  executablePath = $appExe.FullName
  executableSha256 = (Get-FileHash -LiteralPath $appExe.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  mcpBinaryPath = $expectedMcpExecutable
  mcpBinarySha256 = [string]$mcpEvidence.sha256
  mcpQualificationBinding = "compiled-release-sha256+canonical-path-identity+file-identity+sha256+version"
  buildStartedAtUtc = ([DateTimeOffset]$buildStartedAt).ToString("o")
  buildCompletedAtUtc = ([DateTimeOffset]$buildCompletedAt).ToString("o")
  authenticodeVerified = $true
}
[IO.File]::WriteAllText(
  $portableProvenancePath,
  ($portableProvenance | ConvertTo-Json -Depth 3),
  (New-Object Text.UTF8Encoding($false))
)
try {
  & (Join-Path $PSScriptRoot "build_portable_release.ps1") `
    -RequireAuthenticode `
    -ExistingBuildProvenancePath $portableProvenancePath | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "Portable signed release build failed with exit code $LASTEXITCODE" }
} finally {
  Remove-Item -LiteralPath $portableProvenancePath -Force -ErrorAction SilentlyContinue
}
$downloadUrl = "https://github.com/$Repository/releases/download/v$version/$($releaseFilenames.GitHubAsset)"
& (Join-Path $PSScriptRoot "build_latest_json.ps1") `
  -Version $version `
  -DownloadUrl $downloadUrl `
  -UpdaterSignature ((Get-Content -LiteralPath $signature.FullName -Raw).Trim()) `
  -ArtifactPath $installer.FullName `
  -UpdaterPublicKeyPath (Join-Path $ProjectRoot "apps\desktop\src-tauri\updater-public.key") `
  -OutputPath $latestPath | Out-Host

$latest = Get-Content -LiteralPath $latestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$detachedUpdaterSignature = (Get-Content -LiteralPath $signature.FullName -Raw -Encoding UTF8).Trim()
if ([string]$latest.platforms.'windows-x86_64'.signature -cne $detachedUpdaterSignature) {
  throw "latest.json must contain the exact detached updater signature"
}
$decodedUpdaterSignature = [Text.Encoding]::UTF8.GetString(
  [Convert]::FromBase64String($detachedUpdaterSignature)
).Trim()
$trustedComment = @($decodedUpdaterSignature -split "`r?`n")[2]
if (-not $trustedComment.EndsWith("`tfile:$($releaseFilenames.SignedArtifact)", [StringComparison]::Ordinal)) {
  throw "The updater signature trusted comment must retain the Tauri local-space installer filename"
}

$stagingDirectory = [IO.Path]::GetFullPath($releaseFilenames.StagingDirectory)
if (Test-Path -LiteralPath $stagingDirectory) {
  throw "The fixed App release staging directory already exists; run the fixed release cleanup before rebuilding"
}
$stagingParent = Split-Path -Parent $stagingDirectory
New-Item -ItemType Directory -Path $stagingParent -Force | Out-Null
New-Item -ItemType Directory -Path $stagingDirectory -ErrorAction Stop | Out-Null

$stagedInstaller = Join-Path $stagingDirectory $releaseFilenames.AppAssets[0]
$stagedInstallerChecksum = Join-Path $stagingDirectory $releaseFilenames.AppAssets[1]
$stagedSignature = Join-Path $stagingDirectory $releaseFilenames.AppAssets[2]
$stagedLatest = Join-Path $stagingDirectory $releaseFilenames.AppAssets[3]
$stagedPortable = Join-Path $stagingDirectory $releaseFilenames.AppAssets[4]
$stagedPortableChecksum = Join-Path $stagingDirectory $releaseFilenames.AppAssets[5]

Install-LawyerAssistanceCreateNewIndependentFile $installer.FullName $stagedInstaller
$stagedInstallerHash = (Get-FileHash -LiteralPath $stagedInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
Write-LawyerAssistanceCreateNewUtf8File `
  $stagedInstallerChecksum `
  "$stagedInstallerHash  $($releaseFilenames.AppAssets[0])`n"
Install-LawyerAssistanceCreateNewIndependentFile $signature.FullName $stagedSignature
Install-LawyerAssistanceCreateNewIndependentFile $latestPath $stagedLatest
Install-LawyerAssistanceCreateNewIndependentFile $portableZip $stagedPortable
Install-LawyerAssistanceCreateNewIndependentFile "$portableZip.sha256" $stagedPortableChecksum

# build_latest_json.ps1 has already verified the detached signature against the
# local-space Tauri installer. The two exact-byte comparisons below transfer
# that proof to the independently copied dot-normalized GitHub asset without
# changing the trusted comment's local-space filename.
if ((Get-FileHash -LiteralPath $installer.FullName -Algorithm SHA256).Hash -cne
    (Get-FileHash -LiteralPath $stagedInstaller -Algorithm SHA256).Hash) {
  throw "The dot-normalized installer must be an exact independent copy of the signed Tauri installer bytes"
}
if ([IO.File]::ReadAllBytes($signature.FullName).Length -ne [IO.File]::ReadAllBytes($stagedSignature).Length -or
    (Get-FileHash -LiteralPath $signature.FullName -Algorithm SHA256).Hash -cne
      (Get-FileHash -LiteralPath $stagedSignature -Algorithm SHA256).Hash) {
  throw "The staged updater signature must be an exact copy of the Tauri signature"
}
$stagedLatestValue = Get-Content -LiteralPath $stagedLatest -Raw -Encoding UTF8 | ConvertFrom-Json
if ([string]$stagedLatestValue.platforms.'windows-x86_64'.signature -cne
    (Get-Content -LiteralPath $stagedSignature -Raw -Encoding UTF8).Trim()) {
  throw "The staged latest.json and detached updater signature differ"
}
$stagedItems = @(Get-ChildItem -LiteralPath $stagingDirectory -Force)
$actualStagedNames = [string[]]@($stagedItems | ForEach-Object { $_.Name } | Sort-Object -CaseSensitive)
$expectedStagedNames = [string[]]@($releaseFilenames.LocalAppAssets | Sort-Object -CaseSensitive)
if ($stagedItems.Count -ne 6 -or
    @($stagedItems | Where-Object { -not $_.PSIsContainer }).Count -ne 6 -or
    $actualStagedNames.Count -ne 6 -or
    $expectedStagedNames.Count -ne 6) {
  throw "The local App release staging directory must contain exactly six files"
}
for ($index = 0; $index -lt $expectedStagedNames.Count; $index++) {
  if ($actualStagedNames[$index] -cne $expectedStagedNames[$index]) {
    throw "The local App release staging allowlist does not match the frozen contract"
  }
}
Write-Output $installer.FullName
Write-Output $signature.FullName
Write-Output $latestPath
Write-Output $stagingDirectory
} catch {
  $failure = Resolve-LawyerAssistanceSignedBuildFailure $_
  [Console]::Error.WriteLine("[$($failure.ResultCode)] $($failure.Message)")
  exit $failure.ExitCode
}
exit $exitCodes.Success
