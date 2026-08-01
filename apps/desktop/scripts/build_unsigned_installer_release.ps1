param(
  [string]$OutputDir = "$PSScriptRoot\..\..\..\dist"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "release_filenames.ps1")
. (Join-Path $PSScriptRoot "release_file_ops.ps1")
. (Join-Path $PSScriptRoot "mcp_sidecar_release.ps1")

function Invoke-Checked([string]$Description, [scriptblock]$Command) {
  & $Command
  if ($LASTEXITCODE -ne 0) { throw "$Description failed with exit code $LASTEXITCODE" }
}

function Assert-CleanGitWorktree([string]$Root, [string]$Message) {
  & git -C $Root diff --quiet --ignore-submodules --
  if ($LASTEXITCODE -ne 0) { throw $Message }
  & git -C $Root diff --cached --quiet --ignore-submodules --
  if ($LASTEXITCODE -ne 0) { throw $Message }
  $untracked = @(& git -C $Root ls-files --others --exclude-standard)
  if ($LASTEXITCODE -ne 0 -or $untracked.Count -gt 0) { throw $Message }
}

function Get-NormalizedProductVersion([string]$ExecutablePath) {
  $productVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($ExecutablePath).ProductVersion
  if ($productVersion -match '^(\d+\.\d+\.\d+)\.0$') { return $Matches[1] }
  return $productVersion
}

$ProjectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\.."))
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
$expectedOutputDir = [IO.Path]::GetFullPath((Join-Path $ProjectRoot "dist"))
if (-not $OutputDir.Equals($expectedOutputDir, [StringComparison]::OrdinalIgnoreCase)) {
  throw "OutputDir must be the workspace distribution directory: $expectedOutputDir"
}

$configPath = Join-Path $ProjectRoot "apps\desktop\src-tauri\tauri.conf.json"
$desktopPackagePath = Join-Path $ProjectRoot "apps\desktop\package.json"
$rootPackagePath = Join-Path $ProjectRoot "package.json"
$distributionManifestPath = Join-Path $ProjectRoot "data\generated\legal_core_distribution_manifest.json"
$legalResource = Join-Path $ProjectRoot "apps\desktop\src-tauri\resources\legal_core.sqlite"
$config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
$desktopPackage = Get-Content -LiteralPath $desktopPackagePath -Raw -Encoding UTF8 | ConvertFrom-Json
$rootPackage = Get-Content -LiteralPath $rootPackagePath -Raw -Encoding UTF8 | ConvertFrom-Json
$distribution = Get-Content -LiteralPath $distributionManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$version = [string]$config.version
$productName = [string]$config.productName
if ($version -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') { throw "Invalid application version: $version" }
if ([string]$desktopPackage.version -ne $version -or [string]$rootPackage.version -ne $version) {
  throw "Root, desktop and Tauri versions must match $version"
}
if ($productName -cne "Lawyer Assistance") { throw "Product name must remain Lawyer Assistance" }
if ($config.bundle.createUpdaterArtifacts -ne $true) {
  throw "The checked-in signed-release policy must keep createUpdaterArtifacts enabled"
}
if (-not [string]::IsNullOrWhiteSpace($env:TAURI_SIGNING_PRIVATE_KEY) -or
    -not [string]::IsNullOrWhiteSpace($env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD)) {
  throw "Unsigned installer builds refuse updater signing secrets in the process environment"
}

Assert-CleanGitWorktree $ProjectRoot "Unsigned installers must be built from a clean Git worktree"
$commit = (& git -C $ProjectRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') { throw "Unable to resolve release commit" }
$sourceDateEpoch = (& git -C $ProjectRoot show -s --format=%ct HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceDateEpoch -notmatch '^\d+$') { throw "Unable to resolve release commit timestamp" }
if (-not [string]::IsNullOrWhiteSpace($env:SOURCE_DATE_EPOCH) -and $env:SOURCE_DATE_EPOCH -ne $sourceDateEpoch) {
  throw "SOURCE_DATE_EPOCH must equal the current release commit timestamp $sourceDateEpoch"
}

Invoke-Checked "Formal legal resource verification" {
  python (Join-Path $PSScriptRoot "verify_legal_resource.py") --resource $legalResource --manifest $distributionManifestPath
}
$legalSize = (Get-Item -LiteralPath $legalResource).Length
$legalHash = (Get-FileHash -LiteralPath $legalResource -Algorithm SHA256).Hash.ToLowerInvariant()
if ($legalSize -ne [long]$distribution.size_bytes -or
    $legalHash -ne ([string]$distribution.sha256).ToLowerInvariant()) {
  throw "Verified legal database does not match its distribution manifest"
}
Invoke-Checked "Third-party notice verification" {
  python (Join-Path $ProjectRoot "scripts\generate_third_party_notices.py") --check
}

$tauri = Join-Path $ProjectRoot "apps\desktop\node_modules\.bin\tauri.cmd"
if (-not (Test-Path -LiteralPath $tauri -PathType Leaf)) { throw "Tauri CLI is not installed" }
$releaseDir = Join-Path $ProjectRoot "target\x86_64-pc-windows-msvc\release"
$releaseNames = Get-LawyerAssistanceReleaseFilenames -Version $version
$expectedExecutable = Join-Path $releaseDir "lawyer-assistance.exe"
$mcpPaths = Get-LawyerAssistanceMcpReleasePaths $ProjectRoot
$expectedMcpExecutable = [string]$mcpPaths.ReleaseBinary
$tauriMcpSidecar = [string]$mcpPaths.TauriSidecar
$expectedInstaller = Join-Path $releaseDir "bundle\nsis\$($releaseNames.SignedArtifact)"
$unsignedName = "Lawyer.Assistance_${version}_windows-x86_64-unsigned-setup.exe"
$outputInstaller = Join-Path $OutputDir $unsignedName
$outputChecksum = "$outputInstaller.sha256"
$outputManifest = "$outputInstaller.manifest.json"
$frontendKeep = Join-Path $ProjectRoot "apps\desktop\frontend-dist\.gitkeep"

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
foreach ($stale in @($expectedExecutable, $expectedMcpExecutable, $tauriMcpSidecar, $expectedInstaller, "$expectedInstaller.sig", $outputInstaller, $outputChecksum, $outputManifest)) {
  if (Test-Path -LiteralPath $stale -PathType Leaf) { Remove-Item -LiteralPath $stale -Force }
}

$temporaryRoot = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) "lawyer-assistance-unsigned-$([Guid]::NewGuid().ToString('N'))"))
$tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $temporaryRoot.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Temporary release directory escaped the operating-system temporary directory"
}
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
$overridePath = Join-Path $temporaryRoot "unsigned-tauri.conf.json"
$override = [ordered]@{
  bundle = [ordered]@{
    createUpdaterArtifacts = $false
    targets = @("nsis")
    externalBin = @("binaries/lawyer-assistance-mcp")
  }
}
[IO.File]::WriteAllText($overridePath, ($override | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))

$previousSourceDateEpoch = $env:SOURCE_DATE_EPOCH
$previousCargoNetOffline = $env:CARGO_NET_OFFLINE
$previousMcpReleaseSha256 = $env:LAWYER_ASSISTANCE_MCP_RELEASE_SHA256
$env:SOURCE_DATE_EPOCH = $sourceDateEpoch
$env:CARGO_NET_OFFLINE = "true"
$buildStartedAt = [DateTimeOffset]::UtcNow
try {
  Invoke-LawyerAssistanceFreshMcpReleaseBuild $ProjectRoot
  ConvertTo-LawyerAssistanceIndependentMcpBinary $expectedMcpExecutable
  $mcpReleaseSha256 = (Get-FileHash -LiteralPath $expectedMcpExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($mcpReleaseSha256 -notmatch '^[0-9a-f]{64}$') { throw "MCP release trust anchor is invalid" }
  $env:LAWYER_ASSISTANCE_MCP_RELEASE_SHA256 = $mcpReleaseSha256
  Install-LawyerAssistanceMcpTauriSidecar $expectedMcpExecutable $tauriMcpSidecar
  Push-Location (Join-Path $ProjectRoot "apps\desktop")
  try {
    Invoke-Checked "Offline unsigned Tauri installer build" {
      & $tauri build --config $overridePath
    }
  } finally {
    Pop-Location
  }
} finally {
  Restore-LawyerAssistanceFrontendPlaceholder $frontendKeep
  if ($null -eq $previousSourceDateEpoch) {
    Remove-Item Env:SOURCE_DATE_EPOCH -ErrorAction SilentlyContinue
  } else {
    $env:SOURCE_DATE_EPOCH = $previousSourceDateEpoch
  }
  if ($null -eq $previousCargoNetOffline) {
    Remove-Item Env:CARGO_NET_OFFLINE -ErrorAction SilentlyContinue
  } else {
    $env:CARGO_NET_OFFLINE = $previousCargoNetOffline
  }
  if ($null -eq $previousMcpReleaseSha256) {
    Remove-Item Env:LAWYER_ASSISTANCE_MCP_RELEASE_SHA256 -ErrorAction SilentlyContinue
  } else {
    $env:LAWYER_ASSISTANCE_MCP_RELEASE_SHA256 = $previousMcpReleaseSha256
  }
  if (Test-Path -LiteralPath $temporaryRoot -PathType Container) {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
  }
  Remove-LawyerAssistanceMcpTauriSidecar $tauriMcpSidecar
}
$buildCompletedAt = [DateTimeOffset]::UtcNow

foreach ($artifact in @($expectedExecutable, $expectedInstaller)) {
  $item = Get-Item -LiteralPath $artifact -ErrorAction SilentlyContinue
  if (-not $item) { throw "Fresh unsigned build output is missing: $artifact" }
  if ($item.LastWriteTimeUtc -lt $buildStartedAt.UtcDateTime.AddSeconds(-2) -or
      $item.LastWriteTimeUtc -gt $buildCompletedAt.UtcDateTime.AddSeconds(5)) {
    throw "Unsigned release output is outside this build invocation: $artifact"
  }
}
$mcpEvidence = Assert-LawyerAssistanceMcpReleaseBinary `
  $expectedMcpExecutable $version ([DateTimeOffset]$buildStartedAt) ([DateTimeOffset]$buildCompletedAt)
if ([string]$mcpEvidence.sha256 -ne $mcpReleaseSha256) {
  throw "Packaged MCP binary differs from the trust anchor compiled into the App"
}
if (Test-Path -LiteralPath "$expectedInstaller.sig" -PathType Leaf) {
  throw "Unsigned installer build unexpectedly generated an updater signature"
}
if ((Get-NormalizedProductVersion $expectedExecutable) -ne $version) {
  throw "Executable ProductVersion does not match $version"
}
$executableSignature = Get-AuthenticodeSignature -LiteralPath $expectedExecutable
$installerSignature = Get-AuthenticodeSignature -LiteralPath $expectedInstaller
if ($executableSignature.Status -ne [Management.Automation.SignatureStatus]::NotSigned -or
    $installerSignature.Status -ne [Management.Automation.SignatureStatus]::NotSigned) {
  throw "The unsigned release path produced an Authenticode-signed artifact"
}

$headAfterBuild = (& git -C $ProjectRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $headAfterBuild -ne $commit) {
  throw "Source commit changed during the unsigned installer build"
}
Assert-CleanGitWorktree $ProjectRoot "Source worktree changed during the unsigned installer build"
Copy-Item -LiteralPath $expectedInstaller -Destination $outputInstaller
$sourceInstallerHash = (Get-FileHash -LiteralPath $expectedInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
$installerHash = (Get-FileHash -LiteralPath $outputInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
if ($installerHash -ne $sourceInstallerHash) {
  throw "Copied unsigned installer differs from the freshly verified Tauri output"
}
[IO.File]::WriteAllText($outputChecksum, "$installerHash  $unsignedName`n", (New-Object Text.UTF8Encoding($false)))

$rustVersion = (& rustc --version).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($rustVersion)) { throw "Unable to read rustc version" }
$nodeVersion = (& node --version).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($nodeVersion)) { throw "Unable to read Node.js version" }
$tauriPackagePath = Join-Path $ProjectRoot "apps\desktop\node_modules\@tauri-apps\cli\package.json"
if (-not (Test-Path -LiteralPath $tauriPackagePath -PathType Leaf)) { throw "Tauri CLI package is not installed" }
$tauriVersion = [string](Get-Content -LiteralPath $tauriPackagePath -Raw -Encoding UTF8 | ConvertFrom-Json).version
if ([string]::IsNullOrWhiteSpace($tauriVersion)) { throw "Unable to read Tauri CLI version" }

$manifest = [ordered]@{
  manifestVersion = 1
  version = $version
  commit = $commit
  architecture = "x86_64-pc-windows-msvc"
  artifact = $unsignedName
  sha256 = $installerHash
  size = (Get-Item -LiteralPath $outputInstaller).Length
  signed = $false
  authenticode = [ordered]@{
    executable = [string]$executableSignature.Status
    installer = [string]$installerSignature.Status
  }
  updaterArtifactGenerated = $false
  sourceDateEpoch = [long]$sourceDateEpoch
  mcpBinary = [ordered]@{
    siblingPath = [string]$mcpEvidence.siblingPath
    version = [string]$mcpEvidence.version
    size = [long]$mcpEvidence.size
    sha256 = [string]$mcpEvidence.sha256
    bundledBy = "tauri-externalBin"
    qualificationBinding = "compiled-release-sha256+canonical-path-identity+file-identity+sha256+version"
  }
  generatedAt = [DateTimeOffset]::FromUnixTimeSeconds([long]$sourceDateEpoch).ToString("o")
  legalDatabase = [ordered]@{
    version = [string]$distribution.dataset_version
    size = $legalSize
    sha256 = $legalHash
  }
  toolchain = [ordered]@{
    rustc = $rustVersion
    node = $nodeVersion
    tauriCli = $tauriVersion
  }
}
[IO.File]::WriteAllText($outputManifest, ($manifest | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))

Write-Output $outputInstaller
