param(
  [string]$TargetDir = "$PSScriptRoot\..\..\..\target\x86_64-pc-windows-msvc\release",
  [string]$OutputDir = "$PSScriptRoot\..\..\..\dist",
  [switch]$RequireAuthenticode,
  [string]$ExistingBuildProvenancePath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
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

$ProjectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\.."))
$TargetDir = [IO.Path]::GetFullPath($TargetDir)
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
$expectedTargetDir = [IO.Path]::GetFullPath((Join-Path $ProjectRoot "target\x86_64-pc-windows-msvc\release"))
if (-not $TargetDir.Equals($expectedTargetDir, [StringComparison]::OrdinalIgnoreCase)) {
  throw "TargetDir must be the workspace release directory produced by this script: $expectedTargetDir"
}
$configPath = Join-Path $PSScriptRoot "..\src-tauri\tauri.conf.json"
$desktopPackagePath = Join-Path $ProjectRoot "apps\desktop\package.json"
$rootPackagePath = Join-Path $ProjectRoot "package.json"
$distributionManifestPath = Join-Path $ProjectRoot "data\generated\legal_core_distribution_manifest.json"
$config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
$desktopPackage = Get-Content -LiteralPath $desktopPackagePath -Raw -Encoding UTF8 | ConvertFrom-Json
$rootPackage = Get-Content -LiteralPath $rootPackagePath -Raw -Encoding UTF8 | ConvertFrom-Json
$distribution = Get-Content -LiteralPath $distributionManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$version = [string]$config.version
if ($version -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') { throw "Invalid application version: $version" }
if ([string]$desktopPackage.version -ne $version -or [string]$rootPackage.version -ne $version) {
  throw "Root, desktop and Tauri versions must match $version"
}

Assert-CleanGitWorktree $ProjectRoot "Portable releases must be built from a clean Git worktree"
$commit = (& git -C $ProjectRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') { throw "Unable to resolve release commit" }
$sourceDateEpoch = (& git -C $ProjectRoot show -s --format=%ct HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceDateEpoch -notmatch '^\d+$') { throw "Unable to resolve release commit timestamp" }
if (-not [string]::IsNullOrWhiteSpace($env:SOURCE_DATE_EPOCH) -and $env:SOURCE_DATE_EPOCH -ne $sourceDateEpoch) {
  throw "SOURCE_DATE_EPOCH must equal the current release commit timestamp $sourceDateEpoch"
}
$generatedAt = [DateTimeOffset]::FromUnixTimeSeconds([long]$sourceDateEpoch).UtcDateTime

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$stage = [IO.Path]::GetFullPath((Join-Path $OutputDir "Lawyer-Assistance-portable-x86_64"))
$zip = Join-Path $OutputDir "Lawyer-Assistance_${version}_windows-x86_64-portable.zip"
$outputPrefix = $OutputDir.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $stage.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Portable staging directory escaped output directory: $stage"
}
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
foreach ($staleArtifact in @($zip, "$zip.sha256")) {
  if (Test-Path -LiteralPath $staleArtifact -PathType Leaf) {
    Remove-Item -LiteralPath $staleArtifact -Force
  }
}

$exe = Join-Path $TargetDir "lawyer-assistance.exe"
$mcpPaths = Get-LawyerAssistanceMcpReleasePaths $ProjectRoot
$mcpExe = [string]$mcpPaths.ReleaseBinary
$resourceRoot = Join-Path $PSScriptRoot "..\src-tauri\resources"
$legalResource = Join-Path $resourceRoot "legal_core.sqlite"
$frontendKeep = Join-Path $ProjectRoot "apps\desktop\frontend-dist\.gitkeep"
$buildMode = "fresh-offline-build"
$buildStartedAt = [DateTimeOffset]::UtcNow
$buildCompletedAt = $null
$expectedExecutableHash = $null
$expectedMcpHash = $null
$compiledMcpTrustAnchor = $null

if ([string]::IsNullOrWhiteSpace($ExistingBuildProvenancePath)) {
  if ($RequireAuthenticode) {
    throw "RequireAuthenticode requires a one-time build provenance file from build_signed_release.ps1"
  }
  if (Test-Path -LiteralPath $exe -PathType Leaf) {
    Remove-Item -LiteralPath $exe -Force
  }
  if (Test-Path -LiteralPath $mcpExe -PathType Leaf) {
    Remove-Item -LiteralPath $mcpExe -Force
  }
  $previousSourceDateEpoch = $env:SOURCE_DATE_EPOCH
  $previousCargoNetOffline = $env:CARGO_NET_OFFLINE
  $previousMcpReleaseSha256 = $env:LAWYER_ASSISTANCE_MCP_RELEASE_SHA256
  $env:SOURCE_DATE_EPOCH = $sourceDateEpoch
  $env:CARGO_NET_OFFLINE = "true"
  try {
    Invoke-Checked "Offline frontend build" {
      & node (Join-Path $ProjectRoot "apps\desktop\scripts\build_tauri_frontend.mjs")
    }
    Push-Location $ProjectRoot
    try {
      Invoke-LawyerAssistanceFreshMcpReleaseBuild $ProjectRoot
      ConvertTo-LawyerAssistanceIndependentMcpBinary $mcpExe
      $compiledMcpTrustAnchor = (Get-FileHash -LiteralPath $mcpExe -Algorithm SHA256).Hash.ToLowerInvariant()
      if ($compiledMcpTrustAnchor -notmatch '^[0-9a-f]{64}$') { throw "MCP release trust anchor is invalid" }
      $env:LAWYER_ASSISTANCE_MCP_RELEASE_SHA256 = $compiledMcpTrustAnchor
      Invoke-Checked "Offline Rust release build" {
        & cargo build --release --locked --offline --package lawyer-assistance-desktop --bin lawyer-assistance
      }
    } finally {
      Pop-Location
    }
  } finally {
    New-Item -ItemType Directory -Path (Split-Path -Parent $frontendKeep) -Force | Out-Null
    [IO.File]::WriteAllBytes($frontendKeep, [byte[]]@(0x0A))
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
  }
  $buildCompletedAt = [DateTimeOffset]::UtcNow
} else {
  if (-not $RequireAuthenticode) {
    throw "ExistingBuildProvenancePath is reserved for the signed release workflow"
  }
  $buildMode = "signed-build-provenance"
  $provenanceRoot = [IO.Path]::GetFullPath((Join-Path $ProjectRoot ".release-secrets"))
  $provenancePath = [IO.Path]::GetFullPath($ExistingBuildProvenancePath)
  $provenancePrefix = $provenanceRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  if (-not $provenancePath.StartsWith($provenancePrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Build provenance must be a one-time file below $provenanceRoot"
  }
  if (-not (Test-Path -LiteralPath $provenancePath -PathType Leaf)) { throw "Build provenance file not found" }
  $provenanceItem = Get-Item -LiteralPath $provenancePath
  $provenance = Get-Content -LiteralPath $provenancePath -Raw -Encoding UTF8 | ConvertFrom-Json
  if ([int]$provenance.formatVersion -ne 1 -or [string]$provenance.commit -ne $commit) {
    throw "Build provenance does not identify the current commit"
  }
  if ([string]$provenance.sourceDateEpoch -ne $sourceDateEpoch) {
    throw "Build provenance has the wrong source timestamp"
  }
  $provenanceExecutable = [IO.Path]::GetFullPath([string]$provenance.executablePath)
  if (-not $provenanceExecutable.Equals($exe, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Build provenance identifies an unexpected executable path"
  }
  try {
    $buildStartedAt = [DateTimeOffset]::Parse(
      [string]$provenance.buildStartedAtUtc,
      [Globalization.CultureInfo]::InvariantCulture,
      [Globalization.DateTimeStyles]::RoundtripKind
    )
    $buildCompletedAt = [DateTimeOffset]::Parse(
      [string]$provenance.buildCompletedAtUtc,
      [Globalization.CultureInfo]::InvariantCulture,
      [Globalization.DateTimeStyles]::RoundtripKind
    )
  } catch {
    throw "Build provenance contains invalid timestamps"
  }
  if ($buildCompletedAt -lt $buildStartedAt -or
      ([DateTimeOffset]::UtcNow - $buildCompletedAt).TotalMinutes -gt 30 -or
      $provenanceItem.LastWriteTimeUtc -lt $buildCompletedAt.UtcDateTime.AddSeconds(-2)) {
    throw "Build provenance is stale or internally inconsistent"
  }
  if ($RequireAuthenticode -and $provenance.authenticodeVerified -ne $true) {
    throw "Build provenance does not confirm Authenticode verification"
  }
  $expectedExecutableHash = ([string]$provenance.executableSha256).ToLowerInvariant()
  if ($expectedExecutableHash -notmatch '^[0-9a-f]{64}$') { throw "Build provenance contains an invalid executable hash" }
  $provenanceMcpPath = [IO.Path]::GetFullPath([string]$provenance.mcpBinaryPath)
  if (-not $provenanceMcpPath.Equals($mcpExe, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Build provenance identifies an unexpected MCP binary path"
  }
  $expectedMcpHash = ([string]$provenance.mcpBinarySha256).ToLowerInvariant()
  if ($expectedMcpHash -notmatch '^[0-9a-f]{64}$') { throw "Build provenance contains an invalid MCP binary hash" }
  $compiledMcpTrustAnchor = $expectedMcpHash
}

if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Fresh release executable was not generated: $exe" }
ConvertTo-LawyerAssistanceIndependentMcpBinary $mcpExe
$exeItem = Get-Item -LiteralPath $exe
if ($exeItem.LastWriteTimeUtc -lt $buildStartedAt.UtcDateTime.AddSeconds(-2) -or
    $exeItem.LastWriteTimeUtc -gt $buildCompletedAt.UtcDateTime.AddSeconds(5)) {
  throw "Release executable timestamp is outside this build invocation"
}
$headAfterBuild = (& git -C $ProjectRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $headAfterBuild -ne $commit) {
  throw "Source commit or tracked worktree changed during the release build"
}
Assert-CleanGitWorktree $ProjectRoot "Source commit or tracked worktree changed during the release build"
$exeHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($expectedExecutableHash -and $exeHash -ne $expectedExecutableHash) {
  throw "Release executable does not match its one-time build provenance"
}
$mcpEvidence = Assert-LawyerAssistanceMcpReleaseBinary $mcpExe $version $buildStartedAt $buildCompletedAt
if ($expectedMcpHash -and [string]$mcpEvidence.sha256 -ne $expectedMcpHash) {
  throw "MCP release binary does not match its one-time build provenance"
}
if ([string]$mcpEvidence.sha256 -ne $compiledMcpTrustAnchor) {
  throw "Portable MCP binary differs from the trust anchor compiled into the App"
}
if ($RequireAuthenticode -and
    (Get-AuthenticodeSignature -LiteralPath $mcpExe).Status -ne
      [Management.Automation.SignatureStatus]::Valid) {
  throw "Signed portable MCP sibling does not have a valid Authenticode signature"
}

$productVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($exe).ProductVersion
$normalizedProductVersion = if ($productVersion -match '^(\d+\.\d+\.\d+)\.0$') { $Matches[1] } else { $productVersion }
if ($normalizedProductVersion -ne $version) {
  throw "Executable ProductVersion '$productVersion' does not match $version"
}
if ($RequireAuthenticode) {
  $signature = Get-AuthenticodeSignature -LiteralPath $exe
  if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
    throw "Executable Authenticode signature is not valid: $($signature.Status)"
  }
}

Invoke-Checked "Formal legal resource verification" {
  python (Join-Path $PSScriptRoot "verify_legal_resource.py") --resource $legalResource --manifest $distributionManifestPath
}
$actualLegalSize = (Get-Item -LiteralPath $legalResource).Length
$actualLegalHash = (Get-FileHash -LiteralPath $legalResource -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualLegalSize -ne [long]$distribution.size_bytes) {
  throw "Legal database size mismatch: $actualLegalSize != $($distribution.size_bytes)"
}
if ($actualLegalHash -ne ([string]$distribution.sha256).ToLowerInvariant()) {
  throw "Legal database hash mismatch: $actualLegalHash != $($distribution.sha256)"
}
Invoke-Checked "Third-party notice verification" {
  python (Join-Path $ProjectRoot "scripts\generate_third_party_notices.py") --check
}

# Cargo/Tauri and workspace snapshot tooling may optimize very large resource
# copies as hard links. Runtime database opens intentionally reject hard-linked
# files, so always materialize an independent release-tree copy after the build.
$targetLegalResource = Join-Path $TargetDir "resources\legal_core.sqlite"
Install-LawyerAssistanceIndependentFile $legalResource $targetLegalResource
if ((Get-Item -LiteralPath $targetLegalResource).Length -ne $actualLegalSize -or
    (Get-FileHash -LiteralPath $targetLegalResource -Algorithm SHA256).Hash.ToLowerInvariant() -ne $actualLegalHash) {
  throw "Independent target legal database differs from the verified release resource"
}

$tauriPackagePath = Join-Path $ProjectRoot "apps\desktop\node_modules\@tauri-apps\cli\package.json"
if (-not (Test-Path -LiteralPath $tauriPackagePath -PathType Leaf)) { throw "Tauri CLI package is not installed" }
$tauriCliVersion = [string](Get-Content -LiteralPath $tauriPackagePath -Raw -Encoding UTF8 | ConvertFrom-Json).version
$rustVersion = (& rustc --version).Trim()
if ($LASTEXITCODE -ne 0) { throw "Unable to read rustc version" }
$nodeVersion = (& node --version).Trim()
if ($LASTEXITCODE -ne 0) { throw "Unable to read Node.js version" }

New-Item -ItemType Directory -Path (Join-Path $stage "resources") -Force | Out-Null
Copy-Item -LiteralPath $exe -Destination $stage
Install-LawyerAssistanceIndependentFile $mcpExe (Join-Path $stage "lawyer-assistance-mcp.exe")
foreach ($name in @("legal_core.sqlite", "LICENSE.txt", "THIRD_PARTY_NOTICES.txt", "DATA_SOURCES.md")) {
  $source = Join-Path $resourceRoot $name
  if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Required release resource missing: $source" }
  $destination = Join-Path $stage "resources\$name"
  if ($name -eq "legal_core.sqlite") {
    Install-LawyerAssistanceIndependentFile $source $destination
  } else {
    Copy-Item -LiteralPath $source -Destination $destination
  }
}

$copiedLegalResource = Join-Path $stage "resources\legal_core.sqlite"
$copiedExecutable = Join-Path $stage "lawyer-assistance.exe"
$copiedMcpExecutable = Join-Path $stage "lawyer-assistance-mcp.exe"
if ((Get-FileHash -LiteralPath $copiedExecutable -Algorithm SHA256).Hash.ToLowerInvariant() -ne $exeHash) {
  throw "Copied executable differs from the freshly verified release executable"
}
if ((Get-FileHash -LiteralPath $copiedMcpExecutable -Algorithm SHA256).Hash.ToLowerInvariant() -ne
    [string]$mcpEvidence.sha256) {
  throw "Copied MCP sibling differs from the freshly verified release binary"
}
Assert-LawyerAssistanceSingleLinkFile $copiedMcpExecutable
if ((Get-Item -LiteralPath $copiedLegalResource).Length -ne $actualLegalSize -or
    (Get-FileHash -LiteralPath $copiedLegalResource -Algorithm SHA256).Hash.ToLowerInvariant() -ne $actualLegalHash) {
  throw "Copied legal database differs from the verified release resource"
}
Assert-LawyerAssistanceSingleLinkFile $copiedLegalResource

$forbidden = Get-ChildItem -LiteralPath $stage -Recurse -File | Where-Object {
  $_.Name -match '^(python|node|postgres|mysqld|mongod)(\.exe)?$' -or
  $_.FullName -match '(?i)(CUDA|node_modules|data\\build|sidecar)'
}
if ($forbidden) { throw "Forbidden runtime in portable package: $($forbidden.FullName -join ', ')" }

$files = Get-ChildItem -LiteralPath $stage -Recurse -File | Sort-Object FullName | ForEach-Object {
  $relativePath = $_.FullName.Substring($stage.Length).TrimStart('\').Replace('\','/')
  [ordered]@{
    path = $relativePath
    size = $_.Length
    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  }
}
$manifest = [ordered]@{
  manifestVersion = 1
  manifestScope = "all packaged files except release-manifest.json and the external .sha256 checksum"
  version = $version
  commit = $commit
  architecture = "x86_64-pc-windows-msvc"
  buildMode = $buildMode
  generatedAt = $generatedAt.ToString("o")
  buildProvenance = [ordered]@{
    sourceCommit = $commit
    sourceDateEpoch = [long]$sourceDateEpoch
    executablePath = "target/x86_64-pc-windows-msvc/release/lawyer-assistance.exe"
    executableSha256 = $exeHash
    mcpBinaryPath = "target/x86_64-pc-windows-msvc/release/lawyer-assistance-mcp.exe"
    mcpBinarySha256 = [string]$mcpEvidence.sha256
  }
  mcpBinary = [ordered]@{
    siblingPath = [string]$mcpEvidence.siblingPath
    version = [string]$mcpEvidence.version
    size = [long]$mcpEvidence.size
    sha256 = [string]$mcpEvidence.sha256
    qualificationBinding = "compiled-release-sha256+canonical-path-identity+file-identity+sha256+version"
  }
  toolchain = [ordered]@{
    rustc = $rustVersion
    node = $nodeVersion
    tauriCli = $tauriCliVersion
  }
  lockfiles = [ordered]@{
    cargoSha256 = (Get-FileHash -LiteralPath (Join-Path $ProjectRoot "Cargo.lock") -Algorithm SHA256).Hash.ToLowerInvariant()
    pnpmSha256 = (Get-FileHash -LiteralPath (Join-Path $ProjectRoot "pnpm-lock.yaml") -Algorithm SHA256).Hash.ToLowerInvariant()
  }
  legalDatabase = [ordered]@{
    version = [string]$distribution.dataset_version
    scope = [string]$distribution.data_scope
    size = $actualLegalSize
    sha256 = $actualLegalHash
    sourceManifestSha256 = [string]$distribution.source_manifest_sha256
  }
  updaterPublicKey = (Get-Content -LiteralPath (Join-Path $PSScriptRoot "..\src-tauri\updater-public.key") -Raw -Encoding UTF8).Trim()
  files = @($files)
}
$manifestPath = Join-Path $stage "release-manifest.json"
$manifestJson = $manifest | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText($manifestPath, $manifestJson, (New-Object Text.UTF8Encoding($false)))

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zipStream = [IO.File]::Open($zip, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
  $archive = [IO.Compression.ZipArchive]::new($zipStream, [IO.Compression.ZipArchiveMode]::Create, $true)
  try {
    foreach ($file in (Get-ChildItem -LiteralPath $stage -Recurse -File | Sort-Object FullName)) {
      $relativePath = $file.FullName.Substring($stage.Length).TrimStart('\').Replace('\','/')
      $entry = $archive.CreateEntry($relativePath, [IO.Compression.CompressionLevel]::Optimal)
      $entry.LastWriteTime = [DateTimeOffset]$generatedAt
      $entryStream = $entry.Open()
      try {
        $input = [IO.File]::OpenRead($file.FullName)
        try { $input.CopyTo($entryStream) } finally { $input.Dispose() }
      } finally { $entryStream.Dispose() }
    }
  } finally { $archive.Dispose() }
} finally { $zipStream.Dispose() }

if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -ne $exeHash -or
    (Get-FileHash -LiteralPath $mcpExe -Algorithm SHA256).Hash.ToLowerInvariant() -ne [string]$mcpEvidence.sha256 -or
    (& git -C $ProjectRoot rev-parse HEAD).Trim() -ne $commit) {
  throw "Release inputs changed while the portable archive was being assembled"
}
Assert-CleanGitWorktree $ProjectRoot "Release inputs changed while the portable archive was being assembled"

$zipHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$zip.sha256", "$zipHash  $([IO.Path]::GetFileName($zip))`n", (New-Object Text.UTF8Encoding($false)))
Write-Output $zip
