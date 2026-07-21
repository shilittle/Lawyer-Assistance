param(
  [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$CodeSigningThumbprint,
  [string]$UpdaterPrivateKeyPath = "$PSScriptRoot\..\..\..\.release-secrets\lawyer-assistance-updater.key",
  [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "release_filenames.ps1")
$ProjectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\.."))

function Assert-CleanGitWorktree([string]$Root, [string]$Message) {
  & git -C $Root diff --quiet --ignore-submodules --
  if ($LASTEXITCODE -ne 0) { throw $Message }
  & git -C $Root diff --cached --quiet --ignore-submodules --
  if ($LASTEXITCODE -ne 0) { throw $Message }
  $untracked = @(& git -C $Root ls-files --others --exclude-standard)
  if ($LASTEXITCODE -ne 0 -or $untracked.Count -gt 0) { throw $Message }
}

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
$releaseFilenames = Get-LawyerAssistanceReleaseFilenames -Version $version
if ($productName -cne "Lawyer Assistance") {
  throw "The signed release product name must remain Lawyer Assistance"
}
if (([string](Get-Content -LiteralPath (Join-Path $ProjectRoot "apps\desktop\package.json") -Raw | ConvertFrom-Json).version) -ne $version -or
    ([string](Get-Content -LiteralPath (Join-Path $ProjectRoot "package.json") -Raw | ConvertFrom-Json).version) -ne $version) {
  throw "Root, desktop and Tauri versions must match $version"
}
$UpdaterPrivateKeyPath = [IO.Path]::GetFullPath($UpdaterPrivateKeyPath)
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

$certificate = Get-ChildItem Cert:\CurrentUser\My,Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue |
  Where-Object { $_.Thumbprint -eq $CodeSigningThumbprint -and $_.HasPrivateKey } |
  Select-Object -First 1
if (-not $certificate) { throw "No code-signing certificate with a private key matches thumbprint $CodeSigningThumbprint" }
if ($certificate.NotAfter -le (Get-Date)) { throw "Code-signing certificate has expired" }

$signingConfigPath = Join-Path $ProjectRoot ".release-secrets\tauri.code-signing.conf.json"
$signingConfig = [ordered]@{
  bundle = [ordered]@{
    windows = [ordered]@{
      certificateThumbprint = $CodeSigningThumbprint.ToUpperInvariant()
      digestAlgorithm = "sha256"
      timestampUrl = $TimestampUrl
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
$frontendKeep = Join-Path $ProjectRoot "apps\desktop\frontend-dist\.gitkeep"
foreach ($stale in @($expectedExecutable, $expectedInstaller, $expectedSignature)) {
  if (Test-Path -LiteralPath $stale -PathType Leaf) { Remove-Item -LiteralPath $stale -Force }
}
$buildStartedAt = (Get-Date).ToUniversalTime()
$env:TAURI_SIGNING_PRIVATE_KEY = Get-Content -LiteralPath $UpdaterPrivateKeyPath -Raw
$previousSourceDateEpoch = $env:SOURCE_DATE_EPOCH
$env:SOURCE_DATE_EPOCH = $sourceDateEpoch
try {
  Push-Location (Join-Path $ProjectRoot "apps\desktop")
  & $tauri build --config $signingConfigPath
  if ($LASTEXITCODE -ne 0) { throw "Tauri signed build failed with exit code $LASTEXITCODE" }
} finally {
  Pop-Location
  New-Item -ItemType Directory -Path (Split-Path -Parent $frontendKeep) -Force | Out-Null
  [IO.File]::WriteAllBytes($frontendKeep, [byte[]]@(0x0A))
  Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY -ErrorAction SilentlyContinue
  Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD -ErrorAction SilentlyContinue
  if ($null -eq $previousSourceDateEpoch) {
    Remove-Item Env:SOURCE_DATE_EPOCH -ErrorAction SilentlyContinue
  } else {
    $env:SOURCE_DATE_EPOCH = $previousSourceDateEpoch
  }
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
foreach ($artifact in @($appExe, $installer, $signature)) {
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
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Filter signtool.exe -Recurse -ErrorAction Stop |
  Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "signtool.exe was not found" }
foreach ($artifact in @($appExe, $installer)) {
  & $signtool.FullName verify /pa /all /v $artifact.FullName | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "Authenticode verification failed: $($artifact.FullName)" }
}

$portableProvenancePath = Join-Path $ProjectRoot ".release-secrets\portable-build-$([Guid]::NewGuid().ToString('N')).json"
$portableProvenance = [ordered]@{
  formatVersion = 1
  commit = $commit
  sourceDateEpoch = $sourceDateEpoch
  executablePath = $appExe.FullName
  executableSha256 = (Get-FileHash -LiteralPath $appExe.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
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
Write-Output $installer.FullName
Write-Output $signature.FullName
Write-Output $latestPath
