param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$DownloadUrl,
  [Parameter(Mandatory = $true)][string]$UpdaterSignature,
  [Parameter(Mandatory = $true)][string]$ArtifactPath,
  [Parameter(Mandatory = $true)][string]$UpdaterPublicKeyPath,
  [Parameter(Mandatory = $true)][string]$OutputPath
)
$ErrorActionPreference = "Stop"
$ProjectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\.."))
if ($Version -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') { throw "Version must be valid semantic version text" }
$downloadUri = [Uri]$DownloadUrl
if ($downloadUri.Scheme -ne 'https' -or $downloadUri.DnsSafeHost -ne 'github.com' -or
    -not [string]::IsNullOrEmpty($downloadUri.UserInfo) -or $downloadUri.Port -ne 443 -or
    -not [string]::IsNullOrEmpty($downloadUri.Query) -or -not [string]::IsNullOrEmpty($downloadUri.Fragment)) {
  throw "Updater URL must be an HTTPS github.com URL without credentials, query, or fragment"
}
$signatureBase64 = $UpdaterSignature.Trim()
if ([string]::IsNullOrWhiteSpace($signatureBase64)) { throw "An updater signature is required" }
try {
  $signatureText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($signatureBase64)).Trim()
} catch {
  throw "The updater signature must be the Base64 envelope emitted by Tauri"
}
$signatureLines = @($signatureText -split "`r?`n")
if ([string]::IsNullOrWhiteSpace($signatureText) -or $signatureLines.Count -ne 4) { throw "A four-line minisign signature is required" }
$downloadFilename = [Uri]::UnescapeDataString([IO.Path]::GetFileName($downloadUri.AbsolutePath))
$trustedFilenameMarker = "`tfile:$downloadFilename"
if (-not $signatureLines[2].StartsWith('trusted comment: timestamp:') -or
    -not $signatureLines[2].EndsWith($trustedFilenameMarker)) {
  throw "The minisign trusted comment must bind the exact updater filename"
}
$ArtifactPath = [IO.Path]::GetFullPath($ArtifactPath)
$UpdaterPublicKeyPath = [IO.Path]::GetFullPath($UpdaterPublicKeyPath)
if (-not (Test-Path -LiteralPath $ArtifactPath -PathType Leaf)) { throw "Updater artifact not found" }
if (-not (Test-Path -LiteralPath $UpdaterPublicKeyPath -PathType Leaf)) { throw "Updater public key not found" }
$uri = [Uri]$DownloadUrl
if ([Uri]::UnescapeDataString([IO.Path]::GetFileName($uri.AbsolutePath)) -ne [IO.Path]::GetFileName($ArtifactPath)) {
  throw "Updater URL filename does not match the signed artifact"
}

$verifyDirectory = Join-Path ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($OutputPath))) (".updater-verify-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $verifyDirectory -Force | Out-Null
$decodedPublicKey = Join-Path $verifyDirectory "updater.pub"
$decodedSignature = Join-Path $verifyDirectory "artifact.sig"
try {
  [IO.File]::WriteAllBytes($decodedPublicKey, [Convert]::FromBase64String((Get-Content -LiteralPath $UpdaterPublicKeyPath -Raw -Encoding UTF8).Trim()))
  [IO.File]::WriteAllText($decodedSignature, $signatureText, (New-Object Text.UTF8Encoding($false)))
  & cargo run --locked --offline --manifest-path (Join-Path $ProjectRoot "Cargo.toml") -p minisign-verify --example verify -- $decodedPublicKey $decodedSignature $ArtifactPath | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "Updater signature verification failed" }
} finally {
  $resolvedVerify = [IO.Path]::GetFullPath($verifyDirectory)
  $resolvedParent = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($verifyDirectory)).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  if (-not $resolvedVerify.StartsWith($resolvedParent, [StringComparison]::OrdinalIgnoreCase)) { throw "Unsafe verifier cleanup path" }
  if (Test-Path -LiteralPath $resolvedVerify) { Remove-Item -LiteralPath $resolvedVerify -Recurse -Force }
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$parent = [IO.Path]::GetDirectoryName($OutputPath)
if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$releaseEpoch = if ($env:SOURCE_DATE_EPOCH -match '^\d+$') {
  [DateTimeOffset]::FromUnixTimeSeconds([long]$env:SOURCE_DATE_EPOCH).UtcDateTime.ToString("o")
} else {
  (Get-Date).ToUniversalTime().ToString("o")
}
$payload = [ordered]@{
  version = $Version
  notes = "Lawyer Assistance $Version"
  pub_date = $releaseEpoch
  platforms = [ordered]@{
    "windows-x86_64" = [ordered]@{ signature = $signatureBase64; url = $DownloadUrl }
  }
}
$payloadJson = $payload | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText($OutputPath, $payloadJson, (New-Object Text.UTF8Encoding($false)))
$parsed = Get-Content -LiteralPath $OutputPath -Raw | ConvertFrom-Json
if ($parsed.version -ne $Version -or
    -not $parsed.platforms.'windows-x86_64'.signature -or
    $parsed.platforms.'windows-x86_64'.url -ne $DownloadUrl) { throw "latest.json validation failed" }
$decodedSignature = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$parsed.platforms.'windows-x86_64'.signature)).Trim()
if ($decodedSignature -ne $signatureText) { throw "latest.json signature base64 round-trip failed" }
Write-Output $OutputPath
