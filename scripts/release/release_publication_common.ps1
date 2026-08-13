Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "release_common.ps1")

function Get-ReleaseSha256([string]$Path) {
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-ReleaseOrdinaryFile([string]$Path, [string]$Label) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "$Label is missing."
  }
  $item = Get-Item -LiteralPath $Path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -le 0) {
    throw "$Label must be a nonempty ordinary file."
  }
}

function Read-ReleaseNotesBody {
  param(
    [Parameter(Mandatory = $true)][string]$ProjectRoot,
    [Parameter(Mandatory = $true)][string]$NotesFile
  )

  $canonical = [IO.Path]::GetFullPath((Join-Path $ProjectRoot "RELEASE_NOTES.md"))
  $actual = [IO.Path]::GetFullPath($NotesFile)
  if (-not $actual.Equals($canonical, [StringComparison]::OrdinalIgnoreCase)) {
    throw "The draft Release must use the canonical repository RELEASE_NOTES.md."
  }
  Assert-ReleaseOrdinaryFile $actual "Canonical release notes"
  try {
    $bytes = [IO.File]::ReadAllBytes($actual)
    $body = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
  } catch {
    throw "The canonical release notes are not strict UTF-8."
  }
  if ([string]::IsNullOrWhiteSpace($body) -or $body[0] -eq [char]0xFEFF -or
      -not [Linq.Enumerable]::SequenceEqual(
        [byte[]]$bytes,
        [byte[]]([Text.UTF8Encoding]::new($false).GetBytes($body))
      )) {
    throw "The canonical release notes are empty or contain a UTF-8 BOM."
  }
  return $body
}

function Invoke-ReleaseTextCommand {
  param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [Parameter(Mandatory = $true)][string]$Description
  )

  $output = @(& $Executable @Arguments 2>&1)
  if ($LASTEXITCODE -ne 0) {
    throw "$Description failed."
  }
  return ($output -join "`n")
}

function Assert-ReleaseGitHubHostEnvironment {
  foreach ($name in @("GH_HOST", "GH_REPO")) {
    $override = Get-Item "Env:$name" -ErrorAction SilentlyContinue
    if ($null -ne $override -and -not [string]::IsNullOrWhiteSpace([string]$override.Value)) {
      throw "$name must be absent for the frozen release repository."
    }
  }
}

function Invoke-ReleaseGhAssetDownload {
  param(
    [Parameter(Mandatory = $true)][string]$GhExecutable,
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][long]$AssetId,
    [Parameter(Mandatory = $true)][string]$Destination
  )

  if ($Repository -cnotmatch '^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$' -or $AssetId -le 0) {
    throw "The GitHub asset download identity is invalid."
  }
  $destinationPath = [IO.Path]::GetFullPath($Destination)
  if (Test-Path -LiteralPath $destinationPath) {
    throw "The GitHub asset download destination must not already exist."
  }

  $processInfo = [Diagnostics.ProcessStartInfo]::new()
  $processInfo.FileName = $GhExecutable
  $processInfo.Arguments = "api --hostname github.com repos/$Repository/releases/assets/$AssetId -H Accept:application/octet-stream"
  $processInfo.UseShellExecute = $false
  $processInfo.CreateNoWindow = $true
  $processInfo.RedirectStandardOutput = $true
  $processInfo.RedirectStandardError = $true
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $processInfo
  $stream = $null
  try {
    if (-not $process.Start()) {
      throw "The GitHub asset download process did not start."
    }
    $stream = [IO.File]::Open(
      $destinationPath,
      [IO.FileMode]::CreateNew,
      [IO.FileAccess]::Write,
      [IO.FileShare]::None
    )
    $errorRead = $process.StandardError.ReadToEndAsync()
    $process.StandardOutput.BaseStream.CopyTo($stream)
    $stream.Flush($true)
    $stream.Dispose()
    $stream = $null
    $process.WaitForExit()
    [void]$errorRead.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) {
      Remove-Item -LiteralPath $destinationPath -Force -ErrorAction SilentlyContinue
      throw "GitHub asset download failed."
    }
  } finally {
    if ($null -ne $stream) { $stream.Dispose() }
    $process.Dispose()
  }
  Assert-ReleaseOrdinaryFile $destinationPath "Downloaded GitHub asset"
}

function Read-ReleasePublicationContract([string]$ContractPath) {
  Assert-ReleaseOrdinaryFile $ContractPath "Release contract"
  try {
    $contract = Get-Content -LiteralPath $ContractPath -Raw -Encoding UTF8 | ConvertFrom-Json
  } catch {
    throw "The release contract is not valid JSON."
  }
  if ([int]$contract.schemaVersion -ne 1 -or
      [string]$contract.release.formalVersion -cne "0.4.0" -or
      [string]$contract.release.appTag -cne "v0.4.0" -or
      [string]$contract.release.minerUTag -cne "mineru-components-v0.4.0" -or
      [string]$contract.repository.owner -cne "shilittle" -or
      [string]$contract.repository.name -cne "Lawyer-Assistance" -or
      [string]$contract.repository.httpsUrl -cne "https://github.com/shilittle/Lawyer-Assistance.git") {
    throw "The formal release identity is not the frozen v0.4.0 contract."
  }
  $repository = "$([string]$contract.repository.owner)/$([string]$contract.repository.name)"
  if ($repository -cnotmatch '^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$') {
    throw "The release repository identity is invalid."
  }
  return [pscustomobject][ordered]@{
    Raw = $contract
    Repository = $repository
    RepositoryUrl = [string]$contract.repository.httpsUrl
    Version = [string]$contract.release.formalVersion
    AppTag = [string]$contract.release.appTag
    MinerUTag = [string]$contract.release.minerUTag
  }
}

function Get-MinerUReleaseAssetNames([string]$AssetDirectory) {
  $catalogPath = Join-Path $AssetDirectory "mineru-component-catalog.json"
  Assert-ReleaseOrdinaryFile $catalogPath "MinerU component catalog"
  try {
    $catalog = Get-Content -LiteralPath $catalogPath -Raw -Encoding UTF8 | ConvertFrom-Json
  } catch {
    throw "The MinerU component catalog is not valid JSON."
  }
  if (@($catalog.entries).Count -ne 1) {
    throw "The MinerU component catalog must contain exactly one entry."
  }
  $entry = @($catalog.entries)[0]
  $descriptorUri = [Uri]([string]$entry.downloadUrl)
  $descriptorName = [Uri]::UnescapeDataString([IO.Path]::GetFileName($descriptorUri.AbsolutePath))
  if ($descriptorUri.Scheme -cne "https" -or
      $descriptorName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.laocrparts$') {
    throw "The MinerU descriptor filename is invalid."
  }
  $partNames = @()
  $parts = @($entry.parts)
  if ($parts.Count -lt 1 -or $parts.Count -gt 9999) {
    throw "The MinerU part inventory is invalid."
  }
  for ($index = 1; $index -le $parts.Count; $index++) {
    $part = $parts[$index - 1]
    $expected = "$descriptorName.part$($index.ToString('0000'))-of-$($parts.Count.ToString('0000'))"
    if ([int]$part.number -ne $index -or [string]$part.fileName -cne $expected) {
      throw "The MinerU part inventory is not strictly ordered."
    }
    $partNames += $expected
  }
  return @(
    "mineru-component-catalog.json"
    "mineru-component-catalog.json.minisig"
    "mineru-component-provenance.json"
    "mineru-component-provenance.json.minisig"
    $descriptorName
    $partNames
  )
}

function Get-ReleasePublicationAssetNames {
  param(
    [Parameter(Mandatory = $true)]$Contract,
    [Parameter(Mandatory = $true)][ValidateSet("App", "MinerU")][string]$Kind,
    [Parameter(Mandatory = $true)][string]$AssetDirectory
  )

  if ($Kind -ceq "App") {
    $names = @($Contract.Raw.appAssets | ForEach-Object { [string]$_ })
    if ($names.Count -ne 12) {
      throw "The App asset contract must contain exactly 12 names."
    }
    return $names
  }
  return @(Get-MinerUReleaseAssetNames $AssetDirectory)
}

function Assert-ReleaseAssetDirectory {
  param(
    [Parameter(Mandatory = $true)][string]$AssetDirectory,
    [Parameter(Mandatory = $true)][string[]]$ExpectedNames
  )

  $directory = [IO.Path]::GetFullPath($AssetDirectory)
  if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
    throw "The release asset directory is missing."
  }
  $directoryItem = Get-Item -LiteralPath $directory -Force
  if (($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "The release asset directory must not be a reparse point."
  }
  if ($ExpectedNames.Count -ne (@($ExpectedNames | Sort-Object -Unique)).Count -or
      $ExpectedNames.Count -ne (@($ExpectedNames | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)).Count) {
    throw "The release asset contract contains duplicate or case-aliased names."
  }
  $items = @(Get-ChildItem -LiteralPath $directory -Force)
  if (@($items | Where-Object { -not $_.PSIsContainer }).Count -ne $items.Count) {
    throw "The release asset directory contains a nested directory."
  }
  $actualNames = @($items | ForEach-Object { $_.Name } | Sort-Object -CaseSensitive)
  $sortedExpected = @($ExpectedNames | Sort-Object -CaseSensitive)
  if (($actualNames -join "`n") -cne ($sortedExpected -join "`n")) {
    throw "The release asset directory does not match the exact allowlist."
  }
  foreach ($name in $ExpectedNames) {
    if ([IO.Path]::GetFileName($name) -cne $name) {
      throw "The release asset allowlist contains a non-basename."
    }
    Assert-ReleaseOrdinaryFile (Join-Path $directory $name) "Release asset $name"
  }
}

function Assert-RemoteAnnotatedReleaseTag {
  param(
    [Parameter(Mandatory = $true)][string]$ProjectRoot,
    [Parameter(Mandatory = $true)][string]$RepositoryUrl,
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][scriptblock]$GitText
  )

  if ($Tag -cnotmatch '^(?:v0\.4\.0|mineru-components-v0\.4\.0)$') {
    throw "The release tag is outside the frozen v0.4.0 contract."
  }
  $originUrl = (& $GitText -Arguments @("-C", $ProjectRoot, "remote", "get-url", "--fetch", "origin")).Trim()
  if ($originUrl -cne $RepositoryUrl) {
    throw "The local origin does not match the frozen release repository."
  }
  $head = (& $GitText -Arguments @("-C", $ProjectRoot, "rev-parse", "HEAD")).Trim().ToLowerInvariant()
  if ($head -cnotmatch '^[0-9a-f]{40}$') {
    throw "The release HEAD is invalid."
  }
  $remoteText = & $GitText -Arguments @(
    "-C", $ProjectRoot, "ls-remote", "--tags", "origin", "refs/tags/$Tag", "refs/tags/$Tag^{}"
  )
  $rows = @($remoteText -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($rows.Count -ne 2) {
    throw "The remote release tag must exist as an annotated tag."
  }
  $objects = @{}
  foreach ($row in $rows) {
    if ($row -cnotmatch '^([0-9a-f]{40})\t(refs/tags/.+)$') {
      throw "The remote release tag response is invalid."
    }
    $objects[$Matches[2]] = $Matches[1]
  }
  $tagObject = [string]$objects["refs/tags/$Tag"]
  $peeled = [string]$objects["refs/tags/$Tag^{}"]
  if ($tagObject -cnotmatch '^[0-9a-f]{40}$' -or
      $peeled -cnotmatch '^[0-9a-f]{40}$' -or
      $tagObject -ceq $peeled -or
      $peeled -cne $head) {
    throw "The remote annotated release tag does not peel to exact HEAD."
  }
  return [pscustomobject][ordered]@{
    Head = $head
    TagObject = $tagObject
    Peeled = $peeled
  }
}

function Assert-RemoteAnnotatedReleaseTagUnchanged {
  param(
    [Parameter(Mandatory = $true)][string]$ProjectRoot,
    [Parameter(Mandatory = $true)][string]$RepositoryUrl,
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][scriptblock]$GitText,
    [Parameter(Mandatory = $true)]$Expected
  )

  $actual = Assert-RemoteAnnotatedReleaseTag $ProjectRoot $RepositoryUrl $Tag $GitText
  if ([string]$actual.Head -cne [string]$Expected.Head -or
      [string]$actual.TagObject -cne [string]$Expected.TagObject -or
      [string]$actual.Peeled -cne [string]$Expected.Peeled) {
    throw "The remote annotated release tag changed during the release operation."
  }
  return $actual
}

function Get-GitHubReleaseForTag {
  param(
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][scriptblock]$GhText
  )

  $json = & $GhText -Arguments @("api", "repos/$Repository/releases?per_page=100", "--paginate", "--slurp")
  try {
    $pages = $json | ConvertFrom-Json
  } catch {
    throw "GitHub returned invalid release metadata."
  }
  $matches = @()
  foreach ($page in @($pages)) {
    foreach ($release in @($page)) {
      if ($null -eq $release -or $null -eq $release.PSObject.Properties["tag_name"]) {
        continue
      }
      if ([string]$release.tag_name -ceq $Tag) { $matches += $release }
    }
  }
  if ($matches.Count -gt 1) {
    throw "GitHub returned duplicate releases for the same tag."
  }
  if ($matches.Count -eq 0) { return $null }
  return $matches[0]
}

function Assert-DraftReleaseAssets {
  param(
    [Parameter(Mandatory = $true)]$Release,
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][string[]]$AllowedNames,
    [AllowEmptyString()][string]$ExpectedTitle = "",
    [AllowEmptyString()][string]$ExpectedBody = ""
  )

  if ($null -eq $Release -or $Release.draft -ne $true -or
      [string]$Release.tag_name -cne $Tag -or
      [long]$Release.id -le 0 -or
      ($null -ne $Release.PSObject.Properties["prerelease"] -and $Release.prerelease -ne $false) -or
      (-not [string]::IsNullOrEmpty($ExpectedTitle) -and [string]$Release.name -cne $ExpectedTitle) -or
      (-not [string]::IsNullOrEmpty($ExpectedBody) -and [string]$Release.body -cne $ExpectedBody)) {
    throw "The GitHub Release must remain a draft for the exact tag."
  }
  $assets = @($Release.assets)
  $names = @($assets | ForEach-Object { [string]$_.name })
  if ($names.Count -ne (@($names | Sort-Object -Unique)).Count -or
      $names.Count -ne (@($names | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)).Count) {
    throw "The remote release contains duplicate or case-aliased assets."
  }
  $extra = @($names | Where-Object { $AllowedNames -cnotcontains $_ })
  if ($extra.Count -gt 0) {
    throw "The remote release contains an asset outside the exact allowlist."
  }
  return $assets
}

function Get-ReleaseAssetInventoryEvidence($Assets) {
  $records = @($Assets | ForEach-Object {
    if ([long]$_.id -le 0 -or [long]$_.size -le 0 -or [string]::IsNullOrWhiteSpace([string]$_.name)) {
      throw "The remote release contains invalid asset evidence."
    }
    "$([long]$_.id)`t$([string]$_.name)`t$([long]$_.size)"
  } | Sort-Object -CaseSensitive)
  return ($records -join "`n")
}

function Assert-DraftReleaseUnchanged {
  param(
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][string[]]$AllowedNames,
    [Parameter(Mandatory = $true)][scriptblock]$GhText,
    [Parameter(Mandatory = $true)]$ExpectedRelease,
    [AllowEmptyString()][string]$ExpectedAssetInventory = "",
    [AllowEmptyString()][string]$ExpectedTitle = "",
    [AllowEmptyString()][string]$ExpectedBody = ""
  )

  $actual = Get-GitHubReleaseForTag $Repository $Tag $GhText
  $assets = @(Assert-DraftReleaseAssets $actual $Tag $AllowedNames $ExpectedTitle $ExpectedBody)
  if ([long]$actual.id -ne [long]$ExpectedRelease.id) {
    throw "The draft GitHub Release identity changed during the release operation."
  }
  if (-not [string]::IsNullOrEmpty($ExpectedAssetInventory) -and
      (Get-ReleaseAssetInventoryEvidence $assets) -cne $ExpectedAssetInventory) {
    throw "The draft GitHub Release asset inventory changed during verification."
  }
  return [pscustomobject][ordered]@{ Release = $actual; Assets = $assets }
}

function Assert-ReleaseUploadTransition {
  param(
    [Parameter(Mandatory = $true)]$PreviousRelease,
    [Parameter(Mandatory = $true)]$ActualRelease,
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][string[]]$AllowedNames,
    [Parameter(Mandatory = $true)][string]$UploadedName,
    [Parameter(Mandatory = $true)][long]$UploadedSize,
    [AllowEmptyString()][string]$ExpectedTitle = "",
    [AllowEmptyString()][string]$ExpectedBody = ""
  )

  $previousAssets = @(Assert-DraftReleaseAssets $PreviousRelease $Tag $AllowedNames $ExpectedTitle $ExpectedBody)
  $actualAssets = @(Assert-DraftReleaseAssets $ActualRelease $Tag $AllowedNames $ExpectedTitle $ExpectedBody)
  if ([long]$ActualRelease.id -ne [long]$PreviousRelease.id -or
      $actualAssets.Count -ne ($previousAssets.Count + 1)) {
    throw "The draft GitHub Release changed outside the expected asset upload."
  }
  $previousRecords = @($previousAssets | ForEach-Object {
    "$([long]$_.id)`t$([string]$_.name)`t$([long]$_.size)"
  })
  $actualRecords = @($actualAssets | ForEach-Object {
    "$([long]$_.id)`t$([string]$_.name)`t$([long]$_.size)"
  })
  foreach ($record in $previousRecords) {
    if ($actualRecords -cnotcontains $record) {
      throw "An existing draft asset changed during upload."
    }
  }
  $added = @($actualAssets | Where-Object { $previousRecords -cnotcontains "$([long]$_.id)`t$([string]$_.name)`t$([long]$_.size)" })
  if ($added.Count -ne 1 -or [string]$added[0].name -cne $UploadedName -or
      [long]$added[0].size -ne $UploadedSize -or [long]$added[0].id -le 0) {
    throw "The draft asset upload did not produce the exact expected transition."
  }
  return $actualAssets
}

function New-ReleaseVerificationTempDirectory {
  $root = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
  $directory = [IO.Path]::GetFullPath((Join-Path $root ("lawyer-assistance-release-" + [Guid]::NewGuid().ToString("N"))))
  $prefix = $root.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  if (-not $directory.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "The release verification directory escaped the system temporary directory."
  }
  New-Item -ItemType Directory -Path $directory | Out-Null
  return $directory
}

function Remove-ReleaseVerificationTempDirectory([string]$Directory) {
  $root = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
  $resolved = [IO.Path]::GetFullPath($Directory)
  $prefix = $root.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
      [IO.Path]::GetFileName($resolved) -cnotmatch '^lawyer-assistance-release-[0-9a-f]{32}$') {
    throw "Refusing unsafe release verification cleanup."
  }
  if (Test-Path -LiteralPath $resolved -PathType Container) {
    Remove-Item -LiteralPath $resolved -Recurse -Force
  }
}

function Copy-ReleaseFileCreateNew {
  param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Destination,
    [Parameter(Mandatory = $true)][string]$Label
  )

  Assert-ReleaseOrdinaryFile $Source $Label
  if (Test-Path -LiteralPath $Destination) {
    throw "$Label snapshot destination already exists."
  }
  $input = $null
  $output = $null
  try {
    $input = [IO.File]::Open(
      [IO.Path]::GetFullPath($Source),
      [IO.FileMode]::Open,
      [IO.FileAccess]::Read,
      [IO.FileShare]::Read
    )
    $output = [IO.File]::Open(
      [IO.Path]::GetFullPath($Destination),
      [IO.FileMode]::CreateNew,
      [IO.FileAccess]::Write,
      [IO.FileShare]::None
    )
    $input.CopyTo($output)
    $output.Flush($true)
  } finally {
    if ($null -ne $output) { $output.Dispose() }
    if ($null -ne $input) { $input.Dispose() }
  }
  Assert-ReleaseOrdinaryFile $Destination "$Label snapshot"
}

function New-ReleaseAssetSnapshot {
  param(
    [Parameter(Mandatory = $true)][string]$SourceDirectory,
    [Parameter(Mandatory = $true)][string[]]$Names,
    [Parameter(Mandatory = $true)][string]$TemporaryDirectory
  )

  Assert-ReleaseAssetDirectory $SourceDirectory $Names
  $snapshot = Join-Path $TemporaryDirectory "verified-assets"
  New-Item -ItemType Directory -Path $snapshot | Out-Null
  foreach ($name in $Names) {
    Copy-ReleaseFileCreateNew `
      (Join-Path $SourceDirectory $name) (Join-Path $snapshot $name) "Release asset $name"
  }
  Assert-ReleaseAssetDirectory $snapshot $Names
  return $snapshot
}

function Lock-ReleaseAssetSnapshot {
  param(
    [Parameter(Mandatory = $true)][string]$SnapshotDirectory,
    [Parameter(Mandatory = $true)][string[]]$Names
  )

  Assert-ReleaseAssetDirectory $SnapshotDirectory $Names
  $handles = [Collections.Generic.List[IDisposable]]::new()
  try {
    foreach ($name in $Names) {
      $handles.Add([IO.File]::Open(
        (Join-Path $SnapshotDirectory $name),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
      ))
    }
    return $handles
  } catch {
    foreach ($handle in $handles) { $handle.Dispose() }
    throw
  }
}

function Close-ReleaseAssetSnapshotLocks($Handles) {
  if ($null -eq $Handles) { return }
  foreach ($handle in $Handles) { $handle.Dispose() }
}

function Assert-ReleaseVerificationReport {
  param(
    [Parameter(Mandatory = $true)]$Report,
    [Parameter(Mandatory = $true)][ValidateSet("app", "mineru")][string]$Kind,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$ExpectedCommit,
    [Parameter(Mandatory = $true)][string[]]$ExpectedNames
  )

  $actualNames = @($Report.assetNames | ForEach-Object { [string]$_ })
  if ($Report.ok -ne $true -or [string]$Report.kind -cne $Kind -or
      [string]$Report.version -cne $Version -or
      [string]$Report.expectedCommit -cne $ExpectedCommit -or
      [int]$Report.assetCount -ne $ExpectedNames.Count -or
      ($actualNames -join "`n") -cne ($ExpectedNames -join "`n")) {
    throw "The release asset verifier report did not bind the exact kind, version, HEAD, and ordered allowlist."
  }
}

function Assert-RemoteAssetMatchesLocal {
  param(
    [Parameter(Mandatory = $true)]$Asset,
    [Parameter(Mandatory = $true)][string]$LocalPath,
    [Parameter(Mandatory = $true)][string]$DownloadDirectory,
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][scriptblock]$GhDownload
  )

  Assert-ReleaseOrdinaryFile $LocalPath "Local release asset"
  $local = Get-Item -LiteralPath $LocalPath
  if ([long]$Asset.size -ne $local.Length -or [long]$Asset.id -le 0) {
    throw "The remote release asset size differs from the local asset."
  }
  $download = Join-Path $DownloadDirectory ([string]$Asset.name)
  & $GhDownload $Repository ([long]$Asset.id) $download
  Assert-ReleaseOrdinaryFile $download "Downloaded release asset"
  if ((Get-Item -LiteralPath $download).Length -ne $local.Length -or
      (Get-ReleaseSha256 $download) -cne (Get-ReleaseSha256 $LocalPath)) {
    throw "The remote release asset SHA-256 differs from the local asset."
  }
}

function Invoke-ReleaseRemoteReadback {
  param(
    [Parameter(Mandatory = $true)][string]$ProjectRoot,
    [Parameter(Mandatory = $true)][string]$ContractPath,
    [Parameter(Mandatory = $true)][ValidateSet("App", "MinerU")][string]$Kind,
    [Parameter(Mandatory = $true)][string]$LocalAssetDirectory,
    [string]$GitExecutable = "git",
    [string]$GhExecutable = "gh",
    [scriptblock]$GitText,
    [scriptblock]$GhText,
    [scriptblock]$GhDownload,
    [scriptblock]$AssetVerifier,
    [scriptblock]$AuthenticodeVerifier
  )

  $root = [IO.Path]::GetFullPath($ProjectRoot)
  $localRoot = [IO.Path]::GetFullPath($LocalAssetDirectory)
  $contract = Read-ReleasePublicationContract $ContractPath
  Assert-ReleaseGitHubHostEnvironment
  $tag = if ($Kind -ceq "App") { $contract.AppTag } else { $contract.MinerUTag }
  $title = if ($Kind -ceq "App") {
    "Lawyer Assistance $($contract.Version)"
  } else {
    "MinerU components $($contract.Version)"
  }
  $notesPath = Join-Path $root "RELEASE_NOTES.md"
  $expectedBody = Read-ReleaseNotesBody $root $notesPath
  $names = @(Get-ReleasePublicationAssetNames $contract $Kind $localRoot)
  Assert-ReleaseAssetDirectory $localRoot $names
  if ($null -eq $GitText) {
    $GitText = { param([string[]]$Arguments) Invoke-ReleaseTextCommand $GitExecutable $Arguments "Git release query" }.GetNewClosure()
  }
  if ($null -eq $GhText) {
    $GhText = { param([string[]]$Arguments) Invoke-ReleaseTextCommand $GhExecutable $Arguments "GitHub release query" }.GetNewClosure()
  }
  if ($null -eq $GhDownload) {
    $GhDownload = {
      param([string]$Repository, [long]$AssetId, [string]$Destination)
      Invoke-ReleaseGhAssetDownload $GhExecutable $Repository $AssetId $Destination
    }.GetNewClosure()
  }
  $tagEvidence = Assert-RemoteAnnotatedReleaseTag $root $contract.RepositoryUrl $tag $GitText
  $head = [string]$tagEvidence.Head
  $temporary = New-ReleaseVerificationTempDirectory
  $snapshotLocks = $null
  try {
    $verificationRoot = New-ReleaseAssetSnapshot $localRoot $names $temporary
    $snapshotLocks = Lock-ReleaseAssetSnapshot $verificationRoot $names
    $release = Get-GitHubReleaseForTag $contract.Repository $tag $GhText
    $assets = @(Assert-DraftReleaseAssets $release $tag $names $title $expectedBody)
    $remoteNames = @($assets | ForEach-Object { [string]$_.name } | Sort-Object -CaseSensitive)
    if (($remoteNames -join "`n") -cne ((@($names | Sort-Object -CaseSensitive)) -join "`n")) {
      throw "The remote release does not contain the exact allowlist."
    }
    $releaseAssetEvidence = Get-ReleaseAssetInventoryEvidence $assets
    $downloadDirectory = Join-Path $temporary "downloads"
    New-Item -ItemType Directory -Path $downloadDirectory | Out-Null
    foreach ($asset in $assets) {
      $name = [string]$asset.name
      $destination = Join-Path $downloadDirectory $name
      & $GhDownload $contract.Repository ([long]$asset.id) $destination
      Assert-ReleaseOrdinaryFile $destination "Downloaded release asset $name"
      $local = Join-Path $verificationRoot $name
      if ((Get-Item -LiteralPath $destination).Length -ne (Get-Item -LiteralPath $local).Length -or
          (Get-ReleaseSha256 $destination) -cne (Get-ReleaseSha256 $local)) {
        throw "The server-readback asset differs from the local verified asset."
      }
    }

    Assert-RemoteAnnotatedReleaseTagUnchanged `
      $root $contract.RepositoryUrl $tag $GitText $tagEvidence | Out-Null
    Assert-DraftReleaseUnchanged `
      $contract.Repository $tag $names $GhText $release $releaseAssetEvidence $title $expectedBody | Out-Null

    $verificationOutput = Join-Path $temporary "authenticode"
    $verifierPath = Join-Path $root "scripts\verify_release_assets.py"
    if ($null -eq $AssetVerifier) {
      Assert-ReleaseOrdinaryFile $verifierPath "Release asset verifier"
      $AssetVerifier = {
        param(
          [string]$KindValue,
          [string]$DirectoryValue,
          [string]$ContractValue,
          [string]$CommitValue,
          [string]$VerificationOutputValue
        )
        $arguments = @(
          $verifierPath,
          "--kind", $KindValue,
          "--directory", $DirectoryValue,
          "--contract", $ContractValue,
          "--expected-commit", $CommitValue
        )
        if (-not [string]::IsNullOrEmpty($VerificationOutputValue)) {
          $arguments += @("--verification-output", $VerificationOutputValue)
        }
        Invoke-ReleaseTextCommand "python" $arguments "Server-readback release asset verification"
      }.GetNewClosure()
    }
    $outputArgument = if ($Kind -ceq "App") { $verificationOutput } else { "" }
    $verificationJson = & $AssetVerifier `
      $Kind.ToLowerInvariant() $downloadDirectory ([IO.Path]::GetFullPath($ContractPath)) $head $outputArgument
    try {
      $verification = $verificationJson | ConvertFrom-Json
    } catch {
      throw "The server-readback verifier returned invalid evidence."
    }
    Assert-ReleaseVerificationReport `
      $verification $Kind.ToLowerInvariant() $contract.Version $head $names

    if ($Kind -ceq "App") {
      $authenticodeFiles = @($verification.authenticodeFiles | ForEach-Object { [string]$_ })
      if ($authenticodeFiles.Count -ne 3) {
        throw "The App readback did not expose the installer, portable App, and paired MCP for Authenticode verification."
      }
      $expectedAuthenticodeNames = @(
        "Lawyer.Assistance_$($contract.Version)_x64-setup.exe"
        "portable-lawyer-assistance.exe"
        "portable-lawyer-assistance-mcp.exe"
      )
      $actualAuthenticodeNames = @($authenticodeFiles | ForEach-Object { [IO.Path]::GetFileName($_) })
      if (($actualAuthenticodeNames -join "`n") -cne ($expectedAuthenticodeNames -join "`n")) {
        throw "The App readback Authenticode roles do not match the exact installer, portable App, and paired MCP set."
      }
      if ($null -eq $AuthenticodeVerifier) {
        $AuthenticodeVerifier = {
          param([string]$Path)
          if (-not (Test-LawyerAssistanceRfc3161Authenticode -Path $Path)) {
            throw "An App readback executable lacks a valid Authenticode signature and RFC3161 timestamp."
          }
          $signer = Get-LawyerAssistanceAuthenticodeSignerThumbprint $Path
          if ([string]::IsNullOrEmpty($signer)) {
            throw "An App readback executable lacks canonical publisher evidence."
          }
          return $signer
        }
      }
      $expectedOutputRoot = [IO.Path]::GetFullPath($verificationOutput).TrimEnd('\') + '\'
      $seen = @{}
      $publisherThumbprint = ""
      foreach ($path in $authenticodeFiles) {
        $resolved = [IO.Path]::GetFullPath($path)
        if (-not $resolved.StartsWith($expectedOutputRoot, [StringComparison]::OrdinalIgnoreCase)) {
          throw "An Authenticode verification file escaped the fresh output directory."
        }
        Assert-ReleaseOrdinaryFile $resolved "Readback Authenticode file"
        $folded = [IO.Path]::GetFileName($resolved).ToLowerInvariant()
        if ($seen.ContainsKey($folded)) { throw "The Authenticode output contains a case alias." }
        $seen[$folded] = $true
        $signer = [string](& $AuthenticodeVerifier $resolved)
        if ($signer -notmatch '^[0-9A-Fa-f]{40}$') {
          throw "The Authenticode verifier did not return canonical publisher evidence."
        }
        $signer = $signer.ToUpperInvariant()
        if ([string]::IsNullOrEmpty($publisherThumbprint)) {
          $publisherThumbprint = $signer
        } elseif ($signer -cne $publisherThumbprint) {
          throw "The installer, portable App, and paired MCP do not share one publisher certificate."
        }
      }
    } elseif (@($verification.authenticodeFiles).Count -ne 0) {
      throw "The MinerU verifier unexpectedly exposed Authenticode files."
    }
    Assert-RemoteAnnotatedReleaseTagUnchanged `
      $root $contract.RepositoryUrl $tag $GitText $tagEvidence | Out-Null
    Assert-DraftReleaseUnchanged `
      $contract.Repository $tag $names $GhText $release $releaseAssetEvidence $title $expectedBody | Out-Null
  } finally {
    Close-ReleaseAssetSnapshotLocks $snapshotLocks
    Remove-ReleaseVerificationTempDirectory $temporary
  }

  return [pscustomobject][ordered]@{
    resultCode = "REL-SERVER-READBACK-VERIFIED"
    repository = $contract.Repository
    tag = $tag
    commit = $head
    assetCount = $names.Count
    draft = $true
  }
}

function Invoke-ReleaseDraftPublication {
  param(
    [Parameter(Mandatory = $true)][string]$ProjectRoot,
    [Parameter(Mandatory = $true)][string]$ContractPath,
    [Parameter(Mandatory = $true)][ValidateSet("App", "MinerU")][string]$Kind,
    [Parameter(Mandatory = $true)][string]$AssetDirectory,
    [Parameter(Mandatory = $true)][string]$NotesFile,
    [string]$GitExecutable = "git",
    [string]$GhExecutable = "gh",
    [scriptblock]$GitText,
    [scriptblock]$GhText,
    [scriptblock]$GhDownload,
    [scriptblock]$AssetVerifier
  )

  $root = [IO.Path]::GetFullPath($ProjectRoot)
  $assetRoot = [IO.Path]::GetFullPath($AssetDirectory)
  $expectedBody = Read-ReleaseNotesBody $root $NotesFile
  $contract = Read-ReleasePublicationContract $ContractPath
  Assert-ReleaseGitHubHostEnvironment
  $tag = if ($Kind -ceq "App") { $contract.AppTag } else { $contract.MinerUTag }
  $title = if ($Kind -ceq "App") {
    "Lawyer Assistance $($contract.Version)"
  } else {
    "MinerU components $($contract.Version)"
  }
  $names = @(Get-ReleasePublicationAssetNames $contract $Kind $assetRoot)
  Assert-ReleaseAssetDirectory $assetRoot $names

  if ($null -eq $GitText) {
    $GitText = { param([string[]]$Arguments) Invoke-ReleaseTextCommand $GitExecutable $Arguments "Git release query" }.GetNewClosure()
  }
  if ($null -eq $GhText) {
    $GhText = { param([string[]]$Arguments) Invoke-ReleaseTextCommand $GhExecutable $Arguments "GitHub release operation" }.GetNewClosure()
  }
  if ($null -eq $GhDownload) {
    $GhDownload = {
      param([string]$Repository, [long]$AssetId, [string]$Destination)
      Invoke-ReleaseGhAssetDownload $GhExecutable $Repository $AssetId $Destination
    }.GetNewClosure()
  }

  $tagEvidence = Assert-RemoteAnnotatedReleaseTag $root $contract.RepositoryUrl $tag $GitText
  $head = [string]$tagEvidence.Head
  $temporary = New-ReleaseVerificationTempDirectory
  $snapshotLocks = $null
  $notesLock = $null
  try {
    $publicationRoot = New-ReleaseAssetSnapshot $assetRoot $names $temporary
    $snapshotLocks = Lock-ReleaseAssetSnapshot $publicationRoot $names
    $snapshotNotes = Join-Path $temporary "release-notes.md"
    Copy-ReleaseFileCreateNew ([IO.Path]::GetFullPath($NotesFile)) $snapshotNotes "Release notes"
    $notesLock = [IO.File]::Open(
      $snapshotNotes,
      [IO.FileMode]::Open,
      [IO.FileAccess]::Read,
      [IO.FileShare]::Read
    )

    $assetVerifierPath = Join-Path $root "scripts\verify_release_assets.py"
    $verificationKind = $Kind.ToLowerInvariant()
    if ($null -eq $AssetVerifier) {
      Assert-ReleaseOrdinaryFile $assetVerifierPath "Release asset verifier"
      $AssetVerifier = {
        param([string]$KindValue, [string]$DirectoryValue, [string]$ContractValue, [string]$CommitValue)
        Invoke-ReleaseTextCommand "python" @(
          $assetVerifierPath,
          "--kind", $KindValue,
          "--directory", $DirectoryValue,
          "--contract", $ContractValue,
          "--expected-commit", $CommitValue
        ) "Local release asset verification"
      }.GetNewClosure()
    }
    $verification = & $AssetVerifier `
      $verificationKind $publicationRoot ([IO.Path]::GetFullPath($ContractPath)) $head
    try {
      $verificationReport = $verification | ConvertFrom-Json
    } catch {
      throw "The local release asset verifier returned invalid evidence."
    }
    Assert-ReleaseVerificationReport `
      $verificationReport $verificationKind $contract.Version $head $names

    Assert-RemoteAnnotatedReleaseTagUnchanged `
      $root $contract.RepositoryUrl $tag $GitText $tagEvidence | Out-Null
    $release = Get-GitHubReleaseForTag $contract.Repository $tag $GhText
    if ($null -eq $release) {
      Assert-RemoteAnnotatedReleaseTagUnchanged `
        $root $contract.RepositoryUrl $tag $GitText $tagEvidence | Out-Null
      & $GhText -Arguments @(
        "release", "create", $tag, "-R", $contract.Repository, "--draft", "--verify-tag",
        "--title", $title, "--notes-file", $snapshotNotes
      ) | Out-Null
      Assert-RemoteAnnotatedReleaseTagUnchanged `
        $root $contract.RepositoryUrl $tag $GitText $tagEvidence | Out-Null
      $release = Get-GitHubReleaseForTag $contract.Repository $tag $GhText
      if ($null -eq $release) {
        throw "The draft GitHub Release was not observable after creation."
      }
    }

    $assets = @(Assert-DraftReleaseAssets $release $tag $names $title $expectedBody)
    foreach ($asset in $assets) {
      Assert-RemoteAssetMatchesLocal `
        $asset (Join-Path $publicationRoot ([string]$asset.name)) $temporary $contract.Repository $GhDownload
    }
    $remoteNames = @($assets | ForEach-Object { [string]$_.name })
    foreach ($name in $names) {
      if ($remoteNames -ccontains $name) { continue }
      Assert-RemoteAnnotatedReleaseTagUnchanged `
        $root $contract.RepositoryUrl $tag $GitText $tagEvidence | Out-Null
      $currentRelease = Assert-DraftReleaseUnchanged `
        $contract.Repository $tag $names $GhText $release "" $title $expectedBody
      $release = $currentRelease.Release
      & $GhText -Arguments @(
        "release", "upload", $tag, (Join-Path $publicationRoot $name), "-R", $contract.Repository
      ) | Out-Null
      Assert-RemoteAnnotatedReleaseTagUnchanged `
        $root $contract.RepositoryUrl $tag $GitText $tagEvidence | Out-Null
      $nextRelease = Get-GitHubReleaseForTag $contract.Repository $tag $GhText
      Assert-ReleaseUploadTransition `
        $release $nextRelease $tag $names $name (Get-Item -LiteralPath (Join-Path $publicationRoot $name)).Length $title $expectedBody | Out-Null
      $release = $nextRelease
    }

    Assert-RemoteAnnotatedReleaseTagUnchanged `
      $root $contract.RepositoryUrl $tag $GitText $tagEvidence | Out-Null
    $release = Get-GitHubReleaseForTag $contract.Repository $tag $GhText
    $assets = @(Assert-DraftReleaseAssets $release $tag $names $title $expectedBody)
    $finalRelease = $release
    $finalAssetEvidence = Get-ReleaseAssetInventoryEvidence $assets
    $finalNames = @($assets | ForEach-Object { [string]$_.name } | Sort-Object -CaseSensitive)
    if (($finalNames -join "`n") -cne ((@($names | Sort-Object -CaseSensitive)) -join "`n")) {
      throw "The draft GitHub Release does not contain the exact completed allowlist."
    }
    $secondTemporary = New-ReleaseVerificationTempDirectory
    try {
      foreach ($asset in $assets) {
        Assert-RemoteAssetMatchesLocal `
          $asset (Join-Path $publicationRoot ([string]$asset.name)) $secondTemporary $contract.Repository $GhDownload
      }
    } finally {
      Remove-ReleaseVerificationTempDirectory $secondTemporary
    }
    Assert-RemoteAnnotatedReleaseTagUnchanged `
      $root $contract.RepositoryUrl $tag $GitText $tagEvidence | Out-Null
    Assert-DraftReleaseUnchanged `
      $contract.Repository $tag $names $GhText $finalRelease $finalAssetEvidence $title $expectedBody | Out-Null
  } finally {
    if ($null -ne $notesLock) { $notesLock.Dispose() }
    Close-ReleaseAssetSnapshotLocks $snapshotLocks
    Remove-ReleaseVerificationTempDirectory $temporary
  }

  return [pscustomobject][ordered]@{
    resultCode = "REL-DRAFT-ASSETS-VERIFIED"
    repository = $contract.Repository
    tag = $tag
    commit = $head
    assetCount = $names.Count
    draft = $true
  }
}
