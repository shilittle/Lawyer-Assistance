Set-StrictMode -Version Latest

function Get-LawyerAssistanceHardLinkCount([string]$Path) {
  $resolved = [IO.Path]::GetFullPath($Path)
  if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
    throw "Cannot inspect hard links for a missing file: $resolved"
  }
  $lines = @(& fsutil hardlink list $resolved 2>$null)
  if ($LASTEXITCODE -ne 0) {
    throw "Unable to inspect hard links for: $resolved"
  }
  return @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
}

function Assert-LawyerAssistanceSingleLinkFile([string]$Path) {
  $count = Get-LawyerAssistanceHardLinkCount $Path
  if ($count -ne 1) {
    throw "Release file must have an independent filesystem identity: $Path (links: $count)"
  }
}

function Install-LawyerAssistanceIndependentFile(
  [string]$Source,
  [string]$Destination
) {
  $sourcePath = [IO.Path]::GetFullPath($Source)
  $destinationPath = [IO.Path]::GetFullPath($Destination)
  if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    throw "Independent-copy source is missing: $sourcePath"
  }
  if ($sourcePath.Equals($destinationPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Independent-copy source and destination must differ"
  }

  $parent = Split-Path -Parent $destinationPath
  New-Item -ItemType Directory -Path $parent -Force | Out-Null
  $temporary = Join-Path $parent (".{0}.{1}.{2}.independent-copy" -f
    [IO.Path]::GetFileName($destinationPath),
    $PID,
    [Guid]::NewGuid().ToString("N"))
  $replacedBackup = Join-Path $parent (".{0}.{1}.{2}.replaced-link" -f
    [IO.Path]::GetFileName($destinationPath),
    $PID,
    [Guid]::NewGuid().ToString("N"))

  $sourceStream = $null
  $destinationStream = $null
  try {
    try {
      $sourceStream = [IO.File]::Open(
        $sourcePath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
      )
      $destinationStream = [IO.File]::Open(
        $temporary,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
      )
      $sourceStream.CopyTo($destinationStream, 4MB)
      $destinationStream.Flush($true)
    } finally {
      if ($null -ne $destinationStream) {
        $destinationStream.Dispose()
        $destinationStream = $null
      }
      if ($null -ne $sourceStream) {
        $sourceStream.Dispose()
        $sourceStream = $null
      }
    }

    [IO.File]::SetLastWriteTimeUtc($temporary, [IO.File]::GetLastWriteTimeUtc($sourcePath))
    Assert-LawyerAssistanceSingleLinkFile $temporary
    if (Test-Path -LiteralPath $destinationPath -PathType Leaf) {
      [IO.File]::Replace($temporary, $destinationPath, $replacedBackup, $true)
      Remove-Item -LiteralPath $replacedBackup -Force
    } else {
      [IO.File]::Move($temporary, $destinationPath)
    }
    Assert-LawyerAssistanceSingleLinkFile $destinationPath
  } catch {
    throw "Independent release copy failed: $($_.Exception.Message)"
  } finally {
    if ($null -ne $destinationStream) { $destinationStream.Dispose() }
    if ($null -ne $sourceStream) { $sourceStream.Dispose() }
    if (Test-Path -LiteralPath $temporary -PathType Leaf) {
      Remove-Item -LiteralPath $temporary -Force
    }
    if (Test-Path -LiteralPath $replacedBackup -PathType Leaf) {
      Remove-Item -LiteralPath $replacedBackup -Force
    }
  }
}
