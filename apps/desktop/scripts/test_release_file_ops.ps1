$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "release_file_ops.ps1")

$root = Join-Path ([IO.Path]::GetTempPath()) ("lawyer-assistance-release-file-test-{0}" -f [Guid]::NewGuid().ToString("N"))
$resolvedRoot = [IO.Path]::GetFullPath($root)
$tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
if (-not $resolvedRoot.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Test directory escaped the system temporary directory"
}

try {
  New-Item -ItemType Directory -Path $resolvedRoot | Out-Null
  $source = Join-Path $resolvedRoot "source.sqlite"
  $alias = Join-Path $resolvedRoot "source-alias.sqlite"
  $destination = Join-Path $resolvedRoot "release\resources\legal_core.sqlite"
  [IO.File]::WriteAllText($source, "formal legal database fixture")
  New-Item -ItemType HardLink -Path $alias -Target $source | Out-Null
  if ((Get-LawyerAssistanceHardLinkCount $source) -ne 2) {
    throw "Test precondition did not create a hard-linked source"
  }

  Install-LawyerAssistanceIndependentFile $source $destination
  Assert-LawyerAssistanceSingleLinkFile $destination
  if ([IO.File]::ReadAllText($destination) -cne "formal legal database fixture") {
    throw "Independent copy changed file content"
  }

  [IO.File]::WriteAllText($source, "updated formal legal database fixture")
  Install-LawyerAssistanceIndependentFile $source $destination
  Assert-LawyerAssistanceSingleLinkFile $destination
  if ([IO.File]::ReadAllText($destination) -cne "updated formal legal database fixture") {
    throw "Independent replacement changed file content"
  }

  $frontendPlaceholder = Join-Path $resolvedRoot "frontend-dist\.gitkeep"
  Restore-LawyerAssistanceFrontendPlaceholder $frontendPlaceholder
  $placeholderBytes = [IO.File]::ReadAllBytes($frontendPlaceholder)
  if ($placeholderBytes.Length -ge 3 -and
      $placeholderBytes[0] -eq 0xEF -and
      $placeholderBytes[1] -eq 0xBB -and
      $placeholderBytes[2] -eq 0xBF) {
    throw "Frontend placeholder must be UTF-8 without BOM"
  }
  $placeholderText = [Text.Encoding]::UTF8.GetString($placeholderBytes)
  if ($placeholderText -cne "# Production builds replace this placeholder with verified frontend assets.`n") {
    throw "Frontend placeholder content drifted from the tracked canonical bytes"
  }

  Write-Output "release independent-file copy test passed"
} finally {
  if (Test-Path -LiteralPath $resolvedRoot) {
    Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
  }
}
