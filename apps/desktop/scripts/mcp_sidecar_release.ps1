Set-StrictMode -Version Latest

function Get-LawyerAssistanceMcpReleasePaths([string]$ProjectRoot) {
  $root = [IO.Path]::GetFullPath($ProjectRoot)
  return [ordered]@{
    ReleaseBinary = Join-Path $root "target\x86_64-pc-windows-msvc\release\lawyer-assistance-mcp.exe"
    TauriSidecar = Join-Path $root "apps\desktop\src-tauri\binaries\lawyer-assistance-mcp-x86_64-pc-windows-msvc.exe"
    InstalledSibling = "lawyer-assistance-mcp.exe"
  }
}

function Assert-LawyerAssistanceMcpReleaseBinary(
  [string]$Path,
  [string]$Version,
  [DateTimeOffset]$BuildStartedAt,
  [DateTimeOffset]$BuildCompletedAt
) {
  $resolved = [IO.Path]::GetFullPath($Path)
  $item = Get-Item -LiteralPath $resolved -ErrorAction SilentlyContinue
  if (-not $item -or $item.Name -cne "lawyer-assistance-mcp.exe") {
    throw "Fresh fixed-name MCP release binary is missing: $resolved"
  }
  if ($item.LastWriteTimeUtc -lt $BuildStartedAt.UtcDateTime.AddSeconds(-2) -or
      $item.LastWriteTimeUtc -gt $BuildCompletedAt.UtcDateTime.AddSeconds(5)) {
    throw "MCP release binary is outside this build invocation: $resolved"
  }
  Assert-LawyerAssistanceSingleLinkFile $resolved
  $previousLog = $env:LAWYER_ASSISTANCE_MCP_LOG
  $env:LAWYER_ASSISTANCE_MCP_LOG = "off"
  try {
    $versionOutput = @(& $resolved --version 2>&1)
    if ($LASTEXITCODE -ne 0 -or $versionOutput.Count -ne 1 -or
        [string]$versionOutput[0] -cne "lawyer-assistance-mcp $Version") {
      throw "MCP release binary version does not exactly match $Version"
    }
  } finally {
    if ($null -eq $previousLog) {
      Remove-Item Env:LAWYER_ASSISTANCE_MCP_LOG -ErrorAction SilentlyContinue
    } else {
      $env:LAWYER_ASSISTANCE_MCP_LOG = $previousLog
    }
  }
  $hash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($hash -notmatch '^[0-9a-f]{64}$') { throw "MCP release binary hash is invalid" }
  return [ordered]@{
    path = $resolved
    siblingPath = "lawyer-assistance-mcp.exe"
    version = $Version
    size = $item.Length
    sha256 = $hash
  }
}

function ConvertTo-LawyerAssistanceIndependentMcpBinary([string]$Path) {
  $resolved = [IO.Path]::GetFullPath($Path)
  if ([IO.Path]::GetFileName($resolved) -cne "lawyer-assistance-mcp.exe" -or
      -not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
    throw "Cannot materialize an unexpected MCP release binary path"
  }
  if ((Get-LawyerAssistanceHardLinkCount $resolved) -eq 1) { return }
  $parent = Split-Path -Parent $resolved
  $temporary = Join-Path $parent ".lawyer-assistance-mcp.$PID.$([Guid]::NewGuid().ToString('N')).materialized.exe"
  $backup = Join-Path $parent ".lawyer-assistance-mcp.$PID.$([Guid]::NewGuid().ToString('N')).linked-backup.exe"
  try {
    Install-LawyerAssistanceIndependentFile $resolved $temporary
    [IO.File]::Replace($temporary, $resolved, $backup, $true)
    Remove-Item -LiteralPath $backup -Force
    Assert-LawyerAssistanceSingleLinkFile $resolved
  } finally {
    foreach ($candidate in @($temporary, $backup)) {
      if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        Remove-Item -LiteralPath $candidate -Force
      }
    }
  }
}

function Install-LawyerAssistanceMcpTauriSidecar(
  [string]$Source,
  [string]$Destination
) {
  $destinationPath = [IO.Path]::GetFullPath($Destination)
  if ([IO.Path]::GetFileName($destinationPath) -cne
      "lawyer-assistance-mcp-x86_64-pc-windows-msvc.exe") {
    throw "Tauri MCP sidecar path has an unexpected filename"
  }
  Install-LawyerAssistanceIndependentFile $Source $destinationPath
  $sourceHash = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash.ToLowerInvariant()
  $destinationHash = (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($sourceHash -ne $destinationHash) { throw "Tauri MCP sidecar differs from release binary" }
}

function Remove-LawyerAssistanceMcpTauriSidecar([string]$Path) {
  $resolved = [IO.Path]::GetFullPath($Path)
  if ([IO.Path]::GetFileName($resolved) -cne
      "lawyer-assistance-mcp-x86_64-pc-windows-msvc.exe") {
    throw "Refusing to remove an unexpected MCP sidecar path"
  }
  if (Test-Path -LiteralPath $resolved -PathType Leaf) {
    Remove-Item -LiteralPath $resolved -Force
  }
}
