[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][ValidateSet("App", "MinerU")][string]$Kind,
  [Parameter(Mandatory = $true)][string]$LocalAssetDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "release_publication_common.ps1")

$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$contractPath = Join-Path $PSScriptRoot "release-contract-v0.4.0.json"
try {
  $result = Invoke-ReleaseRemoteReadback `
    -ProjectRoot $projectRoot `
    -ContractPath $contractPath `
    -Kind $Kind `
    -LocalAssetDirectory $LocalAssetDirectory
  $result | ConvertTo-Json -Depth 4
  exit 0
} catch {
  [Console]::Error.WriteLine("[REL-SERVER-READBACK-FAILED] $($_.Exception.Message)")
  exit 71
}
