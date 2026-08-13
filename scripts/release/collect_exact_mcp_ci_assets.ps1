[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[0-9a-f]{40}$')]
  [string]$ExpectedCommit
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "collect_exact_mcp_ci_assets_common.ps1")

$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$contractPath = Join-Path $PSScriptRoot "release-contract-v0.4.0.json"

try {
  $operations = New-LawyerAssistanceExactMcpProductionOperations $projectRoot $contractPath
  $result = Invoke-LawyerAssistanceExactMcpCiCollectionCore $projectRoot $ExpectedCommit $operations
  Write-Output ($result | ConvertTo-Json -Depth 8 -Compress)
} catch {
  [Console]::Error.WriteLine("[REL-MCP-CI-ASSEMBLY-FAILED] $($_.Exception.Message)")
  exit 1
}
