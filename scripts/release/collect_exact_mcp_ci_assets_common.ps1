Set-StrictMode -Version Latest

$script:ExactMcpTargets = @(
  "x86_64-pc-windows-msvc",
  "x86_64-unknown-linux-gnu",
  "aarch64-apple-darwin"
)

function Get-LawyerAssistanceExactMcpArtifactNames {
  return @($script:ExactMcpTargets | ForEach-Object { "lawyer-assistance-mcp-$_" })
}

function Get-LawyerAssistanceExactMcpReleaseNames([string]$Version) {
  if ($Version -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
    throw "The formal MCP release version is invalid."
  }
  $names = @()
  foreach ($target in $script:ExactMcpTargets) {
    $suffix = if ($target -ceq "x86_64-pc-windows-msvc") { ".zip" } else { ".tar.gz" }
    $archive = "lawyer-assistance-mcp-v$Version-$target$suffix"
    $names += $archive
    $names += "$archive.sha256"
  }
  return $names
}

function Assert-LawyerAssistanceExactOrdinaryFile {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Label
  )

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "$Label is missing."
  }
  $item = Get-Item -LiteralPath $Path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -le 0) {
    throw "$Label must be a nonempty ordinary file."
  }
  return $item
}

function Assert-LawyerAssistanceExactOrdinaryDirectory {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Label
  )

  if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw "$Label is missing."
  }
  $item = Get-Item -LiteralPath $Path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Label must be an ordinary directory."
  }
  return $item
}

function Assert-LawyerAssistanceExactFlatAssetDirectory {
  param(
    [Parameter(Mandatory = $true)][string]$Directory,
    [Parameter(Mandatory = $true)][string[]]$ExpectedNames,
    [Parameter(Mandatory = $true)][string]$Label
  )

  [void](Assert-LawyerAssistanceExactOrdinaryDirectory $Directory $Label)
  if ($ExpectedNames.Count -eq 0 -or
      @($ExpectedNames | Sort-Object -CaseSensitive -Unique).Count -ne $ExpectedNames.Count -or
      @($ExpectedNames | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique).Count -ne $ExpectedNames.Count) {
    throw "$Label expected inventory contains duplicate or case-aliased names."
  }
  foreach ($name in $ExpectedNames) {
    if ([string]::IsNullOrWhiteSpace($name) -or [IO.Path]::GetFileName($name) -cne $name) {
      throw "$Label expected inventory contains a non-basename."
    }
  }

  $items = @(Get-ChildItem -LiteralPath $Directory -Force)
  $actualFolded = @($items | ForEach-Object { $_.Name.ToLowerInvariant() })
  if (@($actualFolded | Sort-Object -Unique).Count -ne $actualFolded.Count) {
    throw "$Label contains duplicate or case-aliased members."
  }
  if (@($items | Where-Object { $_.PSIsContainer }).Count -ne 0) {
    throw "$Label must be flat and must not contain nested directories."
  }
  $actual = @($items | ForEach-Object { $_.Name } | Sort-Object -CaseSensitive)
  $expected = @($ExpectedNames | Sort-Object -CaseSensitive)
  if (($actual -join "`n") -cne ($expected -join "`n")) {
    throw "$Label does not match the exact asset inventory."
  }
  foreach ($name in $ExpectedNames) {
    [void](Assert-LawyerAssistanceExactOrdinaryFile (Join-Path $Directory $name) "$Label member $name")
  }
}

function Assert-LawyerAssistanceCanonicalSha256 {
  param(
    [Parameter(Mandatory = $true)][string]$Directory,
    [Parameter(Mandatory = $true)][string]$ArchiveName
  )

  $archive = Join-Path $Directory $ArchiveName
  $checksum = Join-Path $Directory "$ArchiveName.sha256"
  [void](Assert-LawyerAssistanceExactOrdinaryFile $archive "MCP release archive $ArchiveName")
  [void](Assert-LawyerAssistanceExactOrdinaryFile $checksum "MCP release checksum $ArchiveName.sha256")
  $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
  $expected = [Text.Encoding]::ASCII.GetBytes("$hash  $ArchiveName`n")
  $actual = [IO.File]::ReadAllBytes($checksum)
  if ($actual.Length -ne $expected.Length -or
      -not [Linq.Enumerable]::SequenceEqual([byte[]]$actual, [byte[]]$expected)) {
    throw "MCP release checksum is not canonical or does not match $ArchiveName."
  }
}

function Copy-LawyerAssistanceExactCreateNew {
  param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Destination
  )

  $sourcePath = [IO.Path]::GetFullPath($Source)
  $destinationPath = [IO.Path]::GetFullPath($Destination)
  $sourceItem = Assert-LawyerAssistanceExactOrdinaryFile $sourcePath "Release copy source"
  if ($sourcePath.Equals($destinationPath, [StringComparison]::OrdinalIgnoreCase) -or
      (Test-Path -LiteralPath $destinationPath)) {
    throw "Release copy destination must be a distinct, absent path."
  }
  [void](Assert-LawyerAssistanceExactOrdinaryDirectory ([IO.Path]::GetDirectoryName($destinationPath)) "Release copy destination directory")

  $sourceHashBefore = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
  $sourceStream = $null
  $destinationStream = $null
  try {
    $sourceStream = [IO.File]::Open(
      $sourcePath,
      [IO.FileMode]::Open,
      [IO.FileAccess]::Read,
      [IO.FileShare]::Read
    )
    $destinationStream = [IO.File]::Open(
      $destinationPath,
      [IO.FileMode]::CreateNew,
      [IO.FileAccess]::Write,
      [IO.FileShare]::None
    )
    $sourceStream.CopyTo($destinationStream, 4MB)
    $destinationStream.Flush($true)
  } catch {
    if ($null -ne $destinationStream) {
      $destinationStream.Dispose()
      $destinationStream = $null
    }
    if (Test-Path -LiteralPath $destinationPath -PathType Leaf) {
      Remove-Item -LiteralPath $destinationPath -Force
    }
    throw "Create-new independent release copy failed: $($_.Exception.Message)"
  } finally {
    if ($null -ne $destinationStream) { $destinationStream.Dispose() }
    if ($null -ne $sourceStream) { $sourceStream.Dispose() }
  }

  $destinationItem = Assert-LawyerAssistanceExactOrdinaryFile $destinationPath "Release copy destination"
  $sourceHashAfter = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
  $destinationHash = (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($sourceHashBefore -cne $sourceHashAfter -or
      $sourceHashBefore -cne $destinationHash -or
      [long]$sourceItem.Length -ne [long]$destinationItem.Length) {
    throw "Release copy source changed or its independent destination differs."
  }
}

function Read-LawyerAssistanceExactAssemblyContract([string]$ContractPath) {
  [void](Assert-LawyerAssistanceExactOrdinaryFile $ContractPath "Release contract")
  try {
    $contract = Get-Content -LiteralPath $ContractPath -Raw -Encoding UTF8 | ConvertFrom-Json
  } catch {
    throw "The release contract is not valid JSON."
  }
  if ([int]$contract.schemaVersion -ne 1 -or
      [string]$contract.repository.owner -cne "shilittle" -or
      [string]$contract.repository.name -cne "Lawyer-Assistance" -or
      [string]$contract.release.formalVersion -cne "0.4.0" -or
      [string]$contract.release.appTag -cne "v0.4.0") {
    throw "The final asset assembly requires the frozen v0.4.0 contract."
  }
  $assets = @($contract.appAssets | ForEach-Object { [string]$_ })
  if ($assets.Count -ne 12 -or
      @($assets | Sort-Object -CaseSensitive -Unique).Count -ne 12 -or
      @($assets | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique).Count -ne 12) {
    throw "The final App asset allowlist must contain 12 unique exact names."
  }
  $expectedMcp = @(Get-LawyerAssistanceExactMcpReleaseNames "0.4.0")
  if ((@($assets[6..11]) -join "`n") -cne ($expectedMcp -join "`n")) {
    throw "The final App asset allowlist MCP suffix differs from the frozen targets."
  }
  return [pscustomobject][ordered]@{
    Repository = "shilittle/Lawyer-Assistance"
    Version = "0.4.0"
    AppNames = @($assets[0..5])
    McpNames = $expectedMcp
    AllNames = $assets
  }
}

function Assert-LawyerAssistanceExactVerificationReport {
  param(
    [Parameter(Mandatory = $true)]$Report,
    [Parameter(Mandatory = $true)]$Contract,
    [Parameter(Mandatory = $true)][string]$ExpectedCommit
  )

  $names = @($Report.assetNames | ForEach-Object { [string]$_ })
  if ($Report.ok -ne $true -or [string]$Report.kind -cne "app" -or
      [string]$Report.version -cne [string]$Contract.Version -or
      [string]$Report.expectedCommit -cne $ExpectedCommit -or
      [int]$Report.assetCount -ne $Contract.AllNames.Count -or
      ($names -join "`n") -cne ($Contract.AllNames -join "`n") -or
      @($Report.authenticodeFiles).Count -ne 0) {
    throw "Final exact App release verifier report is not bound to the kind, version, HEAD, and ordered allowlist."
  }
}

function Assert-LawyerAssistanceExactMcpCollectionOperations([hashtable]$Operations) {
  $expected = @("ListRuns", "ListArtifacts", "DownloadArtifact", "VerifyFinalAssets")
  if ($Operations.Count -ne $expected.Count -or
      @($Operations.Keys | Where-Object { $_ -cnotin $expected }).Count -ne 0) {
    throw "The exact MCP collection operation set is invalid."
  }
  foreach ($name in $expected) {
    if (-not $Operations.ContainsKey($name) -or $Operations[$name] -isnot [scriptblock]) {
      throw "The exact MCP collection operation $name is missing."
    }
  }
}

function Invoke-LawyerAssistanceExactTextCommand {
  param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [Parameter(Mandatory = $true)][string]$Description
  )

  try {
    $lines = @(& $Executable @Arguments 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) { $exitCode = 0 }
  } catch {
    throw "$Description could not start."
  }
  if ($exitCode -ne 0) {
    throw "$Description returned a nonzero exit code."
  }
  return ($lines -join "`n")
}

function New-LawyerAssistanceExactMcpProductionOperations {
  param(
    [Parameter(Mandatory = $true)][string]$ProjectRoot,
    [Parameter(Mandatory = $true)][string]$ContractPath
  )

  $root = [IO.Path]::GetFullPath($ProjectRoot)
  $contract = [IO.Path]::GetFullPath($ContractPath)
  foreach ($name in @("GH_HOST", "GH_REPO")) {
    $override = Get-Item "Env:$name" -ErrorAction SilentlyContinue
    if ($null -ne $override -and -not [string]::IsNullOrWhiteSpace([string]$override.Value)) {
      throw "GitHub CLI host or repository overrides are forbidden during exact MCP collection."
    }
  }
  $repository = "github.com/shilittle/Lawyer-Assistance"
  $listRuns = {
    param([string]$ExpectedCommit)
    return Invoke-LawyerAssistanceExactTextCommand "gh" @(
      "run", "list",
      "--repo", $repository,
      "--workflow", "mcp-ci.yml",
      "--branch", "main",
      "--commit", $ExpectedCommit,
      "--event", "push",
      "--limit", "20",
      "--json", "databaseId,headBranch,headSha,status,conclusion,event,workflowName"
    ) "Exact-HEAD MCP CI run lookup"
  }.GetNewClosure()
  $listArtifacts = {
    param([long]$RunId)
    return Invoke-LawyerAssistanceExactTextCommand "gh" @(
      "api", "--hostname", "github.com", "repos/shilittle/Lawyer-Assistance/actions/runs/$RunId/artifacts?per_page=100"
    ) "Exact MCP CI artifact lookup"
  }.GetNewClosure()
  $downloadArtifact = {
    param([long]$RunId, [string]$ArtifactName, [string]$Destination)
    [void](Invoke-LawyerAssistanceExactTextCommand "gh" @(
      "run", "download", [string]$RunId,
      "--repo", $repository,
      "--name", $ArtifactName,
      "--dir", $Destination
    ) "Literal MCP CI artifact download")
  }.GetNewClosure()
  $verifyFinalAssets = {
    param([string]$Directory, [string]$ExpectedCommit)
    $verifier = Join-Path $root "scripts\verify_release_assets.py"
    $output = Invoke-LawyerAssistanceExactTextCommand "python" @(
      $verifier,
      "--kind", "app",
      "--directory", $Directory,
      "--contract", $contract,
      "--expected-commit", $ExpectedCommit
    ) "Final exact App release asset verification"
    try {
      $report = $output | ConvertFrom-Json
    } catch {
      throw "Final exact App release asset verifier did not return JSON."
    }
    $expectedNames = @(Read-LawyerAssistanceExactAssemblyContract $contract).AllNames
    if ($report.ok -ne $true -or [string]$report.kind -cne "app" -or
        [string]$report.version -cne "0.4.0" -or
        [string]$report.expectedCommit -cne $ExpectedCommit -or
        [int]$report.assetCount -ne 12 -or
        (@($report.assetNames | ForEach-Object { [string]$_ }) -join "`n") -cne
          ($expectedNames -join "`n") -or
        @($report.authenticodeFiles).Count -ne 0) {
      throw "Final exact App release asset verifier report is invalid."
    }
    return $report
  }.GetNewClosure()
  return @{
    ListRuns = $listRuns
    ListArtifacts = $listArtifacts
    DownloadArtifact = $downloadArtifact
    VerifyFinalAssets = $verifyFinalAssets
  }
}

function Invoke-LawyerAssistanceExactMcpCiCollectionCore {
  param(
    [Parameter(Mandatory = $true)][string]$ProjectRoot,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedCommit,
    [Parameter(Mandatory = $true)][hashtable]$Operations
  )

  Assert-LawyerAssistanceExactMcpCollectionOperations $Operations
  $root = [IO.Path]::GetFullPath($ProjectRoot)
  [void](Assert-LawyerAssistanceExactOrdinaryDirectory $root "Release repository root")
  $contractPath = Join-Path $root "scripts\release\release-contract-v0.4.0.json"
  $contract = Read-LawyerAssistanceExactAssemblyContract $contractPath
  $appDirectory = Join-Path $root "dist\release-v0.4.0\app"
  Assert-LawyerAssistanceExactFlatAssetDirectory $appDirectory $contract.AppNames "Signed App asset staging directory"

  try {
    $runs = @((& $Operations.ListRuns $ExpectedCommit) | ConvertFrom-Json)
  } catch {
    throw "The exact-HEAD MCP CI run response is invalid."
  }
  $matching = @($runs | Where-Object {
    [string]$_.headSha -ceq $ExpectedCommit -and
    [string]$_.headBranch -ceq "main" -and
    [string]$_.event -ceq "push" -and
    [long]$_.databaseId -gt 0
  } | Sort-Object { [long]$_.databaseId } -Descending)
  if ($matching.Count -eq 0) {
    throw "No MCP CI main push run exists for exact expected HEAD."
  }
  $run = $matching[0]
  if ([string]$run.status -cne "completed" -or [string]$run.conclusion -cne "success") {
    throw "The latest exact-HEAD MCP CI main push run is not completed successfully."
  }
  $runId = [long]$run.databaseId

  try {
    $artifactResponse = (& $Operations.ListArtifacts $runId) | ConvertFrom-Json
  } catch {
    throw "The exact MCP CI artifact response is invalid."
  }
  $artifacts = @($artifactResponse.artifacts)
  $expectedArtifactNames = @(Get-LawyerAssistanceExactMcpArtifactNames)
  if ([long]$artifactResponse.total_count -ne 3 -or $artifacts.Count -ne 3) {
    throw "The exact MCP CI run must expose exactly three artifacts."
  }
  $actualArtifactNames = @($artifacts | ForEach-Object { [string]$_.name })
  if (@($actualArtifactNames | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique).Count -ne 3 -or
      ((@($actualArtifactNames | Sort-Object -CaseSensitive) -join "`n") -cne
       (@($expectedArtifactNames | Sort-Object -CaseSensitive) -join "`n"))) {
    throw "The MCP CI artifact names differ from the exact three-target inventory."
  }
  foreach ($artifact in $artifacts) {
    if ([long]$artifact.id -le 0 -or [long]$artifact.size_in_bytes -le 0 -or $artifact.expired -eq $true) {
      throw "An exact MCP CI artifact is missing, empty, expired, or invalid."
    }
  }

  $releaseRoot = Join-Path $root "dist\release-v0.4.0"
  [void](Assert-LawyerAssistanceExactOrdinaryDirectory $releaseRoot "Fixed v0.4.0 release staging root")
  $collectionDirectory = Join-Path $releaseRoot "mcp-ci-artifacts"
  $finalDirectory = Join-Path $releaseRoot "app-release-assets"
  foreach ($path in @($collectionDirectory, $finalDirectory)) {
    if (Test-Path -LiteralPath $path) {
      throw "Fixed MCP collection and final assembly directories must be absent before the run."
    }
  }
  [void][IO.Directory]::CreateDirectory($collectionDirectory)
  [void](Assert-LawyerAssistanceExactOrdinaryDirectory $collectionDirectory "Fixed MCP CI collection directory")

  $mcpSources = @{}
  for ($index = 0; $index -lt $script:ExactMcpTargets.Count; $index++) {
    $target = $script:ExactMcpTargets[$index]
    $artifactName = "lawyer-assistance-mcp-$target"
    $artifactDirectory = Join-Path $collectionDirectory $artifactName
    [void][IO.Directory]::CreateDirectory($artifactDirectory)
    [void](Assert-LawyerAssistanceExactOrdinaryDirectory $artifactDirectory "MCP CI artifact extraction directory")
    & $Operations.DownloadArtifact $runId $artifactName $artifactDirectory

    $suffix = if ($target -ceq "x86_64-pc-windows-msvc") { ".zip" } else { ".tar.gz" }
    $archiveName = "lawyer-assistance-mcp-v$($contract.Version)-$target$suffix"
    $artifactFiles = @($archiveName, "$archiveName.sha256")
    Assert-LawyerAssistanceExactFlatAssetDirectory $artifactDirectory $artifactFiles "MCP CI artifact $artifactName"
    Assert-LawyerAssistanceCanonicalSha256 $artifactDirectory $archiveName
    foreach ($name in $artifactFiles) {
      $mcpSources[$name] = Join-Path $artifactDirectory $name
    }
  }
  if ($mcpSources.Count -ne 6) {
    throw "The exact MCP CI collection did not produce six release files."
  }

  [void][IO.Directory]::CreateDirectory($finalDirectory)
  [void](Assert-LawyerAssistanceExactOrdinaryDirectory $finalDirectory "Final exact App asset directory")
  foreach ($name in $contract.AppNames) {
    Copy-LawyerAssistanceExactCreateNew (Join-Path $appDirectory $name) (Join-Path $finalDirectory $name)
  }
  foreach ($name in $contract.McpNames) {
    if (-not $mcpSources.ContainsKey($name)) {
      throw "The MCP CI collection is missing final release file $name."
    }
    Copy-LawyerAssistanceExactCreateNew $mcpSources[$name] (Join-Path $finalDirectory $name)
  }
  Assert-LawyerAssistanceExactFlatAssetDirectory $finalDirectory $contract.AllNames "Final exact App asset directory"
  $verification = & $Operations.VerifyFinalAssets $finalDirectory $ExpectedCommit
  Assert-LawyerAssistanceExactVerificationReport $verification $contract $ExpectedCommit

  return [pscustomobject][ordered]@{
    ok = $true
    expectedCommit = $ExpectedCommit
    runId = $runId
    artifactNames = $expectedArtifactNames
    assetNames = $contract.AllNames
    collectionDirectory = $collectionDirectory
    finalDirectory = $finalDirectory
    verification = $verification
  }
}
