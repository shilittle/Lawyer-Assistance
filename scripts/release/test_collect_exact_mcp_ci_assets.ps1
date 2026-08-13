$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "collect_exact_mcp_ci_assets_common.ps1")

$script:TestsRun = 0
$script:Head = "a" * 40

function Assert-True([bool]$Condition, [string]$Message) {
  if (-not $Condition) { throw $Message }
}

function Assert-Equal($Expected, $Actual, [string]$Message) {
  if ($Expected -cne $Actual) {
    throw "$Message (expected='$Expected', actual='$Actual')"
  }
}

function Invoke-TestCase([string]$Name, [scriptblock]$Body) {
  & $Body
  $script:TestsRun += 1
  Write-Output "PASS $Name"
}

function Write-TestBytes([string]$Path, [byte[]]$Bytes) {
  $parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
  if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
  [IO.File]::WriteAllBytes($Path, $Bytes)
}

function Write-TestText([string]$Path, [string]$Text) {
  Write-TestBytes $Path ([Text.UTF8Encoding]::new($false).GetBytes($Text))
}

function New-ExactMcpFixture {
  $root = Join-Path ([IO.Path]::GetTempPath()) ("lawyer-assistance-exact-mcp-" + [Guid]::NewGuid().ToString("N"))
  foreach ($directory in @(
    "scripts\release",
    "dist\release-v0.4.0\app"
  )) {
    New-Item -ItemType Directory -Path (Join-Path $root $directory) -Force | Out-Null
  }
  $allNames = @(
    "Lawyer.Assistance_0.4.0_x64-setup.exe",
    "Lawyer.Assistance_0.4.0_x64-setup.exe.sha256",
    "Lawyer.Assistance_0.4.0_x64-setup.exe.sig",
    "latest.json",
    "Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip",
    "Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip.sha256"
  ) + @(Get-LawyerAssistanceExactMcpReleaseNames "0.4.0")
  $contract = [ordered]@{
    schemaVersion = 1
    repository = [ordered]@{
      owner = "shilittle"
      name = "Lawyer-Assistance"
    }
    release = [ordered]@{
      formalVersion = "0.4.0"
      appTag = "v0.4.0"
    }
    appAssets = $allNames
  }
  Write-TestText (Join-Path $root "scripts\release\release-contract-v0.4.0.json") (($contract | ConvertTo-Json -Depth 8) + "`n")
  $appDirectory = Join-Path $root "dist\release-v0.4.0\app"
  foreach ($name in $allNames[0..5]) {
    Write-TestText (Join-Path $appDirectory $name) "signed app fixture $name`n"
  }
  return [pscustomobject][ordered]@{
    Root = $root
    AppDirectory = $appDirectory
    AllNames = $allNames
  }
}

function New-ExactMcpState {
  $artifactNames = @(Get-LawyerAssistanceExactMcpArtifactNames)
  $artifacts = @()
  for ($index = 0; $index -lt $artifactNames.Count; $index++) {
    $artifacts += [pscustomobject][ordered]@{
      id = 100 + $index
      name = $artifactNames[$index]
      size_in_bytes = 123
      expired = $false
    }
  }
  return @{
    Runs = @([pscustomobject][ordered]@{
      databaseId = 42
      headBranch = "main"
      headSha = $script:Head
      status = "completed"
      conclusion = "success"
      event = "push"
      workflowName = "MCP server CI"
    })
    ArtifactResponse = [pscustomobject][ordered]@{
      total_count = 3
      artifacts = $artifacts
    }
    Downloads = [Collections.Generic.List[object]]::new()
    VerifyCalls = [Collections.Generic.List[object]]::new()
    ArtifactMutation = "none"
  }
}

function New-ExactMcpOperations([hashtable]$State) {
  $listRuns = {
    param([string]$ExpectedCommit)
    return ConvertTo-Json -InputObject $State.Runs -Depth 6 -Compress
  }.GetNewClosure()
  $listArtifacts = {
    param([long]$RunId)
    return ($State.ArtifactResponse | ConvertTo-Json -Depth 6 -Compress)
  }.GetNewClosure()
  $downloadArtifact = {
    param([long]$RunId, [string]$ArtifactName, [string]$Destination)
    [void]$State.Downloads.Add([pscustomobject][ordered]@{
      RunId = $RunId
      ArtifactName = $ArtifactName
      Destination = $Destination
    })
    $target = $ArtifactName.Substring("lawyer-assistance-mcp-".Length)
    $suffix = if ($target -ceq "x86_64-pc-windows-msvc") { ".zip" } else { ".tar.gz" }
    $archiveName = "lawyer-assistance-mcp-v0.4.0-$target$suffix"
    $archivePath = Join-Path $Destination $archiveName
    Write-TestText $archivePath "archive fixture $target`n"
    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-TestText (Join-Path $Destination "$archiveName.sha256") "$hash  $archiveName`n"
    switch ([string]$State.ArtifactMutation) {
      "extra" { Write-TestText (Join-Path $Destination "extra.bin") "extra" }
      "nested" {
        New-Item -ItemType Directory -Path (Join-Path $Destination "nested") | Out-Null
        Write-TestText (Join-Path $Destination "nested\extra.bin") "extra"
      }
      "case-alias" { Write-TestText (Join-Path $Destination $archiveName.ToUpperInvariant()) "alias" }
      "wrong-checksum" { Write-TestText (Join-Path $Destination "$archiveName.sha256") "$('0' * 64)  $archiveName`n" }
    }
  }.GetNewClosure()
  $verifyFinalAssets = {
    param([string]$Directory, [string]$ExpectedCommit)
    [void]$State.VerifyCalls.Add([pscustomobject][ordered]@{
      Directory = $Directory
      ExpectedCommit = $ExpectedCommit
    })
    $contract = Read-LawyerAssistanceExactAssemblyContract (Join-Path ([IO.Path]::GetFullPath((Join-Path $Directory "..\..\.."))) "scripts\release\release-contract-v0.4.0.json")
    Assert-LawyerAssistanceExactFlatAssetDirectory $Directory $contract.AllNames "Fake final verifier directory"
    return [pscustomobject][ordered]@{
      ok = $true
      kind = "app"
      version = "0.4.0"
      assetCount = 12
      expectedCommit = $ExpectedCommit
      assetNames = $contract.AllNames
      authenticodeFiles = @()
    }
  }.GetNewClosure()
  return @{
    ListRuns = $listRuns
    ListArtifacts = $listArtifacts
    DownloadArtifact = $downloadArtifact
    VerifyFinalAssets = $verifyFinalAssets
  }
}

function Invoke-ExpectedFailure([string]$Name, [scriptblock]$Body, [string]$Pattern) {
  $failed = $false
  try {
    & $Body
  } catch {
    $failed = $true
    if (-not [string]$_.Exception.Message.Contains($Pattern)) {
      throw "$Name returned an unexpected failure: $($_.Exception.Message)"
    }
  }
  Assert-True $failed "$Name unexpectedly succeeded"
}

Invoke-TestCase "exact three artifacts assemble final twelve with literal downloads" {
  $fixture = New-ExactMcpFixture
  try {
    $state = New-ExactMcpState
    $result = Invoke-LawyerAssistanceExactMcpCiCollectionCore $fixture.Root $script:Head (New-ExactMcpOperations $state)
    Assert-True ([bool]$result.ok) "exact MCP collection did not succeed"
    Assert-Equal 42 ([long]$result.runId) "exact run id changed"
    Assert-Equal 3 $state.Downloads.Count "literal download count changed"
    Assert-Equal 1 $state.VerifyCalls.Count "final Python verifier was not invoked exactly once"
    Assert-LawyerAssistanceExactFlatAssetDirectory $result.finalDirectory $fixture.AllNames "Final test directory"
    foreach ($download in $state.Downloads) {
      Assert-True ($download.ArtifactName -cnotmatch '[*?\[\]]') "artifact download used a wildcard"
      Assert-True ((Get-LawyerAssistanceExactMcpArtifactNames) -ccontains $download.ArtifactName) "artifact download name was not literal"
    }
  } finally {
    if (Test-Path -LiteralPath $fixture.Root) { Remove-Item -LiteralPath $fixture.Root -Recurse -Force }
  }
}

Invoke-TestCase "wrong HEAD has no downloads or final output" {
  $fixture = New-ExactMcpFixture
  try {
    $state = New-ExactMcpState
    $state.Runs[0].headSha = "b" * 40
    Invoke-ExpectedFailure "wrong HEAD" {
      Invoke-LawyerAssistanceExactMcpCiCollectionCore $fixture.Root $script:Head (New-ExactMcpOperations $state)
    } "exact expected HEAD"
    Assert-Equal 0 $state.Downloads.Count "wrong HEAD downloaded an artifact"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $fixture.Root "dist\release-v0.4.0\app-release-assets"))) "wrong HEAD created final output"
  } finally {
    if (Test-Path -LiteralPath $fixture.Root) { Remove-Item -LiteralPath $fixture.Root -Recurse -Force }
  }
}

Invoke-TestCase "latest exact run must be completed success" {
  foreach ($mutation in @(
    @{ Status = "in_progress"; Conclusion = "" },
    @{ Status = "completed"; Conclusion = "failure" }
  )) {
    $fixture = New-ExactMcpFixture
    try {
      $state = New-ExactMcpState
      $state.Runs[0].status = $mutation.Status
      $state.Runs[0].conclusion = $mutation.Conclusion
      Invoke-ExpectedFailure "failed run" {
        Invoke-LawyerAssistanceExactMcpCiCollectionCore $fixture.Root $script:Head (New-ExactMcpOperations $state)
      } "not completed successfully"
      Assert-Equal 0 $state.Downloads.Count "non-success run downloaded an artifact"
    } finally {
      if (Test-Path -LiteralPath $fixture.Root) { Remove-Item -LiteralPath $fixture.Root -Recurse -Force }
    }
  }
}

Invoke-TestCase "incomplete extra or case-aliased artifact inventory fails before download" {
  foreach ($mutation in @("incomplete", "extra", "case-alias")) {
    $fixture = New-ExactMcpFixture
    try {
      $state = New-ExactMcpState
      switch ($mutation) {
        "incomplete" {
          $state.ArtifactResponse.artifacts = @($state.ArtifactResponse.artifacts[0..1])
          $state.ArtifactResponse.total_count = 2
        }
        "extra" {
          $state.ArtifactResponse.artifacts += [pscustomobject]@{
            id = 999; name = "extra"; size_in_bytes = 1; expired = $false
          }
          $state.ArtifactResponse.total_count = 4
        }
        "case-alias" {
          $state.ArtifactResponse.artifacts[2].name = $state.ArtifactResponse.artifacts[0].name.ToUpperInvariant()
        }
      }
      Invoke-ExpectedFailure "artifact inventory $mutation" {
        Invoke-LawyerAssistanceExactMcpCiCollectionCore $fixture.Root $script:Head (New-ExactMcpOperations $state)
      } "artifact"
      Assert-Equal 0 $state.Downloads.Count "bad artifact inventory downloaded content"
    } finally {
      if (Test-Path -LiteralPath $fixture.Root) { Remove-Item -LiteralPath $fixture.Root -Recurse -Force }
    }
  }
}

Invoke-TestCase "artifact payload must be exact flat pair with canonical checksum" {
  foreach ($mutation in @("extra", "nested", "case-alias", "wrong-checksum")) {
    $fixture = New-ExactMcpFixture
    try {
      $state = New-ExactMcpState
      $state.ArtifactMutation = $mutation
      Invoke-ExpectedFailure "artifact payload $mutation" {
        Invoke-LawyerAssistanceExactMcpCiCollectionCore $fixture.Root $script:Head (New-ExactMcpOperations $state)
      } $(if ($mutation -ceq "wrong-checksum") { "checksum" } else { "MCP CI artifact" })
      Assert-Equal 0 $state.VerifyCalls.Count "bad artifact payload reached final verifier"
    } finally {
      if (Test-Path -LiteralPath $fixture.Root) { Remove-Item -LiteralPath $fixture.Root -Recurse -Force }
    }
  }
}

Invoke-TestCase "signed App staging must be exact and preexisting outputs fail closed" {
  foreach ($mutation in @("app-extra", "app-missing", "preexisting-collection", "preexisting-final")) {
    $fixture = New-ExactMcpFixture
    try {
      $state = New-ExactMcpState
      switch ($mutation) {
        "app-extra" { Write-TestText (Join-Path $fixture.AppDirectory "extra") "extra" }
        "app-missing" { Remove-Item -LiteralPath (Join-Path $fixture.AppDirectory $fixture.AllNames[0]) -Force }
        "preexisting-collection" { New-Item -ItemType Directory -Path (Join-Path $fixture.Root "dist\release-v0.4.0\mcp-ci-artifacts") | Out-Null }
        "preexisting-final" { New-Item -ItemType Directory -Path (Join-Path $fixture.Root "dist\release-v0.4.0\app-release-assets") | Out-Null }
      }
      Invoke-ExpectedFailure "staging $mutation" {
        Invoke-LawyerAssistanceExactMcpCiCollectionCore $fixture.Root $script:Head (New-ExactMcpOperations $state)
      } $(if ($mutation -like "app-*") { "Signed App asset" } else { "must be absent" })
      Assert-Equal 0 $state.VerifyCalls.Count "bad staging reached final verifier"
    } finally {
      if (Test-Path -LiteralPath $fixture.Root) { Remove-Item -LiteralPath $fixture.Root -Recurse -Force }
    }
  }
}

Invoke-TestCase "production operations use literal artifact names and no wildcard" {
  $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot "collect_exact_mcp_ci_assets_common.ps1") -Raw -Encoding UTF8
  Assert-True ($source.Contains('"--name", $ArtifactName')) "production download does not pass a literal artifact name"
  Assert-True (-not $source.Contains('"--pattern"')) "production collection permits a pattern download"
  Assert-True (-not $source.Contains('gh run download $RunId')) "production download is missing an explicit artifact name"
}

Write-Output "PASS $script:TestsRun collect_exact_mcp_ci_assets tests"
