$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "release_publication_common.ps1")

function Write-TestUtf8([string]$Path, [string]$Text) {
  $parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
  if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
  [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false))
}

function New-AppPublicationFixture([string]$Root) {
  $names = @(
    "Lawyer.Assistance_0.4.0_x64-setup.exe",
    "Lawyer.Assistance_0.4.0_x64-setup.exe.sha256",
    "Lawyer.Assistance_0.4.0_x64-setup.exe.sig",
    "latest.json",
    "Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip",
    "Lawyer-Assistance_0.4.0_windows-x86_64-portable.zip.sha256",
    "lawyer-assistance-mcp-v0.4.0-x86_64-pc-windows-msvc.zip",
    "lawyer-assistance-mcp-v0.4.0-x86_64-pc-windows-msvc.zip.sha256",
    "lawyer-assistance-mcp-v0.4.0-x86_64-unknown-linux-gnu.tar.gz",
    "lawyer-assistance-mcp-v0.4.0-x86_64-unknown-linux-gnu.tar.gz.sha256",
    "lawyer-assistance-mcp-v0.4.0-aarch64-apple-darwin.tar.gz",
    "lawyer-assistance-mcp-v0.4.0-aarch64-apple-darwin.tar.gz.sha256"
  )
  $contractPath = Join-Path $Root "release-contract-v0.4.0.json"
  $contract = [ordered]@{
    schemaVersion = 1
    repository = [ordered]@{
      owner = "shilittle"
      name = "Lawyer-Assistance"
      httpsUrl = "https://github.com/shilittle/Lawyer-Assistance.git"
    }
    release = [ordered]@{
      formalVersion = "0.4.0"
      appTag = "v0.4.0"
      minerUTag = "mineru-components-v0.4.0"
    }
    appAssets = $names
  }
  Write-TestUtf8 $contractPath (($contract | ConvertTo-Json -Depth 6) + "`n")
  $assetDirectory = Join-Path $Root "assets"
  New-Item -ItemType Directory -Path $assetDirectory | Out-Null
  foreach ($name in $names) {
    Write-TestUtf8 (Join-Path $assetDirectory $name) "exact fixture bytes for $name`n"
  }
  $notes = Join-Path $Root "notes.md"
  $notes = Join-Path $Root "RELEASE_NOTES.md"
  Write-TestUtf8 $notes "# Lawyer Assistance 0.4.0`n"
  return [pscustomobject][ordered]@{
    Contract = $contractPath
    Assets = $assetDirectory
    Notes = $notes
    Names = $names
  }
}

function New-FakePublicationRemote([string]$Root) {
  $remoteDirectory = Join-Path $Root "remote"
  New-Item -ItemType Directory -Path $remoteDirectory | Out-Null
  return @{
    Head = "1" * 40
    TagObject = "2" * 40
    Peeled = "1" * 40
    Lightweight = $false
    Release = $null
    RemoteDirectory = $remoteDirectory
    NextId = 100
    UploadCount = 0
    Commands = [Collections.Generic.List[object]]::new()
    OriginUrl = "https://github.com/shilittle/Lawyer-Assistance.git"
  }
}

function Get-FakeReleaseJson($State) {
  $page = if ($null -eq $State.Release) { @() } else { @($State.Release) }
  return (ConvertTo-Json -InputObject (, $page) -Depth 8 -Compress)
}

function New-FakeGitText($State) {
  return {
    param([string[]]$Arguments)
    if ($Arguments -contains "get-url") { return $State.OriginUrl }
    if ($Arguments -contains "rev-parse") { return $State.Head }
    if ($Arguments -contains "ls-remote") {
      $tag = @($Arguments | Where-Object { $_ -match '^refs/tags/' -and $_ -notmatch '\^\{\}$' })[0]
      if ($State.Lightweight) { return "$($State.Peeled)`t$tag" }
      return "$($State.TagObject)`t$tag`n$($State.Peeled)`t$tag^{}"
    }
    throw "Unexpected fake Git command: $($Arguments -join ' ')"
  }.GetNewClosure()
}

function New-FakeGhText($State) {
  return {
    param([string[]]$Arguments)
    $State.Commands.Add(@($Arguments))
    if ($Arguments[0] -ceq "api") {
      return Get-FakeReleaseJson $State
    }
    if ($Arguments[0] -cne "release") {
      throw "Unexpected fake GitHub command."
    }
    if ($Arguments[1] -ceq "create") {
      if ($null -ne $State.Release -or $Arguments -cnotcontains "--draft" -or $Arguments -cnotcontains "--verify-tag") {
        throw "Invalid draft creation command."
      }
      $State.Release = [pscustomobject][ordered]@{
        id = 7
        tag_name = [string]$Arguments[2]
        name = [string]$Arguments[($Arguments.IndexOf("--title") + 1)]
        body = [IO.File]::ReadAllText([string]$Arguments[($Arguments.IndexOf("--notes-file") + 1)], [Text.Encoding]::UTF8)
        draft = $true
        prerelease = $false
        assets = @()
      }
      return "created"
    }
    if ($Arguments[1] -ceq "upload") {
      $path = [IO.Path]::GetFullPath([string]$Arguments[3])
      if ($path -match '[*?\[\]]') { throw "A release upload used a filename pattern." }
      $forbiddenOverwrite = "--" + "clobber"
      if ($Arguments -ccontains $forbiddenOverwrite) { throw "A release upload requested overwrite." }
      $name = [IO.Path]::GetFileName($path)
      if (@($State.Release.assets | Where-Object { [string]$_.name -ceq $name }).Count -ne 0) {
        throw "The fake GitHub service refuses duplicate assets."
      }
      $destination = Join-Path $State.RemoteDirectory $name
      Copy-Item -LiteralPath $path -Destination $destination
      $asset = [pscustomobject][ordered]@{
        id = [long]$State.NextId
        name = $name
        size = (Get-Item -LiteralPath $destination).Length
      }
      $State.NextId++
      $State.UploadCount++
      $State.Release.assets = @($State.Release.assets) + @($asset)
      return "uploaded"
    }
    throw "Unexpected fake GitHub release command."
  }.GetNewClosure()
}

function New-FakeGhDownload($State) {
  return {
    param([string]$Repository, [long]$AssetId, [string]$Destination)
    if ($Repository -cne "shilittle/Lawyer-Assistance") { throw "Wrong fake repository." }
    $asset = @($State.Release.assets | Where-Object { [long]$_.id -eq $AssetId })
    if ($asset.Count -ne 1) { throw "Unknown fake remote asset." }
    Copy-Item -LiteralPath (Join-Path $State.RemoteDirectory ([string]$asset[0].name)) -Destination $Destination
  }.GetNewClosure()
}

function Invoke-FakePublication($Fixture, $State) {
  $assetVerifier = {
    param([string]$Kind, [string]$Directory, [string]$Contract, [string]$Commit)
    foreach ($name in $Fixture.Names) {
      $snapshotPath = Join-Path $Directory $name
      if (-not [IO.Path]::GetFullPath($snapshotPath).StartsWith(
          [IO.Path]::GetFullPath([IO.Path]::GetTempPath()),
          [StringComparison]::OrdinalIgnoreCase)) {
        throw "The publication verifier did not receive a private temporary snapshot."
      }
      $writeRejected = $false
      try {
        $writer = [IO.File]::Open(
          $snapshotPath,
          [IO.FileMode]::Open,
          [IO.FileAccess]::Write,
          [IO.FileShare]::ReadWrite
        )
        $writer.Dispose()
      } catch [IO.IOException] {
        $writeRejected = $true
      }
      if (-not $writeRejected) {
        throw "A verified upload snapshot remained writable during publication."
      }
    }
    return (@{
      ok = $true
      kind = $Kind
      version = "0.4.0"
      expectedCommit = $Commit
      assetCount = 12
      assetNames = $Fixture.Names
    } | ConvertTo-Json -Compress)
  }.GetNewClosure()
  return Invoke-ReleaseDraftPublication `
    -ProjectRoot $script:testRoot `
    -ContractPath $Fixture.Contract `
    -Kind App `
    -AssetDirectory $Fixture.Assets `
    -NotesFile $Fixture.Notes `
    -GitText (New-FakeGitText $State) `
    -GhText (New-FakeGhText $State) `
    -GhDownload (New-FakeGhDownload $State) `
    -AssetVerifier $assetVerifier
}

function Invoke-FakeReadback($Fixture, $State) {
  $assetVerifier = {
    param(
      [string]$Kind,
      [string]$Directory,
      [string]$Contract,
      [string]$Commit,
      [string]$VerificationOutput
    )
    New-Item -ItemType Directory -Path $VerificationOutput | Out-Null
    $authenticodeFiles = @()
    foreach ($name in @(
      "Lawyer.Assistance_0.4.0_x64-setup.exe",
      "portable-lawyer-assistance.exe",
      "portable-lawyer-assistance-mcp.exe"
    )) {
      $path = Join-Path $VerificationOutput $name
      Write-TestUtf8 $path "verified executable fixture $name`n"
      $authenticodeFiles += $path
    }
    return (@{
      ok = $true
      kind = $Kind
      version = "0.4.0"
      expectedCommit = $Commit
      assetCount = 12
      assetNames = $Fixture.Names
      authenticodeFiles = $authenticodeFiles
    } | ConvertTo-Json -Compress)
  }.GetNewClosure()
  $authenticodeVerifier = {
    param([string]$Path)
    Assert-ReleaseOrdinaryFile $Path "Fake Authenticode file"
    return "A" * 40
  }
  return Invoke-ReleaseRemoteReadback `
    -ProjectRoot $script:testRoot `
    -ContractPath $Fixture.Contract `
    -Kind App `
    -LocalAssetDirectory $Fixture.Assets `
    -GitText (New-FakeGitText $State) `
    -GhText (New-FakeGhText $State) `
    -GhDownload (New-FakeGhDownload $State) `
    -AssetVerifier $assetVerifier `
    -AuthenticodeVerifier $authenticodeVerifier
}

function Assert-Rejected([scriptblock]$Action, [string]$Label) {
  $rejected = $false
  try { & $Action | Out-Null } catch { $rejected = $true }
  if (-not $rejected) { throw "$Label was accepted." }
}

$script:testRoot = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) ("lawyer-assistance-publication-test-" + [Guid]::NewGuid().ToString("N"))))
$temporaryPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
if (-not $script:testRoot.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Publication test root escaped the system temporary directory."
}

try {
  New-Item -ItemType Directory -Path $script:testRoot | Out-Null
  $fixture = New-AppPublicationFixture $script:testRoot
  $savedGhHost = Get-Item Env:GH_HOST -ErrorAction SilentlyContinue
  $env:GH_HOST = "attacker.example"
  try {
    Assert-Rejected { Invoke-FakePublication $fixture (New-FakePublicationRemote (Join-Path $script:testRoot "gh-host")) } "GH_HOST repository redirect"
  } finally {
    if ($null -ne $savedGhHost) { $env:GH_HOST = [string]$savedGhHost.Value }
    else { Remove-Item Env:GH_HOST -ErrorAction SilentlyContinue }
  }
  $contractBytes = [IO.File]::ReadAllBytes($fixture.Contract)
  foreach ($field in @("owner", "name", "httpsUrl")) {
    try {
      $value = Get-Content -LiteralPath $fixture.Contract -Raw -Encoding UTF8 | ConvertFrom-Json
      if ($field -ceq "owner") { $value.repository.owner = "attacker" }
      elseif ($field -ceq "name") { $value.repository.name = "Other" }
      else { $value.repository.httpsUrl = "https://github.com/attacker/Lawyer-Assistance.git" }
      Write-TestUtf8 $fixture.Contract (($value | ConvertTo-Json -Depth 8) + "`n")
      Assert-Rejected { Read-ReleasePublicationContract $fixture.Contract } "Mutated contract repository $field"
    } finally {
      [IO.File]::WriteAllBytes($fixture.Contract, $contractBytes)
    }
  }
  $state = New-FakePublicationRemote $script:testRoot
  $result = Invoke-FakePublication $fixture $state
  if ($result.resultCode -cne "REL-DRAFT-ASSETS-VERIFIED" -or
      $result.commit -cne $state.Head -or
      $result.assetCount -ne 12 -or
      $state.UploadCount -ne 12) {
    throw "Fresh draft publication did not produce exact verified evidence."
  }
  $savedTitle = [string]$state.Release.name
  $state.Release.name = "Wrong release title"
  Assert-Rejected { Invoke-FakePublication $fixture $state } "Wrong draft release title"
  $state.Release.name = $savedTitle
  $savedBody = [string]$state.Release.body
  $state.Release.body = "Wrong release notes"
  Assert-Rejected { Invoke-FakeReadback $fixture $state } "Wrong draft release body"
  $state.Release.body = $savedBody

  $alternateNotes = Join-Path $script:testRoot "alternate-notes.md"
  Write-TestUtf8 $alternateNotes "# Alternate notes`n"
  Assert-Rejected {
    Invoke-ReleaseDraftPublication `
      -ProjectRoot $script:testRoot `
      -ContractPath $fixture.Contract `
      -Kind App `
      -AssetDirectory $fixture.Assets `
      -NotesFile $alternateNotes `
      -GitText (New-FakeGitText $state) `
      -GhText (New-FakeGhText $state) `
      -GhDownload (New-FakeGhDownload $state) `
      -AssetVerifier { throw "Alternate notes reached the asset verifier" }
  } "Noncanonical release notes file"

  Invoke-FakePublication $fixture $state | Out-Null
  if ($state.UploadCount -ne 12) {
    throw "An equal-hash publication retry uploaded an existing asset."
  }
  $readback = Invoke-FakeReadback $fixture $state
  if ($readback.resultCode -cne "REL-SERVER-READBACK-VERIFIED" -or
      $readback.commit -cne $state.Head -or
      $readback.assetCount -ne 12) {
    throw "Fresh server readback did not return exact verification evidence."
  }
  $authenticodeFailureVerifier = {
    param(
      [string]$Kind,
      [string]$Directory,
      [string]$Contract,
      [string]$Commit,
      [string]$VerificationOutput
    )
    New-Item -ItemType Directory -Path $VerificationOutput | Out-Null
    $files = @()
    foreach ($name in @(
      "Lawyer.Assistance_0.4.0_x64-setup.exe",
      "portable-lawyer-assistance.exe",
      "portable-lawyer-assistance-mcp.exe"
    )) {
      $path = Join-Path $VerificationOutput $name
      Write-TestUtf8 $path "verified executable $name`n"
      $files += $path
    }
    return (@{
      ok = $true
      kind = $Kind
      version = "0.4.0"
      expectedCommit = $Commit
      assetCount = 12
      assetNames = $fixture.Names
      authenticodeFiles = $files
    } | ConvertTo-Json -Compress)
  }.GetNewClosure()
  Assert-Rejected {
    Invoke-ReleaseRemoteReadback `
      -ProjectRoot $script:testRoot `
      -ContractPath $fixture.Contract `
      -Kind App `
      -LocalAssetDirectory $fixture.Assets `
      -GitText (New-FakeGitText $state) `
      -GhText (New-FakeGhText $state) `
      -GhDownload (New-FakeGhDownload $state) `
      -AssetVerifier $authenticodeFailureVerifier `
      -AuthenticodeVerifier { param([string]$Path) throw "timestamp absent" }
  } "Missing Authenticode timestamp"

  $publisherCall = 0
  Assert-Rejected {
    Invoke-ReleaseRemoteReadback `
      -ProjectRoot $script:testRoot `
      -ContractPath $fixture.Contract `
      -Kind App `
      -LocalAssetDirectory $fixture.Assets `
      -GitText (New-FakeGitText $state) `
      -GhText (New-FakeGhText $state) `
      -GhDownload (New-FakeGhDownload $state) `
      -AssetVerifier $authenticodeFailureVerifier `
      -AuthenticodeVerifier {
        param([string]$Path)
        $script:publisherCall++
        if ($script:publisherCall -eq 3) { return "B" * 40 }
        return "A" * 40
      }
  } "Mixed trusted Authenticode publishers"

  $firstName = [string]$fixture.Names[0]
  Write-TestUtf8 (Join-Path $state.RemoteDirectory $firstName) "tampered remote bytes`n"
  Assert-Rejected { Invoke-FakePublication $fixture $state } "Different-hash remote asset"
  Assert-Rejected { Invoke-FakeReadback $fixture $state } "Different-hash server readback asset"
  Copy-Item -LiteralPath (Join-Path $fixture.Assets $firstName) -Destination (Join-Path $state.RemoteDirectory $firstName) -Force

  $extraPath = Join-Path $state.RemoteDirectory "unexpected.bin"
  Write-TestUtf8 $extraPath "unexpected"
  $state.Release.assets += [pscustomobject][ordered]@{ id = 999; name = "unexpected.bin"; size = 10 }
  Assert-Rejected { Invoke-FakePublication $fixture $state } "Extra remote asset"
  $state.Release.assets = @($state.Release.assets | Where-Object { [string]$_.name -cne "unexpected.bin" })

  $lightweightState = New-FakePublicationRemote (Join-Path $script:testRoot "lightweight")
  $lightweightState.Lightweight = $true
  Assert-Rejected { Invoke-FakePublication $fixture $lightweightState } "Lightweight release tag"

  $wrongCommitState = New-FakePublicationRemote (Join-Path $script:testRoot "wrong-commit")
  $wrongCommitState.Peeled = "3" * 40
  Assert-Rejected { Invoke-FakePublication $fixture $wrongCommitState } "Wrong-commit release tag"

  $wrongOriginState = New-FakePublicationRemote (Join-Path $script:testRoot "wrong-origin")
  $wrongOriginState.OriginUrl = "https://github.com/attacker/Lawyer-Assistance.git"
  Assert-Rejected { Invoke-FakePublication $fixture $wrongOriginState } "Wrong origin repository"

  $raceState = New-FakePublicationRemote (Join-Path $script:testRoot "identity-race")
  $tagEvidence = Assert-RemoteAnnotatedReleaseTag `
    $script:testRoot $raceState.OriginUrl "v0.4.0" (New-FakeGitText $raceState)
  $raceState.TagObject = "4" * 40
  Assert-Rejected {
    Assert-RemoteAnnotatedReleaseTagUnchanged `
      $script:testRoot $raceState.OriginUrl "v0.4.0" (New-FakeGitText $raceState) $tagEvidence
  } "Remote annotated tag race"

  $expectedRelease = $state.Release
  $assetEvidence = Get-ReleaseAssetInventoryEvidence @($state.Release.assets)
  $replacementRelease = [pscustomobject][ordered]@{
    id = 9999
    tag_name = "v0.4.0"
    name = "Lawyer Assistance 0.4.0"
    body = [IO.File]::ReadAllText($fixture.Notes, [Text.Encoding]::UTF8)
    draft = $true
    prerelease = $false
    assets = @($state.Release.assets)
  }
  $state.Release = $replacementRelease
  Assert-Rejected {
    Assert-DraftReleaseUnchanged `
      "shilittle/Lawyer-Assistance" "v0.4.0" $fixture.Names (New-FakeGhText $state) `
      $expectedRelease $assetEvidence "Lawyer Assistance 0.4.0" $replacementRelease.body
  } "Draft Release replacement race"
  $state.Release = $expectedRelease

  Assert-Rejected {
    Assert-ReleaseVerificationReport `
      ([pscustomobject]@{
        ok = $true
        kind = "mineru"
        version = "0.4.0"
        expectedCommit = $state.Head
        assetCount = 12
        assetNames = $fixture.Names
      }) "app" "0.4.0" $state.Head $fixture.Names
  } "Mismatched verifier report kind"

  $missingPath = Join-Path $fixture.Assets ([string]$fixture.Names[1])
  $missingBytes = [IO.File]::ReadAllBytes($missingPath)
  Remove-Item -LiteralPath $missingPath -Force
  Assert-Rejected { Invoke-FakePublication $fixture (New-FakePublicationRemote (Join-Path $script:testRoot "missing")) } "Missing local asset"
  [IO.File]::WriteAllBytes($missingPath, $missingBytes)

  $caseAlias = Join-Path $fixture.Assets "LATEST.JSON"
  Move-Item -LiteralPath (Join-Path $fixture.Assets "latest.json") -Destination $caseAlias
  Assert-Rejected { Invoke-FakePublication $fixture (New-FakePublicationRemote (Join-Path $script:testRoot "case-alias")) } "Case-aliased local asset"
  Move-Item -LiteralPath $caseAlias -Destination (Join-Path $fixture.Assets "latest.json")

  $productionSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot "publish_draft_release.ps1") -Raw -Encoding UTF8
  $commonSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot "release_publication_common.ps1") -Raw -Encoding UTF8
  if ($commonSource.Contains('throw "GitHub asset download failed: $errorText"') -or
      $commonSource.Contains('throw "GitHub asset download failed:')) {
    throw "Production asset download errors can expose GitHub CLI stderr."
  }
  if (-not $commonSource.Contains('[void]$errorRead.GetAwaiter().GetResult()') -or
      -not $commonSource.Contains('throw "GitHub asset download failed."')) {
    throw "Production asset download must drain stderr and emit only a fixed sanitized error."
  }
  $forbiddenOverwrite = "--" + "clobber"
  if ($productionSource.Contains($forbiddenOverwrite) -or $commonSource.Contains($forbiddenOverwrite)) {
    throw "Production publication source contains a remote overwrite option."
  }
  foreach ($command in $state.Commands) {
    if ($command.Count -ge 2 -and $command[0] -ceq "release" -and $command[1] -ceq "upload") {
      if ([string]$command[3] -match '[*?\[\]]') {
        throw "Production behavior passed a filename pattern to release upload."
      }
    }
  }

  Write-Output "release draft publication behavior tests passed"
} finally {
  if (Test-Path -LiteralPath $script:testRoot -PathType Container) {
    Remove-Item -LiteralPath $script:testRoot -Recurse -Force
  }
}
