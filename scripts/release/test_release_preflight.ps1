$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "release_common.ps1")

$script:TestsRun = 0
$script:TestRoot = $null
$script:Head = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
$script:Thumbprint = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

function Assert-True {
  param([bool]$Condition, [string]$Message)
  if (-not $Condition) { throw $Message }
}

function Assert-Equal {
  param($Expected, $Actual, [string]$Message)
  if ($Expected -cne $Actual) {
    throw "$Message (expected='$Expected', actual='$Actual')"
  }
}

function Invoke-TestCase {
  param([string]$Name, [scriptblock]$Body)
  & $Body
  $script:TestsRun += 1
  Write-Output "PASS $Name"
}

function New-PreflightFixture {
  $root = Join-Path ([IO.Path]::GetTempPath()) ("lawyer-assistance-release-preflight-" + [Guid]::NewGuid().ToString("N"))
  foreach ($directory in @(
    ".git",
    "scripts\release",
    "apps\desktop\scripts",
    "apps\desktop\src-tauri\resources",
    "data\generated",
    ".release-secrets"
  )) {
    New-Item -ItemType Directory -Path (Join-Path $root $directory) -Force | Out-Null
  }
  foreach ($relative in @(
    "scripts\check_release_contract.py",
    "scripts\release\release-contract-v0.4.0.json",
    "apps\desktop\scripts\build_signed_release.ps1",
    "apps\desktop\scripts\verify_legal_resource.py",
    "scripts\generate_third_party_notices.py",
    "apps\desktop\src-tauri\resources\legal_core.sqlite",
    "apps\desktop\src-tauri\resources\LICENSE.txt",
    "apps\desktop\src-tauri\resources\THIRD_PARTY_NOTICES.txt",
    "apps\desktop\src-tauri\resources\DATA_SOURCES.md",
    "data\generated\legal_core_distribution_manifest.json",
    ".release-secrets\lawyer-assistance-updater.key"
  )) {
    $content = if ($relative -ceq "scripts\release\release-contract-v0.4.0.json") {
      @{
        release = @{
          formalVersion = "0.4.0"
          appTag = "v0.4.0"
          minerUTag = "mineru-components-v0.4.0"
        }
        repository = @{
          owner = "shilittle"
          name = "Lawyer-Assistance"
          httpsUrl = "https://github.com/shilittle/Lawyer-Assistance.git"
        }
        immutableTags = @{
          "v0.3.1" = @{
            tagObject = "9a92737f87ef3a5cc33953b874bbc97a8b5e79fc"
            peeledCommit = "0970f1c614b1bec1856869c68065162339849468"
          }
        }
      } | ConvertTo-Json -Depth 5
    } else {
      "fixture"
    }
    [IO.File]::WriteAllText((Join-Path $root $relative), $content, [Text.UTF8Encoding]::new($false))
  }
  return $root
}

function New-PreflightState {
  return [ordered]@{
    IsWindows = $true
    FormalExitCode = 0
    Branch = "main"
    Status = ""
    FetchExitCode = 0
    OriginMain = $script:Head
    RemoteMain = $script:Head
    OriginUrl = "https://github.com/shilittle/Lawyer-Assistance.git"
    SourceTagType = "tag"
    SourceTagObject = "9a92737f87ef3a5cc33953b874bbc97a8b5e79fc"
    SourceTagCommit = "0970f1c614b1bec1856869c68065162339849468"
    RemoteSourceTagObject = "9a92737f87ef3a5cc33953b874bbc97a8b5e79fc"
    RemoteSourceTagCommit = "0970f1c614b1bec1856869c68065162339849468"
    ReleaseTagMode = "absent"
    LegalExitCode = 0
    NoticesExitCode = 0
    CiMode = "success"
    Certificates = @([pscustomobject]@{
      HasPrivateKey = $true
      NotBefore = (Get-Date).AddDays(-1)
      NotAfter = (Get-Date).AddDays(30)
      Thumbprint = $script:Thumbprint
    })
    PrivateKeyReadable = $true
    AuthenticodeProbeValid = $true
    UpdaterKeyValid = $true
    Calls = [Collections.Generic.List[object]]::new()
    CredentialProbeCalls = [Collections.Generic.List[object]]::new()
  }
}

function New-PreflightAdapters {
  param([hashtable]$State)

  $fixtureHead = $script:Head
  $isWindows = { return [bool]$State.IsWindows }.GetNewClosure()
  $getCertificates = { return @($State.Certificates) }.GetNewClosure()
  $testPrivateKey = { param($Certificate) return [bool]$State.PrivateKeyReadable }.GetNewClosure()
  $probeAuthenticode = {
    param([string]$ProjectRoot, [string]$Thumbprint, [Uri]$TimestampUri)
    [void]$State.CredentialProbeCalls.Add([pscustomobject][ordered]@{
      Kind = "Authenticode"
      ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
      Thumbprint = $Thumbprint
      TimestampUri = $TimestampUri.AbsoluteUri
    })
    return [bool]$State.AuthenticodeProbeValid
  }.GetNewClosure()
  $probeUpdater = {
    param([string]$ProjectRoot, [string]$PrivateKeyPath, [string]$Password)
    [void]$State.CredentialProbeCalls.Add([pscustomobject][ordered]@{
      Kind = "Updater"
      ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
      PrivateKeyPath = [IO.Path]::GetFullPath($PrivateKeyPath)
      PasswordPresent = -not [string]::IsNullOrWhiteSpace($Password)
    })
    return [bool]$State.UpdaterKeyValid
  }.GetNewClosure()
  $invokeExternal = {
    param([string]$FilePath, [string[]]$ArgumentList)
    [void]$State.Calls.Add([pscustomobject]@{ FilePath = $FilePath; Arguments = @($ArgumentList) })
    $joined = $ArgumentList -join "`n"
    $exitCode = 0
    $output = ""
    if ($FilePath -ceq "python") {
      if ($ArgumentList[0] -like "*check_release_contract.py") {
        $exitCode = [int]$State.FormalExitCode
      } elseif ($ArgumentList[0] -like "*verify_legal_resource.py") {
        $exitCode = [int]$State.LegalExitCode
      } elseif ($ArgumentList[0] -like "*generate_third_party_notices.py") {
        $exitCode = [int]$State.NoticesExitCode
      } else {
        $exitCode = 99
      }
    } elseif ($FilePath -ceq "git") {
      if ($joined -match '(?m)^remote$' -and $joined -match '(?m)^get-url$') {
        $output = [string]$State.OriginUrl
      } elseif ($joined -match '(?m)^symbolic-ref$') {
        $output = [string]$State.Branch
      } elseif ($joined -match '(?m)^status$') {
        $output = [string]$State.Status
      } elseif ($joined -match '(?m)^fetch$') {
        $exitCode = [int]$State.FetchExitCode
      } elseif ($joined -match '(?m)^ls-remote$' -and $joined -match 'refs/heads/main') {
        $output = "$($State.RemoteMain)`trefs/heads/main"
      } elseif ($joined -match '(?m)^cat-file$' -and $joined -match 'refs/tags/v0\.3\.1') {
        $output = [string]$State.SourceTagType
      } elseif ($joined -match '(?m)^rev-parse$' -and $joined -match 'refs/tags/v0\.3\.1\^\{\}') {
        $output = [string]$State.SourceTagCommit
      } elseif ($joined -match '(?m)^rev-parse$' -and $joined -match 'refs/tags/v0\.3\.1') {
        $output = [string]$State.SourceTagObject
      } elseif ($joined -match '(?m)^ls-remote$' -and $joined -match 'refs/tags/v0\.3\.1') {
        $output = "$($State.RemoteSourceTagObject)`trefs/tags/v0.3.1`n$($State.RemoteSourceTagCommit)`trefs/tags/v0.3.1^{}"
      } elseif ($joined -match '(?m)^show-ref$') {
        $tag = if ($joined -match 'refs/tags/v0\.4\.0') { "app" } else { "mineru" }
        switch ([string]$State.ReleaseTagMode) {
          "absent" { $exitCode = 1 }
          "partial" { $exitCode = if ($tag -ceq "app") { 0 } else { 1 } }
          default { $exitCode = 0 }
        }
      } elseif ($joined -match '(?m)^ls-remote$' -and $joined -match 'refs/tags/v0\.4\.0') {
        switch ([string]$State.ReleaseTagMode) {
          "absent" { $output = "" }
          "partial" { $output = "$fixtureHead`trefs/tags/v0.4.0^{}" }
          { $_ -in @("present", "lightweight", "drift") } {
            $appObject = "cccccccccccccccccccccccccccccccccccccccc"
            $mineruObject = "dddddddddddddddddddddddddddddddddddddddd"
            $peeled = if ($State.ReleaseTagMode -ceq "drift") { "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" } else { $fixtureHead }
            $output = "$appObject`trefs/tags/v0.4.0`n$peeled`trefs/tags/v0.4.0^{}`n$mineruObject`trefs/tags/mineru-components-v0.4.0`n$peeled`trefs/tags/mineru-components-v0.4.0^{}"
          }
        }
      } elseif ($joined -match '(?m)^cat-file$' -and $joined -match 'refs/tags/(v0\.4\.0|mineru-components-v0\.4\.0)') {
        $output = if ($State.ReleaseTagMode -ceq "lightweight") { "commit" } else { "tag" }
      } elseif ($joined -match '(?m)^rev-parse$' -and $joined -match 'refs/tags/v0\.4\.0\^\{\}') {
        $output = if ($State.ReleaseTagMode -ceq "drift") { "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" } else { $fixtureHead }
      } elseif ($joined -match '(?m)^rev-parse$' -and $joined -match 'refs/tags/mineru-components-v0\.4\.0\^\{\}') {
        $output = if ($State.ReleaseTagMode -ceq "drift") { "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" } else { $fixtureHead }
      } elseif ($joined -match '(?m)^rev-parse$' -and $joined -match 'refs/tags/v0\.4\.0') {
        $output = "cccccccccccccccccccccccccccccccccccccccc"
      } elseif ($joined -match '(?m)^rev-parse$' -and $joined -match 'refs/tags/mineru-components-v0\.4\.0') {
        $output = "dddddddddddddddddddddddddddddddddddddddd"
      } elseif ($joined -match '(?m)^rev-parse$' -and $joined -match 'refs/remotes/origin/main') {
        $output = [string]$State.OriginMain
      } elseif ($joined -match '(?m)^rev-parse$' -and $joined -match '(?m)^HEAD$') {
        $output = $fixtureHead
      } else {
        $exitCode = 98
      }
    } elseif ($FilePath -ceq "gh") {
      switch ([string]$State.CiMode) {
        "success" {
          $output = @([ordered]@{
            databaseId = 101
            headBranch = "main"
            headSha = $fixtureHead
            status = "completed"
            conclusion = "success"
            event = "push"
            workflowName = "fixture"
          }) | ConvertTo-Json -Compress
        }
        "pull_request_only" {
          $output = @([ordered]@{
            databaseId = 101
            headBranch = "codex/release-v0.4.0"
            headSha = $fixtureHead
            status = "completed"
            conclusion = "success"
            event = "pull_request"
            workflowName = "fixture"
          }) | ConvertTo-Json -Compress
        }
        "failed_latest" {
          $output = @(
            [ordered]@{ databaseId = 102; headBranch = "main"; headSha = $fixtureHead; status = "completed"; conclusion = "failure"; event = "push"; workflowName = "fixture" },
            [ordered]@{ databaseId = 101; headBranch = "main"; headSha = $fixtureHead; status = "completed"; conclusion = "success"; event = "push"; workflowName = "fixture" }
          ) | ConvertTo-Json -Compress
        }
        "missing" { $output = "[]" }
        default { $exitCode = 97 }
      }
    } else {
      $exitCode = 96
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Output = $output }
  }.GetNewClosure()
  return @{
    IsWindows = $isWindows
    InvokeExternal = $invokeExternal
    GetCodeSigningCertificates = $getCertificates
    TestCertificatePrivateKey = $testPrivateKey
    ProbeAuthenticodeTimestamp = $probeAuthenticode
    ProbeUpdaterKey = $probeUpdater
  }
}

function Invoke-FixturePreflight {
  param([hashtable]$State)
  $adapters = New-PreflightAdapters $State
  return Invoke-LawyerAssistanceReleasePreflightCore `
    -ProjectRoot $script:TestRoot `
    -CodeSigningThumbprint $script:Thumbprint `
    -UpdaterPrivateKeyPath (Join-Path $script:TestRoot ".release-secrets\lawyer-assistance-updater.key") `
    -TimestampUrl "https://timestamp.example.invalid" `
    -Adapters $adapters
}

function Assert-PreflightFailure {
  param([hashtable]$State, [string]$ResultCode, [int]$ExitCode)
  try {
    Invoke-FixturePreflight $State | Out-Null
  } catch {
    $failure = Get-LawyerAssistanceReleaseFailure $_
    Assert-True ($null -ne $failure) "Failure did not carry a stable release result"
    Assert-Equal $ResultCode $failure.ResultCode "Unexpected stable result code"
    Assert-Equal $ExitCode $failure.ExitCode "Unexpected stable exit code"
    return
  }
  throw "Expected preflight failure $ResultCode"
}

$script:TestRoot = New-PreflightFixture
$previousPassword = $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD
$passwordExisted = $null -ne (Get-Item Env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD -ErrorAction SilentlyContinue)
$previousFixtureOverride = $env:LAWYER_ASSISTANCE_ALLOW_CI_LEGAL_FIXTURE
$fixtureOverrideExisted = $null -ne (Get-Item Env:LAWYER_ASSISTANCE_ALLOW_CI_LEGAL_FIXTURE -ErrorAction SilentlyContinue)
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = "fixture-password"
try {
  Invoke-TestCase "successful exact formal preflight" {
    $state = New-PreflightState
    $result = Invoke-FixturePreflight $state
    Assert-Equal "REL-PREFLIGHT-OK" $result.ResultCode "Preflight did not succeed"
    Assert-Equal $script:Head $result.Head "Preflight was not bound to exact HEAD"
    $formal = @($state.Calls | Where-Object { $_.FilePath -ceq "python" -and $_.Arguments[0] -like "*check_release_contract.py" })
    Assert-Equal 1 $formal.Count "Formal contract checker call count"
    Assert-True (($formal[0].Arguments -join "|") -match '\|--contract\|.*release-contract-v0\.4\.0\.json\|--mode\|formal$') "Formal checker arguments were not fixed"
    $authenticodeProbes = @($state.CredentialProbeCalls | Where-Object { $_.Kind -ceq "Authenticode" })
    $updaterProbes = @($state.CredentialProbeCalls | Where-Object { $_.Kind -ceq "Updater" })
    Assert-Equal 1 $authenticodeProbes.Count "Authenticode credential probe call count"
    Assert-Equal 1 $updaterProbes.Count "Updater credential probe call count"
    Assert-Equal ([IO.Path]::GetFullPath($script:TestRoot)) $authenticodeProbes[0].ProjectRoot "Authenticode probe root"
    Assert-Equal $script:Thumbprint $authenticodeProbes[0].Thumbprint "Authenticode probe thumbprint"
    Assert-Equal "https://timestamp.example.invalid/" $authenticodeProbes[0].TimestampUri "Authenticode probe RFC3161 URI"
    Assert-Equal ([IO.Path]::GetFullPath($script:TestRoot)) $updaterProbes[0].ProjectRoot "Updater probe root"
    Assert-Equal ([IO.Path]::GetFullPath((Join-Path $script:TestRoot ".release-secrets\lawyer-assistance-updater.key"))) $updaterProbes[0].PrivateKeyPath "Updater probe key path"
    Assert-True $updaterProbes[0].PasswordPresent "Updater probe did not receive a nonempty password"
    Assert-True (-not ($updaterProbes[0].PSObject.Properties.Name -contains "Password")) "Updater probe test evidence retained a password value"
  }
  Invoke-TestCase "preflight normalizes whitespace in the selected certificate thumbprint" {
    $state = New-PreflightState
    $spacedThumbprint = (($script:Thumbprint -split '(?<=\G.{4})' | Where-Object { $_ }) -join ' ')
    $adapters = New-PreflightAdapters $state
    $result = Invoke-LawyerAssistanceReleasePreflightCore `
      -ProjectRoot $script:TestRoot `
      -CodeSigningThumbprint $spacedThumbprint `
      -UpdaterPrivateKeyPath (Join-Path $script:TestRoot ".release-secrets\lawyer-assistance-updater.key") `
      -TimestampUrl "https://timestamp.example.invalid" `
      -Adapters $adapters
    Assert-Equal $script:Thumbprint $result.CodeSigningThumbprint "Preflight did not return the normalized thumbprint"
    $authenticodeProbe = @($state.CredentialProbeCalls | Where-Object { $_.Kind -ceq "Authenticode" })
    Assert-Equal 1 $authenticodeProbe.Count "Normalized Authenticode probe call count"
    Assert-Equal $script:Thumbprint $authenticodeProbe[0].Thumbprint "Normalized thumbprint was not used by the real capability seam"
  }
  Invoke-TestCase "preflight consumes immutable identity from the checked-in contract" {
    $contractPath = Join-Path $script:TestRoot "scripts\release\release-contract-v0.4.0.json"
    $saved = [IO.File]::ReadAllBytes($contractPath)
    try {
      $contract = Get-Content -LiteralPath $contractPath -Raw -Encoding UTF8 | ConvertFrom-Json
      $contract.immutableTags.'v0.3.1'.peeledCommit = "ffffffffffffffffffffffffffffffffffffffff"
      [IO.File]::WriteAllText(
        $contractPath,
        ($contract | ConvertTo-Json -Depth 8),
        [Text.UTF8Encoding]::new($false)
      )
      $state = New-PreflightState
      Assert-PreflightFailure $state "REL-SOURCE-TAG-DRIFT" 16
    } finally {
      [IO.File]::WriteAllBytes($contractPath, $saved)
    }
  }

  Invoke-TestCase "early platform failure preserves caller location stack" {
    $state = New-PreflightState
    $state.IsWindows = $false
    $before = @(Get-Location -Stack).Count
    Assert-PreflightFailure $state "REL-PLATFORM-UNSUPPORTED" 10
    $after = @(Get-Location -Stack).Count
    Assert-Equal $before $after "Early preflight failure consumed the caller location stack"
  }

  Invoke-TestCase "formal version drift fails closed" {
    $state = New-PreflightState
    $state.FormalExitCode = 1
    Assert-PreflightFailure $state "REL-VERSION-CONTRACT-INVALID" 12
  }
  Invoke-TestCase "non-main branch fails closed" {
    $state = New-PreflightState
    $state.Branch = "codex/release-v0.4.0"
    Assert-PreflightFailure $state "REL-BRANCH-NOT-MAIN" 13
  }
  Invoke-TestCase "dirty worktree fails closed" {
    $state = New-PreflightState
    $state.Status = "?? unexpected.txt"
    Assert-PreflightFailure $state "REL-WORKTREE-DIRTY" 40
  }
  Invoke-TestCase "fetch failure has stable code" {
    $state = New-PreflightState
    $state.FetchExitCode = 1
    Assert-PreflightFailure $state "REL-REMOTE-FETCH-FAILED" 14
  }
  Invoke-TestCase "origin repository mismatch fails before fetch" {
    $state = New-PreflightState
    $state.OriginUrl = "https://github.com/attacker/Lawyer-Assistance.git"
    Assert-PreflightFailure $state "REL-REPOSITORY-INVALID" 11
  }
  Invoke-TestCase "fresh origin main mismatch fails closed" {
    $state = New-PreflightState
    $state.OriginMain = "ffffffffffffffffffffffffffffffffffffffff"
    Assert-PreflightFailure $state "REL-HEAD-NOT-ORIGIN-MAIN" 15
  }
  Invoke-TestCase "live origin main readback mismatch fails closed" {
    $state = New-PreflightState
    $state.RemoteMain = "ffffffffffffffffffffffffffffffffffffffff"
    Assert-PreflightFailure $state "REL-REMOTE-READBACK-MISMATCH" 15
  }
  Invoke-TestCase "immutable v0.3.1 drift fails closed" {
    $state = New-PreflightState
    $state.RemoteSourceTagObject = "ffffffffffffffffffffffffffffffffffffffff"
    Assert-PreflightFailure $state "REL-SOURCE-TAG-DRIFT" 16
  }
  Invoke-TestCase "partial release tag pair fails closed" {
    $state = New-PreflightState
    $state.ReleaseTagMode = "partial"
    Assert-PreflightFailure $state "REL-RELEASE-TAG-PAIR-INCOMPLETE" 17
  }
  Invoke-TestCase "lightweight release tag fails closed" {
    $state = New-PreflightState
    $state.ReleaseTagMode = "lightweight"
    Assert-PreflightFailure $state "REL-RELEASE-TAG-DRIFT" 17
  }
  Invoke-TestCase "annotated exact release tag pair is accepted" {
    $state = New-PreflightState
    $state.ReleaseTagMode = "present"
    $result = Invoke-FixturePreflight $state
    Assert-Equal "REL-PREFLIGHT-OK" $result.ResultCode "Exact annotated release tags were rejected"
  }
  Invoke-TestCase "legal resource failure has stable code and restores CI override" {
    $env:LAWYER_ASSISTANCE_ALLOW_CI_LEGAL_FIXTURE = "caller-value"
    $state = New-PreflightState
    $state.LegalExitCode = 1
    Assert-PreflightFailure $state "REL-LEGAL-RESOURCE-INVALID" 18
    Assert-Equal "caller-value" $env:LAWYER_ASSISTANCE_ALLOW_CI_LEGAL_FIXTURE "Legal fixture override was not restored"
  }
  Invoke-TestCase "notices failure has stable code" {
    $state = New-PreflightState
    $state.NoticesExitCode = 1
    Assert-PreflightFailure $state "REL-NOTICES-INCOMPLETE" 19
  }
  Invoke-TestCase "pull request CI does not close final main" {
    $state = New-PreflightState
    $state.CiMode = "pull_request_only"
    Assert-PreflightFailure $state "REL-CI-CLOSURE-INCOMPLETE" 24
  }
  Invoke-TestCase "GitHub CLI host override fails closed" {
    $savedGhHost = Get-Item Env:GH_HOST -ErrorAction SilentlyContinue
    $env:GH_HOST = "attacker.example"
    try {
      $state = New-PreflightState
      Assert-PreflightFailure $state "REL-REPOSITORY-INVALID" 11
    } finally {
      if ($null -ne $savedGhHost) { $env:GH_HOST = [string]$savedGhHost.Value }
      else { Remove-Item Env:GH_HOST -ErrorAction SilentlyContinue }
    }
  }
  Invoke-TestCase "latest failed CI cannot be hidden by an older success" {
    $state = New-PreflightState
    $state.CiMode = "failed_latest"
    Assert-PreflightFailure $state "REL-CI-CLOSURE-INCOMPLETE" 24
  }
  Invoke-TestCase "missing certificate fails closed" {
    $state = New-PreflightState
    $state.Certificates = @()
    Assert-PreflightFailure $state "REL-AUTH-CERT-NONE" 20
  }
  Invoke-TestCase "unreadable certificate private key fails closed" {
    $state = New-PreflightState
    $state.PrivateKeyReadable = $false
    Assert-PreflightFailure $state "REL-AUTH-PRIVATE-KEY-UNREADABLE" 22
  }
  Invoke-TestCase "failed real RFC3161 Authenticode probe fails closed" {
    $state = New-PreflightState
    $state.AuthenticodeProbeValid = $false
    Assert-PreflightFailure $state "REL-AUTH-TIMESTAMP-PROBE-FAILED" 23
  }
  Invoke-TestCase "RFC3161 inspector fails closed for an unsigned PE and wrong signer" {
    $signtool = Get-LawyerAssistanceSignTool
    Assert-True (-not [string]::IsNullOrWhiteSpace($signtool)) "Windows SDK signtool was not found for the inspector test"
    $unsigned = Join-Path $PSHOME "powershell.exe"
    Assert-True (-not (Test-LawyerAssistanceRfc3161Authenticode $unsigned ("D" * 40) $signtool)) "Unsigned or wrong-signer PE was accepted"
  }
  Invoke-TestCase "RFC3161 inspector accepts a real Windows SDK signed PE and binds the signer" {
    $signtool = Get-LawyerAssistanceSignTool
    $signature = Get-AuthenticodeSignature -LiteralPath $signtool
    Assert-True ($signature.Status -eq [Management.Automation.SignatureStatus]::Valid) "SDK signtool fixture is not validly signed"
    Assert-True (Test-LawyerAssistanceRfc3161Authenticode $signtool $signature.SignerCertificate.Thumbprint $signtool) "Real RFC3161 fixture was rejected"
    Assert-True (-not (Test-LawyerAssistanceRfc3161Authenticode $signtool ("D" * 40) $signtool)) "Real RFC3161 fixture accepted the wrong signer"
  }
  Invoke-TestCase "missing updater key fails closed" {
    $key = Join-Path $script:TestRoot ".release-secrets\lawyer-assistance-updater.key"
    $saved = [IO.File]::ReadAllBytes($key)
    Remove-Item -LiteralPath $key -Force
    try {
      $state = New-PreflightState
      Assert-PreflightFailure $state "REL-UPDATER-KEY-MISSING" 30
    } finally {
      [IO.File]::WriteAllBytes($key, $saved)
    }
  }
  Invoke-TestCase "missing updater password fails closed" {
    Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD -ErrorAction SilentlyContinue
    try {
      $state = New-PreflightState
      Assert-PreflightFailure $state "REL-UPDATER-PASSWORD-MISSING" 31
    } finally {
      $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = "fixture-password"
    }
  }
  Invoke-TestCase "wrong updater key or password fails closed" {
    $state = New-PreflightState
    $state.UpdaterKeyValid = $false
    Assert-PreflightFailure $state "REL-UPDATER-KEY-MISMATCH" 32
  }
  Invoke-TestCase "fixed cleanup preserves secrets source and unrelated output" {
    $paths = Get-LawyerAssistanceFixedReleaseOutputPaths $script:TestRoot
    foreach ($path in $paths.Files) {
      New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($path)) -Force | Out-Null
      [IO.File]::WriteAllText($path, "generated")
    }
    foreach ($path in $paths.Directories) {
      New-Item -ItemType Directory -Path $path -Force | Out-Null
      [IO.File]::WriteAllText((Join-Path $path "generated.txt"), "generated")
    }
    $unrelated = Join-Path $script:TestRoot "dist\unrelated-user-file.txt"
    [IO.File]::WriteAllText($unrelated, "preserve")
    $key = Join-Path $script:TestRoot ".release-secrets\lawyer-assistance-updater.key"
    $cleanup = Remove-LawyerAssistanceFixedReleaseOutputs $script:TestRoot
    Assert-Equal "REL-CLEANUP-OK" $cleanup.ResultCode "Cleanup result"
    foreach ($path in $paths.Files + $paths.Directories) {
      Assert-True (-not (Test-Path -LiteralPath $path)) "Fixed generated output survived cleanup: $path"
    }
    Assert-True (Test-Path -LiteralPath $unrelated -PathType Leaf) "Cleanup removed an unrelated file"
    Assert-True (Test-Path -LiteralPath $key -PathType Leaf) "Cleanup removed the updater private key"
  }
  Invoke-TestCase "production wrapper exposes no adapter or bypass parameter" {
    $wrapper = Get-Content -LiteralPath (Join-Path $PSScriptRoot "release_preflight.ps1") -Raw -Encoding UTF8
    Assert-True ($wrapper -notmatch '(?im)^\s*\[.*\]\s*\$(Adapters|Bypass|Skip[A-Za-z]+)') "Production wrapper exposed a test adapter or bypass parameter"
  }
  Invoke-TestCase "signed build exit resolution preserves stable gates and maps unexpected failures" {
    $exitCodeCopy = Get-LawyerAssistanceReleaseExitCodes
    $exitCodeCopy.Success = 999
    Assert-Equal 0 (Get-LawyerAssistanceReleaseExitCodes).Success "Release exit-code lookup returned mutable shared state"
    foreach ($stable in @(0, 10, 13, 20, 23, 32, 40, 50, 51, 60)) {
      Assert-Equal $stable (Resolve-LawyerAssistanceSignedBuildExitCode $stable) "Stable signed-build exit code was not preserved"
    }
    foreach ($unexpected in @(-1, 1, 2, 49, 52, 255)) {
      Assert-Equal 50 (Resolve-LawyerAssistanceSignedBuildExitCode $unexpected) "Unexpected signed-build exit code was not mapped to 50"
    }
    try {
      Throw-LawyerAssistanceReleaseFailure "REL-BRANCH-NOT-MAIN" 13 "fixture"
    } catch {
      $stableFailure = Resolve-LawyerAssistanceSignedBuildFailure $_
      Assert-Equal "REL-BRANCH-NOT-MAIN" $stableFailure.ResultCode "Structured signed-build result code was not preserved"
      Assert-Equal 13 $stableFailure.ExitCode "Structured signed-build exit code was not preserved"
    }
    try {
      throw "unexpected fixture"
    } catch {
      $unexpectedFailure = Resolve-LawyerAssistanceSignedBuildFailure $_
      Assert-Equal "REL-SIGNED-BUILD-FAILED" $unexpectedFailure.ResultCode "Unexpected signed-build result code"
      Assert-Equal 50 $unexpectedFailure.ExitCode "Unexpected signed-build exit code"
    }
  }
  Invoke-TestCase "environment snapshots restore present and missing values" {
    $names = @(
      "LAWYER_ASSISTANCE_TEST_ENV_PRESENT",
      "LAWYER_ASSISTANCE_TEST_ENV_MISSING"
    )
    $env:LAWYER_ASSISTANCE_TEST_ENV_PRESENT = "caller-value"
    Remove-Item Env:LAWYER_ASSISTANCE_TEST_ENV_MISSING -ErrorAction SilentlyContinue
    $snapshot = Get-LawyerAssistanceEnvironmentSnapshot $names
    $env:LAWYER_ASSISTANCE_TEST_ENV_PRESENT = "changed"
    $env:LAWYER_ASSISTANCE_TEST_ENV_MISSING = "changed"
    Restore-LawyerAssistanceEnvironmentSnapshot $snapshot
    Assert-Equal "caller-value" $env:LAWYER_ASSISTANCE_TEST_ENV_PRESENT "Present environment variable was not restored"
    Assert-True (-not (Test-Path Env:LAWYER_ASSISTANCE_TEST_ENV_MISSING)) "Absent environment variable became present"
    foreach ($name in $names) { Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue }
  }
  Invoke-TestCase "signed build guards Pop-Location and restores TAURI caller environment" {
    $signedBuild = Get-Content -LiteralPath (Join-Path $PSScriptRoot "..\..\apps\desktop\scripts\build_signed_release.ps1") -Raw -Encoding UTF8
    Assert-True ($signedBuild -match '\$releaseLocationPushed\s*=\s*\$false') "Signed build has no location guard"
    Assert-True ($signedBuild -match 'if\s*\(\$releaseLocationPushed\)\s*\{\s*Pop-Location') "Signed build still unconditionally pops the caller stack"
    Assert-True ($signedBuild -match 'Get-LawyerAssistanceEnvironmentSnapshot\s+@\(') "Signed build does not capture caller TAURI environment"
    Assert-True ($signedBuild -match 'Restore-LawyerAssistanceEnvironmentSnapshot\s+\$tauriSigningEnvironment') "Signed build does not restore caller TAURI environment"
  }
} finally {
  if ($passwordExisted) {
    $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = $previousPassword
  } else {
    Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD -ErrorAction SilentlyContinue
  }
  if ($fixtureOverrideExisted) {
    $env:LAWYER_ASSISTANCE_ALLOW_CI_LEGAL_FIXTURE = $previousFixtureOverride
  } else {
    Remove-Item Env:LAWYER_ASSISTANCE_ALLOW_CI_LEGAL_FIXTURE -ErrorAction SilentlyContinue
  }
  if ($null -ne $script:TestRoot -and (Test-Path -LiteralPath $script:TestRoot -PathType Container)) {
    $resolvedRoot = [IO.Path]::GetFullPath($script:TestRoot)
    $resolvedTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if (-not $resolvedRoot.StartsWith($resolvedTemp, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolvedRoot) -notlike "lawyer-assistance-release-preflight-*") {
      throw "Refusing to remove an unexpected test fixture root"
    }
    Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
  }
}

Write-Output "PASS all $script:TestsRun release preflight behavior tests"
