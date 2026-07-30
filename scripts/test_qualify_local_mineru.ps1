$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$subject = Join-Path $PSScriptRoot "qualify_local_mineru.ps1"
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ("lawyer-assistance-mineru-qualification-tests-" + [Guid]::NewGuid().ToString("N"))
$keptJob = $null

function Assert-True {
  param(
    [Parameter(Mandatory = $true)][bool]$Condition,
    [Parameter(Mandatory = $true)][string]$Message
  )

  if (-not $Condition) {
    throw $Message
  }
}

function Write-Utf8NoBom {
  param(
    [Parameter(Mandatory = $true)][string]$LiteralPath,
    [Parameter(Mandatory = $true)][string]$Value
  )

  [IO.File]::WriteAllText($LiteralPath, $Value, (New-Object Text.UTF8Encoding($false)))
}

function Invoke-Qualification {
  param(
    [Parameter(Mandatory = $true)][string]$MineruMock,
    [Parameter(Mandatory = $true)][string]$GpuMock,
    [Parameter(Mandatory = $true)][string]$Evidence,
    [ValidateRange(10, 7200)]
    [int]$TimeoutSeconds = 120,
    [switch]$KeepArtifacts
  )

  $arguments = @{
    MineruCommand = $MineruMock
    NvidiaSmiCommand = $GpuMock
    EvidencePath = $Evidence
    TimeoutSeconds = $TimeoutSeconds
  }
  if ($KeepArtifacts) {
    $arguments.KeepArtifacts = $true
  }
  $output = & $subject @arguments
  return (($output | ForEach-Object { [string]$_ }) -join "`n") | ConvertFrom-Json
}

$mockMineruSource = @'
param(
  [string]$p,
  [string]$o,
  [string]$m,
  [string]$b,
  [string]$l
)
$ErrorActionPreference = "Stop"
if ($env:MINERU_MODEL_SOURCE -cne "local") { exit 21 }
foreach ($name in @("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_DATASETS_OFFLINE")) {
  if ([Environment]::GetEnvironmentVariable($name) -cne "1") { exit 22 }
}
if (-not [string]::IsNullOrEmpty($env:LA_QUALIFICATION_SECRET_CANARY)) { exit 23 }
if ($m -cne "ocr" -or $b -cne "pipeline" -or $l -cne "ch") { exit 24 }
if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { exit 25 }
$pdfAscii = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($p))
if ([regex]::Matches($pdfAscii, "/Subtype /Image").Count -ne 3 -or -not $pdfAscii.Contains("/Count 3") -or $pdfAscii.Contains("/Font")) { exit 26 }
$jobRoot = Split-Path -Parent $p
if ($env:USERPROFILE -cne (Join-Path $jobRoot "runtime") -or $env:HOME -cne (Join-Path $jobRoot "runtime")) { exit 27 }
$encodedPages = @(
  [pscustomobject]@{ Lines = @(
    "5ZCI5oiQ5rOV5b6L5paH5LmmIE9DUiDmtYvor5Ug56ysMemhtQ==",
    "5Y6f5ZGK77ya5byg5LiJ",
    "6KKr5ZGK77ya5p+Q5p+Q56eR5oqA5pyJ6ZmQ5YWs5Y+4",
    "6IGU57O755S16K+d77yaMTM4MDAxMzgwMDA=",
    "6Lqr5Lu96K+B5Y+377yaMTEwMTA1MTk0OTEyMzEwMDJY",
    "6YKu566x77yaY2FzZS50ZXN0QGV4YW1wbGUuaW52YWxpZA==",
    "5qGI5Y+377yaKDIwMjYp5LqsMDEwMeawkeWInTEyM+WPtw==",
    "6aG16Z2i5qCH6K+G77yaTE9DQUwtQ0FOQVJZLVBBR0UtT05F"
  ) },
  [pscustomobject]@{ Lines = @(
    "5ZCI5oiQ5rOV5b6L5paH5LmmIE9DUiDmtYvor5Ug56ysMumhtQ==",
    "55Sz6K+35Lq677ya5p2O5Zub",
    "6KKr55Sz6K+35Lq677ya5p+Q5p+Q6LS45piT5pyJ6ZmQ5YWs5Y+4",
    "6IGU57O755S16K+d77yaMTM5MDAxMzkwMDA=",
    "6Lqr5Lu96K+B5Y+377yaMzEwMTAxMTk4MDAxMDEwMDM3",
    "6YKu566x77yaY2FzZS50d29AZXhhbXBsZS5pbnZhbGlk",
    "5qGI5Y+377yaKDIwMjYp5rKqMDEwMeawkeWInTQ1NuWPtw==",
    "6aG16Z2i5qCH6K+G77yaTE9DQUwtQ0FOQVJZLVBBR0UtVFdP"
  ) },
  [pscustomobject]@{ Lines = @(
    "5ZCI5oiQ5rOV5b6L5paH5LmmIE9DUiDmtYvor5Ug56ysM+mhtQ==",
    "5aeU5omY5Lq677ya546L5LqU",
    "55u45a+55pa577ya5p+Q5p+Q5pyN5Yqh5pyJ6ZmQ5YWs5Y+4",
    "6IGU57O755S16K+d77yaMTM3MDAxMzcwMDA=",
    "6Lqr5Lu96K+B5Y+377yaNDQwMTA2MTk5MDAyMDIwMDE4",
    "6YKu566x77yaY2FzZS50aHJlZUBleGFtcGxlLmludmFsaWQ=",
    "5qGI5Y+377yaKDIwMjYp57KkMDEwNuawkeWInTc4OeWPtw==",
    "6aG16Z2i5qCH6K+G77yaTE9DQUwtQ0FOQVJZLVBBR0UtVEhSRUU="
  ) }
)
$expectedPages = @($encodedPages | ForEach-Object {
  [pscustomobject]@{ Lines = @($_.Lines | ForEach-Object {
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_))
  }) }
})
$content = @()
for ($pageIndex = 0; $pageIndex -lt 3; $pageIndex += 1) {
  $expected = @($expectedPages[$pageIndex].Lines)
  for ($index = 0; $index -lt $expected.Count; $index += 1) {
    $top = 40 + ($index * 80)
    $content += [ordered]@{
      type = "text"
      text = $expected[$index]
      bbox = @(40, $top, 540, ($top + 40))
      page_idx = $pageIndex
    }
  }
}
$middle = [ordered]@{
  pdf_info = @(for ($pageIndex = 0; $pageIndex -lt 3; $pageIndex += 1) {
    [ordered]@{ page_idx = $pageIndex; page_size = @(595, 841) }
  })
  _backend = "pipeline"
  _version_name = "3.4.3"
}
$resultRoot = Join-Path $o "synthetic-canary\ocr"
[void][IO.Directory]::CreateDirectory($resultRoot)
$utf8 = New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $resultRoot "synthetic-canary_content_list.json"), ($content | ConvertTo-Json -Depth 6), $utf8)
[IO.File]::WriteAllText((Join-Path $resultRoot "synthetic-canary_middle.json"), ($middle | ConvertTo-Json -Depth 6), $utf8)
exit 0
'@

$mockGpuSource = @'
if (($args -join " ") -cne "--query-gpu=index,name,driver_version,memory.total --format=csv,noheader,nounits") {
  exit 31
}
Write-Output "0, NVIDIA GeForce RTX 5090, 572.70, 32607"
exit 0
'@

try {
  [void][IO.Directory]::CreateDirectory($testRoot)
  $mockMineru = Join-Path $testRoot "mock-mineru.ps1"
  $mockGpu = Join-Path $testRoot "mock-nvidia-smi.ps1"
  Write-Utf8NoBom -LiteralPath $mockMineru -Value $mockMineruSource
  Write-Utf8NoBom -LiteralPath $mockGpu -Value $mockGpuSource

  $tokens = $null
  $parseErrors = $null
  [Management.Automation.Language.Parser]::ParseFile($subject, [ref]$tokens, [ref]$parseErrors) | Out-Null
  Assert-True -Condition ($parseErrors.Count -eq 0) -Message "qualification script failed AST validation"
  [Management.Automation.Language.Parser]::ParseFile($mockMineru, [ref]$tokens, [ref]$parseErrors) | Out-Null
  Assert-True -Condition ($parseErrors.Count -eq 0) -Message "mock MinerU script failed AST validation"

  $env:LA_QUALIFICATION_SECRET_CANARY = "must-not-reach-child"
  $evidencePath = Join-Path $testRoot "qualification.json"
  $evidence = Invoke-Qualification -MineruMock $mockMineru -GpuMock $mockGpu -Evidence $evidencePath
  $rawEvidence = [IO.File]::ReadAllText($evidencePath, [Text.Encoding]::UTF8)
  foreach ($forbidden in @($testRoot, $mockMineru, $mockGpu, "must-not-reach-child")) {
    Assert-True -Condition (-not $rawEvidence.Contains($forbidden)) -Message "evidence recorded a local path or inherited secret"
  }
  Assert-True -Condition ([bool]$evidence.qualified) -Message "mock qualification did not pass"
  Assert-True -Condition ($evidence.scope -ceq "fixed_synthetic_canary_only") -Message "qualification scope changed"
  Assert-True -Condition (-not [bool]$evidence.safety.acceptsUserCaseInput) -Message "script must never accept case input"
  Assert-True -Condition ([bool]$evidence.safety.localModelSourceForced) -Message "local model source was not recorded"
  Assert-True -Condition (-not [bool]$evidence.safety.networkIsolationEnforced) -Message "environment flags must not be reported as OS network isolation"
  Assert-True -Condition ([bool]$evidence.safety.loopbackApiMayStart) -Message "loopback API limitation was not recorded"
  Assert-True -Condition (-not [bool]$evidence.safety.appAutoEnableAuthorized) -Message "qualification must not authorize App enablement"
  Assert-True -Condition ($evidence.invocation.backend -ceq "pipeline" -and $evidence.invocation.method -ceq "ocr" -and $evidence.invocation.language -ceq "ch") -Message "fixed MinerU invocation changed"
  Assert-True -Condition ([int]$evidence.invocation.exitCode -eq 0) -Message "normal MinerU exit was not recorded"
  Assert-True -Condition ($evidence.mineru.version -ceq "3.4.3") -Message "MinerU version check changed"
  Assert-True -Condition (-not [bool]$evidence.mineru.modelManifestProvided) -Message "missing manifest was incorrectly reported as provided"
  Assert-True -Condition (-not [bool]$evidence.mineru.modelManifestTrustEstablished) -Message "manifest trust was incorrectly established"
  Assert-True -Condition (@($evidence.gpu.devices).Count -eq 1) -Message "GPU metadata count changed"
  Assert-True -Condition ([int]$evidence.gpu.selectedCudaDevice -eq 0) -Message "selected CUDA device was not recorded"
  Assert-True -Condition ([int]$evidence.gpu.devices[0].index -eq 0) -Message "GPU index was not recorded"
  Assert-True -Condition ($evidence.gpu.devices[0].name -ceq "NVIDIA GeForce RTX 5090") -Message "GPU name was not recorded"
  Assert-True -Condition ($evidence.gpu.devices[0].driverVersion -ceq "572.70") -Message "GPU driver was not recorded"
  Assert-True -Condition ([int]$evidence.gpu.devices[0].memoryMiB -eq 32607) -Message "GPU memory was not recorded"
  Assert-True -Condition ([int]$evidence.verification.pageCount -eq 3) -Message "page count check changed"
  Assert-True -Condition ((@($evidence.verification.pageIndices) -join ",") -ceq "0,1,2") -Message "page_idx check changed"
  Assert-True -Condition ([int]$evidence.verification.pageSize[0] -eq 595 -and [int]$evidence.verification.pageSize[1] -eq 841) -Message "page_size check changed"
  Assert-True -Condition ([int]$evidence.verification.exactVerifiedTextEntries -eq 24) -Message "exact verified OCR entry count changed"
  Assert-True -Condition ($evidence.hashes.generatedInputSha256 -match '^[0-9a-f]{64}$') -Message "input hash was not recorded"
  Assert-True -Condition ($evidence.mineru.commandSha256 -match '^[0-9a-f]{64}$') -Message "worker hash was not recorded"
  Assert-True -Condition (-not [bool]$evidence.retention.artifactsRetained) -Message "artifacts must be removed by default"
  Assert-True -Condition (-not [bool]$evidence.retention.artifactPathRecorded) -Message "evidence must not record local paths"
  $minimumTimeoutEvidence = Invoke-Qualification -MineruMock $mockMineru -GpuMock $mockGpu -Evidence (Join-Path $testRoot "qualification-min-timeout.json") -TimeoutSeconds 10
  $maximumTimeoutEvidence = Invoke-Qualification -MineruMock $mockMineru -GpuMock $mockGpu -Evidence (Join-Path $testRoot "qualification-max-timeout.json") -TimeoutSeconds 7200
  Assert-True -Condition ([bool]$minimumTimeoutEvidence.qualified -and [bool]$maximumTimeoutEvidence.qualified) -Message "qualification timeout boundaries changed"
  $defaultJob = Join-Path ([IO.Path]::GetTempPath()) ("lawyer-assistance-mineru-qualification-" + $evidence.runId)
  Assert-True -Condition (-not (Test-Path -LiteralPath $defaultJob)) -Message "default qualification artifacts were retained"
  $evidenceHashBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $evidencePath).Hash
  $rejectedOverwrite = $false
  try {
    Invoke-Qualification -MineruMock $mockMineru -GpuMock $mockGpu -Evidence $evidencePath | Out-Null
  } catch {
    $rejectedOverwrite = $_.Exception.Message -match "overwrite"
  }
  Assert-True -Condition $rejectedOverwrite -Message "existing evidence file was not protected from overwrite"
  $evidenceHashAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $evidencePath).Hash
  Assert-True -Condition ($evidenceHashBefore -ceq $evidenceHashAfter) -Message "existing evidence changed after rejected overwrite"

  $keptEvidencePath = Join-Path $testRoot "qualification-kept.json"
  $keptEvidence = Invoke-Qualification -MineruMock $mockMineru -GpuMock $mockGpu -Evidence $keptEvidencePath -KeepArtifacts
  $keptJob = Join-Path ([IO.Path]::GetTempPath()) ("lawyer-assistance-mineru-qualification-" + $keptEvidence.runId)
  Assert-True -Condition ([bool]$keptEvidence.retention.keepArtifactsRequested) -Message "KeepArtifacts request was not recorded"
  Assert-True -Condition ([bool]$keptEvidence.retention.artifactsRetained) -Message "explicit KeepArtifacts did not retain the fixed fixture"
  Assert-True -Condition (Test-Path -LiteralPath $keptJob -PathType Container) -Message "explicit KeepArtifacts directory was not retained"

  $badMineru = Join-Path $testRoot "mock-mineru-bad-text.ps1"
  Write-Utf8NoBom -LiteralPath $badMineru -Value $mockMineruSource.Replace(
    "5ZCI5oiQ5rOV5b6L5paH5LmmIE9DUiDmtYvor5Ug56ysMemhtQ==",
    "QkFE"
  )
  $rejectedBadText = $false
  $badTextMessage = ""
  try {
    Invoke-Qualification -MineruMock $badMineru -GpuMock $mockGpu -Evidence (Join-Path $testRoot "bad-text.json") | Out-Null
  } catch {
    $rejectedBadText = $true
    $badTextMessage = $_.Exception.Message
  }
  Assert-True -Condition $rejectedBadText -Message "incorrect OCR text was accepted"
  Assert-True -Condition ($badTextMessage -match "OCR text|canary item") -Message ("incorrect OCR text failed for the wrong reason: " + $badTextMessage)

  $badMiddle = Join-Path $testRoot "mock-mineru-bad-middle.ps1"
  Write-Utf8NoBom -LiteralPath $badMiddle -Value $mockMineruSource.Replace(
    "page_size = @(595, 841)",
    "page_size = @(596, 841)"
  )
  $rejectedBadMiddle = $false
  try {
    Invoke-Qualification -MineruMock $badMiddle -GpuMock $mockGpu -Evidence (Join-Path $testRoot "bad-middle.json") | Out-Null
  } catch {
    $rejectedBadMiddle = $_.Exception.Message -match "page_size"
  }
  Assert-True -Condition $rejectedBadMiddle -Message "incorrect middle page_size was accepted"

  Write-Output "local MinerU qualification mock tests passed"
} finally {
  Remove-Item Env:LA_QUALIFICATION_SECRET_CANARY -ErrorAction SilentlyContinue
  if ($null -ne $keptJob -and (Test-Path -LiteralPath $keptJob)) {
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    $keptAbsolute = [IO.Path]::GetFullPath($keptJob).TrimEnd('\')
    if ([IO.Path]::GetDirectoryName($keptAbsolute) -cne $tempRoot -or -not [IO.Path]::GetFileName($keptAbsolute).StartsWith("lawyer-assistance-mineru-qualification-", [StringComparison]::Ordinal)) {
      throw "refusing to clean an unexpected KeepArtifacts path"
    }
    Remove-Item -Force -Recurse -LiteralPath $keptAbsolute
  }
  if (Test-Path -LiteralPath $testRoot) {
    $testAbsolute = [IO.Path]::GetFullPath($testRoot).TrimEnd('\')
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    if ([IO.Path]::GetDirectoryName($testAbsolute) -cne $tempRoot -or -not [IO.Path]::GetFileName($testAbsolute).StartsWith("lawyer-assistance-mineru-qualification-tests-", [StringComparison]::Ordinal)) {
      throw "refusing to clean an unexpected test path"
    }
    Remove-Item -Force -Recurse -LiteralPath $testAbsolute
  }
}
