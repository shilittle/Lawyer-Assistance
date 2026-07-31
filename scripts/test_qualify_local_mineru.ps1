$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$subject = Join-Path $PSScriptRoot "qualify_local_mineru.ps1"
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ("lawyer-assistance-mineru-qualification-tests-" + [Guid]::NewGuid().ToString("N"))
$keptJob = $null
$timeoutProcessIds = @()
$processTreeRootId = 0
$processTreeProcess = $null

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

function Get-SubjectFunctionDefinition {
  param(
    [Parameter(Mandatory = $true)]
    [Management.Automation.Language.ScriptBlockAst]$Ast,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  $definitions = @(
    $Ast.FindAll({
      param($node)
      $node -is [Management.Automation.Language.FunctionDefinitionAst]
    }, $true) | Where-Object { $_.Name -ceq $Name }
  )
  Assert-True -Condition ($definitions.Count -eq 1) -Message ("expected exactly one subject function named " + $Name)
  return $definitions[0]
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

$timeoutProcessMockSource = @'
param(
  [Parameter(Mandatory = $true)][string]$PidRecordPath
)
$ErrorActionPreference = "Stop"
[IO.File]::AppendAllText(
  $PidRecordPath,
  ("{0}`n" -f $PID),
  [Text.Encoding]::ASCII
)
Write-Output ("discarded-stdout:" + $env:LA_TIMEOUT_SECRET_CANARY)
[Console]::Error.WriteLine("discarded-stderr:" + $PidRecordPath)
Start-Sleep -Seconds 60
'@

$processTreeMockSource = @'
param(
  [Parameter(Mandatory = $true)][string]$PidRecordPath
)
$ErrorActionPreference = "Stop"
$childStartInfo = New-Object Diagnostics.ProcessStartInfo
$childStartInfo.FileName = Join-Path $env:SystemRoot "System32\PING.EXE"
$childStartInfo.Arguments = "-n 61 127.0.0.1"
$childStartInfo.UseShellExecute = $false
$childStartInfo.CreateNoWindow = $true
$childStartInfo.RedirectStandardOutput = $true
$childStartInfo.RedirectStandardError = $true
$child = [Diagnostics.Process]::Start($childStartInfo)
[IO.File]::WriteAllText(
  $PidRecordPath,
  ("{0}`n{1}`n" -f $PID, $child.Id),
  [Text.Encoding]::ASCII
)
Start-Sleep -Seconds 60
'@

try {
  [void][IO.Directory]::CreateDirectory($testRoot)
  $mockMineru = Join-Path $testRoot "mock-mineru.ps1"
  $mockGpu = Join-Path $testRoot "mock-nvidia-smi.ps1"
  $timeoutProcessMock = Join-Path $testRoot "mock-timeout-process.ps1"
  $processTreeMock = Join-Path $testRoot "mock-process-tree.ps1"
  Write-Utf8NoBom -LiteralPath $mockMineru -Value $mockMineruSource
  Write-Utf8NoBom -LiteralPath $mockGpu -Value $mockGpuSource
  Write-Utf8NoBom -LiteralPath $timeoutProcessMock -Value $timeoutProcessMockSource
  Write-Utf8NoBom -LiteralPath $processTreeMock -Value $processTreeMockSource

  $tokens = $null
  $parseErrors = $null
  $subjectAst = [Management.Automation.Language.Parser]::ParseFile($subject, [ref]$tokens, [ref]$parseErrors)
  Assert-True -Condition ($parseErrors.Count -eq 0) -Message "qualification script failed AST validation"
  [Management.Automation.Language.Parser]::ParseFile($mockMineru, [ref]$tokens, [ref]$parseErrors) | Out-Null
  Assert-True -Condition ($parseErrors.Count -eq 0) -Message "mock MinerU script failed AST validation"
  [Management.Automation.Language.Parser]::ParseFile($timeoutProcessMock, [ref]$tokens, [ref]$parseErrors) | Out-Null
  Assert-True -Condition ($parseErrors.Count -eq 0) -Message "timeout process mock failed AST validation"
  [Management.Automation.Language.Parser]::ParseFile($processTreeMock, [ref]$tokens, [ref]$parseErrors) | Out-Null
  Assert-True -Condition ($parseErrors.Count -eq 0) -Message "process-tree mock failed AST validation"

  foreach ($functionName in @(
    "Resolve-QualificationProcessTimeoutMilliseconds",
    "ConvertTo-NativeArgument",
    "Stop-ProcessTree",
    "Invoke-SanitizedProcess"
  )) {
    $definition = Get-SubjectFunctionDefinition -Ast $subjectAst -Name $functionName
    . ([scriptblock]::Create($definition.Extent.Text))
  }

  $invokeSanitizedProcessDefinition = Get-SubjectFunctionDefinition -Ast $subjectAst -Name "Invoke-SanitizedProcess"
  $timeoutStopTreeCalls = @(
    $invokeSanitizedProcessDefinition.Body.FindAll({
      param($node)
      $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ceq "Stop-ProcessTree"
    }, $true)
  )
  Assert-True -Condition ($timeoutStopTreeCalls.Count -eq 1) -Message "sanitized timeout path must call Stop-ProcessTree exactly once"
  Assert-True -Condition (
    $timeoutStopTreeCalls[0].Extent.Text -ceq 'Stop-ProcessTree -ProcessId $process.Id'
  ) -Message "sanitized timeout path did not target the launched process tree"
  $timeoutConditional = $timeoutStopTreeCalls[0].Parent
  while ($null -ne $timeoutConditional -and $timeoutConditional -isnot [Management.Automation.Language.IfStatementAst]) {
    $timeoutConditional = $timeoutConditional.Parent
  }
  Assert-True -Condition ($null -ne $timeoutConditional) -Message "Stop-ProcessTree is no longer inside a timeout conditional"
  $timeoutConditionText = $timeoutConditional.Clauses[0].Item1.Extent.Text
  Assert-True -Condition (
    $timeoutConditionText.TrimStart().StartsWith("-not ", [StringComparison]::Ordinal) -and
    $timeoutConditionText.Contains('$process.WaitForExit($timeoutMilliseconds)')
  ) -Message "Stop-ProcessTree is no longer guarded by the bounded process timeout"
  $timeoutConditionalText = $timeoutConditional.Extent.Text
  Assert-True -Condition (
    $timeoutConditionalText.Contains('$process.WaitForExit(10000)') -and
    $timeoutConditionalText.Contains('local qualification process termination failed (stage=$Stage)') -and
    $timeoutConditionalText.Contains('local qualification process timed out (stage=$Stage)')
  ) -Message "sanitized timeout path no longer enforces bounded convergence and fixed failures"

  $timeoutCases = @(
    [pscustomobject]@{ Stage = "mineru_ocr"; IsPowerShellTestDouble = $false; InputSeconds = 10; ExpectedMilliseconds = 10000 },
    [pscustomobject]@{ Stage = "mineru_ocr"; IsPowerShellTestDouble = $false; InputSeconds = 120; ExpectedMilliseconds = 120000 },
    [pscustomobject]@{ Stage = "mineru_ocr"; IsPowerShellTestDouble = $false; InputSeconds = 1800; ExpectedMilliseconds = 1800000 },
    [pscustomobject]@{ Stage = "mineru_ocr"; IsPowerShellTestDouble = $false; InputSeconds = 7200; ExpectedMilliseconds = 7200000 },
    [pscustomobject]@{ Stage = "mineru_ocr"; IsPowerShellTestDouble = $true; InputSeconds = 10; ExpectedMilliseconds = 10000 },
    [pscustomobject]@{ Stage = "mineru_ocr"; IsPowerShellTestDouble = $true; InputSeconds = 120; ExpectedMilliseconds = 120000 },
    [pscustomobject]@{ Stage = "mineru_ocr"; IsPowerShellTestDouble = $true; InputSeconds = 1800; ExpectedMilliseconds = 1800000 },
    [pscustomobject]@{ Stage = "mineru_ocr"; IsPowerShellTestDouble = $true; InputSeconds = 7200; ExpectedMilliseconds = 7200000 },
    [pscustomobject]@{ Stage = "gpu_inventory"; IsPowerShellTestDouble = $false; InputSeconds = 10; ExpectedMilliseconds = 30000 },
    [pscustomobject]@{ Stage = "gpu_inventory"; IsPowerShellTestDouble = $false; InputSeconds = 120; ExpectedMilliseconds = 30000 },
    [pscustomobject]@{ Stage = "gpu_inventory"; IsPowerShellTestDouble = $false; InputSeconds = 1800; ExpectedMilliseconds = 30000 },
    [pscustomobject]@{ Stage = "gpu_inventory"; IsPowerShellTestDouble = $false; InputSeconds = 7200; ExpectedMilliseconds = 30000 },
    [pscustomobject]@{ Stage = "gpu_inventory"; IsPowerShellTestDouble = $true; InputSeconds = 10; ExpectedMilliseconds = 10000 },
    [pscustomobject]@{ Stage = "gpu_inventory"; IsPowerShellTestDouble = $true; InputSeconds = 120; ExpectedMilliseconds = 120000 },
    [pscustomobject]@{ Stage = "gpu_inventory"; IsPowerShellTestDouble = $true; InputSeconds = 1800; ExpectedMilliseconds = 120000 },
    [pscustomobject]@{ Stage = "gpu_inventory"; IsPowerShellTestDouble = $true; InputSeconds = 7200; ExpectedMilliseconds = 120000 }
  )
  foreach ($case in $timeoutCases) {
    $actualMilliseconds = Resolve-QualificationProcessTimeoutMilliseconds `
      -Stage $case.Stage `
      -IsPowerShellTestDouble $case.IsPowerShellTestDouble `
      -TimeoutSeconds $case.InputSeconds
    Assert-True -Condition ([int]$actualMilliseconds -eq [int]$case.ExpectedMilliseconds) -Message (
      "qualification timeout resolver changed for stage={0}, testDouble={1}, seconds={2}" -f
      $case.Stage,
      $case.IsPowerShellTestDouble,
      $case.InputSeconds
    )
  }
  $invalidStageRejected = $false
  try {
    Resolve-QualificationProcessTimeoutMilliseconds `
      -Stage "unapproved_stage" `
      -IsPowerShellTestDouble $false `
      -TimeoutSeconds 120 | Out-Null
  } catch {
    $invalidStageRejected = $true
  }
  Assert-True -Condition $invalidStageRejected -Message "qualification timeout resolver accepted an unapproved stage"

  $invokeProcessCalls = @(
    $subjectAst.FindAll({
      param($node)
      $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ceq "Invoke-SanitizedProcess"
    }, $true)
  )
  Assert-True -Condition ($invokeProcessCalls.Count -eq 2) -Message "qualification script must have exactly two sanitized process call sites"
  $observedStages = @()
  foreach ($call in $invokeProcessCalls) {
    $stageParameterIndices = @()
    $timeoutParameterIndices = @()
    $legacyTimeoutParameterIndices = @()
    for ($elementIndex = 1; $elementIndex -lt $call.CommandElements.Count; $elementIndex += 1) {
      $element = $call.CommandElements[$elementIndex]
      if ($element -isnot [Management.Automation.Language.CommandParameterAst]) {
        continue
      }
      if ($element.ParameterName -ceq "Stage") {
        $stageParameterIndices += $elementIndex
      } elseif ($element.ParameterName -ceq "TimeoutSeconds") {
        $timeoutParameterIndices += $elementIndex
      } elseif ($element.ParameterName -ceq "TimeoutMilliseconds") {
        $legacyTimeoutParameterIndices += $elementIndex
      }
    }
    Assert-True -Condition ($stageParameterIndices.Count -eq 1) -Message "sanitized process call must pass exactly one fixed stage"
    Assert-True -Condition ($timeoutParameterIndices.Count -eq 1) -Message "sanitized process call must pass top-level TimeoutSeconds exactly once"
    Assert-True -Condition ($legacyTimeoutParameterIndices.Count -eq 0) -Message "sanitized process call retained the legacy TimeoutMilliseconds parameter"
    $stageArgument = $call.CommandElements[$stageParameterIndices[0] + 1].Extent.Text
    $timeoutArgument = $call.CommandElements[$timeoutParameterIndices[0] + 1].Extent.Text
    Assert-True -Condition (
      @('"gpu_inventory"', '"mineru_ocr"') -ccontains $stageArgument
    ) -Message "sanitized process call stage must be a fixed approved literal"
    Assert-True -Condition ($timeoutArgument -ceq '$TimeoutSeconds') -Message "sanitized process call did not pass the top-level TimeoutSeconds variable"
    $observedStages += $stageArgument.Trim('"')
  }
  Assert-True -Condition (
    (($observedStages | Sort-Object) -join ",") -ceq "gpu_inventory,mineru_ocr"
  ) -Message "sanitized process call stages changed"
  $legacyTimeoutParameters = @(
    $subjectAst.FindAll({
      param($node)
      $node -is [Management.Automation.Language.CommandParameterAst] -and
        $node.ParameterName -ceq "TimeoutMilliseconds"
    }, $true)
  )
  Assert-True -Condition ($legacyTimeoutParameters.Count -eq 0) -Message "qualification script retained a TimeoutMilliseconds call parameter"
  $subjectSource = [IO.File]::ReadAllText($subject, [Text.Encoding]::UTF8)
  Assert-True -Condition (-not $subjectSource.Contains("-TimeoutMilliseconds 30000")) -Message "qualification script retained the hidden 30000ms GPU invocation"

  $topLevelTimeoutParameters = @(
    $subjectAst.ParamBlock.Parameters | Where-Object {
      $_.Name.VariablePath.UserPath -ceq "TimeoutSeconds"
    }
  )
  Assert-True -Condition ($topLevelTimeoutParameters.Count -eq 1) -Message "qualification script must define exactly one top-level TimeoutSeconds parameter"
  Assert-True -Condition (
    $null -ne $topLevelTimeoutParameters[0].DefaultValue -and
    $topLevelTimeoutParameters[0].DefaultValue.Extent.Text -ceq "1800"
  ) -Message "qualification timeout default changed"
  $timeoutParameter = (Get-Command -Name $subject).Parameters["TimeoutSeconds"]
  $timeoutRange = @($timeoutParameter.Attributes | Where-Object {
    $_ -is [Management.Automation.ValidateRangeAttribute]
  })
  Assert-True -Condition ($timeoutRange.Count -eq 1) -Message "qualification timeout range metadata changed"
  Assert-True -Condition (
    [int]$timeoutRange[0].MinRange -eq 10 -and
    [int]$timeoutRange[0].MaxRange -eq 7200
  ) -Message "qualification timeout boundaries changed"

  $env:LA_QUALIFICATION_SECRET_CANARY = "must-not-reach-child"
  $timeoutPidRecord = Join-Path $testRoot "timeout-process-tree-pids.txt"
  $timeoutEvidencePath = Join-Path $testRoot "timeout-process-tree-evidence.json"
  $timeoutSecret = "timeout-secret-must-not-leak"
  $powerShellLauncher = (Get-Process -Id $PID).Path
  $timeoutDescriptor = [pscustomobject]@{
    LauncherPath = $powerShellLauncher
    IsPowerShellTestDouble = $true
    PrefixArguments = @(
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      $timeoutProcessMock
    )
  }
  $timeoutFailure = ""
  $timeoutStopwatch = [Diagnostics.Stopwatch]::StartNew()
  try {
    Invoke-SanitizedProcess `
      -Descriptor $timeoutDescriptor `
      -Stage "gpu_inventory" `
      -Arguments @($timeoutPidRecord) `
      -Environment @{
        LA_TIMEOUT_SECRET_CANARY = $timeoutSecret
        LA_TIMEOUT_EVIDENCE_PATH = $timeoutEvidencePath
      } `
      -WorkingDirectory $testRoot `
      -TimeoutSeconds 10 | Out-Null
  } catch {
    $timeoutFailure = $_.Exception.Message
  } finally {
    $timeoutStopwatch.Stop()
  }
  $recordedTimeoutProcessIdsAreValid = $true
  if (Test-Path -LiteralPath $timeoutPidRecord -PathType Leaf) {
    foreach ($recordedProcessIdText in @(Get-Content -LiteralPath $timeoutPidRecord)) {
      $parsedProcessId = 0
      if ([int]::TryParse($recordedProcessIdText, [ref]$parsedProcessId) -and $parsedProcessId -gt 0) {
        $timeoutProcessIds += $parsedProcessId
      } else {
        $recordedTimeoutProcessIdsAreValid = $false
      }
    }
  }
  Assert-True -Condition (
    $timeoutFailure -ceq "local qualification process timed out (stage=gpu_inventory)"
  ) -Message "GPU timeout did not return the fixed stage-safe error"
  Assert-True -Condition ($timeoutStopwatch.ElapsedMilliseconds -ge 8000) -Message "GPU timeout returned before its fixed lower bound"
  Assert-True -Condition ($timeoutStopwatch.ElapsedMilliseconds -lt 30000) -Message "GPU timeout did not converge within its fixed upper bound"
  foreach ($forbidden in @($testRoot, $timeoutProcessMock, $timeoutSecret, "must-not-reach-child")) {
    Assert-True -Condition (-not $timeoutFailure.Contains($forbidden)) -Message "GPU timeout error leaked a local path or secret"
  }
  Assert-True -Condition (Test-Path -LiteralPath $timeoutPidRecord -PathType Leaf) -Message "timeout mock did not record its process tree"
  Assert-True -Condition $recordedTimeoutProcessIdsAreValid -Message "timeout mock recorded an invalid process id"
  Assert-True -Condition (
    $timeoutProcessIds.Count -eq 1 -and
    @($timeoutProcessIds | Sort-Object -Unique).Count -eq 1
  ) -Message "timeout path did not run exactly once with one root process"
  $processExitDeadline = [DateTime]::UtcNow.AddSeconds(5)
  do {
    $runningTimeoutProcesses = @(
      $timeoutProcessIds | Where-Object {
        $null -ne (Get-Process -Id $_ -ErrorAction SilentlyContinue)
      }
    )
    if ($runningTimeoutProcesses.Count -eq 0) {
      break
    }
    Start-Sleep -Milliseconds 100
  } while ([DateTime]::UtcNow -lt $processExitDeadline)
  Assert-True -Condition ($runningTimeoutProcesses.Count -eq 0) -Message "timeout process tree was not terminated"
  $timeoutProcessIds = @()
  Assert-True -Condition (-not (Test-Path -LiteralPath $timeoutEvidencePath)) -Message "timeout path produced evidence"

  $processTreePidRecord = Join-Path $testRoot "process-tree-helper-pids.txt"
  $processTreeStartInfo = New-Object Diagnostics.ProcessStartInfo
  $processTreeStartInfo.FileName = $powerShellLauncher
  $processTreeStartInfo.Arguments = ((@(
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    $processTreeMock,
    $processTreePidRecord
  ) | ForEach-Object { ConvertTo-NativeArgument -Value $_ }) -join " ")
  $processTreeStartInfo.WorkingDirectory = $testRoot
  $processTreeStartInfo.UseShellExecute = $false
  $processTreeStartInfo.CreateNoWindow = $true
  $processTreeStartInfo.RedirectStandardInput = $true
  $processTreeStartInfo.RedirectStandardOutput = $true
  $processTreeStartInfo.RedirectStandardError = $true
  $processTreeProcess = New-Object Diagnostics.Process
  $processTreeProcess.StartInfo = $processTreeStartInfo
  Assert-True -Condition $processTreeProcess.Start() -Message "process-tree helper did not start"
  $processTreeRootId = $processTreeProcess.Id
  $timeoutProcessIds = @($processTreeRootId)
  $processTreeProcess.StandardInput.Close()
  $processTreeStdoutTask = $processTreeProcess.StandardOutput.ReadToEndAsync()
  $processTreeStderrTask = $processTreeProcess.StandardError.ReadToEndAsync()
  $processTreeSetupDeadline = [DateTime]::UtcNow.AddSeconds(120)
  $recordedProcessTreeIds = @()
  do {
    if (Test-Path -LiteralPath $processTreePidRecord -PathType Leaf) {
      $candidateProcessTreeIds = @()
      $candidateProcessTreeIdsAreValid = $true
      foreach ($recordedProcessIdText in @(Get-Content -LiteralPath $processTreePidRecord)) {
        $parsedProcessId = 0
        if ([int]::TryParse($recordedProcessIdText, [ref]$parsedProcessId) -and $parsedProcessId -gt 0) {
          $candidateProcessTreeIds += $parsedProcessId
        } else {
          $candidateProcessTreeIdsAreValid = $false
        }
      }
      if ($candidateProcessTreeIdsAreValid -and $candidateProcessTreeIds.Count -gt 0) {
        $timeoutProcessIds = @(
          @($processTreeRootId) + @($candidateProcessTreeIds) |
            Sort-Object -Unique
        )
      }
      if (
        $candidateProcessTreeIdsAreValid -and
        $candidateProcessTreeIds.Count -eq 2 -and
        @($candidateProcessTreeIds | Sort-Object -Unique).Count -eq 2
      ) {
        $recordedProcessTreeIds = $candidateProcessTreeIds
        $timeoutProcessIds = @($recordedProcessTreeIds)
        break
      }
    }
    Start-Sleep -Milliseconds 100
  } while ([DateTime]::UtcNow -lt $processTreeSetupDeadline)
  Assert-True -Condition (
    $recordedProcessTreeIds.Count -eq 2 -and
    $recordedProcessTreeIds[0] -eq $processTreeRootId
  ) -Message "process-tree helper did not record its distinct root and leaf processes"
  Assert-True -Condition (
    @($recordedProcessTreeIds | Where-Object {
      $null -ne (Get-Process -Id $_ -ErrorAction SilentlyContinue)
    }).Count -eq 2
  ) -Message "process-tree helper was not live before termination"
  Stop-ProcessTree -ProcessId $processTreeRootId
  $processTreeRootExited = $false
  try {
    $processTreeRootExited = $processTreeProcess.WaitForExit(10000)
  } catch {
    $processTreeRootExited = $false
  }
  Assert-True -Condition $processTreeRootExited -Message "process-tree helper root did not converge after termination"
  $processTreeExitDeadline = [DateTime]::UtcNow.AddSeconds(5)
  do {
    $runningProcessTreeIds = @(
      $recordedProcessTreeIds | Where-Object {
        $null -ne (Get-Process -Id $_ -ErrorAction SilentlyContinue)
      }
    )
    if ($runningProcessTreeIds.Count -eq 0) {
      break
    }
    Start-Sleep -Milliseconds 100
  } while ([DateTime]::UtcNow -lt $processTreeExitDeadline)
  Assert-True -Condition ($runningProcessTreeIds.Count -eq 0) -Message "Stop-ProcessTree left a root or leaf process running"
  $processTreeStreamsDrained = $false
  $processTreeStdout = ""
  $processTreeStderr = ""
  try {
    $processTreeStreamsDrained = [Threading.Tasks.Task]::WaitAll(
      [Threading.Tasks.Task[]]@($processTreeStdoutTask, $processTreeStderrTask),
      5000
    )
    if ($processTreeStreamsDrained) {
      $processTreeStdout = $processTreeStdoutTask.GetAwaiter().GetResult()
      $processTreeStderr = $processTreeStderrTask.GetAwaiter().GetResult()
    }
  } catch {
    $processTreeStreamsDrained = $false
  }
  Assert-True -Condition $processTreeStreamsDrained -Message "process-tree helper streams did not close after termination"
  Assert-True -Condition (
    $processTreeStdout.Length -eq 0 -and
    $processTreeStderr.Length -eq 0
  ) -Message "process-tree helper emitted unexpected diagnostics"
  $timeoutProcessIds = @()
  $processTreeRootId = 0
  $processTreeProcess.Dispose()
  $processTreeProcess = $null
  $processTreeStdoutTask = $null
  $processTreeStderrTask = $null

  $evidencePath = Join-Path $testRoot "qualification.json"
  $evidence = Invoke-Qualification -MineruMock $mockMineru -GpuMock $mockGpu -Evidence $evidencePath
  $rawEvidence = [IO.File]::ReadAllText($evidencePath, [Text.Encoding]::UTF8)
  foreach ($forbidden in @($testRoot, $mockMineru, $mockGpu, "must-not-reach-child")) {
    Assert-True -Condition (-not $rawEvidence.Contains($forbidden)) -Message "evidence recorded a local path or inherited secret"
  }
  foreach ($forbiddenProperty in @(
    "stage",
    "timeout",
    "timeoutSeconds",
    "timeoutMilliseconds",
    "processKind",
    "descriptorKind",
    "isPowerShellTestDouble"
  )) {
    Assert-True -Condition (
      -not [regex]::IsMatch(
        $rawEvidence,
        ('"' + [regex]::Escape($forbiddenProperty) + '"\s*:'),
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
      )
    ) -Message ("evidence recorded forbidden process diagnostic property " + $forbiddenProperty)
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
  $maximumTimeoutEvidence = Invoke-Qualification -MineruMock $mockMineru -GpuMock $mockGpu -Evidence (Join-Path $testRoot "qualification-max-timeout.json") -TimeoutSeconds 7200
  Assert-True -Condition ([bool]$maximumTimeoutEvidence.qualified) -Message "maximum qualification timeout was not accepted"
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
  if ($processTreeRootId -gt 0) {
    try {
      if ($null -ne (Get-Command -Name Stop-ProcessTree -CommandType Function -ErrorAction SilentlyContinue)) {
        Stop-ProcessTree -ProcessId $processTreeRootId
      } else {
        Stop-Process -Id $processTreeRootId -Force -ErrorAction SilentlyContinue
      }
    } catch {
      Stop-Process -Id $processTreeRootId -Force -ErrorAction SilentlyContinue
    }
  }
  foreach ($timeoutProcessId in @($timeoutProcessIds | Sort-Object -Unique)) {
    Stop-Process -Id $timeoutProcessId -Force -ErrorAction SilentlyContinue
  }
  if ($null -ne $processTreeProcess) {
    $processTreeProcess.Dispose()
  }
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
