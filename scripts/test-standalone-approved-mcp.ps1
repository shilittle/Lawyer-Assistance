[CmdletBinding()]
param(
    [string]$Binary = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = (Resolve-Path (Join-Path $scriptDirectory '..')).Path
$originalBinary = $env:LAWYER_ASSISTANCE_MCP_E2E_BINARY
$hadOriginalBinary = Test-Path Env:LAWYER_ASSISTANCE_MCP_E2E_BINARY
$originalReleaseSha256 = $env:LAWYER_ASSISTANCE_MCP_RELEASE_SHA256
$hadOriginalReleaseSha256 = Test-Path Env:LAWYER_ASSISTANCE_MCP_RELEASE_SHA256
$stopwatch = [Diagnostics.Stopwatch]::StartNew()

function Invoke-CargoStep {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$ResultCode
    )

    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$ResultCode (exit=$LASTEXITCODE)"
    }
}

function Resolve-OrdinaryMcpBinary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Candidate
    )

    $item = Get-Item -LiteralPath $Candidate -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -le 0) {
        throw 'MCP_E2E_BINARY_NOT_REGULAR'
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'MCP_E2E_BINARY_LINK_REJECTED'
    }
    $resolved = [IO.Path]::GetFullPath($item.FullName)
    $expectedName = if ($env:OS -ceq 'Windows_NT') {
        'lawyer-assistance-mcp.exe'
    }
    else {
        'lawyer-assistance-mcp'
    }
    if ([IO.Path]::GetFileName($resolved) -cne $expectedName) {
        throw "MCP_E2E_BINARY_NAME_INVALID (expected=$expectedName)"
    }

    return $resolved
}

Push-Location $repositoryRoot
try {
    $usingExplicitBinary = -not [string]::IsNullOrWhiteSpace($Binary)
    if (-not $usingExplicitBinary) {
        Invoke-CargoStep -ResultCode 'MCP_E2E_BUILD_FAILED' -Arguments @(
            'build',
            '--locked',
            '--offline',
            '-p',
            'legal-mcp',
            '--features',
            'standalone-mcp-e2e',
            '--bin',
            'lawyer-assistance-mcp'
        )
    }

    $metadataJson = & cargo metadata --locked --offline --no-deps --format-version 1
    if ($LASTEXITCODE -ne 0) {
        throw "MCP_E2E_METADATA_FAILED (exit=$LASTEXITCODE)"
    }
    $metadata = $metadataJson | ConvertFrom-Json
    $legalMcpPackages = @($metadata.packages | Where-Object { $_.name -ceq 'legal-mcp' })
    if ($legalMcpPackages.Count -ne 1) {
        throw 'MCP_E2E_PACKAGE_METADATA_INVALID'
    }
    $expectedVersion = [string]$legalMcpPackages[0].version
    if ($expectedVersion -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') {
        throw 'MCP_E2E_PACKAGE_VERSION_INVALID'
    }

    if ($usingExplicitBinary) {
        $binaryPath = Resolve-OrdinaryMcpBinary -Candidate $Binary
    }
    else {
        $targetDirectory = [string]$metadata.target_directory
        $binaryCandidates = @(
            (Join-Path $targetDirectory 'x86_64-pc-windows-msvc\debug\lawyer-assistance-mcp.exe'),
            (Join-Path $targetDirectory 'debug\lawyer-assistance-mcp.exe')
        )
        $candidate = $binaryCandidates |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Select-Object -First 1
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            throw 'MCP_E2E_BINARY_NOT_FOUND'
        }
        $binaryPath = Resolve-OrdinaryMcpBinary -Candidate $candidate
    }

    $versionOutput = @(& $binaryPath --version 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "MCP_E2E_BINARY_VERSION_FAILED (exit=$LASTEXITCODE)"
    }
    $actualVersionLine = (($versionOutput | ForEach-Object { [string]$_ }) -join "`n").Trim()
    $expectedVersionLine = "lawyer-assistance-mcp $expectedVersion"
    if ($actualVersionLine -cne $expectedVersionLine) {
        throw "MCP_E2E_BINARY_VERSION_MISMATCH (expected=$expectedVersionLine)"
    }
    $binarySha256 = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($binarySha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'MCP_E2E_BINARY_HASH_INVALID'
    }

    $env:LAWYER_ASSISTANCE_MCP_E2E_BINARY = $binaryPath
    $env:LAWYER_ASSISTANCE_MCP_RELEASE_SHA256 = $binarySha256
    $testName = if ($usingExplicitBinary) {
        'approved_mcp::standalone_binary_tests::explicit_binary_qualification_canary_is_fail_closed'
    }
    else {
        'approved_mcp::standalone_binary_tests::app_approval_to_real_stdio_and_http_binary_is_fail_closed'
    }
    $testScope = if ($usingExplicitBinary) {
        'release-qualification-canary'
    }
    else {
        'full-standalone-session'
    }
    $testArguments = @(
        'test',
        '--locked',
        '--offline',
        '-p',
        'lawyer-assistance-desktop',
        '--features',
        'standalone-mcp-e2e',
        '--lib',
        $testName
    )
    $listedTests = @(& cargo @testArguments -- --ignored --exact --list)
    if ($LASTEXITCODE -ne 0) {
        throw "MCP_E2E_TEST_LIST_FAILED (exit=$LASTEXITCODE)"
    }
    $expectedListing = "$testName`: test"
    $listedTestCases = @(
        $listedTests |
            ForEach-Object { ([string]$_).Trim() } |
            Where-Object { $_.EndsWith(': test', [System.StringComparison]::Ordinal) }
    )
    if ($listedTestCases.Count -ne 1 -or $listedTestCases[0] -cne $expectedListing) {
        throw "MCP_E2E_TEST_NOT_EXACT (expected one exact ignored test)"
    }
    $runTestArguments = $testArguments + @(
        '--',
        '--ignored',
        '--exact',
        '--nocapture',
        '--test-threads=1'
    )
    Invoke-CargoStep -ResultCode 'MCP_E2E_TEST_FAILED' -Arguments $runTestArguments

    $binarySha256After = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($binarySha256After -cne $binarySha256) {
        throw 'MCP_E2E_BINARY_CHANGED_DURING_TEST'
    }
    $stopwatch.Stop()
    Write-Output 'MCP_STANDALONE_APPROVED_E2E=PASS'
    Write-Output "MCP_STANDALONE_APPROVED_E2E_SCOPE=$testScope"
    Write-Output "MCP_STANDALONE_APPROVED_E2E_SOURCE=$(if ($usingExplicitBinary) { 'explicit' } else { 'default-debug' })"
    Write-Output "MCP_STANDALONE_APPROVED_E2E_BINARY=$binaryPath"
    Write-Output "MCP_STANDALONE_APPROVED_E2E_VERSION=$expectedVersion"
    Write-Output "MCP_STANDALONE_APPROVED_E2E_SHA256=$binarySha256"
    Write-Output "MCP_STANDALONE_APPROVED_E2E_ELAPSED_MS=$($stopwatch.ElapsedMilliseconds)"
}
finally {
    if ($hadOriginalBinary) {
        $env:LAWYER_ASSISTANCE_MCP_E2E_BINARY = $originalBinary
    }
    else {
        Remove-Item Env:LAWYER_ASSISTANCE_MCP_E2E_BINARY -ErrorAction SilentlyContinue
    }
    if ($hadOriginalReleaseSha256) {
        $env:LAWYER_ASSISTANCE_MCP_RELEASE_SHA256 = $originalReleaseSha256
    }
    else {
        Remove-Item Env:LAWYER_ASSISTANCE_MCP_RELEASE_SHA256 -ErrorAction SilentlyContinue
    }
    Pop-Location
}
