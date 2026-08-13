[CmdletBinding()]
param(
    [string]$RunRoot = '',
    [ValidateRange(0, 65535)]
    [int]$CdpPort = 0,
    [string]$CurrentTargetDirectory = '',
    [string]$NodeCommand = 'node',
    [string]$PythonCommand = 'python',
    [string]$PnpmCommand = 'pnpm',
    [string]$GitCommand = 'git',
    [string]$CargoCommand = 'cargo',
    [string]$RustcCommand = 'rustc'
)

# Manual/CI Windows R3 acceptance entry point. The v0.3.1 source identity and
# legal resource are pinned below. Tauri resolves LocalApplicationData through
# the Windows Known Folder API, so this script deliberately does not trust or
# rewrite the LOCALAPPDATA environment variable. Run and application roots are
# unique, initially absent, and retained for audit; this script never removes
# either filesystem tree.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDirectory '..')).ProviderPath
$expectedTagObject = '9a92737f87ef3a5cc33953b874bbc97a8b5e79fc'
$expectedPeeledCommit = '0970f1c614b1bec1856869c68065162339849468'
$expectedLegalResourceBytes = 1775419392L
$expectedLegalResourceSha256 = '86574bba91950b194c6530586eebbae31c689a5bd2a485877b3eed6b611f7d3c'
$expectedPnpmVersion = '11.7.0'
$expectedTauriCliVersion = '2.11.4'
$exactRustTest = 'commands::v031_migration_recovery::tests::r3_real_v031_binary_reopen_and_v040_reupgrade'
$runIdentifier = [Guid]::NewGuid().ToString('N').ToLowerInvariant()
$currentRunId = [Guid]::ParseExact($runIdentifier, 'N').ToString('D').ToLowerInvariant()
$appIdentifier = "com.shilittle.lawyer-assistance.r3-$($runIdentifier.Substring(0, 20))"
$windowClassname = "LawyerAssistanceR3V031$runIdentifier"
$currentWindowClassname = "LawyerAssistanceR3V040$runIdentifier"
$stopwatch = [Diagnostics.Stopwatch]::StartNew()

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-ExistingOrdinaryFixedPath {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$Description,
        [switch]$Directory
    )

    $resolved = (Resolve-Path -LiteralPath $LiteralPath -ErrorAction Stop).ProviderPath
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($Directory) {
        if (-not $item.PSIsContainer) {
            throw "$Description must be a directory"
        }
    }
    elseif ($item.PSIsContainer -or $item.Length -le 0) {
        throw "$Description must be a non-empty regular file"
    }
    $root = [IO.Path]::GetPathRoot($resolved)
    if ([string]::IsNullOrWhiteSpace($root) -or $root.StartsWith('\\', [StringComparison]::Ordinal)) {
        throw "$Description must be on a local fixed drive"
    }
    $drive = [IO.DriveInfo]::new($root)
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) {
        throw "$Description must be on a local fixed drive"
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must not be a reparse point"
    }
    $cursor = if ($item.PSIsContainer) { $item.Parent } else { $item.Directory }
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Description and its ancestors must not be reparse points"
        }
        $cursor = $cursor.Parent
    }
    return $resolved
}

function Resolve-RequiredApplication {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $command = Get-Command -Name $Name -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
    return Assert-ExistingOrdinaryFixedPath -LiteralPath $command.Source -Description $Description
}

function Assert-NoConcurrentRustBuild {
    $running = @(
        Get-CimInstance Win32_Process -ErrorAction Stop |
            Where-Object { $_.Name -match '^(cargo|rustc|link|lld-link|cargo-nextest)\.exe$' }
    )
    if ($running.Count -ne 0) {
        throw 'R3_CONCURRENT_RUST_BUILD_DETECTED'
    }
}

function Invoke-CapturedApplication {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$FailureCode
    )

    $output = @(& $Executable @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureCode (exit=$LASTEXITCODE)"
    }
    return (($output | ForEach-Object { [string]$_ }) -join "`n").Trim()
}

function Invoke-ApplicationStep {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$FailureCode
    )

    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureCode (exit=$LASTEXITCODE)"
    }
}

function Assert-NewDirectChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $ordinaryParent = Assert-ExistingOrdinaryFixedPath -LiteralPath $Parent -Description "$Description parent" -Directory
    if (-not [IO.Path]::IsPathRooted($Candidate)) {
        throw "$Description must be absolute"
    }
    $fullCandidate = [IO.Path]::GetFullPath($Candidate)
    $candidateParent = [IO.Path]::GetDirectoryName($fullCandidate)
    $directorySeparators = [char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $trimmedParent = $ordinaryParent.TrimEnd($directorySeparators)
    $trimmedCandidateParent = $candidateParent.TrimEnd($directorySeparators)
    if (-not $trimmedCandidateParent.Equals($trimmedParent, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Description must be a direct child of its fixed parent"
    }
    $existingCandidate = Get-Item -LiteralPath $fullCandidate -Force -ErrorAction SilentlyContinue
    if ($null -ne $existingCandidate -or (Test-Path -LiteralPath $fullCandidate)) {
        throw "$Description must initially be absent"
    }
    return $fullCandidate
}

function New-LoopbackPortReservation {
    param([int]$RequestedPort)

    if ($RequestedPort -ne 0 -and $RequestedPort -lt 1024) {
        throw 'R3_CDP_PORT_INVALID'
    }
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $RequestedPort)
    try {
        $listener.Server.ExclusiveAddressUse = $true
        $listener.Start()
        $selected = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
        if ($selected -lt 1024 -or $selected -gt 65535) {
            throw 'R3_CDP_PORT_INVALID'
        }
        return [pscustomobject]@{
            Port = $selected
            Listener = $listener
        }
    }
    catch {
        $listener.Stop()
        throw 'R3_CDP_PORT_UNAVAILABLE'
    }
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$Value
    )

    $encoding = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($LiteralPath, $Value, $encoding)
}

function Save-EnvironmentValue {
    param([Parameter(Mandatory = $true)][string]$Name)

    $item = Get-Item -LiteralPath "Env:$Name" -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        Name = $Name
        Present = $null -ne $item
        Value = if ($null -ne $item) { [string]$item.Value } else { '' }
    }
}

function Restore-EnvironmentValue {
    param([Parameter(Mandatory = $true)]$Saved)

    if ($Saved.Present) {
        Set-Item -LiteralPath "Env:$($Saved.Name)" -Value $Saved.Value
    }
    else {
        Remove-Item -LiteralPath "Env:$($Saved.Name)" -ErrorAction SilentlyContinue
    }
}

if (
    [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or
    -not [Environment]::Is64BitOperatingSystem -or
    -not [Environment]::Is64BitProcess
) {
    throw 'R3_REQUIRES_64_BIT_WINDOWS'
}

$repositoryRoot = Assert-ExistingOrdinaryFixedPath -LiteralPath $repositoryRoot -Description 'repository root' -Directory
$nodePath = Resolve-RequiredApplication -Name $NodeCommand -Description 'Node.js executable'
$pythonPath = Resolve-RequiredApplication -Name $PythonCommand -Description 'Python executable'
$pnpmPath = Resolve-RequiredApplication -Name $PnpmCommand -Description 'pnpm executable'
$gitPath = Resolve-RequiredApplication -Name $GitCommand -Description 'Git executable'
$cargoPath = Resolve-RequiredApplication -Name $CargoCommand -Description 'Cargo executable'
$rustcPath = Resolve-RequiredApplication -Name $RustcCommand -Description 'Rust compiler executable'
if ([IO.Path]::GetFileName($nodePath) -ine 'node.exe') {
    throw 'R3_NODE_EXECUTABLE_NAME_INVALID'
}
if ([IO.Path]::GetFileName($pythonPath) -ine 'python.exe') {
    throw 'R3_PYTHON_EXECUTABLE_NAME_INVALID'
}
$cdpHelperPath = Assert-ExistingOrdinaryFixedPath -LiteralPath (Join-Path $scriptDirectory 'v031-real-binary-cdp.mjs') -Description 'R3 CDP helper'
    $currentCdpHelperPath = Assert-ExistingOrdinaryFixedPath -LiteralPath (Join-Path $scriptDirectory 'v040-real-current-binary-cdp.mjs') -Description 'R3 current CDP helper'
$currentCdpHelperSha256 = Get-Sha256Hex -LiteralPath $currentCdpHelperPath
$legalResourcePath = Assert-ExistingOrdinaryFixedPath -LiteralPath (Join-Path $repositoryRoot 'apps\desktop\src-tauri\resources\legal_core.sqlite') -Description 'legal resource'

$savedEnvironment = @(
    'CARGO_TARGET_DIR',
    'CI',
    'COREPACK_ENABLE_DOWNLOAD_PROMPT',
    'Path',
    'LAWYER_ASSISTANCE_R3_V031_EXE',
    'LAWYER_ASSISTANCE_R3_V031_EXE_SHA256',
    'LAWYER_ASSISTANCE_R3_V031_CDP_HELPER',
    'LAWYER_ASSISTANCE_R3_NODE_EXE',
    'LAWYER_ASSISTANCE_R3_APP_IDENTIFIER',
    'LAWYER_ASSISTANCE_R3_WINDOW_CLASS',
    'LAWYER_ASSISTANCE_R3_APP_ROOT',
    'LAWYER_ASSISTANCE_R3_CDP_PORT',
    'LAWYER_ASSISTANCE_R3_RUN_ROOT',
    'LAWYER_ASSISTANCE_R3_TAG_OBJECT',
    'LAWYER_ASSISTANCE_R3_PEELED_COMMIT',
    'LAWYER_ASSISTANCE_R3_TAURI_OVERRIDE_SHA256',
    'LAWYER_ASSISTANCE_R3_LEGAL_RESOURCE_SHA256',
    'LAWYER_ASSISTANCE_R3_KEEP_APP_ROOT',
    'LAWYER_ASSISTANCE_R3_V040_EXE',
    'LAWYER_ASSISTANCE_R3_V040_EXE_SHA256',
    'LAWYER_ASSISTANCE_R3_V040_CDP_HELPER',
    'LAWYER_ASSISTANCE_R3_V040_APP_VERSION',
    'LAWYER_ASSISTANCE_R3_CURRENT_RUN_ID',
    'LAWYER_ASSISTANCE_R3_CURRENT_APP_IDENTIFIER',
    'LAWYER_ASSISTANCE_R3_CURRENT_APP_ROOT',
    'LAWYER_ASSISTANCE_R3_CURRENT_CREDENTIAL_PREFIX',
    'LAWYER_ASSISTANCE_R3_CURRENT_CDP_PORT',
    'LAWYER_ASSISTANCE_R3_CURRENT_WINDOW_CLASS'
) | ForEach-Object { Save-EnvironmentValue -Name $_ }
$portReservation = $null
$currentPortReservation = $null

Push-Location $repositoryRoot
try {
    $env:CI = 'true'
    $env:COREPACK_ENABLE_DOWNLOAD_PROMPT = '0'
    $nodeDirectory = [IO.Path]::GetDirectoryName($nodePath)
    $pythonDirectory = [IO.Path]::GetDirectoryName($pythonPath)
    $cargoDirectory = [IO.Path]::GetDirectoryName($cargoPath)
    $rustcDirectory = [IO.Path]::GetDirectoryName($rustcPath)
    foreach ($requiredDirectory in @($nodeDirectory, $pythonDirectory, $cargoDirectory, $rustcDirectory)) {
        $pathEntries = @($env:Path -split ';')
        if (-not @($pathEntries | Where-Object { $_.Equals($requiredDirectory, [StringComparison]::OrdinalIgnoreCase) }).Count) {
            $env:Path = "$requiredDirectory;$($env:Path)"
        }
    }

    $actualRepositoryRoot = Invoke-CapturedApplication -Executable $gitPath -Arguments @('rev-parse', '--show-toplevel') -FailureCode 'R3_GIT_ROOT_FAILED'
    $actualRepositoryRoot = (Resolve-Path -LiteralPath $actualRepositoryRoot).ProviderPath
    if (-not $actualRepositoryRoot.Equals($repositoryRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'R3_GIT_ROOT_MISMATCH'
    }
    $tagType = Invoke-CapturedApplication -Executable $gitPath -Arguments @('cat-file', '-t', 'v0.3.1') -FailureCode 'R3_TAG_TYPE_FAILED'
    $tagObject = Invoke-CapturedApplication -Executable $gitPath -Arguments @('rev-parse', 'v0.3.1^{tag}') -FailureCode 'R3_TAG_OBJECT_FAILED'
    $peeledCommit = Invoke-CapturedApplication -Executable $gitPath -Arguments @('rev-parse', 'v0.3.1^{commit}') -FailureCode 'R3_TAG_PEEL_FAILED'
    if ($tagType -cne 'tag' -or $tagObject -cne $expectedTagObject -or $peeledCommit -cne $expectedPeeledCommit) {
        throw 'R3_TAG_PROVENANCE_MISMATCH'
    }

    $nodeVersion = Invoke-CapturedApplication -Executable $nodePath -Arguments @('--version') -FailureCode 'R3_NODE_VERSION_FAILED'
    if ($nodeVersion -notmatch '^v(?<major>[0-9]+)\.[0-9]+\.[0-9]+$' -or [int]$Matches.major -lt 24) {
        throw 'R3_NODE_VERSION_UNSUPPORTED'
    }
    $pythonVersion = Invoke-CapturedApplication -Executable $pythonPath -Arguments @('--version') -FailureCode 'R3_PYTHON_VERSION_FAILED'
    if ($pythonVersion -notmatch '^Python 3\.[0-9]+\.[0-9]+$') {
        throw 'R3_PYTHON_VERSION_UNSUPPORTED'
    }
    # The desktop runtime may expose a newer bootstrap pnpm. Execute the exact
    # package-manager version pinned by the peeled v0.3.1 source for every old
    # source operation, rather than treating the bootstrap version as evidence.
    $exactPnpmArguments = @('dlx', "pnpm@$expectedPnpmVersion")
    $pnpmVersion = Invoke-CapturedApplication -Executable $pnpmPath -Arguments ($exactPnpmArguments + @('--version')) -FailureCode 'R3_PNPM_VERSION_FAILED'
    if ($pnpmVersion -cne $expectedPnpmVersion) {
        throw 'R3_PNPM_VERSION_MISMATCH'
    }
    Assert-NoConcurrentRustBuild
    $cargoVersion = Invoke-CapturedApplication -Executable $cargoPath -Arguments @('--version') -FailureCode 'R3_CARGO_VERSION_FAILED'
    $rustcVerbose = Invoke-CapturedApplication -Executable $rustcPath -Arguments @('-vV') -FailureCode 'R3_RUSTC_VERSION_FAILED'
    $rustHostLine = @($rustcVerbose -split "`n" | Where-Object { $_.StartsWith('host: ', [StringComparison]::Ordinal) })
    if ($rustHostLine.Count -ne 1 -or $rustHostLine[0] -cne 'host: x86_64-pc-windows-msvc') {
        throw 'R3_RUST_HOST_UNSUPPORTED'
    }

    $legalResource = Get-Item -LiteralPath $legalResourcePath -Force
    if ($legalResource.Length -ne $expectedLegalResourceBytes) {
        throw 'R3_LEGAL_RESOURCE_SIZE_MISMATCH'
    }
    $legalResourceSha256 = Get-Sha256Hex -LiteralPath $legalResourcePath
    if ($legalResourceSha256 -cne $expectedLegalResourceSha256) {
        throw 'R3_LEGAL_RESOURCE_HASH_MISMATCH'
    }

    if ([string]::IsNullOrWhiteSpace($RunRoot)) {
        $runParentCandidate = Join-Path $repositoryRoot 'tmp'
        if (-not (Test-Path -LiteralPath $runParentCandidate)) {
            New-Item -ItemType Directory -Path $runParentCandidate -ErrorAction Stop | Out-Null
        }
        $runParent = Assert-ExistingOrdinaryFixedPath -LiteralPath $runParentCandidate -Description 'R3 run parent' -Directory
        $runCandidate = Join-Path $runParent "v031-real-binary-r3-$runIdentifier"
    }
    else {
        if (-not [IO.Path]::IsPathRooted($RunRoot)) {
            throw 'R3_RUN_ROOT_MUST_BE_ABSOLUTE'
        }
        $runCandidate = [IO.Path]::GetFullPath($RunRoot)
        $runParent = [IO.Path]::GetDirectoryName($runCandidate)
    }
    $resolvedRunRoot = Assert-NewDirectChildPath -Parent $runParent -Candidate $runCandidate -Description 'R3 run root'
    New-Item -ItemType Directory -Path $resolvedRunRoot -ErrorAction Stop | Out-Null
    $resolvedRunRoot = Assert-ExistingOrdinaryFixedPath -LiteralPath $resolvedRunRoot -Description 'R3 run root' -Directory
    Write-Output "R3_V031_REAL_BINARY_RUN_ROOT_PREPARED=$resolvedRunRoot"

    $knownLocal = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    $knownLocal = Assert-ExistingOrdinaryFixedPath -LiteralPath $knownLocal -Description 'Windows LocalApplicationData known folder' -Directory
    $appRootCandidate = Join-Path $knownLocal $appIdentifier
    $appRoot = Assert-NewDirectChildPath -Parent $knownLocal -Candidate $appRootCandidate -Description 'R3 application root'
    Write-Output "R3_V031_REAL_BINARY_APP_ROOT_RESERVED=$appRoot"
    $portReservation = New-LoopbackPortReservation -RequestedPort $CdpPort
    $selectedCdpPort = [int]$portReservation.Port
    $currentPortReservation = New-LoopbackPortReservation -RequestedPort 0
    $selectedCurrentCdpPort = [int]$currentPortReservation.Port
    if ($selectedCurrentCdpPort -eq $selectedCdpPort) {
        throw 'R3_CURRENT_CDP_PORT_NOT_ISOLATED'
    }

    $archivePath = Join-Path $resolvedRunRoot 'v0.3.1-source.zip'
    $oldSource = Join-Path $resolvedRunRoot 'v0.3.1-source'
    $overridePath = Join-Path $resolvedRunRoot 'tauri.r3-v031-real.conf.json'
    $currentOverridePath = Join-Path $resolvedRunRoot 'tauri.r3-v040-real.conf.json'
    $oldCargoTarget = Join-Path $resolvedRunRoot 'old-target'
    $currentBinaryTarget = Join-Path $resolvedRunRoot 'current-binary-target'
    if (
        (Test-Path -LiteralPath $archivePath) -or
        (Test-Path -LiteralPath $oldSource) -or
        (Test-Path -LiteralPath $oldCargoTarget) -or
        (Test-Path -LiteralPath $currentBinaryTarget)
    ) {
        throw 'R3_RUN_ROOT_NOT_EMPTY'
    }
    Invoke-ApplicationStep -Executable $gitPath -Arguments @('archive', '--format=zip', '--output', $archivePath, $peeledCommit) -FailureCode 'R3_GIT_ARCHIVE_FAILED'
    Expand-Archive -LiteralPath $archivePath -DestinationPath $oldSource -ErrorAction Stop
    $oldSource = Assert-ExistingOrdinaryFixedPath -LiteralPath $oldSource -Description 'archived v0.3.1 source' -Directory

    $oldRootPackagePath = Join-Path $oldSource 'package.json'
    $oldDesktopPackagePath = Join-Path $oldSource 'apps\desktop\package.json'
    $oldTauriConfigPath = Join-Path $oldSource 'apps\desktop\src-tauri\tauri.conf.json'
    $oldRootPackage = Get-Content -LiteralPath $oldRootPackagePath -Raw | ConvertFrom-Json
    $oldDesktopPackage = Get-Content -LiteralPath $oldDesktopPackagePath -Raw | ConvertFrom-Json
    $oldTauriConfig = Get-Content -LiteralPath $oldTauriConfigPath -Raw | ConvertFrom-Json
    if (
        [string]$oldRootPackage.version -cne '0.3.1' -or
        [string]$oldRootPackage.packageManager -cne 'pnpm@11.7.0' -or
        [string]$oldDesktopPackage.version -cne '0.3.1' -or
        [string]$oldTauriConfig.version -cne '0.3.1' -or
        [string]$oldTauriConfig.identifier -cne 'com.shilittle.lawyer-assistance'
    ) {
        throw 'R3_ARCHIVED_SOURCE_VERSION_MISMATCH'
    }

    $oldLegalResourcePath = Join-Path $oldSource 'apps\desktop\src-tauri\resources\legal_core.sqlite'
    if (Test-Path -LiteralPath $oldLegalResourcePath) {
        throw 'R3_ARCHIVED_RESOURCE_UNEXPECTED'
    }
    $resourceTransfer = 'copy'
    if ([IO.Path]::GetPathRoot($legalResourcePath).Equals([IO.Path]::GetPathRoot($oldLegalResourcePath), [StringComparison]::OrdinalIgnoreCase)) {
        try {
            New-Item -ItemType HardLink -Path $oldLegalResourcePath -Target $legalResourcePath -ErrorAction Stop | Out-Null
            $resourceTransfer = 'hardlink'
        }
        catch {
            if (Test-Path -LiteralPath $oldLegalResourcePath) {
                throw 'R3_RESOURCE_HARDLINK_PARTIAL_FAILURE'
            }
            Copy-Item -LiteralPath $legalResourcePath -Destination $oldLegalResourcePath -ErrorAction Stop
        }
    }
    else {
        Copy-Item -LiteralPath $legalResourcePath -Destination $oldLegalResourcePath -ErrorAction Stop
    }
    $oldLegalResourcePath = Assert-ExistingOrdinaryFixedPath -LiteralPath $oldLegalResourcePath -Description 'archived v0.3.1 legal resource'
    if ((Get-Item -LiteralPath $oldLegalResourcePath).Length -ne $expectedLegalResourceBytes -or (Get-Sha256Hex -LiteralPath $oldLegalResourcePath) -cne $expectedLegalResourceSha256) {
        throw 'R3_ARCHIVED_RESOURCE_MISMATCH'
    }

    $additionalBrowserArguments = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --remote-debugging-address=127.0.0.1 --remote-debugging-port=$selectedCdpPort --remote-allow-origins=*"
    $override = [ordered]@{
        '$schema' = 'https://schema.tauri.app/config/2'
        identifier = $appIdentifier
        app = [ordered]@{
            windows = @(
                [ordered]@{
                    label = 'main'
                    title = 'Lawyer Assistance R3 v0.3.1 acceptance'
                    windowClassname = $windowClassname
                    width = 1200
                    height = 800
                    minWidth = 640
                    minHeight = 420
                    maximized = $false
                    visible = $true
                    resizable = $true
                    dataDirectory = 'r3-webview'
                    additionalBrowserArgs = $additionalBrowserArguments
                }
            )
        }
    }
    $overrideJson = $override | ConvertTo-Json -Depth 10
    Write-Utf8NoBom -LiteralPath $overridePath -Value ($overrideJson + "`n")
    $overridePath = Assert-ExistingOrdinaryFixedPath -LiteralPath $overridePath -Description 'R3 Tauri override'
    $overrideSha256 = Get-Sha256Hex -LiteralPath $overridePath

    $pnpmLockPath = Join-Path $oldSource 'pnpm-lock.yaml'
    $cargoLockPath = Join-Path $oldSource 'Cargo.lock'
    $pnpmLockSha256Before = Get-Sha256Hex -LiteralPath $pnpmLockPath
    $cargoLockSha256Before = Get-Sha256Hex -LiteralPath $cargoLockPath

    Push-Location $oldSource
    try {
        Invoke-ApplicationStep -Executable $pnpmPath -Arguments ($exactPnpmArguments + @('install', '--frozen-lockfile')) -FailureCode 'R3_OLD_PNPM_INSTALL_FAILED'
        $tauriCliOutput = Invoke-CapturedApplication -Executable $pnpmPath -Arguments ($exactPnpmArguments + @('--filter', '@lawyer-assistance/desktop', 'exec', 'tauri', '--version')) -FailureCode 'R3_TAURI_CLI_VERSION_FAILED'
        if ($tauriCliOutput -notmatch '(?m)(?:tauri-cli\s+)?(?<version>[0-9]+\.[0-9]+\.[0-9]+)\s*$' -or $Matches.version -cne $expectedTauriCliVersion) {
            throw 'R3_TAURI_CLI_VERSION_MISMATCH'
        }
        Invoke-ApplicationStep -Executable $pnpmPath -Arguments ($exactPnpmArguments + @('--filter', '@lawyer-assistance/desktop', 'verify:legal-resource')) -FailureCode 'R3_OLD_LEGAL_RESOURCE_VERIFICATION_FAILED'
        $env:CARGO_TARGET_DIR = $oldCargoTarget
        Assert-NoConcurrentRustBuild
        Invoke-ApplicationStep -Executable $pnpmPath -Arguments ($exactPnpmArguments + @(
            '--filter',
            '@lawyer-assistance/desktop',
            'tauri',
            'build',
            '--debug',
            '--no-bundle',
            '--ci',
            '--config',
            $overridePath,
            '--',
            '--locked'
        )) -FailureCode 'R3_OLD_TAURI_BUILD_FAILED'
    }
    finally {
        Pop-Location
    }

    if ((Get-Sha256Hex -LiteralPath $pnpmLockPath) -cne $pnpmLockSha256Before -or (Get-Sha256Hex -LiteralPath $cargoLockPath) -cne $cargoLockSha256Before) {
        throw 'R3_OLD_LOCKFILE_CHANGED'
    }
    if ((Get-Sha256Hex -LiteralPath $legalResourcePath) -cne $expectedLegalResourceSha256 -or (Get-Sha256Hex -LiteralPath $oldLegalResourcePath) -cne $expectedLegalResourceSha256) {
        throw 'R3_LEGAL_RESOURCE_CHANGED_DURING_BUILD'
    }
    if (Test-Path -LiteralPath $appRoot) {
        throw 'R3_APP_ROOT_CREATED_DURING_BUILD'
    }

    $oldExePath = Assert-ExistingOrdinaryFixedPath -LiteralPath (Join-Path $oldCargoTarget 'x86_64-pc-windows-msvc\debug\lawyer-assistance.exe') -Description 'real v0.3.1 debug executable'
    if ([IO.Path]::GetFileName($oldExePath) -cne 'lawyer-assistance.exe') {
        throw 'R3_OLD_EXE_NAME_MISMATCH'
    }
    $oldExeSha256 = Get-Sha256Hex -LiteralPath $oldExePath

    $currentTauriConfigPath = Join-Path $repositoryRoot 'apps\desktop\src-tauri\tauri.conf.json'
    $currentTauriConfig = Get-Content -LiteralPath $currentTauriConfigPath -Raw | ConvertFrom-Json
    $currentAppVersion = [string]$currentTauriConfig.version
    if ($currentAppVersion -notmatch '^0\.4\.0(?:$|-)') {
        throw 'R3_CURRENT_APP_VERSION_INVALID'
    }
    $currentOverride = [ordered]@{
        '$schema' = 'https://schema.tauri.app/config/2'
        identifier = $appIdentifier
        app = [ordered]@{ windows = @() }
    }
    Write-Utf8NoBom -LiteralPath $currentOverridePath -Value (($currentOverride | ConvertTo-Json -Depth 8) + "`n")
    $currentOverridePath = Assert-ExistingOrdinaryFixedPath -LiteralPath $currentOverridePath -Description 'R3 current Tauri override'
    $currentOverrideSha256 = Get-Sha256Hex -LiteralPath $currentOverridePath
    $currentCargoLockPath = Join-Path $repositoryRoot 'Cargo.lock'
    $currentPnpmLockPath = Join-Path $repositoryRoot 'pnpm-lock.yaml'
    $currentCargoLockSha256Before = Get-Sha256Hex -LiteralPath $currentCargoLockPath
    $currentPnpmLockSha256Before = Get-Sha256Hex -LiteralPath $currentPnpmLockPath
    $env:CARGO_TARGET_DIR = $currentBinaryTarget
    Assert-NoConcurrentRustBuild
    Invoke-ApplicationStep -Executable $pnpmPath -Arguments @(
        '--filter',
        '@lawyer-assistance/desktop',
        'tauri',
        'build',
        '--debug',
        '--no-bundle',
        '--ci',
        '--config',
        $currentOverridePath,
        '--',
        '--locked',
        '--features',
        'r3-real-current-binary-harness'
    ) -FailureCode 'R3_CURRENT_TAURI_BUILD_FAILED'
    if ((Get-Sha256Hex -LiteralPath $currentCargoLockPath) -cne $currentCargoLockSha256Before -or (Get-Sha256Hex -LiteralPath $currentPnpmLockPath) -cne $currentPnpmLockSha256Before) {
        throw 'R3_CURRENT_LOCKFILE_CHANGED'
    }
    if ((Get-Sha256Hex -LiteralPath $currentCdpHelperPath) -cne $currentCdpHelperSha256) {
        throw 'R3_CURRENT_CDP_HELPER_CHANGED_DURING_BUILD'
    }
    $currentExePath = Assert-ExistingOrdinaryFixedPath -LiteralPath (Join-Path $currentBinaryTarget 'x86_64-pc-windows-msvc\debug\lawyer-assistance.exe') -Description 'real current debug executable'
    $currentExeSha256 = Get-Sha256Hex -LiteralPath $currentExePath

    if ([string]::IsNullOrWhiteSpace($CurrentTargetDirectory)) {
        $currentTarget = Join-Path $resolvedRunRoot 'current-target'
        if (Test-Path -LiteralPath $currentTarget) {
            throw 'R3_CURRENT_TARGET_MUST_BE_ABSENT'
        }
    }
    else {
        if (-not [IO.Path]::IsPathRooted($CurrentTargetDirectory)) {
            throw 'R3_CURRENT_TARGET_MUST_BE_ABSOLUTE'
        }
        $currentTarget = [IO.Path]::GetFullPath($CurrentTargetDirectory)
        if (Test-Path -LiteralPath $currentTarget) {
            throw 'R3_CURRENT_TARGET_MUST_BE_ABSENT'
        }
        $targetParent = [IO.Path]::GetDirectoryName($currentTarget)
        [void](Assert-ExistingOrdinaryFixedPath -LiteralPath $targetParent -Description 'current Cargo target parent' -Directory)
    }

    $env:LAWYER_ASSISTANCE_R3_V031_EXE = $oldExePath
    $env:LAWYER_ASSISTANCE_R3_V031_EXE_SHA256 = $oldExeSha256
    $env:LAWYER_ASSISTANCE_R3_V031_CDP_HELPER = $cdpHelperPath
    $env:LAWYER_ASSISTANCE_R3_NODE_EXE = $nodePath
    $env:LAWYER_ASSISTANCE_R3_APP_IDENTIFIER = $appIdentifier
    $env:LAWYER_ASSISTANCE_R3_WINDOW_CLASS = $windowClassname
    $env:LAWYER_ASSISTANCE_R3_APP_ROOT = $appRoot
    $env:LAWYER_ASSISTANCE_R3_CDP_PORT = [string]$selectedCdpPort
    $env:LAWYER_ASSISTANCE_R3_RUN_ROOT = $resolvedRunRoot
    $env:LAWYER_ASSISTANCE_R3_TAG_OBJECT = $tagObject
    $env:LAWYER_ASSISTANCE_R3_PEELED_COMMIT = $peeledCommit
    $env:LAWYER_ASSISTANCE_R3_TAURI_OVERRIDE_SHA256 = $overrideSha256
    $env:LAWYER_ASSISTANCE_R3_LEGAL_RESOURCE_SHA256 = $legalResourceSha256
    $env:LAWYER_ASSISTANCE_R3_KEEP_APP_ROOT = '1'
    $env:LAWYER_ASSISTANCE_R3_V040_EXE = $currentExePath
    $env:LAWYER_ASSISTANCE_R3_V040_EXE_SHA256 = $currentExeSha256
    $env:LAWYER_ASSISTANCE_R3_V040_CDP_HELPER = $currentCdpHelperPath
    $env:LAWYER_ASSISTANCE_R3_V040_APP_VERSION = $currentAppVersion
    $env:LAWYER_ASSISTANCE_R3_CURRENT_RUN_ID = $currentRunId
    $env:LAWYER_ASSISTANCE_R3_CURRENT_APP_IDENTIFIER = $appIdentifier
    $env:LAWYER_ASSISTANCE_R3_CURRENT_APP_ROOT = $appRoot
    $env:LAWYER_ASSISTANCE_R3_CURRENT_CDP_PORT = [string]$selectedCurrentCdpPort
    $env:LAWYER_ASSISTANCE_R3_CURRENT_WINDOW_CLASS = $currentWindowClassname
    Remove-Item -LiteralPath Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue

    $testArguments = @(
        'test',
        '--locked',
        '-p',
        'lawyer-assistance-desktop',
        '--lib',
        '--target-dir',
        $currentTarget,
        $exactRustTest
    )
    Assert-NoConcurrentRustBuild
    $listedTests = Invoke-CapturedApplication -Executable $cargoPath -Arguments ($testArguments + @('--', '--ignored', '--exact', '--list')) -FailureCode 'R3_REAL_BINARY_TEST_LIST_FAILED'
    $testListings = @(
        $listedTests -split "`n" |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_.EndsWith(': test', [StringComparison]::Ordinal) }
    )
    $expectedListing = "$exactRustTest`: test"
    if ($testListings.Count -ne 1 -or $testListings[0] -cne $expectedListing) {
        throw 'R3_REAL_BINARY_TEST_NOT_EXACT'
    }
    if (Test-Path -LiteralPath $appRoot) {
        throw 'R3_APP_ROOT_CREATED_BEFORE_TEST'
    }
    $portReservation.Listener.Stop()
    $portReservation = $null
    $currentPortReservation.Listener.Stop()
    $currentPortReservation = $null
    Assert-NoConcurrentRustBuild
    Invoke-ApplicationStep -Executable $cargoPath -Arguments ($testArguments + @('--', '--ignored', '--exact', '--nocapture', '--test-threads=1')) -FailureCode 'R3_REAL_BINARY_TEST_FAILED'

    if ((Get-Sha256Hex -LiteralPath $oldExePath) -cne $oldExeSha256) {
        throw 'R3_OLD_EXE_CHANGED_DURING_TEST'
    }
    $startupExitTracePath = Join-Path $resolvedRunRoot 'r3-production-recovery-apply-and-exit.trace'
    if (-not (Test-Path -LiteralPath $startupExitTracePath -PathType Leaf)) {
        throw 'R3_PRODUCTION_STARTUP_EXIT_TRACE_MISSING'
    }
    $startupExitTraceSha256 = Get-Sha256Hex -LiteralPath $startupExitTracePath
    $stopwatch.Stop()
    $attestationPath = Join-Path $resolvedRunRoot 'r3-v031-real-binary-attestation.json'
    $attestation = [ordered]@{
        schemaVersion = 'lawyer-assistance-v031-real-binary-harness-attestation-v1'
        result = 'pass'
        tagObject = $tagObject
        peeledCommit = $peeledCommit
        tagSignature = 'unsigned'
        sourceFlavor = 'peeled-tag-source-with-audited-tauri-config-override'
        appIdentifier = $appIdentifier
        windowClassname = $windowClassname
        appRoot = $appRoot
        cdpPort = $selectedCdpPort
        currentCdpPort = $selectedCurrentCdpPort
        nodeVersion = $nodeVersion
        pythonVersion = $pythonVersion
        pnpmVersion = $pnpmVersion
        tauriCliVersion = $expectedTauriCliVersion
        cargoVersion = $cargoVersion
        legalResourceBytes = $expectedLegalResourceBytes
        legalResourceSha256 = $legalResourceSha256
        legalResourceTransfer = $resourceTransfer
        tauriOverrideSha256 = $overrideSha256
        oldExecutableSha256 = $oldExeSha256
        currentExecutableSha256 = $currentExeSha256
        currentCdpHelperSha256 = $currentCdpHelperSha256
        currentTauriOverrideSha256 = $currentOverrideSha256
        currentAppVersion = $currentAppVersion
        currentWindowClassname = $currentWindowClassname
        productionStartupExitTraceSha256 = $startupExitTraceSha256
        exactRustTest = $exactRustTest
        runRoot = $resolvedRunRoot
        elapsedMilliseconds = $stopwatch.ElapsedMilliseconds
    }
    Write-Utf8NoBom -LiteralPath $attestationPath -Value (($attestation | ConvertTo-Json -Depth 8) + "`n")
    $attestationSha256 = Get-Sha256Hex -LiteralPath $attestationPath

    Write-Output 'R3_V031_REAL_BINARY_HARNESS=PASS'
    Write-Output "R3_V031_REAL_BINARY_TAG_OBJECT=$tagObject"
    Write-Output "R3_V031_REAL_BINARY_PEELED_COMMIT=$peeledCommit"
    Write-Output "R3_V031_REAL_BINARY_SOURCE_FLAVOR=peeled-tag-source-with-audited-tauri-config-override"
    Write-Output "R3_V031_REAL_BINARY_EXE_SHA256=$oldExeSha256"
    Write-Output "R3_V040_REAL_CURRENT_BINARY_EXE_SHA256=$currentExeSha256"
    Write-Output "R3_V031_REAL_BINARY_OVERRIDE_SHA256=$overrideSha256"
    Write-Output "R3_V031_PRODUCTION_STARTUP_EXIT_TRACE_SHA256=$startupExitTraceSha256"
    Write-Output "R3_V031_REAL_BINARY_ATTESTATION_SHA256=$attestationSha256"
    Write-Output "R3_V031_REAL_BINARY_RUN_ROOT=$resolvedRunRoot"
    Write-Output "R3_V031_REAL_BINARY_APP_ROOT=$appRoot"
    Write-Output 'R3_V031_REAL_BINARY_ARTIFACTS_RETAINED=true'
}
finally {
    if ($null -ne $portReservation) {
        $portReservation.Listener.Stop()
    }
    if ($null -ne $currentPortReservation) {
        $currentPortReservation.Listener.Stop()
    }
    foreach ($saved in $savedEnvironment) {
        Restore-EnvironmentValue -Saved $saved
    }
    Pop-Location
}
