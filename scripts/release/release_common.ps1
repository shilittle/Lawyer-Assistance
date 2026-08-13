Set-StrictMode -Version Latest

$script:LawyerAssistanceFrozenReleaseContract = [ordered]@{
  Version = "0.4.0"
  Repository = "shilittle/Lawyer-Assistance"
  Branch = "main"
  AppTag = "v0.4.0"
  MinerUTag = "mineru-components-v0.4.0"
  SourceTag = "v0.3.1"
  SourceTagObject = "9a92737f87ef3a5cc33953b874bbc97a8b5e79fc"
  SourceTagCommit = "0970f1c614b1bec1856869c68065162339849468"
}

$script:LawyerAssistanceReleaseExitCodes = [ordered]@{
  Success = 0
  UnsupportedPlatform = 10
  RepositoryInvalid = 11
  VersionContractInvalid = 12
  BranchInvalid = 13
  RemoteFetchFailed = 14
  RemoteHeadMismatch = 15
  SourceTagInvalid = 16
  ReleaseTagInvalid = 17
  LegalResourceInvalid = 18
  NoticesInvalid = 19
  CertificateMissing = 20
  ThumbprintMissing = 21
  CertificateInvalid = 22
  TimestampInvalid = 23
  CiClosureInvalid = 24
  UpdaterKeyMissing = 30
  UpdaterPasswordMissing = 31
  UpdaterKeyInvalid = 32
  WorktreeDirty = 40
  SignedBuildFailed = 50
  VerificationFailed = 51
  CleanupFailed = 60
}

$script:LawyerAssistanceReleaseContract = [ordered]@{}
foreach ($entry in $script:LawyerAssistanceFrozenReleaseContract.GetEnumerator()) {
  $script:LawyerAssistanceReleaseContract[$entry.Key] = $entry.Value
}

function Get-LawyerAssistanceReleaseExitCodes {
  $copy = [ordered]@{}
  foreach ($entry in $script:LawyerAssistanceReleaseExitCodes.GetEnumerator()) {
    $copy[$entry.Key] = [int]$entry.Value
  }
  return $copy
}

function Get-LawyerAssistanceReleaseContract {
  if ($null -eq $script:LawyerAssistanceReleaseContract) {
    throw "The release contract has not been loaded."
  }
  $copy = [ordered]@{}
  foreach ($entry in $script:LawyerAssistanceReleaseContract.GetEnumerator()) {
    $copy[$entry.Key] = $entry.Value
  }
  return $copy
}

function Import-LawyerAssistanceReleaseContract([string]$ProjectRoot) {
  $contractPath = Join-Path $ProjectRoot "scripts\release\release-contract-v0.4.0.json"
  try {
    $raw = Get-Content -LiteralPath $contractPath -Raw -Encoding UTF8 | ConvertFrom-Json
  } catch {
    Throw-LawyerAssistanceReleaseFailure "REL-VERSION-CONTRACT-INVALID" $script:LawyerAssistanceReleaseExitCodes.VersionContractInvalid "The release contract could not be loaded."
  }
  $version = [string]$raw.release.formalVersion
  $repository = "$([string]$raw.repository.owner)/$([string]$raw.repository.name)"
  $source = $raw.immutableTags.'v0.3.1'
  if ($version -cne "0.4.0" -or
      [string]$raw.release.appTag -cne "v0.4.0" -or
      [string]$raw.release.minerUTag -cne "mineru-components-v0.4.0" -or
      $repository -cne "shilittle/Lawyer-Assistance" -or
      [string]$raw.repository.httpsUrl -cne "https://github.com/shilittle/Lawyer-Assistance.git" -or
      [string]$source.tagObject -cnotmatch '^[0-9a-f]{40}$' -or
      [string]$source.peeledCommit -cnotmatch '^[0-9a-f]{40}$') {
    Throw-LawyerAssistanceReleaseFailure "REL-VERSION-CONTRACT-INVALID" $script:LawyerAssistanceReleaseExitCodes.VersionContractInvalid "The loaded release contract differs from the frozen v0.4.0 identity."
  }
  $script:LawyerAssistanceReleaseContract = [ordered]@{
    Version = $version
    Repository = $repository
    RepositoryUrl = [string]$raw.repository.httpsUrl
    Branch = "main"
    AppTag = [string]$raw.release.appTag
    MinerUTag = [string]$raw.release.minerUTag
    SourceTag = "v0.3.1"
    SourceTagObject = [string]$source.tagObject
    SourceTagCommit = [string]$source.peeledCommit
  }
}

function Throw-LawyerAssistanceReleaseFailure {
  param(
    [Parameter(Mandatory = $true)][ValidatePattern('^REL-[A-Z0-9-]+$')][string]$ResultCode,
    [Parameter(Mandatory = $true)][int]$ExitCode,
    [Parameter(Mandatory = $true)][string]$Message
  )

  $exception = [InvalidOperationException]::new($Message)
  $exception.Data["LawyerAssistanceReleaseResultCode"] = $ResultCode
  $exception.Data["LawyerAssistanceReleaseExitCode"] = $ExitCode
  throw $exception
}

function Get-LawyerAssistanceReleaseFailure {
  param([Parameter(Mandatory = $true)][Management.Automation.ErrorRecord]$ErrorRecord)

  $exception = $ErrorRecord.Exception
  if ($null -eq $exception.Data["LawyerAssistanceReleaseResultCode"] -or
      $null -eq $exception.Data["LawyerAssistanceReleaseExitCode"]) {
    return $null
  }
  return [pscustomobject][ordered]@{
    ResultCode = [string]$exception.Data["LawyerAssistanceReleaseResultCode"]
    ExitCode = [int]$exception.Data["LawyerAssistanceReleaseExitCode"]
    Message = [string]$exception.Message
  }
}

function Test-LawyerAssistanceStableReleaseExitCode([int]$ExitCode) {
  return @($script:LawyerAssistanceReleaseExitCodes.Values | ForEach-Object { [int]$_ }) -contains $ExitCode
}

function Resolve-LawyerAssistanceSignedBuildExitCode([int]$ExitCode) {
  if (Test-LawyerAssistanceStableReleaseExitCode $ExitCode) { return $ExitCode }
  return $script:LawyerAssistanceReleaseExitCodes.SignedBuildFailed
}

function Resolve-LawyerAssistanceSignedBuildFailure {
  param([Parameter(Mandatory = $true)][Management.Automation.ErrorRecord]$ErrorRecord)

  $failure = Get-LawyerAssistanceReleaseFailure $ErrorRecord
  if ($null -ne $failure) { return $failure }
  return [pscustomobject][ordered]@{
    ResultCode = "REL-SIGNED-BUILD-FAILED"
    ExitCode = $script:LawyerAssistanceReleaseExitCodes.SignedBuildFailed
    Message = "The signed release build failed unexpectedly."
  }
}

function Get-LawyerAssistanceEnvironmentSnapshot {
  param([Parameter(Mandatory = $true)][string[]]$Names)
  $saved = @{}
  foreach ($name in $Names) {
    $item = Get-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
    $saved[$name] = [pscustomobject]@{
      Exists = $null -ne $item
      Value = if ($null -eq $item) { $null } else { [string]$item.Value }
    }
  }
  return $saved
}

function Restore-LawyerAssistanceEnvironmentSnapshot {
  param([Parameter(Mandatory = $true)][hashtable]$Snapshot)
  foreach ($name in $Snapshot.Keys) {
    if ($Snapshot[$name].Exists) {
      Set-Item -LiteralPath "Env:$name" -Value $Snapshot[$name].Value
    } else {
      Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
    }
  }
}

function Invoke-LawyerAssistancePreservingEnvironment {
  param(
    [Parameter(Mandatory = $true)][string[]]$Names,
    [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock
  )

  $saved = Get-LawyerAssistanceEnvironmentSnapshot $Names
  foreach ($name in $Names) {
    Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
  }
  try {
    return & $ScriptBlock
  } finally {
    Restore-LawyerAssistanceEnvironmentSnapshot $saved
  }
}

function Invoke-LawyerAssistanceNativeCommand {
  param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ArgumentList
  )

  try {
    $lines = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) { $exitCode = 0 }
    return [pscustomobject][ordered]@{
      ExitCode = [int]$exitCode
      Output = ($lines -join "`n")
    }
  } catch {
    return [pscustomobject][ordered]@{
      ExitCode = 127
      Output = [string]$_.Exception.Message
    }
  }
}

function Test-LawyerAssistanceCertificatePrivateKey {
  param([Parameter(Mandatory = $true)]$Certificate)

  if (-not $Certificate.HasPrivateKey) { return $false }
  $privateKey = $null
  try {
    try {
      $privateKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    } catch {
      $privateKey = $null
    }
    if ($null -eq $privateKey) {
      try {
        $privateKey = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Certificate)
      } catch {
        $privateKey = $null
      }
    }
    return $null -ne $privateKey
  } finally {
    if ($null -ne $privateKey) { $privateKey.Dispose() }
  }
}

function New-LawyerAssistanceReleaseProbeDirectory([string]$Purpose) {
  if ($Purpose -cnotmatch '^[a-z][a-z0-9-]{0,31}$') {
    throw "The release probe purpose is invalid."
  }
  $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
  $directory = [IO.Path]::GetFullPath((Join-Path $temporaryRoot (
    "lawyer-assistance-$Purpose-" + [Guid]::NewGuid().ToString("N")
  )))
  $prefix = $temporaryRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  if (-not $directory.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "The release probe directory escaped the system temporary directory."
  }
  New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
  return $directory
}

function Remove-LawyerAssistanceReleaseProbeDirectory([string]$Directory, [string]$Purpose) {
  $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
  $resolved = [IO.Path]::GetFullPath($Directory)
  $prefix = $temporaryRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  $namePattern = '^lawyer-assistance-' + [regex]::Escape($Purpose) + '-[0-9a-f]{32}$'
  if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
      [IO.Path]::GetFileName($resolved) -cnotmatch $namePattern) {
    throw "Refusing unsafe release probe cleanup."
  }
  if (Test-Path -LiteralPath $resolved -PathType Container) {
    $item = Get-Item -LiteralPath $resolved -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Refusing to clean a reparse-point release probe directory."
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
  }
}

function Get-LawyerAssistanceSignTool {
  $command = Get-Command signtool.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -ne $command) { return [string]$command.Source }
  $kitsRoot = ${env:ProgramFiles(x86)}
  if ([string]::IsNullOrWhiteSpace($kitsRoot)) { return $null }
  $candidate = Get-ChildItem (Join-Path $kitsRoot "Windows Kits\10\bin") `
    -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
  if ($null -eq $candidate) { return $null }
  return [string]$candidate.FullName
}

function Test-LawyerAssistanceAuthenticodeTimestampCapability {
  param(
    [Parameter(Mandatory = $true)][string]$ProjectRoot,
    [Parameter(Mandatory = $true)][string]$Thumbprint,
    [Parameter(Mandatory = $true)][Uri]$TimestampUri
  )

  $null = $ProjectRoot
  $signtool = Get-LawyerAssistanceSignTool
  if ([string]::IsNullOrWhiteSpace($signtool)) { return $false }
  $sourcePe = Join-Path $PSHOME "powershell.exe"
  if (-not (Test-Path -LiteralPath $sourcePe -PathType Leaf)) {
    $sourcePe = (Get-Process -Id $PID).Path
  }
  if (-not (Test-Path -LiteralPath $sourcePe -PathType Leaf)) { return $false }

  $directory = New-LawyerAssistanceReleaseProbeDirectory "authenticode-probe"
  try {
    $probe = Join-Path $directory "rfc3161-probe.exe"
    [IO.File]::Copy($sourcePe, $probe, $false)
    & $signtool sign /sha1 $Thumbprint /fd SHA256 /tr $TimestampUri.AbsoluteUri /td SHA256 $probe *> $null
    if ($LASTEXITCODE -ne 0) { return $false }
    return Test-LawyerAssistanceRfc3161Authenticode `
      -Path $probe `
      -ExpectedSignerThumbprint $Thumbprint `
      -SignToolPath $signtool
  } catch {
    return $false
  } finally {
    Remove-LawyerAssistanceReleaseProbeDirectory $directory "authenticode-probe"
  }
}

function Initialize-LawyerAssistanceAuthenticodeInspector {
  if ($null -eq ("LawyerAssistance.Release.NativeCrypt" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace LawyerAssistance.Release {
  public static class NativeCrypt {
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CryptQueryObject(
      uint objectType,
      string objectPath,
      uint expectedContentTypeFlags,
      uint expectedFormatTypeFlags,
      uint flags,
      out uint messageAndCertificateEncodingType,
      out uint contentType,
      out uint formatType,
      out IntPtr certificateStore,
      out IntPtr cryptographicMessage,
      out IntPtr context);

    [DllImport("crypt32.dll", SetLastError = true)]
    public static extern bool CryptMsgGetParam(
      IntPtr cryptographicMessage,
      uint parameterType,
      uint index,
      byte[] data,
      ref uint dataLength);

    [DllImport("crypt32.dll")]
    public static extern bool CryptMsgClose(IntPtr cryptographicMessage);

    [DllImport("crypt32.dll")]
    public static extern bool CertCloseStore(IntPtr certificateStore, uint flags);

    [DllImport("crypt32.dll")]
    public static extern bool CertFreeCertificateContext(IntPtr certificateContext);
  }
}
'@
  }
  Add-Type -AssemblyName System.Security
}

function Get-LawyerAssistanceEmbeddedAuthenticodeCms([string]$Path) {
  Initialize-LawyerAssistanceAuthenticodeInspector
  $resolved = [IO.Path]::GetFullPath($Path)
  if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { return $null }

  [uint32]$encoding = 0
  [uint32]$contentType = 0
  [uint32]$formatType = 0
  $store = [IntPtr]::Zero
  $message = [IntPtr]::Zero
  $context = [IntPtr]::Zero
  try {
    $queried = [LawyerAssistance.Release.NativeCrypt]::CryptQueryObject(
      1,
      $resolved,
      1024,
      2,
      0,
      [ref]$encoding,
      [ref]$contentType,
      [ref]$formatType,
      [ref]$store,
      [ref]$message,
      [ref]$context
    )
    if (-not $queried -or $message -eq [IntPtr]::Zero -or $contentType -ne 10 -or $formatType -ne 1) {
      return $null
    }
    [uint32]$length = 0
    if (-not [LawyerAssistance.Release.NativeCrypt]::CryptMsgGetParam(
        $message, 29, 0, $null, [ref]$length
      ) -or $length -le 0 -or $length -gt 16MB) {
      return $null
    }
    $bytes = [byte[]]::new([int]$length)
    if (-not [LawyerAssistance.Release.NativeCrypt]::CryptMsgGetParam(
        $message, 29, 0, $bytes, [ref]$length
      ) -or $length -ne $bytes.Length) {
      return $null
    }
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new()
    $cms.Decode($bytes)
    return $cms
  } catch {
    return $null
  } finally {
    if ($context -ne [IntPtr]::Zero) {
      [void][LawyerAssistance.Release.NativeCrypt]::CertFreeCertificateContext($context)
    }
    if ($message -ne [IntPtr]::Zero) {
      [void][LawyerAssistance.Release.NativeCrypt]::CryptMsgClose($message)
    }
    if ($store -ne [IntPtr]::Zero) {
      [void][LawyerAssistance.Release.NativeCrypt]::CertCloseStore($store, 0)
    }
  }
}

function Test-LawyerAssistanceRfc3161Authenticode {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [AllowEmptyString()][string]$ExpectedSignerThumbprint = "",
    [AllowEmptyString()][string]$SignToolPath = ""
  )

  try {
    $resolved = [IO.Path]::GetFullPath($Path)
    if ([string]::IsNullOrWhiteSpace($SignToolPath)) {
      $SignToolPath = Get-LawyerAssistanceSignTool
    }
    if ([string]::IsNullOrWhiteSpace($SignToolPath) -or
        -not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) {
      return $false
    }
    $verifyArguments = @("verify", "/pa", "/all", "/tw", "/v")
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint)) {
      $expected = ($ExpectedSignerThumbprint -replace '\s', '').ToUpperInvariant()
      if ($expected -notmatch '^[0-9A-F]{40}$') { return $false }
      $verifyArguments += @("/sha1", $expected)
    } else {
      $expected = ""
    }
    $verifyArguments += $resolved
    & $SignToolPath @verifyArguments *> $null
    if ($LASTEXITCODE -ne 0) { return $false }

    $authenticode = Get-AuthenticodeSignature -LiteralPath $resolved
    if ([string]$authenticode.Status -cne "Valid" -or
        $null -eq $authenticode.SignerCertificate -or
        $null -eq $authenticode.TimeStamperCertificate -or
        (-not [string]::IsNullOrEmpty($expected) -and
          ([string]$authenticode.SignerCertificate.Thumbprint).ToUpperInvariant() -cne $expected)) {
      return $false
    }

    $cms = Get-LawyerAssistanceEmbeddedAuthenticodeCms $resolved
    if ($null -eq $cms -or $cms.SignerInfos.Count -ne 1) { return $false }
    $cms.CheckSignature($true)
    $signer = $cms.SignerInfos[0]
    if ($null -eq $signer.Certificate -or
        ([string]$signer.Certificate.Thumbprint).ToUpperInvariant() -cne
          ([string]$authenticode.SignerCertificate.Thumbprint).ToUpperInvariant()) {
      return $false
    }
    $rfc3161 = @($signer.UnsignedAttributes | Where-Object {
      [string]$_.Oid.Value -ceq "1.3.6.1.4.1.311.3.3.1"
    })
    $legacy = @($signer.UnsignedAttributes | Where-Object {
      [string]$_.Oid.Value -ceq "1.2.840.113549.1.9.6"
    })
    if ($rfc3161.Count -ne 1 -or $legacy.Count -ne 0 -or $rfc3161[0].Values.Count -ne 1) {
      return $false
    }

    $timestampCms = [Security.Cryptography.Pkcs.SignedCms]::new()
    $timestampCms.Decode($rfc3161[0].Values[0].RawData)
    if ([string]$timestampCms.ContentInfo.ContentType.Value -cne "1.2.840.113549.1.9.16.1.4" -or
        $timestampCms.SignerInfos.Count -ne 1) {
      return $false
    }
    $timestampCms.CheckSignature($true)
    $timestampSigner = $timestampCms.SignerInfos[0]
    return (
      [string]$timestampSigner.DigestAlgorithm.Value -ceq "2.16.840.1.101.3.4.2.1" -and
      $null -ne $timestampSigner.Certificate -and
      ([string]$timestampSigner.Certificate.Thumbprint).ToUpperInvariant() -ceq
        ([string]$authenticode.TimeStamperCertificate.Thumbprint).ToUpperInvariant()
    )
  } catch {
    return $false
  }
}

function Get-LawyerAssistanceAuthenticodeSignerThumbprint([string]$Path) {
  try {
    $signature = Get-AuthenticodeSignature -LiteralPath ([IO.Path]::GetFullPath($Path))
    if ([string]$signature.Status -cne "Valid" -or $null -eq $signature.SignerCertificate) {
      return $null
    }
    $thumbprint = ([string]$signature.SignerCertificate.Thumbprint).ToUpperInvariant()
    if ($thumbprint -notmatch '^[0-9A-F]{40}$') { return $null }
    return $thumbprint
  } catch {
    return $null
  }
}

function Test-LawyerAssistanceUpdaterKeyPair {
  param(
    [Parameter(Mandatory = $true)][string]$ProjectRoot,
    [Parameter(Mandatory = $true)][string]$PrivateKeyPath,
    [Parameter(Mandatory = $true)][string]$Password
  )

  $configPath = Join-Path $ProjectRoot "apps\desktop\src-tauri\tauri.conf.json"
  $publicKeyPath = Join-Path $ProjectRoot "apps\desktop\src-tauri\updater-public.key"
  $tauri = Join-Path $ProjectRoot "apps\desktop\node_modules\.bin\tauri.cmd"
  $verifier = Join-Path $ProjectRoot "scripts\verify_updater_signature.py"
  foreach ($path in @($configPath, $publicKeyPath, $tauri, $verifier)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $false }
  }
  try {
    $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $runtimePublicKey = [string]$config.plugins.updater.pubkey
    $filePublicKey = (Get-Content -LiteralPath $publicKeyPath -Raw -Encoding UTF8).Trim()
    if ([string]::IsNullOrWhiteSpace($runtimePublicKey) -or $runtimePublicKey -cne $filePublicKey) {
      return $false
    }
  } catch {
    return $false
  }

  $directory = New-LawyerAssistanceReleaseProbeDirectory "updater-probe"
  $environment = Get-LawyerAssistanceEnvironmentSnapshot @(
    "TAURI_SIGNING_PRIVATE_KEY",
    "TAURI_SIGNING_PRIVATE_KEY_PATH",
    "TAURI_SIGNING_PRIVATE_KEY_PASSWORD"
  )
  try {
    $probeName = "lawyer-assistance-updater-key-probe.bin"
    $probe = Join-Path $directory $probeName
    $bytes = [byte[]]::new(64)
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($bytes) } finally { $random.Dispose() }
    [IO.File]::WriteAllBytes($probe, $bytes)
    Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY_PATH -ErrorAction SilentlyContinue
    $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = $Password
    & $tauri signer sign --private-key-path $PrivateKeyPath $probe *> $null
    if ($LASTEXITCODE -ne 0) { return $false }
    $signature = "$probe.sig"
    if (-not (Test-Path -LiteralPath $signature -PathType Leaf)) { return $false }
    & python $verifier `
      --artifact $probe `
      --signature $signature `
      --public-key $publicKeyPath `
      --expected-filename $probeName *> $null
    return $LASTEXITCODE -eq 0
  } catch {
    return $false
  } finally {
    Restore-LawyerAssistanceEnvironmentSnapshot $environment
    Remove-LawyerAssistanceReleaseProbeDirectory $directory "updater-probe"
  }
}

function New-LawyerAssistanceProductionReleaseAdapters {
  return @{
    IsWindows = { return $env:OS -ceq "Windows_NT" }
    InvokeExternal = {
      param([string]$FilePath, [string[]]$ArgumentList)
      return Invoke-LawyerAssistanceNativeCommand -FilePath $FilePath -ArgumentList $ArgumentList
    }
    GetCodeSigningCertificates = {
      return @(Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue)
    }
    TestCertificatePrivateKey = {
      param($Certificate)
      return Test-LawyerAssistanceCertificatePrivateKey -Certificate $Certificate
    }
    ProbeAuthenticodeTimestamp = {
      param(
        [string]$ProjectRoot,
        [string]$Thumbprint,
        [Uri]$TimestampUri
      )
      return Test-LawyerAssistanceAuthenticodeTimestampCapability `
        -ProjectRoot $ProjectRoot `
        -Thumbprint $Thumbprint `
        -TimestampUri $TimestampUri
    }
    ProbeUpdaterKey = {
      param(
        [string]$ProjectRoot,
        [string]$PrivateKeyPath,
        [string]$Password
      )
      return Test-LawyerAssistanceUpdaterKeyPair `
        -ProjectRoot $ProjectRoot `
        -PrivateKeyPath $PrivateKeyPath `
        -Password $Password
    }
  }
}

function Assert-LawyerAssistanceReleaseAdapters {
  param([Parameter(Mandatory = $true)][hashtable]$Adapters)

  foreach ($name in @(
    "IsWindows",
    "InvokeExternal",
    "GetCodeSigningCertificates",
    "TestCertificatePrivateKey",
    "ProbeAuthenticodeTimestamp",
    "ProbeUpdaterKey"
  )) {
    if (-not $Adapters.ContainsKey($name) -or $Adapters[$name] -isnot [scriptblock]) {
      Throw-LawyerAssistanceReleaseFailure "REL-REPOSITORY-INVALID" $script:LawyerAssistanceReleaseExitCodes.RepositoryInvalid "The release adapter set is incomplete."
    }
  }
}

function Invoke-LawyerAssistanceReleaseExternal {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Adapters,
    [Parameter(Mandatory = $true)][string]$FilePath,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ArgumentList
  )

  $result = & $Adapters.InvokeExternal $FilePath $ArgumentList
  if ($null -eq $result -or $null -eq $result.ExitCode -or $null -eq $result.Output) {
    Throw-LawyerAssistanceReleaseFailure "REL-REPOSITORY-INVALID" $script:LawyerAssistanceReleaseExitCodes.RepositoryInvalid "An external release check returned an invalid result."
  }
  return [pscustomobject][ordered]@{
    ExitCode = [int]$result.ExitCode
    Output = [string]$result.Output
  }
}

function Assert-LawyerAssistanceReleaseRepositoryLayout {
  param([Parameter(Mandatory = $true)][string]$ProjectRoot)

  $required = @(
    @{ Path = (Join-Path $ProjectRoot ".git"); Type = "Any" },
    @{ Path = (Join-Path $ProjectRoot "scripts\check_release_contract.py"); Type = "Leaf" },
    @{ Path = (Join-Path $ProjectRoot "scripts\release\release-contract-v0.4.0.json"); Type = "Leaf" },
    @{ Path = (Join-Path $ProjectRoot "apps\desktop\scripts\build_signed_release.ps1"); Type = "Leaf" },
    @{ Path = (Join-Path $ProjectRoot "apps\desktop\scripts\verify_legal_resource.py"); Type = "Leaf" },
    @{ Path = (Join-Path $ProjectRoot "scripts\generate_third_party_notices.py"); Type = "Leaf" }
  )
  foreach ($entry in $required) {
    $exists = if ($entry.Type -ceq "Any") {
      Test-Path -LiteralPath $entry.Path
    } else {
      Test-Path -LiteralPath $entry.Path -PathType Leaf
    }
    if (-not $exists) {
      Throw-LawyerAssistanceReleaseFailure "REL-REPOSITORY-INVALID" $script:LawyerAssistanceReleaseExitCodes.RepositoryInvalid "The checked-in release repository layout is incomplete."
    }
  }
}

function ConvertFrom-LawyerAssistanceLsRemote {
  param([AllowEmptyString()][string]$Output)

  $result = @{}
  foreach ($line in @($Output -split "`r?`n")) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    if ($line -notmatch '^([0-9a-f]{40})\s+(.+)$') {
      return $null
    }
    $result[[string]$Matches[2]] = [string]$Matches[1]
  }
  return $result
}

function Assert-LawyerAssistanceFormalVersionContract {
  param([string]$ProjectRoot, [hashtable]$Adapters)

  $checker = Join-Path $ProjectRoot "scripts\check_release_contract.py"
  $contract = Join-Path $ProjectRoot "scripts\release\release-contract-v0.4.0.json"
  $result = Invoke-LawyerAssistanceReleaseExternal $Adapters "python" @(
    $checker, "--root", $ProjectRoot, "--contract", $contract, "--mode", "formal"
  )
  if ($result.ExitCode -ne 0) {
    Throw-LawyerAssistanceReleaseFailure "REL-VERSION-CONTRACT-INVALID" $script:LawyerAssistanceReleaseExitCodes.VersionContractInvalid "The formal 0.4.0 repository contract did not pass."
  }
}

function Get-LawyerAssistanceGitText {
  param(
    [string]$ProjectRoot,
    [hashtable]$Adapters,
    [string[]]$Arguments,
    [string]$ResultCode,
    [int]$ExitCode,
    [string]$Message
  )
  $result = Invoke-LawyerAssistanceReleaseExternal $Adapters "git" (@("-C", $ProjectRoot) + $Arguments)
  if ($result.ExitCode -ne 0) {
    Throw-LawyerAssistanceReleaseFailure $ResultCode $ExitCode $Message
  }
  return $result.Output.Trim()
}

function Assert-LawyerAssistanceMainAndCleanWorktree {
  param([string]$ProjectRoot, [hashtable]$Adapters)

  $branch = Get-LawyerAssistanceGitText $ProjectRoot $Adapters @("symbolic-ref", "--quiet", "--short", "HEAD") "REL-BRANCH-NOT-MAIN" $script:LawyerAssistanceReleaseExitCodes.BranchInvalid "A signed release must run from the main branch."
  if ($branch -cne $script:LawyerAssistanceReleaseContract.Branch) {
    Throw-LawyerAssistanceReleaseFailure "REL-BRANCH-NOT-MAIN" $script:LawyerAssistanceReleaseExitCodes.BranchInvalid "A signed release must run from the main branch."
  }
  $status = Get-LawyerAssistanceGitText $ProjectRoot $Adapters @("status", "--porcelain=v1", "--untracked-files=all") "REL-WORKTREE-CHECK-FAILED" $script:LawyerAssistanceReleaseExitCodes.WorktreeDirty "The Git worktree state could not be read."
  if (-not [string]::IsNullOrEmpty($status)) {
    Throw-LawyerAssistanceReleaseFailure "REL-WORKTREE-DIRTY" $script:LawyerAssistanceReleaseExitCodes.WorktreeDirty "The release commit must have a completely clean worktree."
  }
}

function Assert-LawyerAssistanceFetchedMain {
  param([string]$ProjectRoot, [hashtable]$Adapters)

  $originUrl = Get-LawyerAssistanceGitText $ProjectRoot $Adapters @(
    "remote", "get-url", "--no-push", "origin"
  ) "REL-REPOSITORY-INVALID" $script:LawyerAssistanceReleaseExitCodes.RepositoryInvalid "The origin fetch URL could not be read."
  if ($originUrl -cne $script:LawyerAssistanceReleaseContract.RepositoryUrl) {
    Throw-LawyerAssistanceReleaseFailure "REL-REPOSITORY-INVALID" $script:LawyerAssistanceReleaseExitCodes.RepositoryInvalid "The origin fetch URL does not match the frozen release repository."
  }
  $fetch = Invoke-LawyerAssistanceReleaseExternal $Adapters "git" @(
    "-C", $ProjectRoot, "fetch", "--no-tags", "--prune", "origin",
    "+refs/heads/main:refs/remotes/origin/main"
  )
  if ($fetch.ExitCode -ne 0) {
    Throw-LawyerAssistanceReleaseFailure "REL-REMOTE-FETCH-FAILED" $script:LawyerAssistanceReleaseExitCodes.RemoteFetchFailed "The current origin/main ref could not be fetched."
  }
  $head = Get-LawyerAssistanceGitText $ProjectRoot $Adapters @("rev-parse", "--verify", "HEAD") "REL-REMOTE-HEAD-INVALID" $script:LawyerAssistanceReleaseExitCodes.RemoteHeadMismatch "The release HEAD could not be resolved."
  $tracking = Get-LawyerAssistanceGitText $ProjectRoot $Adapters @("rev-parse", "--verify", "refs/remotes/origin/main") "REL-REMOTE-HEAD-INVALID" $script:LawyerAssistanceReleaseExitCodes.RemoteHeadMismatch "The fetched origin/main ref could not be resolved."
  if ($head -notmatch '^[0-9a-f]{40}$' -or $tracking -cne $head) {
    Throw-LawyerAssistanceReleaseFailure "REL-HEAD-NOT-ORIGIN-MAIN" $script:LawyerAssistanceReleaseExitCodes.RemoteHeadMismatch "HEAD must exactly equal freshly fetched origin/main."
  }
  $remote = Invoke-LawyerAssistanceReleaseExternal $Adapters "git" @("-C", $ProjectRoot, "ls-remote", "--exit-code", "origin", "refs/heads/main")
  $remoteRefs = if ($remote.ExitCode -eq 0) { ConvertFrom-LawyerAssistanceLsRemote $remote.Output } else { $null }
  if ($null -eq $remoteRefs -or $remoteRefs.Count -ne 1 -or
      -not $remoteRefs.ContainsKey("refs/heads/main") -or
      $remoteRefs["refs/heads/main"] -cne $head) {
    Throw-LawyerAssistanceReleaseFailure "REL-REMOTE-READBACK-MISMATCH" $script:LawyerAssistanceReleaseExitCodes.RemoteHeadMismatch "The live origin/main readback must exactly equal HEAD."
  }
  return $head
}

function Assert-LawyerAssistanceSourceTag {
  param([string]$ProjectRoot, [hashtable]$Adapters)

  $contract = $script:LawyerAssistanceReleaseContract
  $type = Get-LawyerAssistanceGitText $ProjectRoot $Adapters @("cat-file", "-t", "refs/tags/$($contract.SourceTag)") "REL-SOURCE-TAG-DRIFT" $script:LawyerAssistanceReleaseExitCodes.SourceTagInvalid "The immutable v0.3.1 tag is absent or invalid."
  $object = Get-LawyerAssistanceGitText $ProjectRoot $Adapters @("rev-parse", "refs/tags/$($contract.SourceTag)") "REL-SOURCE-TAG-DRIFT" $script:LawyerAssistanceReleaseExitCodes.SourceTagInvalid "The immutable v0.3.1 tag object could not be read."
  $commit = Get-LawyerAssistanceGitText $ProjectRoot $Adapters @("rev-parse", "refs/tags/$($contract.SourceTag)^{}") "REL-SOURCE-TAG-DRIFT" $script:LawyerAssistanceReleaseExitCodes.SourceTagInvalid "The immutable v0.3.1 peeled commit could not be read."
  if ($type -cne "tag" -or $object -cne $contract.SourceTagObject -or $commit -cne $contract.SourceTagCommit) {
    Throw-LawyerAssistanceReleaseFailure "REL-SOURCE-TAG-DRIFT" $script:LawyerAssistanceReleaseExitCodes.SourceTagInvalid "The immutable v0.3.1 provenance has drifted."
  }
  $remote = Invoke-LawyerAssistanceReleaseExternal $Adapters "git" @(
    "-C", $ProjectRoot, "ls-remote", "--tags", "origin",
    "refs/tags/$($contract.SourceTag)", "refs/tags/$($contract.SourceTag)^{}"
  )
  $refs = if ($remote.ExitCode -eq 0) { ConvertFrom-LawyerAssistanceLsRemote $remote.Output } else { $null }
  if ($null -eq $refs -or $refs.Count -ne 2 -or
      -not $refs.ContainsKey("refs/tags/$($contract.SourceTag)") -or
      -not $refs.ContainsKey("refs/tags/$($contract.SourceTag)^{}") -or
      $refs["refs/tags/$($contract.SourceTag)"] -cne $contract.SourceTagObject -or
      $refs["refs/tags/$($contract.SourceTag)^{}"] -cne $contract.SourceTagCommit) {
    Throw-LawyerAssistanceReleaseFailure "REL-SOURCE-TAG-DRIFT" $script:LawyerAssistanceReleaseExitCodes.SourceTagInvalid "The remote v0.3.1 provenance has drifted."
  }
}

function Get-LawyerAssistanceLocalTagPresence {
  param([string]$ProjectRoot, [hashtable]$Adapters, [string]$Tag)

  $result = Invoke-LawyerAssistanceReleaseExternal $Adapters "git" @("-C", $ProjectRoot, "show-ref", "--verify", "--quiet", "refs/tags/$Tag")
  if ($result.ExitCode -eq 0) { return $true }
  if ($result.ExitCode -eq 1) { return $false }
  Throw-LawyerAssistanceReleaseFailure "REL-RELEASE-TAG-INVALID" $script:LawyerAssistanceReleaseExitCodes.ReleaseTagInvalid "The local release-tag state could not be read."
}

function Assert-LawyerAssistanceReleaseTagPair {
  param([string]$ProjectRoot, [hashtable]$Adapters, [string]$Head)

  $tags = @($script:LawyerAssistanceReleaseContract.AppTag, $script:LawyerAssistanceReleaseContract.MinerUTag)
  $localPresence = @{}
  foreach ($tag in $tags) {
    $localPresence[$tag] = Get-LawyerAssistanceLocalTagPresence $ProjectRoot $Adapters $tag
  }
  $remoteArguments = @("-C", $ProjectRoot, "ls-remote", "--tags", "origin")
  foreach ($tag in $tags) {
    $remoteArguments += @("refs/tags/$tag", "refs/tags/$tag^{}")
  }
  $remote = Invoke-LawyerAssistanceReleaseExternal $Adapters "git" $remoteArguments
  $remoteRefs = if ($remote.ExitCode -eq 0) { ConvertFrom-LawyerAssistanceLsRemote $remote.Output } else { $null }
  if ($null -eq $remoteRefs) {
    Throw-LawyerAssistanceReleaseFailure "REL-RELEASE-TAG-INVALID" $script:LawyerAssistanceReleaseExitCodes.ReleaseTagInvalid "The remote release-tag state could not be read."
  }
  $noneLocal = @($localPresence.Values | Where-Object { $_ }).Count -eq 0
  $noneRemote = $remoteRefs.Count -eq 0
  if ($noneLocal -and $noneRemote) { return }

  foreach ($tag in $tags) {
    $tagRef = "refs/tags/$tag"
    $peeledRef = "$tagRef^{}"
    if (-not $localPresence[$tag] -or -not $remoteRefs.ContainsKey($tagRef) -or -not $remoteRefs.ContainsKey($peeledRef)) {
      Throw-LawyerAssistanceReleaseFailure "REL-RELEASE-TAG-PAIR-INCOMPLETE" $script:LawyerAssistanceReleaseExitCodes.ReleaseTagInvalid "The two release tags must be jointly absent or jointly present locally and remotely."
    }
    $type = Get-LawyerAssistanceGitText $ProjectRoot $Adapters @("cat-file", "-t", $tagRef) "REL-RELEASE-TAG-INVALID" $script:LawyerAssistanceReleaseExitCodes.ReleaseTagInvalid "A release tag could not be inspected."
    $object = Get-LawyerAssistanceGitText $ProjectRoot $Adapters @("rev-parse", $tagRef) "REL-RELEASE-TAG-INVALID" $script:LawyerAssistanceReleaseExitCodes.ReleaseTagInvalid "A release tag object could not be resolved."
    $commit = Get-LawyerAssistanceGitText $ProjectRoot $Adapters @("rev-parse", "$tagRef^{}") "REL-RELEASE-TAG-INVALID" $script:LawyerAssistanceReleaseExitCodes.ReleaseTagInvalid "A release tag commit could not be resolved."
    if ($type -cne "tag" -or $commit -cne $Head -or
        $remoteRefs[$tagRef] -cne $object -or $remoteRefs[$peeledRef] -cne $Head) {
      Throw-LawyerAssistanceReleaseFailure "REL-RELEASE-TAG-DRIFT" $script:LawyerAssistanceReleaseExitCodes.ReleaseTagInvalid "Both release tags must be annotated, immutable, and point to exact HEAD."
    }
  }
  if ($remoteRefs.Count -ne 4) {
    Throw-LawyerAssistanceReleaseFailure "REL-RELEASE-TAG-PAIR-INCOMPLETE" $script:LawyerAssistanceReleaseExitCodes.ReleaseTagInvalid "The remote release-tag pair is incomplete."
  }
}

function Assert-LawyerAssistanceLegalAndNotices {
  param([string]$ProjectRoot, [hashtable]$Adapters)

  $resource = Join-Path $ProjectRoot "apps\desktop\src-tauri\resources\legal_core.sqlite"
  $manifest = Join-Path $ProjectRoot "data\generated\legal_core_distribution_manifest.json"
  foreach ($relative in @(
    "apps\desktop\src-tauri\resources\legal_core.sqlite",
    "apps\desktop\src-tauri\resources\LICENSE.txt",
    "apps\desktop\src-tauri\resources\THIRD_PARTY_NOTICES.txt",
    "apps\desktop\src-tauri\resources\DATA_SOURCES.md",
    "data\generated\legal_core_distribution_manifest.json"
  )) {
    if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot $relative) -PathType Leaf)) {
      Throw-LawyerAssistanceReleaseFailure "REL-LEGAL-RESOURCE-INVALID" $script:LawyerAssistanceReleaseExitCodes.LegalResourceInvalid "A final legal resource or its release metadata is missing."
    }
  }
  $legalVerifier = Join-Path $ProjectRoot "apps\desktop\scripts\verify_legal_resource.py"
  $legalResult = Invoke-LawyerAssistancePreservingEnvironment @("LAWYER_ASSISTANCE_ALLOW_CI_LEGAL_FIXTURE") {
    Invoke-LawyerAssistanceReleaseExternal $Adapters "python" @($legalVerifier, "--resource", $resource, "--manifest", $manifest)
  }
  if ($legalResult.ExitCode -ne 0) {
    Throw-LawyerAssistanceReleaseFailure "REL-LEGAL-RESOURCE-INVALID" $script:LawyerAssistanceReleaseExitCodes.LegalResourceInvalid "The formal legal resource verification did not pass."
  }
  $noticeGenerator = Join-Path $ProjectRoot "scripts\generate_third_party_notices.py"
  $noticeResult = Invoke-LawyerAssistanceReleaseExternal $Adapters "python" @($noticeGenerator, "--check")
  if ($noticeResult.ExitCode -ne 0) {
    Throw-LawyerAssistanceReleaseFailure "REL-NOTICES-INCOMPLETE" $script:LawyerAssistanceReleaseExitCodes.NoticesInvalid "The checked-in third-party notices are incomplete or stale."
  }
}

function Assert-LawyerAssistanceExactHeadCiClosure {
  param([string]$Head, [hashtable]$Adapters)

  foreach ($name in @("GH_HOST", "GH_REPO")) {
    $override = Get-Item "Env:$name" -ErrorAction SilentlyContinue
    if ($null -ne $override -and -not [string]::IsNullOrWhiteSpace([string]$override.Value)) {
      Throw-LawyerAssistanceReleaseFailure "REL-REPOSITORY-INVALID" $script:LawyerAssistanceReleaseExitCodes.RepositoryInvalid "GitHub CLI host or repository overrides are forbidden during release checks."
    }
  }
  foreach ($workflow in @("ci.yml", "mcp-ci.yml")) {
    $result = Invoke-LawyerAssistanceReleaseExternal $Adapters "gh" @(
      "run", "list", "--repo", "github.com/$($script:LawyerAssistanceReleaseContract.Repository)",
      "--workflow", $workflow, "--branch", $script:LawyerAssistanceReleaseContract.Branch,
      "--commit", $Head, "--limit", "20",
      "--json", "databaseId,headBranch,headSha,status,conclusion,event,workflowName"
    )
    if ($result.ExitCode -ne 0) {
      Throw-LawyerAssistanceReleaseFailure "REL-CI-CLOSURE-INCOMPLETE" $script:LawyerAssistanceReleaseExitCodes.CiClosureInvalid "The exact-HEAD GitHub Actions closure could not be read."
    }
    try {
      $runs = @($result.Output | ConvertFrom-Json)
    } catch {
      Throw-LawyerAssistanceReleaseFailure "REL-CI-CLOSURE-INCOMPLETE" $script:LawyerAssistanceReleaseExitCodes.CiClosureInvalid "The exact-HEAD GitHub Actions response was invalid."
    }
    $matching = @($runs | Where-Object {
      [string]$_.headSha -ceq $Head -and
      [string]$_.headBranch -ceq $script:LawyerAssistanceReleaseContract.Branch -and
      [string]$_.event -ceq "push"
    } | Sort-Object { [Int64]$_.databaseId } -Descending)
    if ($matching.Count -eq 0 -or
        [string]$matching[0].status -cne "completed" -or
        [string]$matching[0].conclusion -cne "success") {
      Throw-LawyerAssistanceReleaseFailure "REL-CI-CLOSURE-INCOMPLETE" $script:LawyerAssistanceReleaseExitCodes.CiClosureInvalid "The latest exact-HEAD main run for each required workflow must be completed successfully."
    }
  }
}

function Assert-LawyerAssistanceSigningCredentials {
  param(
    [string]$ProjectRoot,
    [hashtable]$Adapters,
    [string]$CodeSigningThumbprint,
    [string]$UpdaterPrivateKeyPath,
    [string]$TimestampUrl
  )

  $now = Get-Date
  $certificates = @(& $Adapters.GetCodeSigningCertificates | Where-Object {
    $_.HasPrivateKey -and $_.NotBefore -le $now -and $_.NotAfter -gt $now
  })
  if ($certificates.Count -eq 0) {
    Throw-LawyerAssistanceReleaseFailure "REL-AUTH-CERT-NONE" $script:LawyerAssistanceReleaseExitCodes.CertificateMissing "No current code-signing certificate with a private key is available."
  }
  if ([string]::IsNullOrWhiteSpace($CodeSigningThumbprint)) {
    Throw-LawyerAssistanceReleaseFailure "REL-AUTH-THUMBPRINT-REQUIRED" $script:LawyerAssistanceReleaseExitCodes.ThumbprintMissing "A code-signing certificate thumbprint is required."
  }
  $normalized = ($CodeSigningThumbprint -replace '\s', '').ToUpperInvariant()
  if ($normalized -notmatch '^[0-9A-F]{40}$') {
    Throw-LawyerAssistanceReleaseFailure "REL-AUTH-THUMBPRINT-INVALID" $script:LawyerAssistanceReleaseExitCodes.CertificateInvalid "The selected certificate thumbprint is invalid."
  }
  $selected = @($certificates | Where-Object { ([string]$_.Thumbprint).ToUpperInvariant() -ceq $normalized })
  if ($selected.Count -ne 1 -or -not (& $Adapters.TestCertificatePrivateKey $selected[0])) {
    Throw-LawyerAssistanceReleaseFailure "REL-AUTH-PRIVATE-KEY-UNREADABLE" $script:LawyerAssistanceReleaseExitCodes.CertificateInvalid "The selected current certificate and readable private key were not found."
  }

  $timestampUri = $null
  if ([string]::IsNullOrWhiteSpace($TimestampUrl) -or
      -not [Uri]::TryCreate($TimestampUrl, [UriKind]::Absolute, [ref]$timestampUri) -or
      $timestampUri.Scheme -notin @("http", "https") -or
      [string]::IsNullOrWhiteSpace($timestampUri.Host) -or
      -not [string]::IsNullOrEmpty($timestampUri.UserInfo) -or
      -not [string]::IsNullOrEmpty($timestampUri.Fragment)) {
    Throw-LawyerAssistanceReleaseFailure "REL-TIMESTAMP-ENDPOINT-INVALID" $script:LawyerAssistanceReleaseExitCodes.TimestampInvalid "The RFC3161 timestamp endpoint URL is invalid."
  }
  if (-not (& $Adapters.ProbeAuthenticodeTimestamp $ProjectRoot $normalized $timestampUri)) {
    Throw-LawyerAssistanceReleaseFailure "REL-AUTH-TIMESTAMP-PROBE-FAILED" $script:LawyerAssistanceReleaseExitCodes.TimestampInvalid "The selected certificate could not produce and verify an exact RFC3161-timestamped Authenticode probe."
  }

  if (-not (Test-Path -LiteralPath $UpdaterPrivateKeyPath -PathType Leaf)) {
    Throw-LawyerAssistanceReleaseFailure "REL-UPDATER-KEY-MISSING" $script:LawyerAssistanceReleaseExitCodes.UpdaterKeyMissing "The updater private-key file is absent."
  }
  $stream = $null
  try {
    $stream = [IO.File]::Open($UpdaterPrivateKeyPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    if ($stream.Length -le 0) {
      Throw-LawyerAssistanceReleaseFailure "REL-UPDATER-KEY-MISSING" $script:LawyerAssistanceReleaseExitCodes.UpdaterKeyMissing "The updater private-key file is empty."
    }
  } catch {
    $failure = Get-LawyerAssistanceReleaseFailure $_
    if ($null -ne $failure) { throw }
    Throw-LawyerAssistanceReleaseFailure "REL-UPDATER-KEY-UNREADABLE" $script:LawyerAssistanceReleaseExitCodes.UpdaterKeyMissing "The updater private-key file is unreadable."
  } finally {
    if ($null -ne $stream) { $stream.Dispose() }
  }
  if ([string]::IsNullOrWhiteSpace($env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD)) {
    Throw-LawyerAssistanceReleaseFailure "REL-UPDATER-PASSWORD-MISSING" $script:LawyerAssistanceReleaseExitCodes.UpdaterPasswordMissing "The updater private-key password variable is absent."
  }
  if (-not (& $Adapters.ProbeUpdaterKey `
      $ProjectRoot `
      $UpdaterPrivateKeyPath `
      ([string]$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD))) {
    Throw-LawyerAssistanceReleaseFailure "REL-UPDATER-KEY-MISMATCH" $script:LawyerAssistanceReleaseExitCodes.UpdaterKeyInvalid "The updater private key, password, checked-in key file, and runtime updater trust anchor do not match."
  }
  return $normalized
}

function Invoke-LawyerAssistanceReleasePreflightCore {
  param(
    [Parameter(Mandatory = $true)][string]$ProjectRoot,
    [Parameter(Mandatory = $true)][AllowEmptyString()][string]$CodeSigningThumbprint,
    [Parameter(Mandatory = $true)][string]$UpdaterPrivateKeyPath,
    [Parameter(Mandatory = $true)][string]$TimestampUrl,
    [Parameter(Mandatory = $true)][hashtable]$Adapters
  )

  Assert-LawyerAssistanceReleaseAdapters $Adapters
  if (-not (& $Adapters.IsWindows)) {
    Throw-LawyerAssistanceReleaseFailure "REL-PLATFORM-UNSUPPORTED" $script:LawyerAssistanceReleaseExitCodes.UnsupportedPlatform "Windows is required for a signed release."
  }
  $root = [IO.Path]::GetFullPath($ProjectRoot)
  Assert-LawyerAssistanceReleaseRepositoryLayout $root
  Assert-LawyerAssistanceFormalVersionContract $root $Adapters
  Import-LawyerAssistanceReleaseContract $root
  Assert-LawyerAssistanceMainAndCleanWorktree $root $Adapters
  $head = Assert-LawyerAssistanceFetchedMain $root $Adapters
  Assert-LawyerAssistanceSourceTag $root $Adapters
  Assert-LawyerAssistanceReleaseTagPair $root $Adapters $head
  Assert-LawyerAssistanceLegalAndNotices $root $Adapters
  Assert-LawyerAssistanceExactHeadCiClosure $head $Adapters
  $normalizedThumbprint = Assert-LawyerAssistanceSigningCredentials $root $Adapters $CodeSigningThumbprint $UpdaterPrivateKeyPath $TimestampUrl
  return [pscustomobject][ordered]@{
    ResultCode = "REL-PREFLIGHT-OK"
    ExitCode = $script:LawyerAssistanceReleaseExitCodes.Success
    Version = $script:LawyerAssistanceReleaseContract.Version
    Head = $head
    CodeSigningThumbprint = $normalizedThumbprint
  }
}

function Get-LawyerAssistanceFixedReleaseOutputPaths {
  param([Parameter(Mandatory = $true)][string]$ProjectRoot)

  $root = [IO.Path]::GetFullPath($ProjectRoot)
  $version = $script:LawyerAssistanceReleaseContract.Version
  $releaseDir = Join-Path $root "target\x86_64-pc-windows-msvc\release"
  return [pscustomobject][ordered]@{
    Files = @(
      (Join-Path $releaseDir "lawyer-assistance.exe"),
      (Join-Path $releaseDir "lawyer-assistance-mcp.exe"),
      (Join-Path $root "apps\desktop\src-tauri\binaries\lawyer-assistance-mcp-x86_64-pc-windows-msvc.exe"),
      (Join-Path $releaseDir "bundle\nsis\Lawyer Assistance_${version}_x64-setup.exe"),
      (Join-Path $releaseDir "bundle\nsis\Lawyer Assistance_${version}_x64-setup.exe.sig"),
      (Join-Path $root "dist\latest.json"),
      (Join-Path $root "dist\Lawyer-Assistance_${version}_windows-x86_64-portable.zip"),
      (Join-Path $root "dist\Lawyer-Assistance_${version}_windows-x86_64-portable.zip.sha256"),
      (Join-Path $root ".release-secrets\tauri.code-signing.conf.json")
    )
    Directories = @(
      (Join-Path $root "dist\Lawyer-Assistance-portable-x86_64"),
      (Join-Path $root "dist\release-v${version}\app"),
      (Join-Path $root "dist\release-v${version}\mcp-ci-artifacts"),
      (Join-Path $root "dist\release-v${version}\app-release-assets")
    )
  }
}

function Remove-LawyerAssistanceFixedReleaseOutputs {
  param([Parameter(Mandatory = $true)][string]$ProjectRoot)

  $root = [IO.Path]::GetFullPath($ProjectRoot)
  $paths = Get-LawyerAssistanceFixedReleaseOutputPaths $root
  try {
    foreach ($path in $paths.Files) {
      $resolved = [IO.Path]::GetFullPath($path)
      if (-not $resolved.StartsWith(($root.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)) {
        Throw-LawyerAssistanceReleaseFailure "REL-CLEANUP-FAILED" $script:LawyerAssistanceReleaseExitCodes.CleanupFailed "A fixed cleanup path escaped the repository root."
      }
      if ((Test-Path -LiteralPath $resolved) -and -not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        Throw-LawyerAssistanceReleaseFailure "REL-CLEANUP-FAILED" $script:LawyerAssistanceReleaseExitCodes.CleanupFailed "A fixed cleanup file path has an unexpected filesystem type."
      }
      if (Test-Path -LiteralPath $resolved -PathType Leaf) {
        Remove-Item -LiteralPath $resolved -Force
      }
    }
    foreach ($path in $paths.Directories) {
      $resolved = [IO.Path]::GetFullPath($path)
      if (-not $resolved.StartsWith(($root.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)) {
        Throw-LawyerAssistanceReleaseFailure "REL-CLEANUP-FAILED" $script:LawyerAssistanceReleaseExitCodes.CleanupFailed "A fixed cleanup path escaped the repository root."
      }
      if ((Test-Path -LiteralPath $resolved) -and -not (Test-Path -LiteralPath $resolved -PathType Container)) {
        Throw-LawyerAssistanceReleaseFailure "REL-CLEANUP-FAILED" $script:LawyerAssistanceReleaseExitCodes.CleanupFailed "A fixed cleanup directory path has an unexpected filesystem type."
      }
      if (Test-Path -LiteralPath $resolved -PathType Container) {
        $item = Get-Item -LiteralPath $resolved -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
          Throw-LawyerAssistanceReleaseFailure "REL-CLEANUP-FAILED" $script:LawyerAssistanceReleaseExitCodes.CleanupFailed "A fixed cleanup directory is a reparse point."
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
      }
    }
  } catch {
    $failure = Get-LawyerAssistanceReleaseFailure $_
    if ($null -ne $failure) { throw }
    Throw-LawyerAssistanceReleaseFailure "REL-CLEANUP-FAILED" $script:LawyerAssistanceReleaseExitCodes.CleanupFailed "Cleanup of fixed generated release outputs failed."
  }
  return [pscustomobject][ordered]@{
    ResultCode = "REL-CLEANUP-OK"
    ExitCode = $script:LawyerAssistanceReleaseExitCodes.Success
  }
}
