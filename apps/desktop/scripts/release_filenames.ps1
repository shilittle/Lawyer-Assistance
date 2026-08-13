function Get-LawyerAssistanceReleaseFilenames {
  param(
    [Parameter(Mandatory = $true)][string]$Version
  )

  $semanticVersionPattern = '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|(?:\d*[A-Za-z-][0-9A-Za-z-]*))(?:\.(?:0|[1-9]\d*|(?:\d*[A-Za-z-][0-9A-Za-z-]*)))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$'
  if ($Version -cnotmatch $semanticVersionPattern) {
    throw "Version must be valid semantic version text"
  }

  # Tauri signs the local product filename, while GitHub Releases normalizes
  # spaces in uploaded asset names to periods. Keep this one-way mapping fixed.
  [pscustomobject][ordered]@{
    SignedArtifact = "Lawyer Assistance_${Version}_x64-setup.exe"
    GitHubAsset = "Lawyer.Assistance_${Version}_x64-setup.exe"
  }
}

function Get-LawyerAssistanceFormalReleaseFilenames {
  param(
    [Parameter(Mandatory = $true)][string]$ProjectRoot
  )

  $root = [IO.Path]::GetFullPath($ProjectRoot)
  $contractPath = Join-Path $root "scripts\release\release-contract-v0.4.0.json"
  if (-not (Test-Path -LiteralPath $contractPath -PathType Leaf)) {
    throw "The checked-in v0.4.0 release contract is missing"
  }
  try {
    $contract = Get-Content -LiteralPath $contractPath -Raw -Encoding UTF8 | ConvertFrom-Json
  } catch {
    throw "The checked-in v0.4.0 release contract is not valid JSON"
  }

  $version = [string]$contract.release.formalVersion
  if ($version -cne "0.4.0" -or
      [string]$contract.release.appTag -cne "v0.4.0" -or
      [string]$contract.release.minerUTag -cne "mineru-components-v0.4.0") {
    throw "The checked-in formal release identity must remain exact v0.4.0"
  }
  $generic = Get-LawyerAssistanceReleaseFilenames -Version $version
  $expectedAssets = [string[]]@(
    $generic.GitHubAsset,
    "$($generic.GitHubAsset).sha256",
    "$($generic.GitHubAsset).sig",
    "latest.json",
    "Lawyer-Assistance_${version}_windows-x86_64-portable.zip",
    "Lawyer-Assistance_${version}_windows-x86_64-portable.zip.sha256",
    "lawyer-assistance-mcp-v${version}-x86_64-pc-windows-msvc.zip",
    "lawyer-assistance-mcp-v${version}-x86_64-pc-windows-msvc.zip.sha256",
    "lawyer-assistance-mcp-v${version}-x86_64-unknown-linux-gnu.tar.gz",
    "lawyer-assistance-mcp-v${version}-x86_64-unknown-linux-gnu.tar.gz.sha256",
    "lawyer-assistance-mcp-v${version}-aarch64-apple-darwin.tar.gz",
    "lawyer-assistance-mcp-v${version}-aarch64-apple-darwin.tar.gz.sha256"
  )
  $contractAssets = [string[]]@($contract.appAssets | ForEach-Object { [string]$_ })
  if ($contractAssets.Count -ne $expectedAssets.Count) {
    throw "The checked-in App release allowlist must contain exactly 12 assets"
  }
  for ($index = 0; $index -lt $expectedAssets.Count; $index++) {
    if ($contractAssets[$index] -cne $expectedAssets[$index]) {
      throw "The checked-in App release allowlist name or order drifted at index $index"
    }
  }

  [pscustomobject][ordered]@{
    Version = $version
    AppTag = [string]$contract.release.appTag
    MinerUTag = [string]$contract.release.minerUTag
    SignedArtifact = [string]$generic.SignedArtifact
    GitHubAsset = [string]$generic.GitHubAsset
    AppAssets = [string[]]$contractAssets
    LocalAppAssets = [string[]]$contractAssets[0..5]
    StagingDirectory = Join-Path $root "dist\release-v${version}\app"
  }
}
