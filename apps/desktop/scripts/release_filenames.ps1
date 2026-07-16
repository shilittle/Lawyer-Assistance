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
