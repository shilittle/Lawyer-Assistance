[CmdletBinding()]
param(
  [string]$MineruCommand = "mineru",
  [string]$NvidiaSmiCommand = "nvidia-smi.exe",
  [string]$MineruToolsConfigPath = "",
  [string]$ModelManifestPath = "",
  [string]$EvidencePath = "",
  [string]$GenerateCanaryOnlyPath = "",
  [switch]$KeepArtifacts,
  [ValidateRange(10, 7200)]
  [int]$TimeoutSeconds = 1800
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$script:ExpectedMineruVersion = "3.4.3"
$script:ExpectedBackend = "pipeline"
$script:ExpectedMethod = "ocr"
$script:ExpectedLanguage = "ch"
$script:ExpectedPageWidth = 595
$script:ExpectedPageHeight = 841
$script:ExpectedContentListCoordinateExtent = 1000
$script:QualificationPrefix = "lawyer-assistance-mineru-qualification-"
$encodedExpectedPages = @(
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
$script:ExpectedPages = @($encodedExpectedPages | ForEach-Object {
  [pscustomobject]@{
    Lines = @($_.Lines | ForEach-Object {
      [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_))
    })
  }
})
$script:ExpectedPageCount = $script:ExpectedPages.Count
$script:ExpectedTextEntryCount = @($script:ExpectedPages | ForEach-Object { $_.Lines }).Count
if ($script:ExpectedPageCount -ne 3 -or $script:ExpectedTextEntryCount -ne 24 -or @($script:ExpectedPages | Where-Object { $_.Lines.Count -ne 8 }).Count -ne 0) {
  throw "the fixed qualification page contract is invalid"
}
$encodedExpectedPages = $null

function Get-Sha256Hex {
  param([Parameter(Mandatory = $true)][string]$LiteralPath)

  return (Get-FileHash -Algorithm SHA256 -LiteralPath $LiteralPath).Hash.ToLowerInvariant()
}

function Get-TextSha256Hex {
  param([Parameter(Mandatory = $true)][string]$Value)

  $algorithm = [Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
  } finally {
    $algorithm.Dispose()
  }
}

function Get-BytesSha256Hex {
  param([Parameter(Mandatory = $true)][byte[]]$Bytes)

  $algorithm = [Security.Cryptography.SHA256]::Create()
  try {
    return ([BitConverter]::ToString($algorithm.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
  } finally {
    $algorithm.Dispose()
  }
}

function Assert-FixedLocalPath {
  param(
    [Parameter(Mandatory = $true)][string]$LiteralPath,
    [Parameter(Mandatory = $true)][string]$Description,
    [switch]$Directory
  )

  $resolved = (Resolve-Path -LiteralPath $LiteralPath -ErrorAction Stop).ProviderPath
  $item = Get-Item -Force -LiteralPath $resolved
  if ($Directory) {
    if (-not $item.PSIsContainer) {
      throw "$Description must be a directory"
    }
  } elseif ($item.PSIsContainer) {
    throw "$Description must be a file"
  }

  $root = [IO.Path]::GetPathRoot($resolved)
  if ([string]::IsNullOrWhiteSpace($root) -or $root.StartsWith("\\", [StringComparison]::Ordinal)) {
    throw "$Description must be on a local fixed drive"
  }
  $drive = New-Object IO.DriveInfo($root)
  if ($drive.DriveType -ne [IO.DriveType]::Fixed) {
    throw "$Description must be on a local fixed drive"
  }

  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Description and all of its ancestors must not be reparse points"
  }
  $cursor = if ($item.PSIsContainer) { $item.Parent } else { $item.Directory }
  while ($null -ne $cursor) {
    if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Description and all of its ancestors must not be reparse points"
    }
    $cursor = $cursor.Parent
  }
  return $resolved
}

function Resolve-CommandDescriptor {
  param(
    [Parameter(Mandatory = $true)][string]$Candidate,
    [Parameter(Mandatory = $true)][string]$Description
  )

  $command = Get-Command -Name $Candidate -CommandType Application, ExternalScript -ErrorAction Stop |
    Select-Object -First 1
  $commandPath = if ($command.PSObject.Properties.Name -contains "Path") {
    $command.Path
  } else {
    $command.Source
  }
  $commandPath = Assert-FixedLocalPath -LiteralPath $commandPath -Description $Description
  $extension = [IO.Path]::GetExtension($commandPath)
  if ($extension -ieq ".ps1") {
    $powerShellPath = (Get-Process -Id $PID).Path
    $powerShellPath = Assert-FixedLocalPath -LiteralPath $powerShellPath -Description "PowerShell launcher"
    return [pscustomobject]@{
      CommandPath = $commandPath
      CommandSha256 = Get-Sha256Hex -LiteralPath $commandPath
      LauncherPath = $powerShellPath
      LauncherSha256 = Get-Sha256Hex -LiteralPath $powerShellPath
      PrefixArguments = @(
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        $commandPath
      )
    }
  }
  if ($extension -ine ".exe" -and $extension -ine ".com") {
    throw "$Description must resolve to an executable or a PowerShell test double"
  }
  return [pscustomobject]@{
    CommandPath = $commandPath
    CommandSha256 = Get-Sha256Hex -LiteralPath $commandPath
    LauncherPath = $commandPath
    LauncherSha256 = Get-Sha256Hex -LiteralPath $commandPath
    PrefixArguments = @()
  }
}

function ConvertTo-NativeArgument {
  param([AllowEmptyString()][string]$Value)

  if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
    return $Value
  }
  $builder = New-Object Text.StringBuilder
  [void]$builder.Append('"')
  $slashes = 0
  foreach ($character in $Value.ToCharArray()) {
    if ($character -eq '\') {
      $slashes += 1
      continue
    }
    if ($character -eq '"') {
      [void]$builder.Append(('\' * (($slashes * 2) + 1)))
      [void]$builder.Append('"')
      $slashes = 0
      continue
    }
    if ($slashes -gt 0) {
      [void]$builder.Append(('\' * $slashes))
      $slashes = 0
    }
    [void]$builder.Append($character)
  }
  if ($slashes -gt 0) {
    [void]$builder.Append(('\' * ($slashes * 2)))
  }
  [void]$builder.Append('"')
  return $builder.ToString()
}

function Stop-ProcessTree {
  param([Parameter(Mandatory = $true)][int]$ProcessId)

  $taskkill = Join-Path $env:SystemRoot "System32\taskkill.exe"
  if (Test-Path -LiteralPath $taskkill -PathType Leaf) {
    & $taskkill /PID $ProcessId /T /F 1>$null 2>$null
    return
  }
  Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
}

function Invoke-SanitizedProcess {
  param(
    [Parameter(Mandatory = $true)]$Descriptor,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [Parameter(Mandatory = $true)][hashtable]$Environment,
    [Parameter(Mandatory = $true)][string]$WorkingDirectory,
    [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds
  )

  $allArguments = @($Descriptor.PrefixArguments) + $Arguments
  $startInfo = New-Object Diagnostics.ProcessStartInfo
  $startInfo.FileName = $Descriptor.LauncherPath
  $startInfo.Arguments = (($allArguments | ForEach-Object { ConvertTo-NativeArgument -Value $_ }) -join " ")
  $startInfo.WorkingDirectory = $WorkingDirectory
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardInput = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $startInfo.EnvironmentVariables.Clear()

  foreach ($name in @(
    "SystemRoot",
    "WINDIR",
    "ComSpec",
    "PATHEXT",
    "PATH",
    "CUDA_PATH",
    "CUDA_HOME",
    "LD_LIBRARY_PATH"
  )) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if (-not [string]::IsNullOrEmpty($value)) {
      $startInfo.EnvironmentVariables[$name] = $value
    }
  }
  foreach ($entry in $Environment.GetEnumerator()) {
    $startInfo.EnvironmentVariables[$entry.Key] = [string]$entry.Value
  }

  $process = New-Object Diagnostics.Process
  $process.StartInfo = $startInfo
  $startedAt = [Diagnostics.Stopwatch]::StartNew()
  try {
    if (-not $process.Start()) {
      throw "local qualification process did not start"
    }
    $process.StandardInput.Close()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutMilliseconds)) {
      Stop-ProcessTree -ProcessId $process.Id
      throw "local qualification process timed out"
    }
    $process.WaitForExit()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    if ($stdout.Length -gt 8MB -or $stderr.Length -gt 8MB) {
      throw "local qualification process emitted excessive diagnostic output"
    }
    return [pscustomobject]@{
      ExitCode = $process.ExitCode
      DurationMs = [int64]$startedAt.ElapsedMilliseconds
      Stdout = $stdout
      Stderr = $stderr
    }
  } finally {
    $startedAt.Stop()
    $process.Dispose()
  }
}

function Write-AsciiBytes {
  param(
    [Parameter(Mandatory = $true)][IO.Stream]$Stream,
    [Parameter(Mandatory = $true)][string]$Value
  )

  $bytes = [Text.Encoding]::ASCII.GetBytes($Value)
  $Stream.Write($bytes, 0, $bytes.Length)
}

function New-FixedSyntheticScanPdf {
  param([Parameter(Mandatory = $true)][string]$Destination)

  Add-Type -AssemblyName System.Drawing
  $encoder = [Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() |
    Where-Object { $_.MimeType -ceq "image/jpeg" } |
    Select-Object -First 1
  if ($null -eq $encoder) {
    throw "JPEG encoder is unavailable"
  }
  $jpegPages = @()
  foreach ($expectedPage in $script:ExpectedPages) {
    $bitmap = New-Object Drawing.Bitmap(1240, 1754, [Drawing.Imaging.PixelFormat]::Format24bppRgb)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    $titleFont = $null
    $bodyFont = $null
    $brush = $null
    $jpeg = New-Object IO.MemoryStream
    try {
      $graphics.Clear([Drawing.Color]::White)
      $graphics.TextRenderingHint = [Drawing.Text.TextRenderingHint]::AntiAliasGridFit
      $graphics.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::HighQuality
      $graphics.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
      $titleFont = New-Object Drawing.Font("Microsoft YaHei", 42, [Drawing.FontStyle]::Bold, [Drawing.GraphicsUnit]::Pixel)
      $bodyFont = New-Object Drawing.Font("Microsoft YaHei", 32, [Drawing.FontStyle]::Regular, [Drawing.GraphicsUnit]::Pixel)
      if ($titleFont.Name -cne "Microsoft YaHei" -or $bodyFont.Name -cne "Microsoft YaHei") {
        throw "the fixed Microsoft YaHei qualification font is unavailable"
      }
      $brush = New-Object Drawing.SolidBrush([Drawing.Color]::Black)
      $graphics.DrawString($expectedPage.Lines[0], $titleFont, $brush, 110, 115)
      $y = 300
      foreach ($line in $expectedPage.Lines[1..($expectedPage.Lines.Count - 1)]) {
        $graphics.DrawString($line, $bodyFont, $brush, 110, $y)
        $y += 105
      }
      $parameters = New-Object Drawing.Imaging.EncoderParameters(1)
      try {
        $parameters.Param[0] = New-Object Drawing.Imaging.EncoderParameter(
          [Drawing.Imaging.Encoder]::Quality,
          [int64]95
        )
        $bitmap.Save($jpeg, $encoder, $parameters)
        $jpegPages += ,$jpeg.ToArray()
      } finally {
        if ($null -ne $parameters.Param[0]) {
          $parameters.Param[0].Dispose()
        }
        $parameters.Dispose()
      }
    } finally {
      if ($null -ne $brush) { $brush.Dispose() }
      if ($null -ne $bodyFont) { $bodyFont.Dispose() }
      if ($null -ne $titleFont) { $titleFont.Dispose() }
      $graphics.Dispose()
      $bitmap.Dispose()
      $jpeg.Dispose()
    }
  }
  $jpegHashes = @($jpegPages | ForEach-Object { Get-BytesSha256Hex -Bytes $_ })
  if ($jpegPages.Count -ne $script:ExpectedPageCount -or @($jpegHashes | Sort-Object -Unique).Count -ne $script:ExpectedPageCount) {
    throw "the fixed qualification page images are not distinct"
  }

  $pdf = New-Object IO.MemoryStream
  try {
    Write-AsciiBytes -Stream $pdf -Value "%PDF-1.4`n%synthetic-scan-only`n"
    $offsets = New-Object 'Collections.Generic.List[Int64]'

    [void]$offsets.Add($pdf.Position)
    Write-AsciiBytes -Stream $pdf -Value "1 0 obj`n<< /Type /Catalog /Pages 2 0 R >>`nendobj`n"
    [void]$offsets.Add($pdf.Position)
    Write-AsciiBytes -Stream $pdf -Value "2 0 obj`n<< /Type /Pages /Count 3 /Kids [3 0 R 4 0 R 5 0 R] >>`nendobj`n"
    for ($pageIndex = 0; $pageIndex -lt $script:ExpectedPageCount; $pageIndex += 1) {
      $pageObject = 3 + $pageIndex
      $imageObject = 6 + $pageIndex
      $contentObject = 9 + $pageIndex
      [void]$offsets.Add($pdf.Position)
      Write-AsciiBytes -Stream $pdf -Value ("{0} 0 obj`n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 841] /Resources << /XObject << /Im{1} {2} 0 R >> >> /Contents {3} 0 R >>`nendobj`n" -f $pageObject, $pageIndex, $imageObject, $contentObject)
    }
    for ($pageIndex = 0; $pageIndex -lt $script:ExpectedPageCount; $pageIndex += 1) {
      $imageObject = 6 + $pageIndex
      $imageBytes = $jpegPages[$pageIndex]
      [void]$offsets.Add($pdf.Position)
      Write-AsciiBytes -Stream $pdf -Value ("{0} 0 obj`n<< /Type /XObject /Subtype /Image /Width 1240 /Height 1754 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length {1} >>`nstream`n" -f $imageObject, $imageBytes.Length)
      $pdf.Write($imageBytes, 0, $imageBytes.Length)
      Write-AsciiBytes -Stream $pdf -Value "`nendstream`nendobj`n"
    }
    for ($pageIndex = 0; $pageIndex -lt $script:ExpectedPageCount; $pageIndex += 1) {
      $contentObject = 9 + $pageIndex
      $content = "q`n595 0 0 841 0 0 cm`n/Im$pageIndex Do`nQ`n"
      [void]$offsets.Add($pdf.Position)
      Write-AsciiBytes -Stream $pdf -Value ("{0} 0 obj`n<< /Length {1} >>`nstream`n{2}endstream`nendobj`n" -f $contentObject, ([Text.Encoding]::ASCII.GetByteCount($content)), $content)
    }

    $xrefOffset = $pdf.Position
    Write-AsciiBytes -Stream $pdf -Value "xref`n0 12`n0000000000 65535 f `n"
    foreach ($offset in $offsets) {
      Write-AsciiBytes -Stream $pdf -Value (("{0:D10} 00000 n `n" -f $offset))
    }
    Write-AsciiBytes -Stream $pdf -Value ("trailer`n<< /Size 12 /Root 1 0 R >>`nstartxref`n{0}`n%%EOF`n" -f $xrefOffset)
    [IO.File]::WriteAllBytes($Destination, $pdf.ToArray())
  } finally {
    $pdf.Dispose()
  }
}

function Test-ByteSequence {
  param(
    [Parameter(Mandatory = $true)][byte[]]$Haystack,
    [Parameter(Mandatory = $true)][byte[]]$Needle
  )

  if ($Needle.Length -eq 0 -or $Needle.Length -gt $Haystack.Length) {
    return $false
  }
  for ($start = 0; $start -le $Haystack.Length - $Needle.Length; $start += 1) {
    $match = $true
    for ($offset = 0; $offset -lt $Needle.Length; $offset += 1) {
      if ($Haystack[$start + $offset] -ne $Needle[$offset]) {
        $match = $false
        break
      }
    }
    if ($match) {
      return $true
    }
  }
  return $false
}

function Assert-SyntheticScanPdf {
  param([Parameter(Mandatory = $true)][string]$LiteralPath)

  $bytes = [IO.File]::ReadAllBytes($LiteralPath)
  if ($bytes.Length -gt 4MB) {
    throw "generated synthetic qualification PDF exceeds its fixed size bound"
  }
  $ascii = [Text.Encoding]::ASCII.GetString($bytes)
  foreach ($required in @("/Count 3", "/Kids [3 0 R 4 0 R 5 0 R]", "/MediaBox [0 0 595 841]", "/Im0 6 0 R", "/Im1 7 0 R", "/Im2 8 0 R")) {
    if (-not $ascii.Contains($required)) {
      throw "generated qualification PDF does not have the expected image-only structure"
    }
  }
  if ([regex]::Matches($ascii, "/Type /Page(?!s)").Count -ne $script:ExpectedPageCount) {
    throw "generated qualification PDF does not contain the exact expected page count"
  }
  if ([regex]::Matches($ascii, "/Subtype /Image").Count -ne $script:ExpectedPageCount -or [regex]::Matches($ascii, "/Filter /DCTDecode").Count -ne $script:ExpectedPageCount) {
    throw "generated qualification PDF does not contain three distinct raster image objects"
  }
  foreach ($forbidden in @("/Font", "/ToUnicode", " BT ")) {
    if ($ascii.Contains($forbidden)) {
      throw "generated qualification PDF unexpectedly contains a text-layer marker"
    }
  }
  foreach ($page in $script:ExpectedPages) {
    foreach ($line in $page.Lines) {
      if (Test-ByteSequence -Haystack $bytes -Needle ([Text.Encoding]::UTF8.GetBytes($line))) {
        throw "generated qualification PDF unexpectedly contains clear-text canary bytes"
      }
    }
  }
}

function Assert-SafeTree {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][int]$MaxFiles,
    [Parameter(Mandatory = $true)][int64]$MaxBytes
  )

  $rootPath = (Resolve-Path -LiteralPath $Root).ProviderPath.TrimEnd('\')
  $prefix = $rootPath + "\"
  $fileCount = 0
  $totalBytes = [int64]0
  foreach ($item in Get-ChildItem -Force -Recurse -LiteralPath $rootPath) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "qualification output contains a reparse point"
    }
    $fullPath = [IO.Path]::GetFullPath($item.FullName)
    if (-not $fullPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
      throw "qualification output escaped its isolated root"
    }
    if (-not $item.PSIsContainer) {
      $fileCount += 1
      if ([int64]$item.Length -gt ($MaxBytes - $totalBytes)) {
        throw "qualification output exceeded its fixed file or byte bound"
      }
      $totalBytes += [int64]$item.Length
      if ($fileCount -gt $MaxFiles) {
        throw "qualification output exceeded its fixed file or byte bound"
      }
    }
  }
  return [pscustomobject]@{
    FileCount = $fileCount
    TotalBytes = $totalBytes
  }
}

function Get-UniqueOutputFile {
  param(
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [Parameter(Mandatory = $true)][string]$Suffix
  )

  $matches = @(Get-ChildItem -Force -Recurse -File -LiteralPath $OutputRoot |
    Where-Object { $_.Name.EndsWith($Suffix, [StringComparison]::Ordinal) })
  if ($matches.Count -ne 1) {
    throw "qualification output must contain exactly one $Suffix file"
  }
  return $matches[0].FullName
}

function Assert-MineruOutput {
  param([Parameter(Mandatory = $true)][string]$OutputRoot)

  $contentPath = Get-UniqueOutputFile -OutputRoot $OutputRoot -Suffix "_content_list.json"
  $middlePath = Get-UniqueOutputFile -OutputRoot $OutputRoot -Suffix "_middle.json"
  $content = @((Get-Content -Raw -Encoding UTF8 -LiteralPath $contentPath | ConvertFrom-Json))
  $middle = Get-Content -Raw -Encoding UTF8 -LiteralPath $middlePath | ConvertFrom-Json

  if ($middle._backend -cne $script:ExpectedBackend) {
    throw "MinerU did not report the required pipeline backend"
  }
  if ($middle._version_name -cne $script:ExpectedMineruVersion) {
    throw "MinerU version did not match the fixed qualification version"
  }
  $pages = @($middle.pdf_info)
  if ($pages.Count -ne $script:ExpectedPageCount) {
    throw "MinerU middle output did not contain the exact expected page count"
  }
  if ($content.Count -ne $script:ExpectedTextEntryCount) {
    throw "MinerU content_list did not contain the exact expected text entry count"
  }
  for ($pageIndex = 0; $pageIndex -lt $script:ExpectedPageCount; $pageIndex += 1) {
    if ([int]$pages[$pageIndex].page_idx -ne $pageIndex) {
      throw "MinerU middle output did not preserve the exact page index sequence"
    }
    $pageSize = @($pages[$pageIndex].page_size)
    if ($pageSize.Count -ne 2 -or [double]$pageSize[0] -ne $script:ExpectedPageWidth -or [double]$pageSize[1] -ne $script:ExpectedPageHeight) {
      throw "MinerU middle output did not preserve the fixed page_size"
    }
    $pageContent = @($content | Where-Object { [int]$_.page_idx -eq $pageIndex })
    $expectedLines = @($script:ExpectedPages[$pageIndex].Lines)
    if ($pageContent.Count -ne $expectedLines.Count) {
      throw "MinerU content_list did not preserve the exact per-page text entry count"
    }
    for ($lineIndex = 0; $lineIndex -lt $expectedLines.Count; $lineIndex += 1) {
      $entry = $pageContent[$lineIndex]
      $expectedNormalized = [regex]::Replace([string]$expectedLines[$lineIndex], "\s", "")
      $actualNormalized = [regex]::Replace([string]$entry.text, "\s", "")
      if ($actualNormalized -cne $expectedNormalized) {
        $mismatch = 0
        while ($mismatch -lt [Math]::Min($actualNormalized.Length, $expectedNormalized.Length) -and $actualNormalized[$mismatch] -ceq $expectedNormalized[$mismatch]) {
          $mismatch += 1
        }
        $expectedCode = if ($mismatch -lt $expectedNormalized.Length) { "U+{0:X4}" -f [int][char]$expectedNormalized[$mismatch] } else { "END" }
        $actualCode = if ($mismatch -lt $actualNormalized.Length) { "U+{0:X4}" -f [int][char]$actualNormalized[$mismatch] } else { "END" }
        throw "MinerU OCR text mismatch on synthetic page $pageIndex line $lineIndex at offset $mismatch ($expectedCode/$actualCode)"
      }
      $bbox = @($entry.bbox)
      if ($bbox.Count -ne 4) {
        throw "MinerU content_list item did not contain a four-value bbox"
      }
      foreach ($coordinate in $bbox) {
        $number = [double]$coordinate
        if ([double]::IsNaN($number) -or [double]::IsInfinity($number) -or $number -lt 0) {
          throw "MinerU content_list item contained an invalid bbox"
        }
      }
      if ([double]$bbox[0] -ge [double]$bbox[2] -or [double]$bbox[1] -ge [double]$bbox[3] -or [double]$bbox[2] -gt $script:ExpectedContentListCoordinateExtent -or [double]$bbox[3] -gt $script:ExpectedContentListCoordinateExtent) {
        throw "MinerU content_list item bbox exceeded the fixed 0-1000 coordinate space"
      }
    }
  }
  if (@($content | Where-Object { [int]$_.page_idx -lt 0 -or [int]$_.page_idx -ge $script:ExpectedPageCount }).Count -ne 0) {
    throw "MinerU content_list contained an unexpected page_idx"
  }

  return [pscustomobject]@{
    ContentPath = $contentPath
    MiddlePath = $middlePath
    Version = [string]$middle._version_name
    PageCount = $pages.Count
    PageIndices = @($pages | ForEach-Object { [int]$_.page_idx })
    PageWidth = $script:ExpectedPageWidth
    PageHeight = $script:ExpectedPageHeight
    TextEntryCount = $content.Count
  }
}

function Get-GpuMetadata {
  param(
    [Parameter(Mandatory = $true)]$Descriptor,
    [Parameter(Mandatory = $true)][hashtable]$Environment,
    [Parameter(Mandatory = $true)][string]$WorkingDirectory
  )

  $result = Invoke-SanitizedProcess `
    -Descriptor $Descriptor `
    -Arguments @("--query-gpu=index,name,driver_version,memory.total", "--format=csv,noheader,nounits") `
    -Environment $Environment `
    -WorkingDirectory $WorkingDirectory `
    -TimeoutMilliseconds 30000
  if ($result.ExitCode -ne 0) {
    throw "nvidia-smi did not exit successfully"
  }
  $gpus = @()
  foreach ($line in ($result.Stdout -split "`r?`n")) {
    if ([string]::IsNullOrWhiteSpace($line)) {
      continue
    }
    $fields = @($line.Split(',') | ForEach-Object { $_.Trim() })
    if ($fields.Count -ne 4) {
      throw "nvidia-smi returned an unexpected metadata shape"
    }
    $index = 0
    if (-not [uint32]::TryParse($fields[0], [ref]$index)) {
      throw "nvidia-smi returned an invalid device index"
    }
    $memoryMiB = 0
    if (-not [int]::TryParse($fields[3], [ref]$memoryMiB) -or $memoryMiB -le 0) {
      throw "nvidia-smi returned an invalid memory total"
    }
    $descriptorHash = Get-TextSha256Hex -Value ("{0}|{1}|{2}|{3}" -f $index, $fields[1], $fields[2], $memoryMiB)
    $gpus += [ordered]@{
      index = $index
      name = $fields[1]
      driverVersion = $fields[2]
      memoryMiB = $memoryMiB
      descriptorSha256 = $descriptorHash
    }
  }
  if ($gpus.Count -lt 1 -or $gpus.Count -gt 16) {
    throw "nvidia-smi returned an unsupported device count"
  }
  $indices = @($gpus | ForEach-Object { [uint32]$_.index })
  if (@($indices | Select-Object -Unique).Count -ne $indices.Count) {
    throw "nvidia-smi returned duplicate device indices"
  }
  $selected = @($gpus | Where-Object { [uint32]$_.index -eq 0 })
  if ($selected.Count -ne 1 -or [int]$selected[0].memoryMiB -lt 6144) {
    throw "CUDA_VISIBLE_DEVICES=0 did not resolve to one qualified local GPU"
  }
  return $gpus
}

function Write-EvidenceFile {
  param(
    [Parameter(Mandatory = $true)][string]$LiteralPath,
    [Parameter(Mandatory = $true)][string]$Json
  )

  $absolute = [IO.Path]::GetFullPath($LiteralPath)
  if ([IO.Path]::GetExtension($absolute) -ine ".json") {
    throw "evidence destination must use the .json extension"
  }
  if (Test-Path -LiteralPath $absolute) {
    throw "refusing to overwrite an existing evidence file"
  }
  $parent = Split-Path -Parent $absolute
  if ([string]::IsNullOrWhiteSpace($parent) -or -not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw "evidence parent directory must already exist"
  }
  [void](Assert-FixedLocalPath -LiteralPath $parent -Description "evidence directory" -Directory)
  $temporary = Join-Path $parent (([IO.Path]::GetFileName($absolute)) + "." + [Guid]::NewGuid().ToString("N") + ".tmp")
  try {
    [IO.File]::WriteAllText($temporary, $Json + "`n", (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $absolute
  } finally {
    if (Test-Path -LiteralPath $temporary) {
      Remove-Item -Force -LiteralPath $temporary
    }
  }
}

function Remove-QualificationJob {
  param([Parameter(Mandatory = $true)][string]$JobRoot)

  $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
  $absolute = [IO.Path]::GetFullPath($JobRoot).TrimEnd('\')
  if ([IO.Path]::GetDirectoryName($absolute) -cne $temporaryRoot -or -not [IO.Path]::GetFileName($absolute).StartsWith($script:QualificationPrefix, [StringComparison]::Ordinal)) {
    throw "refusing to remove a path outside the fixed qualification temp scope"
  }
  if (Test-Path -LiteralPath $absolute) {
    Remove-Item -Force -Recurse -LiteralPath $absolute
  }
}

if (-not [string]::IsNullOrWhiteSpace($GenerateCanaryOnlyPath)) {
  if ($KeepArtifacts -or -not [string]::IsNullOrWhiteSpace($EvidencePath)) {
    throw "GenerateCanaryOnlyPath cannot be combined with KeepArtifacts or EvidencePath"
  }

  $destination = [IO.Path]::GetFullPath($GenerateCanaryOnlyPath)
  if (-not $destination.EndsWith(".pdf", [StringComparison]::OrdinalIgnoreCase)) {
    throw "GenerateCanaryOnlyPath must name a PDF"
  }
  if ([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)) {
    throw "GenerateCanaryOnlyPath destination must not already exist"
  }
  $parent = [IO.Path]::GetDirectoryName($destination)
  [void](Assert-FixedLocalPath -LiteralPath $parent -Description "canary destination parent" -Directory)
  if (-not [string]::Equals([IO.Path]::GetFileName($destination), "qualification-canary.pdf", [StringComparison]::Ordinal)) {
    throw "GenerateCanaryOnlyPath filename must be qualification-canary.pdf"
  }

  New-FixedSyntheticScanPdf -Destination $destination
  Assert-SyntheticScanPdf -LiteralPath $destination
  [pscustomobject]@{
    schemaVersion = 1
    kind = "lawyer-assistance-local-mineru-synthetic-canary"
    pageCount = 3
    expectedEntryCount = 24
  } | ConvertTo-Json -Compress
  return
}

$mineru = Resolve-CommandDescriptor -Candidate $MineruCommand -Description "MinerU command"
$nvidiaSmi = Resolve-CommandDescriptor -Candidate $NvidiaSmiCommand -Description "nvidia-smi command"
$programFilesPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$programFilesPath = Assert-FixedLocalPath -LiteralPath $programFilesPath -Description "Program Files directory" -Directory
$configSha256 = $null
$configPath = $null
if (-not [string]::IsNullOrWhiteSpace($MineruToolsConfigPath)) {
  $configPath = Assert-FixedLocalPath -LiteralPath $MineruToolsConfigPath -Description "MinerU tools config"
  $configSha256 = Get-Sha256Hex -LiteralPath $configPath
}
$modelManifestSha256 = $null
if (-not [string]::IsNullOrWhiteSpace($ModelManifestPath)) {
  $manifest = Assert-FixedLocalPath -LiteralPath $ModelManifestPath -Description "model manifest"
  $modelManifestSha256 = Get-Sha256Hex -LiteralPath $manifest
}

$runId = [Guid]::NewGuid().ToString("N")
$jobRoot = Join-Path ([IO.Path]::GetTempPath()) ($script:QualificationPrefix + $runId)
$inputPath = Join-Path $jobRoot "input.pdf"
$outputRoot = Join-Path $jobRoot "output"
$runtimeRoot = Join-Path $jobRoot "runtime"
$evidenceJson = $null

try {
  [void][IO.Directory]::CreateDirectory($jobRoot)
  [void](Assert-FixedLocalPath -LiteralPath $jobRoot -Description "qualification job directory" -Directory)
  [void][IO.Directory]::CreateDirectory($outputRoot)
  [void][IO.Directory]::CreateDirectory($runtimeRoot)
  foreach ($directory in @("temp", "cache", "hf", "paddle", "matplotlib", "modelscope")) {
    [void][IO.Directory]::CreateDirectory((Join-Path $runtimeRoot $directory))
  }

  New-FixedSyntheticScanPdf -Destination $inputPath
  Assert-SyntheticScanPdf -LiteralPath $inputPath

  $environment = @{
    MINERU_MODEL_SOURCE = "local"
    HF_HUB_OFFLINE = "1"
    TRANSFORMERS_OFFLINE = "1"
    HF_DATASETS_OFFLINE = "1"
    HF_HUB_DISABLE_TELEMETRY = "1"
    DO_NOT_TRACK = "1"
    NO_COLOR = "1"
    CUDA_VISIBLE_DEVICES = "0"
    NO_PROXY = "127.0.0.1,localhost,::1"
    HTTP_PROXY = "http://127.0.0.1:9"
    HTTPS_PROXY = "http://127.0.0.1:9"
    ALL_PROXY = "http://127.0.0.1:9"
    TEMP = (Join-Path $runtimeRoot "temp")
    TMP = (Join-Path $runtimeRoot "temp")
    XDG_CACHE_HOME = (Join-Path $runtimeRoot "cache")
    HF_HOME = (Join-Path $runtimeRoot "hf")
    PADDLE_HOME = (Join-Path $runtimeRoot "paddle")
    MPLCONFIGDIR = (Join-Path $runtimeRoot "matplotlib")
    MODELSCOPE_CACHE = (Join-Path $runtimeRoot "modelscope")
    USERPROFILE = $runtimeRoot
    HOME = $runtimeRoot
    ProgramFiles = $programFilesPath
    PIP_NO_INDEX = "1"
    PYTHONNOUSERSITE = "1"
    PYTHONSAFEPATH = "1"
  }
  if ($null -ne $configPath) {
    $environment.MINERU_TOOLS_CONFIG_JSON = $configPath
  }

  $mineruResult = Invoke-SanitizedProcess `
    -Descriptor $mineru `
    -Arguments @(
      "-p", $inputPath,
      "-o", $outputRoot,
      "-m", $script:ExpectedMethod,
      "-b", $script:ExpectedBackend,
      "-l", $script:ExpectedLanguage
    ) `
    -Environment $environment `
    -WorkingDirectory $jobRoot `
    -TimeoutMilliseconds ($TimeoutSeconds * 1000)
  if ($mineruResult.ExitCode -ne 0) {
    throw "MinerU did not exit successfully (exit code $($mineruResult.ExitCode)); diagnostic text was discarded"
  }

  $outputStats = Assert-SafeTree -Root $outputRoot -MaxFiles 128 -MaxBytes 512MB
  $verification = Assert-MineruOutput -OutputRoot $outputRoot
  $jobStats = Assert-SafeTree -Root $jobRoot -MaxFiles 512 -MaxBytes 1GB
  $topLevelNames = @(Get-ChildItem -Force -LiteralPath $jobRoot | ForEach-Object { $_.Name })
  foreach ($name in $topLevelNames) {
    if ($name -cnotin @("input.pdf", "output", "runtime")) {
      throw "qualification process created an unexpected top-level artifact"
    }
  }
  $gpus = @(Get-GpuMetadata -Descriptor $nvidiaSmi -Environment $environment -WorkingDirectory $jobRoot)

  $evidence = [ordered]@{
    schemaVersion = 1
    runId = $runId
    completedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
    qualified = $true
    scope = "fixed_synthetic_canary_only"
    safety = [ordered]@{
      acceptsUserCaseInput = $false
      generatedImageOnlyPdf = $true
      localModelSourceForced = $true
      huggingFaceAndTransformersOfflineForced = $true
      invalidOutboundProxyForced = $true
      loopbackApiMayStart = $true
      networkIsolationEnforced = $false
      networkIsolationReason = "environment flags and invalid proxies are not an OS-level outbound block"
      appAutoEnableAuthorized = $false
      productionCaseOcrAuthorized = $false
    }
    invocation = [ordered]@{
      profile = "mineru -p <generated-three-page-canary> -o <isolated-output> -m ocr -b pipeline -l ch"
      method = $script:ExpectedMethod
      backend = $script:ExpectedBackend
      language = $script:ExpectedLanguage
      cudaVisibleDevices = "0"
      exitCode = $mineruResult.ExitCode
      durationMs = $mineruResult.DurationMs
    }
    mineru = [ordered]@{
      version = $verification.Version
      commandSha256 = $mineru.CommandSha256
      launcherSha256 = $mineru.LauncherSha256
      toolsConfigSha256 = $configSha256
      modelManifestSha256 = $modelManifestSha256
      modelManifestProvided = ($null -ne $modelManifestSha256)
      modelManifestTrustEstablished = $false
    }
    gpu = [ordered]@{
      nvidiaSmiSha256 = $nvidiaSmi.CommandSha256
      selectedCudaDevice = 0
      devices = $gpus
    }
    hashes = [ordered]@{
      scriptSha256 = Get-Sha256Hex -LiteralPath $PSCommandPath
      generatedInputSha256 = Get-Sha256Hex -LiteralPath $inputPath
      expectedTextSha256 = Get-TextSha256Hex -Value (@($script:ExpectedPages | ForEach-Object { $_.Lines }) -join "`n")
      contentListSha256 = Get-Sha256Hex -LiteralPath $verification.ContentPath
      middleSha256 = Get-Sha256Hex -LiteralPath $verification.MiddlePath
    }
    verification = [ordered]@{
      outputResolvedWithinIsolatedRoot = $true
      pageCount = $verification.PageCount
      pageIndices = @($verification.PageIndices)
      pageSize = @($verification.PageWidth, $verification.PageHeight)
      exactVerifiedTextEntries = $verification.TextEntryCount
      outputFileCount = $outputStats.FileCount
      outputBytes = $outputStats.TotalBytes
      isolatedJobFileCount = $jobStats.FileCount
      isolatedJobBytes = $jobStats.TotalBytes
    }
    retention = [ordered]@{
      keepArtifactsRequested = [bool]$KeepArtifacts
      artifactsRetained = [bool]$KeepArtifacts
      artifactPathRecorded = $false
    }
  }
  $evidenceJson = $evidence | ConvertTo-Json -Depth 10
} finally {
  if (-not $KeepArtifacts) {
    Remove-QualificationJob -JobRoot $jobRoot
  } else {
    Write-Verbose "Qualification artifacts were retained by explicit request; their path is intentionally omitted from evidence."
  }
}

if (-not [string]::IsNullOrWhiteSpace($EvidencePath)) {
  Write-EvidenceFile -LiteralPath $EvidencePath -Json $evidenceJson
}
$evidenceJson
