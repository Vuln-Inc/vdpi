# vdpi installer for Windows (x86_64)
# Usage: irm https://vuln-inc.github.io/vdpi/install.ps1 | iex
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = 'Vuln-Inc/vdpi'
$Asset = 'vdpi-windows-x86_64.zip'
$BaseUrl = "https://github.com/$Repo/releases/latest/download"
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("vdpi-install-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

try {
    $ArchivePath = Join-Path $TempDir $Asset
    $SumsPath = Join-Path $TempDir 'SHA256SUMS.txt'

    Write-Host "Downloading $Asset..."
    Invoke-WebRequest -Uri "$BaseUrl/$Asset" -OutFile $ArchivePath -UseBasicParsing
    Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS.txt" -OutFile $SumsPath -UseBasicParsing

    $Expected = $null
    foreach ($line in Get-Content -Path $SumsPath) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$') {
            $name = Split-Path -Leaf $Matches[2]
            if ($name -eq $Asset) {
                $Expected = $Matches[1].ToLowerInvariant()
                break
            }
        }
    }
    if (-not $Expected) {
        throw "Checksum for $Asset not found in SHA256SUMS.txt"
    }

    $Actual = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Actual -ne $Expected) {
        throw "SHA-256 mismatch for $Asset (expected $Expected, got $Actual)"
    }
    Write-Host 'SHA-256 verified.'

    $ExtractDir = Join-Path $TempDir 'extract'
    Expand-Archive -Path $ArchivePath -DestinationPath $ExtractDir -Force
    $ExtractedExe = Join-Path $ExtractDir 'vdpi.exe'
    if (-not (Test-Path $ExtractedExe)) {
        throw 'vdpi.exe was not found inside the downloaded archive'
    }

    $InstallDir = if ($env:VDPI_INSTALL_DIR) { $env:VDPI_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'vdpi\bin' }
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $TargetExe = Join-Path $InstallDir 'vdpi.exe'
    Copy-Item -Path $ExtractedExe -Destination $TargetExe -Force
    foreach ($Companion in @('wintun.dll', 'WINTUN-LICENSE.txt')) {
        $ExtractedCompanion = Join-Path $ExtractDir $Companion
        if (Test-Path $ExtractedCompanion) {
            Copy-Item -Path $ExtractedCompanion -Destination (Join-Path $InstallDir $Companion) -Force
        }
    }

    $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $UserPath) { $UserPath = '' }
    $PathEntries = $UserPath -split ';' | Where-Object { $_ -ne '' }
    if ($PathEntries -notcontains $InstallDir) {
        $NewPath = if ($UserPath.TrimEnd(';')) { "$($UserPath.TrimEnd(';'));$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable('Path', $NewPath, 'User')
        $env:Path = "$InstallDir;$env:Path"
    }

    Write-Host "Installed vdpi to $TargetExe"
    Write-Host "Run 'vdpi install' for automatic background service startup, or 'vdpi start' for the live dashboard."
} finally {
    if (Test-Path $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
