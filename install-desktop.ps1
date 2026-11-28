$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = 'Vuln-Inc/vdpi'
$Asset = 'vdpi-desktop-windows-x86_64-portable.zip'
$InstallDir = Join-Path $env:LOCALAPPDATA 'vdpi-desktop'

Write-Host 'Resolving latest vdpi Desktop release...'
$Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'User-Agent' = 'vdpi-installer' }
$Tag = $Release.tag_name
if (-not $Tag) { throw 'Could not determine latest release tag.' }

$BaseUrl = "https://github.com/$Repo/releases/download/$Tag"
$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("vdpi-desktop-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

try {
    $ZipPath = Join-Path $TmpDir $Asset
    $SumsPath = Join-Path $TmpDir 'SHA256SUMS.txt'

    Write-Host "Downloading vdpi Desktop $Tag..."
    Invoke-WebRequest -Uri "$BaseUrl/$Asset" -OutFile $ZipPath -UseBasicParsing
    Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS.txt" -OutFile $SumsPath -UseBasicParsing

    $ExpectedLine = Get-Content $SumsPath | Where-Object { $_ -match ("\s+" + [regex]::Escape($Asset) + '$') } | Select-Object -First 1
    if (-not $ExpectedLine) { throw "Checksum entry for $Asset not found in SHA256SUMS.txt." }
    $ExpectedHash = ($ExpectedLine -split '\s+')[0].ToLowerInvariant()
    $ActualHash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualHash -ne $ExpectedHash) {
        throw "SHA-256 verification failed for $Asset (expected $ExpectedHash, got $ActualHash)."
    }
    Write-Host "Verified SHA-256 ($ActualHash)"

    Get-Process -Name 'vdpi-desktop' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Expand-Archive -Path $ZipPath -DestinationPath $InstallDir -Force

    # Create Start Menu shortcut
    $StartMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
    $ShortcutPath = Join-Path $StartMenu 'vdpi Desktop.lnk'
    $Wsh = New-Object -ComObject WScript.Shell
    $Sc = $Wsh.CreateShortcut($ShortcutPath)
    $Sc.TargetPath = Join-Path $InstallDir 'vdpi-desktop.exe'
    $Sc.WorkingDirectory = $InstallDir
    $Sc.Description = 'vdpi Desktop - Self-healing anti-DPI engine'
    $Sc.Save()

    Write-Host ""
    Write-Host "Installed vdpi Desktop $Tag to $InstallDir"
    Write-Host "Start Menu shortcut created: $ShortcutPath"
    Write-Host "Launching vdpi Desktop..."
    Start-Process -FilePath (Join-Path $InstallDir 'vdpi-desktop.exe') -WorkingDirectory $InstallDir
} finally {
    Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
