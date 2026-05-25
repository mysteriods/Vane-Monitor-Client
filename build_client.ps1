<#
.SYNOPSIS
    Build Vane Monitor Client into a standalone single-file .exe
.DESCRIPTION
    Creates a clean temporary venv, installs client deps,
    runs PyInstaller in --onefile mode, and outputs to dist\.
    Run from the repo root directory.
.NOTES
    .\build_client.ps1
#>
param(
    [switch]$KeepVenv
)

$ErrorActionPreference = "Stop"

$ScriptDir = $PSScriptRoot
$SharedDir = Join-Path $ScriptDir "shared"
$VenvDir   = Join-Path $ScriptDir ".build_venv"
$DistDir   = Join-Path $ScriptDir "dist"
$BuildDir  = Join-Path $ScriptDir "build"
$ReqFile   = Join-Path $ScriptDir "requirements.txt"

Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  Vane Monitor - Client .exe builder" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

# 1) Create clean virtual environment
if (Test-Path $VenvDir) {
    Write-Host "[1/4] Removing old build venv..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $VenvDir
}

Write-Host "[1/4] Creating clean build venv..." -ForegroundColor Green
python -m venv "$VenvDir"

$PipExe    = Join-Path $VenvDir "Scripts\pip.exe"
$PythonExe = Join-Path $VenvDir "Scripts\python.exe"

if (-not (Test-Path $PipExe))    { throw "pip.exe not found at $PipExe" }
if (-not (Test-Path $PythonExe)) { throw "python.exe not found at $PythonExe" }

# 2) Install dependencies
Write-Host "[2/4] Installing dependencies..." -ForegroundColor Green
& "$PipExe" install --upgrade pip --quiet
& "$PipExe" install -r "$ReqFile" --quiet

# 3) Build single-file .exe with PyInstaller
Write-Host "[3/4] Running PyInstaller (--onefile)..." -ForegroundColor Green

$pyiArgs = @(
    "-m", "PyInstaller",
    "--name", "VaneMonitorClient",
    "--onefile",
    "--noconfirm",
    "--clean",
    "--paths", $ScriptDir,
    "--add-data", "$SharedDir;shared",
    "--hidden-import", "shared",
    "--hidden-import", "shared.config",
    "--hidden-import", "shared.log_handler",
    "--hidden-import", "shared.constants",
    "--hidden-import", "shared.monitor",
    "--hidden-import", "shared.monitor.network_tests",
    "--hidden-import", "shared.monitor.asn_lookup",
    "--distpath", $DistDir,
    "--workpath", $BuildDir,
    "--specpath", $ScriptDir,
    (Join-Path $ScriptDir "main.py")
)

& "$PythonExe" @pyiArgs

# 4) Cleanup
if (-not $KeepVenv) {
    Write-Host "[4/4] Cleaning up build venv..." -ForegroundColor Green
    Remove-Item -Recurse -Force $VenvDir
} else {
    Write-Host "[4/4] Keeping build venv at $VenvDir" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Build complete. Output: $DistDir\VaneMonitorClient.exe" -ForegroundColor Green
Write-Host "The .exe is self-contained. On first run it creates client_config.json next to itself."
Write-Host ""
