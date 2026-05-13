$ErrorActionPreference = "Stop"

Write-Host "=== SwiftProbe Phase 1 Admin Fix ===" -ForegroundColor Cyan
Write-Host "Run this script in an Administrator PowerShell." -ForegroundColor Yellow

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Write-Host "ERROR: Not running as Administrator. Right-click PowerShell and choose 'Run as Administrator'." -ForegroundColor Red
  exit 1
}

Write-Host "Installing Visual Studio Build Tools VC workload..." -ForegroundColor Yellow
winget install --id Microsoft.VisualStudio.BuildTools -e --accept-source-agreements --accept-package-agreements --override "--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"

Write-Host "Installing Sleuth Kit via Autopsy package..." -ForegroundColor Yellow
winget install --id SleuthKit.Autopsy --accept-package-agreements --accept-source-agreements

Write-Host "Attempting to add common Sleuth Kit paths to user PATH..." -ForegroundColor Yellow
$possible = @(
  "C:\Program Files\Autopsy\bin",
  "C:\Program Files\Autopsy",
  "C:\Program Files\sleuthkit\bin"
)
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
foreach ($p in $possible) {
  if ((Test-Path $p) -and ($userPath -notlike "*" + $p + "*")) {
    $userPath = $userPath + ";" + $p
  }
}
[Environment]::SetEnvironmentVariable("Path", $userPath, "User")

Write-Host "Installing pytsk3 in venv311..." -ForegroundColor Yellow
D:\PROJECTS\swiftProbe\venv311\Scripts\python.exe -m pip install --no-cache-dir pytsk3

Write-Host "Re-open terminal after PATH update, then run scripts\phase1_verify.ps1" -ForegroundColor Green
