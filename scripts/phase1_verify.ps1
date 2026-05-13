$ErrorActionPreference = "Stop"

Write-Host "=== SwiftProbe Phase 1 Verification ===" -ForegroundColor Cyan

$venvPy = "D:\PROJECTS\swiftProbe\venv311\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
  Write-Host "FAIL: venv311 not found. Create it first." -ForegroundColor Red
  exit 1
}

Write-Host "Python:" -ForegroundColor Yellow
& $venvPy --version

Write-Host "" 
Write-Host "Import checks:" -ForegroundColor Yellow
$imports = @("flask", "supabase", "dotenv", "volatility3", "Evtx", "requests", "pydantic", "pytsk3")
foreach ($m in $imports) {
  & $venvPy -c "import $m" 2>$null
  if ($LASTEXITCODE -eq 0) {
    Write-Host ("PASS: " + $m) -ForegroundColor Green
  } else {
    Write-Host ("FAIL: " + $m) -ForegroundColor Red
  }
}

Write-Host ""
Write-Host "Sleuth Kit PATH checks:" -ForegroundColor Yellow
$fls = (where.exe fls 2>$null)
$tsk = (where.exe tsk_loaddb 2>$null)
if ($fls) {
  Write-Host "PASS: fls found" -ForegroundColor Green
  $fls
} else {
  Write-Host "FAIL: fls not found in PATH" -ForegroundColor Red
}
if ($tsk) {
  Write-Host "PASS: tsk_loaddb found" -ForegroundColor Green
  $tsk
} else {
  Write-Host "FAIL: tsk_loaddb not found in PATH" -ForegroundColor Red
}

Write-Host ""
Write-Host "Digital Corpora directories:" -ForegroundColor Yellow
$dirs = @(
  "D:\PROJECTS\swiftProbe\evidence\digitalcorpora\raw_images",
  "D:\PROJECTS\swiftProbe\evidence\digitalcorpora\memory_dumps",
  "D:\PROJECTS\swiftProbe\evidence\digitalcorpora\evtx_logs",
  "D:\PROJECTS\swiftProbe\evidence\digitalcorpora\downloads",
  "D:\PROJECTS\swiftProbe\evidence\digitalcorpora\notes"
)
foreach ($d in $dirs) {
  if (Test-Path $d) {
    Write-Host ("PASS: " + $d) -ForegroundColor Green
  } else {
    Write-Host ("FAIL: " + $d) -ForegroundColor Red
  }
}

Write-Host ""
Write-Host "If pytsk3 fails, run scripts\phase1_admin_fix.ps1 in an elevated terminal, then rerun this verification." -ForegroundColor Yellow
