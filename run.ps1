# Windows runner: unit tests, then the live suite. Usage: .\run.ps1 [-Only hapi-r4] [-PerfN 10] [-NoWrite]
param([string[]]$Only = @(), [int]$PerfN = 20, [switch]$NoWrite)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }
& $py -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"
if ($LASTEXITCODE -ne 0) { Write-Error "need Python 3.9+"; exit 2 }

Write-Host "== unit tests"
& $py -m unittest -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$argsList = @("fhircheck.py", "--out", "results", "--perf-n", "$PerfN")
foreach ($o in $Only) { $argsList += @("--only", $o) }
if ($NoWrite) { $argsList += "--no-write" }
if (Test-Path "baseline.json") { $argsList += @("--baseline", "baseline.json") }

Write-Host "== live suite"
& $py @argsList
$status = $LASTEXITCODE

$report = "results/report-win32.md"
if ($env:GITHUB_STEP_SUMMARY -and (Test-Path $report)) { Get-Content $report | Add-Content $env:GITHUB_STEP_SUMMARY }
exit $status
