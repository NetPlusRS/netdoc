# run_tests.ps1
# Uruchamia pytest z pauzowaniem workerów Docker które blokują bazę danych.
# Watchdog widzi kontenery jako "Up (Paused)" — nie restartuje ich.

param(
    [string[]]$TestArgs = @("tests/", "-q", "--tb=short", "--no-cov")
)

$Workers = @(
    "netdoc-cred",
    "netdoc-vuln",
    "netdoc-snmp",
    "netdoc-community",
    "netdoc-ping",
    "netdoc-internet"
)

function Write-Step { param([string]$Msg) Write-Host "[run_tests] $Msg" -ForegroundColor Cyan }
function Write-OK   { param([string]$Msg) Write-Host "[run_tests] $Msg" -ForegroundColor Green }
function Write-Err  { param([string]$Msg) Write-Host "[run_tests] $Msg" -ForegroundColor Red }

# Sprawdź które z workerów faktycznie działają (nie pausuj tych co są zatrzymane)
$RunningWorkers = @()
foreach ($c in $Workers) {
    $status = docker inspect --format "{{.State.Status}}" $c 2>$null
    if ($status -eq "running") {
        $RunningWorkers += $c
    }
}

# Pauzuj workery
if ($RunningWorkers.Count -gt 0) {
    Write-Step "Pauzowanie $($RunningWorkers.Count) workerów: $($RunningWorkers -join ', ')"
    docker pause @RunningWorkers 2>&1 | Out-Null
    Write-OK "Workery zapauzowane. Watchdog nie uruchomi ich ponownie (status: Up (Paused))."
} else {
    Write-Step "Brak działających workerów do pauzowania."
}

# Daj workery chwilę na dokończenie otwartych transakcji (max 3s)
if ($RunningWorkers.Count -gt 0) { Start-Sleep -Seconds 3 }

# Uruchom testy
Write-Step "Uruchamianie: python -m pytest $($TestArgs -join ' ')"
$ExitCode = 0
try {
    python -m pytest @TestArgs
    $ExitCode = $LASTEXITCODE
} finally {
    # Zawsze odpauzuj — nawet gdy testy crashną (blok finally)
    if ($RunningWorkers.Count -gt 0) {
        Write-Step "Odpauzowanie workerów..."
        docker unpause @RunningWorkers 2>&1 | Out-Null
        Write-OK "Workery wznowione."
    }
}

exit $ExitCode
