# netdoc-uninstall.ps1
# Zatrzymuje i usuwa NetDoc z systemu Windows.
#
# Tryby:
#   [1] Zatrzymaj kontenery — zachowuje dane i konfiguracje
#   [2] Pelne odinstalowanie — usuwa kontenery, voluminy, zadania Task Scheduler
#   [3] Anuluj
#
# Uzycie:
#   Kliknij dwukrotnie netdoc-uninstall.bat
#   LUB: powershell -ExecutionPolicy Bypass -File netdoc-uninstall.ps1

#Requires -Version 5.1

$ErrorActionPreference = "Continue"
$ProjectDir = $PSScriptRoot

# ── Log debugowania ────────────────────────────────────────────────────────────

$LogTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogFile      = Join-Path $ProjectDir "netdoc-uninstall-debug-$LogTimestamp.log"
Start-Transcript -Path $LogFile -Append | Out-Null

# ── Funkcje pomocnicze ────────────────────────────────────────────────────────

function Write-Header {
    Clear-Host
    Write-Host ""
    Write-Host "  ================================================" -ForegroundColor Red
    Write-Host "   NetDoc — Odinstalowywanie / Zatrzymanie" -ForegroundColor Red
    Write-Host "  ================================================" -ForegroundColor Red
    Write-Host ""
}

function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "  >> $msg" -ForegroundColor Cyan
}

function Write-OK([string]$msg) {
    Write-Host "     [OK] $msg" -ForegroundColor Green
}

function Write-Warn([string]$msg) {
    Write-Host "     [!!] $msg" -ForegroundColor Yellow
}

function Write-Fail([string]$msg) {
    Write-Host "     [BLAD] $msg" -ForegroundColor Red
}

function Write-Info([string]$msg) {
    Write-Host "           $msg" -ForegroundColor DarkGray
}

function Show-Pause([string]$msg = "Nacisnij Enter aby kontynuowac...") {
    Write-Host ""
    Write-Host "  $msg" -ForegroundColor DarkGray
    Read-Host | Out-Null
}

# ── Start ─────────────────────────────────────────────────────────────────────

Write-Header
Write-Host "  Katalog projektu: $ProjectDir" -ForegroundColor DarkGray
Write-Host "  Log:              $LogFile" -ForegroundColor DarkGray
Write-Host ""

# ── Sprawdz dostepnosc Docker ─────────────────────────────────────────────────

$dockerAvailable = $false
$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if ($dockerCmd) {
    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $dockerAvailable = $true
    }
}

if (-not $dockerAvailable) {
    Write-Warn "Docker Desktop nie jest uruchomiony lub niedostepny."
    Write-Info "Kontenery nie zostaną zatrzymane (nie ma czym)."
    Write-Info "Mozesz recznie zatrzymac Docker Desktop z ikony w zasobniku systemowym."
    Write-Host ""
}

# ── Menu wyboru trybu ─────────────────────────────────────────────────────────

Write-Host "  Co chcesz zrobic?" -ForegroundColor White
Write-Host ""
Write-Host "  [1]  Zatrzymaj kontenery (dane i konfiguracja zostaja)" -ForegroundColor Cyan
Write-Host "  [2]  Pelne odinstalowanie (kontenery + voluminy + Task Scheduler)" -ForegroundColor Red
Write-Host "  [3]  Anuluj — wyjdz bez zmian" -ForegroundColor DarkGray
Write-Host ""
$choice = Read-Host "  Wybor"

switch ($choice) {
    "1" {
        $mode = "stop"
        Write-Host ""
        Write-Host "  Tryb: Zatrzymanie kontenerow" -ForegroundColor Cyan
    }
    "2" {
        $mode = "full"
        Write-Host ""
        Write-Host "  Tryb: Pelne odinstalowanie" -ForegroundColor Red
        Write-Host ""
        Write-Warn "UWAGA: Usuniecie woluminow spowoduje utrate WSZYSTKICH danych"
        Write-Info "(baza PostgreSQL, metryki Prometheus, dashboardy Grafana)"
        Write-Host ""
        $confirm = Read-Host "  Wpisz USUN aby potwierdzic"
        if ($confirm -ne "USUN") {
            Write-Warn "Potwierdzenie nieudane. Anulowanie."
            Stop-Transcript | Out-Null
            exit 0
        }
    }
    default {
        Write-Info "Anulowano. Bez zmian."
        Stop-Transcript | Out-Null
        exit 0
    }
}

# ── Zatrzymaj kontenery ───────────────────────────────────────────────────────

Write-Step "Zatrzymuje kontenery NetDoc..."

if ($dockerAvailable) {
    Set-Location $ProjectDir

    if ($mode -eq "stop") {
        # Tylko zatrzymanie — nie usuwaj
        docker compose stop 2>&1 | Out-Host
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Kontenery zatrzymane. Dane zachowane."
            Write-Info "Aby uruchomic ponownie: docker compose start"
            Write-Info "  lub uruchom netdoc-setup.bat"
        } else {
            Write-Warn "Zatrzymanie zakonczone z ostrzezeniem (kod: $LASTEXITCODE)"
        }

    } elseif ($mode -eq "full") {
        # Pelne usuniecie z woluminami
        Write-Info "Uruchamiam: docker compose down --volumes --remove-orphans"
        docker compose down --volumes --remove-orphans 2>&1 | Out-Host

        if ($LASTEXITCODE -eq 0) {
            Write-OK "Kontenery i voluminy usuniete."
        } else {
            Write-Warn "docker compose down zakonczyl sie z bledem (kod: $LASTEXITCODE)"
            Write-Info "Mozesz recznie sprawdzic: docker ps -a | findstr netdoc"
        }

        # Obrazy Docker (opcjonalnie)
        Write-Host ""
        $removeImages = Read-Host "  Usunac obrazy Docker NetDoc (zaoszczedzi ~2-3 GB)? [T/N]"
        if ($removeImages -eq "T" -or $removeImages -eq "t") {
            Write-Info "Szukam obrazow powiazanych z projektem netdoc..."

            # Obrazy zbudowane przez docker compose (oznaczone labelem projektu)
            $imageIds = @(
                docker images --filter "label=com.docker.compose.project=netdoc" `
                              --format "{{.ID}}" 2>&1 |
                Where-Object { $_ -ne "" }
            )
            # Takze obrazy z "netdoc" w nazwie repozytorium
            $imageIds += @(
                docker images --filter "reference=*netdoc*" --format "{{.ID}}" 2>&1 |
                Where-Object { $_ -ne "" }
            )
            $imageIds = $imageIds | Sort-Object -Unique

            if ($imageIds.Count -gt 0) {
                foreach ($id in $imageIds) {
                    $name = docker inspect --format "{{.RepoTags}}" $id 2>&1
                    Write-Info "Usuwam obraz: $name ($id)"
                    docker rmi $id --force 2>&1 | Out-Null
                }
                Write-OK "$($imageIds.Count) obraz(y) usunieto."
            } else {
                Write-Info "Nie znaleziono obrazow NetDoc do usuniecia."
            }
        }
    }
} else {
    Write-Warn "Docker niedostepny — pomijam zatrzymanie kontenerow."
}

# ── Task Scheduler (tylko pelne odinstalowanie) ───────────────────────────────

if ($mode -eq "full") {
    Write-Step "Usuwam zadania z Task Scheduler..."

    $tasks = @(
        "NetDocScanner",
        "NetDoc Watchdog"
    )

    foreach ($taskName in $tasks) {
        $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existing) {
            # Zatrzymaj jesli dziala
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            # Usun
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-OK "Usunieto zadanie: $taskName"
        } else {
            Write-Info "Zadanie '$taskName' nie bylo zarejestrowane — pomijam."
        }
    }

    # ── Plik PID skanera ──────────────────────────────────────────────────────

    Write-Step "Usuwam pliki runtime..."

    $pidFile = Join-Path $ProjectDir "scanner.pid"
    if (Test-Path $pidFile) {
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
        Write-OK "Usunieto: scanner.pid"
    }

    # ── .env (opcjonalnie) ────────────────────────────────────────────────────

    Write-Host ""
    $removeEnv = Read-Host "  Usunac plik .env (konfiguracja z haslami)? [T/N]"
    if ($removeEnv -eq "T" -or $removeEnv -eq "t") {
        $envFile = Join-Path $ProjectDir ".env"
        if (Test-Path $envFile) {
            Remove-Item $envFile -Force -ErrorAction SilentlyContinue
            Write-OK "Usunieto: .env"
        } else {
            Write-Info ".env nie istnieje — pomijam."
        }
    }

    # ── Logi instalatora (skrypt setup i uninstall) ───────────────────────────

    Write-Host ""
    $removeLogs = Read-Host "  Usunac logi debugowania instalatora (netdoc-setup-debug-*.log)? [T/N]"
    if ($removeLogs -eq "T" -or $removeLogs -eq "t") {
        # Wyklucz aktualny log tego skryptu (jest jeszcze otwarty przez Transcript)
        $logFiles = Get-ChildItem $ProjectDir -Filter "netdoc-*-debug-*.log" -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -ne $LogFile }
        if ($logFiles) {
            $logFiles | ForEach-Object {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                Write-Info "Usunieto: $($_.Name)"
            }
            Write-OK "Logi instalatora usuniete."
        } else {
            Write-Info "Brak logow instalatora do usuniecia."
        }
    }
}

# ── Podsumowanie ─────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  ================================================" -ForegroundColor Cyan

if ($mode -eq "stop") {
    Write-Host "   Kontenery NetDoc zatrzymane." -ForegroundColor Green
    Write-Host "  ================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "   Dane (baza, metryki) sa ZACHOWANE." -ForegroundColor White
    Write-Host "   Aby wznowic prace: uruchom netdoc-setup.bat" -ForegroundColor DarkGray
} else {
    Write-Host "   NetDoc zostal odinstalowany." -ForegroundColor Green
    Write-Host "  ================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "   Co zostalo zachowane (do recznego usuniecia):" -ForegroundColor White
    Write-Host "   - Katalog projektu: $ProjectDir" -ForegroundColor DarkGray
    Write-Host "   - Python i pip packages (zainstalowane globalnie)" -ForegroundColor DarkGray
    Write-Host "   - Docker Desktop (zainstalowany systemowo)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "   Aby odinstalowac Docker Desktop:" -ForegroundColor DarkGray
    Write-Host "   Ustawienia -> Aplikacje -> Docker Desktop -> Odinstaluj" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  Log debugowania: $LogFile" -ForegroundColor DarkGray
Write-Host ""

Stop-Transcript | Out-Null

Show-Pause "Nacisnij Enter aby zamknac..."
