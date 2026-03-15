# netdoc-uninstall.ps1
# Zatrzymuje i usuwa NetDoc z systemu Windows.
#
# Tryby:
#   [1] Zatrzymaj kontenery  -  zachowuje dane i konfiguracje
#   [2] Pelne odinstalowanie  -  usuwa kontenery, voluminy, zadania Task Scheduler
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
    Write-Host "   NetDoc  -  Odinstalowywanie / Zatrzymanie" -ForegroundColor Red
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

# ── Skanuj aktualny stan instalacji ──────────────────────────────────────────

Write-Step "Skanuje stan instalacji NetDoc..."

$runningContainers = @()
$allContainers     = @()
$netdocVolumes     = @()
$netdocImages      = @()

if ($dockerAvailable) {
    Set-Location $ProjectDir

    $runningContainers = @(
        docker ps --filter "name=netdoc" --filter "status=running" `
                  --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" }
    )
    $allContainers = @(
        docker ps -a --filter "name=netdoc" --format "{{.Names}}" 2>&1 |
        Where-Object { $_ -ne "" }
    )
    $netdocVolumes = @(
        docker volume ls --filter "name=netdoc" --format "{{.Name}}" 2>&1 |
        Where-Object { $_ -ne "" }
    )

    $imgIds  = @(docker images --filter "label=com.docker.compose.project=netdoc" `
                               --format "{{.ID}}" 2>&1 | Where-Object { $_ -ne "" })
    $imgIds += @(docker images --filter "reference=*netdoc*" --format "{{.ID}}" 2>&1 |
                 Where-Object { $_ -ne "" })
    $netdocImages = $imgIds | Sort-Object -Unique
} elseif (-not $dockerCmd) {
    Write-Info "Docker nie jest zainstalowany  -  pomijam skanowanie kontenerow."
} else {
    Write-Warn "Docker Desktop nie odpowiada  -  uruchom go przed odinstalowaniem."
    Write-Info "Kontenery i voluminy nie zostana sprawdzone."
}

$schedulerTaskNames = @("NetDocScanner", "NetDoc Watchdog")
$existingTasks = @(
    $schedulerTaskNames | Where-Object {
        $null -ne (Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue)
    }
)

$pidFile  = Join-Path $ProjectDir "scanner.pid"
$hasPid   = Test-Path $pidFile
$envFile  = Join-Path $ProjectDir ".env"
$hasEnv   = Test-Path $envFile
$oldLogs  = @(
    Get-ChildItem $ProjectDir -Filter "netdoc-*-debug-*.log" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -ne $LogFile }
)

# ── Podsumowanie stanu ────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  Stan instalacji NetDoc:" -ForegroundColor White
Write-Host ""

if ($allContainers.Count -gt 0) {
    $runStr = if ($runningContainers.Count -gt 0) {
        "$($runningContainers.Count) uruchomionych"
    } else {
        "wszystkie zatrzymane"
    }
    Write-Host "     Kontenery:      $($allContainers.Count) ($runStr)" -ForegroundColor Yellow
} else {
    Write-Host "     Kontenery:      brak" -ForegroundColor DarkGray
}

if ($netdocVolumes.Count -gt 0) {
    Write-Host "     Voluminy:       $($netdocVolumes.Count) (dane bazy, metryki)" -ForegroundColor Yellow
} else {
    Write-Host "     Voluminy:       brak" -ForegroundColor DarkGray
}

if ($netdocImages.Count -gt 0) {
    Write-Host "     Obrazy Docker:  $($netdocImages.Count)" -ForegroundColor Yellow
} else {
    Write-Host "     Obrazy Docker:  brak" -ForegroundColor DarkGray
}

if ($existingTasks.Count -gt 0) {
    Write-Host "     Task Scheduler: $($existingTasks -join ', ')" -ForegroundColor Yellow
} else {
    Write-Host "     Task Scheduler: brak zadan NetDoc" -ForegroundColor DarkGray
}

if ($hasEnv) {
    Write-Host "     Konfiguracja:   .env (zawiera hasla)" -ForegroundColor Yellow
} else {
    Write-Host "     Konfiguracja:   brak .env" -ForegroundColor DarkGray
}

if ($oldLogs.Count -gt 0) {
    Write-Host "     Logi:           $($oldLogs.Count) plik(ow) debug" -ForegroundColor DarkGray
} else {
    Write-Host "     Logi:           brak" -ForegroundColor DarkGray
}

Write-Host ""

# Sprawdz czy jest cokolwiek do zrobienia
$hasContainers = ($allContainers.Count -gt 0)
$hasData       = ($netdocVolumes.Count -gt 0 -or $netdocImages.Count -gt 0 -or
                  $existingTasks.Count -gt 0 -or $hasPid -or $hasEnv -or $oldLogs.Count -gt 0)

if (-not $hasContainers -and -not $hasData) {
    Write-OK "NetDoc nie jest zainstalowany lub zostal juz w pelni odinstalowany."
    Write-Info "Brak kontenerow, woluminow, zadan i plikow do usuniecia."
    Write-Host ""
    Stop-Transcript | Out-Null
    Show-Pause "Nacisnij Enter aby zamknac..."
    exit 0
}

# ── Menu wyboru trybu ─────────────────────────────────────────────────────────

Write-Host "  Co chcesz zrobic?" -ForegroundColor White
Write-Host ""

if ($hasContainers) {
    if ($runningContainers.Count -gt 0) {
        Write-Host "  [1]  Zatrzymaj kontenery (dane i konfiguracja zostaja)" -ForegroundColor Cyan
    } else {
        Write-Host "  [1]  Kontenery juz zatrzymane  -  brak akcji do wykonania" -ForegroundColor DarkGray
    }
} else {
    Write-Host "  [1]  Brak kontenerow do zatrzymania" -ForegroundColor DarkGray
}

Write-Host "  [2]  Pelne odinstalowanie (usun wszystko co znaleziono powyzej)" -ForegroundColor Red
Write-Host "  [3]  Anuluj  -  wyjdz bez zmian" -ForegroundColor DarkGray
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
        if ($netdocVolumes.Count -gt 0) {
            Write-Warn "UWAGA: Usuniecie woluminow spowoduje utrate WSZYSTKICH danych"
            Write-Info "(baza PostgreSQL, metryki Prometheus, dashboardy Grafana)"
            Write-Host ""
        }
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

# ── Zatrzymaj / usun kontenery ────────────────────────────────────────────────

if ($mode -eq "stop") {

    if (-not $dockerAvailable) {
        Write-Warn "Docker niedostepny  -  nie mozna zatrzymac kontenerow."
    } elseif ($runningContainers.Count -eq 0) {
        Write-OK "Kontenery sa juz zatrzymane  -  nic do zrobienia."
    } else {
        Write-Step "Zatrzymuje kontenery NetDoc..."
        docker compose stop 2>&1 | Out-Host
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Kontenery zatrzymane. Dane zachowane."
            Write-Info "Aby uruchomic ponownie: docker compose start"
            Write-Info "  lub uruchom netdoc-setup.bat"
        } else {
            Write-Warn "Zatrzymanie zakonczone z ostrzezeniem (kod: $LASTEXITCODE)"
        }
    }

} elseif ($mode -eq "full") {

    # ── Kontenery i voluminy ───────────────────────────────────────────────────

    if (-not $dockerAvailable) {
        Write-Warn "Docker niedostepny  -  pomijam usuwanie kontenerow i woluminow."
    } elseif (-not $hasContainers -and $netdocVolumes.Count -eq 0) {
        Write-OK "Brak kontenerow i woluminow do usuniecia."
    } else {
        Write-Step "Usuwam kontenery i voluminy NetDoc..."
        docker compose down --volumes --remove-orphans 2>&1 | Out-Host

        # Weryfikacja: sprawdz czy kontenery i voluminy faktycznie zniknely
        Start-Sleep -Seconds 2
        $remainingContainers = @(
            docker ps -a --filter "name=netdoc" --format "{{.Names}}" 2>&1 |
            Where-Object { $_ -ne "" }
        )
        $remainingVolumes = @(
            docker volume ls --filter "name=netdoc" --format "{{.Name}}" 2>&1 |
            Where-Object { $_ -ne "" }
        )

        if ($remainingContainers.Count -eq 0 -and $remainingVolumes.Count -eq 0) {
            Write-OK "Weryfikacja: kontenery i voluminy usuniete."
        } else {
            Write-Warn "Weryfikacja: nie wszystko zostalo usuniete!"
            foreach ($c in $remainingContainers) { Write-Info "  Kontener nadal istnieje: $c" }
            foreach ($v in $remainingVolumes) { Write-Info "  Volumen nadal istnieje: $v" }
            Write-Info "Sprobuj recznie: docker rm -f \$(docker ps -aq --filter name=netdoc)"
            Write-Info "               docker volume rm \$(docker volume ls -q --filter name=netdoc)"
        }
    }

    # ── Obrazy Docker (tylko jesli istnieja) ──────────────────────────────────

    if ($dockerAvailable -and $netdocImages.Count -gt 0) {
        Write-Host ""
        Write-Host "     Obrazy Docker NetDoc ($($netdocImages.Count)) zajmuja ~2-3 GB." -ForegroundColor DarkGray
        $removeImages = Read-Host "  Usunac obrazy Docker? [T/N]"
        if ($removeImages -eq "T" -or $removeImages -eq "t") {
            $removedCount = 0
            foreach ($id in $netdocImages) {
                $imgName = docker inspect --format "{{.RepoTags}}" $id 2>&1
                Write-Info "Usuwam: $imgName ($id)"
                docker rmi $id --force 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) { $removedCount++ }
            }

            # Weryfikacja: czy obrazy zniknely
            $remainingImages = @(
                docker images --filter "label=com.docker.compose.project=netdoc" `
                              --format "{{.ID}}" 2>&1 | Where-Object { $_ -ne "" }
            )
            $remainingImages += @(
                docker images --filter "reference=*netdoc*" --format "{{.ID}}" 2>&1 |
                Where-Object { $_ -ne "" }
            )
            $remainingImages = $remainingImages | Sort-Object -Unique

            if ($remainingImages.Count -eq 0) {
                Write-OK "Weryfikacja: wszystkie obrazy NetDoc usuniete ($removedCount szt.)."
            } else {
                Write-Warn "Weryfikacja: $($remainingImages.Count) obraz(y) nadal istnieje!"
                Write-Info "Mozliwa przyczyna: obraz jest uzywany przez inny kontener."
                Write-Info "Sprawdz: docker images | findstr netdoc"
            }
        }
    }

    # ── Task Scheduler ────────────────────────────────────────────────────────

    Write-Step "Usuwam zadania z Task Scheduler..."

    if ($existingTasks.Count -eq 0) {
        Write-OK "Brak zadan NetDoc w Task Scheduler  -  pomijam."
    } else {
        foreach ($taskName in $existingTasks) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

            # Weryfikacja
            $stillExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($null -eq $stillExists) {
                Write-OK "Usunieto zadanie: $taskName"
            } else {
                Write-Warn "Nie udalo sie usunac zadania: $taskName  -  sprobuj recznie w Task Scheduler"
            }
        }
    }

    # ── Plik PID skanera ──────────────────────────────────────────────────────

    if ($hasPid) {
        Write-Step "Usuwam pliki runtime..."
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $pidFile)) {
            Write-OK "Usunieto: scanner.pid"
        } else {
            Write-Warn "Nie udalo sie usunac scanner.pid  -  plik moze byc zablokowany przez proces"
        }
    }

    # ── .env (tylko jesli istnieje) ───────────────────────────────────────────

    if ($hasEnv) {
        Write-Host ""
        Write-Host "     Plik .env zawiera hasla i konfiguracje polaczenia." -ForegroundColor DarkGray
        $removeEnv = Read-Host "  Usunac plik .env? [T/N]"
        if ($removeEnv -eq "T" -or $removeEnv -eq "t") {
            Remove-Item $envFile -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $envFile)) {
                Write-OK "Usunieto: .env"
            } else {
                Write-Warn "Nie udalo sie usunac .env"
            }
        } else {
            Write-Info "Zachowano: .env"
        }
    }

    # ── Logi instalatora (tylko jesli istnieja) ───────────────────────────────

    if ($oldLogs.Count -gt 0) {
        Write-Host ""
        Write-Host "     Znaleziono $($oldLogs.Count) plik(ow) logow instalatora." -ForegroundColor DarkGray
        $removeLogs = Read-Host "  Usunac logi debugowania instalatora? [T/N]"
        if ($removeLogs -eq "T" -or $removeLogs -eq "t") {
            $removedLogs = 0
            $oldLogs | ForEach-Object {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                if (-not (Test-Path $_.FullName)) {
                    Write-Info "Usunieto: $($_.Name)"
                    $removedLogs++
                } else {
                    Write-Warn "Nie udalo sie usunac: $($_.Name)"
                }
            }
            Write-OK "Usunieto $removedLogs z $($oldLogs.Count) logow."
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
    Write-Host "   Co zostalo zachowane (do recznego usuniecia jesli chcesz):" -ForegroundColor White
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
