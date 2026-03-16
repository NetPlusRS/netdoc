# netdoc-uninstall.ps1
# Zatrzymuje i usuwa NetDoc z systemu Windows.
#
# Tryby:
#   [1] Zatrzymaj kontenery  -  zachowuje dane i konfiguracje
#   [2] Pelne odinstalowanie  -  wymaga wpisania USUN (z retry na literowke)
#   [3] Pelne odinstalowanie auto  -  odlicza 30s, wcisnij klawisz aby anulowac
#   [4] Anuluj
#
# Uzycie:
#   Kliknij dwukrotnie netdoc-uninstall.bat
#   LUB: powershell -ExecutionPolicy Bypass -File netdoc-uninstall.ps1

#Requires -Version 5.1

$ErrorActionPreference = "Continue"
$ProjectDir = $PSScriptRoot

# ── Self-elevation: wymagaj uprawnien Administratora ──────────────────────────
#    Unregister-ScheduledTask i Stop-ScheduledTask wymagaja admina.
#    Musi byc PRZED Start-Transcript.

$_currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $_currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "  NetDoc Uninstaller wymaga uprawnien Administratora." -ForegroundColor Yellow
    Write-Host "  Za chwile pojawi sie okno UAC  -  kliknij Tak aby kontynuowac." -ForegroundColor DarkGray
    Write-Host ""
    Start-Sleep -Seconds 2
    try {
        Start-Process powershell.exe `
            -Verb RunAs `
            -ArgumentList @("-ExecutionPolicy", "Bypass", "-File", $PSCommandPath) `
            -WorkingDirectory $ProjectDir `
            -ErrorAction Stop
    } catch {
        Write-Host ""
        Write-Host "  Odmowa uprawnien  -  UAC zostalo odrzucone lub zabronione przez polityki." -ForegroundColor Red
        Write-Host "  Sprobuj: prawy klik na netdoc-uninstall.bat -> Uruchom jako administrator" -ForegroundColor DarkGray
        Write-Host ""
        Read-Host "  Nacisnij Enter aby zamknac..."
    }
    exit
}

# ── Log debugowania ────────────────────────────────────────────────────────────

$LogDir       = Join-Path $ProjectDir "logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$LogTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogFile      = Join-Path $LogDir "netdoc-uninstall-debug-$LogTimestamp.log"
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

function Wait-WithCountdown {
    # Odlicza $Seconds sekund. Zwraca $true jesli czas uplynal (kontynuuj), $false jesli klawisz wcisniety (anuluj).
    param([int]$Seconds = 30)
    $nonInteractive = $false   # flaga: stdin niedostepny — pominac wewnetrzna petle
    for ($i = $Seconds; $i -gt 0; $i--) {
        Write-Host "`r  Odliczanie: $i s... (wcisnij dowolny klawisz aby anulowac)   " -NoNewline -ForegroundColor Yellow
        if ($nonInteractive) {
            # stdin niedostepny — nie sprawdzaj klawiszy, po prostu odliczaj
            Start-Sleep -Milliseconds 1000
            continue
        }
        $startTime = [DateTime]::Now
        while (([DateTime]::Now - $startTime).TotalMilliseconds -lt 1000) {
            try {
                if ([Console]::KeyAvailable) {
                    $null = [Console]::ReadKey($true)
                    Write-Host "`r  Odliczanie przerwane przez uzytkownika.                              " -ForegroundColor DarkGray
                    Write-Host ""
                    return $false
                }
            } catch [System.InvalidOperationException] {
                # stdin nie jest interaktywny (potok/CI/ISE) — ustaw flage, pominij kolejne sprawdzenia
                $nonInteractive = $true
                break
            } catch [System.IO.IOException] {
                $nonInteractive = $true   # uchwyt stdin niedostepny
                break
            }
            Start-Sleep -Milliseconds 100
        }
    }
    Write-Host "`r  Czas uplynal. Automatyczne kontynuowanie...                          " -ForegroundColor Green
    Write-Host ""
    return $true
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
    # Docker zainstalowany ale nie dziala — probuj go uruchomic automatycznie
    Write-Warn "Docker Desktop nie odpowiada."
    Write-Info "Probuje uruchomic Docker Desktop automatycznie..."
    $dockerDesktopExe = "${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe"
    if (Test-Path $dockerDesktopExe) {
        Start-Process $dockerDesktopExe -ErrorAction SilentlyContinue
        Write-Info "Czekam az Docker daemon bedzie gotowy (max 60s)..."
        $waited = 0
        while ($waited -lt 60) {
            Start-Sleep -Seconds 3
            $waited += 3
            docker info 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $dockerAvailable = $true
                Write-OK "Docker daemon gotowy."
                Set-Location $ProjectDir
                $runningContainers = @(docker ps --filter "name=netdoc" --filter "status=running" --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })
                $allContainers     = @(docker ps -a --filter "name=netdoc" --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })
                $netdocVolumes     = @(docker volume ls --filter "name=netdoc" --format "{{.Name}}" 2>&1 | Where-Object { $_ -ne "" })
                $imgIds  = @(docker images --filter "label=com.docker.compose.project=netdoc" --format "{{.ID}}" 2>&1 | Where-Object { $_ -ne "" })
                $imgIds += @(docker images --filter "reference=*netdoc*" --format "{{.ID}}" 2>&1 | Where-Object { $_ -ne "" })
                $netdocImages = $imgIds | Sort-Object -Unique
                break
            }
            Write-Host "." -NoNewline -ForegroundColor DarkGray
        }
        Write-Host ""
        if (-not $dockerAvailable) {
            Write-Warn "Docker nie odpowiedzial w ciagu 60s."
            Write-Warn "Kontenery i voluminy NIE zostana usuniete  -  uruchom Docker i ponow odinstalowanie."
        }
    } else {
        Write-Warn "Nie znaleziono Docker Desktop.exe  -  pomijam czyszczenie kontenerow."
    }
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
    # szukaj w logs/ (nowe polozenie) i w glownym katalogu (starsze logi)
    @(Get-ChildItem (Join-Path $ProjectDir "logs") -Filter "netdoc-*-debug-*.log" -ErrorAction SilentlyContinue) +
    @(Get-ChildItem $ProjectDir -Filter "netdoc-*-debug-*.log" -ErrorAction SilentlyContinue) |
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

Write-Host "  [2]  Pelne odinstalowanie  -  potwierdz wpisujac USUN" -ForegroundColor Red
Write-Host "  [3]  Pelne odinstalowanie automatyczne  -  odlicza 30s, wcisnij klawisz aby anulowac" -ForegroundColor Red
Write-Host "  [4]  Anuluj  -  wyjdz bez zmian" -ForegroundColor DarkGray
Write-Host ""
$choice = Read-Host "  Wybor"

$autoMode = $false   # ustawiane na $true tylko przez opcje [3]

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
        # Petla potwierdzenia — probuj dopoki uzytkownik nie wpisze USUN lub jawnie anuluje
        $confirmed = $false
        while (-not $confirmed) {
            $confirm = Read-Host "  Wpisz USUN (wielkie litery) aby potwierdzic lub N aby anulowac"
            if ($confirm -eq "USUN") {
                $confirmed = $true
            } elseif ($confirm -eq "N" -or $confirm -eq "n") {
                Write-Info "Anulowano przez uzytkownika. Bez zmian."
                Stop-Transcript | Out-Null
                exit 0
            } elseif ($confirm -eq "") {
                Write-Warn "Wcisnales Enter zamiast wpisac USUN. Wpisz USUN aby potwierdzic lub N aby anulowac."
            } else {
                Write-Warn "Nieprawidlowy wpis: '$confirm'. Wpisz dokladnie USUN (wielkie litery) lub N aby anulowac."
            }
        }
    }
    "3" {
        $mode = "full"
        $autoMode = $true
        Write-Host ""
        Write-Host "  Tryb: Pelne odinstalowanie automatyczne" -ForegroundColor Red
        Write-Host ""
        if ($netdocVolumes.Count -gt 0) {
            Write-Warn "UWAGA: Usuniecie woluminow spowoduje utrate WSZYSTKICH danych"
            Write-Info "(baza PostgreSQL, metryki Prometheus, dashboardy Grafana)"
            Write-Host ""
        }
        Write-Host "  Odinstalowanie rozpocznie sie za 30 sekund." -ForegroundColor Yellow
        Write-Host "  Wcisnij dowolny klawisz aby anulowac." -ForegroundColor DarkGray
        Write-Host ""
        $proceed = Wait-WithCountdown -Seconds 30
        if (-not $proceed) {
            Write-Info "Anulowano przez uzytkownika. Bez zmian."
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
            # Force-remove fallback — docker compose down czasem zostawia kontenery w zlym stanie
            Write-Warn "docker compose down nie usunal wszystkiego  -  force-remove..."
            $forceIds = @(docker ps -aq --filter "name=netdoc" 2>&1 | Where-Object { $_ -ne "" })
            foreach ($id in $forceIds) {
                docker rm -f $id 2>&1 | Out-Null
            }
            $forceVols = @(docker volume ls -q --filter "name=netdoc" 2>&1 | Where-Object { $_ -ne "" })
            foreach ($v in $forceVols) {
                docker volume rm $v --force 2>&1 | Out-Null
            }
            # Weryfikacja po force-remove
            $stillLeft = @(docker ps -aq --filter "name=netdoc" 2>&1 | Where-Object { $_ -ne "" })
            $volsLeft  = @(docker volume ls -q --filter "name=netdoc" 2>&1 | Where-Object { $_ -ne "" })
            if ($stillLeft.Count -eq 0 -and $volsLeft.Count -eq 0) {
                Write-OK "Weryfikacja: force-remove zakonczony  -  wszystko usuniete."
            } else {
                Write-Warn "Nie udalo sie usunac wszystkiego nawet force-remove!"
                foreach ($c in $remainingContainers) { Write-Info "  Kontener nadal istnieje: $c" }
                foreach ($v in $remainingVolumes) { Write-Info "  Volumen nadal istnieje: $v" }
            }
        }
    }

    # ── Obrazy Docker (tylko jesli istnieja) ──────────────────────────────────

    if ($dockerAvailable -and $netdocImages.Count -gt 0) {
        Write-Host ""
        Write-Host "     Obrazy Docker NetDoc ($($netdocImages.Count)) zajmuja ~2-3 GB." -ForegroundColor DarkGray
        if ($autoMode) {
            Write-Info "Tryb auto: usuwam obrazy bez pytania."
            $removeImages = "T"
        } else {
            $removeImages = Read-Host "  Usunac obrazy Docker? [T/N]"
        }
        if ($removeImages -eq "T" -or $removeImages -eq "t") {
            Write-Info "Usuwam obrazy przez 'docker compose down --rmi all'..."
            # --rmi all jest bardziej niezawodne niz reczne docker rmi po ID:
            # Docker Compose zna dokladnie ktore obrazy naleza do projektu
            docker compose down --rmi all 2>&1 | Out-Host

            # Weryfikacja: czy obrazy zniknely
            Start-Sleep -Seconds 2
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
                Write-OK "Weryfikacja: wszystkie obrazy NetDoc usuniete."
            } else {
                Write-Warn "Weryfikacja: $($remainingImages.Count) obraz(y) nadal istnieje!"
                Write-Info "Mozliwa przyczyna: obraz jest uzywany przez inny kontener."
                Write-Info "Sprobuj recznie: docker rmi --force $(docker images --filter 'reference=*netdoc*' -q)"
            }

            # Usun dangling images oznaczone jako nalezoce do netdoc (warstwy po rebuildach)
            # UWAGA: "docker image prune -f" bez filtra usunelby WSZYSTKIE dangling images systemowe.
            #        Zamiast tego recznie usuwamy tylko te z labelem projektu netdoc.
            $danglingNetdoc = @(
                docker images -f "dangling=true" -f "label=com.docker.compose.project=netdoc" `
                              --format "{{.ID}}" 2>&1 | Where-Object { $_ -ne "" }
            )
            if ($danglingNetdoc.Count -gt 0) {
                Write-Info "Czyszcze $($danglingNetdoc.Count) warstw(y) posrednie NetDoc..."
                foreach ($img in $danglingNetdoc) {
                    docker rmi -f $img 2>&1 | Out-Null
                }
                Write-OK "Warstwy posrednie NetDoc wyczyszczone."
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
        if ($autoMode) {
            Write-Info "Tryb auto: usuwam .env bez pytania."
            $removeEnv = "T"
        } else {
            $removeEnv = Read-Host "  Usunac plik .env? [T/N]"
        }
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
        if ($autoMode) {
            Write-Info "Tryb auto: usuwam logi bez pytania."
            $removeLogs = "T"
        } else {
            $removeLogs = Read-Host "  Usunac logi debugowania instalatora? [T/N]"
        }
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
