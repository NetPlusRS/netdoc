# netdoc_watchdog.ps1
# Watchdog NetDoc - sprawdza stan kontenerow i uruchamia brakujace.
# Uruchamiaj co 5 min przez Task Scheduler (zainstaluj: opcja [8] w netdoc_docker.ps1).

param(
    [switch]$Quiet   # Pomija logi gdy wszystko OK
)

$ProjectDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ComposeFile = Join-Path $ProjectDir "docker-compose.yml"
$LogFile     = Join-Path $ProjectDir "logs\watchdog.log"
$MaxLogLines = 1000

$ExpectedContainers = @(
    "netdoc-postgres"
    "netdoc-prometheus"
    "netdoc-loki"
    "netdoc-promtail"
    "netdoc-grafana"
    "netdoc-api"
    "netdoc-web"
    "netdoc-ping"
    "netdoc-snmp"
    "netdoc-cred"
    "netdoc-vuln"
    "netdoc-internet"
    "netdoc-community"
    "netdoc-clickhouse"
    "netdoc-rsyslog"
    "netdoc-vector"
)

function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Msg"
    if (-not ($Quiet -and $Level -eq "INFO")) {
        Write-Host $line
    }
    try {
        $logDir = Split-Path $LogFile
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
        $lines = Get-Content $LogFile -Encoding UTF8 -ErrorAction SilentlyContinue
        if ($null -ne $lines -and $lines.Count -gt $MaxLogLines) {
            $lines | Select-Object -Last ([int]($MaxLogLines / 2)) | Set-Content $LogFile -Encoding UTF8
        }
    } catch {
        # ignoruj bledy zapisu logu
    }
}

# ── Funkcja: czekaj az Docker odpowie (bez restartu) ───────────────────────────
function Wait-ForDocker {
    param([int]$MaxWaitSec = 180, [int]$AlreadyWaitedSec = 0)
    $waited = $AlreadyWaitedSec
    while ($waited -lt $MaxWaitSec) {
        Start-Sleep -Seconds 10
        $waited += 10
        $result = docker info 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Docker Desktop odpowiada po ${waited}s — OK" "INFO"
            return $true
        }
        Write-Log "Czekam na Docker... ${waited}s/${MaxWaitSec}s" "INFO"
    }
    return $false
}

# ── Funkcja: naprawa Docker Desktop ────────────────────────────────────────────
function Repair-DockerDesktop {
    Write-Log "Docker nie odpowiada — próba naprawy Docker Desktop..." "WARN"

    # Krok 1: Sprawdz czy Docker Desktop juz sie uruchamia (nie zabijaj jesli niedawno startowal)
    $ddProc = Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue | Sort-Object StartTime | Select-Object -First 1
    if ($ddProc) {
        $runningSecs = [int]((Get-Date) - $ddProc.StartTime).TotalSeconds
        if ($runningSecs -lt 180) {
            Write-Log "Docker Desktop uruchamia sie od ${runningSecs}s — czekam zamiast restartowac (moze byc cold start)..." "WARN"
            $ok = Wait-ForDocker -MaxWaitSec 180 -AlreadyWaitedSec $runningSecs
            if ($ok) { return $true }
            Write-Log "Docker Desktop nie odpowiedzial po 180s od startu — wymuszam restart." "WARN"
        } else {
            Write-Log "Docker Desktop dziala od ${runningSecs}s ale nie odpowiada — wymuszam restart." "WARN"
        }
    }

    # Krok 2: Kill wszystkich procesow Docker Desktop i backendu
    $dockerProcs = @("Docker Desktop", "com.docker.backend", "dockerd", "com.docker.dev-envs")
    foreach ($proc in $dockerProcs) {
        $p = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($p) {
            Write-Log "Zatrzymuję: $proc (PID $($p.Id -join ','))" "WARN"
            Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
        }
    }

    Start-Sleep -Seconds 5

    # Krok 3: Upewnij sie ze procesy sa martwe
    foreach ($proc in $dockerProcs) {
        $p = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($p) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }

    Start-Sleep -Seconds 3

    # Krok 4: Uruchom Docker Desktop na nowo
    $dockerExe = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    if (-not (Test-Path $dockerExe)) {
        Write-Log "BLAD: Nie znaleziono Docker Desktop w: $dockerExe" "ERROR"
        return $false
    }

    Write-Log "Uruchamiam Docker Desktop..." "WARN"
    Start-Process -FilePath $dockerExe

    # Krok 5: Czekaj az Docker pipe bedzie dostepny (max 180s — cold start moze trwac 2-3 min)
    $ok = Wait-ForDocker -MaxWaitSec 180

    if (-not $ok) {
        Write-Log "BLAD: Docker Desktop nie uruchomił sie w ciagu 180s!" "ERROR"
        return $false
    }

    # Krok 6: Dodatkowe 5s na stabilizacje daemona przed uruchomieniem kontenerow
    Start-Sleep -Seconds 5
    return $true
}

# ── Sprawdz czy Docker daemon dziala — z auto-naprawa ──────────────────────────
$dockerOk = $false
$dockerInfo = docker info 2>&1
if ($LASTEXITCODE -eq 0) {
    $dockerOk = $true
} else {
    # Docker nie odpowiada — sprawdz czy to chwilowy problem czy zawieszenie
    Write-Log "docker info zwrocil blad: $($dockerInfo | Select-Object -First 1)" "WARN"

    # Proba naprawy
    $repaired = Repair-DockerDesktop
    if (-not $repaired) {
        Write-Log "Naprawa Dockera nieudana — watchdog konczy cykl." "ERROR"
        exit 1
    }
    $dockerOk = $true
    Write-Log "Docker naprawiony pomyslnie." "INFO"
}

# Pobierz liste dzialajacych kontenerow
$runningNames = @(docker ps --filter "name=netdoc" --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })

# Porownaj z oczekiwana lista
$missing = $ExpectedContainers | Where-Object { $runningNames -notcontains $_ }

if ($missing.Count -eq 0) {
    if (-not $Quiet) {
        Write-Log "Wszystkie $($ExpectedContainers.Count) kontenerow dziala - OK"
    }
    # Nie wychodzi — sprawdza jeszcze lab ponizej
} else {
    Write-Log "Brakujace/zatrzymane: $($missing -join ', ')" "WARN"
    Write-Log "Uruchamianie: docker compose up -d ..." "WARN"

    # Pierwsza proba: up -d (uzywa istniejacych obrazow)
    $composeOut = docker compose -f $ComposeFile up -d 2>&1
    $composeOk  = ($LASTEXITCODE -eq 0)

    if (-not $composeOk) {
        # Obraz mogl zostac skasowany - proba z przebudowa
        Write-Log "up -d nie powiodlo sie (brakuje obrazu?) - proba z --build ..." "WARN"
        $composeOut = docker compose -f $ComposeFile up -d --build 2>&1
        $composeOk  = ($LASTEXITCODE -eq 0)
    }

    if (-not $composeOk) {
        Write-Log "BLAD: docker compose up nie powiodlo sie!" "ERROR"
        Write-Log ($composeOut | Out-String).Trim() "ERROR"
        exit 1
    }

    # Weryfikacja po 12s
    Start-Sleep -Seconds 12
    $nowRunning   = @(docker ps --filter "name=netdoc" --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })
    $stillMissing = $ExpectedContainers | Where-Object { $nowRunning -notcontains $_ }

    if ($stillMissing.Count -eq 0) {
        Write-Log "Naprawa OK - wszystkie kontenery dzialaja."
    } else {
        Write-Log "BLAD: nadal brakuje: $($stillMissing -join ', ')" "ERROR"
        exit 1
    }
}

# ── Skaner — pilnowanie lock file i regularnosci uruchomien ───────────────────
$ScannerPid  = Join-Path $ProjectDir "scanner.pid"
$ScannerLog  = Join-Path $ProjectDir "logs\scanner.log"
$TaskName    = "NetDocScanner"

# 1. Sprawdz czy lock file istnieje ale proces jest martwy (stale lock)
if (Test-Path $ScannerPid) {
    $pidContent = Get-Content $ScannerPid -ErrorAction SilentlyContinue
    $pidValue   = [int]($pidContent -as [int])
    if ($pidValue -gt 0) {
        $proc = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
        if ($null -eq $proc) {
            Write-Log "Stale lock file scanner.pid (PID=$pidValue martwy) — usuwam." "WARN"
            Remove-Item $ScannerPid -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log "Skaner dziala (PID=$pidValue)." "INFO"
        }
    } else {
        Write-Log "Nieprawidlowy scanner.pid — usuwam." "WARN"
        Remove-Item $ScannerPid -Force -ErrorAction SilentlyContinue
    }
}

# 2. Sprawdz czy task skanera istnieje — jesli nie, zarejestuj go ponownie
$scannerTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -eq $scannerTask) {
    Write-Log "WARN: Brak zadania Task Scheduler '$TaskName' — rejestruje przez install_autostart.ps1..." "WARN"
    $installScript = Join-Path $ProjectDir "install_autostart.ps1"
    if (Test-Path $installScript) {
        $installOut = & powershell -ExecutionPolicy Bypass -NonInteractive -File $installScript 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "NetDocScanner: zarejestrowano pomyslnie." "INFO"
            Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            Write-Log "NetDocScanner: uruchomiono po rejestracji." "INFO"
        } else {
            Write-Log "BLAD: nie udalo sie zarejestrowac '$TaskName': $($installOut | Select-Object -First 2 | Out-String)" "ERROR"
        }
    } else {
        Write-Log "BLAD: brak $installScript — nie mozna zarejestrowac skanera!" "ERROR"
    }
} else {
    # Task istnieje — sprawdz czy uruchamial sie w ciagu ostatnich 30 min
    try {
        $taskInfo  = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
        $lastRun   = $taskInfo.LastRunTime
        $minsSince = [int]((Get-Date) - $lastRun).TotalMinutes
        if ($minsSince -gt 30) {
            Write-Log "Skaner nie uruchamial sie od ${minsSince} min — wymuszam uruchomienie." "WARN"
            if (-not (Test-Path $ScannerPid)) {
                Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                Write-Log "NetDocScanner — wymuszone uruchomienie." "WARN"
            } else {
                Write-Log "scanner.pid istnieje — skan w toku, pomijam wymuszenie." "INFO"
            }
        } else {
            if (-not $Quiet) {
                Write-Log "Skaner OK — ostatnie uruchomienie $minsSince min temu."
            }
        }
    } catch {
        Write-Log "Nie mozna odczytac stanu NetDocScanner task: $_" "WARN"
    }
}

# ── Lab environment — pilnowanie wg ustawienia lab_monitoring_enabled ──────────
$LabComposeFile = Join-Path $ProjectDir "docker-compose.lab.yml"

# Odczytaj ustawienie lab_monitoring_enabled z API (z fallbackiem na 0 gdy API niedostepne)
$labMonitoringEnabled = $false
try {
    $apiSettings = Invoke-RestMethod -Uri "http://localhost:8000/api/scan/settings" `
        -Method Get -TimeoutSec 4 -ErrorAction Stop
    $labMonitoringEnabled = ($apiSettings.lab_monitoring_enabled -eq 1)
} catch {
    Write-Log "Lab: nie mozna odczytac ustawien z API (${_}) — pomijam monitorowanie lab." "INFO"
}

if ($labMonitoringEnabled) {
    $labRunning = @(docker ps   --filter "name=netdoc-lab-" --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })
    $labAll     = @(docker ps -a --filter "name=netdoc-lab-" --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })

    if ($labAll.Count -eq 0) {
        # Kontenery nie zostaly jeszcze zbudowane
        Write-Log "Lab monitoring wlaczony, ale kontenery nie istnieja — uruchom: docker compose -f docker-compose.lab.yml up -d --build" "WARN"
    } elseif ($labRunning.Count -lt $labAll.Count) {
        # Czesc lub wszystkie kontenery zatrzymane — uruchom
        $stopped = $labAll.Count - $labRunning.Count
        Write-Log "Lab: $stopped/$($labAll.Count) kontenerow zatrzymanych — uruchamianie..." "WARN"
        if (Test-Path $LabComposeFile) {
            $labOut = docker compose -f $LabComposeFile up -d 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Lab: uruchomiono pomyslnie."
                Start-Sleep -Seconds 5
                $labRunning = @(docker ps --filter "name=netdoc-lab-" --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })
            } else {
                Write-Log "BLAD Lab: docker compose up -d nieudane: $($labOut | Select-Object -First 3 | Out-String)" "ERROR"
            }
        } else {
            Write-Log "WARN: brak pliku $LabComposeFile — nie mozna auto-startowac lab." "WARN"
        }
    } else {
        if (-not $Quiet) {
            Write-Log "Lab: wszystkie $($labRunning.Count) kontenerow dziala — OK"
        }
    }

    # Polacz workery z siecia netdoc_lab (idempotentne — "already exists" jest OK)
    if ($labRunning.Count -gt 0) {
        foreach ($worker in @("netdoc-ping", "netdoc-snmp", "netdoc-cred", "netdoc-vuln")) {
            $out = docker network connect netdoc_lab $worker 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Lab: $worker dolaczony do netdoc_lab"
            } elseif ($out -match "already exists") {
                # Juz podlaczony — OK, pomijamy log
            } else {
                Write-Log "WARN Lab: nie udalo sie polaczyc $worker z netdoc_lab: $($out | Select-Object -First 1)" "WARN"
            }
        }
    }
} else {
    if (-not $Quiet) {
        Write-Log "Lab monitoring wylaczony (lab_monitoring_enabled=0) — pomijam kontenery lab."
    }
}
