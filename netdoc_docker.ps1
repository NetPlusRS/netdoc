# netdoc_docker.ps1
# Menu zarzadzania Docker dla projektu NetDoc
# Uruchom jako Administrator: powershell -ExecutionPolicy Bypass -File netdoc_docker.ps1

$ProjectDir  = $PSScriptRoot
$ComposeFile = Join-Path $ProjectDir "docker-compose.yml"

$Services = @(
    @{ Name = "netdoc-postgres";   Port = 15432; Label = "PostgreSQL" }
    @{ Name = "netdoc-api";        Port = 8000;  Label = "API (FastAPI)" }
    @{ Name = "netdoc-web";        Port = 5000;  Label = "Panel Web" }
    @{ Name = "netdoc-grafana";    Port = 3000;  Label = "Grafana" }
    @{ Name = "netdoc-prometheus"; Port = 9090;  Label = "Prometheus" }
    @{ Name = "netdoc-loki";       Port = 3100;  Label = "Loki (logi)" }
    @{ Name = "netdoc-promtail";   Port = 0;     Label = "Promtail" }
    @{ Name = "netdoc-ping";       Port = 8001;  Label = "Ping Worker" }
    @{ Name = "netdoc-snmp";       Port = 8002;  Label = "SNMP Worker" }
    @{ Name = "netdoc-cred";       Port = 8003;  Label = "Cred Worker" }
    @{ Name = "netdoc-vuln";       Port = 8004;  Label = "Vuln Worker" }
)

$WatchdogScript = Join-Path $ProjectDir "netdoc_watchdog.ps1"
$WatchdogTask   = "NetDoc Watchdog"

# Zwraca liste nazw kontenerow netdoc (dzialajacych I zatrzymanych)
function Get-NetDocContainers {
    $names = docker ps -a --filter "name=netdoc" --format "{{.Names}}" 2>&1
    return @($names | Where-Object { $_ -ne "" })
}

# Zwraca liste nazw kontenerow netdoc aktualnie dzialajacych (Up)
function Get-NetDocRunning {
    $names = docker ps --filter "name=netdoc" --format "{{.Names}}" 2>&1
    return @($names | Where-Object { $_ -ne "" })
}

function Write-Header {
    Clear-Host
    $line = "=" * 60
    Write-Host $line -ForegroundColor Cyan
    Write-Host "   NetDoc - Docker Management" -ForegroundColor Cyan
    Write-Host "   Projekt: $ProjectDir" -ForegroundColor DarkGray
    Write-Host $line -ForegroundColor Cyan
    Write-Host ""
}

function Write-Menu {
    Write-Host "  [1] Uruchom Docker (build + start)" -ForegroundColor Green
    Write-Host "       Buduje obrazy Docker od nowa i uruchamia wszystkie 9 kontenerow:" -ForegroundColor DarkGray
    Write-Host "       postgres, api, web, grafana, prometheus, ping/snmp/cred/vuln worker" -ForegroundColor DarkGray
    Write-Host "       Uzyj przy pierwszym uruchomieniu lub po zmianie kodu." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [2] Zatrzymaj Docker (stop)" -ForegroundColor Yellow
    Write-Host "       Zatrzymuje wszystkie kontenery bez kasowania danych." -ForegroundColor DarkGray
    Write-Host "       Baza danych i konfiguracje sa zachowane (woluminy Docker)." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [3] Restart Docker" -ForegroundColor Yellow
    Write-Host "       Restartuje dzialajace kontenery (bez przebudowy obrazow)." -ForegroundColor DarkGray
    Write-Host "       Przydatny gdy kontener zawisl lub przestal odpowiadac." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [4] Status kontenerow" -ForegroundColor Cyan
    Write-Host "       Pokazuje liste kontenerow z ich aktualnym stanem (Up/Exit)." -ForegroundColor DarkGray
    Write-Host "       Zielony = dziala, Czerwony = zatrzymany lub blad." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [5] Testy - sprawdz czy wszystko dziala" -ForegroundColor Cyan
    Write-Host "       Sprawdza dostepnosc portow TCP i HTTP dla wszystkich serwisow:" -ForegroundColor DarkGray
    Write-Host "       API, Panel Web, Grafana, Prometheus oraz polaczenie z baza danych." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [6] Logi kontenera..." -ForegroundColor DarkGray
    Write-Host "       Wyswietla ostatnie 50 linii logow wybranego kontenera." -ForegroundColor DarkGray
    Write-Host "       Przydatne do diagnostyki bledow i sledzenia aktywnosci workerow." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [7] WYCZYSC wszystko (kontenery, obrazy, woluminy, cache)" -ForegroundColor Red
    Write-Host "       UWAGA: NIEODWRACALNE! Kasuje baze danych i wszystkie dane Docker." -ForegroundColor Red
    Write-Host "       Uzyj tylko przy pelnym resecie projektu. Po czyszczeniu uzyj [1]." -ForegroundColor DarkGray
    Write-Host ""
    $wdStatus = try { (Get-ScheduledTask -TaskName $WatchdogTask -ErrorAction Stop).State } catch { "brak" }
    $wdColor  = if ($wdStatus -eq "Ready") { "Green" } elseif ($wdStatus -eq "brak") { "DarkGray" } else { "Yellow" }
    Write-Host "  [8] Watchdog auto-heal  [stan: $wdStatus]" -ForegroundColor $wdColor
    Write-Host "       Usluga co 5 min sprawdza stan kontenerow i uruchamia brakujace." -ForegroundColor DarkGray
    Write-Host "       Radzi sobie z recznym usunieciem kontenerow lub obrazow Docker." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [Q] Wyjdz" -ForegroundColor DarkGray
    Write-Host ""
}

function Test-Port {
    param([int]$Port, [string]$Host = "127.0.0.1", [int]$TimeoutMs = 2000)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $ar  = $tcp.BeginConnect($Host, $Port, $null, $null)
        $ok  = $ar.AsyncWaitHandle.WaitOne($TimeoutMs)
        $tcp.Close()
        return $ok
    } catch { return $false }
}

function Invoke-Status {
    Write-Host ""
    Write-Host "  Kontenery:" -ForegroundColor Cyan
    $rows = docker ps -a --filter "name=netdoc" --format "  {{.Names}}`t{{.Status}}" 2>&1
    $rows = @($rows | Where-Object { $_ -ne "" })
    if ($rows.Count -gt 0) {
        foreach ($r in $rows) {
            if ($r -match "Up") {
                Write-Host $r -ForegroundColor Green
            } elseif ($r -match "Exit|Restart") {
                Write-Host $r -ForegroundColor Red
            } else {
                Write-Host $r -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Host "  Brak kontenerow NetDoc (Docker wyczyszczony lub jeszcze nie uruchomiony)." -ForegroundColor DarkGray
    }
    Write-Host ""
}

function Invoke-Tests {
    Write-Host ""
    Write-Host "  Testowanie portow i API..." -ForegroundColor Cyan
    Write-Host ""

    $allOk = $true

    foreach ($svc in $Services) {
        $open  = Test-Port -Port $svc.Port
        $icon  = if ($open) { "[OK]" } else { "[!!]" }
        $color = if ($open) { "Green" } else { "Red" }
        $ln    = "  {0,-5} {1,-20} port {2}" -f $icon, $svc.Label, $svc.Port
        Write-Host $ln -ForegroundColor $color
        if (-not $open) { $allOk = $false }
    }

    Write-Host ""
    Write-Host "  Sprawdzam HTTP endpoints..." -ForegroundColor Cyan
    Write-Host ""

    $endpoints = @(
        @{ Url = "http://localhost:8000/api/devices/?limit=1"; Label = "API /api/devices"  }
        @{ Url = "http://localhost:5000/";                     Label = "Panel Web /"        }
        @{ Url = "http://localhost:3000/";                     Label = "Grafana /"          }
        @{ Url = "http://localhost:9090/-/ready";              Label = "Prometheus /ready"  }
    )

    foreach ($ep in $endpoints) {
        try {
            $r    = Invoke-WebRequest -Uri $ep.Url -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            $ok   = ($r.StatusCode -ge 200 -and $r.StatusCode -lt 400)
            $icon = if ($ok) { "[OK]" } else { "[!!]" }
            $col  = if ($ok) { "Green" } else { "Yellow" }
            Write-Host ("  {0,-5} {1,-32} HTTP {2}" -f $icon, $ep.Label, $r.StatusCode) -ForegroundColor $col
        } catch {
            Write-Host ("  [!!] {0,-32} brak odpowiedzi" -f $ep.Label) -ForegroundColor Red
            $allOk = $false
        }
    }

    Write-Host ""
    if ($allOk) {
        Write-Host "  Wszystko dziala poprawnie!" -ForegroundColor Green
    } else {
        Write-Host "  Niektore serwisy nie odpowiadaja. Sprawdz logi: opcja [6]" -ForegroundColor Yellow
    }
    Write-Host ""
}

function Connect-LabNetwork {
    # Podlacza workery do sieci lab jesli lab jest uruchomiony
    $labRunning = docker ps --filter "name=lab-" --format "{{.Names}}" 2>&1
    if ($labRunning) {
        Write-Host "  Podlaczam workery do sieci lab (netdoc_lab)..." -ForegroundColor Cyan
        foreach ($w in @("netdoc-ping", "netdoc-snmp", "netdoc-cred", "netdoc-vuln")) {
            $out = docker network connect netdoc_lab $w 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "    OK: $w dolaczony do netdoc_lab" -ForegroundColor Green
            } else {
                # Moze byc juz podlaczony — to normalny stan
                if ($out -match "already exists") {
                    Write-Host "    OK: $w juz w netdoc_lab" -ForegroundColor DarkGray
                }
            }
        }
    } else {
        Write-Host "  Lab nie jest uruchomiony (kontenery lab-* sa zatrzymane)." -ForegroundColor DarkGray
        Write-Host "  Uruchom lab przez panel: Ustawienia -> Srodowisko Lab -> Start" -ForegroundColor DarkGray
    }
    Write-Host ""
}

function Invoke-Start {
    Write-Host ""
    Write-Host "  Buduje i uruchamiam kontenery..." -ForegroundColor Green
    Write-Host ""
    Set-Location $ProjectDir
    docker compose -f $ComposeFile up -d --build
    Write-Host ""
    Write-Host "  Czekam az serwisy beda gotowe (30s)..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 30
    Connect-LabNetwork
    Invoke-Tests
}

function Invoke-Stop {
    Write-Host ""
    $containers = Get-NetDocContainers
    if ($containers.Count -eq 0) {
        Write-Host "  Brak kontenerow do zatrzymania." -ForegroundColor DarkGray
        Write-Host "  Docker jest wyczyszczony. Uzyj opcji [1] aby uruchomic projekt." -ForegroundColor DarkGray
        Write-Host ""
        return
    }
    Write-Host "  Zatrzymuje kontenery..." -ForegroundColor Yellow
    Set-Location $ProjectDir
    docker compose -f $ComposeFile down
    Write-Host ""
    Write-Host "  Kontenery zatrzymane. Dane w bazie sa zachowane." -ForegroundColor Yellow
    Write-Host ""
}

function Invoke-Restart {
    Write-Host ""
    $running = Get-NetDocRunning
    if ($running.Count -eq 0) {
        $all = Get-NetDocContainers
        if ($all.Count -eq 0) {
            Write-Host "  Brak kontenerow NetDoc." -ForegroundColor Yellow
            Write-Host "  Docker jest wyczyszczony. Uzyj opcji [1] aby zbudowac i uruchomic projekt." -ForegroundColor Yellow
        } else {
            Write-Host "  Kontenery istnieja ale nie sa uruchomione." -ForegroundColor Yellow
            Write-Host "  Uzyj opcji [1] aby uruchomic (bez przebudowy trwa krocej)." -ForegroundColor Yellow
        }
        Write-Host ""
        return
    }
    Write-Host "  Restartuje kontenery ($($running.Count) dzialajacych)..." -ForegroundColor Yellow
    Set-Location $ProjectDir
    docker compose -f $ComposeFile restart
    Write-Host ""
    Write-Host "  Czekam az serwisy beda gotowe (20s)..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 20
    Invoke-Tests
}

function Invoke-Prune {
    Write-Host ""
    Write-Host "  UWAGA: To skasuje WSZYSTKO:" -ForegroundColor Red
    Write-Host "    - wszystkie kontenery (rowniez zatrzymane)" -ForegroundColor Red
    Write-Host "    - wszystkie obrazy Docker"                  -ForegroundColor Red
    Write-Host "    - wszystkie woluminy (w tym baza danych!)"  -ForegroundColor Red
    Write-Host "    - build cache"                              -ForegroundColor Red
    Write-Host ""
    $confirm = Read-Host "  Wpisz TAK zeby potwierdzic"
    if ($confirm -ne "TAK") {
        Write-Host "  Anulowano." -ForegroundColor DarkGray
        Write-Host ""
        return
    }
    Write-Host ""
    Write-Host "  Zatrzymuje kontenery..." -ForegroundColor Yellow
    Set-Location $ProjectDir
    docker compose -f $ComposeFile down --volumes 2>&1 | Out-Null
    Write-Host "  Czyszcze Docker (obrazy, woluminy, cache)..." -ForegroundColor Yellow
    docker system prune --all --volumes --force
    Write-Host ""
    Write-Host "  Docker wyczyszczony. Uzyj opcji [1] zeby zbudowac od nowa." -ForegroundColor Green
    Write-Host ""
}

function Invoke-Logs {
    Write-Host ""
    $all = Get-NetDocContainers
    if ($all.Count -eq 0) {
        Write-Host "  Brak kontenerow NetDoc. Uzyj opcji [1] aby uruchomic projekt." -ForegroundColor Yellow
        Write-Host ""
        return
    }
    Write-Host "  Wybierz kontener:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $Services.Count; $i++) {
        $name   = $Services[$i].Name
        $exists = $all -contains $name
        $suffix = if ($exists) { "" } else { " [brak]" }
        Write-Host ("  [{0}] {1}{2}" -f ($i + 1), $Services[$i].Label, $suffix)
    }
    Write-Host ""
    $choice = Read-Host "  Numer"
    $idx    = [int]$choice - 1
    if ($idx -ge 0 -and $idx -lt $Services.Count) {
        $name = $Services[$idx].Name
        if (-not ($all -contains $name)) {
            Write-Host ""
            Write-Host "  Kontener '$name' nie istnieje. Uzyj [1] aby go uruchomic." -ForegroundColor Red
            Write-Host ""
            return
        }
        Write-Host ""
        Write-Host "  Ostatnie 50 linii logow: $name" -ForegroundColor Cyan
        Write-Host ""
        docker logs --tail 50 $name
    } else {
        Write-Host "  Nieprawidlowy wybor." -ForegroundColor Red
    }
    Write-Host ""
}

function Invoke-Watchdog {
    Write-Host ""
    $task = Get-ScheduledTask -TaskName $WatchdogTask -ErrorAction SilentlyContinue

    if (-not $task) {
        Write-Host "  Watchdog: NIE zainstalowany" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [1] Zainstaluj watchdoga (wymaga uprawnien Administratora)"
        Write-Host "  [2] Uruchom recznie jeden cykl sprawdzenia"
        Write-Host "  [X] Anuluj"
        Write-Host ""
        $sub = Read-Host "  Wybierz"
        switch ($sub.ToUpper()) {
            "1" {
                if (-not (Test-Path $WatchdogScript)) {
                    Write-Host "  Brak pliku: $WatchdogScript" -ForegroundColor Red
                    Write-Host ""
                    return
                }
                Write-Host "  Rejestruje zadanie Task Scheduler..." -ForegroundColor Cyan
                $action    = New-ScheduledTaskAction -Execute "powershell.exe" `
                                 -Argument "-NonInteractive -ExecutionPolicy Bypass -File `"$WatchdogScript`" -Quiet"
                $trigger   = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)
                $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 4) `
                                 -MultipleInstances IgnoreNew -StartWhenAvailable
                $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                $t = Register-ScheduledTask -TaskName $WatchdogTask -Action $action `
                         -Trigger $trigger -Settings $settings -Principal $principal `
                         -Description "NetDoc: auto-naprawa kontenerow Docker co 5 minut." -Force
                if ($t) {
                    Write-Host "  OK: Watchdog zainstalowany i aktywny." -ForegroundColor Green
                } else {
                    Write-Host "  BLAD: Rejestracja nie powiodla sie — sprawdz uprawnienia." -ForegroundColor Red
                }
            }
            "2" {
                Write-Host "  Uruchamiam jeden cykl watchdoga..." -ForegroundColor Cyan
                & powershell.exe -ExecutionPolicy Bypass -File $WatchdogScript
            }
        }
    } else {
        Write-Host "  Watchdog: ZAINSTALOWANY  [stan: $($task.State)]" -ForegroundColor Green
        $info = Get-ScheduledTaskInfo -TaskName $WatchdogTask -ErrorAction SilentlyContinue
        if ($info) {
            Write-Host "  Ostatnie uruchomienie : $($info.LastRunTime)" -ForegroundColor DarkGray
            Write-Host "  Wynik ostatniego cyklu: $($info.LastTaskResult)" -ForegroundColor DarkGray
            Write-Host "  Nastepne uruchomienie : $($info.NextRunTime)" -ForegroundColor DarkGray
        }
        $logFile = Join-Path $ProjectDir "logs\watchdog.log"
        if (Test-Path $logFile) {
            Write-Host ""
            Write-Host "  Ostatnie wpisy logu:" -ForegroundColor Cyan
            Get-Content $logFile -Tail 8 | ForEach-Object {
                $col = if ($_ -match "WARN") { "Yellow" } elseif ($_ -match "ERROR") { "Red" } else { "DarkGray" }
                Write-Host "    $_" -ForegroundColor $col
            }
        }
        Write-Host ""
        Write-Host "  [1] Uruchom jeden cykl recznie"
        Write-Host "  [2] Odinstaluj watchdoga"
        Write-Host "  [X] Anuluj"
        Write-Host ""
        $sub = Read-Host "  Wybierz"
        switch ($sub.ToUpper()) {
            "1" { & powershell.exe -ExecutionPolicy Bypass -File $WatchdogScript }
            "2" {
                Unregister-ScheduledTask -TaskName $WatchdogTask -Confirm:$false
                Write-Host "  Watchdog odinstalowany." -ForegroundColor Yellow
            }
        }
    }
    Write-Host ""
}

# --- Petla glowna ---
while ($true) {
    Write-Header
    Invoke-Status
    Write-Menu

    $choice = Read-Host "  Wybierz opcje"

    switch ($choice.ToUpper()) {
        "1" { Invoke-Start }
        "2" { Invoke-Stop }
        "3" { Invoke-Restart }
        "4" { Invoke-Status }
        "5" { Invoke-Tests }
        "6" { Invoke-Logs }
        "7" { Invoke-Prune }
        "8" { Invoke-Watchdog }
        "Q" { Write-Host ""; exit }
        default { Write-Host "  Nieznana opcja." -ForegroundColor Red }
    }

    Write-Host "  Nacisnij Enter aby wrocic do menu..." -ForegroundColor DarkGray
    Read-Host | Out-Null
}
