# netdoc_docker.ps1
# Docker management menu for the NetDoc project
# Run as Administrator: powershell -ExecutionPolicy Bypass -File netdoc_docker.ps1

$ProjectDir  = $PSScriptRoot
$ComposeFile = Join-Path $ProjectDir "docker-compose.yml"

$Services = @(
    @{ Name = "netdoc-postgres";   Port = 15432; Label = "PostgreSQL" }
    @{ Name = "netdoc-nginx";      Port = 80;    Label = "nginx (Panel + Grafana)" }
    @{ Name = "netdoc-api";        Port = 8000;  Label = "API (FastAPI)" }
    @{ Name = "netdoc-web";        Port = 0;     Label = "Web Panel (internal)" }
    @{ Name = "netdoc-grafana";    Port = 0;     Label = "Grafana (internal)" }
    @{ Name = "netdoc-prometheus"; Port = 9090;  Label = "Prometheus" }
    @{ Name = "netdoc-loki";       Port = 3100;  Label = "Loki (logs)" }
    @{ Name = "netdoc-promtail";   Port = 0;     Label = "Promtail" }
    @{ Name = "netdoc-clickhouse"; Port = 8123;  Label = "ClickHouse (syslog DB)" }
    @{ Name = "netdoc-rsyslog";    Port = 514;   Label = "rsyslog (syslog receiver)" }
    @{ Name = "netdoc-vector";     Port = 8688;  Label = "Vector (syslog pipeline)" }
    @{ Name = "netdoc-ping";       Port = 8001;  Label = "Ping Worker" }
    @{ Name = "netdoc-snmp";       Port = 8002;  Label = "SNMP Worker" }
    @{ Name = "netdoc-cred";       Port = 8003;  Label = "Cred Worker" }
    @{ Name = "netdoc-vuln";       Port = 8004;  Label = "Vuln Worker" }
    @{ Name = "netdoc-internet";   Port = 0;     Label = "Internet Worker (internal)" }
    @{ Name = "netdoc-community";  Port = 0;     Label = "Community Worker (internal)" }
)

$WatchdogScript = Join-Path $ProjectDir "netdoc_watchdog.ps1"
$WatchdogTask   = "NetDoc Watchdog"

# Returns list of netdoc container names (running AND stopped)
function Get-NetDocContainers {
    $names = docker ps -a --filter "name=netdoc" --format "{{.Names}}" 2>&1
    return @($names | Where-Object { $_ -ne "" })
}

# Returns list of currently running (Up) netdoc container names
function Get-NetDocRunning {
    $names = docker ps --filter "name=netdoc" --format "{{.Names}}" 2>&1
    return @($names | Where-Object { $_ -ne "" })
}

function Write-Header {
    Clear-Host
    $line = "=" * 60
    Write-Host $line -ForegroundColor Cyan
    Write-Host "   NetDoc - Docker Management" -ForegroundColor Cyan
    Write-Host "   Project: $ProjectDir" -ForegroundColor DarkGray
    Write-Host $line -ForegroundColor Cyan
    Write-Host ""
}

function Write-Menu {
    Write-Host "  [1] Start Docker (build + start)" -ForegroundColor Green
    Write-Host "       Builds Docker images from scratch and starts all containers:" -ForegroundColor DarkGray
    Write-Host "       nginx, postgres, api, web, grafana, prometheus, ping/snmp/cred/vuln worker" -ForegroundColor DarkGray
    Write-Host "       Use on first run or after code changes." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [2] Stop Docker (stop)" -ForegroundColor Yellow
    Write-Host "       Stops all containers without deleting data." -ForegroundColor DarkGray
    Write-Host "       Database and configuration are preserved (Docker volumes)." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [3] Restart Docker" -ForegroundColor Yellow
    Write-Host "       Restarts running containers (without rebuilding images)." -ForegroundColor DarkGray
    Write-Host "       Useful when a container is hung or stopped responding." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [4] Container status" -ForegroundColor Cyan
    Write-Host "       Shows the list of containers with their current state (Up/Exit)." -ForegroundColor DarkGray
    Write-Host "       Green = running, Red = stopped or error." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [5] Tests - check if everything works" -ForegroundColor Cyan
    Write-Host "       Checks TCP and HTTP port availability for all services:" -ForegroundColor DarkGray
    Write-Host "       nginx (:80), API (:8000), Grafana (/grafana), Prometheus." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [6] Container logs..." -ForegroundColor DarkGray
    Write-Host "       Displays the last 50 lines of logs for the selected container." -ForegroundColor DarkGray
    Write-Host "       Useful for diagnosing errors and tracking worker activity." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [7] WIPE everything (containers, images, volumes, cache)" -ForegroundColor Red
    Write-Host "       WARNING: IRREVERSIBLE! Deletes the database and all Docker data." -ForegroundColor Red
    Write-Host "       Use only for a full project reset. After wiping, use [1]." -ForegroundColor DarkGray
    Write-Host ""
    $wdStatus = try { (Get-ScheduledTask -TaskName $WatchdogTask -ErrorAction Stop).State } catch { "not installed" }
    $wdColor  = if ($wdStatus -eq "Ready") { "Green" } elseif ($wdStatus -eq "not installed") { "DarkGray" } else { "Yellow" }

    $relayTask  = Get-ScheduledTask -TaskName "NetDocSyslogRelay" -ErrorAction SilentlyContinue
    $relayPid   = Test-Path (Join-Path $ProjectDir "syslog_relay.pid")
    $relayStatus = if ($relayTask -and $relayPid) { "Running" } elseif ($relayTask) { "Installed (stopped)" } else { "not installed" }
    $relayColor  = if ($relayStatus -eq "Running") { "Green" } elseif ($relayStatus -eq "not installed") { "DarkGray" } else { "Yellow" }

    $bcastTask   = Get-ScheduledTask -TaskName "NetDocBroadcast" -ErrorAction SilentlyContinue
    $bcastPid    = Test-Path (Join-Path $ProjectDir "broadcast.pid")
    $bcastStatus = if ($bcastTask -and $bcastPid) { "Running" } elseif ($bcastTask) { "Installed (stopped)" } else { "not installed" }
    $bcastColor  = if ($bcastStatus -eq "Running") { "Green" } elseif ($bcastStatus -eq "not installed") { "DarkGray" } else { "Yellow" }

    Write-Host "  [8] Watchdog / Host Services" -ForegroundColor $wdColor
    Write-Host ("       Watchdog     [{0}]" -f $wdStatus) -ForegroundColor $wdColor
    Write-Host ("       Syslog Relay [{0}]  — preserves real device IPs in syslog" -f $relayStatus) -ForegroundColor $relayColor
    Write-Host ("       Broadcast    [{0}]  — multicast/broadcast discovery" -f $bcastStatus) -ForegroundColor $bcastColor
    Write-Host ""
    Write-Host "  [Q] Quit" -ForegroundColor DarkGray
    Write-Host ""
}

function Test-Port {
    param([int]$Port, [string]$HostName = "127.0.0.1", [int]$TimeoutMs = 2000)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $ar  = $tcp.BeginConnect($HostName, $Port, $null, $null)
        $ok  = $ar.AsyncWaitHandle.WaitOne($TimeoutMs)
        $tcp.Close()
        return $ok
    } catch { return $false }
}

function Invoke-Status {
    Write-Host ""
    Write-Host "  Containers:" -ForegroundColor Cyan
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
        Write-Host "  No NetDoc containers found (Docker wiped or not yet started)." -ForegroundColor DarkGray
    }
    Write-Host ""
}

function Invoke-Tests {
    Write-Host ""
    Write-Host "  Testing ports and API..." -ForegroundColor Cyan
    Write-Host ""

    $allOk = $true

    foreach ($svc in $Services) {
        if ($svc.Port -eq 0) {
            Write-Host ("  [--] {0,-20} (internal — no host port)" -f $svc.Label) -ForegroundColor DarkGray
            continue
        }
        $open  = Test-Port -Port $svc.Port
        $icon  = if ($open) { "[OK]" } else { "[!!]" }
        $color = if ($open) { "Green" } else { "Red" }
        $ln    = "  {0,-5} {1,-20} port {2}" -f $icon, $svc.Label, $svc.Port
        Write-Host $ln -ForegroundColor $color
        if (-not $open) { $allOk = $false }
    }

    Write-Host ""
    Write-Host "  Checking HTTP endpoints..." -ForegroundColor Cyan
    Write-Host ""

    $endpoints = @(
        @{ Url = "http://localhost/";                          Label = "Web Panel (nginx)"  }
        @{ Url = "http://localhost:8000/api/devices/?limit=1"; Label = "API /api/devices"  }
        @{ Url = "http://localhost/grafana/";                  Label = "Grafana /"          }
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
            Write-Host ("  [!!] {0,-32} no response" -f $ep.Label) -ForegroundColor Red
            $allOk = $false
        }
    }

    Write-Host ""
    if ($allOk) {
        Write-Host "  Everything is working correctly!" -ForegroundColor Green
    } else {
        Write-Host "  Some services are not responding. Check logs: option [6]" -ForegroundColor Yellow
    }
    Write-Host ""
}

function Connect-LabNetwork {
    # Connects workers to the lab network if lab is running
    $labRunning = docker ps --filter "name=netdoc-lab-" --format "{{.Names}}" 2>&1
    if ($labRunning) {
        Write-Host "  Connecting workers to lab network (netdoc_lab)..." -ForegroundColor Cyan
        foreach ($w in @("netdoc-ping", "netdoc-snmp", "netdoc-cred", "netdoc-vuln")) {
            $out = docker network connect netdoc_lab $w 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "    OK: $w connected to netdoc_lab" -ForegroundColor Green
            } else {
                # May already be connected — that is the normal state
                if ($out -match "already exists") {
                    Write-Host "    OK: $w already in netdoc_lab" -ForegroundColor DarkGray
                }
            }
        }
    } else {
        Write-Host "  Lab is not running (lab-* containers are stopped)." -ForegroundColor DarkGray
        Write-Host "  Start lab from the panel: Settings -> Lab Environment -> Start" -ForegroundColor DarkGray
    }
    Write-Host ""
}

function Invoke-Start {
    Write-Host ""
    Write-Host "  Building and starting containers..." -ForegroundColor Green
    Write-Host ""
    Set-Location $ProjectDir
    docker compose -f $ComposeFile up -d --build
    Write-Host ""
    Write-Host "  Waiting for services to be ready (30s)..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 30
    Connect-LabNetwork
    Invoke-Tests
}

function Invoke-Stop {
    Write-Host ""
    $containers = Get-NetDocContainers
    if ($containers.Count -eq 0) {
        Write-Host "  No containers to stop." -ForegroundColor DarkGray
        Write-Host "  Docker has been wiped. Use option [1] to start the project." -ForegroundColor DarkGray
        Write-Host ""
        return
    }
    Write-Host "  Stopping containers..." -ForegroundColor Yellow
    Set-Location $ProjectDir
    docker compose -f $ComposeFile down
    Write-Host ""
    Write-Host "  Containers stopped. Database data is preserved." -ForegroundColor Yellow
    Write-Host ""
}

function Invoke-Restart {
    Write-Host ""
    $running = Get-NetDocRunning
    if ($running.Count -eq 0) {
        $all = Get-NetDocContainers
        if ($all.Count -eq 0) {
            Write-Host "  No NetDoc containers found." -ForegroundColor Yellow
            Write-Host "  Docker has been wiped. Use option [1] to build and start the project." -ForegroundColor Yellow
        } else {
            Write-Host "  Containers exist but are not running." -ForegroundColor Yellow
            Write-Host "  Use option [1] to start (without rebuild it will be faster)." -ForegroundColor Yellow
        }
        Write-Host ""
        return
    }
    Write-Host "  Restarting containers ($($running.Count) running)..." -ForegroundColor Yellow
    Set-Location $ProjectDir
    docker compose -f $ComposeFile restart
    Write-Host ""
    Write-Host "  Waiting for services to be ready (20s)..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 20
    Invoke-Tests
}

function Invoke-Prune {
    Write-Host ""
    Write-Host "  WARNING: This will delete EVERYTHING:" -ForegroundColor Red
    Write-Host "    - all containers (including stopped ones)" -ForegroundColor Red
    Write-Host "    - all Docker images"                       -ForegroundColor Red
    Write-Host "    - all volumes (including the database!)"   -ForegroundColor Red
    Write-Host "    - build cache"                             -ForegroundColor Red
    Write-Host ""
    $confirm = Read-Host "  Type YES to confirm"
    if ($confirm -ne "YES") {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        Write-Host ""
        return
    }
    Write-Host ""
    Write-Host "  Stopping containers..." -ForegroundColor Yellow
    Set-Location $ProjectDir
    docker compose -f $ComposeFile down --volumes 2>&1 | Out-Null
    Write-Host "  Wiping Docker (images, volumes, cache)..." -ForegroundColor Yellow
    docker system prune --all --volumes --force
    Write-Host ""
    Write-Host "  Docker wiped. Use option [1] to rebuild from scratch." -ForegroundColor Green
    Write-Host ""
}

function Invoke-Logs {
    Write-Host ""
    $all = Get-NetDocContainers
    if ($all.Count -eq 0) {
        Write-Host "  No NetDoc containers. Use option [1] to start the project." -ForegroundColor Yellow
        Write-Host ""
        return
    }
    Write-Host "  Select a container:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $Services.Count; $i++) {
        $name   = $Services[$i].Name
        $exists = $all -contains $name
        $suffix = if ($exists) { "" } else { " [missing]" }
        Write-Host ("  [{0}] {1}{2}" -f ($i + 1), $Services[$i].Label, $suffix)
    }
    Write-Host ""
    $choice = Read-Host "  Number"
    $idx    = [int]$choice - 1
    if ($idx -ge 0 -and $idx -lt $Services.Count) {
        $name = $Services[$idx].Name
        if (-not ($all -contains $name)) {
            Write-Host ""
            Write-Host "  Container '$name' does not exist. Use [1] to start it." -ForegroundColor Red
            Write-Host ""
            return
        }
        Write-Host ""
        Write-Host "  Last 50 lines of logs: $name" -ForegroundColor Cyan
        Write-Host ""
        docker logs --tail 50 $name
    } else {
        Write-Host "  Invalid selection." -ForegroundColor Red
    }
    Write-Host ""
}

function Invoke-Watchdog {
    Write-Host ""
    $task = Get-ScheduledTask -TaskName $WatchdogTask -ErrorAction SilentlyContinue

    if (-not $task) {
        Write-Host "  Watchdog: NOT installed" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [1] Install watchdog (requires Administrator privileges)"
        Write-Host "  [2] Run one check cycle manually"
        Write-Host "  [X] Cancel"
        Write-Host ""
        $sub = Read-Host "  Select"
        switch ($sub.ToUpper()) {
            "1" {
                if (-not (Test-Path $WatchdogScript)) {
                    Write-Host "  File not found: $WatchdogScript" -ForegroundColor Red
                    Write-Host ""
                    return
                }
                Write-Host "  Registering Task Scheduler task..." -ForegroundColor Cyan
                $action    = New-ScheduledTaskAction -Execute "powershell.exe" `
                                 -Argument "-NonInteractive -ExecutionPolicy Bypass -File `"$WatchdogScript`" -Quiet"
                $trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date) `
                                 -RepetitionInterval (New-TimeSpan -Minutes 5) `
                                 -RepetitionDuration (New-TimeSpan -Days 3650)
                $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 4) `
                                 -MultipleInstances IgnoreNew -StartWhenAvailable `
                                 -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries
                $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
                $t = Register-ScheduledTask -TaskName $WatchdogTask -Action $action `
                         -Trigger $trigger -Settings $settings -Principal $principal `
                         -Description "NetDoc: auto-repair Docker containers every 5 minutes." -Force
                if ($t) {
                    Write-Host "  OK: Watchdog installed and active." -ForegroundColor Green
                } else {
                    Write-Host "  ERROR: Registration failed — check permissions." -ForegroundColor Red
                }
            }
            "2" {
                Write-Host "  Running one watchdog cycle..." -ForegroundColor Cyan
                & powershell.exe -ExecutionPolicy Bypass -File $WatchdogScript
            }
        }
    } else {
        Write-Host "  Watchdog: INSTALLED  [status: $($task.State)]" -ForegroundColor Green
        $info = Get-ScheduledTaskInfo -TaskName $WatchdogTask -ErrorAction SilentlyContinue
        if ($info) {
            Write-Host "  Last run time  : $($info.LastRunTime)" -ForegroundColor DarkGray
            Write-Host "  Last task result: $($info.LastTaskResult)" -ForegroundColor DarkGray
            Write-Host "  Next run time  : $($info.NextRunTime)" -ForegroundColor DarkGray
        }
        $logFile = Join-Path $ProjectDir "logs\watchdog.log"
        if (Test-Path $logFile) {
            Write-Host ""
            Write-Host "  Recent log entries:" -ForegroundColor Cyan
            Get-Content $logFile -Tail 8 | ForEach-Object {
                $col = if ($_ -match "WARN") { "Yellow" } elseif ($_ -match "ERROR") { "Red" } else { "DarkGray" }
                Write-Host "    $_" -ForegroundColor $col
            }
        }
        Write-Host ""
        Write-Host "  [1] Run one cycle manually"
        Write-Host "  [2] Uninstall watchdog"
        Write-Host "  [X] Cancel"
        Write-Host ""
        $sub = Read-Host "  Select"
        switch ($sub.ToUpper()) {
            "1" { & powershell.exe -ExecutionPolicy Bypass -File $WatchdogScript }
            "2" {
                Unregister-ScheduledTask -TaskName $WatchdogTask -Confirm:$false
                Write-Host "  Watchdog uninstalled." -ForegroundColor Yellow
            }
        }
    }
    Write-Host ""
}

# --- Main loop ---
while ($true) {
    Write-Header
    Invoke-Status
    Write-Menu

    $choice = Read-Host "  Select an option"

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
        default { Write-Host "  Unknown option." -ForegroundColor Red }
    }

    Write-Host "  Press Enter to return to the menu..." -ForegroundColor DarkGray
    Read-Host | Out-Null
}
