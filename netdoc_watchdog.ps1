# netdoc_watchdog.ps1
# NetDoc Watchdog - checks container status and starts any missing ones.
# Run every 5 min via Task Scheduler (install: option [8] in netdoc_docker.ps1).

param(
    [switch]$Quiet   # Suppresses logs when everything is OK
)

$ProjectDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ComposeFile = Join-Path $ProjectDir "docker-compose.yml"
$LogFile     = Join-Path $ProjectDir "logs\watchdog.log"
$MaxLogLines = 1000

# ── Single-instance lock — Named Mutex (released automatically when process exits) ──
$_mutex = [System.Threading.Mutex]::new($false, "Global\NetDocWatchdog")
if (-not $_mutex.WaitOne(0)) {
    # Another instance is running — silent exit (Task Scheduler fires every 5 min,
    # previous run may still be in progress on a slow machine)
    $_mutex.Dispose()
    exit 0
}

# Resolve Python — prefer .venv inside project, fall back to first python in PATH
$_venvPython = Join-Path $ProjectDir ".venv\Scripts\python.exe"
if (Test-Path $_venvPython) {
    $PythonExe = $_venvPython
} else {
    $PythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($PythonCmd) { $PythonExe = $PythonCmd.Source } else { $PythonExe = $null }
    if (-not $PythonExe) {
        $PythonCmd3 = Get-Command python3 -ErrorAction SilentlyContinue
        if ($PythonCmd3) { $PythonExe = $PythonCmd3.Source }
    }
    if (-not $PythonExe) {
        Write-Host "[ERROR] Python not found in PATH and no .venv present — watchdog cannot start processes." -ForegroundColor Red
        # Continue anyway — Docker container checks will still work
    }
}

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
    "netdoc-nginx"
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
        # ignore log write errors
    }
}

# ── Function: wait for Docker to respond (without restarting) ──────────────────
function Wait-ForDocker {
    param([int]$MaxWaitSec = 180, [int]$AlreadyWaitedSec = 0)
    $waited = $AlreadyWaitedSec
    while ($waited -lt $MaxWaitSec) {
        Start-Sleep -Seconds 10
        $waited += 10
        docker info 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Docker Desktop responding after ${waited}s — OK" "INFO"
            return $true
        }
        Write-Log "Waiting for Docker... ${waited}s/${MaxWaitSec}s" "INFO"
    }
    return $false
}

# ── Function: repair Docker Desktop ───────────────────────────────────────────
function Repair-DockerDesktop {
    Write-Log "Docker not responding — attempting Docker Desktop repair..." "WARN"

    # Step 1: Check if Docker Desktop is already starting (don't kill if recently started)
    $ddProc = Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue | Sort-Object StartTime | Select-Object -First 1
    if ($ddProc) {
        $runningSecs = [int]((Get-Date) - $ddProc.StartTime).TotalSeconds
        if ($runningSecs -lt 180) {
            Write-Log "Docker Desktop has been starting for ${runningSecs}s — waiting instead of restarting (may be a cold start)..." "WARN"
            $ok = Wait-ForDocker -MaxWaitSec 180 -AlreadyWaitedSec $runningSecs
            if ($ok) { return $true }
            Write-Log "Docker Desktop did not respond within 180s of starting — forcing restart." "WARN"
        } else {
            Write-Log "Docker Desktop has been running for ${runningSecs}s but is not responding — forcing restart." "WARN"
        }
    }

    # Step 2: Kill all Docker Desktop and backend processes
    $dockerProcs = @("Docker Desktop", "com.docker.backend", "dockerd", "com.docker.dev-envs")
    foreach ($proc in $dockerProcs) {
        $p = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($p) {
            Write-Log "Stopping: $proc (PID $($p.Id -join ','))" "WARN"
            Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
        }
    }

    Start-Sleep -Seconds 5

    # Step 3: Make sure processes are dead
    foreach ($proc in $dockerProcs) {
        $p = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($p) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }

    Start-Sleep -Seconds 3

    # Step 4: Start Docker Desktop again
    # Resolve Docker Desktop executable — prefer PATH, fall back to common install locations
    $dockerExe = $null
    $ddCmd = Get-Command "Docker Desktop" -ErrorAction SilentlyContinue
    if ($ddCmd) {
        $dockerExe = $ddCmd.Source
    } else {
        foreach ($p in @(
            "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
            "${env:ProgramFiles(x86)}\Docker\Docker\Docker Desktop.exe",
            "$env:LOCALAPPDATA\Docker\Docker Desktop.exe"
        )) {
            if (Test-Path $p) { $dockerExe = $p; break }
        }
    }
    if (-not $dockerExe) {
        Write-Log "ERROR: Docker Desktop executable not found — cannot restart Docker." "ERROR"
        return $false
    }
    if (-not (Test-Path $dockerExe)) {
        Write-Log "ERROR: Docker Desktop not found at: $dockerExe" "ERROR"
        return $false
    }

    Write-Log "Starting Docker Desktop..." "WARN"
    Start-Process -FilePath $dockerExe

    # Step 5: Wait for Docker pipe to become available (max 180s — cold start can take 2-3 min)
    $ok = Wait-ForDocker -MaxWaitSec 180

    if (-not $ok) {
        Write-Log "ERROR: Docker Desktop did not start within 180s!" "ERROR"
        return $false
    }

    # Step 6: Additional 5s for daemon to stabilize before starting containers
    Start-Sleep -Seconds 5
    return $true
}

# ── Check if Docker daemon is running — with auto-repair ───────────────────────
$dockerInfo = docker info 2>&1
if ($LASTEXITCODE -eq 0) {
    # Docker is running — nothing to do
} else {
    # Docker not responding — check if it's a temporary issue or a hang
    Write-Log "docker info returned an error: $($dockerInfo | Select-Object -First 1)" "WARN"

    # Attempt repair
    $repaired = Repair-DockerDesktop
    if (-not $repaired) {
        Write-Log "Docker repair failed — watchdog ending cycle." "ERROR"
        exit 1
    }
    Write-Log "Docker repaired successfully." "INFO"
}

# Get list of running containers
$runningNames = @(docker ps --filter "name=netdoc" --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })

# Compare with expected list
$missing = $ExpectedContainers | Where-Object { $runningNames -notcontains $_ }

if ($missing.Count -eq 0) {
    if (-not $Quiet) {
        Write-Log "All $($ExpectedContainers.Count) containers running - OK"
    }
    # Does not exit — checks lab below
} else {
    Write-Log "Missing/stopped: $($missing -join ', ')" "WARN"
    Write-Log "Starting: docker compose up -d ..." "WARN"

    # First attempt: up -d (uses existing images)
    $composeOut = docker compose -f $ComposeFile up -d 2>&1
    $composeOk  = ($LASTEXITCODE -eq 0)

    if (-not $composeOk) {
        # Image may have been deleted — try with rebuild
        Write-Log "up -d failed (missing image?) — retrying with --build ..." "WARN"
        $composeOut = docker compose -f $ComposeFile up -d --build 2>&1
        $composeOk  = ($LASTEXITCODE -eq 0)
    }

    if (-not $composeOk) {
        Write-Log "ERROR: docker compose up failed!" "ERROR"
        Write-Log ($composeOut | Out-String).Trim() "ERROR"
        exit 1
    }

    # Verify after 12s
    Start-Sleep -Seconds 12
    $nowRunning   = @(docker ps --filter "name=netdoc" --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })
    $stillMissing = $ExpectedContainers | Where-Object { $nowRunning -notcontains $_ }

    if ($stillMissing.Count -eq 0) {
        Write-Log "Repair OK - all containers running."
    } else {
        Write-Log "ERROR: still missing: $($stillMissing -join ', ')" "ERROR"
        exit 1
    }
}

# ── Scanner — monitoring lock file and run regularity ─────────────────────────
$ScannerPid  = Join-Path $ProjectDir "scanner.pid"
$TaskName    = "NetDocScanner"

# 1. Check if lock file exists but process is dead (stale lock)
if (Test-Path $ScannerPid) {
    $pidContent = Get-Content $ScannerPid -ErrorAction SilentlyContinue
    $pidValue   = [int]($pidContent -as [int])
    if ($pidValue -gt 0) {
        $proc = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
        if ($null -eq $proc) {
            Write-Log "Stale scanner.pid lock file (PID=$pidValue is dead) — removing." "WARN"
            Remove-Item $ScannerPid -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log "Scanner is running (PID=$pidValue)." "INFO"
        }
    } else {
        Write-Log "Invalid scanner.pid — removing." "WARN"
        Remove-Item $ScannerPid -Force -ErrorAction SilentlyContinue
    }
}

# 2. Check if scanner task exists — if not, re-register it
$scannerTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -eq $scannerTask) {
    Write-Log "WARN: Task Scheduler task '$TaskName' not found — registering via install_autostart.ps1..." "WARN"
    $installScript = Join-Path $ProjectDir "install_autostart.ps1"
    if (Test-Path $installScript) {
        $installOut = & powershell -ExecutionPolicy Bypass -NonInteractive -File $installScript 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "NetDocScanner: registered successfully." "INFO"
            Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            Write-Log "NetDocScanner: started after registration." "INFO"
        } else {
            Write-Log "ERROR: failed to register '$TaskName': $($installOut | Select-Object -First 2 | Out-String)" "ERROR"
        }
    } else {
        Write-Log "ERROR: $installScript not found — cannot register scanner!" "ERROR"
    }
} else {
    # Task exists — check if it ran within the last 30 min
    try {
        $taskInfo  = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
        $lastRun   = $taskInfo.LastRunTime
        $minsSince = [int]((Get-Date) - $lastRun).TotalMinutes
        if ($minsSince -gt 30) {
            Write-Log "Scanner has not run for ${minsSince} min — forcing execution." "WARN"
            if (-not (Test-Path $ScannerPid)) {
                Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                Write-Log "NetDocScanner — forced execution." "WARN"
            } else {
                Write-Log "scanner.pid exists — scan in progress, skipping forced run." "INFO"
            }
        } else {
            if (-not $Quiet) {
                Write-Log "Scanner OK — last run $minsSince min ago."
            }
        }
    } catch {
        Write-Log "Cannot read NetDocScanner task state: $_" "WARN"
    }
}

# ── Broadcast Worker — continuous listener, monitoring via broadcast.pid ──────
$BroadcastPid    = Join-Path $ProjectDir "broadcast.pid"
$BroadcastScript = Join-Path $ProjectDir "run_broadcast_worker.py"
$BroadcastTask   = "NetDocBroadcast"

# 1. Check if PID file exists but process is dead (stale lock)
if (Test-Path $BroadcastPid) {
    $pidContent = Get-Content $BroadcastPid -ErrorAction SilentlyContinue
    $pidValue   = [int]($pidContent -as [int])
    if ($pidValue -gt 0) {
        $proc = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
        if ($null -eq $proc) {
            Write-Log "Stale broadcast.pid (PID=$pidValue is dead) — removing." "WARN"
            Remove-Item $BroadcastPid -Force -ErrorAction SilentlyContinue
        } else {
            if (-not $Quiet) {
                Write-Log "Broadcast worker running (PID=$pidValue) — OK"
            }
        }
    } else {
        Write-Log "Invalid broadcast.pid — removing." "WARN"
        Remove-Item $BroadcastPid -Force -ErrorAction SilentlyContinue
    }
}

# 2. If no PID file — worker is not running, start via Task Scheduler
if (-not (Test-Path $BroadcastPid)) {
    $bcastTask = Get-ScheduledTask -TaskName $BroadcastTask -ErrorAction SilentlyContinue
    if ($null -eq $bcastTask) {
        # Register the task if missing
        Write-Log "Broadcast task '$BroadcastTask' not found — registering..." "WARN"
        $bcastAction   = New-ScheduledTaskAction `
            -Execute $PythonExe `
            -Argument "-u `"$BroadcastScript`"" `
            -WorkingDirectory $ProjectDir
        $bcastTrigger  = New-ScheduledTaskTrigger -AtLogOn
        $bcastSettings = New-ScheduledTaskSettingsSet `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 0) `
            -MultipleInstances IgnoreNew `
            -StartWhenAvailable `
            -DontStopIfGoingOnBatteries `
            -AllowStartIfOnBatteries `
            -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        $bcastPrincipal = New-ScheduledTaskPrincipal `
            -UserId $env:USERNAME `
            -LogonType Interactive `
            -RunLevel Highest
        try {
            Register-ScheduledTask `
                -TaskName $BroadcastTask `
                -Action $bcastAction `
                -Trigger $bcastTrigger `
                -Settings $bcastSettings `
                -Principal $bcastPrincipal `
                -Description "NetDoc broadcast/multicast discovery — continuous listener" `
                -ErrorAction Stop | Out-Null
            Write-Log "Broadcast task registered." "WARN"
        } catch {
            Write-Log "ERROR: cannot register '$BroadcastTask': $_" "ERROR"
        }
    }
    # Start the task (idempotent — already running → IgnoreNew)
    Write-Log "Broadcast worker not running — starting task '$BroadcastTask'..." "WARN"
    Start-ScheduledTask -TaskName $BroadcastTask -ErrorAction SilentlyContinue
    Write-Log "Broadcast worker start requested." "WARN"
}

# ── Lab environment — monitoring based on lab_monitoring_enabled setting ───────
$LabComposeFile = Join-Path $ProjectDir "docker-compose.lab.yml"

# Read lab_monitoring_enabled setting from API (fallback to 0 if API unavailable)
$labMonitoringEnabled = $false
try {
    $apiSettings = Invoke-RestMethod -Uri "http://localhost:8000/api/scan/settings" `
        -Method Get -TimeoutSec 4 -ErrorAction Stop
    $labMonitoringEnabled = ($apiSettings.lab_monitoring_enabled -eq 1)
} catch {
    Write-Log "Lab: cannot read settings from API (${_}) — skipping lab monitoring." "INFO"
}

if ($labMonitoringEnabled) {
    $labRunning = @(docker ps   --filter "name=netdoc-lab-" --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })
    $labAll     = @(docker ps -a --filter "name=netdoc-lab-" --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })

    if ($labAll.Count -eq 0) {
        # Containers have not been built yet
        Write-Log "Lab monitoring enabled, but containers do not exist — run: docker compose -f docker-compose.lab.yml up -d --build" "WARN"
    } elseif ($labRunning.Count -lt $labAll.Count) {
        # Some or all containers are stopped — start them
        $stopped = $labAll.Count - $labRunning.Count
        Write-Log "Lab: $stopped/$($labAll.Count) containers stopped — starting..." "WARN"
        if (Test-Path $LabComposeFile) {
            $labOut = docker compose -f $LabComposeFile up -d 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Lab: started successfully."
                Start-Sleep -Seconds 5
                $labRunning = @(docker ps --filter "name=netdoc-lab-" --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })
            } else {
                Write-Log "ERROR Lab: docker compose up -d failed: $($labOut | Select-Object -First 3 | Out-String)" "ERROR"
            }
        } else {
            Write-Log "WARN: $LabComposeFile not found — cannot auto-start lab." "WARN"
        }
    } else {
        if (-not $Quiet) {
            Write-Log "Lab: all $($labRunning.Count) containers running — OK"
        }
    }

    # Connect workers to netdoc_lab network (idempotent — "already exists" is OK)
    if ($labRunning.Count -gt 0) {
        foreach ($worker in @("netdoc-ping", "netdoc-snmp", "netdoc-cred", "netdoc-vuln")) {
            $out = docker network connect netdoc_lab $worker 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Lab: $worker connected to netdoc_lab"
            } elseif ($out -match "already exists") {
                # Already connected — OK, skip log
            } else {
                Write-Log "WARN Lab: failed to connect $worker to netdoc_lab: $($out | Select-Object -First 1)" "WARN"
            }
        }
    }
} else {
    if (-not $Quiet) {
        Write-Log "Lab monitoring disabled (lab_monitoring_enabled=0) — skipping lab containers."
    }
}

# Release single-instance mutex
try { $_mutex.ReleaseMutex() } catch {}
$_mutex.Dispose()
