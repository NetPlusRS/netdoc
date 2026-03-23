# netdoc-uninstall.ps1
# Stops and removes NetDoc from the Windows system.
#
# Modes:
#   [1] Stop containers  -  keeps data and configuration
#   [2] Full uninstall  -  requires typing REMOVE (with retry on typo)
#   [3] Full uninstall auto  -  counts down 3s, press any key to cancel
#   [4] Cancel
#
# Usage:
#   Double-click netdoc-uninstall.bat
#   OR: powershell -ExecutionPolicy Bypass -File netdoc-uninstall.ps1

#Requires -Version 5.1

$ErrorActionPreference = "Continue"
$ProjectDir = $PSScriptRoot

# ── Self-elevation: require Administrator privileges ──────────────────────────
#    Unregister-ScheduledTask and Stop-ScheduledTask require admin.
#    Must be BEFORE Start-Transcript.

$_currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $_currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "  NetDoc Uninstaller requires Administrator privileges." -ForegroundColor Yellow
    Write-Host "  A UAC prompt will appear shortly  -  click Yes to continue." -ForegroundColor DarkGray
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
        Write-Host "  Permission denied  -  UAC was rejected or blocked by policy." -ForegroundColor Red
        Write-Host "  Try: right-click netdoc-uninstall.bat -> Run as administrator" -ForegroundColor DarkGray
        Write-Host ""
        Read-Host "  Press Enter to close..."
    }
    exit
}

# ── Debug log ─────────────────────────────────────────────────────────────────

$LogDir       = Join-Path $ProjectDir "logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$LogTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogFile      = Join-Path $LogDir "netdoc-uninstall-debug-$LogTimestamp.log"
Start-Transcript -Path $LogFile -Append | Out-Null

# ── Helper functions ──────────────────────────────────────────────────────────

function Write-Header {
    Clear-Host
    Write-Host ""
    Write-Host "  ================================================" -ForegroundColor Red
    Write-Host "   NetDoc  -  Uninstall / Stop" -ForegroundColor Red
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
    Write-Host "     [ERROR] $msg" -ForegroundColor Red
}

function Write-Info([string]$msg) {
    Write-Host "           $msg" -ForegroundColor DarkGray
}

function Show-Pause([string]$msg = "Press Enter to continue...") {
    Write-Host ""
    Write-Host "  $msg" -ForegroundColor DarkGray
    Read-Host | Out-Null
}

function Wait-WithCountdown {
    # Counts down $Seconds seconds. Returns $true if time elapsed (continue), $false if key pressed (cancel).
    param([int]$Seconds = 3)
    $nonInteractive = $false   # flag: stdin unavailable — skip inner loop
    for ($i = $Seconds; $i -gt 0; $i--) {
        Write-Host "`r  Countdown: $i s... (press any key to cancel)   " -NoNewline -ForegroundColor Yellow
        if ($nonInteractive) {
            # stdin unavailable — do not check keys, just count down
            Start-Sleep -Milliseconds 1000
            continue
        }
        $startTime = [DateTime]::Now
        while (([DateTime]::Now - $startTime).TotalMilliseconds -lt 1000) {
            try {
                if ([Console]::KeyAvailable) {
                    $null = [Console]::ReadKey($true)
                    Write-Host "`r  Countdown cancelled by user.                                        " -ForegroundColor DarkGray
                    Write-Host ""
                    return $false
                }
            } catch [System.InvalidOperationException] {
                # stdin is not interactive (pipe/CI/ISE) — set flag, skip subsequent checks
                $nonInteractive = $true
                break
            } catch [System.IO.IOException] {
                $nonInteractive = $true   # stdin handle unavailable
                break
            }
            Start-Sleep -Milliseconds 100
        }
    }
    Write-Host "`r  Time elapsed. Continuing automatically...                            " -ForegroundColor Green
    Write-Host ""
    return $true
}

# ── Start ─────────────────────────────────────────────────────────────────────

Write-Header
Write-Host "  Project directory: $ProjectDir" -ForegroundColor DarkGray
Write-Host "  Log:               $LogFile" -ForegroundColor DarkGray
Write-Host ""

# ── Check Docker availability ─────────────────────────────────────────────────

$dockerAvailable = $false
$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if ($dockerCmd) {
    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $dockerAvailable = $true
    }
}

# ── Scan current installation state ──────────────────────────────────────────

Write-Step "Scanning NetDoc installation state..."

$runningContainers = @()
$allContainers     = @()
$labAllContainers  = @()
$netdocVolumes     = @()
$netdocImages      = @()

if ($dockerAvailable) {
    Set-Location $ProjectDir

    $runningContainers = @(
        @(docker ps --filter "name=netdoc" --filter "status=running" `
                  --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" }) +
        @(docker ps --filter "name=netdoc-lab-"   --filter "status=running" `
                  --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })
    )
    $allContainers = @(
        @(docker ps -a --filter "name=netdoc" --format "{{.Names}}" 2>&1 |
          Where-Object { $_ -ne "" }) +
        @(docker ps -a --filter "name=netdoc-lab-"   --format "{{.Names}}" 2>&1 |
          Where-Object { $_ -ne "" })
    )
    $labAllContainers = @(
        docker ps -a --filter "name=netdoc-lab-" --format "{{.Names}}" 2>&1 |
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
    Write-Info "Docker is not installed  -  skipping container scan."
} else {
    # Docker installed but not running — try to start it automatically
    Write-Warn "Docker Desktop is not responding."
    Write-Info "Attempting to start Docker Desktop automatically..."
    $dockerDesktopExe = "${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe"
    if (Test-Path $dockerDesktopExe) {
        Start-Process $dockerDesktopExe -ErrorAction SilentlyContinue
        Write-Info "Waiting for Docker daemon to be ready (max 60s)..."
        $waited = 0
        while ($waited -lt 60) {
            Start-Sleep -Seconds 3
            $waited += 3
            docker info 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $dockerAvailable = $true
                Write-OK "Docker daemon is ready."
                Set-Location $ProjectDir
                $runningContainers = @(docker ps --filter "name=netdoc" --filter "status=running" --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })
                $allContainers     = @(docker ps -a --filter "name=netdoc" --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })
                $labAllContainers  = @(docker ps -a --filter "name=netdoc-lab-" --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })
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
            Write-Warn "Docker did not respond within 60s."
            Write-Warn "Containers and volumes will NOT be removed  -  start Docker and retry the uninstall."
        }
    } else {
        Write-Warn "Docker Desktop.exe not found  -  skipping container cleanup."
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
    # search in logs/ (new location) and in the root directory (older logs)
    @(Get-ChildItem (Join-Path $ProjectDir "logs") -Filter "netdoc-*-debug-*.log" -ErrorAction SilentlyContinue) +
    @(Get-ChildItem $ProjectDir -Filter "netdoc-*-debug-*.log" -ErrorAction SilentlyContinue) |
    Where-Object { $_.FullName -ne $LogFile }
)

# ── Installation state summary ────────────────────────────────────────────────

Write-Host ""
Write-Host "  NetDoc installation state:" -ForegroundColor White
Write-Host ""

if ($allContainers.Count -gt 0) {
    $runStr = if ($runningContainers.Count -gt 0) {
        "$($runningContainers.Count) running"
    } else {
        "all stopped"
    }
    Write-Host "     Containers:     $($allContainers.Count) ($runStr)" -ForegroundColor Yellow
} else {
    Write-Host "     Containers:     none" -ForegroundColor DarkGray
}

if ($netdocVolumes.Count -gt 0) {
    Write-Host "     Volumes:        $($netdocVolumes.Count) (database data, metrics)" -ForegroundColor Yellow
} else {
    Write-Host "     Volumes:        none" -ForegroundColor DarkGray
}

if ($netdocImages.Count -gt 0) {
    Write-Host "     Docker images:  $($netdocImages.Count)" -ForegroundColor Yellow
} else {
    Write-Host "     Docker images:  none" -ForegroundColor DarkGray
}

if ($existingTasks.Count -gt 0) {
    Write-Host "     Task Scheduler: $($existingTasks -join ', ')" -ForegroundColor Yellow
} else {
    Write-Host "     Task Scheduler: no NetDoc tasks" -ForegroundColor DarkGray
}

if ($hasEnv) {
    Write-Host "     Configuration:  .env (contains passwords)" -ForegroundColor Yellow
} else {
    Write-Host "     Configuration:  no .env" -ForegroundColor DarkGray
}

if ($oldLogs.Count -gt 0) {
    Write-Host "     Logs:           $($oldLogs.Count) debug file(s)" -ForegroundColor DarkGray
} else {
    Write-Host "     Logs:           none" -ForegroundColor DarkGray
}

Write-Host ""

# Check whether there is anything to do
$hasContainers = ($allContainers.Count -gt 0)
$hasData       = ($netdocVolumes.Count -gt 0 -or $netdocImages.Count -gt 0 -or
                  $existingTasks.Count -gt 0 -or $hasPid -or $hasEnv -or $oldLogs.Count -gt 0)

if (-not $hasContainers -and -not $hasData) {
    Write-OK "NetDoc is not installed or has already been fully uninstalled."
    Write-Info "No containers, volumes, tasks or files to remove."
    Write-Host ""
    Stop-Transcript | Out-Null
    Show-Pause "Press Enter to close..."
    exit 0
}

# ── Mode selection menu ───────────────────────────────────────────────────────

Write-Host "  What would you like to do?" -ForegroundColor White
Write-Host ""

if ($hasContainers) {
    if ($runningContainers.Count -gt 0) {
        Write-Host "  [1]  Stop containers (data and configuration are preserved)" -ForegroundColor Cyan
    } else {
        Write-Host "  [1]  Containers already stopped  -  nothing to do" -ForegroundColor DarkGray
    }
} else {
    Write-Host "  [1]  No containers to stop" -ForegroundColor DarkGray
}

Write-Host "  [2]  Full uninstall  -  confirm by typing REMOVE" -ForegroundColor Red
Write-Host "  [3]  Full uninstall automatic  -  counts down 3s, press any key to cancel" -ForegroundColor Red
Write-Host "  [4]  Cancel  -  exit without changes" -ForegroundColor DarkGray
Write-Host ""
$choice = Read-Host "  Choice"

$autoMode = $false   # set to $true only by option [3]

switch ($choice) {
    "1" {
        $mode = "stop"
        Write-Host ""
        Write-Host "  Mode: Stop containers" -ForegroundColor Cyan
    }
    "2" {
        $mode = "full"
        Write-Host ""
        Write-Host "  Mode: Full uninstall" -ForegroundColor Red
        Write-Host ""
        if ($netdocVolumes.Count -gt 0) {
            Write-Warn "WARNING: Removing volumes will permanently delete ALL data"
            Write-Info "(PostgreSQL database, Prometheus metrics, Grafana dashboards)"
            Write-Host ""
        }
        # Confirmation loop — retry until user types REMOVE or explicitly cancels
        $confirmed = $false
        while (-not $confirmed) {
            $confirm = Read-Host "  Type REMOVE (uppercase) to confirm or N to cancel"
            if ($confirm -eq "REMOVE") {
                $confirmed = $true
            } elseif ($confirm -eq "N" -or $confirm -eq "n") {
                Write-Info "Cancelled by user. No changes made."
                Stop-Transcript | Out-Null
                exit 0
            } elseif ($confirm -eq "") {
                Write-Warn "You pressed Enter instead of typing REMOVE. Type REMOVE to confirm or N to cancel."
            } else {
                Write-Warn "Invalid input: '$confirm'. Type exactly REMOVE (uppercase) or N to cancel."
            }
        }
    }
    "3" {
        $mode = "full"
        $autoMode = $true
        Write-Host ""
        Write-Host "  Mode: Full uninstall automatic" -ForegroundColor Red
        Write-Host ""
        if ($netdocVolumes.Count -gt 0) {
            Write-Warn "WARNING: Removing volumes will permanently delete ALL data"
            Write-Info "(PostgreSQL database, Prometheus metrics, Grafana dashboards)"
            Write-Host ""
        }
        Write-Host "  Uninstall will begin in 3 seconds." -ForegroundColor Yellow
        Write-Host "  Press any key to cancel." -ForegroundColor DarkGray
        Write-Host ""
        $proceed = Wait-WithCountdown -Seconds 3
        if (-not $proceed) {
            Write-Info "Cancelled by user. No changes made."
            Stop-Transcript | Out-Null
            exit 0
        }
    }
    default {
        Write-Info "Cancelled. No changes made."
        Stop-Transcript | Out-Null
        exit 0
    }
}

# ── Stop / remove containers ──────────────────────────────────────────────────

if ($mode -eq "stop") {

    if (-not $dockerAvailable) {
        Write-Warn "Docker unavailable  -  cannot stop containers."
    } elseif ($runningContainers.Count -eq 0) {
        Write-OK "Containers are already stopped  -  nothing to do."
    } else {
        Write-Step "Stopping NetDoc containers..."
        docker compose stop 2>&1 | Out-Host
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Containers stopped. Data preserved."
            Write-Info "To start again: docker compose start"
            Write-Info "  or run netdoc-setup.bat"
        } else {
            Write-Warn "Stop completed with warning (exit code: $LASTEXITCODE)"
        }

        # Also stop lab containers (separate Compose project)
        $labComposeFile = Join-Path $ProjectDir "docker-compose.lab.yml"
        $labRunningNow = @(docker ps --filter "name=netdoc-lab-" --filter "status=running" --format "{{.Names}}" 2>&1 | Where-Object { $_ -ne "" })
        if ($labRunningNow.Count -gt 0) {
            Write-Step "Stopping lab containers ($($labRunningNow.Count))..."
            if (Test-Path $labComposeFile) {
                docker compose -f $labComposeFile stop 2>&1 | Out-Host
            } else {
                foreach ($name in $labRunningNow) {
                    docker stop $name 2>&1 | Out-Null
                }
            }
            Write-OK "Lab containers stopped."
        }
    }

} elseif ($mode -eq "full") {

    # ── Containers and volumes ─────────────────────────────────────────────────

    if (-not $dockerAvailable) {
        Write-Warn "Docker unavailable  -  skipping container and volume removal."
    } elseif (-not $hasContainers -and $netdocVolumes.Count -eq 0) {
        Write-OK "No containers or volumes to remove."
    } else {
        Write-Step "Removing NetDoc containers and volumes..."
        docker compose down --volumes --remove-orphans 2>&1 | Out-Host

        # Verification: check that containers and volumes are actually gone
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
            Write-OK "Verification: containers and volumes removed."
        } else {
            # Force-remove fallback — docker compose down sometimes leaves containers in a bad state
            Write-Warn "docker compose down did not remove everything  -  force-remove..."
            $forceIds = @(docker ps -aq --filter "name=netdoc" 2>&1 | Where-Object { $_ -ne "" })
            foreach ($id in $forceIds) {
                docker rm -f $id 2>&1 | Out-Null
            }
            $forceVols = @(docker volume ls -q --filter "name=netdoc" 2>&1 | Where-Object { $_ -ne "" })
            foreach ($v in $forceVols) {
                docker volume rm $v --force 2>&1 | Out-Null
            }
            # Verify after force-remove
            $stillLeft = @(docker ps -aq --filter "name=netdoc" 2>&1 | Where-Object { $_ -ne "" })
            $volsLeft  = @(docker volume ls -q --filter "name=netdoc" 2>&1 | Where-Object { $_ -ne "" })
            if ($stillLeft.Count -eq 0 -and $volsLeft.Count -eq 0) {
                Write-OK "Verification: force-remove complete  -  everything removed."
            } else {
                Write-Warn "Could not remove everything even with force-remove!"
                foreach ($c in $remainingContainers) { Write-Info "  Container still exists: $c" }
                foreach ($v in $remainingVolumes) { Write-Info "  Volume still exists: $v" }
            }
        }

        # ── Lab containers and images (separate Compose project: netdoc-lab) ──────────
        if ($labAllContainers.Count -gt 0) {
            Write-Step "Removing lab containers and images ($($labAllContainers.Count) containers)..."
            $labComposeFile = Join-Path $ProjectDir "docker-compose.lab.yml"
            if (Test-Path $labComposeFile) {
                docker compose -f $labComposeFile down --rmi all 2>&1 | Out-Host
            }
            # Force-remove if compose down didn't clean up (e.g. missing file)
            $labLeftIds = @(docker ps -aq --filter "name=netdoc-lab-" 2>&1 | Where-Object { $_ -ne "" })
            foreach ($id in $labLeftIds) {
                docker rm -f $id 2>&1 | Out-Null
            }
            # Remove lab images manually (reference=*netdoc-lab* — not covered by main compose down)
            $labImgIds = @(docker images --filter "reference=*netdoc-lab*" --format "{{.ID}}" 2>&1 | Where-Object { $_ -ne "" })
            foreach ($img in ($labImgIds | Sort-Object -Unique)) {
                docker rmi -f $img 2>&1 | Out-Null
            }
            # Remove lab network
            docker network rm netdoc_lab 2>&1 | Out-Null
            # Verify
            $labStill = @(docker ps -aq --filter "name=netdoc-lab-" 2>&1 | Where-Object { $_ -ne "" })
            if ($labStill.Count -eq 0) {
                Write-OK "Lab containers and images removed."
            } else {
                Write-Warn "Could not remove $($labStill.Count) lab container(s)."
            }
        }
    }

    # ── Obrazy Docker (tylko jesli istnieja) ──────────────────────────────────

    if ($dockerAvailable -and $netdocImages.Count -gt 0) {
        Write-Host ""
        Write-Host "     NetDoc Docker images ($($netdocImages.Count)) take ~2-3 GB." -ForegroundColor DarkGray
        if ($autoMode) {
            Write-Info "Auto mode: removing images without prompting."
            $removeImages = "Y"
        } else {
            $removeImages = Read-Host "  Remove Docker images? [Y/N]"
        }
        if ($removeImages -eq "Y" -or $removeImages -eq "y") {
            Write-Info "Removing images via 'docker compose down --rmi all'..."
            # --rmi all is more reliable than manual docker rmi by ID:
            # Docker Compose knows exactly which images belong to the project
            docker compose down --rmi all 2>&1 | Out-Host

            # Verify: images are gone
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
                Write-OK "Verification: all NetDoc images removed."
            } else {
                Write-Warn "Verification: $($remainingImages.Count) image(s) still exist!"
                Write-Info "Possible cause: image is used by another container."
                Write-Info "Try manually: docker rmi --force $(docker images --filter 'reference=*netdoc*' -q)"
            }

            # Remove dangling images labelled as belonging to netdoc (layers from rebuilds)
            # NOTE: "docker image prune -f" without filter would remove ALL system dangling images.
            #       Instead, manually remove only those with the netdoc project label.
            $danglingNetdoc = @(
                docker images -f "dangling=true" -f "label=com.docker.compose.project=netdoc" `
                              --format "{{.ID}}" 2>&1 | Where-Object { $_ -ne "" }
            )
            if ($danglingNetdoc.Count -gt 0) {
                Write-Info "Removing $($danglingNetdoc.Count) NetDoc intermediate layer(s)..."
                foreach ($img in $danglingNetdoc) {
                    docker rmi -f $img 2>&1 | Out-Null
                }
                Write-OK "NetDoc intermediate layers cleaned up."
            }
        }
    }

    # ── Task Scheduler ────────────────────────────────────────────────────────

    Write-Step "Removing Task Scheduler tasks..."

    if ($existingTasks.Count -eq 0) {
        Write-OK "No NetDoc tasks found in Task Scheduler  -  skipping."
    } else {
        foreach ($taskName in $existingTasks) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

            # Verify
            $stillExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($null -eq $stillExists) {
                Write-OK "Removed task: $taskName"
            } else {
                Write-Warn "Could not remove task: $taskName  -  try manually in Task Scheduler"
            }
        }
    }

    # ── Scanner PID file ──────────────────────────────────────────────────────

    if ($hasPid) {
        Write-Step "Removing runtime files..."
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $pidFile)) {
            Write-OK "Removed: scanner.pid"
        } else {
            Write-Warn "Could not remove scanner.pid  -  file may be locked by a process"
        }
    }

    # ── .env (only if it exists) ──────────────────────────────────────────────

    if ($hasEnv) {
        Write-Host ""
        Write-Host "     The .env file contains passwords and connection settings." -ForegroundColor DarkGray
        if ($autoMode) {
            Write-Info "Auto mode: removing .env without prompting."
            $removeEnv = "Y"
        } else {
            $removeEnv = Read-Host "  Remove .env file? [Y/N]"
        }
        if ($removeEnv -eq "Y" -or $removeEnv -eq "y") {
            Remove-Item $envFile -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $envFile)) {
                Write-OK "Removed: .env"
            } else {
                Write-Warn "Could not remove .env"
            }
        } else {
            Write-Info "Kept: .env"
        }
    }

    # ── Installer logs (only if they exist) ──────────────────────────────────

    if ($oldLogs.Count -gt 0) {
        Write-Host ""
        Write-Host "     Found $($oldLogs.Count) installer log file(s)." -ForegroundColor DarkGray
        if ($autoMode) {
            Write-Info "Auto mode: removing logs without prompting."
            $removeLogs = "Y"
        } else {
            $removeLogs = Read-Host "  Remove installer debug logs? [Y/N]"
        }
        if ($removeLogs -eq "Y" -or $removeLogs -eq "y") {
            $removedLogs = 0
            $oldLogs | ForEach-Object {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                if (-not (Test-Path $_.FullName)) {
                    Write-Info "Removed: $($_.Name)"
                    $removedLogs++
                } else {
                    Write-Warn "Could not remove: $($_.Name)"
                }
            }
            Write-OK "Removed $removedLogs of $($oldLogs.Count) log(s)."
        }
    }
}

# ── Podsumowanie ─────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  ================================================" -ForegroundColor Cyan

if ($mode -eq "stop") {
    Write-Host "   NetDoc containers stopped." -ForegroundColor Green
    Write-Host "  ================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "   Data (database, metrics) is PRESERVED." -ForegroundColor White
    Write-Host "   To resume: run netdoc-setup.bat" -ForegroundColor DarkGray
} else {
    Write-Host "   NetDoc has been uninstalled." -ForegroundColor Green
    Write-Host "  ================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "   What was kept (remove manually if you want):" -ForegroundColor White
    Write-Host "   - Project directory: $ProjectDir" -ForegroundColor DarkGray
    Write-Host "   - Python and pip packages (installed globally)" -ForegroundColor DarkGray
    Write-Host "   - Docker Desktop (installed system-wide)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "   To uninstall Docker Desktop:" -ForegroundColor DarkGray
    Write-Host "   Settings -> Apps -> Docker Desktop -> Uninstall" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  Debug log: $LogFile" -ForegroundColor DarkGray
Write-Host ""

Stop-Transcript | Out-Null

Show-Pause "Press Enter to close..."
