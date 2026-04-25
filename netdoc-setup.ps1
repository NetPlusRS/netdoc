# netdoc-setup.ps1
# First-time NetDoc setup on Windows.
# Checks and installs required software (WSL2, Docker Desktop, git, Python),
# configures the environment and starts the system.
#
# Usage:
#   Double-click netdoc-setup.bat
#   OR: powershell -ExecutionPolicy Bypass -File netdoc-setup.ps1

#Requires -Version 5.1

$ErrorActionPreference = "Continue"
$ProjectDir = $PSScriptRoot

# ── Self-elevation: require Administrator privileges ──────────────────────────
#    Must be BEFORE Start-Transcript — UAC restarts the process, so the new
#    instance will resume the transcript on its own.

$_currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $_currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "  NetDoc Installer requires Administrator privileges." -ForegroundColor Yellow
    Write-Host "  A UAC prompt will appear  -  click Yes to continue." -ForegroundColor DarkGray
    Write-Host ""
    Start-Sleep -Seconds 2
    $scriptPath = $PSCommandPath   # more reliable than $MyInvocation.MyCommand.Path
    try {
        Start-Process powershell.exe `
            -Verb RunAs `
            -ArgumentList @("-ExecutionPolicy", "Bypass", "-File", $scriptPath) `
            -WorkingDirectory $ProjectDir `
            -ErrorAction Stop
    } catch {
        Write-Host ""
        Write-Host "  Access denied  -  UAC was rejected or blocked by policy." -ForegroundColor Red
        Write-Host "  Installation requires Administrator rights." -ForegroundColor Yellow
        Write-Host "  Try: right-click netdoc-setup.bat -> Run as administrator" -ForegroundColor DarkGray
        Write-Host ""
        Read-Host "  Press Enter to close..."
    }
    exit
}

# ── Debug log file ────────────────────────────────────────────────────────────

$LogDir       = Join-Path $ProjectDir "logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$LogTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogFile      = Join-Path $LogDir "netdoc-setup-debug-$LogTimestamp.log"

# Start-Transcript records EVERYTHING  -  every command, output, and errors
Start-Transcript -Path $LogFile -Append | Out-Null

function Write-LogSection([string]$title) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $sep = "=" * 70
    Write-Host ""
    Write-Host "[$ts] $sep" -ForegroundColor DarkGray
    Write-Host "[$ts] $title" -ForegroundColor DarkGray
    Write-Host "[$ts] $sep" -ForegroundColor DarkGray
}

function Write-LogEntry([string]$level, [string]$msg) {
    $ts = Get-Date -Format "HH:mm:ss"
    Write-Host "[$ts][$level] $msg" -ForegroundColor DarkGray
}

# Dump system information at the beginning of the log
function Write-SystemInfo {
    Write-LogSection "SYSTEM INFORMATION"
    Write-LogEntry "INFO" "Script:     $PSCommandPath"
    Write-LogEntry "INFO" "Directory:  $ProjectDir"
    Write-LogEntry "INFO" "PowerShell: $($PSVersionTable.PSVersion)"
    Write-LogEntry "INFO" "OS:         $([System.Environment]::OSVersion.VersionString)"
    Write-LogEntry "INFO" "Build:      $([System.Environment]::OSVersion.Version.Build)"
    Write-LogEntry "INFO" "User:       $([System.Environment]::UserName)"
    Write-LogEntry "INFO" "Hostname:   $([System.Environment]::MachineName)"
    Write-LogEntry "INFO" "Arch:       $([System.Environment]::Is64BitOperatingSystem)"

    # RAM
    try {
        $ram = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $totalGB = [Math]::Round($ram.TotalVisibleMemorySize / 1MB, 1)
        $freeGB  = [Math]::Round($ram.FreePhysicalMemory     / 1MB, 1)
        Write-LogEntry "INFO" "RAM:        ${totalGB} GB total, ${freeGB} GB free"
    } catch { Write-LogEntry "WARN" "RAM: could not retrieve" }

    # Drive C:
    try {
        $disk = Get-PSDrive C -ErrorAction Stop
        $freeGB = [Math]::Round($disk.Free / 1GB, 1)
        $usedGB = [Math]::Round($disk.Used / 1GB, 1)
        Write-LogEntry "INFO" "Drive C:    ${usedGB} GB used, ${freeGB} GB free"
    } catch { Write-LogEntry "WARN" "Disk: could not retrieve" }

    # PATH
    Write-LogEntry "INFO" "PATH:"
    ($env:PATH -split ";") | ForEach-Object { Write-LogEntry "PATH" "  $_" }

    Write-LogSection "INSTALLATION START"
}

# ── Colors / formatting ───────────────────────────────────────────────────────

function Write-Header {
    Clear-Host
    Write-Host ""
    Write-Host "  ================================================" -ForegroundColor Cyan
    Write-Host "   NetDoc  -  Windows Installer" -ForegroundColor Cyan
    Write-Host "  ================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "  >> $msg" -ForegroundColor Cyan
    # In the log file: visible section with timestamp
    Write-LogEntry "STEP" $msg
}

function Write-OK([string]$msg) {
    Write-Host "     [OK] $msg" -ForegroundColor Green
    Write-LogEntry "OK  " $msg
}

function Write-Warn([string]$msg) {
    Write-Host "     [!!] $msg" -ForegroundColor Yellow
    Write-LogEntry "WARN" $msg
}

function Write-Fail([string]$msg) {
    Write-Host "     [ERROR] $msg" -ForegroundColor Red
    Write-LogEntry "FAIL" $msg
}

function Write-Info([string]$msg) {
    Write-Host "           $msg" -ForegroundColor DarkGray
    Write-LogEntry "INFO" $msg
}

function Show-Pause([string]$msg = "Press Enter to continue...") {
    Write-Host ""
    Write-Host "  $msg" -ForegroundColor DarkGray
    Read-Host | Out-Null
}

# ── Privileges (self-elevation above ensures admin rights) ───────────────────

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

Write-Header
Write-Host "  Project directory: $ProjectDir" -ForegroundColor DarkGray
Write-Host "  Debug log:         $LogFile" -ForegroundColor DarkGray
if ($isAdmin) {
    Write-Host "  Privileges:        Administrator" -ForegroundColor Green
}
Write-Host ""

Write-SystemInfo

# ── Windows version ───────────────────────────────────────────────────────────

Write-Step "Checking Windows version..."

$winver = [System.Environment]::OSVersion.Version
$build  = $winver.Build
Write-Info "Windows Build: $build"

if ($build -lt 19041) {
    Write-Fail "Windows 10 v2004 (Build 19041) or newer is required."
    Write-Info "Your version ($build) is too old  -  please update your system."
    Show-Pause "Press Enter to close..."
    exit 1
} else {
    Write-OK "Windows $($winver.Major).$($winver.Minor) Build $build  -  OK"
}

# ── winget ───────────────────────────────────────────────────────────────────

Write-Step "Checking winget (Windows Package Manager)..."

$wingetPath = Get-Command winget -ErrorAction SilentlyContinue
if ($wingetPath) {
    $wingetVer = (winget --version 2>&1) -replace "[^0-9\.]", ""
    Write-OK "winget $wingetVer"
} else {
    Write-Warn "winget is not available."
    Write-Info "Install 'App Installer' from the Microsoft Store:"
    Write-Info "  https://apps.microsoft.com/detail/9NBLGGH4NNS1"
    Write-Info "  OR update Windows  -  winget is included by default from Windows 10 21H1"
    Show-Pause "Press Enter after installing winget..."
    $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $wingetPath) {
        Write-Fail "winget still not available. Installation aborted."
        exit 1
    }
}

# ── winget installation function ─────────────────────────────────────────────

function Install-WithWinget {
    param(
        [string]$Id,
        [string]$Label,
        [string]$CommandCheck = $null
    )

    if ($CommandCheck) {
        $existing = Get-Command $CommandCheck -ErrorAction SilentlyContinue
        if ($existing) {
            $ver = try { (& $CommandCheck --version 2>&1) | Select-Object -First 1 } catch { "?" }
            Write-OK "$Label installed: $ver"
            return $true
        }
    }

    Write-Warn "$Label not found  -  installing via winget..."
    Write-Info "  winget install -e --id $Id --accept-package-agreements --accept-source-agreements"
    winget install -e --id $Id --accept-package-agreements --accept-source-agreements 2>&1 | Out-Host

    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1978335189) {
        # -1978335189 = already installed (WINGET_INSTALLED_STATUS_ALREADY_INSTALLED)
        Write-OK "$Label installed successfully."
        return $true
    } else {
        Write-Fail "Installation of $Label failed (exit code: $LASTEXITCODE)."
        return $false
    }
}

# ── git ──────────────────────────────────────────────────────────────────────

Write-Step "Checking git..."

$gitOk = Install-WithWinget -Id "Git.Git" -Label "git" -CommandCheck "git"
if (-not $gitOk) {
    # May be installed but not in PATH  -  check common locations
    $gitPaths = @(
        "$env:ProgramFiles\Git\cmd\git.exe",
        "${env:ProgramFiles(x86)}\Git\cmd\git.exe"
    )
    foreach ($p in $gitPaths) {
        if (Test-Path $p) {
            Write-OK "git found: $p"
            $gitOk = $true
            # Refresh PATH in this session
            $env:PATH += ";$(Split-Path $p)"
            break
        }
    }
    if (-not $gitOk) {
        Write-Warn "git is not available. You can continue if the repository is already downloaded."
    }
}

# ── nmap ─────────────────────────────────────────────────────────────────────

Write-Step "Checking nmap (required by python-nmap for port scanning)..."

$nmapKnownPaths = @(
    "${env:ProgramFiles(x86)}\Nmap\nmap.exe",
    "$env:ProgramFiles\Nmap\nmap.exe"
)

$nmapFound = Get-Command nmap -ErrorAction SilentlyContinue

if ($nmapFound) {
    $nmapVer = try { (nmap --version 2>&1 | Select-Object -First 1) } catch { "?" }
    Write-OK "nmap: $nmapVer"
} else {
    # Check common nmap install locations (may be installed without PATH)
    $nmapExe = $nmapKnownPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($nmapExe) {
        $nmapDir = Split-Path $nmapExe
        $env:PATH += ";$nmapDir"
        $nmapVer  = try { (& $nmapExe --version 2>&1 | Select-Object -First 1) } catch { "?" }
        Write-OK "nmap found and added to PATH: $nmapDir"
        Write-Info "$nmapVer"
    } else {
        Write-Warn "nmap not found  -  installing via winget..."
        Install-WithWinget -Id "Insecure.Nmap" -Label "nmap" | Out-Null

        # Refresh PATH and check known locations after installation
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH", "User")

        $nmapExe = $nmapKnownPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($nmapExe) {
            $nmapDir = Split-Path $nmapExe
            if ($env:PATH -notlike "*$nmapDir*") {
                $env:PATH += ";$nmapDir"
            }
            Write-OK "nmap installed and added to PATH: $nmapDir"
        } elseif (Get-Command nmap -ErrorAction SilentlyContinue) {
            Write-OK "nmap installed and available in PATH."
        } else {
            Write-Warn "nmap installed but not found in PATH."
            Write-Info "A terminal restart may be required after installation."
            Write-Info "Nmap installs by default to: ${env:ProgramFiles(x86)}\Nmap\"
        }
    }
}

# ── Python ───────────────────────────────────────────────────────────────────

Write-Step "Checking Python 3.9+ (required by NetDoc)..."

# Minimum version required by the host-side NetDoc scanner
# Docker containers use python:3.11-slim internally  -  host can be 3.9+
$MIN_PY_MAJOR = 3
$MIN_PY_MINOR = 9

function Get-PythonMinorVersion([string]$cmd) {
    try {
        $out = (& $cmd --version 2>&1) | Select-Object -First 1   # "Python 3.10.12"
        if ($out -match "Python (\d+)\.(\d+)") {
            return [int]$Matches[1] * 100 + [int]$Matches[2]   # np. 310
        }
    } catch {}
    return 0
}

$MIN_PY_CODE = $MIN_PY_MAJOR * 100 + $MIN_PY_MINOR   # 309

$pythonCmd  = $null
$pythonPath = $null

# Also check 'py -3' (Windows Launcher  -  always returns the latest Python 3.x)
$candidateCmds = @("python", "python3", "py")

foreach ($cmd in $candidateCmds) {
    $c = Get-Command $cmd -ErrorAction SilentlyContinue
    if (-not $c) { continue }

    $verCode = Get-PythonMinorVersion $cmd
    $verStr  = try { (& $cmd --version 2>&1) | Select-Object -First 1 } catch { "?" }

    if ($verCode -ge $MIN_PY_CODE) {
        Write-OK "$verStr (command: $cmd)"
        $pythonCmd  = $cmd
        $pythonPath = $c.Source
        break
    } elseif ($verCode -gt 0) {
        Write-Info "$verStr  -  too old (Python $MIN_PY_MAJOR.$MIN_PY_MINOR+ required), looking for newer..."
    }
}

if (-not $pythonCmd) {
    Write-Warn "Python $MIN_PY_MAJOR.$MIN_PY_MINOR+ not found  -  installing Python 3.12..."
    Install-WithWinget -Id "Python.Python.3.12" -Label "Python 3.12" | Out-Null

    # Refresh PATH after installation (winget modifies PATH in registry, not in current session)
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH", "User")

    # Add common Python 3.12 locations if not yet in PATH
    foreach ($pyPath in @(
        "$env:LOCALAPPDATA\Programs\Python\Python312",
        "$env:LOCALAPPDATA\Programs\Python\Python312\Scripts",
        "$env:ProgramFiles\Python312",
        "$env:ProgramFiles\Python312\Scripts"
    )) {
        if ((Test-Path $pyPath) -and ($env:PATH -notlike "*$pyPath*")) {
            $env:PATH += ";$pyPath"
        }
    }

    foreach ($cmd in $candidateCmds) {
        $c = Get-Command $cmd -ErrorAction SilentlyContinue
        if (-not $c) { continue }

        $verCode = Get-PythonMinorVersion $cmd
        $verStr  = try { (& $cmd --version 2>&1) | Select-Object -First 1 } catch { "?" }

        if ($verCode -ge $MIN_PY_CODE) {
            Write-OK "Python ready: $verStr"
            $pythonCmd  = $cmd
            $pythonPath = $c.Source
            break
        }
    }

    if (-not $pythonCmd) {
        Write-Warn "Python not available in PATH  -  a terminal restart may be required."
        Write-Warn "Host scanner (run_scanner.py) will not work without Python."
        Write-Info "Docker containers will start and work normally."
        Write-Info "After restarting the terminal run: python -m pip install -r requirements.txt"
        $pythonCmd  = "python"
        $pythonPath = $null
    }
}

# Save Python path  -  needed by install_autostart.ps1
$PythonExeResolved = if ($pythonPath) { $pythonPath } else { "python" }

# ── WSL2 ─────────────────────────────────────────────────────────────────────

Write-Step "Checking WSL2 (required by Docker Desktop)..."

$wslOk = $false

# Method 1: wsl --status (language-independent: exit code 0 = WSL installed)
try {
    wsl --status 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-OK "WSL2 is already installed."
        $wslOk = $true
    }
} catch {}

# Method 2: wsl --list (more compatible with older versions)
if (-not $wslOk) {
    try {
        $wslListOut = wsl --list 2>&1
        if ($LASTEXITCODE -eq 0) {
            # Check if any distribution exists (not just the header)
            $distros = $wslListOut | Where-Object {
                $_ -ne "" -and $_ -notmatch "^\s*$"
            }
            if ($distros.Count -gt 1) {
                # > 1 line = header + at least 1 distribution
                Write-OK "WSL is installed with a Linux distribution."
                Write-Info "Setting WSL2 as default..."
                if ($isAdmin) {
                    wsl --set-default-version 2 2>&1 | Out-Null
                }
                $wslOk = $true
            } else {
                Write-Warn "WSL installed but no Linux distribution found."
                Write-Info "Docker Desktop can install a distribution automatically."
                $wslOk = $true   # do not block  -  Docker Desktop will handle the rest
            }
        }
    } catch {}
}

if (-not $wslOk) {
    Write-Warn "WSL2 is not installed."

    if ($isAdmin) {
        Write-Info "Installing WSL2 (may require a restart)..."
        Write-Info "  Enabling Windows Subsystem for Linux feature..."
        dism /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart 2>&1 | Out-Null
        Write-Info "  Enabling Virtual Machine Platform..."
        dism /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart 2>&1 | Out-Null
        Write-Info "  Setting WSL2 as default..."
        wsl --set-default-version 2 2>&1 | Out-Null
        Write-Info "  Installing Linux kernel..."
        wsl --install --no-launch 2>&1 | Out-Null

        Write-Warn "WSL2 installed  -  SYSTEM RESTART required."
        Write-Info "After restart, run this script again."
        Write-Host ""
        $restartNow = Read-Host "  Restart now? [Y/N]"
        if ($restartNow -eq "Y" -or $restartNow -eq "y") {
            Write-Info "Closing log and restarting system..."
            Stop-Transcript | Out-Null   # close log before restart
            Restart-Computer -Force
        }
        Write-Info "Remember to restart before launching Docker Desktop."
    } else {
        Write-Info "Run PowerShell as Administrator and type:"
        Write-Info "  wsl --install"
        Write-Info "  Then restart your computer."
        Write-Warn "Without WSL2 Docker Desktop may not work."
    }
}

# ── Docker Desktop ────────────────────────────────────────────────────────────

Write-Step "Checking Docker Desktop..."

$dockerCli = Get-Command docker -ErrorAction SilentlyContinue
$dockerInstalled = $false

if ($dockerCli) {
    $dockerInstalled = $true
    $dver = try { (docker --version 2>&1) } catch { "?" }
    Write-OK "Docker CLI: $dver"
} else {
    # Check common Docker Desktop locations
    $dockerPaths = @(
        "$env:ProgramFiles\Docker\Docker\resources\bin\docker.exe",
        "$env:LOCALAPPDATA\Docker\Docker\resources\bin\docker.exe"
    )
    foreach ($p in $dockerPaths) {
        if (Test-Path $p) {
            Write-OK "Docker CLI found: $p"
            $env:PATH += ";$(Split-Path $p)"
            $dockerInstalled = $true
            break
        }
    }
}

if (-not $dockerInstalled) {
    Write-Warn "Docker Desktop is not installed  -  installing..."
    $ok = Install-WithWinget -Id "Docker.DockerDesktop" -Label "Docker Desktop"

    if ($ok) {
        Write-Info "Docker Desktop installed."

        # Refresh PATH  -  winget adds Docker to PATH but not in the current session
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH", "User")

        # Add known Docker locations if not yet in PATH
        foreach ($dockerBinPath in @(
            "$env:ProgramFiles\Docker\Docker\resources\bin",
            "$env:LOCALAPPDATA\Docker\Docker\resources\bin"
        )) {
            if ((Test-Path $dockerBinPath) -and ($env:PATH -notlike "*$dockerBinPath*")) {
                $env:PATH += ";$dockerBinPath"
                Write-Info "Added to PATH: $dockerBinPath"
            }
        }

        Write-Info "Starting Docker Desktop  -  wait until the tray icon is ready..."
        $dockerApp = "${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe"
        if (Test-Path $dockerApp) {
            Start-Process $dockerApp
        }
    } else {
        Write-Fail "Failed to install Docker Desktop."
        Write-Info "Download manually: https://www.docker.com/products/docker-desktop/"
        Show-Pause "Press Enter after installing Docker Desktop manually..."
    }
}

# ── Wait for Docker daemon ─────────────────────────────────────────────────────

Write-Step "Waiting for Docker daemon to become ready..."
Write-Host ""
Write-Host "  IMPORTANT:" -ForegroundColor Yellow
Write-Host "  If a Docker Desktop window appeared on screen — click Accept on the EULA." -ForegroundColor Yellow
Write-Host "  Docker will not start until you accept the license agreement." -ForegroundColor Yellow
Write-Host ""

$dockerReady = $false
$maxWait     = 300   # seconds  (first launch: EULA wizard + engine startup can take 3-5 min)
$waited      = 0
$dotCount    = 0

Write-Host "     " -NoNewline

while ($waited -lt $maxWait) {
    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $dockerReady = $true
        break
    }

    Write-Host "." -NoNewline -ForegroundColor DarkGray
    $dotCount++
    if ($dotCount % 30 -eq 0) { Write-Host "" ; Write-Host "     " -NoNewline }

    Start-Sleep -Seconds 2
    $waited += 2
}

Write-Host ""

if (-not $dockerReady) {
    Write-Fail "Docker daemon did not respond within $maxWait seconds."
    Write-Info "Make sure Docker Desktop is running (tray icon)."
    Write-Info "Then run this script again."
    Show-Pause "Press Enter to close..."
    exit 1
} else {
    Write-OK "Docker daemon is running."
}

# ── .env ─────────────────────────────────────────────────────────────────────

Write-Step "Checking .env configuration..."

$envFile    = Join-Path $ProjectDir ".env"
$envExample = Join-Path $ProjectDir ".env.example"

if (Test-Path $envFile) {
    Write-OK ".env already exists  -  skipping copy."
} elseif (Test-Path $envExample) {
    Copy-Item $envExample $envFile
    Write-OK ".env copied from .env.example"
    Write-Info "You can edit $envFile to customize the configuration."
} else {
    Write-Warn ".env.example not found  -  creating minimal .env..."
    @"
# NetDoc configuration  -  auto-generated by setup
# PostgreSQL connection from HOST (port 15432 = external container port)
DB_HOST=localhost
DB_PORT=15432
DB_NAME=netdoc
DB_USER=netdoc
DB_PASSWORD=netdoc
# uvicorn API bind address (not a URL  -  do not add http://)
API_HOST=0.0.0.0
API_PORT=8000
NETWORK_RANGES=
LOG_LEVEL=INFO
"@ | Set-Content $envFile -Encoding UTF8
    Write-OK ".env created with default values."
}

# ── Python requirements (host-side) ───────────────────────────────────────────
#
# Defender strategy: first try installing without modifying AV configuration.
# Only if pip fails AND Defender is active AND we have admin rights
# do we add exclusions and retry.
# This avoids touching AV settings on systems where there is no problem
# (e.g. AV disabled, different product, user already has exclusions).

Write-Step "Installing Python dependencies (for host-side scanner)..."
Write-Info "  (Docker containers work independently  -  this section only affects the host)"

$reqFile = Join-Path $ProjectDir "requirements.txt"
if (-not (Test-Path $reqFile)) {
    Write-Info "Skipping  -  requirements.txt not found."
} elseif (-not $pythonPath) {
    Write-Warn "Python not available in PATH  -  skipping pip install."
    Write-Info "Run manually after restart: python -m pip install -r requirements.txt"
} else {
    # Update pip before installing dependencies
    # Old pip has a bundled old urllib3 version that conflicts with newer packages
    Write-Info "  Updating pip to latest version..."
    & $PythonExeResolved -m pip install --upgrade pip --quiet 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "pip upgrade failed  -  continuing with current version."
    }

    Write-Info "  Instaluje: $PythonExeResolved -m pip install -r requirements.txt"
    & $PythonExeResolved -m pip install -r $reqFile --quiet 2>&1 | Out-Host
    $pipExitCode = $LASTEXITCODE

    if ($pipExitCode -eq 0) {
        Write-OK "Dependencies installed."
    } else {
        Write-Warn "pip install failed (exit code: $pipExitCode)."

        # Check if Defender may be the cause and if we can do anything about it
        $defStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        $defActive = ($null -ne $defStatus) -and $defStatus.RealTimeProtectionEnabled

        if ($defActive -and $isAdmin) {
            Write-Info "Active Windows Defender detected  -  adding exclusions and retrying..."

            $sitePkg = try {
                (& $PythonExeResolved -c "import site; print(site.getsitepackages()[0])" 2>&1) |
                Select-Object -First 1
            } catch { $null }

            $excludePaths = [System.Collections.Generic.List[string]]::new()
            if ($sitePkg -and (Test-Path $sitePkg)) { $excludePaths.Add($sitePkg) }
            $tempPath = [System.IO.Path]::GetTempPath().TrimEnd('\')
            if ($tempPath) { $excludePaths.Add($tempPath) }
            if ($env:TEMP -and $env:TEMP -ne $tempPath) { $excludePaths.Add($env:TEMP) }
            $pipCache = Join-Path $env:LOCALAPPDATA "pip\Cache"
            if (Test-Path $pipCache) { $excludePaths.Add($pipCache) }
            $excludePaths.Add($ProjectDir)

            $addedAny = $false
            foreach ($path in $excludePaths) {
                Add-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue
                if ($?) {
                    Write-OK "Defender exclusion added: $path"
                    $addedAny = $true
                }
            }

            if ($addedAny) {
                Write-Info "Retrying installation after adding exclusions..."
                & $PythonExeResolved -m pip install -r $reqFile --quiet 2>&1 | Out-Host
                if ($LASTEXITCODE -eq 0) {
                    Write-OK "Dependencies installed after adding Defender exclusions."
                } else {
                    Write-Warn "pip install still failing."
                    Write-Info "Check Defender Quarantine and the log above."
                }
            }
        } elseif ($defActive -and -not $isAdmin) {
            Write-Warn "Active Defender and no admin rights  -  cannot add exclusions."
            Write-Info "If Defender blocks impacket, run the installer as Administrator"
            Write-Info "or add manual exclusions:"
            $sitePkg2 = try {
                (& $PythonExeResolved -c "import site; print(site.getsitepackages()[0])" 2>&1) |
                Select-Object -First 1
            } catch { $null }
            if ($sitePkg2) { Write-Info "  $sitePkg2" }
            Write-Info "  $env:TEMP"
            Write-Info "  $ProjectDir"
        } else {
            Write-Info "Check the messages above. Common causes:"
            Write-Info "  - Windows Defender blocking impacket build (dcomexec.py / dacledit.py)"
            Write-Info "    Solution: run installer as Administrator"
            Write-Info "    (installer will automatically add Defender exclusions and retry)"
            Write-Info "  - Other AV blocking impacket (check Quarantine)"
            Write-Info "  - Missing Visual C++ Build Tools (required by some packages)"
            Write-Info "  - No internet access (pip.pypa.io)"
            Write-Info "You can retry manually: $PythonExeResolved -m pip install -r requirements.txt"
        }

        Write-Info "Docker containers will start independently of this error."
    }
}

# ── Detect and clean previous NetDoc installation ─────────────────────────────

Write-Step "Checking for existing NetDoc installations..."

Set-Location $ProjectDir

$oldContainers = @(docker ps -a --filter "name=netdoc" --format "{{.Names}}" 2>&1 |
                   Where-Object { $_ -ne "" })
$oldVolumes    = @(docker volume ls --filter "name=netdoc" --format "{{.Name}}" 2>&1 |
                   Where-Object { $_ -ne "" })

if ($oldContainers.Count -gt 0 -or $oldVolumes.Count -gt 0) {
    Write-Warn "Existing NetDoc installation found:"
    if ($oldContainers.Count -gt 0) {
        Write-Info "  Containers ($($oldContainers.Count)):"
        foreach ($c in $oldContainers) { Write-Info "    - $c" }
    }
    if ($oldVolumes.Count -gt 0) {
        Write-Info "  Volumes ($($oldVolumes.Count)):"
        foreach ($v in $oldVolumes) { Write-Info "    - $v" }
    }

    Write-Host ""
    Write-Host "  You have two options:" -ForegroundColor White
    Write-Host "   [Y]  Remove old containers and data (clean install)" -ForegroundColor Yellow
    Write-Host "        WARNING: deletes the database, metrics and configuration!" -ForegroundColor DarkGray
    Write-Host "   [N]  Keep data (update / restart)" -ForegroundColor Cyan
    Write-Host "        Old containers will be replaced with new images," -ForegroundColor DarkGray
    Write-Host "        but database data and configuration will be preserved." -ForegroundColor DarkGray
    Write-Host ""

    $cleanUp = Read-Host "  Remove old data and perform a clean install? [Y/N]"

    if ($cleanUp -eq "Y" -or $cleanUp -eq "y") {
        Write-Info "Removing old containers and volumes..."
        docker compose down --volumes --remove-orphans 2>&1 | Out-Host
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Old containers and data removed  -  clean install."
        } else {
            Write-Warn "Cleanup completed with warning (code: $LASTEXITCODE)."
            Write-Info "Continuing  -  docker compose up will replace old containers."
        }
    } else {
        Write-Info "Stopping old containers (data preserved)..."
        docker compose down --remove-orphans 2>&1 | Out-Host
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Old containers stopped  -  volume data preserved."
        } else {
            Write-Warn "Stop completed with warning (code: $LASTEXITCODE)."
        }
    }
} else {
    Write-OK "No previous installation found  -  clean install."
}

# ── docker compose up ─────────────────────────────────────────────────────────

Write-Step "Starting Docker containers (docker compose --profile workers up -d --build)..."
Write-Info "First run may take a few minutes  -  downloading base images."
Write-Host ""
Write-Warn "IMPORTANT  -  required Docker Desktop settings before starting:"
Write-Info "  1. Docker Desktop -> Settings -> Advanced:"
Write-Info "     Enable: 'Allow the default Docker socket to be used (requires password)'"
Write-Info "     (required by the web service and promtail  -  access to /var/run/docker.sock)"
Write-Info "  2. The api and ping-worker containers require NET_RAW capability (ICMP ping)."
Write-Info "     Docker Desktop on Windows handles this by default  -  if ping does not work,"
Write-Info "     check Windows Defender Firewall isolation settings for Docker."
Write-Host ""

# Note: do NOT use "2>&1 | Out-Host" because PowerShell converts stderr of native commands
# to ErrorRecord and Start-Transcript records them as errors (NativeCommandError).
# Docker compose writes its own output — Transcript captures it anyway.
$composeOk      = $false
$composeTries   = 0
$composeMaxTries = 3

while (-not $composeOk -and $composeTries -lt $composeMaxTries) {
    $composeTries++
    if ($composeTries -gt 1) {
        Write-Warn "Retrying docker compose up (attempt $composeTries / $composeMaxTries)..."
        Write-Info "Waiting 30 seconds before retry  -  check Docker Desktop settings in the meantime."
        Write-Info "  Docker Desktop -> Settings -> Advanced ->"
        Write-Info "  'Allow the default Docker socket to be used (requires password)'"
        Start-Sleep -Seconds 30
    }
    docker compose --profile workers up -d --build
    if ($LASTEXITCODE -eq 0) { $composeOk = $true }
}

if (-not $composeOk) {
    Write-Fail "docker compose up failed after $composeMaxTries attempts."
    Write-Info "Check the messages above. Common causes:"
    Write-Info "  - Missing Docker socket permission: Settings -> Advanced ->"
    Write-Info "    'Allow the default Docker socket to be used (requires password)'"
    Write-Info "  - Port 80 or 8000 already in use by another application"
    Write-Info "    Check: netstat -ano | findstr ':80 '"
    Write-Info "  - Insufficient RAM (Docker requires at least 4 GB free)"
    Write-Info "  - Docker Desktop is not running or still starting"
    Write-Info "  - Image build error  -  check internet access (pip, apt)"
    Write-Info "After fixing the issue run: docker compose --profile workers up -d --build"
    Show-Pause "Press Enter to close..."
    exit 1
}

# ── Windows Firewall — syslog port 514 ────────────────────────────────────────

Write-Step "Configuring Windows Firewall for syslog (port 514)..."
Write-Info "  Required so network devices can send logs to NetDoc (rsyslog/vector containers)."

foreach ($proto in @("UDP", "TCP")) {
    $ruleName = "NetDoc Syslog $proto"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        try {
            New-NetFirewallRule `
                -DisplayName $ruleName `
                -Direction Inbound `
                -Protocol $proto `
                -LocalPort 514 `
                -Action Allow `
                -Profile Any `
                -Description "NetDoc: allow syslog from network devices ($proto/514)" `
                -ErrorAction Stop | Out-Null
            Write-OK "Firewall rule added: $ruleName (Inbound $proto 514)"
        } catch {
            Write-Warn "Could not add $ruleName : $_"
            Write-Info "  Add manually (run as Administrator):"
            Write-Info "  New-NetFirewallRule -DisplayName '$ruleName' -Direction Inbound -Protocol $proto -LocalPort 514 -Action Allow"
        }
    } else {
        Write-OK "Firewall rule already exists: $ruleName"
    }
}

# ── Check container status ────────────────────────────────────────────────────

Write-Step "Checking NetDoc container status..."

# Core + workers containers (always started on fresh install).
# Monitoring/syslog/pro are optional profiles — started from UI when needed.
$ExpectedContainers = @(
    "netdoc-postgres",
    "netdoc-api",
    "netdoc-web",
    "netdoc-nginx",
    "netdoc-clickhouse",
    "netdoc-ping",
    "netdoc-snmp",
    "netdoc-cred",
    "netdoc-vuln",
    "netdoc-internet",
    "netdoc-community"
)

$maxContainerWait = 120   # total seconds to wait
$containerWaited  = 0
$allUp            = $false

Write-Host "     " -NoNewline
$dotCount = 0

while ($containerWaited -lt $maxContainerWait) {
    $running = @(docker ps --filter "name=netdoc" --filter "status=running" `
                   --format "{{.Names}}" 2>&1 |
               Where-Object { $_ -ne "" })

    $notUp = $ExpectedContainers | Where-Object { $running -notcontains $_ }

    if ($notUp.Count -eq 0) {
        $allUp = $true
        break
    }

    Write-Host "." -NoNewline -ForegroundColor DarkGray
    $dotCount++
    if ($dotCount % 30 -eq 0) { Write-Host "" ; Write-Host "     " -NoNewline }

    Start-Sleep -Seconds 3
    $containerWaited += 3
}

Write-Host ""

# Display status of each container
$running = @(docker ps --filter "name=netdoc" --format "{{.Names}}" 2>&1 |
             Where-Object { $_ -ne "" })

foreach ($c in $ExpectedContainers) {
    if ($running -contains $c) {
        Write-OK $c
    } else {
        Write-Fail "$c  -  not running!"
    }
}

if (-not $allUp) {
    $notUp = $ExpectedContainers | Where-Object { $running -notcontains $_ }
    Write-Host ""
    Write-Warn "The following containers did not start within $maxContainerWait s:"
    foreach ($c in $notUp) { Write-Info "  - $c" }
    Write-Info "Check logs: docker logs $($notUp[0])"
    Write-Info "Or use: powershell -File netdoc_docker.ps1 -> option [6]"
}

# ── Wait for Web Panel ────────────────────────────────────────────────────────

Write-Step "Waiting for Web Panel to become available (http://localhost)..."

$webReady = $false
$maxWait  = 60
$waited   = 0
$dotCount = 0

Write-Host "     " -NoNewline

while ($waited -lt $maxWait) {
    try {
        $r = Invoke-WebRequest -Uri "http://localhost/" -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
        if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 400) {
            $webReady = $true
            break
        }
    } catch {}

    Write-Host "." -NoNewline -ForegroundColor DarkGray
    $dotCount++
    if ($dotCount % 30 -eq 0) { Write-Host "" ; Write-Host "     " -NoNewline }

    Start-Sleep -Seconds 2
    $waited += 2
}

Write-Host ""

if ($webReady) {
    Write-OK "Web Panel is available!"
    Write-Host ""
    Write-Host "  Opening Devices tab in browser..." -ForegroundColor Cyan
    Write-Info "  (devices will appear automatically after the first scan completes)"
    Start-Process "http://localhost/devices"
} else {
    Write-Warn "Web Panel did not respond within $maxWait seconds."
    Write-Info "Check logs: docker logs netdoc-web"
}

# ── Check API ────────────────────────────────────────────────────────────────

try {
    $apiR = Invoke-WebRequest -Uri "http://localhost:8000/api/devices/?limit=1" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    Write-OK "API available (HTTP $($apiR.StatusCode))"
} catch {
    Write-Warn "API (port 8000) not responding  -  check logs: docker logs netdoc-api"
}

# ── Podsumowanie ─────────────────────────────────────────────────────────────

Write-Host ""
if ($allUp -and $webReady) {
    Write-Host "  ================================================" -ForegroundColor Cyan
    Write-Host "   NetDoc is ready!" -ForegroundColor Green
    Write-Host "  ================================================" -ForegroundColor Cyan
} else {
    Write-Host "  ================================================" -ForegroundColor Cyan
    Write-Host "   NetDoc started (with warnings)" -ForegroundColor Yellow
    Write-Host "  ================================================" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "   Panel Admin   http://localhost" -ForegroundColor White
Write-Host "   API           http://localhost:8000/docs" -ForegroundColor White
Write-Host "   Grafana        http://localhost/grafana   (admin / netdoc)" -ForegroundColor White
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Cyan
Write-Host "   1. First network scan:" -ForegroundColor White
Write-Host "      $pythonCmd run_scanner.py --once" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   2. Docker management:" -ForegroundColor White
Write-Host "      powershell -ExecutionPolicy Bypass -File netdoc_docker.ps1" -ForegroundColor DarkGray
Write-Host ""

# ── First network scan ────────────────────────────────────────────────────────

if ($allUp -and $pythonCmd) {
    Write-Step "Running first network scan..."
    Write-Info "Scanner will discover devices on the local network (ping + nmap + ARP)."
    Write-Info "Results will appear in the panel within 2-5 minutes."
    Write-Host ""

    # Update Python path in install_autostart.ps1 if it has a hardcoded value
    $autostartFile = Join-Path $ProjectDir "install_autostart.ps1"
    if ((Test-Path $autostartFile) -and $pythonPath) {
        $autostartContent = Get-Content $autostartFile -Raw
        $updated = $autostartContent -replace '\$PythonExe\s*=\s*"[^"]*"', "`$PythonExe       = `"$pythonPath`""
        if ($updated -ne $autostartContent) {
            Set-Content $autostartFile -Value $updated -Encoding UTF8 -NoNewline
            Write-OK "Updated Python path in install_autostart.ps1: $pythonPath"
        }
    }

    $scanScript = Join-Path $ProjectDir "run_scanner.py"
    if (Test-Path $scanScript) {
        $env:PYTHONUNBUFFERED = "1"   # force immediate Python log flushing to transcript
        try {
            & $PythonExeResolved $scanScript --once 2>&1 | Out-Host
        } finally {
            Remove-Item -Path env:PYTHONUNBUFFERED -ErrorAction SilentlyContinue
        }
        if ($LASTEXITCODE -eq 0) {
            Write-OK "First scan completed."
        } else {
            Write-Warn "Scan completed with warning (code: $LASTEXITCODE)."
            Write-Info "You can run it again: $pythonCmd run_scanner.py --once"
        }
    } else {
        Write-Warn "run_scanner.py not found  -  skipping scan."
    }
} elseif (-not $allUp) {
    Write-Warn "Skipping scan  -  not all containers are running."
} else {
    Write-Warn "Skipping scan  -  Python not available."
    Write-Info "Run manually: python run_scanner.py --once"
}

# ── Task Scheduler  -  autostart i watchdog ──────────────────────────────────

Write-Step "Registering Task Scheduler tasks (NetDocScanner + NetDoc Watchdog)..."

$autostartScript = Join-Path $ProjectDir "install_autostart.ps1"
$watchdogScript  = Join-Path $ProjectDir "install_watchdog.ps1"

if (Test-Path $autostartScript) {
    & powershell.exe -NonInteractive -ExecutionPolicy Bypass -File $autostartScript 2>&1 | Out-Host
    if ($LASTEXITCODE -eq 0) {
        Write-OK "Task 'NetDocScanner' registered in Task Scheduler."
    } else {
        Write-Warn "Failed to register 'NetDocScanner'  -  run manually: install_autostart.ps1"
    }
} else {
    Write-Warn "install_autostart.ps1 not found  -  skipping scanner registration."
}

if (Test-Path $watchdogScript) {
    & powershell.exe -NonInteractive -ExecutionPolicy Bypass -File $watchdogScript 2>&1 | Out-Host
    if ($LASTEXITCODE -eq 0) {
        Write-OK "Task 'NetDoc Watchdog' registered in Task Scheduler."
    } else {
        Write-Warn "Failed to register 'NetDoc Watchdog'  -  run manually: install_watchdog.ps1"
    }
} else {
    Write-Warn "install_watchdog.ps1 not found  -  skipping watchdog registration."
}

$relayScript = Join-Path $ProjectDir "install_syslog_relay.ps1"
if (Test-Path $relayScript) {
    & powershell.exe -NonInteractive -ExecutionPolicy Bypass -File $relayScript 2>&1 | Out-Host
    if ($LASTEXITCODE -eq 0) {
        Write-OK "Task 'NetDocSyslogRelay' registered in Task Scheduler."
        Start-ScheduledTask -TaskName "NetDocSyslogRelay" -ErrorAction SilentlyContinue
        Write-OK "Syslog Relay started  -  real device IPs will be preserved in ClickHouse."
    } else {
        Write-Warn "Failed to register 'NetDocSyslogRelay'  -  run manually: install_syslog_relay.ps1"
    }
} else {
    Write-Warn "install_syslog_relay.ps1 not found  -  skipping relay registration."
}


Write-Host ""
Write-Host "  Debug log saved to:" -ForegroundColor DarkGray
Write-Host "  $LogFile" -ForegroundColor DarkGray
Write-Host "  (attach when reporting issues)" -ForegroundColor DarkGray
Write-Host ""

Stop-Transcript | Out-Null

Show-Pause "Press Enter to close the installer..."
