# netdoc-setup.ps1
# Pierwszy setup NetDoc na Windows.
# Sprawdza i instaluje wymagane oprogramowanie (WSL2, Docker Desktop, git, Python),
# konfiguruje srodowisko i uruchamia system.
#
# Uzycie:
#   Kliknij dwukrotnie netdoc-setup.bat
#   LUB: powershell -ExecutionPolicy Bypass -File netdoc-setup.ps1

#Requires -Version 5.1

$ErrorActionPreference = "Continue"
$ProjectDir = $PSScriptRoot

# ── Plik logu debugowania ─────────────────────────────────────────────────────

$LogTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogFile      = Join-Path $ProjectDir "netdoc-setup-debug-$LogTimestamp.log"

# Start-Transcript rejestruje WSZYSTKO — kazde polecenie, wyjscie, bledy
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

# Zrzut informacji systemowych na poczatek logu
function Write-SystemInfo {
    Write-LogSection "INFORMACJE SYSTEMOWE"
    Write-LogEntry "INFO" "Skrypt:     $PSCommandPath"
    Write-LogEntry "INFO" "Katalog:    $ProjectDir"
    Write-LogEntry "INFO" "PowerShell: $($PSVersionTable.PSVersion)"
    Write-LogEntry "INFO" "OS:         $([System.Environment]::OSVersion.VersionString)"
    Write-LogEntry "INFO" "Build:      $([System.Environment]::OSVersion.Version.Build)"
    Write-LogEntry "INFO" "Uzytkownik: $([System.Environment]::UserName)"
    Write-LogEntry "INFO" "Hostname:   $([System.Environment]::MachineName)"
    Write-LogEntry "INFO" "Arch:       $([System.Environment]::Is64BitOperatingSystem)"

    # RAM
    try {
        $ram = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $totalGB = [Math]::Round($ram.TotalVisibleMemorySize / 1MB, 1)
        $freeGB  = [Math]::Round($ram.FreePhysicalMemory     / 1MB, 1)
        Write-LogEntry "INFO" "RAM:        ${totalGB} GB total, ${freeGB} GB free"
    } catch { Write-LogEntry "WARN" "RAM: nie udalo sie pobrac" }

    # Dysk C:
    try {
        $disk = Get-PSDrive C -ErrorAction Stop
        $freeGB = [Math]::Round($disk.Free / 1GB, 1)
        $usedGB = [Math]::Round($disk.Used / 1GB, 1)
        Write-LogEntry "INFO" "Dysk C:     ${usedGB} GB uzyte, ${freeGB} GB wolne"
    } catch { Write-LogEntry "WARN" "Dysk: nie udalo sie pobrac" }

    # PATH
    Write-LogEntry "INFO" "PATH:"
    ($env:PATH -split ";") | ForEach-Object { Write-LogEntry "PATH" "  $_" }

    Write-LogSection "ROZPOCZECIE INSTALACJI"
}

# ── Kolory / formatowanie ─────────────────────────────────────────────────────

function Write-Header {
    Clear-Host
    Write-Host ""
    Write-Host "  ================================================" -ForegroundColor Cyan
    Write-Host "   NetDoc — Instalator Windows" -ForegroundColor Cyan
    Write-Host "  ================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "  >> $msg" -ForegroundColor Cyan
    # W pliku logu: widoczna sekcja z timestampem
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
    Write-Host "     [BLAD] $msg" -ForegroundColor Red
    Write-LogEntry "FAIL" $msg
}

function Write-Info([string]$msg) {
    Write-Host "           $msg" -ForegroundColor DarkGray
    Write-LogEntry "INFO" $msg
}

function Show-Pause([string]$msg = "Nacisnij Enter aby kontynuowac...") {
    Write-Host ""
    Write-Host "  $msg" -ForegroundColor DarkGray
    Read-Host | Out-Null
}

# ── Sprawdz czy jest Administrator ───────────────────────────────────────────

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

Write-Header
Write-Host "  Katalog projektu: $ProjectDir" -ForegroundColor DarkGray
Write-Host "  Log debugowania:  $LogFile" -ForegroundColor DarkGray
Write-Host ""

Write-SystemInfo

if (-not $isAdmin) {
    Write-Warn "Skrypt nie jest uruchomiony jako Administrator."
    Write-Info "Niektorych operacji (WSL2, winget system-wide) moze nie byc mozna wykonac."
    Write-Info "Jesli instalacja sie zatrzyma, uruchom ponownie: Prawy klik -> Uruchom jako administrator"
    Write-Host ""
}

# ── Wersja Windows ───────────────────────────────────────────────────────────

Write-Step "Sprawdzam wersje systemu Windows..."

$winver = [System.Environment]::OSVersion.Version
$build  = $winver.Build
Write-Info "Windows Build: $build"

if ($build -lt 19041) {
    Write-Fail "Wymagany Windows 10 v2004 (Build 19041) lub nowszy."
    Write-Info "Twoja wersja ($build) jest zbyt stara — zaktualizuj system."
    Show-Pause "Nacisnij Enter aby zamknac..."
    exit 1
} else {
    Write-OK "Windows $($winver.Major).$($winver.Minor) Build $build — OK"
}

# ── winget ───────────────────────────────────────────────────────────────────

Write-Step "Sprawdzam winget (Windows Package Manager)..."

$wingetPath = Get-Command winget -ErrorAction SilentlyContinue
if ($wingetPath) {
    $wingetVer = (winget --version 2>&1) -replace "[^0-9\.]", ""
    Write-OK "winget $wingetVer"
} else {
    Write-Warn "winget nie jest dostepny."
    Write-Info "Zainstaluj 'App Installer' z Microsoft Store:"
    Write-Info "  https://apps.microsoft.com/detail/9NBLGGH4NNS1"
    Write-Info "  LUB zaktualizuj Windows — winget jest domyslnie od Windows 10 21H1"
    Show-Pause "Nacisnij Enter po zainstalowaniu winget..."
    $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $wingetPath) {
        Write-Fail "winget nadal niedostepny. Instalacja przerwana."
        exit 1
    }
}

# ── Funkcja instalacji przez winget ──────────────────────────────────────────

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
            Write-OK "$Label zainstalowany: $ver"
            return $true
        }
    }

    Write-Warn "$Label nie znaleziony — instaluje przez winget..."
    Write-Info "  winget install -e --id $Id --accept-package-agreements --accept-source-agreements"
    winget install -e --id $Id --accept-package-agreements --accept-source-agreements 2>&1 | Out-Host

    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1978335189) {
        # -1978335189 = juz zainstalowany (WINGET_INSTALLED_STATUS_ALREADY_INSTALLED)
        Write-OK "$Label zainstalowany pomyslnie."
        return $true
    } else {
        Write-Fail "Instalacja $Label nie powiodla sie (kod: $LASTEXITCODE)."
        return $false
    }
}

# ── git ──────────────────────────────────────────────────────────────────────

Write-Step "Sprawdzam git..."

$gitOk = Install-WithWinget -Id "Git.Git" -Label "git" -CommandCheck "git"
if (-not $gitOk) {
    # Moze byc zainstalowany ale nie w PATH — sprawdz typowe lokalizacje
    $gitPaths = @(
        "C:\Program Files\Git\cmd\git.exe",
        "C:\Program Files (x86)\Git\cmd\git.exe"
    )
    foreach ($p in $gitPaths) {
        if (Test-Path $p) {
            Write-OK "git znaleziony: $p"
            $gitOk = $true
            # Odswierz PATH w tej sesji
            $env:PATH += ";$(Split-Path $p)"
            break
        }
    }
    if (-not $gitOk) {
        Write-Warn "git nie jest dostepny. Mozesz kontynuowac jesli repo jest juz pobrane."
    }
}

# ── Python ───────────────────────────────────────────────────────────────────

Write-Step "Sprawdzam Python 3.11+ (wymagany przez NetDoc)..."

# Minimalna wersja wymagana przez NetDoc (zgodna z obrazem Docker python:3.11-slim)
$MIN_PY_MAJOR = 3
$MIN_PY_MINOR = 11

function Get-PythonMinorVersion([string]$cmd) {
    try {
        $out = (& $cmd --version 2>&1) | Select-Object -First 1   # "Python 3.11.9"
        if ($out -match "Python (\d+)\.(\d+)") {
            return [int]$Matches[1] * 100 + [int]$Matches[2]   # np. 311
        }
    } catch {}
    return 0
}

$MIN_PY_CODE = $MIN_PY_MAJOR * 100 + $MIN_PY_MINOR   # 311

$pythonCmd  = $null
$pythonPath = $null

foreach ($cmd in @("python", "python3", "py")) {
    $c = Get-Command $cmd -ErrorAction SilentlyContinue
    if (-not $c) { continue }

    $verCode = Get-PythonMinorVersion $cmd
    $verStr  = try { (& $cmd --version 2>&1) | Select-Object -First 1 } catch { "?" }

    if ($verCode -ge $MIN_PY_CODE) {
        Write-OK "$verStr (komenda: $cmd)"
        $pythonCmd  = $cmd
        $pythonPath = $c.Source
        break
    } elseif ($verCode -gt 0) {
        Write-Warn "$verStr — za stary (wymagany Python $MIN_PY_MAJOR.$MIN_PY_MINOR+)"
    }
}

if (-not $pythonCmd) {
    Write-Warn "Python $MIN_PY_MAJOR.$MIN_PY_MINOR+ nie znaleziony — instaluje Python 3.12..."
    Install-WithWinget -Id "Python.Python.3.12" -Label "Python 3.12" | Out-Null

    # Odswierz PATH po instalacji
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH", "User")

    foreach ($cmd in @("python", "python3", "py")) {
        $c = Get-Command $cmd -ErrorAction SilentlyContinue
        if (-not $c) { continue }

        $verCode = Get-PythonMinorVersion $cmd
        $verStr  = try { (& $cmd --version 2>&1) | Select-Object -First 1 } catch { "?" }

        if ($verCode -ge $MIN_PY_CODE) {
            Write-OK "Python gotowy: $verStr"
            $pythonCmd  = $cmd
            $pythonPath = $c.Source
            break
        }
    }

    if (-not $pythonCmd) {
        Write-Warn "Python nie jest dostepny w PATH — moze byc wymagany restart terminala."
        Write-Info "Po restarcie uruchom ponownie ten skrypt."
        $pythonCmd  = "python"
        $pythonPath = $null
    }
}

# Zapamietaj sciezke do Pythona — potrzebna dla install_autostart.ps1
$PythonExeResolved = if ($pythonPath) { $pythonPath } else { "python" }

# ── WSL2 ─────────────────────────────────────────────────────────────────────

Write-Step "Sprawdzam WSL2 (wymagany przez Docker Desktop)..."

$wslOk = $false

# Metoda 1: wsl --status (jezyk-niezalezne: exit code 0 = WSL zainstalowany)
try {
    wsl --status 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-OK "WSL2 jest juz zainstalowany."
        $wslOk = $true
    }
} catch {}

# Metoda 2: wsl --list (bardziej kompatybilna ze starszymi wersjami)
if (-not $wslOk) {
    try {
        $wslListOut = wsl --list 2>&1
        if ($LASTEXITCODE -eq 0) {
            # Sprawdz czy jest jakas dystrybucja (nie tylko naglowek)
            $distros = $wslListOut | Where-Object {
                $_ -ne "" -and $_ -notmatch "^\s*$"
            }
            if ($distros.Count -gt 1) {
                # > 1 linia = naglowek + przynajmniej 1 dystrybucja
                Write-OK "WSL jest zainstalowany z dystrybucja Linux."
                Write-Info "Wymuszam WSL2 jako domyslny..."
                if ($isAdmin) {
                    wsl --set-default-version 2 2>&1 | Out-Null
                }
                $wslOk = $true
            } else {
                Write-Warn "WSL zainstalowany ale brak dystrybucji Linux."
                Write-Info "Docker Desktop moze zainstalowac dystrybucje automatycznie."
                $wslOk = $true   # nie blokujemy — Docker Desktop obsluzy reszte
            }
        }
    } catch {}
}

if (-not $wslOk) {
    Write-Warn "WSL2 nie jest zainstalowany."

    if ($isAdmin) {
        Write-Info "Instaluje WSL2 (moze wymagac restartu)..."
        Write-Info "  Wlaczam funkcje Windows Subsystem for Linux..."
        dism /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart 2>&1 | Out-Null
        Write-Info "  Wlaczam Virtual Machine Platform..."
        dism /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart 2>&1 | Out-Null
        Write-Info "  Ustawiam WSL2 jako domyslny..."
        wsl --set-default-version 2 2>&1 | Out-Null
        Write-Info "  Instaluje jadro Linux..."
        wsl --install --no-launch 2>&1 | Out-Null

        Write-Warn "WSL2 zainstalowany — wymagany RESTART systemu."
        Write-Info "Po restarcie uruchom ponownie ten skrypt."
        Write-Host ""
        $restartNow = Read-Host "  Restartowac teraz? [T/N]"
        if ($restartNow -eq "T" -or $restartNow -eq "t") {
            Write-Info "Zamykam log i restartuję system..."
            Stop-Transcript | Out-Null   # zamknij log przed restartem
            Restart-Computer -Force
        }
        Write-Info "Pamietaj o restarcie przed uruchomieniem Docker Desktop."
    } else {
        Write-Info "Uruchom PowerShell jako Administrator i wpisz:"
        Write-Info "  wsl --install"
        Write-Info "  Nastepnie zrestartuj komputer."
        Write-Warn "Bez WSL2 Docker Desktop moze nie dzialac."
    }
}

# ── Docker Desktop ────────────────────────────────────────────────────────────

Write-Step "Sprawdzam Docker Desktop..."

$dockerCli = Get-Command docker -ErrorAction SilentlyContinue
$dockerInstalled = $false

if ($dockerCli) {
    $dockerInstalled = $true
    $dver = try { (docker --version 2>&1) } catch { "?" }
    Write-OK "Docker CLI: $dver"
} else {
    # Sprawdz typowe lokalizacje Docker Desktop
    $dockerPaths = @(
        "$env:ProgramFiles\Docker\Docker\resources\bin\docker.exe",
        "$env:LOCALAPPDATA\Docker\Docker\resources\bin\docker.exe"
    )
    foreach ($p in $dockerPaths) {
        if (Test-Path $p) {
            Write-OK "Docker CLI znaleziony: $p"
            $env:PATH += ";$(Split-Path $p)"
            $dockerInstalled = $true
            break
        }
    }
}

if (-not $dockerInstalled) {
    Write-Warn "Docker Desktop nie jest zainstalowany — instaluje..."
    $ok = Install-WithWinget -Id "Docker.DockerDesktop" -Label "Docker Desktop"

    if ($ok) {
        Write-Info "Docker Desktop zainstalowany."

        # Odswierz PATH — winget dodaje Docker do PATH ale nie w biezacej sesji
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH", "User")

        # Dodaj znane lokalizacje Docker jesli nie sa jeszcze w PATH
        foreach ($dockerBinPath in @(
            "$env:ProgramFiles\Docker\Docker\resources\bin",
            "$env:LOCALAPPDATA\Docker\Docker\resources\bin"
        )) {
            if ((Test-Path $dockerBinPath) -and ($env:PATH -notlike "*$dockerBinPath*")) {
                $env:PATH += ";$dockerBinPath"
                Write-Info "Dodano do PATH: $dockerBinPath"
            }
        }

        Write-Info "Uruchamiam Docker Desktop — poczekaj az ikonka w zasobniku bedzie gotowa..."
        $dockerApp = "${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe"
        if (Test-Path $dockerApp) {
            Start-Process $dockerApp
        }
    } else {
        Write-Fail "Nie udalo sie zainstalowac Docker Desktop."
        Write-Info "Pobierz recznie: https://www.docker.com/products/docker-desktop/"
        Show-Pause "Nacisnij Enter po recznie zainstalowanym Docker Desktop..."
    }
}

# ── Poczekaj az Docker daemon odpowie ─────────────────────────────────────────

Write-Step "Czekam az Docker daemon bedzie gotowy..."

$dockerReady = $false
$maxWait     = 120   # sekund
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
    Write-Fail "Docker daemon nie odpowiada po $maxWait sekundach."
    Write-Info "Upewnij sie ze Docker Desktop jest uruchomiony (ikonka w zasobniku)."
    Write-Info "Nastepnie uruchom ponownie ten skrypt."
    Show-Pause "Nacisnij Enter aby zamknac..."
    exit 1
} else {
    Write-OK "Docker daemon dziala."
}

# ── .env ─────────────────────────────────────────────────────────────────────

Write-Step "Sprawdzam konfiguracje .env..."

$envFile    = Join-Path $ProjectDir ".env"
$envExample = Join-Path $ProjectDir ".env.example"

if (Test-Path $envFile) {
    Write-OK ".env juz istnieje — pomijam kopiowanie."
} elseif (Test-Path $envExample) {
    Copy-Item $envExample $envFile
    Write-OK ".env skopiowany z .env.example"
    Write-Info "Mozesz edytowac $envFile aby dostosowac konfiguracje."
} else {
    Write-Warn "Brak .env.example — tworze minimalny .env..."
    @"
# NetDoc konfiguracja — wygenerowany automatycznie przez setup
# Polaczenie z PostgreSQL z HOSTA (port 15432 = zewnetrzny port kontenera)
DB_HOST=localhost
DB_PORT=15432
DB_NAME=netdoc
DB_USER=netdoc
DB_PASSWORD=netdoc
# Adres bindowania API uvicorn (nie URL — nie dodawaj http://)
API_HOST=0.0.0.0
API_PORT=8000
NETWORK_RANGES=
LOG_LEVEL=INFO
"@ | Set-Content $envFile -Encoding UTF8
    Write-OK ".env utworzony z domyslnymi wartosciami."
}

# ── Python requirements (host-side) ───────────────────────────────────────────

Write-Step "Instaluje zaleznosci Python (dla skanera na hoscie)..."

$reqFile = Join-Path $ProjectDir "requirements.txt"
if ((Test-Path $reqFile) -and $pythonCmd) {
    Write-Info "  $PythonExeResolved -m pip install -r requirements.txt --quiet"
    & $PythonExeResolved -m pip install -r $reqFile --quiet 2>&1 | Out-Host
    if ($LASTEXITCODE -eq 0) {
        Write-OK "Zaleznosci zainstalowane."
    } else {
        Write-Warn "pip install zakonczyl sie z bledem — sprawdz logi powyzej."
    }
} else {
    Write-Info "Pomijam (brak requirements.txt lub Python niedostepny)."
}

# ── docker compose up ─────────────────────────────────────────────────────────

Write-Step "Uruchamiam kontenery Docker (docker compose up -d --build)..."
Write-Info "Pierwsze uruchomienie moze zajac kilka minut — pobieranie obrazow bazowych."
Write-Host ""
Write-Warn "WAZNE — wymagane ustawienia Docker Desktop przed uruchomieniem:"
Write-Info "  1. Docker Desktop -> Settings -> Advanced:"
Write-Info "     Wlacz: 'Allow the default Docker socket to be used (requires password)'"
Write-Info "     (wymagane przez serwis web i promtail — dostep do /var/run/docker.sock)"
Write-Info "  2. Kontenery api i ping-worker wymagaja uprawnien NET_RAW (ICMP ping)."
Write-Info "     Docker Desktop na Windows obsluguje to domyslnie — jesli ping nie dziala,"
Write-Info "     sprawdz ustawienia izolacji Windows Defender Firewall dla Dockera."
Write-Host ""

Set-Location $ProjectDir
docker compose up -d --build 2>&1 | Out-Host

if ($LASTEXITCODE -ne 0) {
    Write-Fail "docker compose up zakonczyl sie bledem."
    Write-Info "Sprawdz komunikaty powyzej. Typowe przyczyny:"
    Write-Info "  - Port 5000/8000/3000 jest zajety przez inna aplikacje"
    Write-Info "  - Brak pamieci RAM (Docker wymaga min. 4 GB)"
    Write-Info "  - Docker Desktop nie jest uruchomiony"
    Write-Info "  - Brak uprawnien Docker socket: Settings -> Advanced ->"
    Write-Info "    'Allow the default Docker socket to be used'"
    Write-Info "  - Blad budowania obrazu — sprawdz dostep do internetu (pip, apt)"
    Show-Pause "Nacisnij Enter aby zamknac..."
    exit 1
}

# ── Sprawdz stan kontenerow ───────────────────────────────────────────────────

Write-Step "Sprawdzam stan kontenerow NetDoc..."

# Lista oczekiwanych kontenerow (nazwy z docker-compose.yml)
$ExpectedContainers = @(
    "netdoc-postgres",
    "netdoc-api",
    "netdoc-web",
    "netdoc-grafana",
    "netdoc-prometheus",
    "netdoc-ping",
    "netdoc-snmp",
    "netdoc-cred",
    "netdoc-vuln"
)

$maxContainerWait = 120   # sekund lacznego oczekiwania
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

# Wyswietl status kazdego kontenera
$running = @(docker ps --filter "name=netdoc" --format "{{.Names}}" 2>&1 |
             Where-Object { $_ -ne "" })

foreach ($c in $ExpectedContainers) {
    if ($running -contains $c) {
        Write-OK $c
    } else {
        Write-Fail "$c — nie dziala!"
    }
}

if (-not $allUp) {
    $notUp = $ExpectedContainers | Where-Object { $running -notcontains $_ }
    Write-Host ""
    Write-Warn "Nastepujace kontenery nie uruchomily sie w czasie $maxContainerWait s:"
    foreach ($c in $notUp) { Write-Info "  - $c" }
    Write-Info "Sprawdz logi: docker logs $($notUp[0])"
    Write-Info "Lub uzyj: powershell -File netdoc_docker.ps1 -> opcja [6]"
}

# ── Poczekaj az Panel Web odpowie ─────────────────────────────────────────────

Write-Step "Czekam az Panel Web bedzie dostepny (http://localhost:5000)..."

$webReady = $false
$maxWait  = 60
$waited   = 0
$dotCount = 0

Write-Host "     " -NoNewline

while ($waited -lt $maxWait) {
    try {
        $r = Invoke-WebRequest -Uri "http://localhost:5000/" -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
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
    Write-OK "Panel Web dostepny!"
} else {
    Write-Warn "Panel Web nie odpowiada po $maxWait sekundach."
    Write-Info "Sprawdz logi: docker logs netdoc-web"
}

# ── Sprawdz API ──────────────────────────────────────────────────────────────

try {
    $apiR = Invoke-WebRequest -Uri "http://localhost:8000/api/devices/?limit=1" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    Write-OK "API dostepne (HTTP $($apiR.StatusCode))"
} catch {
    Write-Warn "API (port 8000) nie odpowiada — sprawdz logi: docker logs netdoc-api"
}

# ── Podsumowanie ─────────────────────────────────────────────────────────────

Write-Host ""
if ($allUp -and $webReady) {
    Write-Host "  ================================================" -ForegroundColor Cyan
    Write-Host "   NetDoc jest gotowy!" -ForegroundColor Green
    Write-Host "  ================================================" -ForegroundColor Cyan
} else {
    Write-Host "  ================================================" -ForegroundColor Cyan
    Write-Host "   NetDoc uruchomiony (z ostrzezeniami)" -ForegroundColor Yellow
    Write-Host "  ================================================" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "   Panel Admin   http://localhost:5000" -ForegroundColor White
Write-Host "   API           http://localhost:8000/docs" -ForegroundColor White
Write-Host "   Grafana        http://localhost:3000   (admin / netdoc)" -ForegroundColor White
Write-Host ""
Write-Host "  Nastepne kroki:" -ForegroundColor Cyan
Write-Host "   1. Pierwsze skanowanie sieci:" -ForegroundColor White
Write-Host "      $pythonCmd run_scanner.py --once" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   2. Autostart (Task Scheduler):" -ForegroundColor White
Write-Host "      powershell -ExecutionPolicy Bypass -File install_autostart.ps1" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   3. Zarzadzanie Docker:" -ForegroundColor White
Write-Host "      powershell -ExecutionPolicy Bypass -File netdoc_docker.ps1" -ForegroundColor DarkGray
Write-Host ""

# ── Pierwsze skanowanie sieci ─────────────────────────────────────────────────

if ($allUp -and $pythonCmd) {
    Write-Step "Uruchamiam pierwsze skanowanie sieci..."
    Write-Info "Skaner wykryje urzadzenia w sieci lokalnej (ping + nmap + ARP)."
    Write-Info "Wyniki pojawia sie w panelu po 2-5 minutach."
    Write-Host ""

    # Zaktualizuj sciezke Pythona w install_autostart.ps1 jesli ma hardcoded wartosc
    $autostartFile = Join-Path $ProjectDir "install_autostart.ps1"
    if ((Test-Path $autostartFile) -and $pythonPath) {
        $autostartContent = Get-Content $autostartFile -Raw
        $updated = $autostartContent -replace '\$PythonExe\s*=\s*"[^"]*"', "`$PythonExe       = `"$pythonPath`""
        if ($updated -ne $autostartContent) {
            Set-Content $autostartFile -Value $updated -Encoding UTF8 -NoNewline
            Write-OK "Zaktualizowano sciezke Pythona w install_autostart.ps1: $pythonPath"
        }
    }

    $scanScript = Join-Path $ProjectDir "run_scanner.py"
    if (Test-Path $scanScript) {
        & $PythonExeResolved $scanScript --once 2>&1 | Out-Host
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Pierwsze skanowanie zakonczone."
        } else {
            Write-Warn "Skanowanie zakonczone z ostrzezeniem (kod: $LASTEXITCODE)."
            Write-Info "Mozesz uruchomic ponownie: $pythonCmd run_scanner.py --once"
        }
    } else {
        Write-Warn "Nie znaleziono run_scanner.py — pomijam skanowanie."
    }
} elseif (-not $allUp) {
    Write-Warn "Pomijam skanowanie — nie wszystkie kontenery sa uruchomione."
} else {
    Write-Warn "Pomijam skanowanie — Python niedostepny."
    Write-Info "Uruchom recznie: python run_scanner.py --once"
}

# ── Otworz przegladarke — tylko gdy kontenery i web sa OK ────────────────────

if ($allUp -and $webReady) {
    Write-Host ""
    Write-Host "  Otwieram Panel Admin w domyslnej przegladarce..." -ForegroundColor Cyan
    Start-Process "http://localhost:5000"
} elseif ($webReady) {
    Write-Host ""
    Write-Host "  Otwieram Panel Admin (nie wszystkie kontenery dzialaja)..." -ForegroundColor Yellow
    Start-Process "http://localhost:5000"
} else {
    Write-Warn "Przegladarki nie otwieram — Panel Web niedostepny."
    Write-Info "Sprawdz logi i sprobuj recznie: http://localhost:5000"
}

Write-Host ""
Write-Host "  Log debugowania zapisany w:" -ForegroundColor DarkGray
Write-Host "  $LogFile" -ForegroundColor DarkGray
Write-Host "  (przydatny przy zglaszaniu bledow)" -ForegroundColor DarkGray
Write-Host ""

Stop-Transcript | Out-Null

Show-Pause "Nacisnij Enter aby zamknac instalator..."
