# install_watchdog.ps1
# Rejestruje NetDoc Watchdog jako zadanie Task Scheduler (co 5 minut).
# Uruchom jako Administrator.

$TaskName    = "NetDoc Watchdog"
$ScriptPath  = Join-Path $PSScriptRoot "netdoc_watchdog.ps1"
$Description = "Sprawdza co 5 minut czy kontenery Docker NetDoc dzialaja i uruchamia brakujace."

if (-not (Test-Path $ScriptPath)) {
    Write-Error "Nie znaleziono: $ScriptPath"
    exit 1
}

# Usun stare zadanie jesli istnieje
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

$action  = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`" -Quiet"

# Wyzwalacz: co 5 minut, przez nieskonczona ilosc czasu
$trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 4) `
    -MultipleInstances IgnoreNew `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable:$false

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

$task = Register-ScheduledTask `
    -TaskName    $TaskName `
    -Action      $action `
    -Trigger     $trigger `
    -Settings    $settings `
    -Principal   $principal `
    -Description $Description `
    -Force

if ($task) {
    Write-Host "OK: Zadanie '$TaskName' zarejestrowane." -ForegroundColor Green
    Write-Host "    Skrypt: $ScriptPath" -ForegroundColor DarkGray
    Write-Host "    Interval: co 5 minut, konto: SYSTEM" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Aby odinstalowac:"  -ForegroundColor Yellow
    Write-Host "  Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false" -ForegroundColor Yellow
} else {
    Write-Error "Blad rejestracji zadania."
}
