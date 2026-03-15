# install_autostart.ps1
# Rejestruje NetDoc Scanner jako zadanie w Windows Task Scheduler.
# Uruchom jako Administrator: powershell -ExecutionPolicy Bypass -File install_autostart.ps1
#
# Tryb: --once (jednorazowy przebieg) — kazde uruchomienie to swiezy proces ladujacy aktualny kod z dysku.
# Scheduler odpala skanowanie co SCAN_INTERVAL_MIN minut.

$TaskName        = "NetDocScanner"
$PythonExe       = "C:\Python311\python.exe"
$ScriptPath      = "$PSScriptRoot\run_scanner.py"
$WorkingDir      = $PSScriptRoot
$ScanIntervalMin = 5   # co ile minut uruchamiac kolejny skan (min. 5, skan trwa ~5 min)

Write-Host "Rejestruje zadanie: $TaskName"
Write-Host "Skrypt: $ScriptPath"
Write-Host "Python: $PythonExe"
Write-Host "Tryb: --once (jednorazowy), powtarzany co $ScanIntervalMin min"

# Usun stare zadanie jesli istnieje
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Akcja: uruchom python run_scanner.py --once
$Action = New-ScheduledTaskAction `
    -Execute $PythonExe `
    -Argument "-u `"$ScriptPath`" --once" `
    -WorkingDirectory $WorkingDir

# Trigger 1: przy logowaniu (pierwsze uruchomienie po zalogowaniu)
$TriggerLogon = New-ScheduledTaskTrigger -AtLogOn

# Trigger 2: powtarzaj co ScanIntervalMin minut bez konca
# (-Once z RepetitionInterval — standardowe w PowerShell 5+)
$TriggerRepeat = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date) `
    -RepetitionInterval  (New-TimeSpan -Minutes $ScanIntervalMin) `
    -RepetitionDuration  (New-TimeSpan -Days 3650)

# Ustawienia: limit 15 min (zabij jesli zawieszony), nie startuj jesli poprzedni wciaz dziala
$Settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 0) `
    -MultipleInstances IgnoreNew `
    -StartWhenAvailable `
    -DontStopIfGoingOnBatteries `
    -AllowStartIfOnBatteries

# Aktualny uzytkownik, najwyzsze uprawnienia (nmap potrzebuje raw socket)
$Principal = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -LogonType Interactive `
    -RunLevel Highest

$Task = Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger @($TriggerLogon, $TriggerRepeat) `
    -Settings $Settings `
    -Principal $Principal `
    -Description "NetDoc network scanner - jednorazowy skan co $ScanIntervalMin min"

if ($Task) {
    Write-Host ""
    Write-Host "OK - Zadanie zarejestrowane." -ForegroundColor Green
    Write-Host ""
    Write-Host "Uruchom TERAZ (bez restartu):"
    Write-Host "  Start-ScheduledTask -TaskName NetDocScanner"
    Write-Host ""
    Write-Host "Zatrzymaj biezacy skan:"
    Write-Host "  Stop-ScheduledTask -TaskName NetDocScanner"
    Write-Host ""
    Write-Host "Usun autostart:"
    Write-Host "  Unregister-ScheduledTask -TaskName NetDocScanner -Confirm:`$false"
} else {
    Write-Host "BLAD - nie udalo sie zarejestrowac zadania." -ForegroundColor Red
}
