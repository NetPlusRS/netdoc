# install_autostart.ps1
# Registers NetDoc Scanner as a Windows Task Scheduler task.
# Run as Administrator: powershell -ExecutionPolicy Bypass -File install_autostart.ps1
#
# Mode: --once (single run) — each execution is a fresh process loading the current code from disk.
# Scheduler triggers a scan every SCAN_INTERVAL_MIN minutes.

$TaskName        = "NetDocScanner"
$PythonExe       = "C:\Python311\python.exe"
$ScriptPath      = "$PSScriptRoot\run_scanner.py"
$WorkingDir      = $PSScriptRoot
$ScanIntervalMin = 5   # how often to run the next scan in minutes (min. 5, scan takes ~5 min)

Write-Host "Registering task: $TaskName"
Write-Host "Script: $ScriptPath"
Write-Host "Python: $PythonExe"
Write-Host "Mode: --once (single run), repeated every $ScanIntervalMin min"

# Remove old task if it exists
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Action: run python run_scanner.py --once
$Action = New-ScheduledTaskAction `
    -Execute $PythonExe `
    -Argument "-u `"$ScriptPath`" --once" `
    -WorkingDirectory $WorkingDir

# Trigger 1: at logon (first run after user logs in)
$TriggerLogon = New-ScheduledTaskTrigger -AtLogOn

# Trigger 2: repeat every ScanIntervalMin minutes indefinitely
# (-Once with RepetitionInterval — standard in PowerShell 5+)
$TriggerRepeat = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date) `
    -RepetitionInterval  (New-TimeSpan -Minutes $ScanIntervalMin) `
    -RepetitionDuration  (New-TimeSpan -Days 3650)

# Settings: no time limit, do not start if previous instance is still running
$Settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 0) `
    -MultipleInstances IgnoreNew `
    -StartWhenAvailable `
    -DontStopIfGoingOnBatteries `
    -AllowStartIfOnBatteries

# Current user, highest privileges (nmap requires raw socket)
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
    -Description "NetDoc network scanner - single run every $ScanIntervalMin min"

if ($Task) {
    Write-Host ""
    Write-Host "OK - Task registered." -ForegroundColor Green
    Write-Host ""
    Write-Host "Start NOW (no restart required):"
    Write-Host "  Start-ScheduledTask -TaskName NetDocScanner"
    Write-Host ""
    Write-Host "Stop current scan:"
    Write-Host "  Stop-ScheduledTask -TaskName NetDocScanner"
    Write-Host ""
    Write-Host "Remove autostart:"
    Write-Host "  Unregister-ScheduledTask -TaskName NetDocScanner -Confirm:`$false"
} else {
    Write-Host "ERROR - failed to register task." -ForegroundColor Red
}
