# install_syslog_relay.ps1
# Registers NetDoc Syslog Relay as a Windows Task Scheduler task.
# Run as Administrator: powershell -ExecutionPolicy Bypass -File install_syslog_relay.ps1
#
# The relay listens on UDP 514 (host-side, before Docker NAT) and forwards
# syslog messages to Docker rsyslog on UDP localhost:5140 with the real
# sender IP encoded in the syslog HOSTNAME field.

$TaskName   = "NetDocSyslogRelay"
$ScriptPath = Join-Path $PSScriptRoot "run_syslog_relay.py"
$WorkingDir = $PSScriptRoot

# Resolve Python — prefer pythonw.exe (no console window) over python.exe
$_venvPythonW = Join-Path $PSScriptRoot ".venv\Scripts\pythonw.exe"
$_venvPython  = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (Test-Path $_venvPythonW) {
    $PythonExe = $_venvPythonW
} elseif (Test-Path $_venvPython) {
    $PythonExe = $_venvPython
} else {
    # No venv — look in PATH, prefer pythonw
    $PythonCmd = Get-Command pythonw -ErrorAction SilentlyContinue
    if ($PythonCmd) {
        $PythonExe = $PythonCmd.Source
    } else {
        $PythonCmd = Get-Command python -ErrorAction SilentlyContinue
        if ($PythonCmd) { $PythonExe = $PythonCmd.Source } else { $PythonExe = $null }
    }
    if (-not $PythonExe) {
        Write-Host "ERROR: Python not found in PATH and no .venv present." -ForegroundColor Red
        exit 1
    }
}

if (-not (Test-Path $ScriptPath)) {
    Write-Host "ERROR: run_syslog_relay.py not found at: $ScriptPath" -ForegroundColor Red
    exit 1
}

Write-Host "Registering task: $TaskName"
Write-Host "Script : $ScriptPath"
Write-Host "Python : $PythonExe"

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

$Action = New-ScheduledTaskAction `
    -Execute $PythonExe `
    -Argument "-u `"$ScriptPath`"" `
    -WorkingDirectory $WorkingDir

$Trigger = New-ScheduledTaskTrigger -AtLogOn

$Settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit      (New-TimeSpan -Minutes 0) `
    -MultipleInstances       IgnoreNew `
    -StartWhenAvailable `
    -DontStopIfGoingOnBatteries `
    -AllowStartIfOnBatteries `
    -RestartCount            5 `
    -RestartInterval         (New-TimeSpan -Minutes 1)

$Principal = New-ScheduledTaskPrincipal `
    -UserId    $env:USERNAME `
    -LogonType Interactive `
    -RunLevel  Highest

$Task = Register-ScheduledTask `
    -TaskName   $TaskName `
    -Action     $Action `
    -Trigger    $Trigger `
    -Settings   $Settings `
    -Principal  $Principal `
    -Description "NetDoc Syslog Relay - preserves real device IPs before Docker NAT"

if ($Task) {
    Write-Host ""
    Write-Host "OK - Task '$TaskName' registered." -ForegroundColor Green
    Write-Host "   Listens : UDP 0.0.0.0:514  (network devices)"
    Write-Host "   Forwards: UDP 127.0.0.1:5140 (Docker rsyslog relay input)"
    Write-Host ""
    Write-Host "Start now (no restart required):"
    Write-Host "  Start-ScheduledTask -TaskName $TaskName"
    Write-Host ""
    Write-Host "Stop:"
    Write-Host "  Stop-ScheduledTask -TaskName $TaskName"
    Write-Host ""
    Write-Host "Remove:"
    Write-Host "  Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false"
} else {
    Write-Host "ERROR: task registration failed." -ForegroundColor Red
    exit 1
}
