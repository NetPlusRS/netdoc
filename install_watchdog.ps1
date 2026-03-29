# install_watchdog.ps1
# Registers NetDoc Watchdog as a Task Scheduler task (every 5 minutes).
# Run as Administrator.

$TaskName    = "NetDoc Watchdog"
$ScriptPath  = Join-Path $PSScriptRoot "netdoc_watchdog.ps1"
$Description = "Checks every 5 minutes whether NetDoc Docker containers are running and starts any missing ones."

if (-not (Test-Path $ScriptPath)) {
    Write-Error "File not found: $ScriptPath"
    exit 1
}

# Remove old task if it exists
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

$action  = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`" -Quiet"

# Trigger: every 5 minutes, indefinitely
$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5) `
    -RepetitionDuration (New-TimeSpan -Days 3650)

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 4) `
    -MultipleInstances IgnoreNew `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable:$false `
    -DontStopIfGoingOnBatteries `
    -AllowStartIfOnBatteries

$principal = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -LogonType Interactive `
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
    Write-Host "OK: Task '$TaskName' registered." -ForegroundColor Green
    Write-Host "    Script: $ScriptPath" -ForegroundColor DarkGray
    Write-Host "    Interval: every 5 minutes, account: $env:USERNAME" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "To uninstall:"  -ForegroundColor Yellow
    Write-Host "  Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false" -ForegroundColor Yellow
} else {
    Write-Error "Task registration failed."
}
