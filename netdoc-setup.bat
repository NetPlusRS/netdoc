@echo off
:: NetDoc — Windows Installer
:: Double-click to run.
:: Checks and installs WSL2, Docker Desktop, git, Python,
:: starts containers and opens the Admin Panel in the browser.

chcp 65001 >nul 2>&1

:: Check if PowerShell is available
where powershell >nul 2>&1
if errorlevel 1 (
    echo ERROR: PowerShell is not available.
    echo Install Windows PowerShell 5.1 or newer.
    pause
    exit /b 1
)

:: Launch the PowerShell setup script
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0netdoc-setup.ps1"

:: If the script finished with an error and the window would close — pause
if errorlevel 1 (
    echo.
    echo Installation finished with an error. Check the messages above.
    pause
)
