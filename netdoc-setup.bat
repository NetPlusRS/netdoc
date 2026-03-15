@echo off
:: NetDoc — Instalator Windows
:: Kliknij dwukrotnie aby uruchomic.
:: Sprawdza i instaluje WSL2, Docker Desktop, git, Python,
:: uruchamia kontenery i otwiera Panel Admin w przegladarce.

chcp 65001 >nul 2>&1

:: Sprawdz czy PowerShell jest dostepny
where powershell >nul 2>&1
if errorlevel 1 (
    echo BLAD: PowerShell nie jest dostepny.
    echo Zainstaluj Windows PowerShell 5.1 lub nowszy.
    pause
    exit /b 1
)

:: Uruchom skrypt PowerShell
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0netdoc-setup.ps1"

:: Jesli skrypt sie zakonczyl z bledem i okno zostaloby zamkniete — zatrzymaj
if errorlevel 1 (
    echo.
    echo Instalacja zakonczyla sie z bledem. Sprawdz komunikaty powyzej.
    pause
)
