@echo off
cd /d "%~dp0"
python export_cli_reference.py
start "" "device_commands\cli_reference.html"
