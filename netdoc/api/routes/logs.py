"""Endpoint do odczytywania logów skanera."""
import os
from fastapi import APIRouter, Query
from fastapi.responses import PlainTextResponse

router = APIRouter(prefix="/api/logs", tags=["logs"])

_LOG_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "logs"))
LOG_FILE = os.path.join(_LOG_DIR, "scanner.log")
_WATCHDOG_LOG = os.path.join(_LOG_DIR, "watchdog.log")
_CRED_LOG      = os.path.join(_LOG_DIR, "cred.log")
_BROADCAST_LOG = os.path.join(_LOG_DIR, "broadcast.log")


def _read_tail(path: str, tail: int) -> str:
    if not os.path.exists(path):
        return f"Plik {os.path.basename(path)} nie istnieje."
    try:
        # utf-8-sig automatycznie usuwa BOM (PowerShell Add-Content -Encoding UTF8 dodaje BOM)
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            lines = f.readlines()
        return "".join(lines[-tail:])
    except Exception as exc:
        return f"Błąd odczytu: {exc}"


@router.get("/scanner", response_class=PlainTextResponse)
def scanner_log(tail: int = Query(default=200, ge=10, le=2000)):
    """Zwraca ostatnie N linii pliku logs/scanner.log."""
    return _read_tail(LOG_FILE, tail)


@router.get("/watchdog", response_class=PlainTextResponse)
def watchdog_log(tail: int = Query(default=200, ge=10, le=2000)):
    """Zwraca ostatnie N linii pliku logs/watchdog.log."""
    return _read_tail(_WATCHDOG_LOG, tail)


@router.get("/cred", response_class=PlainTextResponse)
def cred_log(tail: int = Query(default=200, ge=10, le=2000)):
    """Zwraca ostatnie N linii pliku logs/cred.log."""
    return _read_tail(_CRED_LOG, tail)


@router.get("/broadcast", response_class=PlainTextResponse)
def broadcast_log(tail: int = Query(default=200, ge=10, le=2000)):
    """Zwraca ostatnie N linii pliku logs/broadcast.log."""
    return _read_tail(_BROADCAST_LOG, tail)
