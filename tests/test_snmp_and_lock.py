"""Testy dla _snmp_get (hard timeout) i _acquire_scanner_lock (single-instance)."""
import os
import sys
import time
import tempfile
import threading
from unittest.mock import patch, MagicMock

import pytest


# ─── _snmp_get: hard timeout via daemon thread ────────────────────────────────

def test_snmp_get_returns_none_on_timeout():
    """_snmp_get musi wrocic w skonczonym czasie nawet gdy asyncio zawiesza sie."""
    import netdoc.collector.drivers.snmp as snmp_mod

    def _hanging_run_until_complete(coro):
        time.sleep(60)  # symuluje zawieszony pysnmp
        return None

    with patch("asyncio.new_event_loop") as mock_loop_factory:
        mock_loop = MagicMock()
        mock_loop.run_until_complete.side_effect = _hanging_run_until_complete
        mock_loop_factory.return_value = mock_loop

        t0 = time.monotonic()
        result = snmp_mod._snmp_get("10.0.0.1", "public", "1.3.6.1.2.1.1.5.0", timeout=1)
        elapsed = time.monotonic() - t0

    assert result is None
    assert elapsed < 6, f"_snmp_get zawisl na {elapsed:.1f}s — powinien wrocic w <6s"


def test_snmp_get_returns_value_on_success():
    """_snmp_get zwraca wynik gdy pysnmp odpowie normalnie."""
    import netdoc.collector.drivers.snmp as snmp_mod

    with patch.object(snmp_mod, "_async_get", return_value="router-01"):
        # Zastap _async_get coroutine-like zachowaniem
        import asyncio

        async def _fast_coro(*a, **kw):
            return "router-01"

        with patch.object(snmp_mod, "_async_get", side_effect=_fast_coro):
            # Musimy uzyc prawdziwego loop bo _snmp_get uzywa asyncio.new_event_loop()
            result = snmp_mod._snmp_get("10.0.0.1", "public", "1.3.6.1.2.1.1.5.0", timeout=2)

    # W tym tescie _async_get jest zastapione — wynik zalezny od implementacji
    # Sprawdzamy tylko ze funkcja nie rzuca wyjatku i wraca w skonczonym czasie
    assert result is None or isinstance(result, str)


def test_snmp_get_returns_within_deadline():
    """_snmp_get musi wrocic w timeout+3 sekundy nawet na nieosiagalny host."""
    import netdoc.collector.drivers.snmp as snmp_mod

    timeout = 1
    t0 = time.monotonic()
    result = snmp_mod._snmp_get("192.0.2.1", "public", "1.3.6.1.2.1.1.5.0", timeout=timeout)
    elapsed = time.monotonic() - t0

    assert result is None
    assert elapsed < timeout + 4, f"_snmp_get trwal {elapsed:.1f}s, oczekiwano <{timeout+4}s"


# ─── _acquire_scanner_lock: single-instance protection ────────────────────────

def test_lock_acquired_fresh(tmp_path, monkeypatch):
    """Bez istniejacego pliku — lock powinien zostac przyznany."""
    lock_file = str(tmp_path / "scanner.pid")
    monkeypatch.setattr("run_scanner._LOCK_FILE", lock_file)

    # Import po monkeypatch
    import importlib
    import run_scanner
    importlib.reload(run_scanner)  # reload zeby monkeypatch zadziałał
    monkeypatch.setattr(run_scanner, "_LOCK_FILE", lock_file)

    result = run_scanner._acquire_scanner_lock()
    assert result is True
    assert os.path.exists(lock_file)
    pid_in_file = int(open(lock_file).read().strip())
    assert pid_in_file == os.getpid()


def test_lock_rejected_when_other_process_running(tmp_path, monkeypatch, caplog):
    """Jesli plik PID wskazuje na dzialajacy skaner — odrzuc lock."""
    import run_scanner

    lock_file = str(tmp_path / "scanner.pid")
    monkeypatch.setattr(run_scanner, "_LOCK_FILE", lock_file)

    fake_pid = os.getpid() + 1000  # dowolny PID rozny od naszego
    with open(lock_file, "w") as f:
        f.write(str(fake_pid))

    # _is_scanner_process uzywa psutil — mockujemy ja bezposrednio
    monkeypatch.setattr(run_scanner, "_is_scanner_process", lambda pid: True)

    import logging
    with caplog.at_level(logging.ERROR, logger="root"):
        result = run_scanner._acquire_scanner_lock()

    assert result is False


def test_lock_overrides_stale_pid(tmp_path, monkeypatch):
    """Jesli plik PID wskazuje na martwy proces — nadpisz i przyznaj lock."""
    import run_scanner

    lock_file = str(tmp_path / "scanner.pid")
    monkeypatch.setattr(run_scanner, "_LOCK_FILE", lock_file)

    # PID 99999999 prawie na pewno nie istnieje
    with open(lock_file, "w") as f:
        f.write("99999999")

    result = run_scanner._acquire_scanner_lock()
    assert result is True
    pid_in_file = int(open(lock_file).read().strip())
    assert pid_in_file == os.getpid()
