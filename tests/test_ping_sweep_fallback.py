"""Testy regresyjne dla TCP fallback w ping_sweep().

Weryfikuje:
- gdy nmap rzuca PortScannerError (np. brak Npcap), TCP fallback jest uzywany
- _tcp_sweep_fallback: hosty z otwartymi portami sa wykrywane
- _tcp_sweep_fallback: sieci zbyt duze (>2048 hostow) sa pomijane
- ping_sweep zwraca liste (nie rzuca wyjatku) gdy nmap niedostepny
"""
import pytest
from unittest.mock import patch, MagicMock
import nmap as nmap_lib


# ─── ping_sweep: TCP fallback gdy nmap niedostepny ───────────────────────────

def test_ping_sweep_uses_tcp_fallback_on_nmap_error():
    """Gdy nmap rzuca PortScannerError, ping_sweep uzywa TCP fallback (nie zwraca [])."""
    from netdoc.collector.discovery import ping_sweep

    with patch("nmap.PortScanner") as mock_ps:
        mock_ps.return_value.scan.side_effect = nmap_lib.PortScannerError("nmap not found")

        with patch("netdoc.collector.discovery._tcp_sweep_fallback") as mock_tcp:
            mock_tcp.return_value = ["192.168.1.1", "192.168.1.5"]

            result = ping_sweep("192.168.1.0/24")

    mock_tcp.assert_called_once_with("192.168.1.0/24")
    assert result == ["192.168.1.1", "192.168.1.5"]


def test_ping_sweep_returns_empty_list_on_unicode_error():
    """UnicodeDecodeError (np. zle kodowanie wyjscia nmap) zwraca [] bez fallback."""
    from netdoc.collector.discovery import ping_sweep

    with patch("nmap.PortScanner") as mock_ps:
        mock_ps.return_value.scan.side_effect = UnicodeDecodeError("utf-8", b"", 0, 1, "reason")

        result = ping_sweep("192.168.1.0/24")

    assert result == []


# ─── _tcp_sweep_fallback ──────────────────────────────────────────────────────

def test_tcp_sweep_fallback_detects_active_hosts():
    """Hosty z otwartym portem TCP sa zwracane przez fallback."""
    from netdoc.collector.discovery import _tcp_sweep_fallback
    import socket

    def fake_connect(addr, timeout=None):
        ip, port = addr
        if ip == "192.168.1.1" and port == 80:
            return MagicMock(__enter__=MagicMock(return_value=None), __exit__=MagicMock(return_value=False))
        raise OSError("Connection refused")

    with patch("netdoc.collector.discovery._socket.create_connection", side_effect=fake_connect):
        result = _tcp_sweep_fallback("192.168.1.0/30")

    assert "192.168.1.1" in result


def test_tcp_sweep_fallback_returns_empty_for_no_active():
    """Jezeli zadna maszyna nie odpowiada TCP, zwraca []."""
    from netdoc.collector.discovery import _tcp_sweep_fallback

    with patch("netdoc.collector.discovery._socket.create_connection", side_effect=OSError("timeout")):
        result = _tcp_sweep_fallback("10.0.0.0/30")

    assert result == []


def test_tcp_sweep_fallback_skips_too_large_network():
    """Sieci powyzej 2048 hostow sa pomijane (za dlugi skan TCP)."""
    from netdoc.collector.discovery import _tcp_sweep_fallback

    # /20 = 4094 hosts — za duza
    result = _tcp_sweep_fallback("10.0.0.0/20")

    assert result == []


def test_tcp_sweep_fallback_invalid_network():
    """Nieprawidlowy CIDR zwraca [] bez wyjatku."""
    from netdoc.collector.discovery import _tcp_sweep_fallback

    result = _tcp_sweep_fallback("not-a-network")

    assert result == []


# ─── scanner_mode wpisywany przed seedami (weryfikacja kodu) ────────────────

def test_set_status_called_before_seeds_in_source():
    """Weryfikuje ze w kodzie run_scanner.py _set_status(scanner_mode) jest przed seed_*()
    wewnatrz funkcji main() — chroni przed regresja gdzie ktos przeniesie _set_status za seedy.
    """
    from pathlib import Path
    source = Path("run_scanner.py").read_text(encoding="utf-8")

    # Wyizoluj cialo funkcji main() — szukaj od 'def main():'
    main_start = source.find("def main():")
    assert main_start != -1, "Nie znaleziono def main() w run_scanner.py"
    main_body = source[main_start:]

    set_status_idx = main_body.find('"scanner_mode": "host"')
    seed_snmp_idx  = main_body.find("seed_snmp_communities(db)")
    seed_creds_idx = main_body.find("seed_default_credentials(db)")

    assert set_status_idx != -1, 'Nie znaleziono _set_status z "scanner_mode" w main()'
    assert seed_snmp_idx  != -1, "Nie znaleziono seed_snmp_communities(db) w main()"
    assert seed_creds_idx != -1, "Nie znaleziono seed_default_credentials(db) w main()"

    assert set_status_idx < seed_snmp_idx, (
        "_set_status(scanner_mode) musi byc PRZED seed_snmp_communities — "
        "inaczej UI pokazuje 'no scanner' podczas startu"
    )
    assert set_status_idx < seed_creds_idx, (
        "_set_status(scanner_mode) musi byc PRZED seed_default_credentials — "
        "inaczej UI pokazuje 'no scanner' podczas startu"
    )
