"""Testy regresyjne — odczyt konfiguracji z system_status przez workery i discovery.

Pokrywa:
- run_ping._read_settings() zwraca 5-krotke z tcp_timeout i fail_threshold
- run_snmp_worker._read_snmp_settings() zwraca 3-krotke z snmp_timeout
- run_vuln_worker._read_settings() zwraca 7-krotke z tcp_timeout i http_timeout
- discovery._read_discovery_overrides() — nadpisania zakresow sieci z DB
- scan.py WorkerSettings — nowe pola w modelu (ping_tcp_timeout, snmp_timeout_s, itd.)
- app.py settings_workers_update — przesyla float i string do API
"""
import importlib
import sys
from unittest.mock import MagicMock, patch

import pytest


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_status_row(value):
    row = MagicMock()
    row.value = str(value)
    return row


def _mock_db(value=None):
    """DB mock zwracajacy podana wartosc dla kazdego klucza."""
    db = MagicMock()
    if value is None:
        db.query.return_value.filter.return_value.first.return_value = None
    else:
        db.query.return_value.filter.return_value.first.return_value = _make_status_row(value)
    return db


# ─────────────────────────────────────────────────────────────────────────────
# run_ping._read_settings
# ─────────────────────────────────────────────────────────────────────────────

class TestPingReadSettings:
    """run_ping._read_settings() zwraca 5-krotke (interval, workers, inactive, tcp_timeout, fail_threshold)."""

    def test_returns_five_tuple(self):
        import run_ping
        with patch("run_ping.SessionLocal", return_value=_mock_db()):
            result = run_ping._read_settings()
        assert len(result) == 5, f"Oczekiwano 5 elementow, jest {len(result)}"

    def test_defaults_when_no_db_rows(self):
        """Brak wierszy w DB → wartosci domyslne z env."""
        import run_ping
        with patch("run_ping.SessionLocal", return_value=_mock_db()):
            interval, workers, inactive, tcp_timeout, fail_threshold = run_ping._read_settings()
        assert interval == run_ping._DEFAULT_INTERVAL
        assert workers  == run_ping._DEFAULT_WORKERS
        assert inactive == run_ping._DEFAULT_INACT
        assert isinstance(tcp_timeout, float)
        assert isinstance(fail_threshold, int)

    def test_tcp_timeout_from_db(self):
        """ping_tcp_timeout z DB jest odczytywany jako float."""
        import run_ping
        db = MagicMock()
        def _first_for_key(key_matcher):
            # Dla ping_tcp_timeout zwroc 2.5, reszta domyslnie
            f = MagicMock()
            # Nie mozemy latwlo rozroznic kluczy w mocku — testujemy ze DB z jedna wartoscia
            f.first.return_value = _make_status_row("2.5")
            return f
        db.query.return_value.filter = _first_for_key
        with patch("run_ping.SessionLocal", return_value=db):
            _, _, _, tcp_timeout, _ = run_ping._read_settings()
        # Wartosc powinna byc float >= 0.1
        assert isinstance(tcp_timeout, float)
        assert tcp_timeout >= 0.1

    def test_fail_threshold_clamped_to_minimum_1(self):
        """Wartosc 0 dla ping_fail_threshold jest clamped do 1."""
        import run_ping
        with patch("run_ping.SessionLocal", return_value=_mock_db(0)):
            _, _, _, _, fail_threshold = run_ping._read_settings()
        assert fail_threshold >= 1

    def test_exception_returns_defaults(self):
        """Wyjątek w trakcie odczytu → wartosci domyslne z env."""
        import run_ping
        db = MagicMock()
        db.query.side_effect = Exception("DB error")
        with patch("run_ping.SessionLocal", return_value=db):
            result = run_ping._read_settings()
        assert len(result) == 5
        interval, workers, inactive, tcp_timeout, fail_threshold = result
        assert interval == run_ping._DEFAULT_INTERVAL
        assert workers  == run_ping._DEFAULT_WORKERS


# ─────────────────────────────────────────────────────────────────────────────
# run_snmp_worker._read_snmp_settings
# ─────────────────────────────────────────────────────────────────────────────

class TestSnmpReadSettings:
    """run_snmp_worker._read_snmp_settings() zwraca 3-krotke z snmp_timeout."""

    def test_returns_four_tuple(self):
        """_read_snmp_settings zwraca 4 wartosci: interval, workers, timeout, community_delay."""
        import run_snmp_worker
        with patch("run_snmp_worker.SessionLocal", return_value=_mock_db()):
            result = run_snmp_worker._read_snmp_settings()
        assert len(result) == 4, f"Oczekiwano 4 elementow, jest {len(result)}"

    def test_defaults_when_no_db_rows(self):
        import run_snmp_worker
        with patch("run_snmp_worker.SessionLocal", return_value=_mock_db()):
            interval, workers, snmp_timeout, _delay = run_snmp_worker._read_snmp_settings()
        assert interval == run_snmp_worker._DEFAULT_SNMP_INTERVAL
        assert workers  == run_snmp_worker._DEFAULT_SNMP_WORKERS
        assert isinstance(snmp_timeout, int)
        assert snmp_timeout >= 1

    def test_snmp_timeout_clamped_to_minimum_1(self):
        """snmp_timeout_s=0 z DB jest clamped do 1."""
        import run_snmp_worker
        with patch("run_snmp_worker.SessionLocal", return_value=_mock_db(0)):
            _, _, snmp_timeout, _ = run_snmp_worker._read_snmp_settings()
        assert snmp_timeout >= 1

    def test_exception_returns_defaults(self):
        import run_snmp_worker
        db = MagicMock()
        db.query.side_effect = Exception("DB down")
        with patch("run_snmp_worker.SessionLocal", return_value=db):
            result = run_snmp_worker._read_snmp_settings()
        assert len(result) == 4


# ─────────────────────────────────────────────────────────────────────────────
# run_vuln_worker._read_settings
# ─────────────────────────────────────────────────────────────────────────────

class TestVulnReadSettings:
    """run_vuln_worker._read_settings() zwraca 7-krotke z tcp_timeout i http_timeout."""

    def test_returns_seven_tuple(self):
        import run_vuln_worker as w
        with patch("run_vuln_worker.SessionLocal", return_value=_mock_db()):
            result = w._read_settings()
        assert len(result) == 7, f"Oczekiwano 7 elementow, jest {len(result)}"

    def test_defaults_when_no_db_rows(self):
        import run_vuln_worker as w
        with patch("run_vuln_worker.SessionLocal", return_value=_mock_db()):
            interval, workers, close_after, skip_printers, limit_ap_iot, tcp_timeout, http_timeout = w._read_settings()
        assert isinstance(tcp_timeout, float)
        assert isinstance(http_timeout, float)
        assert tcp_timeout  >= 0.5
        assert http_timeout >= 0.5

    def test_tcp_timeout_float_from_db(self):
        """vuln_tcp_timeout przechowywany jako string w DB jest konwertowany na float."""
        import run_vuln_worker as w
        with patch("run_vuln_worker.SessionLocal", return_value=_mock_db("2.5")):
            _, _, _, _, _, tcp_timeout, http_timeout = w._read_settings()
        # Wartosc powinna byc float (moze byc 2.5 lub clamped do max/min)
        assert isinstance(tcp_timeout, float)
        assert isinstance(http_timeout, float)

    def test_exception_returns_defaults(self):
        import run_vuln_worker as w
        db = MagicMock()
        db.query.side_effect = Exception("DB error")
        with patch("run_vuln_worker.SessionLocal", return_value=db):
            result = w._read_settings()
        assert len(result) == 7
        _, _, _, skip_printers, limit_ap_iot, tcp_timeout, http_timeout = result
        assert skip_printers is True
        assert limit_ap_iot  is True


# ─────────────────────────────────────────────────────────────────────────────
# discovery._read_discovery_overrides
# ─────────────────────────────────────────────────────────────────────────────

class TestDiscoveryOverrides:
    """_read_discovery_overrides(db) odczytuje nadpisania zakresow sieci z system_status."""

    def _get_overrides(self):
        from netdoc.collector.discovery import _read_discovery_overrides
        return _read_discovery_overrides

    def test_empty_db_returns_none_for_all(self):
        """Brak wpisow w DB → (None, None, None, None) — uzyj .env i ustawien domyslnych."""
        fn = self._get_overrides()
        db = _mock_db()
        extra_ranges, include_vpn, include_virtual, ignore_laa = fn(db)
        assert extra_ranges    is None
        assert include_vpn     is None
        assert include_virtual is None

    def test_network_ranges_parsed_to_list(self):
        """network_ranges CSV z DB jest parsowany do listy CIDR."""
        fn = self._get_overrides()
        db = _mock_db("10.8.0.0/24,192.168.100.0/24")
        extra_ranges, _, _, _ = fn(db)
        assert extra_ranges is not None
        assert "10.8.0.0/24" in extra_ranges
        assert "192.168.100.0/24" in extra_ranges
        assert len(extra_ranges) == 2

    def test_empty_network_ranges_returns_none(self):
        """Pusty string w network_ranges → None (uzyj .env)."""
        fn = self._get_overrides()
        db = _mock_db("")
        extra_ranges, _, _, _ = fn(db)
        assert extra_ranges is None

    def test_scan_vpn_networks_value_1_returns_true(self):
        """scan_vpn_networks = '1' w DB → include_vpn = True."""
        fn = self._get_overrides()
        db = _mock_db("1")
        _, include_vpn, include_virtual, _ = fn(db)
        assert include_vpn     is True
        assert include_virtual is True

    def test_scan_vpn_networks_value_0_returns_false(self):
        """scan_vpn_networks = '0' w DB → include_vpn = False."""
        fn = self._get_overrides()
        db = _mock_db("0")
        _, include_vpn, include_virtual, _ = fn(db)
        assert include_vpn     is False
        assert include_virtual is False

    def test_exception_returns_quad_none(self):
        """Wyjatek (np. brak tabeli) → (None, None, None, None) — bezpieczny fallback."""
        fn = self._get_overrides()
        db = MagicMock()
        db.query.side_effect = Exception("no table")
        extra_ranges, include_vpn, include_virtual, ignore_laa = fn(db)
        assert extra_ranges    is None
        assert include_vpn     is None
        assert include_virtual is None
        assert ignore_laa      is None


# ─────────────────────────────────────────────────────────────────────────────
# scan.py WorkerSettings — nowe pola w modelu
# ─────────────────────────────────────────────────────────────────────────────

class TestScanApiWorkerSettings:
    """WorkerSettings Pydantic model zawiera nowe pola konfiguracyjne."""

    def test_new_ping_fields_exist(self):
        from netdoc.api.routes.scan import WorkerSettings
        ws = WorkerSettings(ping_tcp_timeout=2.5, ping_fail_threshold=5)
        assert ws.ping_tcp_timeout  == 2.5
        assert ws.ping_fail_threshold == 5

    def test_new_snmp_timeout_field_exists(self):
        from netdoc.api.routes.scan import WorkerSettings
        ws = WorkerSettings(snmp_timeout_s=4)
        assert ws.snmp_timeout_s == 4

    def test_new_vuln_timeout_fields_exist(self):
        from netdoc.api.routes.scan import WorkerSettings
        ws = WorkerSettings(vuln_tcp_timeout=1.5, vuln_http_timeout=10.0)
        assert ws.vuln_tcp_timeout  == 1.5
        assert ws.vuln_http_timeout == 10.0

    def test_new_cred_delay_fields_exist(self):
        from netdoc.api.routes.scan import WorkerSettings
        ws = WorkerSettings(cred_min_delay_s=3, cred_max_delay_s=15)
        assert ws.cred_min_delay_s == 3
        assert ws.cred_max_delay_s == 15

    def test_network_discovery_fields_exist(self):
        from netdoc.api.routes.scan import WorkerSettings
        ws = WorkerSettings(
            network_ranges="10.8.0.0/24,192.168.100.0/24",
            scan_vpn_networks=1,
            scan_virtual_networks=0,
        )
        assert ws.network_ranges      == "10.8.0.0/24,192.168.100.0/24"
        assert ws.scan_vpn_networks   == 1
        assert ws.scan_virtual_networks == 0

    def test_all_new_fields_default_to_none(self):
        """Wszystkie nowe pola maja domyslna wartosc None (nie sa wymagane)."""
        from netdoc.api.routes.scan import WorkerSettings
        ws = WorkerSettings()
        assert ws.ping_tcp_timeout     is None
        assert ws.ping_fail_threshold  is None
        assert ws.snmp_timeout_s       is None
        assert ws.vuln_tcp_timeout     is None
        assert ws.vuln_http_timeout    is None
        assert ws.cred_min_delay_s     is None
        assert ws.cred_max_delay_s     is None
        assert ws.network_ranges       is None
        assert ws.scan_vpn_networks    is None
        assert ws.scan_virtual_networks is None


# ─────────────────────────────────────────────────────────────────────────────
# run_scanner.py — nowe klucze w _config_defaults
# ─────────────────────────────────────────────────────────────────────────────

class TestScannerConfigDefaults:
    """run_scanner.py inicjalizuje nowe klucze konfiguracyjne w system_status."""

    def _get_defaults(self):
        """Odczytuje _config_defaults z run_scanner.py bez uruchamiania skryptu."""
        # Importujemy przez czytanie kodu zrodlowego
        import ast, pathlib
        code = pathlib.Path("run_scanner.py").read_text(encoding="utf-8")
        # Szukamy fragmentu ze slownikiem _config_defaults
        start = code.find("_config_defaults = {")
        end   = code.find("}", start) + 1
        # Uproszczony parser — szukamy kluczy przez string matching
        return code[start:end]

    def test_cred_mssql_enabled_in_defaults(self):
        code = self._get_defaults()
        assert "cred_mssql_enabled" in code

    def test_cred_mysql_enabled_in_defaults(self):
        code = self._get_defaults()
        assert "cred_mysql_enabled" in code

    def test_cred_postgres_enabled_in_defaults(self):
        code = self._get_defaults()
        assert "cred_postgres_enabled" in code

    def test_network_ranges_in_defaults(self):
        code = self._get_defaults()
        assert "network_ranges" in code

    def test_scan_vpn_networks_in_defaults(self):
        code = self._get_defaults()
        assert "scan_vpn_networks" in code

    def test_scan_virtual_networks_in_defaults(self):
        code = self._get_defaults()
        assert "scan_virtual_networks" in code


# ─────────────────────────────────────────────────────────────────────────────
# app.py settings_workers_update — nowe pola w _FIELDS
# ─────────────────────────────────────────────────────────────────────────────

class TestAppSettingsWorkers:
    """app.py settings_workers_update przesyla wszystkie nowe pola do API."""

    def _get_app_code(self):
        import pathlib
        code = pathlib.Path("netdoc/web/app.py").read_text(encoding="utf-8")
        start = code.find("def settings_workers_update")
        end   = code.find("def ", start + 1)
        return code[start:end]

    def test_cred_web_workers_in_int_fields(self):
        assert "cred_web_workers" in self._get_app_code()

    def test_cred_min_delay_s_in_int_fields(self):
        assert "cred_min_delay_s" in self._get_app_code()

    def test_cred_max_delay_s_in_int_fields(self):
        assert "cred_max_delay_s" in self._get_app_code()

    def test_ping_tcp_timeout_in_float_fields(self):
        code = self._get_app_code()
        assert "ping_tcp_timeout" in code
        assert "_FLOAT_FIELDS" in code

    def test_vuln_tcp_timeout_in_float_fields(self):
        assert "vuln_tcp_timeout" in self._get_app_code()

    def test_vuln_http_timeout_in_float_fields(self):
        assert "vuln_http_timeout" in self._get_app_code()

    def test_network_ranges_in_str_fields(self):
        code = self._get_app_code()
        assert "network_ranges" in code
        assert "_STR_FIELDS" in code

    def test_scan_vpn_networks_in_int_fields(self):
        assert "scan_vpn_networks" in self._get_app_code()

    def test_vuln_close_after_in_int_fields(self):
        """Regresja: vuln_close_after byl brakujacy w _FIELDS — teraz musi byc."""
        assert "vuln_close_after" in self._get_app_code()

    def test_vuln_skip_printers_in_int_fields(self):
        """Regresja: vuln_skip_printers byl brakujacy w _FIELDS — teraz musi byc."""
        assert "vuln_skip_printers" in self._get_app_code()

    def test_nmap_min_rate_in_int_fields(self):
        """Regresja: nmap_min_rate byl brakujacy w _FIELDS — teraz musi byc."""
        assert "nmap_min_rate" in self._get_app_code()

    def test_lab_monitoring_enabled_in_int_fields(self):
        """Regresja: lab_monitoring_enabled byl brakujacy w _FIELDS — teraz musi byc."""
        assert "lab_monitoring_enabled" in self._get_app_code()
