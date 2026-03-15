"""Testy modułów vendor databases: oid_lookup.py i fingerprinting.py."""
import json
import pytest
from pathlib import Path
from unittest.mock import patch


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_oid_db(tmp_path):
    """Tymczasowa baza OID z kilkoma wpisami."""
    data = {
        "9":     {"vendor": "Cisco",    "description": "Cisco Systems"},
        "14988": {"vendor": "MikroTik", "description": "MikroTik RouterOS"},
        "41112": {"vendor": "Ubiquiti", "description": "Ubiquiti Networks"},
        "12356": {"vendor": "Fortinet", "description": "Fortinet (FortiGate)"},
        "8072":  {"vendor": "Net-SNMP", "description": "Net-SNMP (Linux)"},
    }
    f = tmp_path / "enterprise_vendors.json"
    f.write_text(json.dumps(data), encoding="utf-8")
    return f


@pytest.fixture
def tmp_banner_db(tmp_path):
    """Tymczasowa baza bannerów w formacie YAML."""
    content = """
http_server:
  - pattern: "ZyXEL-RomPager"
    vendor: "ZyXEL"
    device_type: "router"
  - pattern: "HP HTTP Server"
    vendor: "HP"
    device_type: "printer"
  - pattern: "MikroTik"
    vendor: "MikroTik"
    device_type: "router"
  - pattern: "Apache"
    vendor: null
    device_type: "server"
  - pattern: "nginx"
    vendor: null
    device_type: null

ssh_banner:
  - pattern: "SSH-2.0-ROSSSH"
    vendor: "MikroTik"
    model: "RouterOS"
    device_type: "router"
  - pattern: "SSH-2.0-Cisco"
    vendor: "Cisco"
    device_type: "router"
  - pattern: "SSH-2.0-dropbear"
    vendor: null
    device_type: "router"
"""
    f = tmp_path / "banners.yaml"
    f.write_text(content, encoding="utf-8")
    return f


# ─────────────────────────────────────────────────────────────────────────────
# OIDDatabase — testy
# ─────────────────────────────────────────────────────────────────────────────

class TestOIDDatabase:
    def _make_db(self, tmp_oid_db):
        from netdoc.collector.oid_lookup import OIDDatabase
        db = OIDDatabase()
        with patch("netdoc.collector.oid_lookup._DATA_FILE", tmp_oid_db):
            db.load()
        return db

    def test_load_counts_entries(self, tmp_oid_db):
        db = self._make_db(tmp_oid_db)
        assert db.status()["entries"] == 5
        assert db.status()["loaded"] is True

    def test_lookup_cisco(self, tmp_oid_db):
        db = self._make_db(tmp_oid_db)
        result = db.lookup("1.3.6.1.4.1.9.1.1")
        assert result is not None
        assert result["vendor"] == "Cisco"

    def test_lookup_mikrotik(self, tmp_oid_db):
        db = self._make_db(tmp_oid_db)
        result = db.lookup("1.3.6.1.4.1.14988.1")
        assert result["vendor"] == "MikroTik"

    def test_lookup_ubiquiti(self, tmp_oid_db):
        db = self._make_db(tmp_oid_db)
        result = db.lookup("1.3.6.1.4.1.41112.1.4")
        assert result["vendor"] == "Ubiquiti"

    def test_lookup_unknown_enterprise(self, tmp_oid_db):
        db = self._make_db(tmp_oid_db)
        result = db.lookup("1.3.6.1.4.1.99999.1")
        assert result is None

    def test_lookup_vendor_shorthand(self, tmp_oid_db):
        db = self._make_db(tmp_oid_db)
        assert db.lookup_vendor("1.3.6.1.4.1.9.1.100") == "Cisco"
        assert db.lookup_vendor("1.3.6.1.4.1.99.1") is None

    def test_lookup_none_oid(self, tmp_oid_db):
        db = self._make_db(tmp_oid_db)
        assert db.lookup(None) is None
        assert db.lookup("") is None

    def test_lookup_oid_with_leading_dot(self, tmp_oid_db):
        db = self._make_db(tmp_oid_db)
        result = db.lookup(".1.3.6.1.4.1.14988.1")
        assert result["vendor"] == "MikroTik"

    def test_lookup_non_enterprise_oid(self, tmp_oid_db):
        """OID spoza 1.3.6.1.4.1 — nie ma enterprise numbera."""
        db = self._make_db(tmp_oid_db)
        assert db.lookup("1.3.6.1.2.1.1.1.0") is None

    def test_load_missing_file(self, tmp_path):
        from netdoc.collector.oid_lookup import OIDDatabase
        db = OIDDatabase()
        with patch("netdoc.collector.oid_lookup._DATA_FILE", tmp_path / "nonexistent.json"):
            db.load()
        assert db.status()["loaded"] is False
        assert db.lookup("1.3.6.1.4.1.9.1") is None

    def test_status_includes_file_path(self, tmp_oid_db):
        db = self._make_db(tmp_oid_db)
        status = db.status()
        assert "entries" in status
        assert "loaded" in status
        assert "file" in status


# ─────────────────────────────────────────────────────────────────────────────
# _extract_enterprise_number — testy
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractEnterpriseNumber:
    def test_cisco(self):
        from netdoc.collector.oid_lookup import _extract_enterprise_number
        assert _extract_enterprise_number("1.3.6.1.4.1.9.1.100") == "9"

    def test_mikrotik(self):
        from netdoc.collector.oid_lookup import _extract_enterprise_number
        assert _extract_enterprise_number("1.3.6.1.4.1.14988.1") == "14988"

    def test_leading_dot(self):
        from netdoc.collector.oid_lookup import _extract_enterprise_number
        assert _extract_enterprise_number(".1.3.6.1.4.1.9.1") == "9"

    def test_non_enterprise_oid(self):
        from netdoc.collector.oid_lookup import _extract_enterprise_number
        assert _extract_enterprise_number("1.3.6.1.2.1.1.1.0") is None

    def test_empty(self):
        from netdoc.collector.oid_lookup import _extract_enterprise_number
        assert _extract_enterprise_number("") is None

    def test_none(self):
        from netdoc.collector.oid_lookup import _extract_enterprise_number
        assert _extract_enterprise_number(None) is None


# ─────────────────────────────────────────────────────────────────────────────
# BannerDatabase — testy
# ─────────────────────────────────────────────────────────────────────────────

class TestBannerDatabase:
    def _make_db(self, tmp_banner_db):
        from netdoc.collector.fingerprinting import BannerDatabase
        db = BannerDatabase()
        with patch("netdoc.collector.fingerprinting._DATA_FILE", tmp_banner_db):
            db.load()
        return db

    # ── HTTP Server header ──────────────────────────────────────────────────

    def test_http_zyxel_rompager(self, tmp_banner_db):
        db = self._make_db(tmp_banner_db)
        result = db.fingerprint_server_header("ZyXEL-RomPager/4.51")
        assert result is not None
        assert result["vendor"] == "ZyXEL"
        assert result["device_type"] == "router"

    def test_http_hp_printer(self, tmp_banner_db):
        db = self._make_db(tmp_banner_db)
        result = db.fingerprint_server_header("HP HTTP Server; HP LaserJet M402")
        assert result["vendor"] == "HP"
        assert result["device_type"] == "printer"

    def test_http_mikrotik(self, tmp_banner_db):
        db = self._make_db(tmp_banner_db)
        result = db.fingerprint_server_header("MikroTik/6.49")
        assert result["vendor"] == "MikroTik"

    def test_http_apache_returns_none_vendor(self, tmp_banner_db):
        """Apache ma vendor=null — fingerprinting zwraca None (generic)."""
        db = self._make_db(tmp_banner_db)
        result = db.fingerprint_server_header("Apache/2.4.41 (Ubuntu)")
        assert result is None  # vendor=null i device_type=server → pomijany

    def test_http_nginx_returns_none(self, tmp_banner_db):
        """nginx ma vendor=null i device_type=null — jawnie ignorowany."""
        db = self._make_db(tmp_banner_db)
        assert db.fingerprint_server_header("nginx/1.18.0") is None

    def test_http_unknown_header(self, tmp_banner_db):
        db = self._make_db(tmp_banner_db)
        assert db.fingerprint_server_header("SomeUnknownServer/1.0") is None

    def test_http_empty_header(self, tmp_banner_db):
        db = self._make_db(tmp_banner_db)
        assert db.fingerprint_server_header("") is None

    def test_http_none_header(self, tmp_banner_db):
        db = self._make_db(tmp_banner_db)
        assert db.fingerprint_server_header(None) is None

    def test_http_case_insensitive(self, tmp_banner_db):
        """Dopasowanie jest case-insensitive."""
        db = self._make_db(tmp_banner_db)
        result = db.fingerprint_server_header("zyxel-rompager/4.51")
        assert result is not None
        assert result["vendor"] == "ZyXEL"

    # ── SSH banner ──────────────────────────────────────────────────────────

    def test_ssh_mikrotik_rosssh(self, tmp_banner_db):
        db = self._make_db(tmp_banner_db)
        result = db.fingerprint_ssh_banner("SSH-2.0-ROSSSH")
        assert result["vendor"] == "MikroTik"
        assert result["model"] == "RouterOS"
        assert result["device_type"] == "router"

    def test_ssh_cisco(self, tmp_banner_db):
        db = self._make_db(tmp_banner_db)
        result = db.fingerprint_ssh_banner("SSH-2.0-Cisco-1.25")
        assert result["vendor"] == "Cisco"

    def test_ssh_dropbear_no_vendor(self, tmp_banner_db):
        """Dropbear ma vendor=null ale device_type=router — zwracamy None (vendor=null pomijany)."""
        db = self._make_db(tmp_banner_db)
        result = db.fingerprint_ssh_banner("SSH-2.0-dropbear_2022.82")
        assert result is None  # vendor=null → pomijany przez _match

    def test_ssh_openssh_unknown(self, tmp_banner_db):
        db = self._make_db(tmp_banner_db)
        assert db.fingerprint_ssh_banner("SSH-2.0-OpenSSH_8.9p1") is None

    def test_ssh_empty(self, tmp_banner_db):
        db = self._make_db(tmp_banner_db)
        assert db.fingerprint_ssh_banner("") is None

    # ── Status ──────────────────────────────────────────────────────────────

    def test_status_after_load(self, tmp_banner_db):
        db = self._make_db(tmp_banner_db)
        status = db.status()
        assert status["loaded"] is True
        assert status["http_rules"] > 0
        assert status["ssh_rules"] > 0

    def test_load_missing_file(self, tmp_path):
        from netdoc.collector.fingerprinting import BannerDatabase
        db = BannerDatabase()
        with patch("netdoc.collector.fingerprinting._DATA_FILE", tmp_path / "missing.yaml"):
            db.load()
        assert db.status()["loaded"] is False
        assert db.fingerprint_server_header("MikroTik") is None


# ─────────────────────────────────────────────────────────────────────────────
# SNMP driver — integracja z OID lookup
# ─────────────────────────────────────────────────────────────────────────────

class TestSNMPDriverOIDLookup:
    def test_snmp_collect_populates_vendor_from_oid(self, tmp_oid_db):
        """SNMPDriver.collect() wypełnia vendor gdy sysObjectID wskazuje znany enterprise."""
        from netdoc.collector.drivers.snmp import SNMPDriver

        def _fake_snmp_get(ip, community, oid, timeout=2):
            return {
                "1.3.6.1.2.1.1.5.0": "mikrotik-router",
                "1.3.6.1.2.1.1.1.0": "RouterOS 6.49",
                "1.3.6.1.2.1.1.6.0": "Warsaw",
                "1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.14988.1",
                "1.3.6.1.2.1.1.4.0": "admin@example.com",
            }.get(oid)

        from netdoc.collector.oid_lookup import OIDDatabase
        fake_oid_db = OIDDatabase()
        with patch("netdoc.collector.oid_lookup._DATA_FILE", tmp_oid_db):
            fake_oid_db.load()

        with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=_fake_snmp_get), \
             patch("netdoc.collector.drivers.snmp.SNMPDriver.collect",
                   wraps=SNMPDriver("10.0.0.1").collect):
            # Patch oid_db inside the snmp module
            import netdoc.collector.oid_lookup as oid_mod
            original_db = oid_mod.oid_db
            oid_mod.oid_db = fake_oid_db
            try:
                with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=_fake_snmp_get):
                    driver = SNMPDriver("10.0.0.1")
                    result = driver.collect()
            finally:
                oid_mod.oid_db = original_db

        assert result.hostname == "mikrotik-router"
        assert result.vendor == "MikroTik"
        assert result.os_version == "RouterOS 6.49"
        assert result.raw.get("sysObjectID") == "1.3.6.1.4.1.14988.1"

    def test_snmp_collect_no_vendor_when_oid_unknown(self, tmp_oid_db):
        """SNMPDriver.collect() ustawia vendor=None gdy OID nieznany."""
        from netdoc.collector.drivers.snmp import SNMPDriver

        def _fake_snmp_get(ip, community, oid, timeout=2):
            return {
                "1.3.6.1.2.1.1.5.0": "some-device",
                "1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.99999.1",  # nieznany enterprise
            }.get(oid)

        from netdoc.collector.oid_lookup import OIDDatabase
        fake_oid_db = OIDDatabase()
        with patch("netdoc.collector.oid_lookup._DATA_FILE", tmp_oid_db):
            fake_oid_db.load()

        import netdoc.collector.oid_lookup as oid_mod
        original_db = oid_mod.oid_db
        oid_mod.oid_db = fake_oid_db
        try:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=_fake_snmp_get):
                driver = SNMPDriver("10.0.0.2")
                result = driver.collect()
        finally:
            oid_mod.oid_db = original_db

        assert result.hostname == "some-device"
        assert result.vendor is None

    def test_snmp_collect_no_sysname_returns_empty(self):
        """SNMPDriver fail-fast: brak sysName → DeviceData bez vendora."""
        from netdoc.collector.drivers.snmp import SNMPDriver
        with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=None):
            result = SNMPDriver("10.0.0.3").collect()
        assert result.hostname is None
        assert result.vendor is None


# ─────────────────────────────────────────────────────────────────────────────
# Real data files sanity checks
# ─────────────────────────────────────────────────────────────────────────────

class TestRealDataFiles:
    """Sprawdzają czy pliki danych są załadowane i mają sensowną zawartość."""

    def test_real_enterprise_vendors_loads(self):
        """Rzeczywisty plik enterprise_vendors.json powinien mieć >50 wpisów."""
        from netdoc.collector.oid_lookup import OIDDatabase
        db = OIDDatabase()
        db.load()
        if db.status()["loaded"]:
            assert db.status()["entries"] >= 50

    def test_real_oid_lookup_cisco(self):
        """Cisco OID 1.3.6.1.4.1.9 powinien być rozpoznany."""
        from netdoc.collector.oid_lookup import OIDDatabase
        db = OIDDatabase()
        db.load()
        if db.status()["loaded"]:
            assert db.lookup_vendor("1.3.6.1.4.1.9.1.1") == "Cisco"

    def test_real_oid_lookup_mikrotik(self):
        from netdoc.collector.oid_lookup import OIDDatabase
        db = OIDDatabase()
        db.load()
        if db.status()["loaded"]:
            assert db.lookup_vendor("1.3.6.1.4.1.14988.1") == "MikroTik"

    def test_real_banners_yaml_loads(self):
        """Rzeczywisty plik banners.yaml powinien załadować się bez błędów."""
        pytest.importorskip("yaml")
        from netdoc.collector.fingerprinting import BannerDatabase
        db = BannerDatabase()
        db.load()
        if db.status()["loaded"]:
            assert db.status()["http_rules"] >= 20
            assert db.status()["ssh_rules"] >= 3

    def test_real_banner_zyxel(self):
        pytest.importorskip("yaml")
        from netdoc.collector.fingerprinting import BannerDatabase
        db = BannerDatabase()
        db.load()
        if db.status()["loaded"]:
            result = db.fingerprint_server_header("ZyXEL-RomPager/4.51 EmbeddedWeb")
            assert result is not None
            assert result["vendor"] == "ZyXEL"

    def test_real_banner_mikrotik(self):
        pytest.importorskip("yaml")
        from netdoc.collector.fingerprinting import BannerDatabase
        db = BannerDatabase()
        db.load()
        if db.status()["loaded"]:
            result = db.fingerprint_server_header("MikroTik/6.49.8 (stable)")
            assert result is not None
            assert result["vendor"] == "MikroTik"
