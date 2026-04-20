"""Testy jednostkowe dla:
  - netdoc/collector/snmp_l2.py   — helpers i collect_*
  - netdoc/collector/snmp_profiles.py — detect_vendor_profile, get_profile
  - netdoc/collector/snmp_sensors.py — helpers i _sanitize_sensors
  - run_snmp_worker._collect_if_metrics — filtracja HC vs 32-bit
  - run_snmp_worker._save_fdb/_save_vlan_port/_save_stp_ports — logika upsert (mock DB)
"""
import sys
import types
from unittest.mock import MagicMock, patch, call
import pytest

# ── stub prometheus przed importem workera ────────────────────────────────────
prom_stub = types.ModuleType("prometheus_client")
prom_stub.Gauge = lambda *a, **kw: MagicMock()
prom_stub.start_http_server = lambda *a, **kw: None
sys.modules.setdefault("prometheus_client", prom_stub)

from netdoc.collector import snmp_l2 as l2
from netdoc.collector import snmp_profiles as prof
from netdoc.collector import snmp_sensors as sens
import run_snmp_worker as w


# ═══════════════════════════════════════════════════════════════════════════════
# snmp_l2 — helper functions
# ═══════════════════════════════════════════════════════════════════════════════

class TestOidSuffixInt:
    def test_returns_last_element(self):
        assert l2._oid_suffix_int("1.3.6.1.2.1.17.1.4.1.2.5", "1.3.6.1.2.1.17.1.4.1.2") == 5

    def test_returns_none_on_empty(self):
        assert l2._oid_suffix_int("", "1.2.3") is None

    def test_returns_none_on_non_numeric(self):
        assert l2._oid_suffix_int("1.3.6.1.2.1.foo", "1.3.6.1.2.1") is None

    def test_single_element_oid(self):
        assert l2._oid_suffix_int("42", "") == 42


class TestBytesToMac:
    def test_bytes_input(self):
        assert l2._bytes_to_mac(b"\x00\x15\x69\xAB\xCD\xEF") == "00:15:69:ab:cd:ef"

    def test_oid_style_string(self):
        assert l2._bytes_to_mac("0.21.105.171.205.239") == "00:15:69:ab:cd:ef"

    def test_hex_string(self):
        assert l2._bytes_to_mac("001569ABCDEF") == "00:15:69:ab:cd:ef"

    def test_colon_separated_hex(self):
        assert l2._bytes_to_mac("00:15:69:ab:cd:ef") == "00:15:69:ab:cd:ef"

    def test_wrong_length_returns_none(self):
        assert l2._bytes_to_mac(b"\x00\x15\x69") is None

    def test_none_input_returns_none(self):
        assert l2._bytes_to_mac(None) is None

    def test_bytearray_input(self):
        assert l2._bytes_to_mac(bytearray(b"\xaa\xbb\xcc\xdd\xee\xff")) == "aa:bb:cc:dd:ee:ff"


class TestParseBitstring:
    def test_single_byte_first_bit(self):
        # 0b10000000 = 0x80 → port 1
        assert l2._parse_bitstring(b"\x80") == [1]

    def test_single_byte_last_bit(self):
        # 0b00000001 = 0x01 → port 8
        assert l2._parse_bitstring(b"\x01") == [8]

    def test_two_bytes(self):
        # 0b10000000 0b10000000 → ports 1, 9
        assert l2._parse_bitstring(b"\x80\x80") == [1, 9]

    def test_all_bits(self):
        ports = l2._parse_bitstring(b"\xFF")
        assert ports == [1, 2, 3, 4, 5, 6, 7, 8]

    def test_hex_string_input(self):
        # "80" = 0b10000000 → port 1
        assert l2._parse_bitstring("80") == [1]

    def test_empty_bytes_returns_empty(self):
        assert l2._parse_bitstring(b"") == []

    def test_invalid_input_returns_empty(self):
        assert l2._parse_bitstring(12345) == []


# ═══════════════════════════════════════════════════════════════════════════════
# snmp_l2 — collect_fdb
# ═══════════════════════════════════════════════════════════════════════════════

def _make_snmp_walk_side_effect(responses: dict):
    """Zwraca mock snmp_walk który zwraca rózne dane dla róznych OID prefix."""
    def _walk(ip, oid_prefix, community, timeout=2, max_iter=512):
        return responses.get(oid_prefix, [])
    return _walk


_SNMP_WALK_PATH = "netdoc.collector.snmp_walk.snmp_walk"


class TestCollectFdb:
    def test_empty_when_walk_returns_nothing(self):
        with patch(_SNMP_WALK_PATH, return_value=[]):
            result = l2.collect_fdb("10.0.0.1", "public")
        assert result == []

    def test_basic_mac_learned(self):
        # bridge_port 1 → ifIndex 3
        port_ifindex_rows = [
            (l2._OID_BASE_PORT_IFINDEX + ".1", "3", "Integer32"),
        ]
        # MAC 00:15:69:ab:cd:ef → bridge_port 1
        fdb_port_rows = [
            (l2._OID_FDB_PORT + ".0.21.105.171.205.239", "1", "Integer32"),
        ]
        fdb_status_rows = [
            (l2._OID_FDB_STATUS + ".0.21.105.171.205.239", "3", "Integer32"),
        ]
        walk_map = {
            l2._OID_BASE_PORT_IFINDEX: port_ifindex_rows,
            l2._OID_FDB_PORT:         fdb_port_rows,
            l2._OID_FDB_STATUS:       fdb_status_rows,
        }
        with patch(_SNMP_WALK_PATH,
                   side_effect=_make_snmp_walk_side_effect(walk_map)):
            result = l2.collect_fdb("10.0.0.1", "public")

        assert len(result) == 1
        entry = result[0]
        assert entry["mac"] == "00:15:69:ab:cd:ef"
        assert entry["bridge_port"] == 1
        assert entry["if_index"] == 3
        assert entry["fdb_status"] == 3
        assert entry["vlan_id"] == 1  # domyślna instancja bridge = VLAN 1

    def test_multicast_mac_filtered(self):
        """MAC z pierwszym bajtem nieparzystym (multicast) musi byc odfiltrowany."""
        fdb_port_rows = [
            # 01:00:5e:... — multicast (bit 0 bajtu 1 = 1)
            (l2._OID_FDB_PORT + ".1.0.94.0.0.1", "1", "Integer32"),
        ]
        walk_map = {
            l2._OID_BASE_PORT_IFINDEX: [],
            l2._OID_FDB_PORT:         fdb_port_rows,
            l2._OID_FDB_STATUS:       [],
        }
        with patch(_SNMP_WALK_PATH,
                   side_effect=_make_snmp_walk_side_effect(walk_map)):
            result = l2.collect_fdb("10.0.0.1", "public")
        assert result == []

    def test_walk_exception_returns_empty(self):
        with patch(_SNMP_WALK_PATH, side_effect=Exception("timeout")):
            result = l2.collect_fdb("10.0.0.1", "public")
        assert result == []


# ═══════════════════════════════════════════════════════════════════════════════
# snmp_l2 — collect_vlan_port (podstawowe scenariusze)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCollectVlanPort:
    def test_empty_when_no_vlans(self):
        with patch(_SNMP_WALK_PATH, return_value=[]):
            result = l2.collect_vlan_port("10.0.0.1", "public")
        assert result == []

    def test_walk_exception_returns_empty(self):
        with patch(_SNMP_WALK_PATH, side_effect=Exception("refused")):
            result = l2.collect_vlan_port("10.0.0.1", "public")
        assert result == []


# ═══════════════════════════════════════════════════════════════════════════════
# snmp_l2 — collect_stp_ports
# ═══════════════════════════════════════════════════════════════════════════════

class TestCollectStpPorts:
    def test_empty_when_no_data(self):
        with patch(_SNMP_WALK_PATH, return_value=[]):
            ports, root_mac, root_cost = l2.collect_stp_ports("10.0.0.1", "public")
        assert ports == []
        assert root_mac is None
        assert root_cost is None

    def test_stp_state_names(self):
        """Sprawdza ze mapa stanow STP jest kompletna i poprawna."""
        assert l2._STP_STATE_NAMES[1] == "disabled"
        assert l2._STP_STATE_NAMES[5] == "forwarding"
        assert l2._STP_STATE_NAMES[2] == "blocking"

    def test_walk_exception_returns_empty_tuple(self):
        with patch(_SNMP_WALK_PATH, side_effect=Exception("timeout")):
            ports, root_mac, root_cost = l2.collect_stp_ports("10.0.0.1", "public")
        assert ports == []


# ═══════════════════════════════════════════════════════════════════════════════
# snmp_profiles — detect_vendor_profile
# ═══════════════════════════════════════════════════════════════════════════════

class TestDetectVendorProfile:
    def test_cisco_ios_via_oid(self):
        name = prof.detect_vendor_profile("1.3.6.1.4.1.9.1.1", None)
        assert name == "cisco_ios"

    def test_mikrotik_via_oid(self):
        name = prof.detect_vendor_profile("1.3.6.1.4.1.14988.1", None)
        assert name == "mikrotik"

    def test_generic_when_nothing_matches(self):
        name = prof.detect_vendor_profile("9.9.9.9.9.9.9", "unknown vendor X")
        assert name == "generic"

    def test_sysdescr_fallback_when_oid_unknown(self):
        name = prof.detect_vendor_profile(None, "MikroTik RouterOS 7.13")
        assert name == "mikrotik"

    def test_both_none_returns_generic(self):
        name = prof.detect_vendor_profile(None, None)
        assert name == "generic"

    def test_empty_strings_returns_generic(self):
        name = prof.detect_vendor_profile("", "")
        assert name == "generic"

    def test_get_profile_returns_dict(self):
        profile = prof.get_profile("1.3.6.1.4.1.9.1.1", None)
        assert isinstance(profile, dict)
        assert "fdb_supported" in profile

    def test_get_profile_generic_fallback(self):
        profile = prof.get_profile(None, None)
        assert isinstance(profile, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# snmp_sensors — helper functions
# ═══════════════════════════════════════════════════════════════════════════════

class TestSensorsHelpers:
    # _int_val
    def test_int_val_from_int(self):
        assert sens._int_val(42) == 42

    def test_int_val_from_string(self):
        assert sens._int_val("100") == 100

    def test_int_val_from_bytes(self):
        # 0x00, 0x64 = 100
        assert sens._int_val(b"\x00\x64") == 100

    def test_int_val_none_returns_none(self):
        assert sens._int_val(None) is None

    def test_int_val_invalid_string_returns_none(self):
        assert sens._int_val("abc") is None

    def test_int_val_empty_bytes_returns_none(self):
        assert sens._int_val(b"") is None

    # _str_val
    def test_str_val_from_string(self):
        assert sens._str_val("hello") == "hello"

    def test_str_val_from_bytes(self):
        assert sens._str_val(b"hello") == "hello"

    def test_str_val_none_returns_empty(self):
        assert sens._str_val(None) == ""

    def test_str_val_strips_whitespace(self):
        assert sens._str_val("  stripped  ") == "stripped"

    # _sensor
    def test_sensor_creates_correct_dict(self):
        s = sens._sensor("cpu_temp", 45.5, "°C", "cisco_envmon")
        assert s["name"] == "cpu_temp"
        assert s["value"] == 45.5
        assert s["unit"] == "°C"
        assert s["source"] == "cisco_envmon"

    def test_sensor_invalid_value_stores_none(self):
        s = sens._sensor("cpu_temp", "invalid", "°C", "test")
        assert s["value"] is None

    def test_sensor_zero_value_stored(self):
        s = sens._sensor("fan", 0, "rpm", "test")
        assert s["value"] == 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# snmp_sensors — _sanitize_sensors
# ═══════════════════════════════════════════════════════════════════════════════

class TestSanitizeSensors:
    def _s(self, name, value, unit=""):
        return {"name": name, "value": value, "unit": unit, "source": "test", "raw": ""}

    def test_removes_raw_kb_fields(self):
        sensors = [
            self._s("ram_total_kb", 1024),
            self._s("ram_used_kb", 512),
            self._s("ram_free_kb", 512),
            self._s("ram_used_pct", 50, "%"),
        ]
        result = sens._sanitize_sensors(sensors)
        names = [s["name"] for s in result]
        assert "ram_total_kb" not in names
        assert "ram_used_kb" not in names
        assert "ram_free_kb" not in names
        assert "ram_used_pct" in names

    def test_removes_ram_pct_out_of_range(self):
        sensors = [
            self._s("ram_used_pct", 150, "%"),  # > 100 = invalid
            self._s("ram_used_pct", -5, "%"),   # < 0 = invalid (duplicate key — nie dojdzie)
        ]
        result = sens._sanitize_sensors(sensors)
        assert result == []

    def test_keeps_valid_ram_pct(self):
        sensors = [self._s("ram_used_pct", 75)]
        result = sens._sanitize_sensors(sensors)
        assert len(result) == 1

    def test_removes_zero_celsius(self):
        sensors = [self._s("cpu_temp", 0.0, "°C")]
        result = sens._sanitize_sensors(sensors)
        assert result == []

    def test_keeps_one_celsius(self):
        """BUG-L4: 1°C to prawidlowa temp. outdoor gear — nie jest sentinel."""
        sensors = [self._s("sensor_x", 1.0, "°C")]
        result = sens._sanitize_sensors(sensors)
        assert len(result) == 1

    def test_keeps_valid_temperature(self):
        sensors = [self._s("cpu_temp", 45.0, "°C")]
        result = sens._sanitize_sensors(sensors)
        assert len(result) == 1

    def test_removes_zero_rpm_fan(self):
        sensors = [self._s("fan1", 0, "rpm")]
        result = sens._sanitize_sensors(sensors)
        assert result == []

    def test_keeps_nonzero_rpm(self):
        sensors = [self._s("fan1", 1500, "rpm")]
        result = sens._sanitize_sensors(sensors)
        assert len(result) == 1

    def test_deduplicates_case_insensitive(self):
        sensors = [
            self._s("cpu_temp", 45.0, "°C"),
            self._s("CPU_TEMP", 50.0, "°C"),  # duplikat — powinien zostac odrzucony
        ]
        result = sens._sanitize_sensors(sensors)
        assert len(result) == 1
        assert result[0]["value"] == 45.0  # pierwsza wygrywa

    def test_empty_list_returns_empty(self):
        assert sens._sanitize_sensors([]) == []

    def test_normal_sensors_pass_through(self):
        sensors = [
            self._s("cpu_temp", 55.0, "°C"),
            self._s("fan1", 2000, "rpm"),
            self._s("cpu_load", 30.0, "%"),
        ]
        result = sens._sanitize_sensors(sensors)
        assert len(result) == 3


# ═══════════════════════════════════════════════════════════════════════════════
# run_snmp_worker._collect_if_metrics — HC vs 32-bit deduplication
# ═══════════════════════════════════════════════════════════════════════════════

class TestCollectIfMetrics:
    def _make_walk(self, oid_to_rows: dict):
        def _walk(ip, oid_prefix, community, timeout=2, max_iter=512):
            return oid_to_rows.get(oid_prefix, [])
        return _walk

    def test_empty_when_no_snmp_data(self):
        with patch(_SNMP_WALK_PATH, return_value=[]):
            result = w._collect_if_metrics("10.0.0.1", "public")
        assert result == []

    def test_hc_octets_preferred_over_32bit(self):
        """Gdy dostepne HC (64-bit), pomiń 32-bit in_octets/out_octets dla tego samego if_index."""
        hc_in_oid  = "1.3.6.1.2.1.31.1.1.1.6"
        hc_out_oid = "1.3.6.1.2.1.31.1.1.1.10"
        in32_oid   = "1.3.6.1.2.1.2.2.1.10"
        out32_oid  = "1.3.6.1.2.1.2.2.1.16"

        walk_map = {
            hc_in_oid:  [(hc_in_oid  + ".1", "1000000", "Counter64")],
            hc_out_oid: [(hc_out_oid + ".1", "500000",  "Counter64")],
            in32_oid:   [(in32_oid   + ".1", "999",     "Counter32")],  # powinien byc pominiety
            out32_oid:  [(out32_oid  + ".1", "888",     "Counter32")],  # powinien byc pominiety
        }
        with patch(_SNMP_WALK_PATH, side_effect=self._make_walk(walk_map)):
            result = w._collect_if_metrics("10.0.0.1", "public")

        metrics_by_name = {(idx, name): val for idx, name, val in result}
        # HC muszą byc w wynikach
        assert (1, "in_octets_hc")  in metrics_by_name
        assert (1, "out_octets_hc") in metrics_by_name
        # 32-bit muszą byc pominięte gdy HC dostępne
        assert (1, "in_octets")  not in metrics_by_name
        assert (1, "out_octets") not in metrics_by_name

    def test_32bit_used_when_no_hc(self):
        """Gdy brak HC, używaj 32-bit in_octets/out_octets."""
        in32_oid  = "1.3.6.1.2.1.2.2.1.10"
        out32_oid = "1.3.6.1.2.1.2.2.1.16"

        walk_map = {
            in32_oid:  [(in32_oid  + ".2", "12345", "Counter32")],
            out32_oid: [(out32_oid + ".2", "67890", "Counter32")],
        }
        with patch(_SNMP_WALK_PATH, side_effect=self._make_walk(walk_map)):
            result = w._collect_if_metrics("10.0.0.1", "public")

        metrics_by_name = {(idx, name): val for idx, name, val in result}
        assert (2, "in_octets")  in metrics_by_name
        assert (2, "out_octets") in metrics_by_name
        assert metrics_by_name[(2, "in_octets")]  == 12345.0
        assert metrics_by_name[(2, "out_octets")] == 67890.0

    def test_errors_and_discards_always_included(self):
        """in_errors/out_errors/in_discards/out_discards zawsze obecne (nie deduplikowane)."""
        err_in_oid  = "1.3.6.1.2.1.2.2.1.14"
        err_out_oid = "1.3.6.1.2.1.2.2.1.20"
        disc_in_oid = "1.3.6.1.2.1.2.2.1.13"
        disc_out_oid= "1.3.6.1.2.1.2.2.1.19"
        hc_in_oid   = "1.3.6.1.2.1.31.1.1.1.6"

        walk_map = {
            hc_in_oid:   [(hc_in_oid   + ".3", "9999", "Counter64")],
            err_in_oid:  [(err_in_oid  + ".3", "10",   "Counter32")],
            err_out_oid: [(err_out_oid + ".3", "5",    "Counter32")],
            disc_in_oid: [(disc_in_oid + ".3", "2",    "Counter32")],
            disc_out_oid:[(disc_out_oid+ ".3", "1",    "Counter32")],
        }
        with patch(_SNMP_WALK_PATH, side_effect=self._make_walk(walk_map)):
            result = w._collect_if_metrics("10.0.0.1", "public")

        metrics_by_name = {(idx, name): val for idx, name, val in result}
        assert (3, "in_errors")    in metrics_by_name
        assert (3, "out_errors")   in metrics_by_name
        assert (3, "in_discards")  in metrics_by_name
        assert (3, "out_discards") in metrics_by_name

    def test_invalid_oid_value_skipped(self):
        """Niekonwertowalna wartosc (not a number) jest pomijana bez bledu."""
        in32_oid = "1.3.6.1.2.1.2.2.1.10"
        walk_map = {
            in32_oid: [(in32_oid + ".4", "invalid_value", "Counter32")],
        }
        with patch(_SNMP_WALK_PATH, side_effect=self._make_walk(walk_map)):
            result = w._collect_if_metrics("10.0.0.1", "public")
        # Żaden wynik dla if_index 4
        assert not any(idx == 4 for idx, _, _ in result)

    def test_bytes_raw_val_decoded(self):
        """raw_val jako bytes (typ zwracany przez snmp_walk) musi byc poprawnie dekodowany.

        Regresja: float(bytes) rzuca TypeError — wartosci byly ciche dropowane.
        snmp_walk zwraca surowe bajty BER dla Counter32/Counter64.
        """
        in32_oid = "1.3.6.1.2.1.2.2.1.10"
        # b'\x00\x01\x86\xa0' = 100000 decimal (big-endian)
        walk_map = {
            in32_oid: [(in32_oid + ".5", b"\x00\x01\x86\xa0", 0x41)],
        }
        with patch(_SNMP_WALK_PATH, side_effect=self._make_walk(walk_map)):
            result = w._collect_if_metrics("10.0.0.1", "public")
        metrics_by_name = {(idx, name): val for idx, name, val in result}
        assert (5, "in_octets") in metrics_by_name
        assert metrics_by_name[(5, "in_octets")] == 100000.0

    def test_bytes_hc_counter64_decoded(self):
        """Counter64 jako bytes — big-endian 8 bajtow."""
        hc_in_oid = "1.3.6.1.2.1.31.1.1.1.6"
        # 0x0000_0001_0000_0000 = 4294967296 (przekroczone Counter32 max)
        raw = b"\x00\x00\x00\x01\x00\x00\x00\x00"
        walk_map = {
            hc_in_oid: [(hc_in_oid + ".6", raw, 0x46)],
        }
        with patch(_SNMP_WALK_PATH, side_effect=self._make_walk(walk_map)):
            result = w._collect_if_metrics("10.0.0.1", "public")
        metrics_by_name = {(idx, name): val for idx, name, val in result}
        assert (6, "in_octets_hc") in metrics_by_name
        assert metrics_by_name[(6, "in_octets_hc")] == 4294967296.0


# ═══════════════════════════════════════════════════════════════════════════════
# run_snmp_worker._save_fdb — logika z mockowanym DB
# ═══════════════════════════════════════════════════════════════════════════════

_PG_INSERT_PATH = "sqlalchemy.dialects.postgresql.insert"


class TestSaveFdb:
    def test_empty_entries_returns_zero(self):
        db = MagicMock()
        result = w._save_fdb(db, device_id=1, entries=[])
        assert result == 0
        db.execute.assert_not_called()

    def test_returns_count_on_success(self):
        db = MagicMock()
        entries = [
            {"mac": "aa:bb:cc:dd:ee:ff", "bridge_port": 1, "if_index": 3,
             "fdb_status": 3, "vlan_id": None},
        ]
        db.query.return_value.filter.return_value.all.return_value = []

        with patch(_PG_INSERT_PATH) as mock_pg:
            mock_stmt = MagicMock()
            mock_pg.return_value = mock_stmt
            mock_stmt.on_conflict_do_update.return_value = mock_stmt
            result = w._save_fdb(db, device_id=1, entries=entries)

        assert result == 1
        db.commit.assert_called_once()

    def test_db_exception_returns_zero(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = []
        entries = [{"mac": "aa:bb:cc:dd:ee:ff", "bridge_port": 1,
                    "if_index": None, "fdb_status": 3, "vlan_id": None}]

        with patch(_PG_INSERT_PATH, side_effect=Exception("DB error")):
            result = w._save_fdb(db, device_id=1, entries=entries)

        assert result == 0
        db.rollback.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# run_snmp_worker._save_vlan_port
# ═══════════════════════════════════════════════════════════════════════════════

class TestSaveVlanPort:
    def test_empty_entries_returns_zero(self):
        db = MagicMock()
        assert w._save_vlan_port(db, device_id=1, entries=[]) == 0
        db.execute.assert_not_called()

    def test_missing_vlan_id_or_if_index_filtered(self):
        """Wpisy bez vlan_id lub if_index sa pomijane — rows staje sie pusta lista = return 0."""
        db = MagicMock()
        entries = [
            {"vlan_id": None, "if_index": 3, "vlan_name": "Mgmt", "port_mode": "access", "is_pvid": True},
            {"vlan_id": 10,   "if_index": None, "vlan_name": "Data", "port_mode": "trunk", "is_pvid": False},
        ]
        # Nie patchujemy pg_insert — funkcja powinna wrocic przed execute bo rows=[]
        result = w._save_vlan_port(db, device_id=1, entries=entries)
        assert result == 0
        db.execute.assert_not_called()

    def test_valid_entry_saved(self):
        db = MagicMock()
        entries = [{"vlan_id": 10, "if_index": 3, "vlan_name": "Mgmt",
                    "port_mode": "access", "is_pvid": True}]
        with patch(_PG_INSERT_PATH) as mock_pg:
            mock_stmt = MagicMock()
            mock_pg.return_value = mock_stmt
            mock_stmt.on_conflict_do_update.return_value = mock_stmt
            result = w._save_vlan_port(db, device_id=1, entries=entries)
        assert result == 1
        db.commit.assert_called_once()

    def test_db_exception_returns_zero(self):
        db = MagicMock()
        entries = [{"vlan_id": 10, "if_index": 3, "vlan_name": None,
                    "port_mode": "access", "is_pvid": False}]
        with patch(_PG_INSERT_PATH, side_effect=Exception("constraint")):
            result = w._save_vlan_port(db, device_id=1, entries=entries)
        assert result == 0
        db.rollback.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# run_snmp_worker._save_stp_ports
# ═══════════════════════════════════════════════════════════════════════════════

class TestSaveStpPorts:
    def test_empty_ports_and_no_root_returns_zero(self):
        db = MagicMock()
        assert w._save_stp_ports(db, device_id=1, ports=[], root_mac=None, root_cost=None) == 0
        db.execute.assert_not_called()

    def test_only_root_info_updates_device(self):
        """Samo root_mac bez portow aktualizuje device.stp_root_mac i commituje."""
        from netdoc.storage.models import Device
        dev = MagicMock(spec=Device)
        db = MagicMock()
        db.query.return_value.filter_by.return_value.first.return_value = dev

        result = w._save_stp_ports(db, device_id=1, ports=[],
                                    root_mac="aa:bb:cc:dd:ee:ff", root_cost=None)
        assert result == 0
        assert dev.stp_root_mac == "aa:bb:cc:dd:ee:ff"
        db.commit.assert_called_once()

    def test_stp_port_without_port_num_filtered(self):
        """Port bez stp_port_num jest pomijany — rows=[] = return 0."""
        db = MagicMock()
        db.query.return_value.filter_by.return_value.first.return_value = None
        ports = [{"stp_port_num": None, "stp_state": "forwarding", "stp_role": "designated"}]
        result = w._save_stp_ports(db, device_id=1, ports=ports,
                                    root_mac=None, root_cost=None)
        assert result == 0
        db.execute.assert_not_called()

    def test_valid_port_saved(self):
        db = MagicMock()
        db.query.return_value.filter_by.return_value.first.return_value = None
        ports = [{"stp_port_num": 1, "if_index": 3, "stp_state": "forwarding",
                  "stp_role": "designated", "path_cost": 4}]
        with patch(_PG_INSERT_PATH) as mock_pg:
            mock_stmt = MagicMock()
            mock_pg.return_value = mock_stmt
            mock_stmt.on_conflict_do_update.return_value = mock_stmt
            result = w._save_stp_ports(db, device_id=1, ports=ports,
                                        root_mac=None, root_cost=None)
        assert result == 1
        db.commit.assert_called_once()

    def test_db_exception_returns_zero(self):
        db = MagicMock()
        db.query.return_value.filter_by.return_value.first.return_value = None
        ports = [{"stp_port_num": 1, "if_index": 3, "stp_state": "forwarding",
                  "stp_role": "root", "path_cost": 0}]
        with patch(_PG_INSERT_PATH, side_effect=Exception("uq violation")):
            result = w._save_stp_ports(db, device_id=1, ports=ports,
                                        root_mac=None, root_cost=None)
        assert result == 0
        db.rollback.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# run_snmp_worker._reclassify_from_snmp — Cisco device type correction
# ═══════════════════════════════════════════════════════════════════════════════

def _make_cisco_device(device_type, vendor="Cisco IOS", os_version="", model="",
                       snmp_sys_object_id=None, hostname=""):
    """Tworzy mock urządzenia Cisco do testów reklasyfikacji."""
    from netdoc.storage.models import DeviceType
    dev = MagicMock()
    dev.device_type = device_type
    dev.vendor      = vendor
    dev.os_version  = os_version
    dev.model       = model
    dev.hostname    = hostname
    dev.snmp_sys_object_id = snmp_sys_object_id
    return dev


class TestReclassifyCisco:
    def test_catalyst_model_reclassified_to_switch(self):
        """Cisco z modelem WS-C (Catalyst) musi zostac przeklasyfikowany na switch."""
        from netdoc.storage.models import DeviceType
        dev = _make_cisco_device(DeviceType.router, model="WS-C3750X-48P",
                                  os_version="Cisco IOS Software, Catalyst")
        w._reclassify_from_snmp(dev)
        assert dev.device_type == DeviceType.switch

    def test_c9300_switch(self):
        """Cisco Catalyst 9300 — switch."""
        from netdoc.storage.models import DeviceType
        dev = _make_cisco_device(DeviceType.router, model="C9300-48P",
                                  os_version="Cisco IOS XE Software")
        w._reclassify_from_snmp(dev)
        assert dev.device_type == DeviceType.switch

    def test_nexus_nxos_switch(self):
        """Cisco Nexus (NX-OS) — switch DC."""
        from netdoc.storage.models import DeviceType
        dev = _make_cisco_device(DeviceType.router, model="Nexus 9336C-FX2",
                                  os_version="Cisco NX-OS Software")
        w._reclassify_from_snmp(dev)
        assert dev.device_type == DeviceType.switch

    def test_asa_reclassified_to_firewall(self):
        """Cisco ASA musi zostac przeklasyfikowana na firewall."""
        from netdoc.storage.models import DeviceType
        dev = _make_cisco_device(DeviceType.router,
                                  os_version="Cisco Adaptive Security Appliance Software")
        w._reclassify_from_snmp(dev)
        assert dev.device_type == DeviceType.firewall

    def test_asa_by_profile(self):
        """Cisco ASA wykryta przez profil SNMP — firewall."""
        from netdoc.storage.models import DeviceType
        dev = _make_cisco_device(DeviceType.router,
                                  os_version="Cisco IOS Software",
                                  model="ASA5505")
        with patch("netdoc.collector.snmp_profiles.detect_vendor_profile", return_value="cisco_asa"):
            w._reclassify_from_snmp(dev)
        assert dev.device_type == DeviceType.firewall

    def test_wlc_reclassified_to_ap(self):
        """Cisco WLC musi zostac przeklasyfikowany na ap."""
        from netdoc.storage.models import DeviceType
        dev = _make_cisco_device(DeviceType.router,
                                  os_version="Cisco Wireless LAN Controller Software")
        w._reclassify_from_snmp(dev)
        assert dev.device_type == DeviceType.ap

    def test_ios_xr_stays_router(self):
        """Cisco IOS-XR (backbone router) — pozostaje router."""
        from netdoc.storage.models import DeviceType
        dev = _make_cisco_device(DeviceType.router,
                                  os_version="Cisco IOS XR Software")
        w._reclassify_from_snmp(dev)
        assert dev.device_type == DeviceType.router

    def test_isr_router_stays_router(self):
        """Cisco ISR (router) — nie zmieniaj na switch."""
        from netdoc.storage.models import DeviceType
        dev = _make_cisco_device(DeviceType.router, model="ISR4351",
                                  os_version="Cisco IOS XE Software")
        w._reclassify_from_snmp(dev)
        assert dev.device_type == DeviceType.router

    def test_profile_fallback_ios_xe_to_switch(self):
        """Cisco IOS XE bez słów kluczowych w modelu — profil ios_xe → switch (ma FDB)."""
        from netdoc.storage.models import DeviceType
        dev = _make_cisco_device(DeviceType.router, os_version="Cisco IOS XE Software")
        with patch("netdoc.collector.snmp_profiles.detect_vendor_profile", return_value="cisco_ios_xe"):
            w._reclassify_from_snmp(dev)
        assert dev.device_type == DeviceType.switch

    def test_already_correct_type_no_change(self):
        """Urządzenie już poprawnie sklasyfikowane — nie zmieniaj (brak logu)."""
        from netdoc.storage.models import DeviceType
        dev = _make_cisco_device(DeviceType.firewall,
                                  os_version="Cisco Adaptive Security Appliance Software")
        w._reclassify_from_snmp(dev)
        assert dev.device_type == DeviceType.firewall

    def test_non_cisco_not_touched(self):
        """Urządzenie bez Cisco w vendor/os_version — nie reklasyfikuj."""
        from netdoc.storage.models import DeviceType
        dev = _make_cisco_device(DeviceType.router,
                                  vendor="MikroTik",
                                  os_version="RouterOS 7.13")
        original_type = dev.device_type
        w._reclassify_from_snmp(dev)
        # MikroTik nie ma "cisco" ani "ubiquiti" — zostaje bez zmian
        assert dev.device_type == original_type

    def test_c2960_switch(self):
        """Cisco 2960 (klasyczny switch dostępowy) → switch."""
        from netdoc.storage.models import DeviceType
        dev = _make_cisco_device(DeviceType.router, model="WS-C2960-48TC-L",
                                  os_version="Cisco IOS Software, C2960 Software")
        w._reclassify_from_snmp(dev)
        assert dev.device_type == DeviceType.switch
