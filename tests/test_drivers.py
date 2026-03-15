"""Testy unit driverow: CiscoDriver, MikrotikDriver, UnifiDriver.

Wszystkie testy uzywaja mockowan SSH / HTTP — bez prawdziwych polaczen.
"""
import pytest
from unittest.mock import patch, MagicMock, call
from netdoc.storage.models import DeviceType


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _mock_cred(username="admin", password="secret"):
    cred = MagicMock()
    cred.username = username
    cred.password_encrypted = password
    cred.api_key_encrypted = None
    return cred


# ─────────────────────────────────────────────────────────────────────────────
# CiscoDriver — parsery (bez SSH)
# ─────────────────────────────────────────────────────────────────────────────

class TestCiscoDriverParsers:
    """Testuje parsery CiscoDriver bez potrzeby SSH."""

    def setup_method(self):
        from netdoc.collector.drivers.cisco import CiscoDriver
        self.driver = CiscoDriver(ip="10.0.0.1")

    def test_parse_interfaces_empty_list(self):
        assert self.driver._parse_interfaces([]) == []

    def test_parse_interfaces_non_list_returns_empty(self):
        """Gdy output to string (np. blad textfsm) — nie crashuje."""
        assert self.driver._parse_interfaces("Error parsing") == []

    def test_parse_interfaces_parses_basic_entry(self):
        output = [{
            "interface": "GigabitEthernet0/1",
            "ip_address": "192.168.1.1",
            "link_status": "up",
            "protocol_status": "up",
            "description": "Uplink",
        }]
        result = self.driver._parse_interfaces(output)
        assert len(result) == 1
        iface = result[0]
        assert iface.name == "GigabitEthernet0/1"
        assert iface.ip == "192.168.1.1"
        assert iface.oper_status is True
        assert iface.admin_status is True
        assert iface.description == "Uplink"

    def test_parse_interfaces_admin_down(self):
        output = [{
            "interface": "FastEthernet0/2",
            "ip_address": "",
            "link_status": "administratively down",
            "protocol_status": "down",
            "description": "",
        }]
        result = self.driver._parse_interfaces(output)
        assert result[0].admin_status is False
        assert result[0].oper_status is False

    def test_parse_interfaces_no_ip_returns_none(self):
        output = [{"interface": "Lo0", "ip_address": "", "link_status": "up", "protocol_status": "up"}]
        result = self.driver._parse_interfaces(output)
        assert result[0].ip is None

    def test_parse_interfaces_multiple(self):
        output = [
            {"interface": "Gi0/0", "ip_address": "10.0.0.1", "link_status": "up", "protocol_status": "up"},
            {"interface": "Gi0/1", "ip_address": "10.0.1.1", "link_status": "up", "protocol_status": "down"},
            {"interface": "Gi0/2", "ip_address": "", "link_status": "administratively down", "protocol_status": "down"},
        ]
        result = self.driver._parse_interfaces(output)
        assert len(result) == 3
        assert result[1].oper_status is False
        assert result[2].admin_status is False

    def test_parse_lldp_neighbors_empty(self):
        assert self.driver._parse_lldp_neighbors([]) == []

    def test_parse_lldp_neighbors_non_list(self):
        assert self.driver._parse_lldp_neighbors("") == []

    def test_parse_lldp_neighbors_parses_entry(self):
        output = [{
            "local_interface": "Gi0/1",
            "neighbor": "switch-core",
            "management_ip": "192.168.1.254",
            "neighbor_interface": "Gi1/0/1",
        }]
        result = self.driver._parse_lldp_neighbors(output)
        assert len(result) == 1
        nb = result[0]
        assert nb.local_interface == "Gi0/1"
        assert nb.remote_hostname == "switch-core"
        assert nb.remote_ip == "192.168.1.254"
        assert nb.remote_interface == "Gi1/0/1"
        assert nb.protocol == "lldp"

    def test_parse_lldp_neighbors_no_mgmt_ip_returns_none(self):
        output = [{"local_interface": "Gi0/2", "neighbor": "ap1", "management_ip": "", "neighbor_interface": ""}]
        result = self.driver._parse_lldp_neighbors(output)
        assert result[0].remote_ip is None

    def test_parse_lldp_neighbors_multiple(self):
        output = [
            {"local_interface": "Gi0/1", "neighbor": "sw1", "management_ip": "10.0.0.1", "neighbor_interface": "Gi1"},
            {"local_interface": "Gi0/2", "neighbor": "sw2", "management_ip": "10.0.0.2", "neighbor_interface": "Gi2"},
        ]
        result = self.driver._parse_lldp_neighbors(output)
        assert len(result) == 2


class TestCiscoDriverCollect:
    """Testuje collect() z mockiem SSH."""

    def test_collect_auth_failure_returns_empty(self):
        from netdoc.collector.drivers.cisco import CiscoDriver
        from netmiko.exceptions import NetmikoAuthenticationException
        with patch("netdoc.collector.drivers.cisco.ConnectHandler",
                   side_effect=NetmikoAuthenticationException("auth fail")):
            data = CiscoDriver(ip="10.0.0.1").collect()
        assert data.ip == "10.0.0.1"
        assert data.hostname is None

    def test_collect_timeout_returns_empty(self):
        from netdoc.collector.drivers.cisco import CiscoDriver
        from netmiko.exceptions import NetmikoTimeoutException
        with patch("netdoc.collector.drivers.cisco.ConnectHandler",
                   side_effect=NetmikoTimeoutException("timeout")):
            data = CiscoDriver(ip="10.0.0.2").collect()
        assert data.ip == "10.0.0.2"
        assert data.hostname is None

    def test_collect_generic_exception_returns_empty(self):
        from netdoc.collector.drivers.cisco import CiscoDriver
        with patch("netdoc.collector.drivers.cisco.ConnectHandler",
                   side_effect=Exception("connection refused")):
            data = CiscoDriver(ip="10.0.0.3").collect()
        assert data.hostname is None

    def test_collect_success_returns_device_data(self):
        from netdoc.collector.drivers.cisco import CiscoDriver

        mock_conn = MagicMock()
        mock_conn.base_prompt = "Router-HQ"
        mock_conn.send_command.side_effect = [
            [{"hardware": ["C3750-48P"], "version": "15.2(4)"}],  # show version
            [{"interface": "Gi0/1", "ip_address": "10.0.0.1",
              "link_status": "up", "protocol_status": "up", "description": ""}],  # show interfaces
            [],  # show lldp neighbors
        ]
        mock_conn.__enter__ = lambda s: s
        mock_conn.__exit__ = MagicMock(return_value=False)

        with patch("netdoc.collector.drivers.cisco.ConnectHandler", return_value=mock_conn):
            data = CiscoDriver(ip="10.0.0.1").collect()

        assert data.hostname == "Router-HQ"
        assert data.vendor == "Cisco"
        assert data.model == "C3750-48P"
        assert data.os_version == "15.2(4)"
        assert data.device_type == DeviceType.router
        assert len(data.interfaces) == 1

    def test_collect_version_empty_list_returns_no_model(self):
        """Gdy show version zwraca [] — model/os_version sa None."""
        from netdoc.collector.drivers.cisco import CiscoDriver

        mock_conn = MagicMock()
        mock_conn.base_prompt = "Switch"
        mock_conn.send_command.side_effect = [[], [], []]
        mock_conn.__enter__ = lambda s: s
        mock_conn.__exit__ = MagicMock(return_value=False)

        with patch("netdoc.collector.drivers.cisco.ConnectHandler", return_value=mock_conn):
            data = CiscoDriver(ip="10.0.0.5").collect()

        assert data.model is None
        assert data.os_version is None
        assert data.hostname == "Switch"

    def test_collect_uses_credential(self):
        """Driver poprawnie uzyywa podanego credential."""
        from netdoc.collector.drivers.cisco import CiscoDriver
        from netmiko.exceptions import NetmikoTimeoutException

        cred = _mock_cred("cisco_user", "encrypted_pass")
        with patch("netdoc.config.credentials.decrypt", return_value="plain_pass"):
            with patch("netdoc.collector.drivers.cisco.ConnectHandler",
                       side_effect=NetmikoTimeoutException) as mock_ch:
                CiscoDriver(ip="10.0.0.1", credential=cred).collect()

        call_kwargs = mock_ch.call_args[1]
        assert call_kwargs["username"] == "cisco_user"
        assert call_kwargs["password"] == "plain_pass"

    def test_platform_map_ios_xe(self):
        from netdoc.collector.drivers.cisco import CiscoDriver
        driver = CiscoDriver(ip="10.0.0.1", platform="ios-xe")
        assert driver.platform == "cisco_xe"

    def test_platform_map_nxos(self):
        from netdoc.collector.drivers.cisco import CiscoDriver
        driver = CiscoDriver(ip="10.0.0.1", platform="nx-os")
        assert driver.platform == "cisco_nxos"

    def test_platform_map_unknown_defaults_to_ios(self):
        from netdoc.collector.drivers.cisco import CiscoDriver
        driver = CiscoDriver(ip="10.0.0.1", platform="unknown_platform")
        assert driver.platform == "cisco_ios"


# ─────────────────────────────────────────────────────────────────────────────
# MikrotikDriver — parsery (bez SSH)
# ─────────────────────────────────────────────────────────────────────────────

class TestMikrotikDriverParsers:
    """Testuje parsery MikrotikDriver bez potrzeby SSH."""

    def setup_method(self):
        from netdoc.collector.drivers.mikrotik import MikrotikDriver
        self.driver = MikrotikDriver(ip="192.168.88.1")

    def test_parse_value_finds_key(self):
        text = "name: MyRouter\nboard-name: RB3011\nversion: 6.49.7"
        assert self.driver._parse_value(text, "name") == "MyRouter"
        assert self.driver._parse_value(text, "board-name") == "RB3011"
        assert self.driver._parse_value(text, "version") == "6.49.7"

    def test_parse_value_missing_key_returns_none(self):
        text = "name: MyRouter"
        assert self.driver._parse_value(text, "serial-number") is None

    def test_parse_value_strips_whitespace(self):
        text = "name:   Router With Spaces   \n"
        assert self.driver._parse_value(text, "name") == "Router With Spaces"

    def test_parse_interfaces_empty_returns_empty(self):
        assert self.driver._parse_interfaces("") == []

    def test_parse_interfaces_parses_basic_entry(self):
        text = (
            "Flags: D - dynamic, X - disabled\n"
            " 0   name=\"ether1\" mac-address=AA:BB:CC:DD:EE:01 running\n"
            " 1   name=\"ether2\" mac-address=AA:BB:CC:DD:EE:02 disabled"
        )
        result = self.driver._parse_interfaces(text)
        assert len(result) == 2
        assert result[0].name == "ether1"
        assert result[0].oper_status is True
        assert result[0].admin_status is True
        assert result[1].name == "ether2"
        assert result[1].oper_status is False
        assert result[1].admin_status is False

    def test_parse_interfaces_normalizes_mac(self):
        # Regex splits on "\n\s*\d+\s+" — potrzebujemy co najmniej 2 blokow
        text = "header\n 0   name=\"ether1\" mac-address=AA:BB:CC:DD:EE:01 running"
        result = self.driver._parse_interfaces(text)
        assert len(result) >= 1
        assert result[0].mac is not None

    def test_parse_interfaces_no_mac_is_none(self):
        text = "header\n 0   name=\"loopback0\" running"
        result = self.driver._parse_interfaces(text)
        assert len(result) >= 1
        assert result[0].mac is None

    def test_parse_neighbors_empty_returns_empty(self):
        assert self.driver._parse_neighbors("") == []

    def test_parse_neighbors_parses_entry(self):
        text = (
            "Flags: A - active\n"
            " 0   interface=ether1 address=192.168.1.1 identity=\"sw-core\""
        )
        result = self.driver._parse_neighbors(text)
        assert len(result) == 1
        nb = result[0]
        assert nb.local_interface == "ether1"
        assert nb.remote_ip == "192.168.1.1"
        assert nb.remote_hostname == "sw-core"

    def test_parse_neighbors_no_identity_returns_none(self):
        text = "header\n 0   interface=ether2 address=10.0.0.1"
        result = self.driver._parse_neighbors(text)
        assert len(result) >= 1
        assert result[0].remote_hostname is None

    def test_parse_neighbors_no_address_returns_none(self):
        text = "header\n 0   interface=ether3 identity=\"peer1\""
        result = self.driver._parse_neighbors(text)
        assert len(result) >= 1
        assert result[0].remote_ip is None

    def test_parse_neighbors_multiple(self):
        text = (
            "Flags:\n"
            " 0   interface=ether1 address=10.0.0.1 identity=\"sw1\"\n"
            " 1   interface=ether2 address=10.0.0.2 identity=\"sw2\""
        )
        result = self.driver._parse_neighbors(text)
        assert len(result) == 2


class TestMikrotikDriverCollect:
    """Testuje collect() z mockiem SSH."""

    def test_collect_auth_failure_returns_empty(self):
        from netdoc.collector.drivers.mikrotik import MikrotikDriver
        from netmiko.exceptions import NetmikoAuthenticationException
        with patch("netdoc.collector.drivers.mikrotik.ConnectHandler",
                   side_effect=NetmikoAuthenticationException):
            data = MikrotikDriver(ip="192.168.88.1").collect()
        assert data.ip == "192.168.88.1"
        assert data.hostname is None

    def test_collect_timeout_returns_empty(self):
        from netdoc.collector.drivers.mikrotik import MikrotikDriver
        from netmiko.exceptions import NetmikoTimeoutException
        with patch("netdoc.collector.drivers.mikrotik.ConnectHandler",
                   side_effect=NetmikoTimeoutException):
            data = MikrotikDriver(ip="192.168.88.2").collect()
        assert data.hostname is None

    def test_collect_success_returns_device_data(self):
        from netdoc.collector.drivers.mikrotik import MikrotikDriver

        mock_conn = MagicMock()
        mock_conn.send_command.side_effect = [
            "name: MyRouter",            # /system identity print
            "board-name: RB4011\nversion: 6.49.7",  # /system resource print
            "",                          # /interface print detail
            "",                          # /ip neighbor print detail
        ]
        mock_conn.__enter__ = lambda s: s
        mock_conn.__exit__ = MagicMock(return_value=False)

        with patch("netdoc.collector.drivers.mikrotik.ConnectHandler", return_value=mock_conn):
            data = MikrotikDriver(ip="192.168.88.1").collect()

        assert data.hostname == "MyRouter"
        assert data.vendor == "MikroTik"
        assert data.model == "RB4011"
        assert data.os_version == "6.49.7"
        assert data.device_type == DeviceType.router

    def test_collect_with_interfaces_and_neighbors(self):
        from netdoc.collector.drivers.mikrotik import MikrotikDriver

        mock_conn = MagicMock()
        iface_text = "Flags:\n 0   name=\"ether1\" mac-address=AA:BB:CC:DD:EE:01 running"
        neigh_text = "Flags:\n 0   interface=ether1 address=10.0.0.1 identity=\"sw1\""
        mock_conn.send_command.side_effect = [
            "name: TestRouter",
            "board-name: CCR1036\nversion: 7.1",
            iface_text,
            neigh_text,
        ]
        mock_conn.__enter__ = lambda s: s
        mock_conn.__exit__ = MagicMock(return_value=False)

        with patch("netdoc.collector.drivers.mikrotik.ConnectHandler", return_value=mock_conn):
            data = MikrotikDriver(ip="192.168.88.3").collect()

        assert len(data.interfaces) == 1
        assert len(data.neighbors) == 1
        assert data.interfaces[0].name == "ether1"
        assert data.neighbors[0].remote_hostname == "sw1"

    def test_collect_uses_default_admin_when_no_credential(self):
        from netdoc.collector.drivers.mikrotik import MikrotikDriver
        from netmiko.exceptions import NetmikoTimeoutException

        with patch("netdoc.collector.drivers.mikrotik.ConnectHandler",
                   side_effect=NetmikoTimeoutException) as mock_ch:
            MikrotikDriver(ip="192.168.88.1").collect()

        call_kwargs = mock_ch.call_args[1]
        assert call_kwargs["username"] == "admin"
        assert call_kwargs["password"] == ""


# ─────────────────────────────────────────────────────────────────────────────
# UnifiDriver — parsery i collect()
# ─────────────────────────────────────────────────────────────────────────────

class TestUnifiDriverParsers:
    """Testuje _parse_device() bez HTTP."""

    def setup_method(self):
        from netdoc.collector.drivers.unifi import UnifiDriver
        self.driver = UnifiDriver(ip="192.168.1.2")

    def test_parse_device_usg_is_router(self):
        data = {
            "model": "UGW3",
            "name": "USG-HQ",
            "mac": "aa:bb:cc:dd:ee:01",
            "version": "6.8.9",
            "port_table": [],
        }
        result = self.driver._parse_device(data)
        assert result.device_type == DeviceType.router
        assert result.hostname == "USG-HQ"
        assert result.vendor == "Ubiquiti"
        assert result.os_version == "6.8.9"

    def test_parse_device_usw_is_switch(self):
        data = {"model": "USWPRO24", "name": "SW-Office", "mac": "", "version": "6.5", "port_table": []}
        result = self.driver._parse_device(data)
        assert result.device_type == DeviceType.switch

    def test_parse_device_uap_is_ap(self):
        data = {"model": "UAP-AC-LR", "name": "AP-Floor2", "mac": "", "version": "6.2", "port_table": []}
        result = self.driver._parse_device(data)
        assert result.device_type == DeviceType.ap

    def test_parse_device_unknown_model_is_unknown(self):
        data = {"model": "unknown_xyz", "name": "dev1", "mac": "", "version": "", "port_table": []}
        result = self.driver._parse_device(data)
        assert result.device_type == DeviceType.unknown

    def test_parse_device_parses_ports(self):
        data = {
            "model": "USWPRO24",
            "name": "SW",
            "mac": "",
            "version": "",
            "port_table": [
                {"name": "Port 1", "port_idx": 1, "speed": 1000, "up": True, "disabled": False},
                {"name": "Port 2", "port_idx": 2, "speed": 100, "up": False, "disabled": True},
            ],
        }
        result = self.driver._parse_device(data)
        assert len(result.interfaces) == 2
        assert result.interfaces[0].oper_status is True
        assert result.interfaces[0].admin_status is True
        assert result.interfaces[1].oper_status is False
        assert result.interfaces[1].admin_status is False

    def test_parse_device_uses_hostname_when_name_missing(self):
        data = {"model": "UAP", "name": None, "hostname": "ap-fallback", "mac": "", "version": "", "port_table": []}
        result = self.driver._parse_device(data)
        assert result.hostname == "ap-fallback"

    def test_parse_device_normalizes_mac(self):
        data = {"model": "USW", "name": "sw", "mac": "aabb.ccdd.eeff", "version": "", "port_table": []}
        result = self.driver._parse_device(data)
        assert result.mac == "AA:BB:CC:DD:EE:FF"


class TestUnifiDriverCollect:
    """Testuje collect() z mockiem HTTP."""

    def _make_driver(self, ip="192.168.1.2"):
        from netdoc.collector.drivers.unifi import UnifiDriver
        return UnifiDriver(ip=ip)

    def test_collect_login_failure_returns_empty(self):
        from requests.exceptions import RequestException
        driver = self._make_driver()
        with patch.object(driver, "_login", side_effect=RequestException("refused")):
            data = driver.collect()
        assert data.hostname is None
        assert data.ip == "192.168.1.2"

    def test_collect_device_not_found_returns_empty(self):
        driver = self._make_driver("10.1.1.1")
        mock_session = MagicMock()
        with patch.object(driver, "_login", return_value=mock_session):
            with patch.object(driver, "_get_devices", return_value=[
                {"ip": "10.1.1.2", "model": "UAP", "name": "other", "mac": "", "version": "", "port_table": []}
            ]):
                data = driver.collect()
        assert data.hostname is None  # IP not found

    def test_collect_finds_device_by_ip(self):
        driver = self._make_driver("10.1.1.100")
        device_data = {
            "ip": "10.1.1.100",
            "model": "UAP-AC-PRO",
            "name": "AP-Office",
            "mac": "aa:bb:cc:dd:ee:ff",
            "version": "6.5.28",
            "port_table": [],
        }
        mock_session = MagicMock()
        with patch.object(driver, "_login", return_value=mock_session):
            with patch.object(driver, "_get_devices", return_value=[device_data]):
                data = driver.collect()
        assert data.hostname == "AP-Office"
        assert data.device_type == DeviceType.ap
        assert data.vendor == "Ubiquiti"

    def test_collect_multiple_devices_picks_correct_ip(self):
        driver = self._make_driver("10.0.0.2")
        devices = [
            {"ip": "10.0.0.1", "model": "USW", "name": "sw1", "mac": "", "version": "", "port_table": []},
            {"ip": "10.0.0.2", "model": "USG", "name": "gw1", "mac": "", "version": "", "port_table": []},
        ]
        mock_session = MagicMock()
        with patch.object(driver, "_login", return_value=mock_session):
            with patch.object(driver, "_get_devices", return_value=devices):
                data = driver.collect()
        assert data.hostname == "gw1"


# ─────────────────────────────────────────────────────────────────────────────
# BaseDriver helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestBaseDriver:
    """Testuje pomocnicze metody BaseDriver."""

    def _make_driver(self, credential=None):
        from netdoc.collector.drivers.cisco import CiscoDriver
        return CiscoDriver(ip="10.0.0.1", credential=credential)

    def test_get_username_no_credential(self):
        assert self._make_driver()._get_username() is None

    def test_get_username_with_credential(self):
        cred = _mock_cred("admin", "pass")
        assert self._make_driver(cred)._get_username() == "admin"

    def test_get_password_no_credential(self):
        assert self._make_driver()._get_password() is None

    def test_get_password_no_encrypted(self):
        cred = MagicMock()
        cred.password_encrypted = None
        assert self._make_driver(cred)._get_password() is None

    def test_get_password_decrypts(self):
        cred = _mock_cred("admin", "encrypted_blob")
        with patch("netdoc.config.credentials.decrypt", return_value="plaintext") as mock_dec:
            result = self._make_driver(cred)._get_password()
        assert result == "plaintext"
        mock_dec.assert_called_once_with("encrypted_blob")


# ─────────────────────────────────────────────────────────────────────────────
# Normalizer edge cases
# ─────────────────────────────────────────────────────────────────────────────

class TestNormalizerEdgeCases:
    """Dodatkowe edge cases dla normalize_mac."""

    @pytest.mark.parametrize("raw, expected", [
        # Mieszane separatory — replace("-",":") daje poprawne 6 cześci → normalizuje
        ("AA-BB:CC-DD:EE-FF", "AA:BB:CC:DD:EE:FF"),
        # Zbyt krotki
        ("AA:BB:CC", "AA:BB:CC"),
        # Za dlugi
        ("AA:BB:CC:DD:EE:FF:00", "AA:BB:CC:DD:EE:FF:00"),
        # Puste string (nie None)
        ("", None),
        # Lowercase notacja kropkowa — poprawna
        ("aabb.ccdd.eeff", "AA:BB:CC:DD:EE:FF"),
        # Uppercase bez separatorow
        ("AABBCCDDEEFF", "AA:BB:CC:DD:EE:FF"),
        # Zapis Windows z kreskami
        ("AA-BB-CC-DD-EE-FF", "AA:BB:CC:DD:EE:FF"),
        # Single digit hex — zfill w joiningu nie jest uzywane bo split da 6 parts ale poszczegolne maja 2 znaki
        ("00:00:00:00:00:01", "00:00:00:00:00:01"),
    ])
    def test_normalize_mac_edge_cases(self, raw, expected):
        from netdoc.collector.normalizer import normalize_mac
        assert normalize_mac(raw) == expected

    def test_normalize_mac_empty_string_returns_none(self):
        from netdoc.collector.normalizer import normalize_mac
        # pusty string jest falsy -> zwraca None
        assert normalize_mac("") is None

    def test_normalize_mac_whitespace_stripped(self):
        from netdoc.collector.normalizer import normalize_mac
        result = normalize_mac("  AA:BB:CC:DD:EE:FF  ")
        assert result == "AA:BB:CC:DD:EE:FF"

    def test_normalize_mac_lowercase_colon_format(self):
        from netdoc.collector.normalizer import normalize_mac
        assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_interface_data_defaults(self):
        from netdoc.collector.normalizer import InterfaceData
        iface = InterfaceData(name="eth0")
        assert iface.mac is None
        assert iface.ip is None
        assert iface.speed is None
        assert iface.duplex is None
        assert iface.admin_status is True
        assert iface.oper_status is False
        assert iface.description is None

    def test_neighbor_data_defaults(self):
        from netdoc.collector.normalizer import NeighborData
        nb = NeighborData(local_interface="eth0")
        assert nb.remote_ip is None
        assert nb.remote_hostname is None
        assert nb.remote_interface is None
        assert nb.protocol == "lldp"

    def test_device_data_raw_default_empty_dict(self):
        from netdoc.collector.normalizer import DeviceData
        d = DeviceData(ip="1.2.3.4")
        assert isinstance(d.raw, dict)
        assert d.raw == {}

    def test_device_data_stores_raw(self):
        from netdoc.collector.normalizer import DeviceData
        raw = {"key": "value", "number": 42}
        d = DeviceData(ip="1.2.3.4", raw=raw)
        assert d.raw["key"] == "value"
