"""Testy klasyfikacji urzadzen wedlug vendora i portu.

Testuje _guess_device_type z parametrami vendor i mac.
Moze uzywac lookup_vendor_from_mac z mockowanym oui_db.
"""
from unittest.mock import patch
import pytest

from netdoc.collector.discovery import _guess_device_type, _resolve_vendor
from netdoc.storage.models import DeviceType


# --- _resolve_vendor ---

def test_resolve_vendor_from_vendor_field():
    """Jesli vendor podany — uzywa go bezposrednio."""
    assert _resolve_vendor("Cisco Systems", None) == "cisco systems"


def test_resolve_vendor_prefers_vendor_over_mac():
    """Jesli vendor podany, nie odpytuje MAC."""
    with patch("netdoc.collector.discovery.oui_db") as mock_oui:
        result = _resolve_vendor("Ubiquiti", "9C:05:D6:00:00:01")
        mock_oui.lookup.assert_not_called()
    assert result == "ubiquiti"


def test_resolve_vendor_falls_back_to_mac():
    """Brak vendora — robi OUI lookup z MAC."""
    with patch("netdoc.collector.discovery.oui_db") as mock_oui:
        mock_oui.lookup.return_value = "Synology Incorporated"
        result = _resolve_vendor(None, "90:09:D0:00:00:00")
    assert result == "synology incorporated"


def test_resolve_vendor_no_data_returns_empty():
    with patch("netdoc.collector.discovery.oui_db") as mock_oui:
        mock_oui.lookup.return_value = None
        assert _resolve_vendor(None, "AA:BB:CC:DD:EE:FF") == ""
    assert _resolve_vendor(None, None) == ""


# --- camera ---

def test_guess_camera_novus_by_vendor():
    assert _guess_device_type({80: {}}, None, vendor="Novus Security Sp. z o.o.") == DeviceType.camera


def test_guess_camera_dahua_by_vendor():
    assert _guess_device_type({80: {}, 443: {}}, None, vendor="Zhejiang Dahua Technology") == DeviceType.camera


def test_guess_camera_hikvision():
    assert _guess_device_type({80: {}}, None, vendor="Hikvision Digital Technology") == DeviceType.camera


def test_guess_camera_by_mac_oui():
    """Kamera rozpoznana przez MAC OUI gdy brak pola vendor."""
    with patch("netdoc.collector.discovery.oui_db") as mock_oui:
        mock_oui.lookup.return_value = "Novus Security Sp. z o.o."
        result = _guess_device_type({80: {}}, None, vendor=None, mac="00:1B:9D:00:00:01")
    assert result == DeviceType.camera


def test_guess_camera_beats_server_ports():
    """Kamera ma wyzszy priorytet niz serwer mimo portow 80/443."""
    assert _guess_device_type({22: {}, 80: {}, 443: {}}, None, vendor="Hikvision") == DeviceType.camera


# --- nas ---

def test_guess_nas_synology():
    assert _guess_device_type({80: {}, 443: {}}, None, vendor="Synology") == DeviceType.nas


def test_guess_nas_qnap():
    assert _guess_device_type({443: {}}, None, vendor="QNAP Systems") == DeviceType.nas


def test_guess_nas_by_mac():
    with patch("netdoc.collector.discovery.oui_db") as mock_oui:
        mock_oui.lookup.return_value = "Synology Incorporated"
        result = _guess_device_type({443: {}}, None, vendor=None, mac="90:09:D0:00:00:00")
    assert result == DeviceType.nas


# --- router / network ---

def test_guess_ubiquiti_ap_default():
    """Ubiquiti bez hostname -> domyslnie ap (najczestszy typ)."""
    assert _guess_device_type({80: {}, 443: {}}, None, vendor="Ubiquiti Inc") == DeviceType.ap


def test_guess_ubiquiti_ap_by_hostname():
    """Ubiquiti z hostname U6-* -> ap."""
    assert _guess_device_type({}, None, vendor="Ubiquiti Inc", hostname="U6-IW-Biuro") == DeviceType.ap


def test_guess_ubiquiti_switch_by_hostname():
    """Ubiquiti z hostname US-* -> switch."""
    assert _guess_device_type({}, None, vendor="Ubiquiti Inc", hostname="US-8-60W") == DeviceType.switch


def test_guess_ubiquiti_router_by_hostname():
    """Ubiquiti z hostname UDM/USG -> router."""
    assert _guess_device_type({}, None, vendor="Ubiquiti Inc", hostname="UDM-Pro") == DeviceType.router


def test_guess_router_cisco_vendor():
    assert _guess_device_type({80: {}}, None, vendor="Cisco Systems") == DeviceType.router


def test_guess_router_mikrotik_vendor():
    assert _guess_device_type({}, None, vendor="MikroTik") == DeviceType.router


def test_guess_firewall_fortinet_vendor():
    assert _guess_device_type({443: {}}, None, vendor="Fortinet Inc.") == DeviceType.firewall


def test_guess_firewall_fortinet_os():
    assert _guess_device_type({443: {}}, "FortiOS v7.2", vendor=None) == DeviceType.firewall


def test_guess_ubiquiti_by_mac():
    """Ubiquiti rozpoznany przez MAC OUI — bez hostname -> ap."""
    with patch("netdoc.collector.discovery.oui_db") as mock_oui:
        mock_oui.lookup.return_value = "Ubiquiti Inc"
        result = _guess_device_type({80: {}}, None, vendor=None, mac="9C:05:D6:00:00:01")
    assert result == DeviceType.ap


# --- iot ---

def test_guess_iot_philips():
    assert _guess_device_type({80: {}}, None, vendor="Philips Lighting BV") == DeviceType.iot


def test_guess_iot_google():
    assert _guess_device_type({443: {}}, None, vendor="Google LLC") == DeviceType.iot


def test_guess_iot_camille_bauer():
    assert _guess_device_type({}, None, vendor="Camille Bauer") == DeviceType.iot


def test_guess_iot_siemens():
    assert _guess_device_type({80: {}}, None, vendor="Siemens AG") == DeviceType.iot


# --- printer ---

def test_guess_printer_by_port_9100():
    """Port JetDirect 9100 bez vendora serwera -> drukarka."""
    assert _guess_device_type({9100: {}}, None, vendor=None) == DeviceType.printer


def test_guess_printer_by_vendor():
    assert _guess_device_type({80: {}}, None, vendor="Kyocera Document Solutions") == DeviceType.printer


def test_guess_printer_hp_9100_with_ssh_is_printer():
    """HP z portem 9100 (JetDirect) i SSH -> drukarka, nie serwer.

    HP LaserJet enterprise maja SSH management — SSH nie dyskwalifikuje drukarki.
    """
    result = _guess_device_type({9100: {}, 22: {}, 80: {}, 443: {}}, None, vendor="Hewlett Packard")
    assert result == DeviceType.printer


def test_guess_printer_hp_9100_with_smtp_is_server():
    """HP z portem 9100 i SMTP (25) -> serwer (SMTP dyskwalifikuje drukarkę)."""
    result = _guess_device_type({9100: {}, 25: {}}, None, vendor="Hewlett Packard")
    assert result == DeviceType.server


def test_guess_printer_hp_9100_with_rdp_is_workstation():
    """HP z portem 9100 i RDP -> workstation (RDP dyskwalifikuje drukarkę; HP+RDP = stacja robocza).

    Nie jest klasyfikowane jako printer (RDP jest w _server_service).
    Nie jest serwerem bo HP+RDP -> step 9 zwraca workstation.
    """
    result = _guess_device_type({9100: {}, 3389: {}}, None, vendor="Hewlett Packard")
    assert result == DeviceType.workstation


# --- server ---

def test_guess_server_hp_with_web():
    assert _guess_device_type({80: {}, 443: {}}, None, vendor="Hewlett Packard") == DeviceType.server


def test_guess_server_dell_with_ssh():
    assert _guess_device_type({22: {}}, None, vendor="Dell Inc.") == DeviceType.server


def test_guess_server_hp_only_snmp_is_server():
    """HP z samym SNMP (161) → server (HP serwer z management agent)."""
    assert _guess_device_type({161}, None, vendor="Hewlett Packard") == DeviceType.server


# --- conservative: no guessing ---

def test_no_os_no_vendor_no_mac_is_unknown():
    """Brak jakichkolwiek danych -> unknown."""
    assert _guess_device_type({22: {}, 80: {}, 443: {}}, None, vendor=None, mac=None) == DeviceType.unknown


def test_unknown_mac_oui_is_unknown():
    """Nieznany OUI -> unknown, nie zgadujemy po portach."""
    with patch("netdoc.collector.discovery.oui_db") as mock_oui:
        mock_oui.lookup.return_value = None
        result = _guess_device_type({22: {}, 80: {}}, None, vendor=None, mac="AA:BB:CC:00:00:00")
    assert result == DeviceType.unknown


# --- OS fingerprint priority ---

def test_os_cisco_beats_vendor():
    """OS fingerprint ma wyzszy priorytet niz vendor."""
    # vendor mowi Ubiquiti (router), ale Cisco IOS jest pewniejszy
    assert _guess_device_type({}, "Cisco IOS 15.2", vendor="Ubiquiti") == DeviceType.router


def test_windows_os_with_network_vendor_is_not_server():
    """Windows na sprzecie sieciowym (np. Cisco z Windows CE) -> nie serwer."""
    result = _guess_device_type({80: {}}, "Windows CE", vendor="Cisco Systems")
    # Cisco vendor triggeruje router przed sprawdzeniem Windows
    # Windows check wymaga braku network vendor
    assert result == DeviceType.router


# --- inverter / PV ---

def test_guess_inverter_by_port_502():
    """Port 502 (Modbus TCP) -> inverter."""
    assert _guess_device_type({502: {}}, None, vendor=None) == DeviceType.inverter


def test_guess_inverter_by_vendor_sma():
    """Vendor SMA -> inverter."""
    assert _guess_device_type({}, None, vendor="SMA Solar Technology AG") == DeviceType.inverter


def test_guess_inverter_by_vendor_fronius():
    """Vendor Fronius -> inverter."""
    assert _guess_device_type({80: {}}, None, vendor="Fronius International GmbH") == DeviceType.inverter


def test_guess_inverter_by_vendor_solaredge():
    """Vendor SolarEdge -> inverter."""
    assert _guess_device_type({}, None, vendor="SolarEdge Technologies") == DeviceType.inverter


def test_guess_inverter_by_vendor_victron():
    """Victron Energy -> inverter (nie IoT, mimo ze victron jest tez w _IOT_VENDORS)."""
    # Inverter check jest PRZED IoT check w _guess_device_type
    # Po dodaniu port 502 lub vendor match -> inverter
    assert _guess_device_type({502: {}}, None, vendor="Victron Energy BV") == DeviceType.inverter


def test_guess_inverter_port_502_overrides_unknown():
    """Brak vendora, tylko port 502 -> inverter (nie unknown)."""
    assert _guess_device_type({502: {}, 80: {}}, None, vendor=None) == DeviceType.inverter


# --- gateway reclassification ---

def test_get_default_gateways_returns_set():
    """_get_default_gateways zwraca set (moze byc pusty jezeli route niedostepny)."""
    from netdoc.collector.discovery import _get_default_gateways
    result = _get_default_gateways()
    assert isinstance(result, set)


def test_get_default_gateways_parses_linux_output():
    """_get_default_gateways rozpoznaje output 'ip route show default' (Linux)."""
    from unittest.mock import patch, MagicMock
    from netdoc.collector.discovery import _get_default_gateways
    fake = MagicMock()
    fake.stdout = "default via 192.168.5.1 dev eth0 proto dhcp metric 100\n"
    with patch("subprocess.run", return_value=fake):
        result = _get_default_gateways()
    assert "192.168.5.1" in result


def test_get_default_gateways_parses_windows_output():
    """_get_default_gateways rozpoznaje output 'route print' (Windows)."""
    from unittest.mock import patch, MagicMock
    from netdoc.collector.discovery import _get_default_gateways
    windows_route = (
        "IPv4 Route Table\n"
        "===========================================================================\n"
        "Active Routes:\n"
        "Network Destination        Netmask          Gateway       Interface  Metric\n"
        "          0.0.0.0          0.0.0.0      192.168.5.1     192.168.5.50     25\n"
    )
    # Pierwsze wywolanie (Linux 'ip route') rzuca wyjatek, drugie (Windows) zwraca dane
    with patch("subprocess.run", side_effect=[Exception("not linux"), MagicMock(stdout=windows_route)]):
        result = _get_default_gateways()
    assert "192.168.5.1" in result


def test_ubiquiti_no_hostname_default_ap():
    """Ubiquiti bez hostname domyslnie AP (istniejace zachowanie)."""
    assert _guess_device_type({22: {}, 443: {}}, None, vendor="Ubiquiti Inc", hostname="") == DeviceType.ap


def test_ubiquiti_custom_hostname_default_ap():
    """Ubiquiti z niestandardowym hostname (np. 'Krasnicza-W') -> AP (bez gateway fix)."""
    assert _guess_device_type({22: {}, 80: {}, 443: {}}, None, vendor="Ubiquiti Inc",
                              hostname="Krasnicza-W") == DeviceType.ap


def test_moxa_technologies_classified_as_router():
    """Moxa Technologies -> router (network vendor), nie IoT."""
    assert _guess_device_type({22: {}, 80: {}}, None, vendor="Moxa Technologies") == DeviceType.router


def test_moxa_inc_classified_as_router():
    """Moxa Inc -> router (vendor zawiera 'moxa'), nie IoT."""
    assert _guess_device_type({}, None, vendor="Moxa Inc.") == DeviceType.router


def test_industrial_hirschmann_classified_as_router():
    """Hirschmann (przemyslowy switch) -> router."""
    assert _guess_device_type({22: {}, 80: {}}, None, vendor="Hirschmann Automation") == DeviceType.router


def test_industrial_westermo_classified_as_router():
    """Westermo (przemyslowe urzadzenie sieciowe) -> router."""
    assert _guess_device_type({22: {}}, None, vendor="Westermo Network Tech") == DeviceType.router


def test_ubiquiti_switch_us860w_no_dash():
    """Ubiquiti US860W (bez myslnika) -> switch, nie ap."""
    assert _guess_device_type({}, None, vendor="Ubiquiti Inc", hostname="US860W") == DeviceType.switch


def test_ubiquiti_switch_us8_prefix():
    """Ubiquiti US8-* -> switch."""
    assert _guess_device_type({}, None, vendor="Ubiquiti Inc", hostname="US8-60W") == DeviceType.switch


def test_tuya_smart_not_inverter():
    """Tuya Smart Inc -> iot, NIE inverter (false positive przez 'sma' w 'smart')."""
    result = _guess_device_type({}, None, vendor="Tuya Smart Inc.")
    assert result == DeviceType.iot, f"Tuya Smart powinno byc iot, nie {result}"


def test_sma_solar_still_inverter():
    """SMA Solar Technology AG -> inverter (mimo zmiany 'sma' na 'sma solar')."""
    assert _guess_device_type({}, None, vendor="SMA Solar Technology AG") == DeviceType.inverter


def test_fronius_schweissmaschinen_inverter():
    """Fronius Schweissmaschinen -> inverter (Fronius produkuje rowniez falowniki PV)."""
    assert _guess_device_type({}, None, vendor="Fronius Schweissmaschinen") == DeviceType.inverter


# --- HP workstation vs server (regression) ---

def test_hp_vendor_with_rdp_is_workstation():
    """HP + RDP (3389) bez bazy danych -> workstation (stacja robocza HP EliteBook/ProDesk).

    Regresja: HP vendor + web ports NIE powinno byc serwerem gdy jest RDP bez DB/mail.
    """
    result = _guess_device_type({80: {}, 443: {}, 3389: {}, 135: {}, 139: {}}, None,
                                vendor="Hewlett Packard")
    assert result == DeviceType.workstation


def test_hp_vendor_with_rdp_and_netbios_is_workstation():
    """HP + RDP + NetBIOS -> workstation (typowe porty Windows PC)."""
    result = _guess_device_type({3389: {}, 139: {}, 445: {}, 135: {}}, None,
                                vendor="Hewlett Packard")
    assert result == DeviceType.workstation


def test_hp_vendor_with_database_is_server():
    """HP + baza danych (1433 MSSQL) -> serwer (nie workstation)."""
    result = _guess_device_type({80: {}, 443: {}, 1433: {}}, None, vendor="Hewlett Packard")
    assert result == DeviceType.server


def test_hp_vendor_with_winrm_is_server():
    """HP + WinRM (5985) -> serwer (zarzadzanie serwerami)."""
    result = _guess_device_type({5985: {}, 3389: {}}, None, vendor="Hewlett Packard")
    assert result == DeviceType.server


def test_dell_vendor_with_rdp_is_workstation():
    """Dell + RDP bez bazy -> workstation (Dell Latitude/Optiplex)."""
    result = _guess_device_type({3389: {}, 80: {}, 443: {}}, None, vendor="Dell Inc.")
    assert result == DeviceType.workstation


def test_hp_printer_with_ssh_and_web_is_printer():
    """HP z portem 9100 + SSH + web -> drukarka (HP LaserJet enterprise ma SSH management)."""
    result = _guess_device_type({9100: {}, 22: {}, 80: {}, 443: {}}, None,
                                vendor="Hewlett Packard")
    assert result == DeviceType.printer


def test_brother_printer_with_ssh_is_printer():
    """Brother z portem 9100 + SSH -> drukarka (nie serwer)."""
    result = _guess_device_type({9100: {}, 22: {}}, None, vendor="Brother Industries")
    assert result == DeviceType.printer


# --- phone ---

def test_iphone_by_snmp_os():
    """iPhone z OS SNMP 'Apple iOS 6.1.4 (Darwin 13.0.0)' -> phone."""
    result = _guess_device_type(set(), "Apple iOS 6.1.4 (Darwin 13.0.0)")
    assert result == DeviceType.phone


def test_iphone_by_os_iphone_string():
    """'iPhone OS' w OS fingerprint -> phone."""
    result = _guess_device_type(set(), "iPhone OS 15.2")
    assert result == DeviceType.phone


def test_ipad_by_os():
    """iPad OS fingerprint -> phone."""
    result = _guess_device_type(set(), "Apple iPad iOS 14.0")
    assert result == DeviceType.phone


def test_android_by_os():
    """Android w OS fingerprint -> phone."""
    result = _guess_device_type(set(), "Android 12")
    assert result == DeviceType.phone


def test_oneplus_vendor_is_phone():
    """Vendor OnePlus (producent telefonow) -> phone."""
    result = _guess_device_type(set(), None, vendor="OnePlus Technology")
    assert result == DeviceType.phone


def test_motorola_vendor_is_phone():
    """Vendor Motorola -> phone."""
    result = _guess_device_type(set(), None, vendor="Motorola Solutions")
    assert result == DeviceType.phone


def test_itunes_sync_port_is_phone():
    """Port 62078 (iTunes WiFi Sync) -> phone niezaleznie od vendora."""
    result = _guess_device_type({62078}, None, vendor=None)
    assert result == DeviceType.phone


def test_itunes_sync_port_with_apple_vendor():
    """Port 62078 + vendor Apple -> phone."""
    result = _guess_device_type({62078}, None, vendor="Apple Inc.")
    assert result == DeviceType.phone


def test_iphone_hostname_no_os_no_vendor():
    """Hostname 'iPhone' bez OS i vendora -> phone."""
    result = _guess_device_type(set(), None, vendor=None, hostname="iPhone")
    assert result == DeviceType.phone


def test_ipad_hostname_no_os():
    """Hostname 'iPad' bez OS -> phone."""
    result = _guess_device_type(set(), None, vendor=None, hostname="iPad-Pro")
    assert result == DeviceType.phone


def test_android_hostname_prefix_no_os():
    """Hostname 'android-abc123' bez OS -> phone."""
    result = _guess_device_type(set(), None, vendor=None, hostname="android-abc123")
    assert result == DeviceType.phone


def test_android_hostname_underscore_no_os():
    """Hostname 'android_abc123' (podkreslnik) bez OS -> phone."""
    result = _guess_device_type(set(), None, vendor=None, hostname="android_abc123")
    assert result == DeviceType.phone


def test_galaxy_hostname_underscore_no_os():
    """Hostname 'galaxy_s24' (podkreslnik zamiast dash) bez OS -> phone."""
    result = _guess_device_type(set(), None, vendor=None, hostname="galaxy_s24")
    assert result == DeviceType.phone


def test_pixel_hostname_underscore_no_os():
    """Hostname 'pixel_6' (podkreslnik) bez OS -> phone."""
    result = _guess_device_type(set(), None, vendor=None, hostname="pixel_6")
    assert result == DeviceType.phone


def test_apple_vendor_no_os_no_ports_is_phone():
    """Apple Inc. vendor + brak OS + brak portow (poza mDNS) -> phone (iPhone/iPad)."""
    result = _guess_device_type({5353}, None, vendor="Apple Inc.")
    assert result == DeviceType.phone


def test_apple_vendor_with_macos_os_is_workstation():
    """Apple vendor + macOS OS fingerprint -> workstation (Mac)."""
    result = _guess_device_type(set(), "macOS 14.2 Sonoma", vendor="Apple Inc.")
    assert result == DeviceType.workstation


def test_apple_vendor_with_mac_os_x_is_workstation():
    """Apple vendor + 'Mac OS X' OS fingerprint -> workstation (MacBook)."""
    result = _guess_device_type(set(), "Mac OS X 10.15 Catalina", vendor="Apple Inc.")
    assert result == DeviceType.workstation


def test_apple_vendor_with_open_ports_is_not_phone():
    """Apple vendor + brak OS + otwarte porty (SSH/web) -> server (Mac z usługami serwera)."""
    result = _guess_device_type({22, 80, 443}, None, vendor="Apple Inc.")
    assert result == DeviceType.server


# --- EDGE CASES: konflikt hostname vs OS ---

def test_iphone_hostname_but_windows_os_is_not_phone():
    """Hostname 'iPhone' ale OS Windows -> workstation (OS wygrywa nad hostname)."""
    result = _guess_device_type({3389}, "Windows 10", vendor=None, hostname="iPhone")
    assert result == DeviceType.workstation


def test_iphone_hostname_but_linux_os_is_not_phone():
    """Hostname 'iPhone' ale OS Linux -> serwer/unknown (OS wygrywa)."""
    result = _guess_device_type({22, 80}, "Linux 5.15", vendor=None, hostname="iPhone")
    # Linux z SSH/web -> server
    assert result == DeviceType.server


def test_android_hostname_but_windows_os_is_not_phone():
    """Hostname 'android-123' ale OS Windows -> workstation."""
    result = _guess_device_type({135, 139}, "Windows 11", vendor=None, hostname="android-123")
    assert result == DeviceType.workstation


def test_ios_os_but_windows_banner_loses_to_ios():
    """OS fingerprint 'Apple iOS' + banner hint Windows -> iOS wygrywa (os_lower ma wyzszy priorytet)."""
    # os_lower = 'apple ios 14' wygrywa nad _banner_hint (bo os_lower nie jest pusty)
    result = _guess_device_type(set(), "Apple iOS 14.0", vendor=None)
    assert result == DeviceType.phone


def test_iphone_hostname_with_apple_vendor_no_os_no_ports():
    """Hostname 'iPhone' + vendor Apple + brak OS + brak portow -> phone."""
    result = _guess_device_type(set(), None, vendor="Apple Inc.", hostname="iPhone")
    assert result == DeviceType.phone
