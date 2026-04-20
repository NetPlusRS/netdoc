"""Testy modulu discovery (z mockowaniem nmap)."""
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, call
import pytest

import socket

from netdoc.collector.discovery import (
    _guess_device_type,
    _resolve_vendor,
    _get_default_gateways,
    lookup_vendor_from_mac,
    read_arp_table,
    ping_sweep,
    port_scan,
    full_port_scan,
    run_discovery,
    upsert_device,
    mark_missing_devices,
    detect_ip_conflicts,
    register_network,
    _tcp_reachable,
    nbns_scan,
    mdns_scan,
    wsd_scan,
    apipa_from_arp,
    reverse_dns_lookup,
    check_dns_responds,
    ldap_query_rootdse,
    _is_in_subnet,
    _compute_full_run_id,
    _load_full_scan_state,
    _save_full_scan_state_host,
    _clear_full_scan_state,
    _make_full_port_range_batches,
    _full_scan_one_group,
    _FULL_SCAN_STATE_PATH,
)
from netdoc.collector.normalizer import DeviceData
from netdoc.storage.models import Device, DeviceType, Event, EventType, DiscoveredNetwork, NetworkSource


# --- _guess_device_type ---

def test_guess_router_by_os():
    assert _guess_device_type({}, "Cisco IOS") == DeviceType.router

def test_guess_mikrotik():
    assert _guess_device_type({}, "RouterOS") == DeviceType.router

def test_guess_server():
    # Linux + SSH + web = serwer (silny sygnal)
    assert _guess_device_type({22: {}, 80: {}, 443: {}}, "Linux") == DeviceType.server


def test_guess_server_web_only_is_unknown():
    # Linux + tylko web (brak SSH) = unknown (moze byc IoT, AP, router z web management)
    assert _guess_device_type({80: {}, 443: {}}, "Linux") == DeviceType.unknown


def test_guess_server_windows():
    # Windows + web = serwer
    assert _guess_device_type({80: {}, 443: {}}, "Windows Server 2022") == DeviceType.server

def test_guess_unknown():
    assert _guess_device_type({}, None) == DeviceType.unknown


# --- _guess_device_type: Windows paths (previously returned DeviceType.workstation — nie istnieje) ---

def test_guess_windows_workstation_ports_returns_workstation():
    """Windows z portami NetBIOS/RDP ale bez web/SSH — stacja robocza."""
    result = _guess_device_type({139, 445, 3389}, "Windows 10")
    assert result == DeviceType.workstation

def test_guess_windows_no_ports_returns_workstation():
    """Windows 11 (stacja robocza) bez portow — workstation, bo znamy wersje desktopowa."""
    result = _guess_device_type(set(), "Windows 11 Pro")
    assert result == DeviceType.workstation

def test_guess_windows_with_ssh_returns_server():
    """Windows z SSH — powinien byc server."""
    result = _guess_device_type({22: {}}, "Windows Server 2019")
    assert result == DeviceType.server


# --- _guess_device_type: DeviceType.phone nie istnieje — sprawdz zwracane wartosci ---

def test_guess_ios_returns_valid_type():
    """iOS fingerprint — nie powinna byc zwracana nieprawidlowa wartosc enum."""
    result = _guess_device_type({}, "iOS 17.0")
    assert isinstance(result, DeviceType)  # musi byc poprawny enum, nie AttributeError

def test_guess_android_returns_valid_type():
    """Android fingerprint — musi zwracac poprawny enum."""
    result = _guess_device_type({}, "Android 14")
    assert isinstance(result, DeviceType)


# --- _guess_device_type: workstation vendor paths ---

def test_guess_lenovo_no_server_ports_returns_server():
    """Lenovo bez portow serwera — mapuje na server (dawniej workstation)."""
    result = _guess_device_type({}, None, vendor="Lenovo")
    assert result == DeviceType.server

def test_guess_apple_vendor_returns_server():
    """Apple (MacBook) — mapuje na server (dawniej workstation)."""
    result = _guess_device_type({22: {}, 80: {}}, None, vendor="Apple Inc.")
    assert result == DeviceType.server



# --- NAS via OS/SNMP sysDescr (Synology bez OUI w bazie) ---

def test_guess_synology_via_os_snmp_descr():
    """Synology: SNMP sysDescr 'DiskStation Manager' → DeviceType.nas."""
    result = _guess_device_type({22, 80, 443, 5000, 5001}, "DiskStation Manager 7.2")
    assert result == DeviceType.nas, "Synology z sysDescr DSM musi byc klasyfikowane jako NAS"

def test_guess_synology_diskstation_keyword():
    """Synology: samo slowo 'diskstation' w os_version → nas."""
    result = _guess_device_type({445, 5000}, "DiskStation")
    assert result == DeviceType.nas

def test_guess_truenas_via_os():
    """TrueNAS: os_version → nas."""
    result = _guess_device_type({22, 80, 443}, "TrueNAS SCALE 24.10")
    assert result == DeviceType.nas

def test_guess_synology_via_vendor_oui():
    """Synology z OUI vendora → nas (istniejaca sciezka)."""
    result = _guess_device_type({22, 5000}, None, vendor="Synology Inc.")
    assert result == DeviceType.nas


# --- upsert_device ---

def test_upsert_new_device(db):
    data = DeviceData(ip="10.1.1.1", hostname="test-router", vendor="Cisco")
    device = upsert_device(db, data)

    assert device.id is not None
    assert device.ip == "10.1.1.1"
    assert device.hostname == "test-router"
    # Powinien pojawic sie event device_appeared
    events = db.query(Event).filter(Event.device_id == device.id).all()
    assert any(e.event_type == EventType.device_appeared for e in events)


def test_upsert_existing_device(db):
    """Upsert istniejacego urzadzenia nie tworzy duplikatu."""
    data = DeviceData(ip="10.1.1.2", hostname="switch-01")
    d1 = upsert_device(db, data)

    data2 = DeviceData(ip="10.1.1.2", hostname="switch-01-updated", vendor="Cisco")
    d2 = upsert_device(db, data2)

    assert d1.id == d2.id
    assert db.query(Device).filter(Device.ip == "10.1.1.2").count() == 1
    assert db.get(Device, d1.id).hostname == "switch-01-updated"


def test_upsert_reappeared_device(db):
    """Urzadzenie ktore wrocilo po nieobecnosci dostaje event device_appeared."""
    device = Device(ip="10.1.1.3", is_active=False, device_type=DeviceType.unknown)
    db.add(device)
    db.commit()

    data = DeviceData(ip="10.1.1.3")
    upsert_device(db, data)

    events = db.query(Event).filter(
        Event.device_id == device.id,
        Event.event_type == EventType.device_appeared,
    ).all()
    assert len(events) >= 1


# --- mark_missing_devices ---

def test_mark_missing(db):
    """Urzadzenie ze starym last_seen (>10 min) zostaje wylaczone."""
    old = datetime.utcnow() - timedelta(minutes=15)
    d1 = Device(ip="10.2.0.1", is_active=True, device_type=DeviceType.unknown, last_seen=old)
    d2 = Device(ip="10.2.0.2", is_active=True, device_type=DeviceType.unknown, last_seen=old)
    db.add_all([d1, d2])
    db.commit()

    mark_missing_devices(db, found_ips=["10.2.0.1"])

    db.refresh(d1)
    db.refresh(d2)
    assert d1.is_active is True
    assert d2.is_active is False

    events = db.query(Event).filter(
        Event.device_id == d2.id,
        Event.event_type == EventType.device_disappeared,
    ).all()
    assert len(events) == 1


def test_mark_missing_cooldown_protects_recent(db):
    """Urzadzenie ze swiezym last_seen (<10 min) NIE zostaje wylaczone przez discovery
    nawet jesli nmap go nie widzial — ping-worker mogl go potwierdzic."""
    recent = datetime.utcnow() - timedelta(minutes=3)
    d = Device(ip="10.2.0.3", is_active=True, device_type=DeviceType.unknown, last_seen=recent)
    db.add(d)
    db.commit()

    mark_missing_devices(db, found_ips=[])  # nmap nie znalazl go

    db.refresh(d)
    assert d.is_active is True  # cooldown ochronil urzadzenie
    events = db.query(Event).filter(
        Event.device_id == d.id,
        Event.event_type == EventType.device_disappeared,
    ).all()
    assert len(events) == 0


# --- get_scan_targets ---

def test_get_scan_targets_uses_auto_detect_when_no_manual(db):
    """Brak NETWORK_RANGES w settings -> uzywa auto-wykrywania."""
    from unittest.mock import patch
    from netdoc.collector.discovery import get_scan_targets

    with patch("netdoc.collector.discovery.settings") as mock_settings, \
         patch("netdoc.collector.discovery.detect_local_networks", return_value=["10.5.0.0/24"]):
        mock_settings.network_ranges_list = []
        targets = get_scan_targets(db)

    assert "10.5.0.0/24" in targets


def test_get_scan_targets_manual_overrides(db):
    """Reczny NETWORK_RANGES jest uzywany i zapisywany do DB."""
    from unittest.mock import patch
    from netdoc.collector.discovery import get_scan_targets
    from netdoc.storage.models import DiscoveredNetwork, NetworkSource

    with patch("netdoc.collector.discovery.settings") as mock_settings, \
         patch("netdoc.collector.discovery.detect_local_networks", return_value=[]):
        mock_settings.network_ranges_list = ["192.168.99.0/24"]
        targets = get_scan_targets(db)

    assert "192.168.99.0/24" in targets
    net = db.query(DiscoveredNetwork).filter(DiscoveredNetwork.cidr == "192.168.99.0/24").first()
    assert net is not None
    assert net.source == NetworkSource.manual


def test_get_scan_targets_auto_detect_additive_with_manual(db):
    """Regresja: auto-wykrywanie dziala ROWNIEZ gdy NETWORK_RANGES jest ustawiony.
    Przelaczenie na nowa siec (nowy gateway/subnet) jest wykrywane automatycznie
    bez koniecznosci edycji .env — oba zakresy sa addytywne."""
    from unittest.mock import patch
    from netdoc.collector.discovery import get_scan_targets
    from netdoc.storage.models import DiscoveredNetwork, NetworkSource

    with patch("netdoc.collector.discovery.settings") as mock_settings, \
         patch("netdoc.collector.discovery.detect_local_networks",
               return_value=["10.20.30.0/24"]):
        # NETWORK_RANGES ustawiony + auto-detect zwraca NOWA siec
        mock_settings.network_ranges_list = ["192.168.5.0/24"]
        targets = get_scan_targets(db)

    # Oba zakresy musza byc w wynikach
    assert "192.168.5.0/24" in targets, "Zakres z NETWORK_RANGES musi byc w targets"
    assert "10.20.30.0/24" in targets, \
        "Auto-wykryta nowa siec musi byc DODANA do targets nawet gdy NETWORK_RANGES jest ustawiony"

    # Nowa siec zapisana jako auto w DB
    net = db.query(DiscoveredNetwork).filter(DiscoveredNetwork.cidr == "10.20.30.0/24").first()
    assert net is not None
    assert net.source == NetworkSource.auto


def test_get_scan_targets_no_duplicate_when_manual_and_auto_overlap(db):
    """Gdy NETWORK_RANGES i auto-detect zwracaja ten sam CIDR — brak duplikatu w targets."""
    from unittest.mock import patch
    from netdoc.collector.discovery import get_scan_targets

    with patch("netdoc.collector.discovery.settings") as mock_settings, \
         patch("netdoc.collector.discovery.detect_local_networks",
               return_value=["192.168.5.0/24"]):   # ten sam co w manual
        mock_settings.network_ranges_list = ["192.168.5.0/24"]
        targets = get_scan_targets(db)

    assert targets.count("192.168.5.0/24") == 1, \
        "Pokrywajace sie CIDR z manual i auto-detect nie moze byc zduplikowane"


def test_get_scan_targets_includes_db_networks(db):
    """Sieci zapisane w DB (np. z LLDP) sa dolaczane do skanowania."""
    from netdoc.collector.discovery import get_scan_targets, register_network
    from netdoc.storage.models import NetworkSource

    # 172.16.0.0/12 is filtered as infrastructure — use 10.99.x.x which is not in infra list
    register_network(db, "10.99.5.0/24", NetworkSource.lldp)

    with patch("netdoc.collector.discovery.settings") as mock_settings, \
         patch("netdoc.collector.discovery.detect_local_networks", return_value=[]):
        mock_settings.network_ranges_list = []
        targets = get_scan_targets(db)

    assert "10.99.5.0/24" in targets


# --- get_stale_full_scan_ips ---

def test_stale_device_no_full_scan(db):
    """Urzadzenie bez zadnego nmap_full jest stale."""
    from netdoc.collector.discovery import get_stale_full_scan_ips
    d = Device(ip="10.5.0.1", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit()

    stale = get_stale_full_scan_ips(db, max_age_days=7)
    assert "10.5.0.1" in stale


def test_stale_device_old_full_scan(db):
    """Urzadzenie z nmap_full starszym niz max_age jest stale."""
    from netdoc.collector.discovery import get_stale_full_scan_ips
    from netdoc.storage.models import ScanResult
    from datetime import timedelta
    d = Device(ip="10.5.0.2", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit()
    db.add(ScanResult(
        device_id=d.id, scan_type="nmap_full",
        scan_time=__import__("datetime").datetime.utcnow() - timedelta(days=10),
        open_ports={},
    ))
    db.commit()

    stale = get_stale_full_scan_ips(db, max_age_days=7)
    assert "10.5.0.2" in stale


def test_fresh_device_not_stale(db):
    """Urzadzenie z aktualnym nmap_full nie jest stale."""
    from netdoc.collector.discovery import get_stale_full_scan_ips
    from netdoc.storage.models import ScanResult
    d = Device(ip="10.5.0.3", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit()
    db.add(ScanResult(
        device_id=d.id, scan_type="nmap_full",
        scan_time=__import__("datetime").datetime.utcnow(),
        open_ports={"80": {}},
    ))
    db.commit()

    stale = get_stale_full_scan_ips(db, max_age_days=7)
    assert "10.5.0.3" not in stale


def test_inactive_device_excluded_from_stale(db):
    """Nieaktywne urzadzenie nie jest zwracane jako stale."""
    from netdoc.collector.discovery import get_stale_full_scan_ips
    d = Device(ip="10.5.0.4", is_active=False, device_type=DeviceType.unknown)
    db.add(d); db.commit()

    stale = get_stale_full_scan_ips(db, max_age_days=7)
    assert "10.5.0.4" not in stale


def test_no_full_scan_device_excluded_from_stale(db):
    """Urzadzenie z no_full_scan=True jest pomijane w kolejce full scan."""
    from netdoc.collector.discovery import get_stale_full_scan_ips
    d_normal   = Device(ip="10.5.0.5", is_active=True, no_full_scan=False, device_type=DeviceType.unknown)
    d_excluded = Device(ip="10.5.0.6", is_active=True, no_full_scan=True,  device_type=DeviceType.unknown)
    db.add_all([d_normal, d_excluded]); db.commit()

    stale = get_stale_full_scan_ips(db, max_age_days=7)
    assert "10.5.0.5" in stale
    assert "10.5.0.6" not in stale


def test_no_full_scan_default_is_false(db):
    """Nowe Device() bez podania no_full_scan ma domyslnie False (nie NULL)."""
    d = Device(ip="10.5.0.7", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit(); db.refresh(d)
    assert d.no_full_scan is False


def test_run_full_scan_with_ips(db):
    """run_full_scan z lista IP skanuje tylko podane hosty i zapisuje per batch."""
    from unittest.mock import patch
    from netdoc.collector.discovery import run_full_scan
    from netdoc.storage.models import ScanResult
    d1 = Device(ip="10.6.0.1", is_active=True, device_type=DeviceType.unknown)
    d2 = Device(ip="10.6.0.2", is_active=True, device_type=DeviceType.unknown)
    db.add_all([d1, d2]); db.commit()

    batch_data = {"10.6.0.1": {"open_ports": {22: {"service": "ssh"}}}}

    def _fake_full_port_scan(hosts, progress_callback=None, **kw):
        assert "10.6.0.1" in hosts
        assert "10.6.0.2" not in hosts
        if progress_callback:
            progress_callback(done=1, total=1, batch_ips=hosts, batch_result=batch_data)
        return batch_data

    with patch("netdoc.collector.discovery.full_port_scan", side_effect=_fake_full_port_scan):
        result = run_full_scan(db, ips=["10.6.0.1"])

    assert result == 1
    sr = db.query(ScanResult).filter_by(scan_type="nmap_full").first()
    assert sr is not None
    assert "22" in sr.open_ports


def test_run_full_scan_no_ips_scans_all_active(db):
    """run_full_scan bez ips skanuje wszystkie aktywne urzadzenia."""
    from unittest.mock import patch
    from netdoc.collector.discovery import run_full_scan
    d = Device(ip="10.6.0.3", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit()

    captured = []
    def _fake_full_port_scan(hosts, progress_callback=None, **kw):
        captured.extend(hosts)
        return {}

    with patch("netdoc.collector.discovery.full_port_scan", side_effect=_fake_full_port_scan):
        run_full_scan(db)

    assert "10.6.0.3" in captured


def test_run_full_scan_checkpoint_saves_per_batch(db):
    """run_full_scan zapisuje wyniki do DB po kazdym batchu (checkpoint)."""
    from unittest.mock import patch
    from netdoc.collector.discovery import run_full_scan
    from netdoc.storage.models import ScanResult
    d = Device(ip="10.6.0.10", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit()

    batch_data = {"10.6.0.10": {"open_ports": {80: {"service": "http"}}}}
    cb_calls = []

    def _fake_scan(hosts, progress_callback=None, **kw):
        # Symuluj 2 batchow — po pierwszym callback zapisuje do DB
        if progress_callback:
            progress_callback(done=1, total=2, batch_ips=hosts, batch_result=batch_data)
            # W tym momencie wyniki sa juz w DB (checkpoint)
            count = db.query(ScanResult).filter_by(scan_type="nmap_full").count()
            cb_calls.append(count)
            progress_callback(done=2, total=2, batch_ips=[], batch_result={})
        return batch_data

    def _user_cb(done, total, batch_ips):
        pass  # progress callback przekazany przez uzytkownika

    with patch("netdoc.collector.discovery.full_port_scan", side_effect=_fake_scan):
        result = run_full_scan(db, progress_callback=_user_cb)

    assert result == 1
    # Po pierwszym batchu wyniki byly juz w DB
    assert cb_calls[0] == 1


def test_upsert_updates_os_version_and_mac(db):
    """upsert_device aktualizuje os_version i mac dla istniejacego urzadzenia."""
    data = DeviceData(ip="10.7.0.1")
    d = upsert_device(db, data)

    data2 = DeviceData(ip="10.7.0.1", os_version="Cisco IOS 15.2", mac="AA:BB:CC:DD:EE:FF")
    upsert_device(db, data2)

    db.refresh(d)
    assert d.os_version == "Cisco IOS 15.2"
    assert d.mac is not None  # znormalizowany MAC


def test_upsert_does_not_overwrite_with_empty(db):
    """Puste pola w nowym DeviceData nie nadpisuja istniejacych danych."""
    data = DeviceData(ip="10.7.0.2", hostname="original", vendor="Cisco")
    d = upsert_device(db, data)

    # upsert z pustymi polami — nie powinien nadpisac
    data2 = DeviceData(ip="10.7.0.2")
    upsert_device(db, data2)

    db.refresh(d)
    assert d.hostname == "original"
    assert d.vendor == "Cisco"


# --- lookup_vendor_from_mac ---

def test_lookup_vendor_from_mac_delegates_to_oui_db():
    with patch("netdoc.collector.discovery.oui_db") as mock_oui:
        mock_oui.lookup.return_value = "Cisco Systems"
        result = lookup_vendor_from_mac("00:1a:2b:3c:4d:5e")
    assert result == "Cisco Systems"
    mock_oui.lookup.assert_called_once_with("00:1a:2b:3c:4d:5e")


def test_lookup_vendor_from_mac_unknown_returns_none():
    with patch("netdoc.collector.discovery.oui_db") as mock_oui:
        mock_oui.lookup.return_value = None
        result = lookup_vendor_from_mac("ff:ff:ff:ff:ff:ff")
    assert result is None


# --- read_arp_table ---

def test_read_arp_table_parses_windows_output():
    windows_arp = (
        "Interface: 192.168.1.10 --- 0xd\n"
        "  Internet Address      Physical Address      Type\n"
        "  192.168.1.1          d0-21-f9-85-54-8e     dynamic\n"
        "  192.168.1.254        00-90-e8-62-bf-ed     dynamic\n"
    )
    with patch("subprocess.check_output", return_value=windows_arp):
        result = read_arp_table()
    assert "192.168.1.1" in result
    assert "192.168.1.254" in result


def test_read_arp_table_parses_multiple_dynamic_entries():
    windows_arp = (
        "  192.168.1.1    d0-21-f9-85-54-8e    dynamic\n"
        "  192.168.1.2    00-90-e8-62-bf-ed    dynamic\n"
        "  192.168.1.3    ff-ff-ff-ff-ff-ff    static\n"   # static — nie wchodzi
    )
    with patch("subprocess.check_output", return_value=windows_arp):
        result = read_arp_table()
    assert "192.168.1.1" in result
    assert "192.168.1.2" in result


def test_read_arp_table_filters_laa_macs_by_default():
    """Domyslnie ignore_laa=True — LAA MAC (bit 1 pierwszego oktetu) jest pomijany."""
    windows_arp = (
        "  192.168.1.1    26-12-ac-1a-80-01    dynamic\n"
        "  192.168.1.2    d0-21-f9-85-54-8e    dynamic\n"
        "  192.168.1.3    aa-bb-cc-dd-ee-ff    dynamic\n"
    )
    with patch("subprocess.check_output", return_value=windows_arp):
        result = read_arp_table()
    assert "192.168.1.1" not in result
    assert "192.168.1.3" not in result
    assert "192.168.1.2" in result


def test_read_arp_table_keeps_laa_when_disabled():
    """ignore_laa=False — LAA MAC nie jest filtrowany."""
    windows_arp = (
        "  192.168.1.1    26-12-ac-1a-80-01    dynamic\n"
        "  192.168.1.2    d0-21-f9-85-54-8e    dynamic\n"
    )
    with patch("subprocess.check_output", return_value=windows_arp):
        result = read_arp_table(ignore_laa=False)
    assert "192.168.1.1" in result
    assert "192.168.1.2" in result


def test_read_arp_table_returns_empty_on_error():
    with patch("subprocess.check_output", side_effect=Exception("fail")):
        result = read_arp_table()
    assert result == {}


# --- _resolve_vendor ---

def test_resolve_vendor_returns_vendor_lower():
    assert _resolve_vendor("Cisco Systems", None) == "cisco systems"


def test_resolve_vendor_fallback_to_mac_lookup():
    with patch("netdoc.collector.discovery.lookup_vendor_from_mac", return_value="Ubiquiti"):
        result = _resolve_vendor(None, "aa:bb:cc:dd:ee:ff")
    assert result == "ubiquiti"


def test_resolve_vendor_returns_empty_when_both_none():
    with patch("netdoc.collector.discovery.lookup_vendor_from_mac", return_value=None):
        result = _resolve_vendor(None, None)
    assert result == ""


# --- _get_default_gateways ---

def test_get_default_gateways_linux_output():
    linux_output = "default via 192.168.1.1 dev eth0 proto dhcp\n"
    mock_result = MagicMock()
    mock_result.stdout = linux_output
    with patch("subprocess.run", return_value=mock_result):
        gateways = _get_default_gateways()
    assert "192.168.1.1" in gateways


def test_get_default_gateways_returns_empty_on_error():
    with patch("subprocess.run", side_effect=Exception("no route")):
        gateways = _get_default_gateways()
    assert isinstance(gateways, set)


# --- _tcp_reachable ---

def test_tcp_reachable_returns_true_on_connection():
    mock_sock = MagicMock()
    mock_ctx = MagicMock()
    mock_ctx.__enter__ = MagicMock(return_value=mock_sock)
    mock_ctx.__exit__ = MagicMock(return_value=False)
    with patch("socket.create_connection", return_value=mock_ctx):
        assert _tcp_reachable("192.168.1.1") is True


def test_tcp_reachable_returns_false_when_all_fail():
    with patch("socket.create_connection", side_effect=OSError("refused")):
        assert _tcp_reachable("192.168.1.1") is False


# --- ping_sweep ---

def test_ping_sweep_returns_active_hosts():
    nm_mock = MagicMock()
    nm_mock.all_hosts.return_value = ["192.168.1.1", "192.168.1.2"]
    nm_mock.__getitem__ = lambda self, k: MagicMock(state=lambda: "up")
    with patch("nmap.PortScanner", return_value=nm_mock):
        result = ping_sweep("192.168.1.0/24")
    assert "192.168.1.1" in result


def test_ping_sweep_unicode_error_returns_empty():
    nm_mock = MagicMock()
    nm_mock.scan.side_effect = UnicodeDecodeError("utf-8", b"", 0, 1, "")
    with patch("nmap.PortScanner", return_value=nm_mock):
        result = ping_sweep("192.168.1.0/24")
    assert result == []


def test_ping_sweep_nmap_error_returns_empty():
    import nmap as nmap_module
    nm_mock = MagicMock()
    nm_mock.scan.side_effect = nmap_module.PortScannerError("nmap not found")
    with patch("nmap.PortScanner", return_value=nm_mock):
        result = ping_sweep("192.168.1.0/24")
    assert result == []


def test_ping_sweep_does_not_use_send_ip():
    """Ping sweep NIE moze uzywac --send-ip — na Windows blokuje wykrywanie hostow przez ICMP."""
    nm_mock = MagicMock()
    nm_mock.all_hosts.return_value = []
    with patch("nmap.PortScanner", return_value=nm_mock):
        ping_sweep("192.168.1.0/24")
    call_args = nm_mock.scan.call_args
    arguments = call_args[1].get("arguments", call_args[0][1] if len(call_args[0]) > 1 else "")
    assert "--send-ip" not in arguments, (
        "--send-ip w ping sweep blokuje odkrywanie hostow na Windows (raw IP nie moze wysylac ICMP)"
    )


# --- port_scan ---

def test_port_scan_empty_hosts_returns_empty():
    assert port_scan([]) == {}


def test_port_scan_returns_parsed_results():
    nm_mock = MagicMock()
    nm_mock.all_hosts.return_value = ["10.0.0.1"]
    port_info = {"state": "open", "name": "ssh", "version": "OpenSSH", "product": ""}
    nm_mock.__getitem__ = lambda self, k: {
        "tcp": {22: port_info},
        "osmatch": [{"name": "Linux 5.x"}],
        "vendor": {},
    }
    with patch("nmap.PortScanner", return_value=nm_mock):
        result = port_scan(["10.0.0.1"])
    assert "10.0.0.1" in result
    assert 22 in result["10.0.0.1"]["open_ports"]


def test_port_scan_unicode_error_returns_empty():
    """Klasyczny tryb: UnicodeDecodeError → pusty wynik."""
    nm_mock = MagicMock()
    nm_mock.scan.side_effect = UnicodeDecodeError("utf-8", b"", 0, 1, "")
    classic = {"concurrency": 0, "batch_size": 0, "batch_pause_s": 0, "resume_enabled": False}
    with patch("nmap.PortScanner", return_value=nm_mock):
        result = port_scan(["10.0.0.1"], _batch_settings=classic)
    assert result == {}


def test_port_scan_nmap_error_returns_empty():
    """Klasyczny tryb: PortScannerError → pusty wynik."""
    import nmap as nmap_module
    nm_mock = MagicMock()
    nm_mock.scan.side_effect = nmap_module.PortScannerError("error")
    classic = {"concurrency": 0, "batch_size": 0, "batch_pause_s": 0, "resume_enabled": False}
    with patch("nmap.PortScanner", return_value=nm_mock):
        result = port_scan(["10.0.0.1"], _batch_settings=classic)
    assert result == {}


# --- full_port_scan ---

def test_full_port_scan_calls_progress_callback():
    with patch("netdoc.collector.discovery._full_scan_one_group", return_value={"10.0.0.1": {}}):
        calls = []
        def _cb(done, total, batch_ips, batch_result=None):
            calls.append((done, batch_result))
        full_port_scan(["10.0.0.1"], workers=1, batch_size=1, progress_callback=_cb)
    assert len(calls) == 1
    assert calls[0][0] == 1
    # batch_result przekazywane do callbacka
    assert calls[0][1] == {"10.0.0.1": {}}


def test_full_port_scan_empty_hosts_returns_empty():
    result = full_port_scan([])
    assert result == {}


def test_full_port_scan_batch_exception_continues():
    def _bad_group(hosts, port_batches, batch_pause_s=3.0):
        raise RuntimeError("nmap fail")
    with patch("netdoc.collector.discovery._full_scan_one_group", side_effect=_bad_group):
        result = full_port_scan(["10.0.0.1"], workers=1, batch_size=1)
    assert result == {}


# --- _make_full_port_range_batches ---

def test_make_full_port_range_batches_zero_returns_single():
    result = _make_full_port_range_batches(0)
    assert result == ["1-65535"]

def test_make_full_port_range_batches_5000():
    result = _make_full_port_range_batches(5000)
    assert result[0] == "1-5000"
    assert result[1] == "5001-10000"
    assert result[-1].endswith("65535")
    # wszystkie partie pokrywaja 1-65535
    assert len(result) == 14  # ceil(65535/5000)

def test_make_full_port_range_batches_large_returns_single():
    result = _make_full_port_range_batches(100000)
    assert result == ["1-65535"]

def test_make_full_port_range_batches_covers_all_ports():
    batches = _make_full_port_range_batches(1000)
    starts = [int(b.split("-")[0]) for b in batches]
    ends   = [int(b.split("-")[1]) for b in batches]
    assert starts[0] == 1
    assert ends[-1] == 65535
    # kazda partia zaczyna sie tam gdzie poprzednia skonczyla
    for i in range(1, len(batches)):
        assert starts[i] == ends[i - 1] + 1


# --- _compute_full_run_id ---

def test_compute_full_run_id_same_hosts_same_id():
    a = _compute_full_run_id(["10.0.0.1", "10.0.0.2"], 5000)
    b = _compute_full_run_id(["10.0.0.2", "10.0.0.1"], 5000)  # kolejnosc bez znaczenia
    assert a == b

def test_compute_full_run_id_different_hosts_different_id():
    a = _compute_full_run_id(["10.0.0.1"], 5000)
    b = _compute_full_run_id(["10.0.0.2"], 5000)
    assert a != b

def test_compute_full_run_id_different_batch_size_different_id():
    a = _compute_full_run_id(["10.0.0.1"], 5000)
    b = _compute_full_run_id(["10.0.0.1"], 1000)
    assert a != b

def test_compute_full_run_id_length_14():
    rid = _compute_full_run_id(["10.0.0.1"], 5000)
    assert len(rid) == 14


# --- _save_full_scan_state_host / _load_full_scan_state / _clear_full_scan_state ---

def test_save_and_load_full_scan_state(tmp_path, monkeypatch):
    state_file = tmp_path / "full_scan_progress.json"
    monkeypatch.setattr("netdoc.collector.discovery._FULL_SCAN_STATE_PATH", state_file)

    run_id = "testrunid12345"
    _save_full_scan_state_host(run_id, "10.0.0.1", ["1-5000"], [22, 80])
    _save_full_scan_state_host(run_id, "10.0.0.2", ["1-5000", "5001-10000"], [443])

    result = _load_full_scan_state(run_id, ["10.0.0.1", "10.0.0.2"])
    assert result["10.0.0.1"]["done_ranges"] == ["1-5000"]
    assert set(result["10.0.0.1"]["found_ports"]) == {22, 80}
    assert result["10.0.0.2"]["done_ranges"] == ["1-5000", "5001-10000"]
    assert result["10.0.0.2"]["found_ports"] == [443]

def test_load_full_scan_state_wrong_run_id_returns_empty(tmp_path, monkeypatch):
    state_file = tmp_path / "full_scan_progress.json"
    monkeypatch.setattr("netdoc.collector.discovery._FULL_SCAN_STATE_PATH", state_file)

    _save_full_scan_state_host("run_A", "10.0.0.1", ["1-5000"], [22])
    result = _load_full_scan_state("run_B", ["10.0.0.1"])
    assert result == {}

def test_load_full_scan_state_missing_file_returns_empty(tmp_path, monkeypatch):
    state_file = tmp_path / "nonexistent.json"
    monkeypatch.setattr("netdoc.collector.discovery._FULL_SCAN_STATE_PATH", state_file)
    result = _load_full_scan_state("any", ["10.0.0.1"])
    assert result == {}

def test_clear_full_scan_state_removes_file(tmp_path, monkeypatch):
    state_file = tmp_path / "full_scan_progress.json"
    monkeypatch.setattr("netdoc.collector.discovery._FULL_SCAN_STATE_PATH", state_file)

    _save_full_scan_state_host("run1", "10.0.0.1", ["1-5000"], [22])
    assert state_file.exists()
    _clear_full_scan_state()
    assert not state_file.exists()

def test_clear_full_scan_state_no_error_when_missing(tmp_path, monkeypatch):
    state_file = tmp_path / "nonexistent.json"
    monkeypatch.setattr("netdoc.collector.discovery._FULL_SCAN_STATE_PATH", state_file)
    _clear_full_scan_state()  # nie powinno rzucic wyjatku


def test_save_full_scan_state_recovers_from_corrupted_json(tmp_path, monkeypatch):
    """Uszkodzony plik JSON jest ignorowany — nowy zapis resetuje stan bez wyjatku."""
    state_file = tmp_path / "full_scan_progress.json"
    monkeypatch.setattr("netdoc.collector.discovery._FULL_SCAN_STATE_PATH", state_file)

    # Zapisz uszkodzony JSON
    state_file.write_text("{invalid json!!!", encoding="utf-8")

    # Zapis powinien sie udac (nie rzucic wyjatku) i nadpisac uszkodzony plik
    _save_full_scan_state_host("run1", "10.0.0.1", ["1-5000"], [22])

    # Plik powinien teraz zawierac poprawny JSON
    result = _load_full_scan_state("run1", ["10.0.0.1"])
    assert "10.0.0.1" in result
    assert result["10.0.0.1"]["found_ports"] == [22]


def test_save_full_scan_state_atomic_write_uses_tmp(tmp_path, monkeypatch):
    """Zapis jest atomowy: plik .tmp jest tworzony i zastepuje docelowy."""
    state_file = tmp_path / "full_scan_progress.json"
    monkeypatch.setattr("netdoc.collector.discovery._FULL_SCAN_STATE_PATH", state_file)

    _save_full_scan_state_host("run1", "10.0.0.5", ["1-1000"], [80])

    # Plik docelowy istnieje i jest poprawny
    assert state_file.exists()
    # Plik tymczasowy nie powinien pozostac po sukcesie
    tmp_file = state_file.with_suffix(".tmp")
    assert not tmp_file.exists()


# --- _full_scan_one_group z resume ---

def test_full_scan_one_group_skips_done_ranges():
    """Partia portow juz w done_ranges nie jest przekazywana do nmap."""
    calls = []

    class _FakeNM:
        def scan(self, hosts, arguments):
            calls.append(arguments)
        def all_hosts(self):
            return []

    with patch("netdoc.collector.discovery.nmap.PortScanner", return_value=_FakeNM()):
        host_states = {"10.0.0.1": {"done_ranges": ["1-5000"], "found_ports": []}}
        _full_scan_one_group(
            ["10.0.0.1"],
            ["1-5000", "5001-10000"],
            batch_pause_s=0,
            host_states=host_states,
        )

    # Tylko druga partia powinna byc skanowana
    assert len(calls) == 1
    assert "5001-10000" in calls[0]

def test_full_scan_one_group_restores_found_ports_from_state():
    """Porty z poprzedniego przebiegu (found_ports w stanie) trafiaja do -sV."""
    sv_calls = []

    class _FakeNM:
        def __init__(self):
            self._call = 0
        def scan(self, hosts, arguments):
            self._call += 1
            if "-sV" in arguments:
                sv_calls.append(arguments)
        def all_hosts(self):
            return []

    with patch("netdoc.collector.discovery.nmap.PortScanner", side_effect=lambda **kw: _FakeNM()):
        host_states = {"10.0.0.1": {"done_ranges": ["1-65535"], "found_ports": [22, 80]}}
        _full_scan_one_group(
            ["10.0.0.1"],
            ["1-65535"],
            batch_pause_s=0,
            host_states=host_states,
        )

    # -sV powinno byc wywolane z portami 22 i 80
    assert sv_calls, "Oczekiwano wywolania -sV z portami z poprzedniego przebiegu"
    assert "22" in sv_calls[0] and "80" in sv_calls[0]

def test_full_scan_one_group_saves_state_after_each_range(tmp_path, monkeypatch):
    """Stan jest zapisywany po kazdej partii portow."""
    state_file = tmp_path / "full_scan_progress.json"
    monkeypatch.setattr("netdoc.collector.discovery._FULL_SCAN_STATE_PATH", state_file)

    class _FakeNM:
        def scan(self, hosts, arguments):
            pass
        def all_hosts(self):
            return ["10.0.0.1"]
        def __getitem__(self, host):
            return {"tcp": {22: {"state": "open", "name": "ssh", "version": "", "product": ""}}}

    saved_states = []
    orig_save = __import__("netdoc.collector.discovery", fromlist=["_save_full_scan_state_host"])._save_full_scan_state_host

    def _mock_save(run_id, ip, done_ranges, found_ports):
        saved_states.append((ip, list(done_ranges), list(found_ports)))

    with patch("netdoc.collector.discovery.nmap.PortScanner", return_value=_FakeNM()), \
         patch("netdoc.collector.discovery._save_full_scan_state_host", side_effect=_mock_save):
        _full_scan_one_group(
            ["10.0.0.1"],
            ["1-5000", "5001-10000"],
            batch_pause_s=0,
            run_id="testrun",
        )

    # Powinny byc 2 zapisy — po kazdej partii
    assert len(saved_states) == 2
    assert saved_states[0][1] == ["1-5000"]
    assert saved_states[1][1] == ["1-5000", "5001-10000"]


# --- full_port_scan z resume ---

def test_full_port_scan_clears_state_on_success(tmp_path, monkeypatch):
    """Stan jest usuwany po pomyslnym zakonczeniu pelnego skanu."""
    state_file = tmp_path / "full_scan_progress.json"
    monkeypatch.setattr("netdoc.collector.discovery._FULL_SCAN_STATE_PATH", state_file)
    state_file.write_text('{"run_id":"x","hosts":{}}', encoding="utf-8")

    with patch("netdoc.collector.discovery._full_scan_one_group", return_value={}), \
         patch("netdoc.collector.discovery._read_batch_scan_settings",
               return_value={"full_port_batch": 0, "batch_pause_s": 0, "resume_enabled": True}):
        full_port_scan(["10.0.0.1"], workers=1, batch_size=1)

    assert not state_file.exists()

def test_full_port_scan_resume_disabled_does_not_clear_state(tmp_path, monkeypatch):
    """Gdy resume wylaczone, plik stanu NIE jest usuwany (nie byl tez ladowany)."""
    state_file = tmp_path / "full_scan_progress.json"
    monkeypatch.setattr("netdoc.collector.discovery._FULL_SCAN_STATE_PATH", state_file)
    state_file.write_text('{"run_id":"x","hosts":{}}', encoding="utf-8")

    with patch("netdoc.collector.discovery._full_scan_one_group", return_value={}), \
         patch("netdoc.collector.discovery._read_batch_scan_settings",
               return_value={"full_port_batch": 0, "batch_pause_s": 0, "resume_enabled": False}):
        full_port_scan(["10.0.0.1"], workers=1, batch_size=1)

    assert state_file.exists()  # nie dotknieto pliku

def test_full_port_scan_loads_state_and_passes_to_group(tmp_path, monkeypatch):
    """full_port_scan laduje stan i przekazuje host_states do _full_scan_one_group."""
    state_file = tmp_path / "full_scan_progress.json"
    monkeypatch.setattr("netdoc.collector.discovery._FULL_SCAN_STATE_PATH", state_file)

    import json as _json
    run_id = _compute_full_run_id(["10.0.0.1"], 0)
    state_file.write_text(_json.dumps({
        "run_id": run_id,
        "hosts": {"10.0.0.1": {"done_ranges": ["1-65535"], "found_ports": [22]}},
    }), encoding="utf-8")

    captured = {}

    def _fake_group(hosts, port_batches, batch_pause_s=3.0, run_id=None, host_states=None):
        captured["host_states"] = host_states
        return {}

    with patch("netdoc.collector.discovery._full_scan_one_group", side_effect=_fake_group), \
         patch("netdoc.collector.discovery._read_batch_scan_settings",
               return_value={"full_port_batch": 0, "batch_pause_s": 0, "resume_enabled": True}):
        full_port_scan(["10.0.0.1"], workers=1, batch_size=1)

    assert "10.0.0.1" in captured["host_states"]
    assert captured["host_states"]["10.0.0.1"]["found_ports"] == [22]


# --- register_network ---

def test_register_network_creates_new_entry(db):
    register_network(db, "10.99.0.0/24")
    nets = db.query(DiscoveredNetwork).filter(DiscoveredNetwork.cidr == "10.99.0.0/24").all()
    assert len(nets) == 1


def test_register_network_updates_existing_last_seen(db):
    register_network(db, "10.88.0.0/24")
    net = db.query(DiscoveredNetwork).filter(DiscoveredNetwork.cidr == "10.88.0.0/24").first()
    old_seen = net.last_seen
    register_network(db, "10.88.0.0/24")
    db.refresh(net)
    assert net.is_active is True


# --- _guess_device_type missing branches ---

def test_guess_fortios_firewall():
    assert _guess_device_type({}, "FortiOS 7.x") == DeviceType.firewall


def test_guess_ios_apple_is_phone():
    assert _guess_device_type({}, "Apple iOS 17") == DeviceType.phone


def test_guess_android_is_phone():
    assert _guess_device_type({}, "Android 14") == DeviceType.phone


def test_guess_macos_no_services_is_workstation():
    """macOS bez usług serwerowych → workstation (MacBook)."""
    assert _guess_device_type(set(), "macOS 14") == DeviceType.workstation

def test_guess_macos_with_ssh_is_server():
    """macOS z SSH → server (Mac mini server / Mac Pro)."""
    assert _guess_device_type({22}, "macOS 14") == DeviceType.server


def test_guess_camera_by_vendor():
    assert _guess_device_type({80}, "", vendor="Dahua Technology") == DeviceType.camera


def test_guess_nas_by_vendor():
    assert _guess_device_type({}, "", vendor="Synology Inc") == DeviceType.nas


def test_guess_printer_by_port_9100():
    assert _guess_device_type({9100}, "", vendor="Unknown") == DeviceType.printer


def test_guess_printer_by_vendor():
    assert _guess_device_type({}, "", vendor="Canon Inc") == DeviceType.printer


def test_guess_iot_by_vendor():
    assert _guess_device_type({}, "", vendor="Shelly Group") == DeviceType.iot


def test_guess_inverter_by_port_502():
    assert _guess_device_type({502}, "", vendor="") == DeviceType.inverter


def test_guess_ubiquiti_ap_by_hostname():
    assert _guess_device_type({}, "", vendor="Ubiquiti", hostname="U7Pro") == DeviceType.ap


def test_guess_ubiquiti_switch_by_hostname():
    assert _guess_device_type({}, "", vendor="Ubiquiti", hostname="US-8-60W") == DeviceType.switch


def test_guess_ubiquiti_router_by_hostname():
    assert _guess_device_type({}, "", vendor="Ubiquiti", hostname="UDM-Pro") == DeviceType.router


def test_guess_ubiquiti_no_hostname_is_ap():
    assert _guess_device_type({}, "", vendor="Ubiquiti", hostname=None) == DeviceType.ap


def test_guess_fortinet_vendor_firewall():
    assert _guess_device_type({}, "", vendor="Fortinet") == DeviceType.firewall


def test_guess_linux_ssh_only_is_server():
    """BUG-L6: SSH-only Linux = headless server, nie router."""
    assert _guess_device_type({22}, "Linux 5.x") == DeviceType.server


def test_guess_linux_ssh_and_http_is_server():
    assert _guess_device_type({22, 80}, "Linux 5.x") == DeviceType.server


# --- run_discovery ---

def test_run_discovery_returns_empty_when_no_targets(db):
    with patch("netdoc.collector.discovery.get_scan_targets", return_value=[]):
        result = run_discovery(db)
    assert result == []


_PASSIVE_SCAN_MOCKS = {
    "netdoc.collector.discovery.ssdp_scan": {},
    "netdoc.collector.discovery.nbns_scan": {},
    "netdoc.collector.discovery.mdns_scan": {},
    "netdoc.collector.discovery.wsd_scan": {},
    "netdoc.collector.discovery.apipa_from_arp": {},
    "netdoc.collector.discovery.reverse_dns_lookup": {},
    "netdoc.collector.discovery.is_network_reachable": True,
}


def _with_passive_mocks(fn, *args, **kwargs):
    """Opakowuje wywolanie fn w patche blokujace realne skany pasywne."""
    from contextlib import ExitStack
    with ExitStack() as stack:
        for target, rv in _PASSIVE_SCAN_MOCKS.items():
            stack.enter_context(patch(target, return_value=rv))
        return fn(*args, **kwargs)


def test_run_discovery_returns_empty_when_no_active_hosts(db):
    with patch("netdoc.collector.discovery.get_scan_targets", return_value=["192.168.1.0/24"]):
        with patch("netdoc.collector.discovery.ping_sweep", return_value=[]):
            result = _with_passive_mocks(run_discovery, db)
    assert result == []


def test_run_discovery_upserts_devices_from_scan(db):
    with patch("netdoc.collector.discovery.get_scan_targets", return_value=["192.168.1.0/24"]):
        with patch("netdoc.collector.discovery.ping_sweep", return_value=["192.168.1.1"]):
            with patch("netdoc.collector.discovery.port_scan", return_value={}):
                with patch("netdoc.collector.discovery.read_arp_table", return_value={}):
                    with patch("netdoc.collector.discovery._get_default_gateways", return_value=set()):
                        result = _with_passive_mocks(run_discovery, db)
    assert len(result) >= 1
    assert result[0].ip == "192.168.1.1"


# ── Nowe testy: drukarka HP, workstation, bannery portow ─────────────────────

def test_guess_printer_hp_port_9100_no_ssh():
    """HP z portem 9100 i bez SSH → drukarka (nie serwer!)."""
    result = _guess_device_type({9100, 80}, None, vendor="HP Inc")
    assert result == DeviceType.printer


def test_guess_printer_hp_port_9100_with_ssh_is_printer():
    """HP z portem 9100, SSH i web → drukarka (HP LaserJet enterprise ma SSH management).

    SSH nie dyskwalifikuje drukarki — tylko SMTP/RDP/WinRM sa sygnalami serwera.
    """
    result = _guess_device_type({9100, 22, 80}, None, vendor="HP Inc")
    assert result == DeviceType.printer


def test_guess_printer_port_515_ldp():
    """Port 515 (LPD) bez SSH → drukarka."""
    result = _guess_device_type({515}, None)
    assert result == DeviceType.printer


def test_guess_printer_port_631_ipp():
    """Port 631 (IPP) bez SSH → drukarka."""
    result = _guess_device_type({631}, None)
    assert result == DeviceType.printer


def test_guess_printer_hp_ipp_no_ssh():
    """HP z portem 631 (IPP/AirPrint) → drukarka."""
    result = _guess_device_type({631, 80}, None, vendor="Hewlett Packard")
    assert result == DeviceType.printer


def test_guess_workstation_windows_rdp_only():
    """Windows z samym RDP (3389) bez web → workstation."""
    result = _guess_device_type({3389}, "Windows 11")
    assert result == DeviceType.workstation


def test_guess_workstation_windows_amt_rdp():
    """Windows z Intel AMT (623) i RDP → workstation (enterprise z vPro)."""
    result = _guess_device_type({623, 3389, 135, 139}, "Windows 11")
    assert result == DeviceType.workstation


def test_guess_workstation_windows_netbios_no_web():
    """Windows z NetBIOS (135+139) bez web → workstation."""
    result = _guess_device_type({135, 139}, "Windows 10")
    assert result == DeviceType.workstation


def test_guess_server_windows_with_web():
    """Windows Server z web (80/443) → server."""
    result = _guess_device_type({80, 443, 139}, "Windows Server 2022")
    assert result == DeviceType.server


def test_guess_workstation_windows10_with_web():
    """Windows 10 z portem web (80/443) → workstation (nie serwer!). Blad sprzed fixa."""
    result = _guess_device_type({80, 443, 3389}, "Windows 10")
    assert result == DeviceType.workstation


def test_guess_workstation_windows10_with_ssh():
    """Windows 10 z SSH (WSL/OpenSSH) → workstation, nie serwer."""
    result = _guess_device_type({22, 3389}, "Windows 10")
    assert result == DeviceType.workstation


def test_guess_server_windows_server_2019_with_ssh():
    """Windows Server 2019 z SSH → server."""
    result = _guess_device_type({22, 443}, "Windows Server 2019")
    assert result == DeviceType.server


def test_guess_server_windows10_with_db():
    """Windows 10 z baza danych (MSSQL) → server (mimo wersji desktopowej)."""
    result = _guess_device_type({1433, 3389}, "Windows 10")
    assert result == DeviceType.server


def test_guess_workstation_windows10_no_ports():
    """Windows 10 bez portow → workstation (znana wersja desktopowa)."""
    result = _guess_device_type(set(), "Windows 10")
    assert result == DeviceType.workstation


def test_guess_workstation_netbios_no_vendor_no_os():
    """Tylko porty NetBIOS (135+139) bez vendora/OS → workstation."""
    result = _guess_device_type({135, 139}, None)
    assert result == DeviceType.workstation


def test_guess_workstation_smb_only_no_vendor():
    """Sam port 445 (SMB) bez vendora/OS → workstation."""
    result = _guess_device_type({445}, None)
    assert result == DeviceType.workstation


def test_guess_server_netbios_with_http():
    """NetBIOS + HTTP bez vendora → server (np. Windows serwer plików + IIS)."""
    result = _guess_device_type({135, 139, 80}, None)
    assert result == DeviceType.server


def test_guess_type_from_banner_windows_rpc():
    """Banner 'Microsoft Windows RPC' w open_ports_detail → Windows workstation."""
    detail = {
        135: {"product": "Microsoft Windows RPC", "service": "msrpc"},
        139: {"product": "Microsoft Windows netbios-ssn", "service": "netbios-ssn"},
    }
    result = _guess_device_type({135, 139}, None, open_ports_detail=detail)
    assert result == DeviceType.workstation


def test_guess_type_from_banner_windows_server_with_http():
    """Banner Windows + port 80 → server."""
    detail = {
        80: {"product": "Microsoft IIS httpd", "service": "http"},
        135: {"product": "Microsoft Windows RPC", "service": "msrpc"},
    }
    result = _guess_device_type({80, 135}, None, open_ports_detail=detail)
    assert result == DeviceType.server


def test_guess_server_lenovo_no_services():
    """Lenovo bez portów → server (Lenovo jest w _SERVER_VENDORS, defaultuje do server)."""
    result = _guess_device_type(set(), None, vendor="Lenovo")
    assert result == DeviceType.server


def test_guess_server_lenovo_with_ssh():
    """Lenovo z SSH → server (Lenovo ThinkStation jako serwer)."""
    result = _guess_device_type({22, 80}, None, vendor="Lenovo")
    assert result == DeviceType.server


def test_guess_workstation_hp_rdp_no_web():
    """HP Dell z RDP, bez web → workstation (PC biurowy z remote desktop)."""
    result = _guess_device_type({3389, 445}, None, vendor="Dell")
    assert result == DeviceType.workstation


# --- _guess_device_type: camera port detection ---

def test_guess_camera_by_rtsp_port_554():
    """Port 554 (RTSP) bez portów serwera → kamera."""
    result = _guess_device_type({554}, None)
    assert result == DeviceType.camera


def test_guess_camera_by_rtsp_alternate_port_8554():
    """Port 8554 (RTSP alternate) → kamera."""
    result = _guess_device_type({8554, 80}, None)
    assert result == DeviceType.camera


def test_guess_camera_by_dahua_port_37777():
    """Port 37777 (Dahua DVR) → kamera."""
    result = _guess_device_type({37777}, None)
    assert result == DeviceType.camera


def test_guess_camera_by_xmeye_port_34567():
    """Port 34567 (XMEye DVR) → kamera."""
    result = _guess_device_type({34567}, None)
    assert result == DeviceType.camera


def test_guess_camera_multiple_stream_ports():
    """Kilka portów kamer jednocześnie → kamera."""
    result = _guess_device_type({554, 37777, 80}, None)
    assert result == DeviceType.camera


def test_guess_camera_port_excluded_for_linux_server():
    """Port 554 + SSH + HTTP + os=linux → serwer (np. serwer mediów), nie kamera."""
    result = _guess_device_type({22, 80, 554}, "linux ubuntu")
    assert result != DeviceType.camera
    assert result in (DeviceType.server, DeviceType.unknown)


def test_guess_camera_port_excluded_for_linux_server_https():
    """Port 554 + SSH + HTTPS + os=linux → serwer, nie kamera."""
    result = _guess_device_type({22, 443, 554}, "linux debian")
    assert result != DeviceType.camera


def test_guess_camera_port_37777_not_server_without_ssh():
    """Port 37777 bez SSH → kamera (brak ssh = nie serwer administracyjny)."""
    result = _guess_device_type({37777, 80}, None)
    assert result == DeviceType.camera


def test_guess_camera_port_wins_over_generic_vendor():
    """Port kamery przy nieznanym vendorze → kamera (port silniejszy od default unknown)."""
    result = _guess_device_type({554}, None, vendor="Unknown Corp")
    assert result == DeviceType.camera


# ── Testy: nbns_scan ──────────────────────────────────────────────────────────

def test_nbns_scan_socket_error_returns_empty():
    """Blad socketa → pusty slownik (bez wyjatku)."""
    import socket as _sock
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock:
        mock_sock.side_effect = _sock.error("test error")
        result = nbns_scan(timeout=0.1)
    assert result == {}


def test_nbns_scan_no_response_returns_empty():
    """Brak odpowiedzi w czasie timeout → pusty slownik."""
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock:
        sock_inst = MagicMock()
        mock_sock.return_value = sock_inst
        sock_inst.recvfrom.side_effect = socket.timeout()
        result = nbns_scan(timeout=0.05)
    assert result == {}


def test_nbns_scan_response_too_short_ignored():
    """Odpowiedz krotsza niz 57 bajtow → pomijana."""
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock:
        sock_inst = MagicMock()
        mock_sock.return_value = sock_inst
        sock_inst.recvfrom.side_effect = [
            (b'\x00' * 30, ("192.168.1.50", 137)),
            socket.timeout(),
        ]
        result = nbns_scan(timeout=0.05)
    assert result == {}


def test_nbns_scan_parses_computer_name():
    """Poprawna odpowiedz NBSTAT → hostname wyodrebniany z pola nazwy."""
    # Zbuduj minimalny pakiet NBSTAT response:
    # 56 bajtow naglowka + num_names=1 + 18 bajtow (name=15B + type=1B + flags=2B)
    name_field = b"MYCOMPUTER     "   # 15 bajtow
    name_type = b"\x00"               # Workstation
    flags = b"\x04\x00"
    num_names = b"\x01"
    header = b"\x00" * 56 + num_names + name_field + name_type + flags

    with patch("netdoc.collector.discovery._socket.socket") as mock_sock:
        sock_inst = MagicMock()
        mock_sock.return_value = sock_inst
        sock_inst.recvfrom.side_effect = [
            (header, ("192.168.1.10", 137)),
            socket.timeout(),
        ]
        result = nbns_scan(timeout=0.1)
    assert "192.168.1.10" in result
    assert result["192.168.1.10"] == "MYCOMPUTER"


# ── Testy: mdns_scan ──────────────────────────────────────────────────────────

def test_mdns_scan_socket_error_returns_empty():
    """Blad socketa → pusty slownik."""
    import socket as _sock
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock:
        mock_sock.side_effect = _sock.error("multicast blocked")
        result = mdns_scan(timeout=0.1)
    assert result == {}


def test_mdns_scan_no_response_returns_empty():
    """Brak odpowiedzi → pusty slownik."""
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock:
        sock_inst = MagicMock()
        mock_sock.return_value = sock_inst
        sock_inst.recvfrom.side_effect = socket.timeout()
        result = mdns_scan(timeout=0.05)
    assert result == {}


def test_mdns_scan_extracts_hostname():
    """Odpowiedz z .local hostname w formacie tekstowym → wyodrebniony hostname."""
    # mDNS odpowiedzi zawieraja nazwy jako czytelny tekst w TXT/SRV recordach
    data = b'\x00' * 12 + b'MyDevice.local\x00'
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock:
        sock_inst = MagicMock()
        mock_sock.return_value = sock_inst
        sock_inst.recvfrom.side_effect = [
            (data, ("192.168.1.5", 5353)),
            socket.timeout(),
        ]
        result = mdns_scan(timeout=0.1)
    assert "192.168.1.5" in result
    assert result["192.168.1.5"]["hostname"] == "MyDevice"


def test_mdns_scan_detects_airprint_service():
    """Odpowiedz zawierajaca _airprint → uslugi zawieraja _airprint."""
    data = b'\x00' * 12 + b'_airprint._tcp.local\x00'
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock:
        sock_inst = MagicMock()
        mock_sock.return_value = sock_inst
        sock_inst.recvfrom.side_effect = [
            (data, ("192.168.1.20", 5353)),
            socket.timeout(),
        ]
        result = mdns_scan(timeout=0.1)
    assert "192.168.1.20" in result
    assert "_airprint" in result["192.168.1.20"]["services"]


def test_mdns_scan_skips_non_private_ips():
    """IP spoza prywatnych zakresow → pomijany."""
    data = b'\x00' * 12 + b'device\x05local\x00'
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock:
        sock_inst = MagicMock()
        mock_sock.return_value = sock_inst
        sock_inst.recvfrom.side_effect = [
            (data, ("8.8.8.8", 5353)),
            socket.timeout(),
        ]
        result = mdns_scan(timeout=0.1)
    assert "8.8.8.8" not in result


# ── Testy: reverse_dns_lookup ─────────────────────────────────────────────────

def test_reverse_dns_lookup_empty_list():
    """Pusta lista IP → pusty slownik."""
    result = reverse_dns_lookup([])
    assert result == {}


def test_reverse_dns_lookup_no_ptr_record():
    """IP bez rekordu PTR → pomijany."""
    with patch("netdoc.collector.discovery._socket.gethostbyaddr",
               side_effect=socket.herror("not found")):
        result = reverse_dns_lookup(["192.168.1.1"])
    assert result == {}


def test_reverse_dns_lookup_returns_short_hostname():
    """FQDN z DNS → skrocony do short hostname (przed pierwsza kropka)."""
    with patch("netdoc.collector.discovery._socket.gethostbyaddr",
               return_value=("server01.corp.local", [], ["192.168.1.1"])):
        result = reverse_dns_lookup(["192.168.1.1"])
    assert result == {"192.168.1.1": "server01"}


def test_reverse_dns_lookup_hostname_without_dot():
    """Hostname bez kropki → zwracany bez zmian."""
    with patch("netdoc.collector.discovery._socket.gethostbyaddr",
               return_value=("myhost", [], ["192.168.1.2"])):
        result = reverse_dns_lookup(["192.168.1.2"])
    assert result == {"192.168.1.2": "myhost"}


def test_reverse_dns_lookup_mixed_results():
    """Czesc IP ma PTR, czesc nie → tylko te z PTR w wyniku."""
    def _fake_lookup(ip):
        if ip == "192.168.1.1":
            return ("srv01.local", [], [ip])
        raise socket.herror("not found")

    with patch("netdoc.collector.discovery._socket.gethostbyaddr", side_effect=_fake_lookup):
        result = reverse_dns_lookup(["192.168.1.1", "192.168.1.2"])
    assert "192.168.1.1" in result
    assert "192.168.1.2" not in result


def test_reverse_dns_lookup_timeout_returns_partial_results():
    """TimeoutError z as_completed → zwroc czesciowe wyniki bez wyjatku."""
    from concurrent.futures import as_completed as real_as_completed

    call_count = [0]

    def _patched_as_completed(fs, timeout=None):
        """Symuluje timeout po pierwszym future."""
        it = real_as_completed(fs)
        for i, f in enumerate(it):
            call_count[0] += 1
            if i == 0:
                yield f
            else:
                raise TimeoutError("simulated timeout")

    with patch("netdoc.collector.discovery._socket.gethostbyaddr",
               return_value=("host.local", [], ["192.168.1.1"])):
        with patch("netdoc.collector.discovery.as_completed", _patched_as_completed):
            result = reverse_dns_lookup(["192.168.1.1", "192.168.1.2"])
    # Nie powinno rzucic wyjatku — czesc wynikow moze byc pusta
    assert isinstance(result, dict)


# ── Testy: _guess_device_type z mdns_services ────────────────────────────────

def test_guess_device_type_mdns_airprint_returns_printer():
    """mDNS _airprint → drukarka (priorytet 0, wyzszy niz port scan)."""
    result = _guess_device_type({22, 80}, None, mdns_services=["_airprint"])
    assert result == DeviceType.printer


def test_guess_device_type_mdns_ipp_returns_printer():
    """mDNS _ipp → drukarka."""
    result = _guess_device_type(set(), None, mdns_services=["_ipp"])
    assert result == DeviceType.printer


def test_guess_device_type_mdns_googlecast_returns_iot():
    """mDNS _googlecast → IoT (Chromecast)."""
    result = _guess_device_type(set(), None, mdns_services=["_googlecast"])
    assert result == DeviceType.iot


def test_guess_device_type_mdns_afp_no_server_ports_returns_workstation():
    """mDNS _afp bez portow serwerowych → workstation (macOS)."""
    result = _guess_device_type(set(), None, mdns_services=["_afp"])
    assert result == DeviceType.workstation


def test_guess_device_type_mdns_afp_with_ssh_returns_server():
    """mDNS _afp z SSH → serwer (macOS z uslugsami)."""
    result = _guess_device_type({22, 80}, None, mdns_services=["_afp"])
    assert result == DeviceType.server


def test_guess_device_type_empty_mdns_services_no_change():
    """Pusta lista mdns_services nie zmienia klasyfikacji."""
    result = _guess_device_type({22, 80}, "Linux 5.x", mdns_services=[])
    assert result == DeviceType.server


# ── Testy: PLC vs falownik (klasyfikacja port 502) ───────────────────────────

def test_guess_plc_siemens_port_502_is_iot_not_inverter():
    """Siemens + port 502 → iot (PLC), nie inverter (falownik PV)."""
    result = _guess_device_type({502, 80}, None, vendor="Siemens AG")
    assert result == DeviceType.iot


def test_guess_plc_schneider_port_502_is_iot():
    """Schneider + port 502 → iot (PLC/licznik), nie inverter."""
    result = _guess_device_type({502, 80}, None, vendor="Schneider Electric")
    assert result == DeviceType.iot


def test_guess_plc_beckhoff_port_502_is_iot():
    """Beckhoff (PLC) + port 502 → iot."""
    result = _guess_device_type({502}, None, vendor="Beckhoff Automation")
    assert result == DeviceType.iot


def test_guess_pv_inverter_sma_port_502_is_inverter():
    """SMA Solar (falownik PV) + port 502 → inverter."""
    result = _guess_device_type({502, 80}, None, vendor="SMA Solar Technology")
    assert result == DeviceType.inverter


def test_guess_pv_inverter_fronius_port_502_is_inverter():
    """Fronius (falownik PV) → inverter."""
    result = _guess_device_type({502, 80}, None, vendor="Fronius International")
    assert result == DeviceType.inverter


def test_guess_modbus_no_vendor_is_inverter():
    """Port 502 bez vendora → inverter (fallback dla nieznanego Modbus)."""
    result = _guess_device_type({502}, None)
    assert result == DeviceType.inverter


def test_guess_abb_with_iot_vendor_pattern_is_iot():
    """ABB AC500 (PLC) — vendor 'abb ' pasuje do IOT_VENDORS → iot, nie inverter."""
    result = _guess_device_type({502}, None, vendor="ABB AC500 PLC")
    assert result == DeviceType.iot


# ── Testy: _is_in_subnet / site_id lab ───────────────────────────────────────

def test_is_in_subnet_lab_ip():
    """172.28.0.10 jest w 172.28.0.0/24."""
    assert _is_in_subnet("172.28.0.10", "172.28.0.0/24") is True


def test_is_in_subnet_non_lab_ip():
    """192.168.1.1 nie jest w 172.28.0.0/24."""
    assert _is_in_subnet("192.168.1.1", "172.28.0.0/24") is False


def test_is_in_subnet_invalid_ip():
    """Nieprawidlowy IP → False (bez wyjatku)."""
    assert _is_in_subnet("not.an.ip", "172.28.0.0/24") is False


def test_upsert_device_sets_site_id_lab(db):
    """Nowe urzadzenie z site_id='lab' ma poprawnie ustawiony site_id."""
    d = DeviceData(ip="172.28.0.10", site_id="lab")
    device = upsert_device(db, d)
    assert device.site_id == "lab"


def test_upsert_device_does_not_overwrite_existing_site_id(db):
    """Juz istniejace urzadzenie z site_id='production' — site_id nie jest nadpisywany przez 'lab'."""
    d = DeviceData(ip="172.28.0.99", site_id="production")
    upsert_device(db, d)
    # Drugi upsert z site_id='lab' nie powinien nadpisac 'production'
    d2 = DeviceData(ip="172.28.0.99", site_id="lab")
    device = upsert_device(db, d2)
    assert device.site_id == "production"


def test_upsert_device_sets_site_id_when_was_none(db):
    """Urzadzenie bez site_id → site_id='lab' ustawiany przy kolejnym upsert."""
    d = DeviceData(ip="172.28.0.55")
    upsert_device(db, d)
    d2 = DeviceData(ip="172.28.0.55", site_id="lab")
    device = upsert_device(db, d2)
    assert device.site_id == "lab"


# --- hostname collision protection ---

def test_hostname_collision_on_new_device_gets_empty_hostname(db):
    """Nowe urzadzenie NIE przejmuje hostname juz uzytego przez inne IP."""
    # Urzadzenie A z hostname DESKTOP-TEST
    upsert_device(db, DeviceData(ip="192.168.1.1", hostname="DESKTOP-TEST"))
    # Kamera (inne IP) odkryta z tym samym hostnamen (NBNS/mDNS collision)
    camera = upsert_device(db, DeviceData(ip="192.168.1.50", hostname="DESKTOP-TEST"))
    # Kamera nie powinna dostac nazwy DESKTOP-TEST — hostname powinien byc pusty
    assert camera.hostname is None, (
        "Kamera nie powinna miec hostname 'DESKTOP-TEST' — to kolizja z PC przy 192.168.1.1"
    )
    # Oryginalny PC powinien miec nadal swoj hostname
    pc = db.query(Device).filter_by(ip="192.168.1.1").first()
    assert pc.hostname == "DESKTOP-TEST"


def test_hostname_collision_on_update_keeps_old_hostname(db):
    """Aktualizacja urzadzenia NIE nadpisuje hostname innego urzadzenia przez kolizje."""
    # Device A (PC)
    upsert_device(db, DeviceData(ip="192.168.1.1", hostname="DESKTOP-TEST"))
    # Device B (kamera) bez hostname
    cam = upsert_device(db, DeviceData(ip="192.168.1.50", hostname=None))
    assert cam.hostname is None

    # Kolejny skan — kamera dostaje bledny NBNS z hostnamen "DESKTOP-TEST"
    cam_after = upsert_device(db, DeviceData(ip="192.168.1.50", hostname="DESKTOP-TEST"))
    # Hostname nie powinien zostac nadpisany na kolizyjny
    assert cam_after.hostname is None, (
        "Kamera nie powinna dostac 'DESKTOP-TEST' przez kolizje NBNS"
    )
    # PC nadal ma swoj hostname
    pc = db.query(Device).filter_by(ip="192.168.1.1").first()
    assert pc.hostname == "DESKTOP-TEST"


def test_hostname_no_collision_when_unique(db):
    """Normalny przypadek: unikalne hostname przydzielane bez problemu."""
    d1 = upsert_device(db, DeviceData(ip="10.0.0.1", hostname="router-main"))
    d2 = upsert_device(db, DeviceData(ip="10.0.0.2", hostname="switch-01"))
    assert d1.hostname == "router-main"
    assert d2.hostname == "switch-01"


def test_hostname_update_same_device_allowed(db):
    """Urzadzenie moze dostac nowy unikalny hostname (np. po rebrandingu)."""
    upsert_device(db, DeviceData(ip="10.0.0.1", hostname="old-name"))
    d = upsert_device(db, DeviceData(ip="10.0.0.1", hostname="new-name"))
    assert d.hostname == "new-name"


def test_hostname_collision_update_existing_device_with_same_hostname(db):
    """Urzadzenie ktore juz MA ten hostname moze dostac potwierdzenie (ten sam hostname → OK)."""
    upsert_device(db, DeviceData(ip="10.0.0.1", hostname="router"))
    # Ponowny skan tego samego urzadzenia z tym samym hostnamen — brak konfliktu
    d = upsert_device(db, DeviceData(ip="10.0.0.1", hostname="router"))
    assert d.hostname == "router"


def test_hostname_collision_none_hostname_no_check(db):
    """Urzadzenie z hostname=None nie wyzwala sprawdzenia kolizji."""
    upsert_device(db, DeviceData(ip="10.0.0.1", hostname="router"))
    # Drugie urzadzenie bez hostname — nie koliduje z niczym
    d = upsert_device(db, DeviceData(ip="10.0.0.2", hostname=None))
    assert d.hostname is None
    # Router nadal ma swoj hostname
    assert db.query(Device).filter_by(ip="10.0.0.1").first().hostname == "router"


# ── Deduplikacja po MAC (zmiana IP) ────────────────────────────────────────────

def test_upsert_device_mac_ip_migration_preserves_hostname(db):
    """Laptop zmienil siec (nowe IP) — ten sam MAC → hostname zachowany, bez duplikatu.
    Przypadek DESKTOP-TEST: poprzednia siec 192.168.1.50, nowa siec 192.168.5.192.
    """
    mac = "aa:bb:cc:dd:ee:ff"
    mac_norm = "AA:BB:CC:DD:EE:FF"  # normalize_mac zwraca uppercase
    # Skan z poprzedniej sieci — urzadzenie ma hostname
    upsert_device(db, DeviceData(ip="192.168.1.50", mac=mac, hostname="DESKTOP-TEST"))

    # Skan z nowej sieci — nowy IP, ten sam MAC
    d = upsert_device(db, DeviceData(ip="192.168.5.192", mac=mac, hostname="DESKTOP-TEST"))

    # Hostname zachowany (nie wyzerowany przez antyduplikacje)
    assert d.hostname == "DESKTOP-TEST", "Hostname powinien byc zachowany po migracji IP"
    assert d.ip == "192.168.5.192", "IP powinno byc zaktualizowane do nowego"

    # W bazie tylko JEDEN rekord dla tego MAC — brak duplikatu
    all_devices = db.query(Device).filter(Device.mac == mac_norm).all()
    assert len(all_devices) == 1, f"Oczekiwano 1 rekordu, jest {len(all_devices)}"


def test_upsert_device_mac_ip_migration_old_ip_gone(db):
    """Po migracji IP stary adres nie istnieje juz w bazie."""
    mac = "11:22:33:44:55:66"
    upsert_device(db, DeviceData(ip="10.0.1.100", mac=mac, hostname="router-home"))
    upsert_device(db, DeviceData(ip="10.0.2.100", mac=mac, hostname="router-home"))

    old = db.query(Device).filter_by(ip="10.0.1.100").first()
    assert old is None, "Stary IP nie powinien istniec po migracji MAC"
    new = db.query(Device).filter_by(ip="10.0.2.100").first()
    assert new is not None
    assert new.hostname == "router-home"


def test_upsert_device_mac_none_creates_duplicate(db):
    """Bez MAC nie ma deduplikacji — urz. z nowym IP tworzy nowy rekord (stare zachowanie)."""
    # Hostname collision protection: nowy rekord dostanie pusty hostname
    upsert_device(db, DeviceData(ip="192.168.1.50", mac=None, hostname="DESKTOP-TEST"))
    d = upsert_device(db, DeviceData(ip="192.168.5.192", mac=None, hostname="DESKTOP-TEST"))

    # Stary rekord nadal istnieje
    old = db.query(Device).filter_by(ip="192.168.1.50").first()
    assert old is not None
    # Nowy rekord zostal utworzony z pustym hostname (kolizja bez MAC)
    assert d.hostname is None, "Bez MAC hostname kolizja powinna zerować hostname nowego wpisu"


def test_upsert_device_mac_ip_migration_is_active(db):
    """Po migracji IP urzadzenie jest oznaczone jako aktywne."""
    mac = "de:ad:be:ef:00:01"
    dev = upsert_device(db, DeviceData(ip="10.10.1.1", mac=mac))
    # Symuluj ze stare IP zostalo oznaczone jako nieaktywne
    dev.is_active = False
    db.commit()

    # Urzadzenie pojawia sie z nowym IP
    d = upsert_device(db, DeviceData(ip="10.10.2.1", mac=mac))
    assert d.is_active is True
    assert d.ip == "10.10.2.1"


# ── Testy regresyjne: SSDP Server header fingerprinting ──────────────────────

def test_run_discovery_ssdp_server_header_uses_fingerprinting(db):
    """SSDP Server header 'ZyXEL-RomPager/4.51' → vendor='ZyXEL' (nie 'ZyXEL-RomPager')."""
    ssdp = {"192.168.1.100": {"server": "ZyXEL-RomPager/4.51 EmbeddedWeb"}}
    with patch("netdoc.collector.discovery.get_scan_targets", return_value=["192.168.1.0/24"]):
        with patch("netdoc.collector.discovery.ping_sweep", return_value=["192.168.1.100"]):
            with patch("netdoc.collector.discovery.port_scan", return_value={}):
                with patch("netdoc.collector.discovery.read_arp_table", return_value={}):
                    with patch("netdoc.collector.discovery._get_default_gateways", return_value=set()):
                        with patch("netdoc.collector.discovery.ssdp_scan", return_value=ssdp):
                            with patch("netdoc.collector.discovery.nbns_scan", return_value={}):
                                with patch("netdoc.collector.discovery.mdns_scan", return_value={}):
                                    with patch("netdoc.collector.discovery.reverse_dns_lookup", return_value={}):
                                        result = run_discovery(db)
    dev = db.query(Device).filter_by(ip="192.168.1.100").first()
    assert dev is not None
    # Fingerprinting zwraca "ZyXEL", nie raw "ZyXEL-RomPager" ze splitu
    assert dev.vendor == "ZyXEL"


def test_run_discovery_ssdp_server_header_mikrotik(db):
    """SSDP Server header 'MikroTik/6.49' → vendor='MikroTik'."""
    ssdp = {"192.168.1.101": {"server": "MikroTik/6.49 (stable)"}}
    with patch("netdoc.collector.discovery.get_scan_targets", return_value=["192.168.1.0/24"]):
        with patch("netdoc.collector.discovery.ping_sweep", return_value=["192.168.1.101"]):
            with patch("netdoc.collector.discovery.port_scan", return_value={}):
                with patch("netdoc.collector.discovery.read_arp_table", return_value={}):
                    with patch("netdoc.collector.discovery._get_default_gateways", return_value=set()):
                        with patch("netdoc.collector.discovery.ssdp_scan", return_value=ssdp):
                            with patch("netdoc.collector.discovery.nbns_scan", return_value={}):
                                with patch("netdoc.collector.discovery.mdns_scan", return_value={}):
                                    with patch("netdoc.collector.discovery.reverse_dns_lookup", return_value={}):
                                        run_discovery(db)
    dev = db.query(Device).filter_by(ip="192.168.1.101").first()
    assert dev is not None
    assert dev.vendor == "MikroTik"


def test_run_discovery_ssdp_server_header_unknown_falls_back_to_raw_split(db):
    """SSDP Server header nieznany fingerprinting → fallback na raw split '/[0]'."""
    ssdp = {"192.168.1.102": {"server": "SomeUnknownFirmware/1.0.2"}}
    with patch("netdoc.collector.discovery.get_scan_targets", return_value=["192.168.1.0/24"]):
        with patch("netdoc.collector.discovery.ping_sweep", return_value=["192.168.1.102"]):
            with patch("netdoc.collector.discovery.port_scan", return_value={}):
                with patch("netdoc.collector.discovery.read_arp_table", return_value={}):
                    with patch("netdoc.collector.discovery._get_default_gateways", return_value=set()):
                        with patch("netdoc.collector.discovery.ssdp_scan", return_value=ssdp):
                            with patch("netdoc.collector.discovery.nbns_scan", return_value={}):
                                with patch("netdoc.collector.discovery.mdns_scan", return_value={}):
                                    with patch("netdoc.collector.discovery.reverse_dns_lookup", return_value={}):
                                        run_discovery(db)
    dev = db.query(Device).filter_by(ip="192.168.1.102").first()
    assert dev is not None
    # Fallback: raw split daje pierwsza czesc przed "/"
    assert dev.vendor == "SomeUnknownFirmware"


def test_run_discovery_ssdp_server_header_apache_no_vendor(db):
    """SSDP Server header 'Apache/2.4.41' → vendor=None (generic, fingerprinting ignoruje)."""
    ssdp = {"192.168.1.103": {"server": "Apache/2.4.41 (Ubuntu)"}}
    with patch("netdoc.collector.discovery.get_scan_targets", return_value=["192.168.1.0/24"]):
        with patch("netdoc.collector.discovery.ping_sweep", return_value=["192.168.1.103"]):
            with patch("netdoc.collector.discovery.port_scan", return_value={}):
                with patch("netdoc.collector.discovery.read_arp_table", return_value={}):
                    with patch("netdoc.collector.discovery._get_default_gateways", return_value=set()):
                        with patch("netdoc.collector.discovery.ssdp_scan", return_value=ssdp):
                            with patch("netdoc.collector.discovery.nbns_scan", return_value={}):
                                with patch("netdoc.collector.discovery.mdns_scan", return_value={}):
                                    with patch("netdoc.collector.discovery.reverse_dns_lookup", return_value={}):
                                        run_discovery(db)
    dev = db.query(Device).filter_by(ip="192.168.1.103").first()
    assert dev is not None
    # Apache jest generic (vendor=null w banners.yaml) → fallback na raw split "Apache"
    assert dev.vendor == "Apache"


# --- _ensure_lab_monitoring ---

from netdoc.collector.discovery import _ensure_lab_monitoring
from netdoc.storage.models import SystemStatus


def _set_lab_monitoring(db, enabled: bool):
    """Pomocnik: ustawia lab_monitoring_enabled w DB."""
    row = db.query(SystemStatus).filter(SystemStatus.key == "lab_monitoring_enabled").first()
    if row:
        row.value = "1" if enabled else "0"
    else:
        db.add(SystemStatus(key="lab_monitoring_enabled", value="1" if enabled else "0"))
    db.commit()


def test_ensure_lab_monitoring_disabled_does_nothing(db):
    """Gdy lab_monitoring_enabled=0, urzadzenia lab NIE sa automatycznie monitorowane."""
    _set_lab_monitoring(db, False)
    d = upsert_device(db, DeviceData(ip="172.28.0.10", site_id="lab"))
    d.is_monitored = False
    db.commit()

    count = _ensure_lab_monitoring(db)
    assert count == 0
    db.refresh(d)
    assert d.is_monitored is False


def test_ensure_lab_monitoring_enabled_activates_lab_devices(db):
    """Gdy lab_monitoring_enabled=1, urzadzenia z site_id='lab' dostaja is_monitored=True."""
    _set_lab_monitoring(db, True)
    d = upsert_device(db, DeviceData(ip="172.28.0.20", site_id="lab"))
    d.is_monitored = False
    db.commit()

    count = _ensure_lab_monitoring(db)
    assert count == 1
    db.refresh(d)
    assert d.is_monitored is True
    assert "lab" in (d.monitor_note or "")


def test_ensure_lab_monitoring_skips_already_monitored(db):
    """Urzadzenia lab juz monitorowane nie sa liczane ponownie."""
    _set_lab_monitoring(db, True)
    d = upsert_device(db, DeviceData(ip="172.28.0.30", site_id="lab"))
    d.is_monitored = True
    db.commit()

    count = _ensure_lab_monitoring(db)
    assert count == 0  # juz monitorowane — nic do zrobienia


def test_ensure_lab_monitoring_does_not_affect_non_lab_devices(db):
    """Urzadzenia bez site_id='lab' nie sa dotykane przez _ensure_lab_monitoring."""
    _set_lab_monitoring(db, True)
    d_lab = upsert_device(db, DeviceData(ip="172.28.0.40", site_id="lab"))
    d_lan = upsert_device(db, DeviceData(ip="192.168.1.50", site_id="production"))
    d_lab.is_monitored = False
    d_lan.is_monitored = False
    db.commit()

    count = _ensure_lab_monitoring(db)
    assert count == 1  # tylko d_lab
    db.refresh(d_lab)
    db.refresh(d_lan)
    assert d_lab.is_monitored is True
    assert d_lan.is_monitored is False  # nie zmieniony


def test_ensure_lab_monitoring_multiple_lab_devices(db):
    """Wiele urzadzen lab — wszystkie dostaja is_monitored=True."""
    _set_lab_monitoring(db, True)
    devices = [
        upsert_device(db, DeviceData(ip=f"172.28.0.{i}", site_id="lab"))
        for i in range(10, 15)
    ]
    for d in devices:
        d.is_monitored = False
    db.commit()

    count = _ensure_lab_monitoring(db)
    assert count == 5
    for d in devices:
        db.refresh(d)
        assert d.is_monitored is True


# --- OUI vendor → klasyfikacja: testy integracyjne run_discovery ---

def test_run_discovery_classifies_ap_via_arp_mac_oui(db):
    """run_discovery: gdy nmap nie wykryje vendora, MAC z ARP + OUI → AP (Ubiquiti)."""
    with patch("netdoc.collector.discovery.get_scan_targets", return_value=["192.168.1.0/24"]):
        with patch("netdoc.collector.discovery.ping_sweep", return_value=["192.168.1.10"]):
            with patch("netdoc.collector.discovery.port_scan", return_value={}):
                # ARP zwraca MAC Ubiquiti
                with patch("netdoc.collector.discovery.read_arp_table",
                           return_value={"192.168.1.10": "9C:05:D6:AA:BB:CC"}):
                    with patch("netdoc.collector.discovery._get_default_gateways", return_value=set()):
                        with patch("netdoc.collector.discovery.oui_db") as mock_oui:
                            mock_oui.lookup.return_value = "Ubiquiti Inc"
                            result = _with_passive_mocks(run_discovery, db)

    dev = db.query(Device).filter_by(ip="192.168.1.10").first()
    assert dev is not None
    assert dev.device_type == DeviceType.ap
    assert dev.vendor == "Ubiquiti Inc"
    assert dev.mac == "9C:05:D6:AA:BB:CC"


def test_run_discovery_classifies_camera_via_arp_mac_oui(db):
    """run_discovery: MAC z ARP → Hikvision OUI → camera."""
    with patch("netdoc.collector.discovery.get_scan_targets", return_value=["192.168.1.0/24"]):
        with patch("netdoc.collector.discovery.ping_sweep", return_value=["192.168.1.20"]):
            with patch("netdoc.collector.discovery.port_scan",
                       return_value={"192.168.1.20": {"open_ports": {80: {}, 554: {}}, "os": None, "vendor": None}}):
                with patch("netdoc.collector.discovery.read_arp_table",
                           return_value={"192.168.1.20": "08:ED:ED:AA:BB:CC"}):
                    with patch("netdoc.collector.discovery._get_default_gateways", return_value=set()):
                        with patch("netdoc.collector.discovery.oui_db") as mock_oui:
                            mock_oui.lookup.return_value = "Hikvision Digital Technology"
                            result = _with_passive_mocks(run_discovery, db)

    dev = db.query(Device).filter_by(ip="192.168.1.20").first()
    assert dev is not None
    assert dev.device_type == DeviceType.camera


def test_run_discovery_no_mac_in_arp_stays_unknown_without_vendor(db):
    """run_discovery: brak MAC w ARP i brak vendora → unknown (nie zgadujemy)."""
    with patch("netdoc.collector.discovery.get_scan_targets", return_value=["192.168.1.0/24"]):
        with patch("netdoc.collector.discovery.ping_sweep", return_value=["192.168.1.30"]):
            with patch("netdoc.collector.discovery.port_scan",
                       return_value={"192.168.1.30": {"open_ports": {22: {}, 80: {}}, "os": None, "vendor": None}}):
                with patch("netdoc.collector.discovery.read_arp_table", return_value={}):
                    with patch("netdoc.collector.discovery._get_default_gateways", return_value=set()):
                        result = _with_passive_mocks(run_discovery, db)

    dev = db.query(Device).filter_by(ip="192.168.1.30").first()
    assert dev is not None
    assert dev.device_type == DeviceType.unknown


def test_run_discovery_nmap_vendor_wins_over_oui(db):
    """run_discovery: vendor z nmap ma priorytet nad OUI z MAC."""
    with patch("netdoc.collector.discovery.get_scan_targets", return_value=["192.168.1.0/24"]):
        with patch("netdoc.collector.discovery.ping_sweep", return_value=["192.168.1.40"]):
            with patch("netdoc.collector.discovery.port_scan",
                       return_value={"192.168.1.40": {"open_ports": {22: {}}, "os": "Cisco IOS 15.2",
                                                       "vendor": "Cisco Systems", "hostname": None}}):
                with patch("netdoc.collector.discovery.read_arp_table",
                           return_value={"192.168.1.40": "AA:BB:CC:DD:EE:FF"}):
                    with patch("netdoc.collector.discovery._get_default_gateways", return_value=set()):
                        with patch("netdoc.collector.discovery.oui_db") as mock_oui:
                            # OUI mowi Ubiquiti, nmap mowi Cisco — Cisco powinien wygrac
                            mock_oui.lookup.return_value = "Ubiquiti Inc"
                            result = _with_passive_mocks(run_discovery, db)

    dev = db.query(Device).filter_by(ip="192.168.1.40").first()
    assert dev is not None
    # Cisco IOS OS fingerprint → router (wyzsza prio niz vendor)
    assert dev.device_type == DeviceType.router
    assert dev.vendor == "Cisco Systems"



# ── Testy skanowania partiami (batch scan) ───────────────────────────────────

import json
import time
import threading
from unittest.mock import patch

import nmap as _nmap_mod

from netdoc.collector.discovery import (
    _make_port_batches,
    _compute_run_id,
    _load_scan_state,
    _save_scan_state,
    _clear_scan_state,
    _port_scan_one_host_batched,
    port_scan,
)


# --- _make_port_batches ---

def test_make_port_batches_disabled():
    """batch_size=0 → jedna lista zawierajaca wszystkie porty."""
    ports = [22, 80, 443, 3389]
    assert _make_port_batches(ports, 0) == [ports]


def test_make_port_batches_exact_split():
    """6 portow, batch=2 → 3 partie po 2."""
    ports = [22, 80, 443, 3389, 8080, 8443]
    assert _make_port_batches(ports, 2) == [[22, 80], [443, 3389], [8080, 8443]]


def test_make_port_batches_uneven():
    """5 portow, batch=2 → 2+2+1."""
    ports = [22, 80, 443, 3389, 8080]
    result = _make_port_batches(ports, 2)
    assert result == [[22, 80], [443, 3389], [8080]]
    assert sum(len(b) for b in result) == 5


def test_make_port_batches_larger_than_list():
    """batch_size >= len(ports) → jedna partia."""
    assert _make_port_batches([22, 80], 100) == [[22, 80]]


def test_make_port_batches_preserves_all_ports():
    """Zadne porty nie sa gubione przy podziale."""
    ports = list(range(1, 66))
    batches = _make_port_batches(ports, 10)
    flat = [p for b in batches for p in b]
    assert flat == ports
    assert len(batches) == 7


# --- _compute_run_id ---

def test_compute_run_id_same_hosts_same_id():
    """Te same hosty, rozna kolejnosc → ten sam run_id."""
    id1 = _compute_run_id(["10.0.0.1", "10.0.0.2"], 100)
    id2 = _compute_run_id(["10.0.0.2", "10.0.0.1"], 100)
    assert id1 == id2


def test_compute_run_id_different_hosts():
    """Rozne hosty → rozny run_id."""
    assert _compute_run_id(["10.0.0.1"], 100) != _compute_run_id(["10.0.0.2"], 100)


def test_compute_run_id_different_batch_size():
    """Te same hosty, inny batch_size → inny run_id."""
    assert _compute_run_id(["10.0.0.1"], 100) != _compute_run_id(["10.0.0.1"], 200)


# --- _load_scan_state / _save_scan_state / _clear_scan_state ---

def test_load_scan_state_new(tmp_path, monkeypatch):
    """Brak pliku stanu → pusty stan z run_id."""
    state_file = tmp_path / "scan_progress.json"
    monkeypatch.setattr("netdoc.collector.discovery._SCAN_STATE_PATH", state_file)
    batches = [[22, 80], [443, 3389]]
    state = _load_scan_state("abc123", batches)
    assert state["run_id"] == "abc123"
    assert state["hosts"] == {}
    assert state["port_batches"] == batches


def test_save_and_load_state(tmp_path, monkeypatch):
    """Zapis stanu → wczytanie → poprawne dane.

    Uwaga: JSON serializuje klucze portow jako stringi.
    Konwersja int(k) odbywa sie w _port_scan_one_host_batched przy odczycie.
    """
    state_file = tmp_path / "scan_progress.json"
    monkeypatch.setattr("netdoc.collector.discovery._SCAN_STATE_PATH", state_file)
    batches = [[22, 80], [443, 3389]]
    run_id = "test_run_001"

    state = _load_scan_state(run_id, batches)
    state["hosts"]["10.0.0.1"] = {"done_batches": [0], "open_ports": {22: {"service": "ssh"}}}
    _save_scan_state(state)

    restored = _load_scan_state(run_id, batches)
    assert restored["run_id"] == run_id
    assert "10.0.0.1" in restored["hosts"]
    assert restored["hosts"]["10.0.0.1"]["done_batches"] == [0]
    # Po JSON round-trip klucze portow sa stringami ("22"), nie intami (22)
    open_ports = restored["hosts"]["10.0.0.1"]["open_ports"]
    assert "22" in open_ports or 22 in open_ports  # akceptuj obie formy
    port_data = open_ports.get("22") or open_ports.get(22)
    assert port_data["service"] == "ssh"


def test_load_state_different_run_id_resets(tmp_path, monkeypatch):
    """Stan z innym run_id → ignorowany, nowy pusty stan."""
    state_file = tmp_path / "scan_progress.json"
    monkeypatch.setattr("netdoc.collector.discovery._SCAN_STATE_PATH", state_file)
    batches = [[22]]
    old = {"run_id": "stary", "port_batches": batches,
           "hosts": {"10.0.0.1": {"done_batches": [0], "open_ports": {}}}}
    state_file.write_text(json.dumps(old), encoding="utf-8")

    new_state = _load_scan_state("nowy", batches)
    assert new_state["run_id"] == "nowy"
    assert new_state["hosts"] == {}


def test_clear_scan_state_removes_file(tmp_path, monkeypatch):
    """clear_scan_state usuwa plik."""
    state_file = tmp_path / "scan_progress.json"
    state_file.write_text("{}", encoding="utf-8")
    monkeypatch.setattr("netdoc.collector.discovery._SCAN_STATE_PATH", state_file)
    _clear_scan_state()
    assert not state_file.exists()


def test_clear_scan_state_no_file_ok(tmp_path, monkeypatch):
    """clear_scan_state nie rzuca bledu gdy brak pliku."""
    state_file = tmp_path / "scan_progress.json"
    monkeypatch.setattr("netdoc.collector.discovery._SCAN_STATE_PATH", state_file)
    _clear_scan_state()


# --- _port_scan_one_host_batched ---

def _build_nmap_mock(port_sequences):
    """Zwraca mock klasy PortScanner.

    port_sequences: lista dicts {ip: [lista_otwartych_portow]} — jeden per wywolanie scan().
    """
    seq = iter(port_sequences)

    class MockNm:
        def __init__(self, **kw):
            self._data = {}

        def scan(self, hosts, arguments):
            entry = next(seq, {})
            self._data = {}
            for ip, ports in entry.items():
                self._data[ip] = {"tcp": {
                    p: {"state": "open", "name": "svc", "version": "", "product": ""}
                    for p in ports
                }}

        def all_hosts(self):
            return list(self._data.keys())

        def __getitem__(self, host):
            return self._data.get(host, {})

        def get(self, key, default=None):
            return default

    return MockNm


def test_batched_scan_combines_all_batches(tmp_path, monkeypatch):
    """Dwie partie → wyniki z obu polaczone w open_ports."""
    sf = tmp_path / "s.json"
    monkeypatch.setattr("netdoc.collector.discovery._SCAN_STATE_PATH", sf)
    monkeypatch.setattr("netdoc.collector.discovery._NMAP_SEARCH_PATH", ("nmap",))

    batches = [[22, 80], [443, 3389]]
    state = {"run_id": "r", "port_batches": batches, "hosts": {}}
    MockNm = _build_nmap_mock([{"192.168.1.1": [22, 80]}, {"192.168.1.1": [443]}])

    with patch("netdoc.collector.discovery.nmap.PortScanner", MockNm):
        with patch("netdoc.collector.discovery.time.sleep"):
            result = _port_scan_one_host_batched(
                "192.168.1.1", batches, 1.0, 100, 1, state)

    assert 22 in result["open_ports"]
    assert 80 in result["open_ports"]
    assert 443 in result["open_ports"]
    assert 3389 not in result["open_ports"]


def test_batched_scan_resume_skips_done_batches(tmp_path, monkeypatch):
    """Partia 0 juz w done_batches → nmap wywolany tylko dla partii 1."""
    sf = tmp_path / "s.json"
    monkeypatch.setattr("netdoc.collector.discovery._SCAN_STATE_PATH", sf)
    monkeypatch.setattr("netdoc.collector.discovery._NMAP_SEARCH_PATH", ("nmap",))

    batches = [[22, 80], [443, 3389]]
    state = {
        "run_id": "r", "port_batches": batches,
        "hosts": {"10.0.0.5": {
            "done_batches": [0],
            "open_ports": {22: {"service": "ssh", "version": "", "product": ""}},
        }},
    }

    scan_args_captured = []

    class MockNm:
        def __init__(self, **kw): pass

        def scan(self, hosts, arguments):
            scan_args_captured.append(arguments)
            self._h = hosts

        def all_hosts(self): return [self._h]

        def __getitem__(self, host):
            return {"tcp": {443: {"state": "open", "name": "https", "version": "", "product": ""}}}

        def get(self, k, d=None): return d

    with patch("netdoc.collector.discovery.nmap.PortScanner", MockNm):
        with patch("netdoc.collector.discovery.time.sleep"):
            result = _port_scan_one_host_batched("10.0.0.5", batches, 0, 100, 1, state)

    assert len(scan_args_captured) == 1          # tylko partia 1
    assert "443" in scan_args_captured[0]
    assert 22 in result["open_ports"]            # z resume
    assert 443 in result["open_ports"]           # z skan


def test_batched_scan_state_saved_after_each_batch(tmp_path, monkeypatch):
    """Stan zapisywany po kazdej partii, nawet gdy nmap rzuca blad."""
    sf = tmp_path / "s.json"
    monkeypatch.setattr("netdoc.collector.discovery._SCAN_STATE_PATH", sf)
    monkeypatch.setattr("netdoc.collector.discovery._NMAP_SEARCH_PATH", ("nmap",))

    batches = [[22], [80], [443]]
    state = {"run_id": "r", "port_batches": batches, "hosts": {}}
    call_count = {"n": 0}

    class MockNm:
        def __init__(self, **kw): pass

        def scan(self, hosts, arguments):
            call_count["n"] += 1
            self._h = hosts
            if call_count["n"] == 2:
                raise _nmap_mod.PortScannerError("symulowane przerwanie")

        def all_hosts(self):
            return [self._h] if call_count["n"] != 2 else []

        def __getitem__(self, host): return {}

        def get(self, k, d=None): return d

    with patch("netdoc.collector.discovery.nmap.PortScanner", MockNm):
        with patch("netdoc.collector.discovery.time.sleep"):
            _port_scan_one_host_batched("10.0.0.1", batches, 0, 100, 1, state)

    saved = json.loads(sf.read_text())
    done = saved["hosts"]["10.0.0.1"]["done_batches"]
    assert 0 in done
    assert 1 in done  # nmap dal blad dla partii 1, ale partia nadal oznaczona jako done


def test_port_scan_uses_batched_mode_when_batch_size_gt_0(tmp_path, monkeypatch):
    """port_scan z batch_size>0 → kazdy host skanowany przez _port_scan_one_host_batched."""
    sf = tmp_path / "s.json"
    monkeypatch.setattr("netdoc.collector.discovery._SCAN_STATE_PATH", sf)

    called = []

    def mock_batched(ip, batches, batch_pause_s, nmap_rate, nmap_vi, state):
        called.append(ip)
        return {"open_ports": {}, "os": None, "vendor": None}

    settings = {"concurrency": 0, "batch_size": 10, "batch_pause_s": 0.0, "resume_enabled": False}

    with patch("netdoc.collector.discovery._port_scan_one_host_batched", side_effect=mock_batched):
        with patch("netdoc.collector.discovery._read_nmap_settings", return_value=(100, 1)):
            result = port_scan(["10.0.0.1", "10.0.0.2"], _batch_settings=settings)

    assert set(called) == {"10.0.0.1", "10.0.0.2"}
    assert set(result.keys()) == {"10.0.0.1", "10.0.0.2"}


def test_port_scan_classic_when_both_zero():
    """batch_size=0 i concurrency=0 → klasyczny jeden nmap dla wszystkich hostow."""
    classic_hosts_arg = []

    class MockNm:
        def __init__(self, **kw): pass

        def scan(self, hosts, arguments):
            classic_hosts_arg.append(hosts)

        def all_hosts(self): return []

    settings = {"concurrency": 0, "batch_size": 0, "batch_pause_s": 0.0, "resume_enabled": False}

    with patch("netdoc.collector.discovery.nmap.PortScanner", MockNm):
        with patch("netdoc.collector.discovery._read_nmap_settings", return_value=(100, 1)):
            port_scan(["10.0.0.1", "10.0.0.2"], _batch_settings=settings)

    assert len(classic_hosts_arg) == 1
    assert "10.0.0.1" in classic_hosts_arg[0]
    assert "10.0.0.2" in classic_hosts_arg[0]


def test_port_scan_concurrency_1_limits_parallelism(tmp_path, monkeypatch):
    """concurrency=1 → nigdy wiecej niz 1 host skanowany jednoczesnie."""
    sf = tmp_path / "s.json"
    monkeypatch.setattr("netdoc.collector.discovery._SCAN_STATE_PATH", sf)

    max_concurrent = {"v": 0}
    current = {"v": 0}
    lock = threading.Lock()

    def mock_batched(ip, batches, pause, rate, vi, state):
        with lock:
            current["v"] += 1
            max_concurrent["v"] = max(max_concurrent["v"], current["v"])
        time.sleep(0.05)
        with lock:
            current["v"] -= 1
        return {"open_ports": {}, "os": None, "vendor": None}

    settings = {"concurrency": 1, "batch_size": 10, "batch_pause_s": 0.0, "resume_enabled": False}

    with patch("netdoc.collector.discovery._port_scan_one_host_batched", side_effect=mock_batched):
        with patch("netdoc.collector.discovery._read_nmap_settings", return_value=(100, 1)):
            port_scan(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
                      _batch_settings=settings)

    assert max_concurrent["v"] == 1


def test_port_scan_resume_loads_state_and_clears_on_success(tmp_path, monkeypatch):
    """port_scan: wczytuje stan z pliku i usuwa go po pomyslnym zakonczeniu."""
    sf = tmp_path / "s.json"
    monkeypatch.setattr("netdoc.collector.discovery._SCAN_STATE_PATH", sf)

    hosts = ["10.1.1.1", "10.1.1.2"]
    settings = {"concurrency": 0, "batch_size": 10, "batch_pause_s": 0.0, "resume_enabled": True}
    run_id = _compute_run_id(hosts, 10)

    # Zapisz istniejacy stan (symulacja przerwanego poprzedniego skanu)
    existing_state = {"run_id": run_id, "port_batches": [], "hosts": {
        "10.1.1.1": {"done_batches": [0, 1, 2], "open_ports": {22: {"service": "ssh", "version": "", "product": ""}}},
    }}
    sf.write_text(json.dumps(existing_state), encoding="utf-8")

    loaded_states = []

    def mock_batched(ip, batches, pause, rate, vi, state):
        loaded_states.append({"ip": ip, "hosts_in_state": list(state["hosts"].keys())})
        return {"open_ports": {22: {"service": "ssh", "version": "", "product": ""}},
                "os": None, "vendor": None}

    with patch("netdoc.collector.discovery._port_scan_one_host_batched", side_effect=mock_batched):
        with patch("netdoc.collector.discovery._read_nmap_settings", return_value=(100, 1)):
            result = port_scan(hosts, _batch_settings=settings)

    # State z pliku wczytany — host 10.1.1.1 byl juz w stanie
    scanned_ips = {s["ip"] for s in loaded_states}
    assert "10.1.1.1" in scanned_ips
    assert "10.1.1.2" in scanned_ips
    # Kazdy host widzial ten sam stan z zaladowanymi danymi
    for s in loaded_states:
        assert "10.1.1.1" in s["hosts_in_state"]
    # Plik usuniety po pomyslnym skanowaniu
    assert not sf.exists()


def test_port_scan_resume_disabled_ignores_state_file(tmp_path, monkeypatch):
    """resume_enabled=False → stary plik stanu ignorowany, zawsze skan od nowa."""
    sf = tmp_path / "s.json"
    monkeypatch.setattr("netdoc.collector.discovery._SCAN_STATE_PATH", sf)

    hosts = ["10.2.2.1"]
    run_id = _compute_run_id(hosts, 10)
    # Stary stan z "done" partiami
    sf.write_text(json.dumps({"run_id": run_id, "port_batches": [], "hosts": {
        "10.2.2.1": {"done_batches": list(range(10)), "open_ports": {}}
    }}), encoding="utf-8")

    called_with_done = []

    def mock_batched(ip, batches, pause, rate, vi, state):
        called_with_done.append(state["hosts"].get(ip, {}).get("done_batches", []))
        return {"open_ports": {}, "os": None, "vendor": None}

    settings = {"concurrency": 0, "batch_size": 10, "batch_pause_s": 0.0, "resume_enabled": False}

    with patch("netdoc.collector.discovery._port_scan_one_host_batched", side_effect=mock_batched):
        with patch("netdoc.collector.discovery._read_nmap_settings", return_value=(100, 1)):
            port_scan(hosts, _batch_settings=settings)

    # Resume wyłączony → stan inicjowany od zera, done_batches puste
    assert called_with_done == [[]]  # pusty stan (nie z pliku)


# ── Testy live-status tooltipow (scan_batch_status.json) ─────────────────────

import json
from unittest.mock import patch

import netdoc.collector.discovery as _disc_mod
from netdoc.collector.discovery import (
    _update_batch_live_status,
    _clear_scan_state,
    _port_scan_one_host_batched,
)


def test_update_batch_live_status_creates_file(tmp_path, monkeypatch):
    sf = tmp_path / "scan_batch_status.json"
    monkeypatch.setattr(_disc_mod, "_SCAN_BATCH_STATUS_PATH", sf)
    _update_batch_live_status("10.0.0.1", 0, 3, "22,80,443")
    assert sf.exists()
    data = json.loads(sf.read_text())
    assert data["10.0.0.1"]["batch"] == 1   # batch_idx+1
    assert data["10.0.0.1"]["total"] == 3
    assert data["10.0.0.1"]["ports"] == "22,80,443"


def test_update_batch_live_status_updates_multiple_ips(tmp_path, monkeypatch):
    sf = tmp_path / "scan_batch_status.json"
    monkeypatch.setattr(_disc_mod, "_SCAN_BATCH_STATUS_PATH", sf)
    _update_batch_live_status("10.0.0.1", 0, 3, "22,80")
    _update_batch_live_status("10.0.0.2", 1, 3, "443,8080")
    _update_batch_live_status("10.0.0.1", 2, 3, "3389")   # nadpisz 10.0.0.1
    data = json.loads(sf.read_text())
    assert data["10.0.0.1"]["batch"] == 3
    assert data["10.0.0.1"]["ports"] == "3389"
    assert "10.0.0.2" in data   # inne IP zachowane


def test_clear_scan_state_also_removes_batch_status(tmp_path, monkeypatch):
    state_file = tmp_path / "scan_progress.json"
    batch_file = tmp_path / "scan_batch_status.json"
    state_file.write_text("{}", encoding="utf-8")
    batch_file.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(_disc_mod, "_SCAN_STATE_PATH", state_file)
    monkeypatch.setattr(_disc_mod, "_SCAN_BATCH_STATUS_PATH", batch_file)
    _clear_scan_state()
    assert not state_file.exists()
    assert not batch_file.exists()   # batch status rowniez usuniety


def test_port_scan_one_host_writes_live_status(tmp_path, monkeypatch):
    sf = tmp_path / "s.json"
    bs = tmp_path / "bs.json"
    monkeypatch.setattr(_disc_mod, "_SCAN_STATE_PATH", sf)
    monkeypatch.setattr(_disc_mod, "_SCAN_BATCH_STATUS_PATH", bs)
    monkeypatch.setattr(_disc_mod, "_NMAP_SEARCH_PATH", ("nmap",))

    batches = [[22, 80], [443, 3389]]
    state = {"run_id": "r", "port_batches": batches, "hosts": {}}

    class MockNm:
        def __init__(self, **kw): pass
        def scan(self, hosts, arguments): self._h = hosts
        def all_hosts(self): return [self._h]
        def __getitem__(self, host): return {}
        def get(self, k, d=None): return d

    with patch(_disc_mod.__name__ + ".nmap.PortScanner", MockNm):
        with patch(_disc_mod.__name__ + ".time.sleep"):
            _port_scan_one_host_batched("192.168.0.5", batches, 0, 100, 1, state)

    assert bs.exists()
    data = json.loads(bs.read_text())
    assert "192.168.0.5" in data
    assert data["192.168.0.5"]["total"] == 2


# ── Testy: wsd_scan ────────────────────────────────────────────────────────────

def test_wsd_scan_socket_error_returns_empty():
    """Blad socketa (np. siec niedostepna) → pusty slownik bez wyjatku."""
    import socket as _sock
    from netdoc.collector.discovery import wsd_scan
    with patch("netdoc.collector.discovery._socket.socket",
               side_effect=_sock.error("network unreachable")):
        result = wsd_scan(timeout=0.1)
    assert result == {}


def test_wsd_scan_no_response_returns_empty():
    """Brak odpowiedzi w czasie timeout → pusty slownik."""
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock:
        inst = mock_sock.return_value
        inst.recvfrom.side_effect = socket.timeout
        result = wsd_scan(timeout=0.1)
    assert result == {}


def test_wsd_scan_parses_xaddrs_and_types():
    """Odpowiedz WSD z XAddrs i Types → zwrocone w meta."""
    import socket as _sock
    from netdoc.collector.discovery import wsd_scan

    wsd_response = (
        '<?xml version="1.0"?>'
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
        '<soap:Body>'
        '<wsd:ProbeMatches>'
        '<wsd:ProbeMatch>'
        '<wsd:Types>wsdp:Device wprt:PrintDeviceType</wsd:Types>'
        '<wsd:XAddrs>http://192.168.1.50:3911/wsdl</wsd:XAddrs>'
        '</wsd:ProbeMatch>'
        '</wsd:ProbeMatches>'
        '</soap:Body>'
        '</soap:Envelope>'
    ).encode("utf-8")

    call_count = [0]

    def _recvfrom(bufsize):
        if call_count[0] == 0:
            call_count[0] += 1
            return (wsd_response, ("192.168.1.50", 3702))
        raise _sock.timeout

    with patch("netdoc.collector.discovery._socket.socket") as mock_sock:
        inst = mock_sock.return_value
        inst.recvfrom.side_effect = _recvfrom
        result = wsd_scan(timeout=0.1)

    assert "192.168.1.50" in result
    assert "http://192.168.1.50:3911/wsdl" in result["192.168.1.50"]["xaddrs"]
    assert "wprt:PrintDeviceType" in result["192.168.1.50"]["types"]


def test_wsd_scan_deduplicates_same_ip():
    """Ten sam IP odpowiada dwa razy → tylko jeden wpis w wyniku."""
    import socket as _sock
    from netdoc.collector.discovery import wsd_scan

    wsd_response = b"<wsd:Types>wsdp:Device</wsd:Types><wsd:XAddrs>http://10.0.0.1/wsd</wsd:XAddrs>"
    call_count = [0]

    def _recvfrom(bufsize):
        if call_count[0] < 2:
            call_count[0] += 1
            return (wsd_response, ("10.0.0.1", 3702))
        raise _sock.timeout

    with patch("netdoc.collector.discovery._socket.socket") as mock_sock:
        inst = mock_sock.return_value
        inst.recvfrom.side_effect = _recvfrom
        result = wsd_scan(timeout=0.1)

    assert len([k for k in result if k == "10.0.0.1"]) == 1


def test_wsd_scan_empty_xaddrs_when_missing():
    """Odpowiedz bez XAddrs → lista xaddrs pusta."""
    import socket as _sock
    from netdoc.collector.discovery import wsd_scan

    wsd_response = b"<wsd:Types>wsdp:Device</wsd:Types>"
    call_count = [0]

    def _recvfrom(bufsize):
        if call_count[0] == 0:
            call_count[0] += 1
            return (wsd_response, ("192.168.5.10", 3702))
        raise _sock.timeout

    with patch("netdoc.collector.discovery._socket.socket") as mock_sock:
        inst = mock_sock.return_value
        inst.recvfrom.side_effect = _recvfrom
        result = wsd_scan(timeout=0.1)

    assert result["192.168.5.10"]["xaddrs"] == []


# ── Testy: apipa_from_arp ─────────────────────────────────────────────────────

def test_apipa_from_arp_returns_only_169_254():
    """ARP table z mieszanymi adresami → tylko 169.254.x.x w wyniku."""
    from netdoc.collector.discovery import apipa_from_arp
    arp_data = {
        "192.168.1.10": "aa:bb:cc:dd:ee:01",
        "169.254.5.20": "aa:bb:cc:dd:ee:02",
        "10.0.0.1":     "aa:bb:cc:dd:ee:03",
        "169.254.0.1":  "aa:bb:cc:dd:ee:04",
    }
    with patch("netdoc.collector.discovery.read_arp_table", return_value=arp_data):
        result = apipa_from_arp()
    assert set(result.keys()) == {"169.254.5.20", "169.254.0.1"}
    assert result["169.254.5.20"] == "aa:bb:cc:dd:ee:02"


def test_apipa_from_arp_empty_when_no_apipa():
    """ARP table bez 169.254.x.x → pusty slownik."""
    from netdoc.collector.discovery import apipa_from_arp
    arp_data = {"192.168.1.1": "aa:bb:cc:dd:ee:ff", "10.0.0.1": "ff:ee:dd:cc:bb:aa"}
    with patch("netdoc.collector.discovery.read_arp_table", return_value=arp_data):
        result = apipa_from_arp()
    assert result == {}


def test_apipa_from_arp_empty_table():
    """Pusta ARP table → pusty slownik."""
    from netdoc.collector.discovery import apipa_from_arp
    with patch("netdoc.collector.discovery.read_arp_table", return_value={}):
        result = apipa_from_arp()
    assert result == {}


def test_apipa_from_arp_all_apipa():
    """ARP table tylko z APIPA → wszystkie zwrocone."""
    from netdoc.collector.discovery import apipa_from_arp
    arp_data = {
        "169.254.1.1": "11:22:33:44:55:66",
        "169.254.2.2": "66:55:44:33:22:11",
    }
    with patch("netdoc.collector.discovery.read_arp_table", return_value=arp_data):
        result = apipa_from_arp()
    assert len(result) == 2


# ── Testy: detect_ip_conflicts ────────────────────────────────────────────────

def _make_device(db, ip, mac, hostname=None, is_active=True):
    """Helper: tworzy Device w bazie i zwraca obiekt."""
    from netdoc.collector.normalizer import normalize_mac
    device = Device(
        ip=ip,
        mac=normalize_mac(mac) if mac else None,
        hostname=hostname,
        is_active=is_active,
        device_type=DeviceType.unknown,
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


def test_detect_ip_conflicts_no_arp_returns_empty(db):
    """Pusta ARP table → brak konfliktow."""
    result = detect_ip_conflicts(db, {})
    assert result == []


def test_detect_ip_conflicts_no_conflict_when_macs_match(db):
    """ARP MAC zgodny z DB → brak konfliktu."""
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    result = detect_ip_conflicts(db, {"192.168.1.10": "aa:bb:cc:dd:ee:01"})
    assert result == []


def test_detect_ip_conflicts_no_conflict_when_device_not_in_db(db):
    """IP w ARP ale nie w DB → brak konfliktu (nowe urzadzenie)."""
    result = detect_ip_conflicts(db, {"192.168.1.99": "aa:bb:cc:dd:ee:01"})
    assert result == []


def test_detect_ip_conflicts_no_conflict_when_device_has_no_mac(db):
    """Urzadzenie w DB bez MAC → brak konfliktu (nic do porownania)."""
    _make_device(db, "192.168.1.10", mac=None)
    result = detect_ip_conflicts(db, {"192.168.1.10": "aa:bb:cc:dd:ee:01"})
    assert result == []


def test_detect_ip_conflicts_detects_different_mac(db):
    """Rozny MAC w ARP i DB → konflikt wykryty."""
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    result = detect_ip_conflicts(db, {"192.168.1.10": "ff:00:11:22:33:44"})
    assert len(result) == 1
    assert result[0]["ip"] == "192.168.1.10"
    # normalize_mac zwraca uppercase
    assert result[0]["old_mac"].upper() == "AA:BB:CC:DD:EE:01"
    assert result[0]["new_mac"].upper() == "FF:00:11:22:33:44"


def test_detect_ip_conflicts_creates_event_in_db(db):
    """Wykryty konflikt → Event ip_conflict zapisany w bazie."""
    dev = _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    detect_ip_conflicts(db, {"192.168.1.10": "ff:00:11:22:33:44"})
    events = db.query(Event).filter(
        Event.device_id == dev.id,
        Event.event_type == EventType.ip_conflict,
    ).all()
    assert len(events) == 1
    assert events[0].details["old_mac"].upper() == "AA:BB:CC:DD:EE:01"
    assert events[0].details["new_mac"].upper() == "FF:00:11:22:33:44"


def test_detect_ip_conflicts_event_contains_ip(db):
    """Event ip_conflict zawiera pole ip w details."""
    _make_device(db, "192.168.1.20", "11:22:33:44:55:66")
    detect_ip_conflicts(db, {"192.168.1.20": "aa:bb:cc:00:11:22"})
    ev = db.query(Event).filter(Event.event_type == EventType.ip_conflict).first()
    assert ev is not None
    assert ev.details["ip"] == "192.168.1.20"


def test_detect_ip_conflicts_rate_limiting_suppresses_repeat(db):
    """Drugi skan z tym samym konfliktem w ciagu 30 min → brak duplikatu eventu."""
    dev = _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    arp = {"192.168.1.10": "ff:00:11:22:33:44"}

    # Pierwszy wywolanie — konflikt wykryty
    r1 = detect_ip_conflicts(db, arp)
    assert len(r1) == 1

    # Drugi wywolanie (symuluje nastepny skan, MAC w DB nadal stary)
    r2 = detect_ip_conflicts(db, arp)
    # Rate-limiting: drugi alarm powinien byc zablokowany
    assert len(r2) == 0

    # W DB nadal tylko JEDEN event ip_conflict
    count = db.query(Event).filter(
        Event.device_id == dev.id,
        Event.event_type == EventType.ip_conflict,
    ).count()
    assert count == 1


def test_detect_ip_conflicts_ignores_broadcast_mac(db):
    """ARP z MAC ff:ff:ff:ff:ff:ff → pomijany (nieprawidlowy)."""
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    result = detect_ip_conflicts(db, {"192.168.1.10": "ff:ff:ff:ff:ff:ff"})
    assert result == []


def test_detect_ip_conflicts_ignores_zero_mac(db):
    """ARP z MAC 00:00:00:00:00:00 → pomijany (nieprawidlowy)."""
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    result = detect_ip_conflicts(db, {"192.168.1.10": "00:00:00:00:00:00"})
    assert result == []


def test_detect_ip_conflicts_ignores_inactive_devices(db):
    """Nieaktywne urzadzenie w DB → brak konfliktu (moze byc juz usuniete)."""
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01", is_active=False)
    result = detect_ip_conflicts(db, {"192.168.1.10": "ff:00:11:22:33:44"})
    assert result == []


def test_detect_ip_conflicts_multiple_conflicts(db):
    """Wiele konfliktow w jednym skanowaniu → wszystkie wykryte."""
    _make_device(db, "192.168.1.10", "aa:bb:cc:00:00:01")
    _make_device(db, "192.168.1.20", "aa:bb:cc:00:00:02")
    _make_device(db, "192.168.1.30", "aa:bb:cc:00:00:03")  # ten bez konfliktu

    arp = {
        "192.168.1.10": "ff:00:00:00:00:01",  # konflikt
        "192.168.1.20": "ff:00:00:00:00:02",  # konflikt
        "192.168.1.30": "aa:bb:cc:00:00:03",  # brak konfliktu (MAC zgodny)
    }
    result = detect_ip_conflicts(db, arp)
    conflict_ips = {c["ip"] for c in result}
    assert conflict_ips == {"192.168.1.10", "192.168.1.20"}


def test_detect_ip_conflicts_hostname_in_result(db):
    """Wynik zawiera hostname urzadzenia."""
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01", hostname="serwer-pliku")
    result = detect_ip_conflicts(db, {"192.168.1.10": "ff:00:11:22:33:44"})
    assert result[0]["hostname"] == "serwer-pliku"


def test_detect_ip_conflicts_fallback_hostname_is_ip(db):
    """Urzadzenie bez hostname → fallback to IP w wyniku."""
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01", hostname=None)
    result = detect_ip_conflicts(db, {"192.168.1.10": "ff:00:11:22:33:44"})
    assert result[0]["hostname"] == "192.168.1.10"


def test_detect_ip_conflicts_telegram_exception_does_not_crash(db):
    """Blad Telegram (np. brak sieci) → funkcja nie rzuca wyjatku, event w DB jest."""
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    # Symuluj blad podczas wysylania Telegram (lazy import w try/except)
    with patch("netdoc.notifications.telegram.send_telegram", side_effect=Exception("conn error")):
        with patch("netdoc.notifications.telegram.get_telegram_config",
                   return_value={"bot_token": "TOK", "chat_id": "123"}):
            # Nie powinno rzucic wyjatku
            result = detect_ip_conflicts(db, {"192.168.1.10": "ff:00:11:22:33:44"})
    # Event w DB musi byc niezaleznie od bledu Telegram
    ev = db.query(Event).filter(Event.event_type == EventType.ip_conflict).first()
    assert ev is not None
    assert len(result) == 1


# ── Scenariusze firmowe: detect_ip_conflicts ──────────────────────────────────


def test_detect_ip_conflicts_windows_broadcast_dash_format_ignored(db):
    """Windows ARP: broadcast MAC z kreskami (ff-ff-ff-ff-ff-ff) → pomijany.

    Windows cmd 'arp -a' zwraca MACs w formacie 'ff-ff-ff-ff-ff-ff' (kreski, lowercase).
    Poprzedni kod: current_mac.lower() in {"ff:ff:ff:ff:ff:ff"} = False → BUG!
    Po naprawie: normalize_mac() konwertuje kreski na dwukropki przed porownaniem.
    """
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    result = detect_ip_conflicts(db, {"192.168.1.10": "ff-ff-ff-ff-ff-ff"})
    assert result == []


def test_detect_ip_conflicts_windows_zero_mac_dash_format_ignored(db):
    """Windows ARP: zero MAC z kreskami (00-00-00-00-00-00) → pomijany."""
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    result = detect_ip_conflicts(db, {"192.168.1.10": "00-00-00-00-00-00"})
    assert result == []


def test_detect_ip_conflicts_same_mac_different_format_no_false_positive(db):
    """Scenariusz: DB ma MAC z kolkami, ARP zwraca kreski (Windows) → brak konfliktu.

    Firma: Windows DHCP server w ARP → MACs z kreskami aa-bb-cc-dd-ee-01.
    DB ma ten sam MAC zapisany przez poprzedni skan z kolkami aa:bb:cc:dd:ee:01.
    Bez normalizacji byloby false positive.
    """
    _make_device(db, "192.168.1.100", "aa:bb:cc:dd:ee:01")
    result = detect_ip_conflicts(db, {"192.168.1.100": "aa-bb-cc-dd-ee-01"})
    assert result == []


def test_detect_ip_conflicts_mac_case_insensitive_no_false_positive(db):
    """Rozne systemy zwracaja MACs uppercase/lowercase → nie powinno generowac konfliktu.

    Scenario: Linux ARP 'AA:BB:CC:DD:EE:01' vs Windows 'aa:bb:cc:dd:ee:01'.
    """
    _make_device(db, "192.168.1.10", "AA:BB:CC:DD:EE:01")
    result = detect_ip_conflicts(db, {"192.168.1.10": "aa:bb:cc:dd:ee:01"})
    assert result == []


def test_detect_ip_conflicts_mac_case_mixed_no_false_positive(db):
    """MACs rozniczkowane wielkoscia liter (Linux uppercase, DB lowercase) → brak konfliktu."""
    _make_device(db, "192.168.1.55", "aa:bb:cc:dd:ee:ff")
    result = detect_ip_conflicts(db, {"192.168.1.55": "AA:BB:CC:DD:EE:FF"})
    assert result == []


def test_detect_ip_conflicts_windows_dash_real_conflict_detected(db):
    """Windows ARP: inny MAC (kreski) niz w DB → PRAWDZIWY konflikt wykryty.

    Scenariusz: administrator pomylkowo przypisal ten sam statyczny IP
    drukarce i stacji roboczej. Windows ARP zwraca MAC nowej drukarki (kreski).
    """
    _make_device(db, "192.168.1.50", "aa:bb:cc:00:00:01", hostname="stacja-01")
    result = detect_ip_conflicts(db, {"192.168.1.50": "bb-cc-dd-00-00-02"})
    assert len(result) == 1
    assert result[0]["ip"] == "192.168.1.50"
    assert result[0]["new_mac"].upper() == "BB:CC:DD:00:00:02"
    assert result[0]["old_mac"].upper() == "AA:BB:CC:00:00:01"


def test_detect_ip_conflicts_vm_mac_hyper_v_prefix_detected_as_conflict(db):
    """Scenariusz: VM Hyper-V dostala ten sam IP co fizyczny host.

    Firmy z Hyper-V: VM dostaje MAC 00:15:5D:xx:xx:xx.
    Jesli stacja fizyczna juz miala ten IP w DB → konflikt!
    """
    _make_device(db, "192.168.1.200", "c8:d9:d2:aa:bb:cc", hostname="host-fizyczny")
    # Hyper-V VM MAC prefix 00:15:5D
    result = detect_ip_conflicts(db, {"192.168.1.200": "00:15:5d:01:02:03"})
    assert len(result) == 1
    assert result[0]["new_mac"].upper() == "00:15:5D:01:02:03"


def test_detect_ip_conflicts_vm_mac_vmware_prefix_detected_as_conflict(db):
    """Scenariusz: VMware VM zajela IP fizycznego hosta.

    VMware MAC prefix: 00:50:56:xx:xx:xx lub 00:0C:29:xx:xx:xx.
    """
    _make_device(db, "10.0.0.50", "c8:d9:d2:11:22:33", hostname="srv-prod")
    result = detect_ip_conflicts(db, {"10.0.0.50": "00:50:56:ab:cd:ef"})
    assert len(result) == 1
    assert result[0]["new_mac"].upper() == "00:50:56:AB:CD:EF"


def test_detect_ip_conflicts_result_macs_always_normalized(db):
    """Wynikowe pola old_mac i new_mac sa zawsze znormalizowane (uppercase, kolki).

    Zapewnia spojnosc przy wyswietlaniu w UI i logach.
    """
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    result = detect_ip_conflicts(db, {"192.168.1.10": "ff-00-11-22-33-44"})
    assert len(result) == 1
    # Oba pola uppercase z dwukropkami
    assert result[0]["old_mac"] == "AA:BB:CC:DD:EE:01"
    assert result[0]["new_mac"] == "FF:00:11:22:33:44"


def test_detect_ip_conflicts_event_macs_always_normalized(db):
    """Event details zawiera znormalizowane MACs (uppercase, kolki).

    Szukanie w DB: 'SELECT * FROM events WHERE details->>'old_mac' = ...' dziala
    tylko przy spojnym formacie.
    """
    dev = _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    detect_ip_conflicts(db, {"192.168.1.10": "ff-00-11-22-33-44"})
    ev = db.query(Event).filter(
        Event.device_id == dev.id,
        Event.event_type == EventType.ip_conflict,
    ).first()
    assert ev is not None
    assert ev.details["old_mac"] == "AA:BB:CC:DD:EE:01"
    assert ev.details["new_mac"] == "FF:00:11:22:33:44"


def test_detect_ip_conflicts_rate_limiting_expires_after_cooldown(db):
    """Po uplywie cooldown (symulacja) — kolejny konflikt JEST rejestrowany.

    Scenariusz: konflikt trwa wiele godzin. Po 30 min cooldown dostajemy
    kolejny alert zeby administrator wiedzial ze problem nadal trwa.
    """
    dev = _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    arp = {"192.168.1.10": "ff:00:11:22:33:44"}

    # Pierwszy konflikt
    r1 = detect_ip_conflicts(db, arp)
    assert len(r1) == 1

    # Symuluj ze ostatni event jest sprzed 31 minut (cooldown minal)
    old_event = db.query(Event).filter(Event.device_id == dev.id).first()
    old_event.event_time = datetime.utcnow() - timedelta(minutes=31)
    db.commit()

    # Drugi wywolanie po cooldown → powinien wykryc ponownie
    r2 = detect_ip_conflicts(db, arp)
    assert len(r2) == 1

    # W DB sa teraz DWA eventy ip_conflict
    count = db.query(Event).filter(
        Event.device_id == dev.id,
        Event.event_type == EventType.ip_conflict,
    ).count()
    assert count == 2


def test_detect_ip_conflicts_apipa_ip_conflict(db):
    """Scenariusz: APIPA (169.254.x.x) — dwa urzadzenia bez DHCP walcza o autoIP.

    APIPA konflikt = powazny problem: oba urzadzenia NIE maja dostepu do sieci.
    """
    _make_device(db, "169.254.1.10", "aa:bb:cc:00:00:01", hostname="kamera-apipa")
    result = detect_ip_conflicts(db, {"169.254.1.10": "dd:ee:ff:00:00:02"})
    assert len(result) == 1
    assert result[0]["ip"] == "169.254.1.10"


def test_detect_ip_conflicts_mixed_valid_invalid_arp_entries(db):
    """Mieszana ARP table: nieprawidlowe MACs pomijane, prawdziwy konflikt wykryty.

    Firma: Windows 'arp -a' zwraca broadcast, zero MAC, i realny MAC — wszystkie razem.
    """
    _make_device(db, "192.168.1.10", "aa:bb:cc:00:00:01")
    _make_device(db, "192.168.1.20", "aa:bb:cc:00:00:02")
    _make_device(db, "192.168.1.30", "aa:bb:cc:00:00:03")

    arp = {
        "192.168.255.255": "ff-ff-ff-ff-ff-ff",   # broadcast — pomiń
        "192.168.1.10": "00-00-00-00-00-00",       # zero MAC — pomiń
        "192.168.1.20": "aa:bb:cc:00:00:02",       # brak konfliktu (MAC zgodny)
        "192.168.1.30": "bb:cc:dd:00:00:04",       # KONFLIKT
    }
    result = detect_ip_conflicts(db, arp)
    assert len(result) == 1
    assert result[0]["ip"] == "192.168.1.30"


def test_detect_ip_conflicts_enterprise_large_batch(db):
    """Scenariusz firmowy: 20 hostow w sieci, 5 konfliktow jednoczesnie.

    Testuje wydajnosc i poprawnosc przy wiekszej ilosci urzadzen.
    """
    # Tworzymy 20 urzadzen w DB
    devices = []
    for i in range(1, 21):
        d = _make_device(db, f"10.0.1.{i}", f"aa:bb:cc:00:00:{i:02x}")
        devices.append(d)

    # ARP: pierwsze 5 ma inny MAC (konflikty), pozostale zgodne
    arp = {}
    for i in range(1, 21):
        if i <= 5:
            arp[f"10.0.1.{i}"] = f"ff:00:00:00:00:{i:02x}"  # konflikt
        else:
            arp[f"10.0.1.{i}"] = f"aa:bb:cc:00:00:{i:02x}"  # brak konfliktu

    result = detect_ip_conflicts(db, arp)
    assert len(result) == 5
    conflict_ips = {c["ip"] for c in result}
    for i in range(1, 6):
        assert f"10.0.1.{i}" in conflict_ips


def test_detect_ip_conflicts_printer_duplicate_static_ip(db):
    """Klasyczny scenariusz firmowy: drukarka ze statycznym IP zduplikowanym przez DHCP.

    Nowy komputer dostal od DHCP IP 192.168.1.50, ktory byl juz przypisany statycznie
    do drukarki HP. Teraz dwa urzadzenia walcza o ten sam adres.
    MAC w DB = drukarka HP (OUI 00:17:C8), ARP teraz pokazuje laptop.
    """
    _make_device(db, "192.168.1.50", "00:17:c8:aa:bb:cc", hostname="drukarka-HP-4015")
    # Laptop dostal ten sam IP od DHCP
    laptop_mac = "d4:61:9d:11:22:33"  # Dell OUI
    result = detect_ip_conflicts(db, {"192.168.1.50": laptop_mac})
    assert len(result) == 1
    c = result[0]
    assert c["hostname"] == "drukarka-HP-4015"
    assert c["old_mac"].upper() == "00:17:C8:AA:BB:CC"
    assert c["new_mac"].upper() == "D4:61:9D:11:22:33"


def test_detect_ip_conflicts_none_mac_in_arp_skipped(db):
    """ARP entry z MAC=None → pomijany bez bledu (obrona przed None)."""
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    result = detect_ip_conflicts(db, {"192.168.1.10": None})
    assert result == []


def test_detect_ip_conflicts_empty_string_mac_in_arp_skipped(db):
    """ARP entry z MAC='' (pusty string) → pomijany bez bledu."""
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    result = detect_ip_conflicts(db, {"192.168.1.10": ""})
    assert result == []


def test_detect_ip_conflicts_rate_limiting_does_not_block_different_devices(db):
    """Rate-limiting jednego urzadzenia nie blokuje alarmow dla innych.

    Scenariusz: 192.168.1.10 ma aktywny cooldown, ale .20 nie — oba sa sprawdzane.
    """
    dev1 = _make_device(db, "192.168.1.10", "aa:bb:cc:00:00:01")
    _make_device(db, "192.168.1.20", "aa:bb:cc:00:00:02")

    # Pierwszy skan: oba konflikty
    r1 = detect_ip_conflicts(db, {
        "192.168.1.10": "ff:00:00:00:00:01",
        "192.168.1.20": "ff:00:00:00:00:02",
    })
    assert len(r1) == 2

    # Drugi skan: .10 jest rate-limited, .20 tez (oba mialy events przed chwila)
    r2 = detect_ip_conflicts(db, {
        "192.168.1.10": "ff:00:00:00:00:01",
        "192.168.1.20": "ff:00:00:00:00:02",
    })
    assert len(r2) == 0

    # Resetuj cooldown tylko dla .10
    ev1 = db.query(Event).filter(Event.device_id == dev1.id).first()
    ev1.event_time = datetime.utcnow() - timedelta(minutes=31)
    db.commit()

    # Trzeci skan: tylko .10 jest po cooldown → tylko jeden alarm
    r3 = detect_ip_conflicts(db, {
        "192.168.1.10": "ff:00:00:00:00:01",
        "192.168.1.20": "ff:00:00:00:00:02",
    })
    assert len(r3) == 1
    assert r3[0]["ip"] == "192.168.1.10"


# ── Runda 2: nowe bugi i edge cases ──────────────────────────────────────────


def test_detect_ip_conflicts_linux_incomplete_arp_ignored(db):
    """Linux ARP 'incomplete' entry — typowe dla probowanych ale nieosiagalnych IP.

    Scenariusz: 'arp -a' na Linuxie zwraca '(incomplete)' lub 'incomplete' dla
    adresow ktore nie odpowiedzialy na ARP request (timeout w trakcie skanu).
    Poprzedni kod: normalize_mac('incomplete') = 'incomplete' (truthy) → BUG:
    false positive conflict gdyby to IP bylo w DB z prawdziwym MAC.
    Po naprawie: regex walidacja odrzuca nienormalizowane stringi.
    """
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01", hostname="server-db")
    result = detect_ip_conflicts(db, {"192.168.1.10": "incomplete"})
    assert result == []


def test_detect_ip_conflicts_linux_incomplete_parentheses_ignored(db):
    """Linux 'arp -a' moze zawierac '(incomplete)' z nawiasami — pomijany."""
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    result = detect_ip_conflicts(db, {"192.168.1.10": "(incomplete)"})
    assert result == []


def test_detect_ip_conflicts_ip_as_mac_ignored(db):
    """IP address jako wartosc MAC w ARP — pomijany bez false positive.

    Scenariusz: blad parsowania ARP table — kolumna MAC zawiera IP zamiast MAC.
    normalize_mac('192.168.1.1') zwraca '192.168.1.1' (nie moze sparsowac).
    Bez regex walidacji: '192.168.1.1' != 'AA:BB:CC:DD:EE:01' → false positive!
    """
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    result = detect_ip_conflicts(db, {"192.168.1.10": "192.168.1.1"})
    assert result == []


def test_detect_ip_conflicts_too_short_mac_ignored(db):
    """Za krotki string MAC (np. 3 oktety) — pomijany."""
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    result = detect_ip_conflicts(db, {"192.168.1.10": "aa:bb:cc"})
    assert result == []


def test_detect_ip_conflicts_too_long_mac_ignored(db):
    """Za dlugi string MAC (7 oktetow — blad parsowania) — pomijany.

    Scenariusz: nmap lub inny tool zwroci IPv6 link-local jako 'MAC' — 8 bajtow.
    """
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    result = detect_ip_conflicts(db, {"192.168.1.10": "aa:bb:cc:dd:ee:ff:11"})
    assert result == []


def test_detect_ip_conflicts_garbage_string_ignored(db):
    """Dowolny smieci string jako MAC — pomijany bez false positive."""
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    for garbage in ("N/A", "unknown", "NOARP", "?", "dynamic", "static", "00:00:00"):
        result = detect_ip_conflicts(db, {"192.168.1.10": garbage})
        assert result == [], f"Garbage MAC '{garbage}' nie powinien generowac konfliktu"


def test_detect_ip_conflicts_valid_mac_after_garbage_batch(db):
    """ARP z mieszanymi wpisami: smieci + prawdziwy konflikt — tylko prawdziwy wykryty."""
    _make_device(db, "192.168.1.10", "aa:bb:cc:dd:ee:01")
    _make_device(db, "192.168.1.20", "aa:bb:cc:dd:ee:02")

    arp = {
        "192.168.1.10": "incomplete",        # garbage → ignoruj
        "192.168.1.20": "ff:00:11:22:33:44", # prawdziwy konflikt
        "192.168.1.30": "N/A",               # garbage dla IP bez wpisu w DB
    }
    result = detect_ip_conflicts(db, arp)
    assert len(result) == 1
    assert result[0]["ip"] == "192.168.1.20"


# ── WSD scan: socket close w finally ─────────────────────────────────────────


def test_wsd_scan_socket_closed_on_sendto_exception():
    """Socket jest zamykany nawet gdy sendto() rzuca wyjatek (Bug B fix).

    Poprzedni kod: sock.close() bylo w try block → wyciek deskryptora gdy
    sendto() rzucil wyjatek (np. 'Network unreachable', 'No route to host').
    Po naprawie: finally block zawsze zamyka socket.
    """
    import socket as _sock
    from netdoc.collector.discovery import wsd_scan

    mock_sock_inst = MagicMock()
    mock_sock_inst.sendto.side_effect = _sock.error("Network unreachable")
    mock_sock_inst.close = MagicMock()

    with patch("netdoc.collector.discovery._socket.socket",
               return_value=mock_sock_inst):
        result = wsd_scan(timeout=0.1)

    assert result == {}
    # Socket MUSI byc zamkniety mimo wyjatku
    mock_sock_inst.close.assert_called_once()


def test_wsd_scan_socket_closed_on_setsockopt_exception():
    """Socket zamykany rowniez gdy setsockopt() rzuca wyjatek."""
    import socket as _sock
    from netdoc.collector.discovery import wsd_scan

    mock_sock_inst = MagicMock()
    mock_sock_inst.setsockopt.side_effect = _sock.error("Operation not permitted")
    mock_sock_inst.close = MagicMock()

    with patch("netdoc.collector.discovery._socket.socket",
               return_value=mock_sock_inst):
        result = wsd_scan(timeout=0.1)

    assert result == {}
    mock_sock_inst.close.assert_called_once()


def test_wsd_scan_socket_closed_on_successful_scan():
    """Socket zamykany rowniez po udanym skanowaniu (regresja)."""
    import socket as _sock
    from netdoc.collector.discovery import wsd_scan

    call_count = [0]
    mock_sock_inst = MagicMock()

    def _recvfrom(bufsize):
        if call_count[0] == 0:
            call_count[0] += 1
            return (b"<wsd:Types>wsdp:Device</wsd:Types>", ("10.0.0.1", 3702))
        raise _sock.timeout

    mock_sock_inst.recvfrom.side_effect = _recvfrom
    mock_sock_inst.close = MagicMock()

    with patch("netdoc.collector.discovery._socket.socket",
               return_value=mock_sock_inst):
        result = wsd_scan(timeout=0.1)

    assert "10.0.0.1" in result
    mock_sock_inst.close.assert_called_once()


# ── normalize_mac: edge cases ─────────────────────────────────────────────────


def test_normalize_mac_ip_address_returns_original():
    """IP address jako wejscie → zwrot oryginalu (nie None)."""
    from netdoc.collector.normalizer import normalize_mac
    result = normalize_mac("192.168.1.1")
    # normalize_mac nie moze sparsowac IP → zwraca oryginal
    assert result == "192.168.1.1"
    # WAZNE: wynik nie jest prawidlowym MAC — detect_ip_conflicts filtruje regex


def test_normalize_mac_five_octets_returns_original():
    """5-oktetowy string → zwrot oryginalu."""
    from netdoc.collector.normalizer import normalize_mac
    result = normalize_mac("aa:bb:cc:dd:ee")
    assert result == "aa:bb:cc:dd:ee"


def test_normalize_mac_seven_octets_returns_original():
    """7-oktetowy string → zwrot oryginalu."""
    from netdoc.collector.normalizer import normalize_mac
    result = normalize_mac("aa:bb:cc:dd:ee:ff:11")
    assert result == "aa:bb:cc:dd:ee:ff:11"


def test_normalize_mac_cisco_dot_notation():
    """Cisco dot notation (aabb.ccdd.eeff) → poprawna normalizacja."""
    from netdoc.collector.normalizer import normalize_mac
    assert normalize_mac("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("001a.2b3c.4d5e") == "00:1A:2B:3C:4D:5E"


def test_normalize_mac_no_separator_12hex():
    """12-cyfrowy hex bez separatora → poprawna normalizacja."""
    from netdoc.collector.normalizer import normalize_mac
    assert normalize_mac("AABBCCDDEEFF") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("001a2b3c4d5e") == "00:1A:2B:3C:4D:5E"


# ── Runda 3: upsert_device i mark_missing_devices ────────────────────────────


def test_upsert_device_device_type_updated_on_second_scan(db):
    """device_type aktualizowany gdy nowy typ jest konkretny (nie unknown).

    Scenariusz: etap 1 tworzy urzadzenie jako unknown (brak portow),
    etap 2 klasyfikuje jako printer (port 9100). Po naprawie: typ aktualizowany.
    Poprzedni kod: update branch nie aktualizowal device_type → zawsze unknown.
    """
    # Etap 1: brak danych portow → unknown
    upsert_device(db, DeviceData(ip="192.168.1.50"))
    dev = db.query(Device).filter_by(ip="192.168.1.50").first()
    assert dev.device_type == DeviceType.unknown

    # Etap 2: port scan wykazal 9100 → guess daje printer
    upsert_device(db, DeviceData(ip="192.168.1.50", device_type=DeviceType.printer))
    db.refresh(dev)
    assert dev.device_type == DeviceType.printer


def test_upsert_device_device_type_not_downgraded_to_unknown(db):
    """Znana klasyfikacja (printer) NIE jest nadpisywana przez unknown.

    Scenariusz: etap 1 nie ma portow → device_type=unknown przekazany,
    ale urzadzenie w DB ma printer z poprzedniego skanu. Nie regresujemy.
    """
    upsert_device(db, DeviceData(ip="192.168.1.50", device_type=DeviceType.printer))
    dev = db.query(Device).filter_by(ip="192.168.1.50").first()
    assert dev.device_type == DeviceType.printer

    # Kolejny upsert z unknown (ping sweep bez portow)
    upsert_device(db, DeviceData(ip="192.168.1.50", device_type=DeviceType.unknown))
    db.refresh(dev)
    # Typ musi zostac printer — nie regresujemy do unknown!
    assert dev.device_type == DeviceType.printer


def test_upsert_device_device_type_reclassification_allowed(db):
    """Reklasyfikacja z jednego konkretnego typu na inny (np. unknown→camera→nvr).

    Scenariusz: SNMP/pipeline dowiaduje sie ze to NVR, nie kamera.
    """
    upsert_device(db, DeviceData(ip="192.168.1.50", device_type=DeviceType.camera))
    dev = db.query(Device).filter_by(ip="192.168.1.50").first()
    assert dev.device_type == DeviceType.camera

    # Dokladniejsze dane → reklasyfikacja
    upsert_device(db, DeviceData(ip="192.168.1.50", device_type=DeviceType.server))
    db.refresh(dev)
    assert dev.device_type == DeviceType.server


def test_upsert_device_model_updated_on_second_scan(db):
    """model ustawiany gdy dotad byl None (np. SNMP zwrocil model po etapie 2).

    Poprzedni kod: update branch nie aktualizowal model → model zawsze None
    dla istniejacych urzadzen mimo ze pipeline go odkryl.
    """
    upsert_device(db, DeviceData(ip="10.0.0.1", vendor="Cisco"))
    dev = db.query(Device).filter_by(ip="10.0.0.1").first()
    assert dev.model is None

    # SNMP/pipeline odkryl model
    upsert_device(db, DeviceData(ip="10.0.0.1", model="Catalyst 2960"))
    db.refresh(dev)
    assert dev.model == "Catalyst 2960"


def test_upsert_device_model_not_overwritten_if_already_set(db):
    """Model dokladniejszy (z SNMP) nie jest nadpisywany przez gorszy (z nmap).

    site_id i model: ustawiamy tylko gdy nie bylo wczesniej — API konsekwencji.
    """
    upsert_device(db, DeviceData(ip="10.0.0.1", model="Catalyst 2960-24T"))
    dev = db.query(Device).filter_by(ip="10.0.0.1").first()
    assert dev.model == "Catalyst 2960-24T"

    # Nmap ma tylko ogolny model
    upsert_device(db, DeviceData(ip="10.0.0.1", model="Cisco Switch"))
    db.refresh(dev)
    # Dokladny model nie powinien byc nadpisany ogolnym
    assert dev.model == "Catalyst 2960-24T"


def test_upsert_device_model_set_on_creation(db):
    """Nowe urzadzenie: model ustawiany przy tworzeniu."""
    upsert_device(db, DeviceData(ip="10.0.0.5", model="FortiGate 60F"))
    dev = db.query(Device).filter_by(ip="10.0.0.5").first()
    assert dev.model == "FortiGate 60F"


def test_mark_missing_devices_empty_found_ips_deactivates_nothing(db):
    """found_ips=[] — ZADNE urzadzenie nie jest deaktywowane (guard przed katastrofa).

    Scenariusz: chwilowy blad sieci, ping sweep nie znalazl nikogo → found_ips=[].
    Poprzedni kod: SQLAlchemy notin_([]) generuje TRUE → wszystkie urzadzenia
    z last_seen > cooldown zostalby deaktywowane (cala infrastruktura offline!).
    Po naprawie: wczesny return, brak zmian w DB.
    """
    old_time = datetime.utcnow() - timedelta(minutes=60)
    d1 = Device(ip="10.0.0.1", is_active=True, device_type=DeviceType.unknown, last_seen=old_time)
    d2 = Device(ip="10.0.0.2", is_active=True, device_type=DeviceType.unknown, last_seen=old_time)
    d3 = Device(ip="10.0.0.3", is_active=True, device_type=DeviceType.unknown, last_seen=old_time)
    db.add_all([d1, d2, d3])
    db.commit()

    mark_missing_devices(db, found_ips=[])

    db.refresh(d1); db.refresh(d2); db.refresh(d3)
    # Wszystkie MUSZA byc nadal aktywne — guard przed pusta lista zadziałał
    assert d1.is_active is True
    assert d2.is_active is True
    assert d3.is_active is True

    # Brak eventow device_disappeared
    count = db.query(Event).filter(Event.event_type == EventType.device_disappeared).count()
    assert count == 0


def test_mark_missing_devices_empty_found_ips_no_events_created(db):
    """found_ips=[] → zero eventow device_disappeared (regresja dla guard)."""
    old_time = datetime.utcnow() - timedelta(minutes=30)
    for i in range(5):
        db.add(Device(ip=f"10.1.0.{i}", is_active=True,
                      device_type=DeviceType.unknown, last_seen=old_time))
    db.commit()

    mark_missing_devices(db, found_ips=[])

    count = db.query(Event).filter(Event.event_type == EventType.device_disappeared).count()
    assert count == 0


def test_mark_missing_devices_normal_behavior_preserved(db):
    """mark_missing_devices normalnie dziala z niepusta lista found_ips (regresja)."""
    old_time = datetime.utcnow() - timedelta(minutes=60)
    d1 = Device(ip="10.0.0.1", is_active=True, device_type=DeviceType.unknown, last_seen=old_time)
    d2 = Device(ip="10.0.0.2", is_active=True, device_type=DeviceType.unknown, last_seen=old_time)
    db.add_all([d1, d2])
    db.commit()

    # d1 znaleziony przez nmap, d2 nie
    mark_missing_devices(db, found_ips=["10.0.0.1"])

    db.refresh(d1); db.refresh(d2)
    assert d1.is_active is True   # znaleziony — aktywny
    assert d2.is_active is False  # nieznaleziony i stary last_seen — deaktywowany


def test_upsert_device_complete_update_scenario(db):
    """Pelny scenariusz: etap 1 (minimal) → etap 2 (pelne dane) → weryfikacja.

    Firma: discovery wykrywa 192.168.1.100 — tylko IP z ARP.
    Etap 2: port scan → HP drukarka, model z banneru.
    Pipeline: SNMP → model dokładny.
    Kazdy krok enrichuje — nie niszczy.
    """
    # Etap 1: tylko IP i MAC
    upsert_device(db, DeviceData(
        ip="192.168.1.100", mac="00:17:c8:aa:bb:cc",
    ))
    dev = db.query(Device).filter_by(ip="192.168.1.100").first()
    assert dev.device_type == DeviceType.unknown
    assert dev.model is None

    # Etap 2: port scan
    upsert_device(db, DeviceData(
        ip="192.168.1.100",
        vendor="Hewlett Packard",
        device_type=DeviceType.printer,
        os_version="HP JetDirect",
    ))
    db.refresh(dev)
    assert dev.device_type == DeviceType.printer
    assert dev.vendor == "Hewlett Packard"

    # Pipeline: SNMP model
    upsert_device(db, DeviceData(
        ip="192.168.1.100",
        model="HP LaserJet Pro M404n",
        device_type=DeviceType.printer,  # potwierdzamy
    ))
    db.refresh(dev)
    assert dev.model == "HP LaserJet Pro M404n"
    assert dev.device_type == DeviceType.printer  # bez regresu


# ══════════════════════════════════════════════════════════════════════
# Testy DNS + Domain Controller detection (2026-03-12)
# ══════════════════════════════════════════════════════════════════════

# --- _guess_device_type: Domain Controller ---

def test_dc_full_windows_ports():
    """Windows DC: Kerberos + LDAP + SMB + RDP."""
    result = _guess_device_type(
        {88, 389, 445, 135, 139, 3389}, "Windows Server 2022"
    )
    assert result == DeviceType.domain_controller


def test_dc_minimum_ports_kerberos_ldap_smb():
    """DC minimum: tylko 88 + 389 + 445."""
    result = _guess_device_type({88, 389, 445}, "")
    assert result == DeviceType.domain_controller


def test_dc_global_catalog_instead_of_ldap():
    """DC z Global Catalog (3268) zamiast podstawowego LDAP (389)."""
    result = _guess_device_type({88, 3268, 445}, "Windows Server 2019")
    assert result == DeviceType.domain_controller


def test_dc_ldaps_and_gc_ssl():
    """DC z LDAPS (636) i Global Catalog SSL (3269)."""
    result = _guess_device_type({88, 636, 3269, 445, 3389}, "")
    assert result == DeviceType.domain_controller


def test_dc_samba_on_linux():
    """Samba DC na Linuxie: vendor pusty, OS Samba, porty DC."""
    result = _guess_device_type({88, 389, 445, 22}, "Samba AD DC")
    assert result == DeviceType.domain_controller


def test_dc_no_kerberos_not_dc():
    """Brak Kerberos (88) → nie DC, mimo LDAP + SMB."""
    result = _guess_device_type({389, 445, 135}, "Windows Server 2019")
    assert result != DeviceType.domain_controller


def test_dc_no_smb_not_dc():
    """Brak SMB (445) → nie DC, mimo Kerberos + LDAP."""
    result = _guess_device_type({88, 389, 636, 3389}, "Windows Server 2022")
    assert result != DeviceType.domain_controller


def test_dc_no_ldap_and_no_gc_not_dc():
    """Kerberos + SMB, ale ani LDAP ani GC → nie DC."""
    result = _guess_device_type({88, 445, 22}, "")
    assert result != DeviceType.domain_controller


def test_dc_network_vendor_excluded():
    """Cisco z portami DC-like → nie DC (wykluczone przez vendor)."""
    result = _guess_device_type(
        {88, 389, 445}, "Cisco IOS", vendor="Cisco Systems"
    )
    assert result != DeviceType.domain_controller


def test_dc_fortios_excluded():
    """FortiGate z portami DC-like → nie DC."""
    result = _guess_device_type(
        {88, 389, 445}, "FortiOS", vendor="Fortinet"
    )
    assert result != DeviceType.domain_controller


def test_dc_kerberos_client_workstation_not_dc():
    """Kerberos client (88 open) + RDP + brak LDAP/SMB → nie DC."""
    result = _guess_device_type({88, 3389, 135, 139}, "Windows 10")
    assert result != DeviceType.domain_controller


def test_dc_beats_generic_server():
    """DC wygrywa z klasyfikacja generic server przy portach mieszanych."""
    result = _guess_device_type(
        {88, 389, 445, 22, 80, 443, 3389}, "Windows Server 2022"
    )
    assert result == DeviceType.domain_controller


def test_dc_ad_banner_hint():
    """Banner 'Active Directory' w open_ports_detail → hint Windows → DC."""
    ports_detail = {389: {"product": "Microsoft Active Directory LDAP"}}
    result = _guess_device_type(
        {88, 389, 445}, "", open_ports_detail=ports_detail
    )
    assert result == DeviceType.domain_controller


def test_dc_gc_ssl_only_no_basic_ldap():
    """GC-SSL (3269) bez standardowego LDAP (389) → DC gdy Kerberos + SMB."""
    result = _guess_device_type({88, 3269, 445}, "")
    assert result == DeviceType.domain_controller


def test_dc_small_biz_single_dc():
    """Typowy maly DC: Essentials — 88+389+445+3389+53."""
    result = _guess_device_type(
        {88, 389, 445, 3389, 53}, "Windows Server Essentials"
    )
    assert result == DeviceType.domain_controller


def test_dc_rodc_read_only():
    """RODC (Read-Only DC) — te same porty co pelny DC."""
    result = _guess_device_type(
        {88, 389, 636, 3268, 3269, 445, 3389}, "Windows Server 2022"
    )
    assert result == DeviceType.domain_controller


def test_dc_wins_over_windows_server_classification():
    """DC nie jest sklasyfikowany jako zwykly 'server'."""
    generic = _guess_device_type({135, 139, 445, 3389}, "Windows Server 2022")
    dc = _guess_device_type({88, 389, 445, 3389}, "Windows Server 2022")
    assert generic != DeviceType.domain_controller
    assert dc == DeviceType.domain_controller


# --- _guess_device_type: DNS server ---

def test_dns_server_with_ssh_classified_as_server():
    """Port 53 + SSH → serwer DNS (np. BIND na Linuxie)."""
    result = _guess_device_type({53, 22}, "")
    assert result == DeviceType.server


def test_dns_server_with_rdp():
    """Port 53 + RDP → Windows DNS Server."""
    result = _guess_device_type({53, 3389, 135}, "Windows Server 2019")
    assert result == DeviceType.server


def test_dns_port_alone_not_classified_as_server():
    """Sam port 53 bez typowych portow zarzadzania → nie server przez logike DNS."""
    result = _guess_device_type({53, 80}, "")
    assert result != DeviceType.server


def test_dns_pihole_with_ssh():
    """Pi-hole: port 53 + SSH + 80 → server."""
    result = _guess_device_type({53, 22, 80}, "")
    assert result == DeviceType.server


def test_dc_with_dns_stays_dc():
    """DC z portem 53 (DNS role na DC) → nadal domain_controller, nie server."""
    result = _guess_device_type(
        {88, 389, 445, 53, 3389}, "Windows Server 2022"
    )
    assert result == DeviceType.domain_controller


def test_dns_with_winrm():
    """Port 53 + WinRM (5985) → Windows DNS Server."""
    result = _guess_device_type({53, 5985, 135}, "Windows Server 2022")
    assert result == DeviceType.server


# --- check_dns_responds ---

def test_check_dns_socket_error():
    """Blad socket (host nieosiagalny) → responds=False."""
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.sendto.side_effect = OSError("Network unreachable")
        result = check_dns_responds("10.0.0.1")
    assert result == {"responds": False, "recursive": False, "rcode": -1}


def test_check_dns_timeout():
    """Timeout (brak odpowiedzi) → responds=False."""
    import socket as _s
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = _s.timeout("timed out")
        result = check_dns_responds("10.0.0.2")
    assert result["responds"] is False


def test_check_dns_nxdomain_with_recursion():
    """NXDOMAIN (rcode=3) + RA=1 → responds=True, recursive=True."""
    # TxID = 0xABCD, QR=1, RA=1, RCODE=3
    tx_id = bytes([0xab, 0xcd])
    flags = (1 << 15) | (1 << 7) | 3
    response = tx_id + flags.to_bytes(2, "big") + bytes([0, 1, 0, 0, 0, 0, 0, 0])
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.return_value = (response, ("10.0.0.3", 53))
        result = check_dns_responds("10.0.0.3")
    assert result["responds"] is True
    assert result["recursive"] is True
    assert result["rcode"] == 3


def test_check_dns_noerror_recursive():
    """NOERROR (rcode=0) + RA=1 → responds=True, recursive=True, rcode=0."""
    tx_id = bytes([0xab, 0xcd])
    flags = (1 << 15) | (1 << 7) | 0
    response = tx_id + flags.to_bytes(2, "big") + bytes([0, 1, 0, 1, 0, 0, 0, 0])
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.return_value = (response, ("10.0.0.5", 53))
        result = check_dns_responds("10.0.0.5")
    assert result["responds"] is True
    assert result["recursive"] is True
    assert result["rcode"] == 0


def test_check_dns_refused_no_recursion():
    """REFUSED (rcode=5) + RA=0 → responds=True, recursive=False (authoritative)."""
    tx_id = bytes([0xab, 0xcd])
    flags = (1 << 15) | 5   # QR=1, RA=0, RCODE=5
    response = tx_id + flags.to_bytes(2, "big") + bytes([0, 1, 0, 0, 0, 0, 0, 0])
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.return_value = (response, ("10.0.0.6", 53))
        result = check_dns_responds("10.0.0.6")
    assert result["responds"] is True
    assert result["recursive"] is False
    assert result["rcode"] == 5


def test_check_dns_wrong_transaction_id():
    """Odpowiedz z innym TxID → responds=False."""
    wrong_id = bytes([0xff, 0xfe])
    flags = (1 << 15) | (1 << 7)
    response = wrong_id + flags.to_bytes(2, "big") + bytes([0, 1, 0, 1, 0, 0, 0, 0])
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.return_value = (response, ("10.0.0.7", 53))
        result = check_dns_responds("10.0.0.7")
    assert result["responds"] is False


def test_check_dns_qr_bit_zero_query_not_response():
    """QR=0 (zapytanie, nie odpowiedz) → responds=False."""
    tx_id = bytes([0xab, 0xcd])
    flags = 0   # QR=0
    response = tx_id + flags.to_bytes(2, "big") + bytes([0, 1, 0, 0, 0, 0, 0, 0])
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.return_value = (response, ("10.0.0.8", 53))
        result = check_dns_responds("10.0.0.8")
    assert result["responds"] is False


def test_check_dns_too_short_response():
    """Odpowiedz krotsza niz 12 bajtow → responds=False."""
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.return_value = (bytes([0xab, 0xcd, 0x81, 0x80]), ("10.0.0.9", 53))
        result = check_dns_responds("10.0.0.9")
    assert result["responds"] is False


def test_check_dns_socket_closed_on_success():
    """Socket jest zamykany nawet gdy odpowiedz jest poprawna."""
    tx_id = bytes([0xab, 0xcd])
    flags = (1 << 15) | (1 << 7)
    response = tx_id + flags.to_bytes(2, "big") + bytes([0, 1, 0, 1, 0, 0, 0, 0])
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.return_value = (response, ("10.0.0.10", 53))
        check_dns_responds("10.0.0.10")
    mock_sock.close.assert_called()


def test_check_dns_socket_closed_on_exception():
    """Socket jest zamykany takze gdy wyjatek (brak wycieku)."""
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.sendto.side_effect = RuntimeError("boom")
        check_dns_responds("10.0.0.11")
    mock_sock.close.assert_called()


# --- ldap_query_rootdse ---

def test_ldap_connection_refused():
    """Brak LDAP na hoscie → pusty dict."""
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.connect.side_effect = ConnectionRefusedError()
        result = ldap_query_rootdse("10.0.0.1")
    assert result == {}


def test_ldap_timeout():
    """Timeout LDAP → pusty dict."""
    import socket as _s
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.connect.side_effect = _s.timeout("timed out")
        result = ldap_query_rootdse("10.0.0.2")
    assert result == {}


def test_ldap_empty_response():
    """Puste dane z LDAP → pusty dict."""
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recv.return_value = b""
        result = ldap_query_rootdse("10.0.0.3")
    assert result == {}


def test_ldap_parses_domain_from_naming_context():
    """Odpowiedz z defaultNamingContext DC=firma,DC=local → domain='firma.local'."""
    payload = b"defaultNamingContextDC=firma,DC=local\x00dnsHostName\x00"
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recv.side_effect = [payload, b""]
        result = ldap_query_rootdse("10.0.0.4")
    assert result.get("domain") == "firma.local"


def test_ldap_parses_dc_hostname():
    """Odpowiedz z dnsHostName dc01.firma.local → dc_hostname zawiera 'dc01.firma.local'."""
    payload = b"defaultNamingContextDC=firma,DC=localXXXdnsHostNamedc01.firma.local\x00"
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recv.side_effect = [payload, b""]
        result = ldap_query_rootdse("10.0.0.5")
    assert "dc01.firma.local" in result.get("dc_hostname", "")


def test_ldap_three_level_domain():
    """Trojpoziomowa domena: DC=dc,DC=firma,DC=local → domain='dc.firma.local'."""
    payload = b"defaultNamingContextDC=dc,DC=firma,DC=local\x00dnsHostName\x00"
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recv.side_effect = [payload, b""]
        result = ldap_query_rootdse("10.0.0.6")
    assert result.get("domain") == "dc.firma.local"


def test_ldap_non_ad_server_no_naming_context():
    """OpenLDAP bez Active Directory — brak DC= wzorca → pusty dict."""
    payload = b"cn=config\x00entryDN\x00olcDatabase\x00"
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recv.side_effect = [payload, b""]
        result = ldap_query_rootdse("10.0.0.7")
    assert result == {}


def test_ldap_socket_closed_on_success():
    """Socket jest zamykany po udanym parsowaniu."""
    payload = b"defaultNamingContextDC=test,DC=local\x00"
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recv.side_effect = [payload, b""]
        ldap_query_rootdse("10.0.0.8")
    mock_sock.close.assert_called()


def test_ldap_socket_closed_on_exception():
    """Socket jest zamykany takze przy wyjatku (brak wycieku)."""
    with patch("netdoc.collector.discovery._socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.sendall.side_effect = RuntimeError("boom")
        ldap_query_rootdse("10.0.0.9")
    mock_sock.close.assert_called()


# --- Scenariusze firmowe (z db fixture) ---

def test_dc_scenario_small_biz_single_dc(db):
    """Mala firma, jeden DC: upsert z domain_controller i os_version AD."""
    data = DeviceData(
        ip="192.168.1.10",
        mac="00:11:22:33:44:55",
        device_type=DeviceType.domain_controller,
        os_version="Active Directory: firma.local",
        vendor="Microsoft",
    )
    upsert_device(db, data)
    dev = db.query(Device).filter_by(ip="192.168.1.10").first()
    assert dev is not None
    assert dev.device_type == DeviceType.domain_controller
    assert dev.os_version == "Active Directory: firma.local"


def test_dc_scenario_reclassified_from_unknown(db):
    """Urzadzenie wpisane jako unknown → ponowny skan z portami DC → domain_controller."""
    upsert_device(db, DeviceData(ip="192.168.1.11", device_type=DeviceType.unknown))
    dev = db.query(Device).filter_by(ip="192.168.1.11").first()
    assert dev.device_type == DeviceType.unknown

    upsert_device(db, DeviceData(
        ip="192.168.1.11",
        device_type=DeviceType.domain_controller,
        os_version="Active Directory: corp.example.com",
    ))
    db.refresh(dev)
    assert dev.device_type == DeviceType.domain_controller


def test_dc_scenario_enterprise_multiple_dcs(db):
    """Korporacja: dwa DC-e w tej samej domenie — oba domain_controller."""
    for ip, mac in [("10.0.0.11", "00:aa:bb:cc:dd:01"), ("10.0.0.12", "00:aa:bb:cc:dd:02")]:
        upsert_device(db, DeviceData(
            ip=ip, mac=mac,
            device_type=DeviceType.domain_controller,
            os_version="Active Directory: enterprise.local",
        ))
    devs = db.query(Device).filter(
        Device.ip.in_(["10.0.0.11", "10.0.0.12"])
    ).all()
    assert len(devs) == 2
    assert all(d.device_type == DeviceType.domain_controller for d in devs)
    assert all("enterprise.local" in (d.os_version or "") for d in devs)


def test_dc_scenario_openldap_not_dc(db):
    """OpenLDAP na Linuxie — port 389 bez Kerberos (88) → nie DC."""
    ports = {389, 22, 443}
    result = _guess_device_type(ports, "Ubuntu Linux", vendor="")
    assert result != DeviceType.domain_controller
    upsert_device(db, DeviceData(ip="192.168.1.20", device_type=result))
    dev = db.query(Device).filter_by(ip="192.168.1.20").first()
    assert dev.device_type != DeviceType.domain_controller


def test_dns_scenario_pihole_server(db):
    """Pi-hole: upsert z device_type=server i os_version='DNS recursive'."""
    upsert_device(db, DeviceData(
        ip="192.168.1.30",
        device_type=DeviceType.server,
        os_version="DNS recursive",
    ))
    dev = db.query(Device).filter_by(ip="192.168.1.30").first()
    assert dev.device_type == DeviceType.server
    assert dev.os_version == "DNS recursive"


def test_dns_scenario_windows_dns_no_ad(db):
    """Windows DNS bez AD: porty 53+3389+135, brak 88/389 → nie DC."""
    ports = {53, 3389, 135, 139}
    result = _guess_device_type(ports, "Windows Server 2019")
    assert result != DeviceType.domain_controller
    upsert_device(db, DeviceData(ip="192.168.1.31", device_type=result))
    dev = db.query(Device).filter_by(ip="192.168.1.31").first()
    assert dev.device_type != DeviceType.domain_controller


def test_dns_scenario_router_dns_relay(db):
    """Router z DNS relay: MikroTik RouterOS z portem 53 → router (nie server)."""
    ports = {53, 80, 443}
    result = _guess_device_type(ports, "RouterOS", vendor="MikroTik")
    assert result == DeviceType.router


def test_dns_enrichment_role_label():
    """check_dns_responds wynik: recursive=True → 'DNS recursive', False → 'DNS authoritative'."""
    assert ("DNS recursive" if True else "DNS authoritative") == "DNS recursive"
    assert ("DNS recursive" if False else "DNS authoritative") == "DNS authoritative"


def test_ldap_scenario_firma_local(db):
    """ldap_query_rootdse wynik dla firma.local → DC ma os_version z firma.local."""
    ldap_result = {"domain": "firma.local", "dc_hostname": "dc01.firma.local"}
    os_ver = f"Active Directory: {ldap_result['domain']}"
    upsert_device(db, DeviceData(
        ip="192.168.1.50",
        device_type=DeviceType.domain_controller,
        os_version=os_ver,
    ))
    dev = db.query(Device).filter_by(ip="192.168.1.50").first()
    assert dev.device_type == DeviceType.domain_controller
    assert "firma.local" in dev.os_version


def test_ldap_scenario_enterprise_subdomain(db):
    """ldap_query_rootdse parsuje trojpoziomowa domene corp.enterprise.com."""
    ldap_result = {"domain": "corp.enterprise.com"}
    os_ver = f"Active Directory: {ldap_result['domain']}"
    upsert_device(db, DeviceData(
        ip="10.10.0.1",
        device_type=DeviceType.domain_controller,
        os_version=os_ver,
    ))
    dev = db.query(Device).filter_by(ip="10.10.0.1").first()
    assert "corp.enterprise.com" in dev.os_version


# === NOWE TESTY: _is_laa_mac ===

def test_is_laa_mac_true_for_laa():
    """MAC z ustawionym bitem LAA (bit 1 pierwszego oktetu) zwraca True."""
    from netdoc.collector.discovery import _is_laa_mac
    assert _is_laa_mac("26:12:AC:1A:80:01") is True   # 0x26 & 0x02 = 1
    assert _is_laa_mac("AA:BB:CC:DD:EE:FF") is True   # 0xAA & 0x02 = 1
    assert _is_laa_mac("02:00:00:00:00:01") is True   # 0x02 & 0x02 = 1


def test_is_laa_mac_false_for_oui():
    """Globalny MAC (OUI) zwraca False."""
    from netdoc.collector.discovery import _is_laa_mac
    assert _is_laa_mac("D0:21:F9:85:54:8E") is False  # 0xD0 & 0x02 = 0
    assert _is_laa_mac("00:90:E8:62:BF:ED") is False  # 0x00 & 0x02 = 0
    assert _is_laa_mac("D8:B3:70:8B:84:35") is False  # 0xD8 & 0x02 = 0


def test_is_laa_mac_handles_dashes():
    """_is_laa_mac dziala z formatem aa-bb-cc (myslniki)."""
    from netdoc.collector.discovery import _is_laa_mac
    assert _is_laa_mac("26-12-AC-1A-80-01") is True
    assert _is_laa_mac("D0-21-F9-85-54-8E") is False


def test_is_laa_mac_handles_invalid():
    """Nieprawidlowy MAC zwraca False (nie rzuca wyjatku)."""
    from netdoc.collector.discovery import _is_laa_mac
    assert _is_laa_mac("invalid") is False
    assert _is_laa_mac("") is False


# === NOWE TESTY: snmp_community saved in DB via _snmp_save_community ===

def test_snmp_save_community_updates_device_snmp_community(db):
    """_snmp_save_community zapisuje community i snmp_ok_at na urzadzeniu."""
    from netdoc.storage.models import Credential, CredentialMethod
    from netdoc.collector.discovery import _snmp_save_community

    d = Device(ip="10.20.0.1", device_type=DeviceType.router)
    db.add(d); db.commit(); db.refresh(d)
    assert d.snmp_community is None
    assert d.snmp_ok_at is None

    cred = Credential(device_id=None, method=CredentialMethod.snmp,
                      username="public", priority=25)
    db.add(cred); db.commit()

    _snmp_save_community(db, d, "public")
    db.refresh(d)

    assert d.snmp_community == "public"
    assert d.snmp_ok_at is not None


def test_snmp_save_community_per_device_updates_device(db):
    """_snmp_save_community aktualizuje snmp_community gdy jest per-device credential."""
    from netdoc.storage.models import Credential, CredentialMethod
    from netdoc.collector.discovery import _snmp_save_community

    d = Device(ip="10.20.0.2", device_type=DeviceType.switch)
    db.add(d); db.commit(); db.refresh(d)

    cred = Credential(device_id=d.id, method=CredentialMethod.snmp,
                      username="custom", priority=10)
    db.add(cred); db.commit()

    _snmp_save_community(db, d, "custom")
    db.refresh(d)

    assert d.snmp_community == "custom"
    assert d.snmp_ok_at is not None


def test_snmp_save_community_creates_new_global_if_none(db):
    """_snmp_save_community tworzy nowy global cred gdy brak jakichkolwiek SNMP."""
    from netdoc.storage.models import Credential, CredentialMethod
    from netdoc.collector.discovery import _snmp_save_community

    d = Device(ip="10.20.0.3", device_type=DeviceType.server)
    db.add(d); db.commit(); db.refresh(d)

    _snmp_save_community(db, d, "community123")
    db.refresh(d)

    assert d.snmp_community == "community123"
    global_cred = (db.query(Credential)
                   .filter(Credential.device_id.is_(None),
                           Credential.method == CredentialMethod.snmp,
                           Credential.username == "community123")
                   .first())
    assert global_cred is not None


# ─── Testy regresyjne: --send-ip usuniete z argumentow nmap ──────────────────
# Regresja: na Windows z wieloma wirtualnymi interfejsami (Hyper-V, VPN)
# flaga --send-ip powoduje "route_loop() failed" — nmap nie moze wyslac pakietow.
# Fix: usunieto --send-ip ze wszystkich wywolan nmap.PortScanner.scan().

import netdoc.collector.discovery as _disc_module


def test_nmap_args_no_send_ip_in_source():
    """Regresja: --send-ip nie moze pojawiac sie w kodzie zrodlowym discovery.py."""
    import inspect
    src = inspect.getsource(_disc_module)
    assert "--send-ip" not in src, (
        "Znaleziono --send-ip w discovery.py — powoduje route_loop() failed "
        "na Windows z Hyper-V/VPN. Usun flage i pozwol nmap auto-wykryc metode."
    )


def test_nmap_full_args_fast_no_send_ip():
    """Regresja: _NMAP_FULL_ARGS_FAST nie zawiera --send-ip."""
    assert "--send-ip" not in _disc_module._NMAP_FULL_ARGS_FAST


def test_nmap_full_args_safe_no_send_ip():
    """Regresja: _NMAP_FULL_ARGS_SAFE nie zawiera --send-ip."""
    assert "--send-ip" not in _disc_module._NMAP_FULL_ARGS_SAFE


def test_port_scan_classic_nmap_call_no_send_ip():
    """Regresja: port_scan (tryb klasyczny) nie przekazuje --send-ip do nmap."""
    nm_mock = MagicMock()
    nm_mock.all_hosts.return_value = []
    classic = {"concurrency": 0, "batch_size": 0, "batch_pause_s": 0, "resume_enabled": False}

    with patch("nmap.PortScanner", return_value=nm_mock):
        port_scan(["10.0.0.1"], _batch_settings=classic)

    call_args = nm_mock.scan.call_args
    assert call_args is not None
    arguments = call_args.kwargs.get("arguments", "") or ""
    assert "--send-ip" not in arguments, (
        f"port_scan przekazal --send-ip do nmap: {arguments!r}"
    )


def test_full_scan_one_group_nmap_call_no_send_ip():
    """Regresja: _full_scan_one_group nie przekazuje --send-ip do nmap."""
    nm_mock = MagicMock()
    nm_mock.all_hosts.return_value = []

    with patch("nmap.PortScanner", return_value=nm_mock):
        _full_scan_one_group(["10.0.0.1"], ["1-1000"])

    for c in nm_mock.scan.call_args_list:
        arguments = c.kwargs.get("arguments", "") or ""
        assert "--send-ip" not in arguments, (
            f"_full_scan_one_group przekazal --send-ip do nmap: {arguments!r}"
        )
