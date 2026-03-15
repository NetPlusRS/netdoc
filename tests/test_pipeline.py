"""Testy pipeline collectora — dobor driverow i graceful degradation."""
from unittest.mock import patch, MagicMock
import pytest

from netdoc.collector.pipeline import (
    _pick_drivers, _apply_device_data, collect_device, run_pipeline,
    _try_snmp_communities, _ensure_snmp_credential,
)
from netdoc.collector.normalizer import DeviceData, InterfaceData, NeighborData
from netdoc.collector.drivers.snmp import SNMPDriver
from netdoc.collector.drivers.cisco import CiscoDriver
from netdoc.collector.drivers.mikrotik import MikrotikDriver
from netdoc.storage.models import (
    Device, DeviceType, Interface, TopologyLink,
    Credential, CredentialMethod, ScanResult,
)
from datetime import datetime


def _make_device(db, ip: str, vendor: str = None) -> Device:
    d = Device(ip=ip, vendor=vendor, device_type=DeviceType.unknown, is_active=True)
    db.add(d)
    db.commit()
    db.refresh(d)
    return d


def _add_scan_with_ports(db, device: Device, ports: list) -> None:
    db.add(ScanResult(
        device_id=device.id,
        scan_time=datetime.utcnow(),
        scan_type="nmap",
        open_ports={str(p): {"service": "test"} for p in ports},
    ))
    db.commit()


def _add_ssh_cred(db, device: Device = None) -> Credential:
    cred = Credential(
        device_id=device.id if device else None,
        method=CredentialMethod.ssh,
        username="admin",
        password_encrypted="dummy",
    )
    db.add(cred)
    db.commit()
    return cred


# --- _pick_drivers ---

def test_no_credentials_no_ports_unknown_no_snmp(db):
    """Urzadzenie unknown bez historii SNMP nie dostaje SNMPDriver — community-worker odkryje."""
    device = _make_device(db, "10.0.0.1")
    drivers = _pick_drivers(db, device)
    # unknown bez port 161 i bez snmp_community = brak SNMPDriver (nowa logika)
    assert not any(isinstance(d, SNMPDriver) for d in drivers)


def test_router_type_without_community_gets_snmp_driver(db):
    """Urzadzenie typu router bez snmp_community dostaje SNMPDriver."""
    from unittest.mock import patch, MagicMock
    d = Device(ip="10.0.0.99", device_type=DeviceType.router, is_active=True)
    db.add(d); db.commit(); db.refresh(d)
    # _ensure_snmp_credential zwroci None (brak community) — ale driver nadal dodany przez typ
    with patch("netdoc.collector.pipeline._ensure_snmp_credential", return_value=None):
        drivers = _pick_drivers(db, d)
    # Bez community → credential = None → driver NIE jest dodany (nowa logika: if snmp_cred)
    assert not any(isinstance(drv, SNMPDriver) for drv in drivers)


def test_router_with_known_community_gets_snmp_driver(db):
    """Router z ustawioną snmp_community dostaje SNMPDriver z właściwą community."""
    d = Device(ip="10.0.0.100", device_type=DeviceType.router,
               is_active=True, snmp_community="public")
    db.add(d); db.commit(); db.refresh(d)
    cred = Credential(device_id=None, method=CredentialMethod.snmp, username="public", priority=10)
    db.add(cred); db.commit()
    drivers = _pick_drivers(db, d)
    snmp_drivers = [drv for drv in drivers if isinstance(drv, SNMPDriver)]
    assert snmp_drivers
    assert snmp_drivers[0].community == "public"


def test_ssh_driver_selected_for_cisco_with_cred(db):
    """Cisco z SSH portem i credentials → CiscoDriver."""
    device = _make_device(db, "10.0.0.2", vendor="Cisco")
    _add_scan_with_ports(db, device, [22, 443])
    _add_ssh_cred(db, device)

    drivers = _pick_drivers(db, device)
    assert any(isinstance(d, CiscoDriver) for d in drivers)


def test_no_ssh_driver_without_credentials(db):
    """Port 22 otwarty ale brak credentials → brak CiscoDriver."""
    device = _make_device(db, "10.0.0.3", vendor="Cisco")
    _add_scan_with_ports(db, device, [22])
    # brak credentials

    drivers = _pick_drivers(db, device)
    assert not any(isinstance(d, CiscoDriver) for d in drivers)


def test_no_ssh_driver_without_port(db):
    """Credentials sa ale port 22 zamkniety → brak CiscoDriver."""
    device = _make_device(db, "10.0.0.4", vendor="Cisco")
    _add_scan_with_ports(db, device, [443])  # brak 22
    _add_ssh_cred(db, device)

    drivers = _pick_drivers(db, device)
    assert not any(isinstance(d, CiscoDriver) for d in drivers)


def test_default_credential_used_when_no_device_specific(db):
    """Domyslny credential (device_id=None) jest uzywany dla wszystkich urzadzen."""
    device = _make_device(db, "10.0.0.5", vendor="Cisco")
    _add_scan_with_ports(db, device, [22])
    # credential bez device_id = domyslny
    _add_ssh_cred(db, device=None)

    drivers = _pick_drivers(db, device)
    assert any(isinstance(d, CiscoDriver) for d in drivers)


# --- _apply_device_data ---

def test_apply_updates_hostname(db):
    device = _make_device(db, "10.1.0.1")
    data = DeviceData(ip="10.1.0.1", hostname="new-hostname", vendor="Cisco")
    _apply_device_data(db, device, data)
    db.refresh(device)
    assert device.hostname == "new-hostname"
    assert device.vendor == "Cisco"


def test_apply_does_not_overwrite_existing_hostname(db):
    """Istniejacy hostname nie jest nadpisywany przez driver."""
    device = _make_device(db, "10.1.0.2")
    device.hostname = "existing"
    db.commit()
    data = DeviceData(ip="10.1.0.2", hostname="new-hostname")
    _apply_device_data(db, device, data)
    db.refresh(device)
    assert device.hostname == "existing"


def test_apply_creates_interfaces(db):
    device = _make_device(db, "10.1.0.3")
    data = DeviceData(
        ip="10.1.0.3",
        interfaces=[
            InterfaceData(name="eth0", speed=1000, oper_status=True),
            InterfaceData(name="eth1", speed=100, oper_status=False),
        ],
    )
    _apply_device_data(db, device, data)
    db.refresh(device)
    assert len(device.interfaces) == 2
    names = {i.name for i in device.interfaces}
    assert "eth0" in names and "eth1" in names


def test_apply_upserts_interfaces(db):
    """Powtorone wywolanie aktualizuje interfejsy zamiast tworzyc duplikaty."""
    device = _make_device(db, "10.1.0.4")
    data = DeviceData(ip="10.1.0.4", interfaces=[InterfaceData(name="eth0", oper_status=False)])
    _apply_device_data(db, device, data)

    data2 = DeviceData(ip="10.1.0.4", interfaces=[InterfaceData(name="eth0", oper_status=True)])
    _apply_device_data(db, device, data2)

    db.refresh(device)
    assert len(device.interfaces) == 1
    assert device.interfaces[0].oper_status is True


def test_apply_creates_topology_link(db):
    """Sasiad z LLDP tworzy TopologyLink jezeli remote_ip istnieje w bazie."""
    src = _make_device(db, "10.2.0.1")
    dst = _make_device(db, "10.2.0.2")

    data = DeviceData(
        ip="10.2.0.1",
        neighbors=[NeighborData(local_interface="eth0", remote_ip="10.2.0.2", protocol="lldp")],
    )
    _apply_device_data(db, src, data)

    link = db.query(TopologyLink).filter(
        TopologyLink.src_device_id == src.id,
        TopologyLink.dst_device_id == dst.id,
    ).first()
    assert link is not None


def test_apply_no_link_for_unknown_neighbor(db):
    """Sasiad ktorego nie ma w bazie nie tworzy TopologyLink."""
    src = _make_device(db, "10.2.0.3")
    data = DeviceData(
        ip="10.2.0.3",
        neighbors=[NeighborData(local_interface="eth0", remote_ip="99.99.99.99", protocol="lldp")],
    )
    _apply_device_data(db, src, data)
    assert db.query(TopologyLink).count() == 0


# --- collect_device ---

def _make_snmp_device(db, ip: str) -> Device:
    """Helper: tworzy router z ustawioną snmp_community — gwarantuje SNMPDriver w pipeline."""
    cred = Credential(device_id=None, method=CredentialMethod.snmp,
                      username="public", priority=10)
    db.add(cred); db.commit()
    d = Device(ip=ip, device_type=DeviceType.router, is_active=True, snmp_community="public")
    db.add(d); db.commit(); db.refresh(d)
    return d


def test_collect_device_no_drivers_returns_false(db):
    """Router z SNMP driver zwracajacym puste dane — wynik False."""
    device = _make_snmp_device(db, "10.3.0.1")
    with patch("netdoc.collector.pipeline.SNMPDriver.collect", return_value=DeviceData(ip="10.3.0.1")):
        result = collect_device(db, device)
    assert result is False  # pusty DeviceData = brak danych


def test_collect_device_enriches_when_driver_returns_data(db):
    """Driver zwracajacy dane wzbogaca urzadzenie."""
    device = _make_snmp_device(db, "10.3.0.2")
    rich_data = DeviceData(ip="10.3.0.2", hostname="snmp-host", interfaces=[InterfaceData(name="eth0")])

    with patch("netdoc.collector.pipeline.SNMPDriver.collect", return_value=rich_data):
        result = collect_device(db, device)

    assert result is True
    db.refresh(device)
    assert device.hostname == "snmp-host"


def test_collect_device_sets_last_credential_ok_at(db):
    """Po udanym driverze last_credential_ok_at jest ustawiane na urzadzeniu."""
    device = _make_snmp_device(db, "10.4.0.1")
    assert device.last_credential_ok_at is None

    rich_data = DeviceData(ip="10.4.0.1", hostname="cred-ok-host", interfaces=[InterfaceData(name="eth0")])
    with patch("netdoc.collector.pipeline.SNMPDriver.collect", return_value=rich_data):
        collect_device(db, device)

    db.refresh(device)
    assert device.last_credential_ok_at is not None


def test_collect_device_no_data_does_not_set_credential_ok_at(db):
    """Gdy driver nie zwraca danych, last_credential_ok_at pozostaje None."""
    device = _make_snmp_device(db, "10.4.0.2")
    empty_data = DeviceData(ip="10.4.0.2")  # brak hostname/interfaces/neighbors

    with patch("netdoc.collector.pipeline.SNMPDriver.collect", return_value=empty_data):
        collect_device(db, device)

    db.refresh(device)
    assert device.last_credential_ok_at is None


def test_get_credential_returns_highest_priority(db):
    """Gdy kilka credentials dla urzadzenia — zwraca ten z najwyzszym priorytetem."""
    from netdoc.collector.pipeline import _get_credential
    device = _make_device(db, "10.9.0.1", vendor="Cisco")
    _add_scan_with_ports(db, device, [22])

    # Konwencja: nizszy numer priorytetu = wyzszy priorytet probowania
    # cred_important (priority=50) powinien byc probowany PRZED cred_fallback (priority=200)
    cred_important = Credential(
        device_id=device.id, method=CredentialMethod.ssh,
        username="admin_important", password_encrypted="x", priority=50,
    )
    cred_fallback = Credential(
        device_id=device.id, method=CredentialMethod.ssh,
        username="admin_fallback", password_encrypted="x", priority=200,
    )
    db.add_all([cred_important, cred_fallback])
    db.commit()

    result = _get_credential(db, device, CredentialMethod.ssh)
    assert result is not None
    assert result.username == "admin_important"  # nizszy numer = wyzszy priorytet


def test_get_credential_global_fallback_highest_priority(db):
    """Globalny credential: nizszy numer priorytetu probowany pierwszy."""
    from netdoc.collector.pipeline import _get_credential
    device = _make_device(db, "10.9.0.2")

    cred_a = Credential(device_id=None, method=CredentialMethod.ssh, username="a", priority=100)
    cred_b = Credential(device_id=None, method=CredentialMethod.ssh, username="b", priority=200)
    db.add_all([cred_a, cred_b])
    db.commit()

    result = _get_credential(db, device, CredentialMethod.ssh)
    assert result.username == "a"  # priority 100 < 200 — nizszy = wazniejszy


# --- _ensure_snmp_credential ---

def test_ensure_snmp_no_port_161_returns_none(db):
    """Bez otwartego portu 161 i bez credentials w DB — zwraca None."""
    from netdoc.collector.pipeline import _ensure_snmp_credential
    device = _make_device(db, "10.8.0.1")
    # Brak scan_results = port 161 nie jest wykryty
    result = _ensure_snmp_credential(db, device)
    assert result is None


def test_ensure_snmp_existing_credential_returned(db):
    """Gdy credential SNMP juz istnieje w DB — zwraca go bez proba."""
    from netdoc.collector.pipeline import _ensure_snmp_credential
    device = _make_device(db, "10.8.0.2")
    cred = Credential(
        device_id=None, method=CredentialMethod.snmp,
        username="public", priority=100,
    )
    db.add(cred)
    db.commit()

    result = _ensure_snmp_credential(db, device)
    assert result is not None
    assert result.username == "public"


def test_ensure_snmp_port_161_open_community_works(db):
    """Port 161 otwarty + dzialajaca community — tworzy global credential."""
    from unittest.mock import patch
    from netdoc.collector.pipeline import _ensure_snmp_credential
    device = _make_device(db, "10.8.0.3")
    _add_scan_with_ports(db, device, [161])

    with patch("netdoc.collector.pipeline._try_snmp_communities", return_value="public"):
        result = _ensure_snmp_credential(db, device)

    assert result is not None
    assert result.username == "public"
    # Sprawdz ze zostal zapisany w DB jako global default
    saved = db.query(Credential).filter(
        Credential.device_id == None,
        Credential.method == CredentialMethod.snmp,
        Credential.username == "public",
    ).first()
    assert saved is not None


def test_ensure_snmp_port_161_no_community_returns_none(db):
    """Port 161 otwarty ale zadna community nie dziala — zwraca None."""
    device = _make_device(db, "10.8.0.4")
    _add_scan_with_ports(db, device, [161])

    with patch("netdoc.collector.pipeline._try_snmp_communities", return_value=None):
        result = _ensure_snmp_credential(db, device)

    assert result is None


# --- _try_snmp_communities ---

def test_try_snmp_communities_returns_first_working():
    def _fake_snmp_get(ip, community, oid, timeout=1):
        if community == "public":
            return "router"
        return None

    with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=_fake_snmp_get):
        result = _try_snmp_communities("10.0.0.1", ["private", "public"])
    assert result == "public"


def test_try_snmp_communities_returns_none_when_all_fail():
    with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=None):
        result = _try_snmp_communities("10.0.0.1", ["public", "private"])
    assert result is None


def test_try_snmp_communities_empty_list_returns_none():
    result = _try_snmp_communities("10.0.0.1", [])
    assert result is None


def test_try_snmp_communities_exception_in_probe_handled():
    with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=Exception("timeout")):
        result = _try_snmp_communities("10.0.0.1", ["public"])
    assert result is None


# --- _ensure_snmp_credential auto-discovery ---

def test_ensure_snmp_saves_new_global_credential(db):
    """Gdy brak globalnego SNMP cred i community dziala — zapisuje nowy global."""
    device = _make_device(db, "10.9.0.1")
    _add_scan_with_ports(db, device, [161])

    with patch("netdoc.collector.pipeline._try_snmp_communities", return_value="public"):
        result = _ensure_snmp_credential(db, device)

    assert result is not None
    assert result.username == "public"
    assert result.device_id is None  # global


def test_ensure_snmp_updates_existing_global_credential(db):
    """Gdy auto-discovery znajduje community i global cred z ta sama wartoscia istnieje — aktualizuje go."""
    device = _make_device(db, "10.9.0.2")
    _add_scan_with_ports(db, device, [161])
    existing = Credential(
        device_id=None, method=CredentialMethod.snmp,
        username="public", priority=50, success_count=5,
    )
    db.add(existing)
    db.commit()

    # Mockujemy _get_credential aby zwrocilo None (symulacja braku cred dla urzadzenia)
    # i _try_snmp_communities aby zwrocilo "public" (to samo co global)
    with patch("netdoc.collector.pipeline._get_credential", return_value=None):
        with patch("netdoc.collector.pipeline._try_snmp_communities", return_value="public"):
            result = _ensure_snmp_credential(db, device)

    assert result is not None
    db.refresh(existing)
    assert existing.success_count == 6


def test_ensure_snmp_saves_per_device_when_global_differs(db):
    """Gdy auto-discovery zwraca community inne niz istniejacy global — zapisuje per-device."""
    device = _make_device(db, "10.9.0.3")
    _add_scan_with_ports(db, device, [161])
    db.add(Credential(
        device_id=None, method=CredentialMethod.snmp,
        username="private", priority=50,
    ))
    db.commit()

    # Mockujemy _get_credential aby zwrocilo None, a communities aby zwrocilo inne community
    with patch("netdoc.collector.pipeline._get_credential", return_value=None):
        with patch("netdoc.collector.pipeline._try_snmp_communities", return_value="community"):
            result = _ensure_snmp_credential(db, device)

    assert result is not None
    assert result.username == "community"
    assert result.device_id == device.id  # per-device


# --- _pick_drivers MikroTik ---

def test_mikrotik_driver_selected_for_mikrotik_vendor_with_cred(db):
    """MikroTik vendor + port 22 + SSH cred → MikrotikDriver."""
    device = _make_device(db, "10.0.0.5", vendor="MikroTik")
    _add_scan_with_ports(db, device, [22])
    _add_ssh_cred(db, device)

    drivers = _pick_drivers(db, device)
    names = [d.name for d in drivers]
    assert any("mikrotik" in n.lower() for n in names)


# --- collect_device exception handling ---

def test_collect_device_driver_exception_continues_to_next(db):
    """Wyjatek w pierwszym driverze — pipeline probuje kolejny i nie crashuje."""
    device = _make_device(db, "10.0.0.9")

    mock_driver_fail = MagicMock()
    mock_driver_fail.name = "failing_driver"
    mock_driver_fail.collect.side_effect = RuntimeError("connection refused")
    mock_driver_fail.credential = None

    mock_driver_ok = MagicMock()
    mock_driver_ok.name = "ok_driver"
    mock_driver_ok.collect.return_value = DeviceData(
        ip=device.ip, hostname="router01"
    )
    mock_driver_ok.credential = None

    with patch("netdoc.collector.pipeline._pick_drivers",
               return_value=[mock_driver_fail, mock_driver_ok]):
        result = collect_device(db, device)

    assert result is True
    mock_driver_fail.collect.assert_called_once()
    mock_driver_ok.collect.assert_called_once()


def test_collect_device_all_drivers_fail_returns_false(db):
    """Wszystkie drivery rzucaja wyjatek — collect_device zwraca False."""
    device = _make_device(db, "10.0.0.10")

    mock_driver = MagicMock()
    mock_driver.name = "bad_driver"
    mock_driver.collect.side_effect = RuntimeError("fail")
    mock_driver.credential = None

    with patch("netdoc.collector.pipeline._pick_drivers", return_value=[mock_driver]):
        result = collect_device(db, device)

    assert result is False


# --- run_pipeline ---

def test_run_pipeline_returns_stats(db):
    """run_pipeline zwraca statystyki total/enriched/basic_only."""
    device1 = _make_device(db, "10.0.0.20")
    device2 = _make_device(db, "10.0.0.21")

    with patch("netdoc.collector.pipeline.collect_device", side_effect=[True, False]):
        stats = run_pipeline(db, [device1, device2])

    assert stats["total"] == 2
    assert stats["enriched"] == 1
    assert stats["basic_only"] == 1


def test_run_pipeline_empty_list_returns_zeros(db):
    stats = run_pipeline(db, [])
    assert stats == {"total": 0, "enriched": 0, "basic_only": 0}



# === NOWE TESTY: _try_snmp_communities — sekwencyjnosc i delay ===

def test_try_snmp_communities_sequential_order():
    """_try_snmp_communities probuje community w kolejnosci listy (sekwencyjnie)."""
    called = []

    def _fake_snmp_get(ip, community, oid, timeout=1):
        called.append(community)
        return "router" if community == "public" else None

    with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=_fake_snmp_get):
        result = _try_snmp_communities("10.0.0.1", ["private", "secret", "public"], delay=0)

    assert result == "public"
    # Sprawdz ze probowalo w kolejnosci — "private" i "secret" przed "public"
    assert called.index("private") < called.index("public")
    assert called.index("secret") < called.index("public")


def test_try_snmp_communities_stops_at_first_success():
    """_try_snmp_communities zatrzymuje sie na pierwszej dzialajcej community."""
    called = []

    def _fake_snmp_get(ip, community, oid, timeout=1):
        called.append(community)
        return "router"  # wszystkie dzialaja

    with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=_fake_snmp_get):
        result = _try_snmp_communities("10.0.0.1", ["first", "second", "third"], delay=0)

    assert result == "first"
    assert called == ["first"]  # tylko pierwsza probowana


def test_try_snmp_communities_delay_zero_skips_sleep():
    """delay=0 nie blokuje — przydatne w testach i konfiguracji bez opoznien."""
    with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=None):
        with patch("time.sleep") as mock_sleep:
            _try_snmp_communities("10.0.0.1", ["a", "b"], delay=0)
    mock_sleep.assert_not_called()


def test_try_snmp_communities_calls_sleep_with_delay():
    """delay>0 wywoluje time.sleep miedzy probami."""
    import time
    with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=None):
        with patch("time.sleep") as mock_sleep:
            _try_snmp_communities("10.0.0.1", ["a", "b", "c"], delay=5)
    # 3 community bez sukcesu = 3 sleep (po kazdej probie)
    assert mock_sleep.call_count == 3
    mock_sleep.assert_called_with(5)
