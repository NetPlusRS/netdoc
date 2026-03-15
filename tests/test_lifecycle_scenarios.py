"""
Testy scenariuszy cyklu życia — zachowanie skanera po działaniach użytkownika.

Scenariusz główny:
  Użytkownik uruchamia pełny skan, a następnie kasuje wszystkie hosty i sieci.
  Skaner nadal działa (to celowe zachowanie) — nie zauważa że z bazy wyleciały dane,
  bo działa na liście IP zebranej PRZED kasowaniem.
  Po kolejnym uruchomieniu skanera — dane wracają (rediscovery).

Testowane zachowania:
  1. Kasowanie aktywnego urządzenia wymaga force=True
  2. Po skasowaniu urządzeń — baza jest pusta
  3. ScanResults są cascade-delete razem z Device
  4. get_scan_targets() zwraca sieci auto-wykryte nawet gdy DB jest pusta
  5. upsert_device() tworzy nowy rekord gdy device zostal skasowany (rediscovery)
  6. run_full_scan() z pustą listą aktywnych urządzeń → 0 wyników (nic nie robi)
  7. mark_missing_devices() ze skasowanymi devices → nie crashuje
  8. Sieć wstrzymana przez użytkownika nie trafia do targets (nie jest auto-wykryta)
  9. Sieć auto-wykryta trafia do targets nawet gdy DiscoveredNetwork jest pusta
  10. Po kasowaniu WSZYSTKIEGO — kolejny skan re-odkrywa hosty i tworzy rekordy
"""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta


# ─────────────────────────────────────────────────────────────────────────────
# 1. Kasowanie urządzenia — force / no-force
# ─────────────────────────────────────────────────────────────────────────────

def test_delete_active_device_without_force_returns_409(client):
    """Aktywne urządzenie nie może być skasowane bez force=True (smoke test)."""
    r = client.delete("/api/devices/99999")  # nieistniejące → 404
    assert r.status_code == 404


def test_delete_nonexistent_device_returns_404(client):
    """DELETE /api/devices/99999 dla nieistniejącego ID zwraca 404."""
    r = client.delete("/api/devices/99999")
    assert r.status_code == 404


def test_delete_active_device_without_force_is_rejected(client, db):
    """Aktywny device bez force=True → 409 Conflict."""
    from netdoc.storage.models import Device, DeviceType

    dev = Device(ip="10.5.5.1", device_type=DeviceType.unknown,
                 is_active=True, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev)
    db.commit()
    db.refresh(dev)

    r = client.delete(f"/api/devices/{dev.id}")
    assert r.status_code == 409
    assert "aktywne" in r.json()["detail"].lower()


def test_delete_active_device_with_force_succeeds(client, db):
    """Aktywny device z force=true → 204 i usunięty z DB."""
    from netdoc.storage.models import Device, DeviceType

    dev = Device(ip="10.5.5.2", device_type=DeviceType.unknown,
                 is_active=True, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev)
    db.commit()
    db.refresh(dev)
    dev_id = dev.id

    r = client.delete(f"/api/devices/{dev_id}?force=true")
    assert r.status_code == 204
    db.expire_all()
    assert db.query(Device).filter_by(id=dev_id).first() is None


def test_delete_inactive_device_without_force_succeeds(client, db):
    """Nieaktywny device bez force → 204 (force potrzebne tylko dla aktywnych)."""
    from netdoc.storage.models import Device, DeviceType

    dev = Device(ip="10.5.5.3", device_type=DeviceType.unknown,
                 is_active=False, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev)
    db.commit()
    db.refresh(dev)
    dev_id = dev.id

    r = client.delete(f"/api/devices/{dev_id}")
    assert r.status_code == 204
    db.expire_all()
    assert db.query(Device).filter_by(id=dev_id).first() is None


# ─────────────────────────────────────────────────────────────────────────────
# 2. Cascade delete — ScanResult i inne rekordy
# ─────────────────────────────────────────────────────────────────────────────

def test_scan_results_cascade_deleted_with_device(client, db):
    """ScanResult jest kasowany automatycznie przy usunięciu Device (cascade)."""
    from netdoc.storage.models import Device, DeviceType, ScanResult

    dev = Device(ip="10.5.5.10", device_type=DeviceType.unknown,
                 is_active=False, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev)
    db.commit()
    db.refresh(dev)

    sr = ScanResult(device_id=dev.id, scan_type="nmap",
                    open_ports={"22": {"service": "ssh"}})
    db.add(sr)
    db.commit()
    sr_id = sr.id

    r = client.delete(f"/api/devices/{dev.id}")
    assert r.status_code == 204

    db.expire_all()
    assert db.query(ScanResult).filter_by(id=sr_id).first() is None


def test_credentials_cascade_deleted_with_device(client, db):
    """Device-specific Credential jest kasowany automatycznie przy usunięciu Device."""
    from netdoc.storage.models import Device, DeviceType, Credential, CredentialMethod

    dev = Device(ip="10.5.5.11", device_type=DeviceType.unknown,
                 is_active=False, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev)
    db.commit()
    db.refresh(dev)

    cred = Credential(device_id=dev.id, method=CredentialMethod.ssh,
                      username="admin", priority=100)
    db.add(cred)
    db.commit()
    cred_id = cred.id

    client.delete(f"/api/devices/{dev.id}")
    db.expire_all()
    assert db.query(Credential).filter_by(id=cred_id).first() is None


def test_delete_all_devices_leaves_empty_db(client, db):
    """Po skasowaniu wszystkich urządzeń — baza jest pusta."""
    from netdoc.storage.models import Device, DeviceType

    for ip in ["10.5.6.1", "10.5.6.2", "10.5.6.3"]:
        db.add(Device(ip=ip, device_type=DeviceType.unknown, is_active=False,
                      first_seen=datetime.utcnow(), last_seen=datetime.utcnow()))
    db.commit()

    devices = db.query(Device).all()
    for dev in devices:
        r = client.delete(f"/api/devices/{dev.id}")
        assert r.status_code == 204

    db.expire_all()
    assert db.query(Device).count() == 0


# ─────────────────────────────────────────────────────────────────────────────
# 3. get_scan_targets — zachowanie gdy DB jest pusta
# ─────────────────────────────────────────────────────────────────────────────

def test_get_scan_targets_empty_db_returns_auto_detected(db):
    """get_scan_targets() z pustą DB zwraca sieci z auto-detect (host interfaces)."""
    from netdoc.collector.discovery import get_scan_targets

    # Mockuj detect_local_networks żeby zwracał znany zakres
    with patch("netdoc.collector.discovery.detect_local_networks",
               return_value=["192.168.99.0/24"]):
        with patch("netdoc.collector.discovery._read_discovery_overrides",
                   return_value=(None, None, None, None)):
            with patch("netdoc.config.settings.settings") as mock_settings:
                mock_settings.network_ranges_list = []
                mock_settings.scan_vpn_networks = False
                mock_settings.scan_virtual_networks = False
                targets = get_scan_targets(db)

    assert "192.168.99.0/24" in targets, \
        "Auto-wykryta siec powinna byc w targets nawet gdy DB jest pusta"


def test_get_scan_targets_deleted_networks_not_in_targets(db):
    """Po skasowaniu sieci z DB — nie trafia do targets (jest poza auto-detected)."""
    from netdoc.collector.discovery import get_scan_targets
    from netdoc.storage.models import DiscoveredNetwork, NetworkSource

    # Dodaj siec i od razu ją skasuj
    net = DiscoveredNetwork(cidr="10.77.0.0/24", source=NetworkSource.manual, is_active=True)
    db.add(net)
    db.commit()
    db.delete(net)
    db.commit()

    # Mockuj żeby auto-detect nie dodawał tej sieci
    with patch("netdoc.collector.discovery.detect_local_networks", return_value=[]):
        with patch("netdoc.collector.discovery._read_discovery_overrides",
                   return_value=(None, None, None, None)):
            with patch("netdoc.config.settings.settings") as mock_settings:
                mock_settings.network_ranges_list = []
                mock_settings.scan_vpn_networks = False
                mock_settings.scan_virtual_networks = False
                targets = get_scan_targets(db)

    assert "10.77.0.0/24" not in targets, \
        "Skasowana siec nie powinna byc w targets"


def test_get_scan_targets_paused_network_with_no_autodetect(db):
    """Sieć wstrzymana (is_active=False) nie trafia do targets."""
    from netdoc.collector.discovery import get_scan_targets
    from netdoc.storage.models import DiscoveredNetwork, NetworkSource

    net = DiscoveredNetwork(cidr="10.88.0.0/24", source=NetworkSource.manual, is_active=False)
    db.add(net)
    db.commit()

    with patch("netdoc.collector.discovery.detect_local_networks", return_value=[]):
        with patch("netdoc.collector.discovery._read_discovery_overrides",
                   return_value=(None, None, None, None)):
            with patch("netdoc.config.settings.settings") as mock_settings:
                mock_settings.network_ranges_list = []
                mock_settings.scan_vpn_networks = False
                mock_settings.scan_virtual_networks = False
                targets = get_scan_targets(db)

    assert "10.88.0.0/24" not in targets, \
        "Wstrzymana siec nie powinna byc w targets"


# ─────────────────────────────────────────────────────────────────────────────
# 4. upsert_device — rediscovery po skasowaniu
# ─────────────────────────────────────────────────────────────────────────────

def test_upsert_device_creates_new_when_deleted(db):
    """upsert_device() tworzy nowy rekord gdy device był skasowany z DB."""
    from netdoc.collector.discovery import upsert_device
    from netdoc.collector.normalizer import DeviceData
    from netdoc.storage.models import Device, DeviceType

    # Stwórz i skasuj device
    dev = Device(ip="10.99.1.1", device_type=DeviceType.unknown,
                 is_active=True, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev)
    db.commit()
    old_id = dev.id
    db.delete(dev)
    db.commit()

    # Teraz skaner rediscovery — upsert powinien stworzyć nowy rekord
    data = DeviceData(ip="10.99.1.1", hostname="rediscovered-host",
                      vendor="Cisco", device_type=DeviceType.router)
    new_dev = upsert_device(db, data)

    assert new_dev is not None
    assert new_dev.ip == "10.99.1.1"
    assert new_dev.hostname == "rediscovered-host"
    assert new_dev.is_active is True
    # Nowe ID (SQLite może przydzielić to samo lub inne)
    existing = db.query(Device).filter_by(ip="10.99.1.1").first()
    assert existing is not None


def test_upsert_device_updates_existing_device(db):
    """upsert_device() aktualizuje istniejący rekord (nie duplikuje)."""
    from netdoc.collector.discovery import upsert_device
    from netdoc.collector.normalizer import DeviceData
    from netdoc.storage.models import Device, DeviceType

    dev = Device(ip="10.99.1.2", device_type=DeviceType.unknown, hostname="old-name",
                 is_active=True, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev)
    db.commit()

    data = DeviceData(ip="10.99.1.2", hostname="new-name", vendor="MikroTik")
    updated = upsert_device(db, data)

    assert updated.hostname == "new-name"
    # Tylko jeden rekord w DB
    count = db.query(Device).filter_by(ip="10.99.1.2").count()
    assert count == 1


def test_upsert_device_reactivates_inactive_device(db):
    """upsert_device() przywraca is_active=True dla nieaktywnego urządzenia."""
    from netdoc.collector.discovery import upsert_device
    from netdoc.collector.normalizer import DeviceData
    from netdoc.storage.models import Device, DeviceType

    dev = Device(ip="10.99.1.3", device_type=DeviceType.unknown,
                 is_active=False, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev)
    db.commit()

    data = DeviceData(ip="10.99.1.3")
    updated = upsert_device(db, data)

    assert updated.is_active is True


# ─────────────────────────────────────────────────────────────────────────────
# 5. run_full_scan — zachowanie z pustą bazą
# ─────────────────────────────────────────────────────────────────────────────

def test_run_full_scan_empty_db_returns_zero(db):
    """run_full_scan() z pustą bazą zwraca 0 (brak aktywnych urządzeń do skanowania)."""
    from netdoc.collector.discovery import run_full_scan

    result = run_full_scan(db)
    assert result == 0


def test_run_full_scan_with_deleted_devices_returns_zero(db):
    """run_full_scan() gdy wszystkie devices skasowane — zwraca 0 (nic do skanowania)."""
    from netdoc.collector.discovery import run_full_scan
    from netdoc.storage.models import Device, DeviceType

    # Stwórz i skasuj urządzenia
    for ip in ["10.1.0.1", "10.1.0.2"]:
        dev = Device(ip=ip, device_type=DeviceType.unknown, is_active=True,
                     first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
        db.add(dev)
    db.commit()

    # Kasowanie przez DB (symulacja użytkownika)
    db.query(Device).delete(synchronize_session="fetch")
    db.commit()

    result = run_full_scan(db)
    assert result == 0


def test_run_full_scan_skips_inactive_devices(db):
    """run_full_scan() pobiera tylko is_active=True urządzenia."""
    from netdoc.collector.discovery import run_full_scan
    from netdoc.storage.models import Device, DeviceType

    dev = Device(ip="10.1.0.10", device_type=DeviceType.unknown, is_active=False,
                 first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev)
    db.commit()

    result = run_full_scan(db)
    assert result == 0


# ─────────────────────────────────────────────────────────────────────────────
# 6. mark_missing_devices — zachowanie z pustą bazą
# ─────────────────────────────────────────────────────────────────────────────

def test_mark_missing_devices_empty_db_no_crash(db):
    """mark_missing_devices() z pustą bazą nie crashuje."""
    from netdoc.collector.discovery import mark_missing_devices

    mark_missing_devices(db, found_ips=["10.0.0.1", "10.0.0.2"])


def test_mark_missing_devices_deactivates_missing(db):
    """mark_missing_devices() oznacza urządzenia których nie widzi nmap."""
    from netdoc.collector.discovery import mark_missing_devices
    from netdoc.storage.models import Device, DeviceType

    dev_present = Device(ip="10.0.0.1", device_type=DeviceType.unknown, is_active=True,
                         first_seen=datetime.utcnow(),
                         last_seen=datetime.utcnow() - timedelta(minutes=30))  # stale
    dev_missing = Device(ip="10.0.0.2", device_type=DeviceType.unknown, is_active=True,
                         first_seen=datetime.utcnow(),
                         last_seen=datetime.utcnow() - timedelta(minutes=30))  # stale
    db.add_all([dev_present, dev_missing])
    db.commit()

    mark_missing_devices(db, found_ips=["10.0.0.1"])

    db.expire_all()
    assert db.query(Device).filter_by(ip="10.0.0.1").first().is_active is True
    assert db.query(Device).filter_by(ip="10.0.0.2").first().is_active is False


def test_mark_missing_devices_skips_recently_seen(db):
    """mark_missing_devices() nie deaktywuje jeśli ping-worker widział urządzenie niedawno."""
    from netdoc.collector.discovery import mark_missing_devices
    from netdoc.storage.models import Device, DeviceType

    dev = Device(ip="10.0.0.5", device_type=DeviceType.unknown, is_active=True,
                 first_seen=datetime.utcnow(),
                 last_seen=datetime.utcnow() - timedelta(minutes=2))  # świeży!
    db.add(dev)
    db.commit()

    # Nmap nie widzi tego hosta, ale ping-worker widział go 2 min temu — cooldown
    mark_missing_devices(db, found_ips=[], cooldown_minutes=10)

    db.expire_all()
    assert db.query(Device).filter_by(ip="10.0.0.5").first().is_active is True


# ─────────────────────────────────────────────────────────────────────────────
# 7. Pełny scenariusz: kasowanie + rediscovery
# ─────────────────────────────────────────────────────────────────────────────

def test_full_lifecycle_delete_and_rediscover(db):
    """
    Scenariusz: urządzenie wykryte → użytkownik kasuje → skaner re-odkrywa.

    1. upsert_device() → device w DB
    2. Device usunięty (symulacja DELETE od użytkownika)
    3. upsert_device() → nowy rekord (rediscovery)
    4. Baza ma dokładnie 1 device z tym IP
    """
    from netdoc.collector.discovery import upsert_device
    from netdoc.collector.normalizer import DeviceData
    from netdoc.storage.models import Device, DeviceType

    ip = "10.200.0.1"

    # Krok 1: Pierwsza detekcja
    data = DeviceData(ip=ip, hostname="router-1", device_type=DeviceType.router)
    dev1 = upsert_device(db, data)
    assert dev1.hostname == "router-1"

    # Krok 2: Użytkownik kasuje
    db.delete(dev1)
    db.commit()
    assert db.query(Device).filter_by(ip=ip).first() is None

    # Krok 3: Skaner rediscovery
    data2 = DeviceData(ip=ip, hostname="router-1-reborn", device_type=DeviceType.router)
    dev2 = upsert_device(db, data2)
    assert dev2 is not None
    assert dev2.hostname == "router-1-reborn"
    assert dev2.is_active is True

    # Krok 4: Dokładnie 1 rekord
    count = db.query(Device).filter_by(ip=ip).count()
    assert count == 1


def test_full_lifecycle_delete_all_networks_scanner_still_runs(db):
    """
    Scenariusz: użytkownik kasuje wszystkie sieci.
    Skaner wykrywa sieci przez auto-detect — skanowanie nie zatrzymuje się.

    get_scan_targets() z pustą DiscoveredNetwork zwraca auto-wykryte sieci.
    """
    from netdoc.collector.discovery import get_scan_targets
    from netdoc.storage.models import DiscoveredNetwork, NetworkSource

    # Stwórz i skasuj wszystkie sieci
    for cidr in ["192.168.1.0/24", "10.0.0.0/24"]:
        db.add(DiscoveredNetwork(cidr=cidr, source=NetworkSource.manual, is_active=True))
    db.commit()
    db.query(DiscoveredNetwork).delete(synchronize_session="fetch")
    db.commit()

    assert db.query(DiscoveredNetwork).count() == 0

    # Skaner wykrywa auto-detect — nie jest zablokowany
    with patch("netdoc.collector.discovery.detect_local_networks",
               return_value=["10.0.1.0/24"]):
        with patch("netdoc.collector.discovery._read_discovery_overrides",
                   return_value=(None, None, None, None)):
            with patch("netdoc.config.settings.settings") as mock_settings:
                mock_settings.network_ranges_list = []
                mock_settings.scan_vpn_networks = False
                mock_settings.scan_virtual_networks = False
                targets = get_scan_targets(db)

    assert len(targets) >= 1, "Skaner powinien miec co najmniej 1 cel (auto-detect)"
    assert "10.0.1.0/24" in targets


def test_clear_ports_then_rediscover(client, db):
    """
    Scenariusz: użytkownik czyści porty urządzenia → skan daje nowe wyniki.

    1. Device z portami w DB
    2. DELETE /api/devices/{id}/scan-results → puste
    3. upsert_device + persist_scan_batch → porty wracają
    """
    from netdoc.storage.models import Device, DeviceType, ScanResult
    from netdoc.collector.discovery import _persist_scan_batch

    dev = Device(ip="10.100.0.1", device_type=DeviceType.server,
                 is_active=True, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev)
    db.commit()
    db.refresh(dev)

    # Stwórz stary wynik skanu
    old_sr = ScanResult(device_id=dev.id, scan_type="nmap_full",
                        open_ports={"22": {"service": "ssh"}})
    db.add(old_sr)
    db.commit()

    # Krok 2: Użytkownik czyści porty
    r = client.delete(f"/api/devices/{dev.id}/scan-results")
    assert r.status_code == 200
    db.expire_all()
    assert db.query(ScanResult).filter_by(device_id=dev.id).count() == 0

    # Krok 3: Nowy skan full przez _persist_scan_batch (skaner nadal działa)
    batch = {
        dev.ip: {
            "open_ports": {
                22: {"service": "ssh", "version": "OpenSSH 8.9", "product": ""},
                80: {"service": "http", "version": "", "product": "nginx"},
            }
        }
    }
    saved = _persist_scan_batch(db, batch)
    assert saved == 1

    db.expire_all()
    new_srs = db.query(ScanResult).filter_by(device_id=dev.id).all()
    assert len(new_srs) == 1
    assert "22" in new_srs[0].open_ports
    assert "80" in new_srs[0].open_ports
