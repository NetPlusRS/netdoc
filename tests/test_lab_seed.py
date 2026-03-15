"""Testy dla seed_lab_devices — automatyczne dodawanie urzadzen lab do bazy."""
from unittest.mock import patch, MagicMock
import pytest


def _make_running_result():
    """subprocess.run mock zwracajacy 'true' (kontener dziala)."""
    m = MagicMock()
    m.stdout = "true\n"
    return m


def _make_stopped_result():
    """subprocess.run mock zwracajacy '' (kontener nie dziala)."""
    m = MagicMock()
    m.stdout = "false\n"
    return m


# ─── seed_lab_devices ─────────────────────────────────────────────────────────

def test_seed_lab_devices_adds_all_when_empty(db):
    """Gdy baza jest pusta i lab dziala — dodaje wszystkie 6 urzadzen."""
    import run_scanner

    with patch("subprocess.run", return_value=_make_running_result()):
        run_scanner.seed_lab_devices(db)

    from netdoc.storage.models import Device
    devices = db.query(Device).filter(Device.ip.like("172.28.%")).all()
    assert len(devices) == 6


def test_seed_lab_devices_skips_when_lab_stopped(db):
    """Gdy kontener lab jest zatrzymany — baza pozostaje nienaruszona."""
    import run_scanner

    with patch("subprocess.run", return_value=_make_stopped_result()):
        run_scanner.seed_lab_devices(db)

    from netdoc.storage.models import Device
    devices = db.query(Device).filter(Device.ip.like("172.28.%")).all()
    assert len(devices) == 0


def test_seed_lab_devices_skips_when_docker_unavailable(db):
    """Gdy docker nie jest dostepny (OSError) — nie rzuca wyjatku, nie dodaje nic."""
    import run_scanner

    with patch("subprocess.run", side_effect=OSError("docker not found")):
        run_scanner.seed_lab_devices(db)

    from netdoc.storage.models import Device
    devices = db.query(Device).filter(Device.ip.like("172.28.%")).all()
    assert len(devices) == 0


def test_seed_lab_devices_idempotent(db):
    """Dwukrotne wywolanie nie duplikuje urzadzen."""
    import run_scanner

    with patch("subprocess.run", return_value=_make_running_result()):
        run_scanner.seed_lab_devices(db)
        run_scanner.seed_lab_devices(db)

    from netdoc.storage.models import Device
    devices = db.query(Device).filter(Device.ip.like("172.28.%")).all()
    assert len(devices) == 6


def test_seed_lab_devices_correct_ips(db):
    """Dodane urzadzenia maja oczekiwane adresy IP."""
    import run_scanner

    with patch("subprocess.run", return_value=_make_running_result()):
        run_scanner.seed_lab_devices(db)

    from netdoc.storage.models import Device
    ips = {d.ip for d in db.query(Device).filter(Device.ip.like("172.28.%")).all()}
    assert "172.28.0.10" in ips  # PLC Siemens
    assert "172.28.0.20" in ips  # Router MikroTik
    assert "172.28.0.40" in ips  # HMI


def test_seed_lab_devices_all_active(db):
    """Wszystkie dodane urzadzenia lab maja is_active=True."""
    import run_scanner

    with patch("subprocess.run", return_value=_make_running_result()):
        run_scanner.seed_lab_devices(db)

    from netdoc.storage.models import Device
    devices = db.query(Device).filter(Device.ip.like("172.28.%")).all()
    assert all(d.is_active for d in devices)


def test_lab_devices_constant_has_6_entries():
    """_LAB_DEVICES zawiera dokladnie 6 wpisow (tyle ile kontenerow w lab)."""
    import run_scanner
    assert len(run_scanner._LAB_DEVICES) == 6


def test_seed_partial_existing(db):
    """Gdy czesc urzadzen juz istnieje — dodaje tylko brakujace."""
    import run_scanner
    from netdoc.storage.models import Device, DeviceType
    from datetime import datetime

    # Pre-insert jednego
    db.add(Device(
        ip="172.28.0.10",
        hostname="existing",
        device_type=DeviceType.unknown,
        is_active=True,
        is_trusted=False,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    ))
    db.commit()

    with patch("subprocess.run", return_value=_make_running_result()):
        run_scanner.seed_lab_devices(db)

    from netdoc.storage.models import Device
    devices = db.query(Device).filter(Device.ip.like("172.28.%")).all()
    assert len(devices) == 6
    # Istniejacy rekord nie zostal nadpisany
    existing = next(d for d in devices if d.ip == "172.28.0.10")
    assert existing.hostname == "existing"
