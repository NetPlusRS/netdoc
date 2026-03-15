"""Testy logiki sieci: liczenie i usuwanie urzadzen wg CIDR."""
import ipaddress
import pytest
from netdoc.storage.models import Device, DiscoveredNetwork, DeviceType, NetworkSource


def _add_device(db, ip: str) -> Device:
    d = Device(ip=ip, device_type=DeviceType.unknown, is_active=True)
    db.add(d)
    db.commit()
    db.refresh(d)
    return d


def _add_network(db, cidr: str, is_active: bool = True) -> DiscoveredNetwork:
    n = DiscoveredNetwork(cidr=cidr, source=NetworkSource.manual, is_active=is_active)
    db.add(n)
    db.commit()
    db.refresh(n)
    return n


# ── helper functions replicated from app.py (logic-only tests) ────────────────

def _count_devices_in_cidr(db, cidr: str) -> int:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return 0
    devices = db.query(Device).all()
    count = 0
    for d in devices:
        try:
            if ipaddress.ip_address(d.ip) in net:
                count += 1
        except ValueError:
            pass
    return count


def _delete_devices_in_cidr(db, cidr: str) -> int:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return 0
    devices = db.query(Device).all()
    deleted = 0
    for d in devices:
        try:
            if ipaddress.ip_address(d.ip) in net:
                db.delete(d)
                deleted += 1
        except ValueError:
            pass
    return deleted


# ── count tests ────────────────────────────────────────────────────────────────

def test_count_devices_in_cidr_empty(db):
    assert _count_devices_in_cidr(db, "10.0.0.0/24") == 0


def test_count_devices_in_cidr_matches(db):
    _add_device(db, "10.0.0.1")
    _add_device(db, "10.0.0.2")
    _add_device(db, "192.168.1.1")  # spoza zakresu
    assert _count_devices_in_cidr(db, "10.0.0.0/24") == 2


def test_count_devices_in_cidr_none_match(db):
    _add_device(db, "192.168.5.1")
    assert _count_devices_in_cidr(db, "10.0.0.0/24") == 0


def test_count_devices_in_cidr_exact_host(db):
    _add_device(db, "172.16.0.5")
    assert _count_devices_in_cidr(db, "172.16.0.5/32") == 1


def test_count_devices_in_cidr_invalid(db):
    _add_device(db, "10.0.0.1")
    assert _count_devices_in_cidr(db, "not-a-cidr") == 0


def test_count_all_devices_in_slash16(db):
    for i in range(5):
        _add_device(db, f"10.10.{i}.1")
    _add_device(db, "10.11.0.1")  # spoza /16
    assert _count_devices_in_cidr(db, "10.10.0.0/16") == 5


# ── delete tests ───────────────────────────────────────────────────────────────

def test_delete_devices_in_cidr_empty(db):
    count = _delete_devices_in_cidr(db, "10.0.0.0/24")
    assert count == 0


def test_delete_devices_in_cidr_removes_correct(db):
    _add_device(db, "10.0.0.1")
    _add_device(db, "10.0.0.2")
    _add_device(db, "192.168.1.1")
    deleted = _delete_devices_in_cidr(db, "10.0.0.0/24")
    db.commit()
    assert deleted == 2
    remaining = db.query(Device).all()
    assert len(remaining) == 1
    assert remaining[0].ip == "192.168.1.1"


def test_delete_devices_in_cidr_none_match(db):
    _add_device(db, "192.168.5.10")
    deleted = _delete_devices_in_cidr(db, "10.0.0.0/24")
    db.commit()
    assert deleted == 0
    assert db.query(Device).count() == 1


def test_delete_devices_in_cidr_invalid_cidr(db):
    _add_device(db, "10.0.0.1")
    deleted = _delete_devices_in_cidr(db, "bad-cidr")
    assert deleted == 0


def test_delete_devices_in_cidr_host32(db):
    _add_device(db, "10.5.0.100")
    _add_device(db, "10.5.0.101")
    deleted = _delete_devices_in_cidr(db, "10.5.0.100/32")
    db.commit()
    assert deleted == 1
    assert db.query(Device).count() == 1


# ── API endpoint integration tests via FastAPI client ─────────────────────────

def test_network_toggle_pause_with_delete(client, db):
    """POST /networks/{id}/toggle z delete_devices=1 usuwa urzadzenia z zakresu."""
    # Create via DB directly — web routes don't exist in the FastAPI router
    # These tests use the Flask client fixture from test_web_app.py approach
    # Skip if no /networks endpoint in FastAPI (web is Flask)
    pytest.skip("Endpoint /networks nalezy do Flask web app — testowany w test_web_app.py")


# ── network model tests ────────────────────────────────────────────────────────

def test_discovered_network_model(db):
    n = _add_network(db, "192.168.100.0/24")
    assert n.id is not None
    assert n.cidr == "192.168.100.0/24"
    assert n.is_active is True
    assert n.source == NetworkSource.manual


def test_network_toggle_active(db):
    n = _add_network(db, "10.1.0.0/16", is_active=True)
    n.is_active = False
    db.commit()
    db.refresh(n)
    assert n.is_active is False


def test_delete_network_does_not_cascade_to_devices_by_default(db):
    """Usuniecie sieci NIE kasuje urzadzen (brak FK cascade)."""
    n = _add_network(db, "10.20.0.0/24")
    d = _add_device(db, "10.20.0.1")
    db.delete(n)
    db.commit()
    # Device nadal w bazie
    remaining = db.query(Device).filter_by(id=d.id).first()
    assert remaining is not None


def test_delete_network_with_devices_manual(db):
    """Reczne usuniecie urzadzen + sieci — pelny przeplyw."""
    n = _add_network(db, "10.30.0.0/24")
    _add_device(db, "10.30.0.5")
    _add_device(db, "10.30.0.6")
    _add_device(db, "192.168.0.1")  # poza siecia

    # Usun urzadzenia z zakresu
    deleted = _delete_devices_in_cidr(db, n.cidr)
    db.delete(n)
    db.commit()

    assert deleted == 2
    assert db.query(Device).count() == 1  # tylko 192.168.0.1 zostaje
    assert db.query(DiscoveredNetwork).count() == 0
