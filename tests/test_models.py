"""Testy modeli SQLAlchemy i operacji na bazie danych."""
from datetime import datetime
import pytest

from netdoc.storage.models import Device, DeviceType, Interface, Event, EventType


def test_create_device(db):
    """Tworzenie urzadzenia i zapis do bazy."""
    device = Device(
        ip="192.168.1.1",
        hostname="router-test",
        vendor="Cisco",
        device_type=DeviceType.router,
    )
    db.add(device)
    db.commit()
    db.refresh(device)

    assert device.id is not None
    assert device.ip == "192.168.1.1"
    assert device.is_active is True
    assert device.first_seen is not None


def test_device_ip_unique(db):
    """IP urzadzenia musi byc unikalne."""
    from sqlalchemy.exc import IntegrityError

    db.add(Device(ip="10.0.0.1", device_type=DeviceType.unknown))
    db.commit()
    db.add(Device(ip="10.0.0.1", device_type=DeviceType.switch))
    with pytest.raises(IntegrityError):
        db.commit()


def test_device_with_interfaces(db):
    """Urzadzenie z interfejsami — relacja one-to-many."""
    device = Device(ip="10.0.0.2", device_type=DeviceType.switch)
    db.add(device)
    db.flush()

    iface = Interface(device_id=device.id, name="eth0", oper_status=True)
    db.add(iface)
    db.commit()
    db.refresh(device)

    assert len(device.interfaces) == 1
    assert device.interfaces[0].name == "eth0"


def test_device_events(db):
    """Zdarzenia powiazane z urzadzeniem."""
    device = Device(ip="10.0.0.3", device_type=DeviceType.ap)
    db.add(device)
    db.flush()

    event = Event(
        device_id=device.id,
        event_type=EventType.device_appeared,
        details={"ip": "10.0.0.3"},
    )
    db.add(event)
    db.commit()
    db.refresh(device)

    assert len(device.events) == 1
    assert device.events[0].event_type == EventType.device_appeared


def test_cascade_delete(db):
    """Usuniecie urzadzenia kasuje powiazane interfejsy i zdarzenia."""
    device = Device(ip="10.0.0.4", device_type=DeviceType.unknown)
    db.add(device)
    db.flush()
    db.add(Interface(device_id=device.id, name="eth0"))
    db.add(Event(device_id=device.id, event_type=EventType.device_appeared))
    db.commit()

    db.delete(device)
    db.commit()

    assert db.query(Interface).count() == 0
    assert db.query(Event).filter(Event.device_id == device.id).count() == 0


# --- DeviceType.domain_controller ---

def test_devicetype_domain_controller_exists():
    """DeviceType zawiera domain_controller."""
    assert DeviceType.domain_controller.value == "domain_controller"


def test_device_snmp_community_default_null(db):
    """Nowe pole snmp_community domyslnie NULL."""
    d = Device(ip="10.10.0.1", device_type=DeviceType.server)
    db.add(d); db.commit(); db.refresh(d)
    assert d.snmp_community is None


def test_device_snmp_ok_at_default_null(db):
    """Nowe pole snmp_ok_at domyslnie NULL."""
    d = Device(ip="10.10.0.2", device_type=DeviceType.server)
    db.add(d); db.commit(); db.refresh(d)
    assert d.snmp_ok_at is None


def test_device_snmp_community_persists(db):
    """snmp_community i snmp_ok_at zapisuja sie i odczytuja poprawnie."""
    from datetime import datetime
    now = datetime(2026, 3, 12, 21, 0, 0)
    d = Device(ip="10.10.0.3", device_type=DeviceType.router,
               snmp_community="public", snmp_ok_at=now)
    db.add(d); db.commit(); db.refresh(d)
    assert d.snmp_community == "public"
    assert d.snmp_ok_at == now


def test_device_snmp_community_update(db):
    """snmp_community mozna zaktualizowac z NULL na wartosc i z powrotem."""
    d = Device(ip="10.10.0.4", device_type=DeviceType.switch)
    db.add(d); db.commit()
    d.snmp_community = "private"
    db.commit(); db.refresh(d)
    assert d.snmp_community == "private"
    d.snmp_community = None
    db.commit(); db.refresh(d)
    assert d.snmp_community is None


def test_domain_controller_device_type_in_db(db):
    """Domain controller mozna zapisac w DB jako device_type."""
    d = Device(ip="10.10.0.5", device_type=DeviceType.domain_controller)
    db.add(d); db.commit(); db.refresh(d)
    assert d.device_type == DeviceType.domain_controller
