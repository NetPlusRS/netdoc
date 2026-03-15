"""Testy API endpointu /api/events/."""
from netdoc.storage.models import Device, DeviceType, Event, EventType
from datetime import datetime


def _add_device(db, ip="10.0.0.1"):
    d = Device(ip=ip, device_type=DeviceType.router, is_active=True)
    db.add(d)
    db.commit()
    db.refresh(d)
    return d


def _add_event(db, device_id=None, event_type=EventType.device_appeared):
    e = Event(device_id=device_id, event_type=event_type, event_time=datetime.utcnow(), details={})
    db.add(e)
    db.commit()
    db.refresh(e)
    return e


def test_list_events_empty(client):
    r = client.get("/api/events/")
    assert r.status_code == 200
    assert r.json() == []


def test_list_events_returns_all(client, db):
    dev = _add_device(db)
    _add_event(db, dev.id, EventType.device_appeared)
    _add_event(db, dev.id, EventType.port_opened)
    r = client.get("/api/events/")
    assert r.status_code == 200
    assert len(r.json()) == 2


def test_list_events_filter_device_id(client, db):
    dev1 = _add_device(db, "10.0.0.1")
    dev2 = _add_device(db, "10.0.0.2")
    _add_event(db, dev1.id, EventType.device_appeared)
    _add_event(db, dev2.id, EventType.device_disappeared)

    r = client.get(f"/api/events/?device_id={dev1.id}")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["device_id"] == dev1.id
    assert data[0]["event_type"] == "device_appeared"


def test_list_events_filter_event_type(client, db):
    dev = _add_device(db)
    _add_event(db, dev.id, EventType.device_appeared)
    _add_event(db, dev.id, EventType.port_opened)
    _add_event(db, dev.id, EventType.port_closed)

    r = client.get("/api/events/?event_type=port_opened")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["event_type"] == "port_opened"


def test_list_events_filter_both(client, db):
    dev1 = _add_device(db, "10.0.0.1")
    dev2 = _add_device(db, "10.0.0.2")
    _add_event(db, dev1.id, EventType.port_opened)
    _add_event(db, dev2.id, EventType.port_opened)
    _add_event(db, dev1.id, EventType.device_appeared)

    r = client.get(f"/api/events/?device_id={dev1.id}&event_type=port_opened")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["device_id"] == dev1.id
    assert data[0]["event_type"] == "port_opened"


def test_list_events_limit(client, db):
    dev = _add_device(db)
    for _ in range(5):
        _add_event(db, dev.id, EventType.device_appeared)

    r = client.get("/api/events/?limit=3")
    assert r.status_code == 200
    assert len(r.json()) == 3
