"""Testy API endpointow /api/topology/."""
from netdoc.storage.models import Device, DeviceType, TopologyLink, TopologyProtocol, Confidence


def _add_device(db, ip, active=True):
    d = Device(ip=ip, device_type=DeviceType.router, is_active=active)
    db.add(d)
    db.commit()
    db.refresh(d)
    return d


def _add_link(db, src, dst):
    link = TopologyLink(
        src_device_id=src.id,
        dst_device_id=dst.id,
        protocol=TopologyProtocol.lldp,
        confidence=Confidence.auto,
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return link


def test_topology_empty(client):
    r = client.get("/api/topology/")
    assert r.status_code == 200
    data = r.json()
    assert data["nodes"] == []
    assert data["links"] == []


def test_topology_active_only_by_default(client, db):
    active = _add_device(db, "10.0.0.1", active=True)
    _add_device(db, "10.0.0.2", active=False)

    r = client.get("/api/topology/")
    assert r.status_code == 200
    data = r.json()
    assert len(data["nodes"]) == 1
    assert data["nodes"][0]["ip"] == "10.0.0.1"


def test_topology_active_only_false_returns_all(client, db):
    _add_device(db, "10.0.0.1", active=True)
    _add_device(db, "10.0.0.2", active=False)

    r = client.get("/api/topology/?active_only=false")
    assert r.status_code == 200
    data = r.json()
    assert len(data["nodes"]) == 2


def test_topology_includes_links_between_active(client, db):
    d1 = _add_device(db, "10.0.1.1")
    d2 = _add_device(db, "10.0.1.2")
    _add_link(db, d1, d2)

    r = client.get("/api/topology/")
    assert r.status_code == 200
    data = r.json()
    assert len(data["nodes"]) == 2
    assert len(data["links"]) == 1
    assert data["links"][0]["src_device_id"] == d1.id
    assert data["links"][0]["dst_device_id"] == d2.id


def test_topology_excludes_link_to_inactive_device(client, db):
    active = _add_device(db, "10.0.2.1", active=True)
    inactive = _add_device(db, "10.0.2.2", active=False)
    _add_link(db, active, inactive)

    r = client.get("/api/topology/")
    assert r.status_code == 200
    data = r.json()
    # inactive nie jest w nodes, wiec link tez odpada (filtrowanie po device_ids)
    assert len(data["links"]) == 0


def test_list_links_empty(client):
    r = client.get("/api/topology/links")
    assert r.status_code == 200
    assert r.json() == []


def test_list_links_returns_all(client, db):
    d1 = _add_device(db, "10.0.3.1")
    d2 = _add_device(db, "10.0.3.2")
    d3 = _add_device(db, "10.0.3.3")
    _add_link(db, d1, d2)
    _add_link(db, d2, d3)

    r = client.get("/api/topology/links")
    assert r.status_code == 200
    assert len(r.json()) == 2
