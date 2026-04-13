"""Testy dla DELETE /api/credentials/bulk/all.

Sprawdza: usuniecie po typie, scope global vs all, pusty wynik,
nieprawidlowa metoda, izolacje per-device credentiali.
"""
import pytest
from netdoc.storage.models import Device, DeviceType


def _cred(client, method="snmp", username="public", device_id=None, priority=100):
    payload = {"method": method, "username": username, "priority": priority}
    if device_id is not None:
        payload["device_id"] = device_id
    r = client.post("/api/credentials/", json=payload)
    assert r.status_code == 201
    return r.json()["id"]


def _add_device(db):
    d = Device(ip="10.0.0.1", device_type=DeviceType.router, is_active=True)
    db.add(d)
    db.commit()
    db.refresh(d)
    return d.id


# ── pusta baza ────────────────────────────────────────────────────────────────

def test_bulk_delete_empty_db(client):
    r = client.delete("/api/credentials/bulk/all")
    assert r.status_code == 200
    assert r.json() == {"deleted": 0}


# ── scope=global (domyslny) ───────────────────────────────────────────────────

def test_bulk_delete_all_global(client):
    _cred(client, "snmp", "public")
    _cred(client, "ssh", "admin")
    r = client.delete("/api/credentials/bulk/all")
    assert r.status_code == 200
    assert r.json()["deleted"] == 2
    assert client.get("/api/credentials/").json() == []


def test_bulk_delete_by_method_snmp_leaves_ssh(client):
    _cred(client, "snmp", "public")
    _cred(client, "ssh", "admin")
    r = client.delete("/api/credentials/bulk/all", params={"method": "snmp"})
    assert r.status_code == 200
    assert r.json()["deleted"] == 1
    remaining = client.get("/api/credentials/").json()
    assert len(remaining) == 1
    assert remaining[0]["method"] == "ssh"


def test_bulk_delete_by_method_ssh_leaves_snmp(client):
    _cred(client, "snmp", "public")
    _cred(client, "ssh", "admin")
    r = client.delete("/api/credentials/bulk/all", params={"method": "ssh"})
    assert r.status_code == 200
    assert r.json()["deleted"] == 1
    remaining = client.get("/api/credentials/").json()
    assert len(remaining) == 1
    assert remaining[0]["method"] == "snmp"


def test_bulk_delete_global_does_not_touch_per_device(client, db):
    dev_id = _add_device(db)
    _cred(client, "ssh", "global_admin")                         # global
    _cred(client, "ssh", "device_admin", device_id=dev_id)      # per-device

    r = client.delete("/api/credentials/bulk/all")               # scope=global (default)
    assert r.status_code == 200
    assert r.json()["deleted"] == 1                              # tylko globalny

    remaining = client.get("/api/credentials/").json()
    assert len(remaining) == 1
    assert remaining[0]["device_id"] == dev_id                   # per-device pozostal


# ── scope=include_device=true ─────────────────────────────────────────────────

def test_bulk_delete_include_device_removes_all(client, db):
    dev_id = _add_device(db)
    _cred(client, "ssh", "global_admin")
    _cred(client, "ssh", "device_admin", device_id=dev_id)

    r = client.delete("/api/credentials/bulk/all", params={"include_device": "true"})
    assert r.status_code == 200
    assert r.json()["deleted"] == 2
    assert client.get("/api/credentials/").json() == []


def test_bulk_delete_method_and_include_device(client, db):
    dev_id = _add_device(db)
    _cred(client, "ssh",  "global_ssh")
    _cred(client, "snmp", "global_snmp")
    _cred(client, "ssh",  "device_ssh",  device_id=dev_id)
    _cred(client, "snmp", "device_snmp", device_id=dev_id)

    # Usun tylko SSH (global + per-device), SNMP zostaje
    r = client.delete("/api/credentials/bulk/all",
                      params={"method": "ssh", "include_device": "true"})
    assert r.status_code == 200
    assert r.json()["deleted"] == 2

    remaining = client.get("/api/credentials/").json()
    assert len(remaining) == 2
    assert all(c["method"] == "snmp" for c in remaining)


# ── walidacja ─────────────────────────────────────────────────────────────────

def test_bulk_delete_invalid_method_returns_400(client):
    _cred(client, "snmp", "public")
    r = client.delete("/api/credentials/bulk/all", params={"method": "notaprotocol"})
    assert r.status_code == 400
    # nic nie usunieto
    assert len(client.get("/api/credentials/").json()) == 1


# ── routing: /bulk/all nie koliduje z /{cred_id} ─────────────────────────────

def test_single_delete_still_works_after_bulk_route_added(client):
    cid = _cred(client, "snmp", "public")
    assert client.delete(f"/api/credentials/{cid}").status_code == 204
    assert client.get("/api/credentials/").json() == []


def test_bulk_delete_count_matches_actual_rows(client):
    """Liczba zwrocona przez API == liczba faktycznie usunietych rekordow."""
    for i in range(5):
        _cred(client, "ssh", f"user{i}")
    r = client.delete("/api/credentials/bulk/all")
    assert r.json()["deleted"] == 5
    assert client.get("/api/credentials/").json() == []
