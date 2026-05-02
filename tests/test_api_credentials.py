"""Testy REST API dla endpointow /api/credentials.

Pokrywa regresje naprawione w sesji 2026-05-02:
- POST z haslem nie generuje SQL `IS 'value'` (blad 500)
- Wykrywanie duplikatow dziala dla global i per-device credentials
- Bulk delete i delete single dzialaja poprawnie
"""
from netdoc.storage.models import Credential, CredentialMethod, Device, DeviceType


def _add_device(db, ip="10.0.0.1") -> Device:
    d = Device(ip=ip, device_type=DeviceType.switch, is_active=True)
    db.add(d)
    db.commit()
    db.refresh(d)
    return d


def _add_cred(db, method=CredentialMethod.ssh, username="admin", password=None, device_id=None, priority=100):
    c = Credential(
        method=method,
        username=username,
        password_encrypted=password,
        device_id=device_id,
        priority=priority,
    )
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


# ──────────────────────────────────────────────
# POST /api/credentials/
# ──────────────────────────────────────────────

def test_create_global_credential_no_password(client):
    resp = client.post("/api/credentials/", json={"method": "snmp", "username": "public", "priority": 10})
    assert resp.status_code == 201
    data = resp.json()
    assert data["method"] == "snmp"
    assert data["username"] == "public"
    assert data["device_id"] is None


def test_create_global_credential_with_password(client):
    """Regresja: POST z haslem nie moze zwrocic 500 (blad IS zamiast =)."""
    resp = client.post("/api/credentials/", json={
        "method": "ssh", "username": "admin", "password": "Secret123!", "priority": 100
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["username"] == "admin"
    assert "password" not in data  # haslo nie moze byc zwracane


def test_create_credential_duplicate_global(client):
    """Regresja: duplikat globalnego credentials musi zwrocic 409."""
    payload = {"method": "ssh", "username": "admin", "password": "pass1", "priority": 100}
    r1 = client.post("/api/credentials/", json=payload)
    assert r1.status_code == 201

    r2 = client.post("/api/credentials/", json=payload)
    assert r2.status_code == 409


def test_create_credential_duplicate_per_device(client, db):
    """Regresja: duplikat per-device credentials musi zwrocic 409."""
    dev = _add_device(db)
    payload = {"method": "ssh", "username": "user", "password": "pw", "priority": 50, "device_id": dev.id}

    r1 = client.post("/api/credentials/", json=payload)
    assert r1.status_code == 201

    r2 = client.post("/api/credentials/", json=payload)
    assert r2.status_code == 409


def test_create_credential_no_password_then_with_password_are_different(client):
    """Credential bez hasla i z haslem to rozne wpisy — oba powinny powstawac."""
    r1 = client.post("/api/credentials/", json={"method": "ssh", "username": "admin", "priority": 100})
    assert r1.status_code == 201

    r2 = client.post("/api/credentials/", json={"method": "ssh", "username": "admin", "password": "secret", "priority": 100})
    assert r2.status_code == 201


def test_create_credential_unknown_device_returns_404(client):
    resp = client.post("/api/credentials/", json={"method": "ssh", "username": "x", "device_id": 9999})
    assert resp.status_code == 404


# ──────────────────────────────────────────────
# GET /api/credentials/
# ──────────────────────────────────────────────

def test_list_credentials_empty(client):
    resp = client.get("/api/credentials/")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_credentials_returns_device_ip(client, db):
    dev = _add_device(db, ip="192.168.1.50")
    _add_cred(db, device_id=dev.id, username="u1")
    _add_cred(db, username="global")

    resp = client.get("/api/credentials/")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2

    per_dev = next(d for d in data if d["device_id"] == dev.id)
    assert per_dev["device_ip"] == "192.168.1.50"

    global_c = next(d for d in data if d["device_id"] is None)
    assert global_c["device_ip"] is None


def test_list_credentials_no_password_field(client, db):
    _add_cred(db, password="SuperSecret")
    resp = client.get("/api/credentials/")
    body = resp.text
    assert "SuperSecret" not in body


# ──────────────────────────────────────────────
# PUT /api/credentials/{id}
# ──────────────────────────────────────────────

def test_update_credential(client, db):
    c = _add_cred(db, username="old", priority=50)
    resp = client.put(f"/api/credentials/{c.id}", json={
        "method": "ssh", "username": "new", "priority": 200
    })
    assert resp.status_code == 200
    assert resp.json()["username"] == "new"
    assert resp.json()["priority"] == 200


def test_update_credential_not_found(client):
    resp = client.put("/api/credentials/9999", json={"method": "ssh", "username": "x", "priority": 1})
    assert resp.status_code == 404


# ──────────────────────────────────────────────
# DELETE /api/credentials/{id}
# ──────────────────────────────────────────────

def test_delete_credential(client, db):
    c = _add_cred(db)
    resp = client.delete(f"/api/credentials/{c.id}")
    assert resp.status_code == 204

    resp2 = client.delete(f"/api/credentials/{c.id}")
    assert resp2.status_code == 404


def test_delete_credential_not_found(client):
    resp = client.delete("/api/credentials/9999")
    assert resp.status_code == 404


# ──────────────────────────────────────────────
# DELETE /api/credentials/bulk/all
# ──────────────────────────────────────────────

def test_bulk_delete_all_global(client, db):
    _add_cred(db, username="g1")
    _add_cred(db, username="g2")
    dev = _add_device(db)
    _add_cred(db, username="p1", device_id=dev.id)

    resp = client.delete("/api/credentials/bulk/all")
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 2  # tylko globalne, nie per-device


def test_bulk_delete_including_device(client, db):
    _add_cred(db, username="g1")
    dev = _add_device(db)
    _add_cred(db, username="p1", device_id=dev.id)

    resp = client.delete("/api/credentials/bulk/all?include_device=true")
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 2


def test_bulk_delete_by_method(client, db):
    _add_cred(db, method=CredentialMethod.ssh, username="ssh1")
    _add_cred(db, method=CredentialMethod.snmp, username="snmp1")

    resp = client.delete("/api/credentials/bulk/all?method=ssh")
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 1

    remaining = client.get("/api/credentials/")
    assert len(remaining.json()) == 1
    assert remaining.json()[0]["method"] == "snmp"


def test_bulk_delete_invalid_method(client):
    resp = client.delete("/api/credentials/bulk/all?method=invalid")
    assert resp.status_code == 400
