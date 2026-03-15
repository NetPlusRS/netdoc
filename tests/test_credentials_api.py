"""Testy CRUD dla API credentials.
Uzywa fixtures z conftest.py (db, client) - SQLite in-memory z StaticPool.

API credentials:
  POST/PUT: method (snmp/ssh/telnet/api), username (SNMP=community), password, priority, notes
  GET /api/credentials/snmp-fallback-list -> {communities: [...], count: N}
"""


def test_list_empty(client):
    assert client.get("/api/credentials/").json() == []


def test_create_snmp(client):
    r = client.post("/api/credentials/", json={"method": "snmp", "username": "public", "priority": 100})
    assert r.status_code == 201
    d = r.json()
    assert d["method"] == "snmp"
    assert d["username"] == "public"


def test_create_ssh(client):
    r = client.post("/api/credentials/", json={
        "method": "ssh", "username": "admin", "password": "s3cr3t",
        "priority": 200, "notes": "routerHQ",
    })
    assert r.status_code == 201
    assert r.json()["notes"] == "routerHQ"
    assert r.json()["method"] == "ssh"


def test_list_returns_items(client):
    client.post("/api/credentials/", json={"method": "snmp", "username": "public"})
    client.post("/api/credentials/", json={"method": "ssh", "username": "admin"})
    assert len(client.get("/api/credentials/").json()) >= 2


def test_update(client):
    cr = client.post("/api/credentials/", json={"method": "snmp", "username": "public"})
    cid = cr.json()["id"]
    r = client.put(f"/api/credentials/{cid}", json={
        "method": "snmp", "username": "private", "priority": 50, "notes": "changed"
    })
    assert r.status_code == 200
    assert r.json()["notes"] == "changed"
    assert r.json()["username"] == "private"


def test_delete(client):
    cr = client.post("/api/credentials/", json={"method": "snmp", "username": "tmp"})
    cid = cr.json()["id"]
    assert client.delete(f"/api/credentials/{cid}").status_code == 204
    assert cid not in [c["id"] for c in client.get("/api/credentials/").json()]


def test_delete_404(client):
    assert client.delete("/api/credentials/99999").status_code == 404


def test_snmp_fallback_list(client):
    r = client.get("/api/credentials/snmp-fallback-list")
    assert r.status_code == 200
    data = r.json()
    assert "communities" in data and "count" in data
    assert "public" in data["communities"]
    assert data["count"] >= 10


def test_create_credential_device_not_found(client):
    """POST z nieistniejacym device_id zwraca 404."""
    r = client.post("/api/credentials/", json={
        "method": "snmp", "username": "public", "device_id": 99999
    })
    assert r.status_code == 404


def test_update_credential_not_found(client):
    """PUT na nieistniejacy credential zwraca 404."""
    r = client.put("/api/credentials/99999", json={
        "method": "snmp", "username": "public", "priority": 100
    })
    assert r.status_code == 404


# ─── /api/credentials/cred-scan-stats ────────────────────────────────────────

def test_cred_scan_stats_empty(client):
    """Brak urzadzen i credentiali — zwraca pusta liste."""
    r = client.get("/api/credentials/cred-scan-stats")
    assert r.status_code == 200
    d = r.json()
    assert "devices" in d
    assert "cred_totals" in d
    assert "global_cred_usage" in d
    assert isinstance(d["devices"], list)
    assert isinstance(d["cred_totals"], dict)


def test_cred_scan_stats_counts_global_creds(client):
    """Globalne SSH credentials sa liczone w cred_totals."""
    client.post("/api/credentials/", json={"method": "ssh", "username": "admin",
                                           "password": "admin", "priority": 100})
    client.post("/api/credentials/", json={"method": "ssh", "username": "root",
                                           "password": "root", "priority": 100})
    r = client.get("/api/credentials/cred-scan-stats")
    assert r.status_code == 200
    d = r.json()
    assert d["cred_totals"]["ssh"] == 2


def test_cred_scan_stats_global_cred_usage_zero_when_no_devices(client):
    """Globalny credential — usage = 0 gdy brak device-specific sukcesow."""
    r_cred = client.post("/api/credentials/", json={"method": "ssh", "username": "admin",
                                                    "password": "x", "priority": 1})
    cred_id = r_cred.json()["id"]
    r = client.get("/api/credentials/cred-scan-stats")
    d = r.json()
    assert d["global_cred_usage"].get(str(cred_id), 0) == 0


def test_cred_scan_stats_interval_fallback(client):
    """interval_s ma rozsdna wartosc domyslna gdy brak wpisow w SystemStatus."""
    r = client.get("/api/credentials/cred-scan-stats")
    d = r.json()
    assert d["interval_s"] >= 10
