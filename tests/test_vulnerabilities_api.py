"""Testy API dla wykrywania podatnosci bezpieczenstwa.
Uzywa fixtures z conftest.py (db, client) - SQLite in-memory.

API:
  GET  /api/vulnerabilities/         - lista z filtrami
  GET  /api/vulnerabilities/summary  - podsumowanie wg severity
  PATCH /api/vulnerabilities/{id}/close - reczne zamkniecie
"""
from datetime import datetime
from netdoc.storage.models import Device, DeviceType, Vulnerability, VulnType, VulnSeverity


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_device(db, ip="10.0.0.1"):
    d = Device(ip=ip, device_type=DeviceType.unknown, is_active=True)
    db.add(d)
    db.commit()
    db.refresh(d)
    return d


def _make_vuln(db, device_id, vuln_type=VulnType.open_telnet,
               severity=VulnSeverity.high, port=23, is_open=True):
    v = Vulnerability(
        device_id=device_id,
        vuln_type=vuln_type,
        severity=severity,
        title="Test vuln",
        port=port,
        evidence="test evidence",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        is_open=is_open,
    )
    db.add(v)
    db.commit()
    db.refresh(v)
    return v


# ─── GET /api/vulnerabilities/ ───────────────────────────────────────────────

def test_list_empty(client):
    r = client.get("/api/vulnerabilities/")
    assert r.status_code == 200
    assert r.json() == []


def test_list_returns_vuln(client, db):
    dev = _make_device(db)
    _make_vuln(db, dev.id)
    r = client.get("/api/vulnerabilities/")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["vuln_type"] == "open_telnet"
    assert data[0]["severity"] == "high"
    assert data[0]["is_open"] is True


def test_list_filter_is_open(client, db):
    dev = _make_device(db)
    _make_vuln(db, dev.id, is_open=True)
    _make_vuln(db, dev.id, vuln_type=VulnType.open_ftp, port=21, is_open=False)
    r = client.get("/api/vulnerabilities/?is_open=true")
    assert r.status_code == 200
    assert len(r.json()) == 1
    assert r.json()[0]["is_open"] is True


def test_list_filter_severity(client, db):
    dev = _make_device(db)
    _make_vuln(db, dev.id, severity=VulnSeverity.critical, vuln_type=VulnType.redis_noauth, port=6379)
    _make_vuln(db, dev.id, severity=VulnSeverity.medium, vuln_type=VulnType.open_ftp, port=21)
    r = client.get("/api/vulnerabilities/?severity=critical")
    assert r.status_code == 200
    assert len(r.json()) == 1
    assert r.json()[0]["severity"] == "critical"


def test_list_filter_device_id(client, db):
    dev1 = _make_device(db, ip="10.0.0.1")
    dev2 = _make_device(db, ip="10.0.0.2")
    _make_vuln(db, dev1.id)
    _make_vuln(db, dev2.id, vuln_type=VulnType.open_ftp, port=21)
    r = client.get(f"/api/vulnerabilities/?device_id={dev1.id}")
    assert r.status_code == 200
    assert len(r.json()) == 1
    assert r.json()[0]["device_id"] == dev1.id


def test_list_filter_vuln_type(client, db):
    dev = _make_device(db)
    _make_vuln(db, dev.id, vuln_type=VulnType.open_telnet, port=23)
    _make_vuln(db, dev.id, vuln_type=VulnType.redis_noauth, port=6379, severity=VulnSeverity.critical)
    r = client.get("/api/vulnerabilities/?vuln_type=redis_noauth")
    assert r.status_code == 200
    assert len(r.json()) == 1
    assert r.json()[0]["vuln_type"] == "redis_noauth"


def test_list_invalid_severity_ignored(client, db):
    """Nieznane severity jest ignorowane — nie ma 400."""
    dev = _make_device(db)
    _make_vuln(db, dev.id)
    r = client.get("/api/vulnerabilities/?severity=nonexistent")
    assert r.status_code == 200


def test_list_invalid_vuln_type_ignored(client, db):
    """Nieznany vuln_type jest ignorowany — nie ma 400."""
    dev = _make_device(db)
    _make_vuln(db, dev.id)
    r = client.get("/api/vulnerabilities/?vuln_type=nonexistent")
    assert r.status_code == 200


# ─── GET /api/vulnerabilities/summary ────────────────────────────────────────

def test_summary_empty(client):
    r = client.get("/api/vulnerabilities/summary")
    assert r.status_code == 200
    data = r.json()
    assert data["total_open"] == 0
    assert data["critical"] == 0
    assert data["high"] == 0


def test_summary_counts(client, db):
    dev = _make_device(db)
    _make_vuln(db, dev.id, severity=VulnSeverity.critical, vuln_type=VulnType.redis_noauth, port=6379)
    _make_vuln(db, dev.id, severity=VulnSeverity.high, vuln_type=VulnType.open_telnet, port=23)
    _make_vuln(db, dev.id, severity=VulnSeverity.medium, vuln_type=VulnType.open_ftp, port=21)
    # jedna zamknieta - nie liczyc
    _make_vuln(db, dev.id, severity=VulnSeverity.critical, vuln_type=VulnType.docker_api_exposed,
               port=2375, is_open=False)
    r = client.get("/api/vulnerabilities/summary")
    assert r.status_code == 200
    data = r.json()
    assert data["total_open"] == 3
    assert data["critical"] == 1
    assert data["high"] == 1
    assert data["medium"] == 1
    assert data["by_type"]["redis_noauth"] == 1
    assert data["by_type"]["open_telnet"] == 1


def test_summary_by_type(client, db):
    dev = _make_device(db)
    _make_vuln(db, dev.id, vuln_type=VulnType.open_telnet, port=23)
    _make_vuln(db, dev.id, vuln_type=VulnType.snmp_public, port=161,
               severity=VulnSeverity.medium)
    r = client.get("/api/vulnerabilities/summary")
    data = r.json()
    assert "open_telnet" in data["by_type"]
    assert "snmp_public" in data["by_type"]


# ─── PATCH /api/vulnerabilities/{id}/close ───────────────────────────────────

def test_close_vulnerability(client, db):
    dev = _make_device(db)
    v = _make_vuln(db, dev.id, is_open=True)
    r = client.patch(f"/api/vulnerabilities/{v.id}/close")
    assert r.status_code == 200
    assert r.json()["is_open"] is False


def test_close_vulnerability_404(client):
    r = client.patch("/api/vulnerabilities/99999/close")
    assert r.status_code == 404


def test_close_already_closed(client, db):
    """Zamkniecie juz zamknietej podatnosci nie powoduje bledu."""
    dev = _make_device(db)
    v = _make_vuln(db, dev.id, is_open=False)
    r = client.patch(f"/api/vulnerabilities/{v.id}/close")
    assert r.status_code == 200
    assert r.json()["is_open"] is False


def test_closed_vuln_not_in_open_list(client, db):
    """Zamknieta podatnosc nie pojawia sie w filtrze is_open=true."""
    dev = _make_device(db)
    v = _make_vuln(db, dev.id, is_open=True)
    client.patch(f"/api/vulnerabilities/{v.id}/close")
    r = client.get("/api/vulnerabilities/?is_open=true")
    ids = [x["id"] for x in r.json()]
    assert v.id not in ids


# ─── PATCH /api/vulnerabilities/{id}/suppress ───────────────────────────────

def test_suppress_vulnerability(client, db):
    dev = _make_device(db)
    v = _make_vuln(db, dev.id, is_open=True)
    r = client.patch(f"/api/vulnerabilities/{v.id}/suppress")
    assert r.status_code == 200
    data = r.json()
    assert data["suppressed"] is True
    assert data["is_open"] is False


def test_suppress_vulnerability_404(client):
    r = client.patch("/api/vulnerabilities/99999/suppress")
    assert r.status_code == 404


def test_suppressed_vuln_not_in_open_list(client, db):
    """Wyciszona podatnosc nie pojawia sie w filtrze is_open=true."""
    dev = _make_device(db)
    v = _make_vuln(db, dev.id, is_open=True)
    client.patch(f"/api/vulnerabilities/{v.id}/suppress")
    r = client.get("/api/vulnerabilities/?is_open=true")
    ids = [x["id"] for x in r.json()]
    assert v.id not in ids


def test_suppress_already_suppressed(client, db):
    """Ponowne wyciszenie juz wyciszonej podatnosci nie powoduje bledu."""
    dev = _make_device(db)
    v = _make_vuln(db, dev.id, is_open=False)
    r = client.patch(f"/api/vulnerabilities/{v.id}/suppress")
    assert r.status_code == 200
    assert r.json()["suppressed"] is True


# ─── PATCH /api/vulnerabilities/{id}/unsuppress ──────────────────────────────

def test_unsuppress_vulnerability(client, db):
    dev = _make_device(db)
    v = _make_vuln(db, dev.id, is_open=False)
    # najpierw wycisz
    client.patch(f"/api/vulnerabilities/{v.id}/suppress")
    # teraz cofnij wyciszenie
    r = client.patch(f"/api/vulnerabilities/{v.id}/unsuppress")
    assert r.status_code == 200
    data = r.json()
    assert data["suppressed"] is False
    assert data["is_open"] is True


def test_unsuppress_vulnerability_404(client):
    r = client.patch("/api/vulnerabilities/99999/unsuppress")
    assert r.status_code == 404


def test_unsuppressed_vuln_in_open_list(client, db):
    """Podatnosc po cofnieciu wyciszenia pojawia sie w filtrze is_open=true."""
    dev = _make_device(db)
    v = _make_vuln(db, dev.id, is_open=True)
    client.patch(f"/api/vulnerabilities/{v.id}/suppress")
    client.patch(f"/api/vulnerabilities/{v.id}/unsuppress")
    r = client.get("/api/vulnerabilities/?is_open=true")
    ids = [x["id"] for x in r.json()]
    assert v.id in ids


# ─── PATCH /api/vulnerabilities/unsuppress-all ───────────────────────────────

def test_unsuppress_all(client, db):
    dev = _make_device(db)
    v1 = _make_vuln(db, dev.id, port=23)
    v2 = _make_vuln(db, dev.id, vuln_type=VulnType.open_ftp, port=21)
    client.patch(f"/api/vulnerabilities/{v1.id}/suppress")
    client.patch(f"/api/vulnerabilities/{v2.id}/suppress")
    r = client.patch("/api/vulnerabilities/unsuppress-all")
    assert r.status_code == 200
    assert r.json()["unsuppressed"] == 2


def test_unsuppress_all_zero_when_none_suppressed(client, db):
    dev = _make_device(db)
    _make_vuln(db, dev.id, is_open=True)
    r = client.patch("/api/vulnerabilities/unsuppress-all")
    assert r.status_code == 200
    assert r.json()["unsuppressed"] == 0


def test_unsuppress_all_reactivates_vulns(client, db):
    """Po unsuppress-all podatnosci wracaja do listy open."""
    dev = _make_device(db)
    v = _make_vuln(db, dev.id, is_open=True)
    client.patch(f"/api/vulnerabilities/{v.id}/suppress")
    # potwierdzenie ze nie widac w open
    r = client.get("/api/vulnerabilities/?is_open=true")
    assert v.id not in [x["id"] for x in r.json()]
    # unsuppress-all
    client.patch("/api/vulnerabilities/unsuppress-all")
    r = client.get("/api/vulnerabilities/?is_open=true")
    assert v.id in [x["id"] for x in r.json()]
