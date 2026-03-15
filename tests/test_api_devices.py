"""Testy REST API dla endpointow /api/devices."""
from netdoc.storage.models import Device, DeviceType


def _add_device(db, ip: str, hostname: str = None, active: bool = True, dtype=DeviceType.router) -> Device:
    d = Device(ip=ip, hostname=hostname, device_type=dtype, is_active=active)
    db.add(d)
    db.commit()
    db.refresh(d)
    return d


def test_list_devices_empty(client):
    resp = client.get("/api/devices/")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_devices(client, db):
    _add_device(db, "192.168.1.1", "router-01")
    _add_device(db, "192.168.1.2", "switch-01", dtype=DeviceType.switch)

    resp = client.get("/api/devices/")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    ips = {d["ip"] for d in data}
    assert "192.168.1.1" in ips


def test_list_devices_filter_active(client, db):
    _add_device(db, "10.0.0.1", active=True)
    _add_device(db, "10.0.0.2", active=False)

    resp = client.get("/api/devices/?active_only=true")
    data = resp.json()
    assert len(data) == 1
    assert data[0]["ip"] == "10.0.0.1"


def test_list_devices_filter_type(client, db):
    _add_device(db, "10.0.1.1", dtype=DeviceType.switch)
    _add_device(db, "10.0.1.2", dtype=DeviceType.router)

    resp = client.get("/api/devices/?device_type=switch")
    data = resp.json()
    assert len(data) == 1
    assert data[0]["device_type"] == "switch"


def test_get_device(client, db):
    device = _add_device(db, "172.16.0.1", "fw-01")
    resp = client.get(f"/api/devices/{device.id}")
    assert resp.status_code == 200
    assert resp.json()["hostname"] == "fw-01"


def test_get_device_not_found(client):
    resp = client.get("/api/devices/9999")
    assert resp.status_code == 404


def test_update_device(client, db):
    device = _add_device(db, "172.16.0.2")
    resp = client.patch(
        f"/api/devices/{device.id}",
        json={"hostname": "new-name", "location": "Serwerownia A"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["hostname"] == "new-name"
    assert data["location"] == "Serwerownia A"


def test_delete_inactive_device(client, db):
    device = _add_device(db, "172.16.0.3", active=False)
    resp = client.delete(f"/api/devices/{device.id}")
    assert resp.status_code == 204


def test_delete_active_device_rejected(client, db):
    device = _add_device(db, "172.16.0.4", active=True)
    resp = client.delete(f"/api/devices/{device.id}")
    assert resp.status_code == 409


def test_delete_active_device_with_force(client, db):
    """DELETE /api/devices/{id}?force=true usuwa aktywne urzadzenie."""
    device = _add_device(db, "172.16.0.5", active=True)
    resp = client.delete(f"/api/devices/{device.id}?force=true")
    assert resp.status_code == 204
    # Urzadzenie zniklo z bazy
    resp2 = client.get(f"/api/devices/{device.id}")
    assert resp2.status_code == 404


def test_delete_device_not_found(client):
    """DELETE /api/devices/9999 zwraca 404."""
    resp = client.delete("/api/devices/9999")
    assert resp.status_code == 404


# ── Reclassify endpoint ───────────────────────────────────────────────────────

def test_reclassify_device(client, db):
    """POST /api/devices/{id}/reclassify ustawia nowy typ na podstawie portow."""
    from netdoc.storage.models import ScanResult
    device = _add_device(db, "10.5.0.1", dtype=DeviceType.unknown)
    # Dodaj wynik skanu z portem 9100 (drukarka)
    sr = ScanResult(device_id=device.id, scan_type="nmap",
                    open_ports={"9100": {"service": "jetdirect"}})
    db.add(sr); db.commit()
    resp = client.post(f"/api/devices/{device.id}/reclassify")
    assert resp.status_code == 200
    assert resp.json()["device_type"] == "printer"


def test_reclassify_device_no_scan(client, db):
    """POST /reclassify bez skanu zwraca unknown (brak portow)."""
    device = _add_device(db, "10.5.0.2", dtype=DeviceType.unknown)
    resp = client.post(f"/api/devices/{device.id}/reclassify")
    assert resp.status_code == 200
    # Bez danych nadal unknown
    assert resp.json()["device_type"] == "unknown"


def test_reclassify_device_not_found(client):
    """POST /reclassify na nieistniejacym urzadzeniu zwraca 404."""
    resp = client.post("/api/devices/9999/reclassify")
    assert resp.status_code == 404


def test_reclassify_device_uses_mac_oui_when_no_vendor(client, db):
    """POST /reclassify: gdy vendor=None ale mac ustawiony, OUI decyduje o typie."""
    from unittest.mock import patch
    # Ubiquiti MAC, brak vendora, brak portow w DB
    device = Device(ip="10.5.0.10", mac="9C:05:D6:AA:BB:CC",
                    vendor=None, device_type=DeviceType.unknown, is_active=True)
    db.add(device); db.commit(); db.refresh(device)

    with patch("netdoc.collector.discovery.oui_db") as mock_oui:
        mock_oui.lookup.return_value = "Ubiquiti Inc"
        resp = client.post(f"/api/devices/{device.id}/reclassify")
    assert resp.status_code == 200
    assert resp.json()["device_type"] == "ap"


def test_reclassify_device_vendor_field_wins_over_mac_oui(client, db):
    """POST /reclassify: vendor z pola ma priorytet nad OUI z MAC."""
    from unittest.mock import patch
    from netdoc.storage.models import ScanResult
    device = Device(ip="10.5.0.11", mac="9C:05:D6:AA:BB:CC",
                    vendor="Synology Incorporated", device_type=DeviceType.unknown, is_active=True)
    db.add(device); db.commit(); db.refresh(device)
    sr = ScanResult(device_id=device.id, scan_type="nmap", open_ports={"443": {}})
    db.add(sr); db.commit()

    with patch("netdoc.collector.discovery.oui_db") as mock_oui:
        # OUI twierdzi Ubiquiti, ale vendor w DB to Synology
        mock_oui.lookup.return_value = "Ubiquiti Inc"
        resp = client.post(f"/api/devices/{device.id}/reclassify")
    assert resp.status_code == 200
    # Synology + port 443 → nas
    assert resp.json()["device_type"] == "nas"
    mock_oui.lookup.assert_not_called()


def test_reclassify_device_mac_and_ports_combined(client, db):
    """POST /reclassify: MAC → OUI vendor + porty razem daja prawidlowy typ."""
    from unittest.mock import patch
    from netdoc.storage.models import ScanResult
    # Hikvision kamera: brak vendora, MAC z OUI Hikvision, port RTSP 554
    device = Device(ip="10.5.0.12", mac="08:ED:ED:AA:BB:CC",
                    vendor=None, device_type=DeviceType.unknown, is_active=True)
    db.add(device); db.commit(); db.refresh(device)
    sr = ScanResult(device_id=device.id, scan_type="nmap", open_ports={"80": {}, "554": {}})
    db.add(sr); db.commit()

    with patch("netdoc.collector.discovery.oui_db") as mock_oui:
        mock_oui.lookup.return_value = "Hikvision Digital Technology"
        resp = client.post(f"/api/devices/{device.id}/reclassify")
    assert resp.status_code == 200
    assert resp.json()["device_type"] == "camera"


# ── Trust endpoints ───────────────────────────────────────────────────────────

def test_trust_device(client, db):
    """PATCH /trust ustawia is_trusted=True z kategoria i notatka."""
    device = _add_device(db, "10.1.1.1")
    resp = client.patch(f"/api/devices/{device.id}/trust",
                        json={"trusted": True, "note": "router HQ", "category": "infrastructure"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_trusted"] is True
    assert data["trust_note"] == "router HQ"
    assert data["trust_category"] == "infrastructure"
    assert data["trusted_at"] is not None


def test_untrust_device(client, db):
    """PATCH /trust z trusted=False usuwa oznaczenie."""
    device = _add_device(db, "10.1.1.2")
    # Najpierw ustaw jako zaufane
    client.patch(f"/api/devices/{device.id}/trust",
                 json={"trusted": True, "note": "test", "category": "iot"})
    # Potem usun zaufanie
    resp = client.patch(f"/api/devices/{device.id}/trust", json={"trusted": False})
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_trusted"] is False
    assert data["trust_note"] is None
    assert data["trust_category"] is None
    assert data["trusted_at"] is None


def test_trust_device_not_found(client):
    """PATCH /trust na nieistniejacym urzadzeniu zwraca 404."""
    resp = client.patch("/api/devices/99999/trust", json={"trusted": True})
    assert resp.status_code == 404


def test_device_has_trust_fields_in_output(client, db):
    """GET /api/devices/ zawiera pola is_trusted w odpowiedzi."""
    _add_device(db, "10.1.1.3")
    resp = client.get("/api/devices/")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) > 0
    assert "is_trusted" in data[0]
    assert data[0]["is_trusted"] is False  # domyslnie niezaufane


# ── Inventory fields ──────────────────────────────────────────────────────────

def test_inventory_fields_in_output(client, db):
    """GET /api/devices/ zawiera pola inwentaryzacyjne w odpowiedzi."""
    _add_device(db, "10.2.0.1")
    resp = client.get("/api/devices/")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) > 0
    d = data[0]
    for field in ("serial_number", "asset_tag", "purchase_date",
                  "purchase_price", "purchase_vendor",
                  "invoice_number", "support_end", "responsible_person", "asset_notes"):
        assert field in d, f"Brak pola {field!r} w odpowiedzi API"
        assert d[field] is None, f"Pole {field!r} powinno byc None, jest: {d[field]!r}"
    # purchase_currency ma domyslna wartosc PLN
    assert "purchase_currency" in d


def test_update_inventory_fields(client, db):
    """PATCH /api/devices/{id} aktualizuje pola inwentaryzacyjne."""
    device = _add_device(db, "10.2.0.2")
    payload = {
        "serial_number": "SN-ABC-123",
        "asset_tag": "AT-001",
        "purchase_date": "2023-06-15",
        "purchase_price": "4500.00",
        "purchase_currency": "PLN",
        "purchase_vendor": "ABC Computers",
        "invoice_number": "FV/2023/1234",
        "support_end": "2028-06-15",
        "responsible_person": "Jan Kowalski",
        "asset_notes": "Switch w serwerowni A",
    }
    resp = client.patch(f"/api/devices/{device.id}", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["serial_number"] == "SN-ABC-123"
    assert data["asset_tag"] == "AT-001"
    assert data["purchase_date"] == "2023-06-15"
    assert data["purchase_currency"] == "PLN"
    assert data["responsible_person"] == "Jan Kowalski"
    assert data["support_end"] == "2028-06-15"


def test_inventory_partial_update(client, db):
    """PATCH z podzbiorem pol inwentaryzacyjnych nie kasuje pozostalych."""
    device = _add_device(db, "10.2.0.3")
    # Ustaw pola
    client.patch(f"/api/devices/{device.id}",
                 json={"serial_number": "SN-X", "responsible_person": "Anna"})
    # Zaktualizuj tylko jeden pola
    resp = client.patch(f"/api/devices/{device.id}",
                        json={"asset_tag": "AT-999"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["serial_number"] == "SN-X"         # poprzednia wartosc zachowana
    assert data["responsible_person"] == "Anna"    # poprzednia wartosc zachowana
    assert data["asset_tag"] == "AT-999"           # nowa wartosc


def test_set_ip_type_static(client, db):
    """PATCH /ip-type ustawia ip_type=static."""
    device = _add_device(db, "10.3.0.1")
    resp = client.patch(f"/api/devices/{device.id}/ip-type", json={"ip_type": "static"})
    assert resp.status_code == 200
    assert resp.json()["ip_type"] == "static"


def test_set_ip_type_dhcp(client, db):
    """PATCH /ip-type ustawia ip_type=dhcp."""
    device = _add_device(db, "10.3.0.2")
    resp = client.patch(f"/api/devices/{device.id}/ip-type", json={"ip_type": "dhcp"})
    assert resp.status_code == 200
    assert resp.json()["ip_type"] == "dhcp"


def test_set_ip_type_unknown(client, db):
    """PATCH /ip-type resetuje do unknown."""
    device = _add_device(db, "10.3.0.3")
    client.patch(f"/api/devices/{device.id}/ip-type", json={"ip_type": "static"})
    resp = client.patch(f"/api/devices/{device.id}/ip-type", json={"ip_type": "unknown"})
    assert resp.status_code == 200
    assert resp.json()["ip_type"] == "unknown"


def test_set_ip_type_invalid(client, db):
    """PATCH /ip-type z niedozwolona wartoscia zwraca 422."""
    device = _add_device(db, "10.3.0.4")
    resp = client.patch(f"/api/devices/{device.id}/ip-type", json={"ip_type": "reserved"})
    assert resp.status_code == 422


def test_set_ip_type_not_found(client):
    """PATCH /ip-type na nieistniejacym urzadzeniu zwraca 404."""
    resp = client.patch("/api/devices/99999/ip-type", json={"ip_type": "static"})
    assert resp.status_code == 404


def test_device_ip_type_default(client, db):
    """Nowe urzadzenie ma ip_type=unknown domyslnie."""
    device = _add_device(db, "10.3.0.5")
    resp = client.get(f"/api/devices/{device.id}")
    assert resp.status_code == 200
    assert resp.json()["ip_type"] == "unknown"


# ── Testy: DELETE /api/devices/{id}/scan-results ─────────────────────────────

def _add_scan_result(db, device_id, scan_type="nmap_full", open_ports=None):
    from netdoc.storage.models import ScanResult
    sr = ScanResult(device_id=device_id, scan_type=scan_type, open_ports=open_ports or {"22": {}})
    db.add(sr)
    db.commit()
    db.refresh(sr)
    return sr


def test_clear_device_scan_results_all(client, db):
    """DELETE /api/devices/{id}/scan-results usuwa wszystkie wyniki skanu."""
    from netdoc.storage.models import ScanResult
    device = _add_device(db, "10.10.0.1")
    _add_scan_result(db, device.id, scan_type="nmap")
    _add_scan_result(db, device.id, scan_type="nmap_full")

    resp = client.delete(f"/api/devices/{device.id}/scan-results")
    assert resp.status_code == 200
    data = resp.json()
    assert data["deleted"] == 2
    assert db.query(ScanResult).filter_by(device_id=device.id).count() == 0


def test_clear_device_scan_results_nmap_full_only(client, db):
    """DELETE /api/devices/{id}/scan-results?scan_type=nmap_full usuwa tylko pelny skan."""
    from netdoc.storage.models import ScanResult
    device = _add_device(db, "10.10.0.2")
    _add_scan_result(db, device.id, scan_type="nmap")
    _add_scan_result(db, device.id, scan_type="nmap_full")

    resp = client.delete(f"/api/devices/{device.id}/scan-results?scan_type=nmap_full")
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 1
    # Szybki skan (nmap) powinien pozostac
    remaining = db.query(ScanResult).filter_by(device_id=device.id).all()
    assert len(remaining) == 1
    assert remaining[0].scan_type == "nmap"


def test_clear_device_scan_results_not_found(client):
    """DELETE /api/devices/99999/scan-results zwraca 404."""
    resp = client.delete("/api/devices/99999/scan-results")
    assert resp.status_code == 404


def test_clear_device_scan_results_no_results(client, db):
    """DELETE /api/devices/{id}/scan-results gdy brak wynikow zwraca deleted=0."""
    device = _add_device(db, "10.10.0.3")
    resp = client.delete(f"/api/devices/{device.id}/scan-results")
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 0


# ── Testy: DELETE /api/devices/scan-results (bulk) ───────────────────────────

def test_clear_bulk_scan_results_all(client, db):
    """DELETE /api/devices/scan-results bez parametrow usuwa wszystkie wyniki."""
    from netdoc.storage.models import ScanResult
    d1 = _add_device(db, "10.20.0.1")
    d2 = _add_device(db, "10.20.0.2")
    _add_scan_result(db, d1.id)
    _add_scan_result(db, d2.id)

    resp = client.delete("/api/devices/scan-results")
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 2
    assert db.query(ScanResult).count() == 0


def test_clear_bulk_scan_results_selected_ids(client, db):
    """DELETE /api/devices/scan-results?device_ids=x,y usuwa tylko wybrane urzadzenia."""
    from netdoc.storage.models import ScanResult
    d1 = _add_device(db, "10.20.0.3")
    d2 = _add_device(db, "10.20.0.4")
    d3 = _add_device(db, "10.20.0.5")
    _add_scan_result(db, d1.id)
    _add_scan_result(db, d2.id)
    _add_scan_result(db, d3.id)

    resp = client.delete(f"/api/devices/scan-results?device_ids={d1.id},{d2.id}")
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 2
    # d1 i d2 musza byc usuniete
    assert db.query(ScanResult).filter_by(device_id=d1.id).count() == 0, "d1 musi byc usuniety"
    assert db.query(ScanResult).filter_by(device_id=d2.id).count() == 0, "d2 musi byc usuniety"
    # d3 powinno pozostac nietkniete
    assert db.query(ScanResult).filter_by(device_id=d3.id).count() == 1, "d3 musi pozostac"


def test_clear_bulk_scan_results_invalid_ids(client):
    """DELETE /api/devices/scan-results z nieprawidlowym device_ids zwraca 400."""
    resp = client.delete("/api/devices/scan-results?device_ids=abc,xyz")
    assert resp.status_code == 400


def test_clear_bulk_scan_results_scan_type_filter(client, db):
    """DELETE /api/devices/scan-results?scan_type=nmap_full usuwa tylko pelny skan."""
    from netdoc.storage.models import ScanResult
    d = _add_device(db, "10.20.0.6")
    _add_scan_result(db, d.id, scan_type="nmap")
    _add_scan_result(db, d.id, scan_type="nmap_full")

    resp = client.delete("/api/devices/scan-results?scan_type=nmap_full")
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 1
    remaining = db.query(ScanResult).filter_by(device_id=d.id).all()
    assert len(remaining) == 1
    assert remaining[0].scan_type == "nmap"


# ── Testy: auto-czyszczenie w _persist_scan_batch ────────────────────────────

def test_persist_scan_batch_clears_old_nmap_full(db):
    """_persist_scan_batch usuwa stare nmap_full przed zapisem nowego wyniku."""
    from netdoc.storage.models import ScanResult
    from netdoc.collector.discovery import _persist_scan_batch

    device = _add_device(db, "192.168.99.1")
    # Dodaj stary wynik pelnego skanu
    old_sr = _add_scan_result(db, device.id, scan_type="nmap_full", open_ports={"22": {}, "80": {}})
    assert db.query(ScanResult).filter_by(device_id=device.id, scan_type="nmap_full").count() == 1

    # Uruchom _persist_scan_batch z nowym wynikiem
    batch = {"192.168.99.1": {"open_ports": {"443": {"service": "https"}}}}
    _persist_scan_batch(db, batch)

    # Powinien byc dokladnie 1 wynik nmap_full (nowy, stary usuniety)
    results = db.query(ScanResult).filter_by(device_id=device.id, scan_type="nmap_full").all()
    assert len(results) == 1
    assert "443" in results[0].open_ports
    assert "22" not in results[0].open_ports


# === NOWE TESTY: DeviceOut zwraca snmp_community i snmp_ok_at ===

def test_api_device_out_has_snmp_fields(client, db):
    """GET /api/devices/ zawiera pola snmp_community i snmp_ok_at."""
    from netdoc.storage.models import Device, DeviceType
    from datetime import datetime
    d = Device(ip="10.30.0.1", device_type=DeviceType.router,
               snmp_community="public", snmp_ok_at=datetime(2026, 3, 12, 21, 0, 0))
    db.add(d); db.commit(); db.refresh(d)

    resp = client.get("/api/devices/")
    assert resp.status_code == 200
    data = resp.json()
    dev = next((x for x in data if x["ip"] == "10.30.0.1"), None)
    assert dev is not None
    assert dev["snmp_community"] == "public"
    assert dev["snmp_ok_at"] is not None


def test_api_device_out_snmp_null_by_default(client, db):
    """GET /api/devices/ zwraca snmp_community=null gdy nie ustawiono."""
    from netdoc.storage.models import Device, DeviceType
    d = Device(ip="10.30.0.2", device_type=DeviceType.unknown)
    db.add(d); db.commit(); db.refresh(d)

    resp = client.get("/api/devices/")
    assert resp.status_code == 200
    data = resp.json()
    dev = next((x for x in data if x["ip"] == "10.30.0.2"), None)
    assert dev is not None
    assert dev["snmp_community"] is None
    assert dev["snmp_ok_at"] is None
