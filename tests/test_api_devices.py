"""Testy REST API dla endpointow /api/devices."""
from datetime import datetime
from netdoc.storage.models import (
    Device, DeviceType, Interface, DeviceVlanPort, DeviceStpPort,
    DeviceFdbEntry, TopologyLink, TopologyProtocol,
)


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
    for field in ("serial_number", "asset_tag", "sys_contact",
                  "responsible_person", "asset_notes"):
        assert field in d, f"Brak pola {field!r} w odpowiedzi API"
        assert d[field] is None, f"Pole {field!r} powinno byc None, jest: {d[field]!r}"


def test_update_inventory_fields(client, db):
    """PATCH /api/devices/{id} aktualizuje pola inwentaryzacyjne."""
    device = _add_device(db, "10.2.0.2")
    payload = {
        "serial_number": "SN-ABC-123",
        "asset_tag": "AT-001",
        "sys_contact": "admin@firma.pl",
        "responsible_person": "Jan Kowalski",
        "asset_notes": "Switch w serwerowni A",
        "location": "Rack 3",
    }
    resp = client.patch(f"/api/devices/{device.id}", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["serial_number"] == "SN-ABC-123"
    assert data["asset_tag"] == "AT-001"
    assert data["sys_contact"] == "admin@firma.pl"
    assert data["responsible_person"] == "Jan Kowalski"
    assert data["location"] == "Rack 3"


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


# ─── BUG-API-5: exclude_unset w PATCH ────────────────────────────────────────

def test_patch_device_without_device_type_does_not_zero_it(client, db):
    """BUG-API-5: PATCH bez device_type nie zeruje istniejacego typu (exclude_unset)."""
    device = _add_device(db, "10.9.0.1", dtype=DeviceType.switch)
    resp = client.patch(f"/api/devices/{device.id}", json={"hostname": "sw-test"})
    assert resp.status_code == 200
    assert resp.json()["device_type"] == "switch"
    assert resp.json()["hostname"] == "sw-test"


def test_patch_device_type_explicitly(client, db):
    """PATCH z jawnym device_type zmienia typ."""
    device = _add_device(db, "10.9.0.2", dtype=DeviceType.switch)
    resp = client.patch(f"/api/devices/{device.id}", json={"device_type": "router"})
    assert resp.status_code == 200
    assert resp.json()["device_type"] == "router"


# ── where-connected endpoint ──────────────────────────────────────────────────

def _add_fdb(db, switch_id: int, mac: str, bridge_port: int = 1,
             if_index: int = None, interface_name: str = None,
             vlan_id: int = None, fdb_status: int = 3) -> "DeviceFdbEntry":
    from netdoc.storage.models import DeviceFdbEntry
    from datetime import datetime
    entry = DeviceFdbEntry(
        device_id=switch_id,
        mac=mac,
        bridge_port=bridge_port,
        if_index=if_index,
        interface_name=interface_name,
        vlan_id=vlan_id,
        fdb_status=fdb_status,
        polled_at=datetime.utcnow(),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def test_where_connected_not_found(client):
    """GET /where-connected na nieistniejacym urzadzeniu zwraca 404."""
    resp = client.get("/api/devices/99999/where-connected")
    assert resp.status_code == 404


def test_where_connected_no_mac(client, db):
    """Urzadzenie bez MAC zwraca puste connections."""
    device = _add_device(db, "10.40.0.1")
    assert device.mac is None
    resp = client.get(f"/api/devices/{device.id}/where-connected")
    assert resp.status_code == 200
    data = resp.json()
    assert data["mac"] is None
    assert data["connections"] == []


def test_where_connected_mac_no_fdb(client, db):
    """Urzadzenie z MAC ale bez wpisow FDB zwraca puste connections."""
    device = Device(ip="10.40.0.2", mac="aa:bb:cc:dd:ee:ff",
                    device_type=DeviceType.server, is_active=True)
    db.add(device); db.commit(); db.refresh(device)

    resp = client.get(f"/api/devices/{device.id}/where-connected")
    assert resp.status_code == 200
    data = resp.json()
    assert data["mac"] == "aa:bb:cc:dd:ee:ff"
    assert data["connections"] == []


def test_where_connected_with_fdb_entry(client, db):
    """Urzadzenie z wpisem FDB na switchu zwraca polaczenie z danymi portu."""
    switch = _add_device(db, "192.168.1.1", hostname="sw-core-01", dtype=DeviceType.switch)
    client_dev = Device(ip="192.168.1.100", mac="11:22:33:44:55:66",
                        device_type=DeviceType.workstation, is_active=True)
    db.add(client_dev); db.commit(); db.refresh(client_dev)

    _add_fdb(db, switch_id=switch.id, mac="11:22:33:44:55:66",
             bridge_port=5, if_index=5, interface_name="GigabitEthernet0/5",
             vlan_id=10, fdb_status=3)

    resp = client.get(f"/api/devices/{client_dev.id}/where-connected")
    assert resp.status_code == 200
    data = resp.json()
    assert data["mac"] == "11:22:33:44:55:66"
    assert len(data["connections"]) == 1
    conn = data["connections"][0]
    assert conn["switch_id"] == switch.id
    assert conn["switch_hostname"] == "sw-core-01"
    assert conn["switch_ip"] == "192.168.1.1"
    assert conn["interface_name"] == "GigabitEthernet0/5"
    assert conn["if_index"] == 5
    assert conn["vlan_id"] == 10
    assert conn["fdb_status"] == 3
    assert conn["polled_at"] is not None
    assert conn["polled_at"].endswith("Z"), f"polled_at musi miec sufiks Z (UTC), got: {conn['polled_at']!r}"


def test_where_connected_multiple_switches(client, db):
    """Gdy ten sam MAC widziany na kilku switchach — zwraca wiele wpisow (max 10)."""
    sw1 = _add_device(db, "192.168.2.1", hostname="sw-1", dtype=DeviceType.switch)
    sw2 = _add_device(db, "192.168.2.2", hostname="sw-2", dtype=DeviceType.switch)
    client_dev = Device(ip="192.168.2.100", mac="aa:11:22:33:44:55",
                        device_type=DeviceType.server, is_active=True)
    db.add(client_dev); db.commit(); db.refresh(client_dev)

    _add_fdb(db, switch_id=sw1.id, mac="aa:11:22:33:44:55", bridge_port=1,
             interface_name="Gi0/1")
    _add_fdb(db, switch_id=sw2.id, mac="aa:11:22:33:44:55", bridge_port=2,
             interface_name="Gi0/2")

    resp = client.get(f"/api/devices/{client_dev.id}/where-connected")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["connections"]) == 2
    switch_ips = {c["switch_ip"] for c in data["connections"]}
    assert "192.168.2.1" in switch_ips
    assert "192.168.2.2" in switch_ips


# ─────────────────────────────────────────────────────────────────────────────
# Helpers for L2 tests
# ─────────────────────────────────────────────────────────────────────────────

def _add_iface(db, device_id, if_index, name, alias=None, admin=True, oper=True,
               speed=1000, port_mode=None, native_vlan=None) -> Interface:
    iface = Interface(
        device_id=device_id, if_index=if_index, name=name,
        alias=alias, admin_status=admin, oper_status=oper,
        speed=speed, port_mode=port_mode, native_vlan=native_vlan,
        polled_at=datetime.utcnow(),
    )
    db.add(iface)
    db.commit()
    db.refresh(iface)
    return iface


def _add_vlan_port(db, device_id, vlan_id, if_index, vlan_name=None,
                   port_mode="access", is_pvid=True) -> DeviceVlanPort:
    vp = DeviceVlanPort(
        device_id=device_id, vlan_id=vlan_id, if_index=if_index,
        vlan_name=vlan_name, port_mode=port_mode, is_pvid=is_pvid,
        polled_at=datetime.utcnow(),
    )
    db.add(vp)
    db.commit()
    db.refresh(vp)
    return vp


def _add_stp_port(db, device_id, stp_port_num, if_index=None,
                  stp_state=5, stp_role="designated", path_cost=19) -> DeviceStpPort:
    sp = DeviceStpPort(
        device_id=device_id, stp_port_num=stp_port_num, if_index=if_index,
        stp_state=stp_state, stp_role=stp_role, path_cost=path_cost,
        polled_at=datetime.utcnow(),
    )
    db.add(sp)
    db.commit()
    db.refresh(sp)
    return sp


# ─────────────────────────────────────────────────────────────────────────────
# FDB endpoint tests
# ─────────────────────────────────────────────────────────────────────────────

def test_fdb_not_found(client):
    resp = client.get("/api/devices/99999/fdb")
    assert resp.status_code == 404


def test_fdb_empty(client, db):
    sw = _add_device(db, "10.50.0.1", dtype=DeviceType.switch)
    resp = client.get(f"/api/devices/{sw.id}/fdb")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["entries"] == []


def test_fdb_returns_entries(client, db):
    sw = _add_device(db, "10.50.0.2", dtype=DeviceType.switch)
    _add_fdb(db, switch_id=sw.id, mac="aa:bb:cc:dd:ee:01",
             bridge_port=10, if_index=10, interface_name="Gi1/0/10", vlan_id=100, fdb_status=3)

    resp = client.get(f"/api/devices/{sw.id}/fdb")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    e = data["entries"][0]
    assert e["mac"] == "aa:bb:cc:dd:ee:01"
    assert e["interface_name"] == "Gi1/0/10"
    assert e["vlan_id"] == 100
    assert e["fdb_status"] == 3
    assert e["polled_at"] is not None
    assert e["polled_at"].endswith("Z"), f"polled_at must end with Z, got: {e['polled_at']!r}"


def test_fdb_mac_filter(client, db):
    sw = _add_device(db, "10.50.0.3", dtype=DeviceType.switch)
    _add_fdb(db, switch_id=sw.id, mac="aa:bb:cc:dd:ee:01", bridge_port=1)
    _add_fdb(db, switch_id=sw.id, mac="11:22:33:44:55:66", bridge_port=2)

    resp = client.get(f"/api/devices/{sw.id}/fdb?mac=aa:bb")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["entries"]) == 1
    assert data["entries"][0]["mac"] == "aa:bb:cc:dd:ee:01"


# ─────────────────────────────────────────────────────────────────────────────
# VLAN ports endpoint tests
# ─────────────────────────────────────────────────────────────────────────────

def test_vlan_ports_not_found(client):
    resp = client.get("/api/devices/99999/vlan-ports")
    assert resp.status_code == 404


def test_vlan_ports_empty(client, db):
    sw = _add_device(db, "10.51.0.1", dtype=DeviceType.switch)
    resp = client.get(f"/api/devices/{sw.id}/vlan-ports")
    assert resp.status_code == 200
    data = resp.json()
    assert data["vlans"] == []


def test_vlan_ports_returns_vlan_name(client, db):
    """vlan_name (opis VLAN) musi byc zwracany przez API."""
    sw = _add_device(db, "10.51.0.2", dtype=DeviceType.switch)
    _add_vlan_port(db, sw.id, vlan_id=10, if_index=1,
                   vlan_name="Management", port_mode="access", is_pvid=True)

    resp = client.get(f"/api/devices/{sw.id}/vlan-ports")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["vlans"]) == 1
    v = data["vlans"][0]
    assert v["vlan_id"] == 10
    assert v["vlan_name"] == "Management", "VLAN name must be returned from DB"
    assert len(v["ports"]) == 1
    assert v["ports"][0]["if_index"] == 1
    assert v["ports"][0]["port_mode"] == "access"
    assert v["ports"][0]["is_pvid"] is True
    assert v["polled_at"] is not None
    assert v["polled_at"].endswith("Z"), f"polled_at must end with Z, got: {v['polled_at']!r}"


def test_vlan_ports_groups_by_vlan(client, db):
    """Porty access i trunk w tym samym VLAN sa grupowane razem."""
    sw = _add_device(db, "10.51.0.3", dtype=DeviceType.switch)
    _add_vlan_port(db, sw.id, vlan_id=20, if_index=1, port_mode="access", is_pvid=True)
    _add_vlan_port(db, sw.id, vlan_id=20, if_index=2, port_mode="trunk", is_pvid=False)
    _add_vlan_port(db, sw.id, vlan_id=30, if_index=3, port_mode="access", is_pvid=True)

    resp = client.get(f"/api/devices/{sw.id}/vlan-ports")
    assert resp.status_code == 200
    data = resp.json()
    vlans_by_id = {v["vlan_id"]: v for v in data["vlans"]}
    assert set(vlans_by_id.keys()) == {20, 30}
    assert len(vlans_by_id[20]["ports"]) == 2
    assert len(vlans_by_id[30]["ports"]) == 1


def test_vlan_ports_filter_by_vlan_id(client, db):
    sw = _add_device(db, "10.51.0.4", dtype=DeviceType.switch)
    _add_vlan_port(db, sw.id, vlan_id=10, if_index=1)
    _add_vlan_port(db, sw.id, vlan_id=20, if_index=2)

    resp = client.get(f"/api/devices/{sw.id}/vlan-ports?vlan_id=10")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["vlans"]) == 1
    assert data["vlans"][0]["vlan_id"] == 10


# ─────────────────────────────────────────────────────────────────────────────
# STP endpoint tests
# ─────────────────────────────────────────────────────────────────────────────

def test_stp_not_found(client):
    resp = client.get("/api/devices/99999/stp")
    assert resp.status_code == 404


def test_stp_empty(client, db):
    sw = _add_device(db, "10.52.0.1", dtype=DeviceType.switch)
    resp = client.get(f"/api/devices/{sw.id}/stp")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ports"] == []
    assert data["root_mac"] is None


def test_stp_returns_ports_with_labels(client, db):
    """Stan STP musi miec czytelna etykiete (stp_state_label)."""
    sw = _add_device(db, "10.52.0.2", dtype=DeviceType.switch)
    iface = _add_iface(db, sw.id, if_index=1, name="Gi1/0/1")
    _add_stp_port(db, sw.id, stp_port_num=1, if_index=iface.if_index,
                  stp_state=5, stp_role="designated", path_cost=19)

    resp = client.get(f"/api/devices/{sw.id}/stp")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["ports"]) == 1
    p = data["ports"][0]
    assert p["stp_state"] == 5
    assert p["stp_state_label"] == "forwarding"
    assert p["stp_role"] == "designated"
    assert p["path_cost"] == 19
    assert p["interface_name"] == "Gi1/0/1", "Interface name must be resolved from if_index"
    assert p["polled_at"] is not None
    assert p["polled_at"].endswith("Z"), f"polled_at must end with Z, got: {p['polled_at']!r}"


def test_stp_is_root_detection(client, db):
    """is_root=True gdy MAC urzadzenia == root bridge MAC."""
    sw = Device(ip="10.52.0.3", device_type=DeviceType.switch, is_active=True,
                mac="aa:bb:cc:dd:ee:ff", stp_root_mac="aa:bb:cc:dd:ee:ff")
    db.add(sw); db.commit(); db.refresh(sw)

    resp = client.get(f"/api/devices/{sw.id}/stp")
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_root"] is True


def test_stp_not_root(client, db):
    sw = Device(ip="10.52.0.4", device_type=DeviceType.switch, is_active=True,
                mac="aa:bb:cc:dd:ee:ff", stp_root_mac="11:22:33:44:55:66")
    db.add(sw); db.commit(); db.refresh(sw)

    resp = client.get(f"/api/devices/{sw.id}/stp")
    assert resp.status_code == 200
    assert resp.json()["is_root"] is False


# ─────────────────────────────────────────────────────────────────────────────
# Port Summary endpoint tests
# ─────────────────────────────────────────────────────────────────────────────

def test_port_summary_not_found(client):
    resp = client.get("/api/devices/99999/port-summary")
    assert resp.status_code == 404


def test_port_summary_empty(client, db):
    sw = _add_device(db, "10.53.0.1", dtype=DeviceType.switch)
    resp = client.get(f"/api/devices/{sw.id}/port-summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ports"] == []


def test_port_summary_returns_alias(client, db):
    """alias (opis portu ifAlias) musi byc zwracany przez API."""
    sw = _add_device(db, "10.53.0.2", dtype=DeviceType.switch)
    _add_iface(db, sw.id, if_index=1, name="GigabitEthernet1/0/1",
               alias="Uplink to core")

    resp = client.get(f"/api/devices/{sw.id}/port-summary")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["ports"]) == 1
    p = data["ports"][0]
    assert p["name"] == "GigabitEthernet1/0/1"
    assert p["alias"] == "Uplink to core", "Port alias (ifAlias) must be returned"
    assert p["speed_mbps"] == 1000
    assert p["admin_up"] is True
    assert p["oper_up"] is True


def test_port_summary_vlan_from_interface(client, db):
    """native_vlan z tabeli interfaces musi byc zwracany jako VLAN portu."""
    sw = _add_device(db, "10.53.0.3", dtype=DeviceType.switch)
    _add_iface(db, sw.id, if_index=2, name="Gi1/0/2",
               port_mode="access", native_vlan=42)

    resp = client.get(f"/api/devices/{sw.id}/port-summary")
    assert resp.status_code == 200
    port = resp.json()["ports"][0]
    assert port["port_mode"] == "access"
    assert port["native_vlan"] == 42


def test_port_summary_vlan_from_device_vlan_port(client, db):
    """Gdy interface.native_vlan=None, VLAN pochodzi z DeviceVlanPort (PVID)."""
    sw = _add_device(db, "10.53.0.4", dtype=DeviceType.switch)
    _add_iface(db, sw.id, if_index=3, name="Gi1/0/3")  # brak native_vlan
    _add_vlan_port(db, sw.id, vlan_id=100, if_index=3, is_pvid=True)

    resp = client.get(f"/api/devices/{sw.id}/port-summary")
    assert resp.status_code == 200
    port = resp.json()["ports"][0]
    assert port["native_vlan"] == 100, "native_vlan must fall back to PVID from DeviceVlanPort"


def test_port_summary_port_mode_fallback(client, db):
    """Gdy interface.port_mode=None, tryb pochodzi z DeviceVlanPort."""
    sw = _add_device(db, "10.53.0.5", dtype=DeviceType.switch)
    _add_iface(db, sw.id, if_index=4, name="Gi1/0/4")  # brak port_mode
    _add_vlan_port(db, sw.id, vlan_id=10, if_index=4, port_mode="trunk", is_pvid=False)

    resp = client.get(f"/api/devices/{sw.id}/port-summary")
    assert resp.status_code == 200
    port = resp.json()["ports"][0]
    assert port["port_mode"] == "trunk", "port_mode must fall back to DeviceVlanPort data"


def test_port_summary_stp_info(client, db):
    """Dane STP (rola, stan) musza byc dolaczone do portu przez if_index."""
    sw = _add_device(db, "10.53.0.6", dtype=DeviceType.switch)
    _add_iface(db, sw.id, if_index=5, name="Gi1/0/5")
    _add_stp_port(db, sw.id, stp_port_num=5, if_index=5,
                  stp_state=5, stp_role="root", path_cost=4)

    resp = client.get(f"/api/devices/{sw.id}/port-summary")
    assert resp.status_code == 200
    port = resp.json()["ports"][0]
    assert port["stp_role"] == "root"
    assert port["stp_state"] == "forwarding"
    assert port["stp_path_cost"] == 4


def test_port_summary_lldp_neighbor(client, db):
    """Sasiad LLDP musi byc dolaczony do portu przez TopologyLink."""
    sw1 = _add_device(db, "10.53.1.1", hostname="sw-core", dtype=DeviceType.switch)
    sw2 = _add_device(db, "10.53.1.2", hostname="sw-access", dtype=DeviceType.switch)
    iface1 = _add_iface(db, sw1.id, if_index=1, name="Gi1/0/1")
    iface2 = _add_iface(db, sw2.id, if_index=1, name="Gi1/0/1", alias="To sw-core")

    link = TopologyLink(
        src_device_id=sw1.id, src_interface_id=iface1.id,
        dst_device_id=sw2.id, dst_interface_id=iface2.id,
        protocol=TopologyProtocol.lldp,
    )
    db.add(link); db.commit()

    resp = client.get(f"/api/devices/{sw1.id}/port-summary")
    assert resp.status_code == 200
    port = resp.json()["ports"][0]
    assert port["neighbor_hostname"] == "sw-access"
    assert port["neighbor_port"] == "Gi1/0/1"
    assert port["neighbor_alias"] == "To sw-core"
    assert port["neighbor_protocol"] == "lldp"
