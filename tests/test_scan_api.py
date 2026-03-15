"""Testy dla API scan endpoints. Uzywa fixtures z conftest.py."""
from unittest.mock import patch, MagicMock


def test_scan_status(client):
    r = client.get("/api/scan/status")
    assert r.status_code == 200
    assert "status" in r.json()


def test_oui_status(client):
    mock_oui = MagicMock()
    mock_oui.status.return_value = {
        "entries": 39000, "loaded": True, "needs_update": False,
        "files": {"IEEE MA-L": {"exists": True, "age_days": 5.2, "size_kb": 1024}},
    }
    with patch("netdoc.api.routes.scan.oui_db", mock_oui):
        r = client.get("/api/scan/oui-status")
    assert r.status_code == 200
    data = r.json()
    assert data["entries"] == 39000
    assert data["age_days"] == 5.2


def test_oui_status_no_files(client):
    """Brak plikow OUI — age_days = None, brak KeyError."""
    mock_oui = MagicMock()
    mock_oui.status.return_value = {"entries": 0, "loaded": False, "needs_update": True, "files": {}}
    with patch("netdoc.api.routes.scan.oui_db", mock_oui):
        r = client.get("/api/scan/oui-status")
    assert r.status_code == 200
    assert r.json()["age_days"] is None


def test_trigger_scan_sets_flag(client, db):
    """POST /api/scan/ ustawia flage scan_requested w system_status."""
    r = client.post("/api/scan/")
    assert r.status_code == 202
    from netdoc.storage.models import SystemStatus
    row = db.query(SystemStatus).filter_by(key="scan_requested").first()
    assert row is not None and row.value == "discovery"


def test_trigger_full_scan_sets_flag(client, db):
    """POST /api/scan/full ustawia flage scan_requested=full."""
    r = client.post("/api/scan/full")
    assert r.status_code == 202
    from netdoc.storage.models import SystemStatus
    row = db.query(SystemStatus).filter_by(key="scan_requested").first()
    assert row is not None and row.value == "full"


def test_trigger_oui_update(client):
    with patch("netdoc.api.routes.scan.oui_db", MagicMock()):
        r = client.post("/api/scan/update-oui")
    assert r.status_code == 200


# ─── Ustawienia intensywnosci skanowania ─────────────────────────────────────

def test_scan_settings_contains_intensity_fields(client):
    """GET /api/scan/settings zawiera nowe pola intensywnosci skanowania."""
    resp = client.get("/api/scan/settings")
    assert resp.status_code == 200
    data = resp.json()
    assert "vuln_skip_printers" in data
    assert "vuln_limit_ap_iot" in data
    assert "nmap_min_rate" in data
    assert "nmap_version_intensity" in data
    assert data["vuln_skip_printers"] == 1
    assert data["vuln_limit_ap_iot"] == 1
    assert data["nmap_min_rate"] == 100
    assert data["nmap_version_intensity"] == 9


def test_scan_settings_contains_lab_monitoring_field(client):
    """GET /api/scan/settings zawiera pole lab_monitoring_enabled (domyslnie 0)."""
    resp = client.get("/api/scan/settings")
    assert resp.status_code == 200
    data = resp.json()
    assert "lab_monitoring_enabled" in data
    assert data["lab_monitoring_enabled"] == 0


def test_scan_settings_put_lab_monitoring_enabled(client):
    """PUT /api/scan/settings zapisuje lab_monitoring_enabled = 1."""
    resp = client.put("/api/scan/settings", json={"lab_monitoring_enabled": 1})
    assert resp.status_code == 200
    assert resp.json()["lab_monitoring_enabled"] == 1


def test_scan_settings_put_lab_monitoring_disabled(client):
    """PUT /api/scan/settings zapisuje lab_monitoring_enabled = 0."""
    # najpierw wlacz
    client.put("/api/scan/settings", json={"lab_monitoring_enabled": 1})
    # potem wylacz
    resp = client.put("/api/scan/settings", json={"lab_monitoring_enabled": 0})
    assert resp.status_code == 200
    assert resp.json()["lab_monitoring_enabled"] == 0


def test_scan_settings_put_intensity_fields(client):
    """PUT /api/scan/settings zapisuje nowe pola intensywnosci skanowania."""
    resp = client.put("/api/scan/settings", json={
        "vuln_skip_printers": 0,
        "vuln_limit_ap_iot": 0,
        "nmap_min_rate": 150,
        "nmap_version_intensity": 1,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["vuln_skip_printers"] == 0
    assert data["vuln_limit_ap_iot"] == 0
    assert data["nmap_min_rate"] == 150
    assert data["nmap_version_intensity"] == 1


def test_scan_settings_put_clamps_nmap_rate(client):
    """nmap_min_rate jest ograniczany do 50–5000."""
    resp = client.put("/api/scan/settings", json={"nmap_min_rate": 99999})
    assert resp.status_code == 200
    assert resp.json()["nmap_min_rate"] == 5000

    resp = client.put("/api/scan/settings", json={"nmap_min_rate": 1})
    assert resp.status_code == 200
    assert resp.json()["nmap_min_rate"] == 50


def test_scan_settings_put_clamps_version_intensity(client):
    """nmap_version_intensity jest ograniczany do 0–9."""
    resp = client.put("/api/scan/settings", json={"nmap_version_intensity": 99})
    assert resp.status_code == 200
    assert resp.json()["nmap_version_intensity"] == 9

    resp = client.put("/api/scan/settings", json={"nmap_version_intensity": -1})
    assert resp.status_code == 200
    assert resp.json()["nmap_version_intensity"] == 0


def test_scan_settings_contains_scan_batch_size(client):
    """GET /api/scan/settings zwraca scan_batch_size z domyslna wartoscia 5000 (quick i full scan)."""
    resp = client.get("/api/scan/settings")
    assert resp.status_code == 200
    assert "scan_batch_size" in resp.json()
    assert resp.json()["scan_batch_size"] == 5000
    # full_scan_port_batch_size zostal usuniety — wspolne ustawienie scan_batch_size
    assert "full_scan_port_batch_size" not in resp.json()


def test_scan_settings_put_scan_batch_size(client):
    """PUT /api/scan/settings zapisuje scan_batch_size — dotyczy quick i full scan."""
    resp = client.put("/api/scan/settings", json={"scan_batch_size": 2000})
    assert resp.status_code == 200
    assert resp.json()["scan_batch_size"] == 2000


def test_scan_settings_put_clamps_scan_batch_size(client):
    """scan_batch_size jest ograniczany do 0–65535."""
    resp = client.put("/api/scan/settings", json={"scan_batch_size": 99999})
    assert resp.status_code == 200
    assert resp.json()["scan_batch_size"] == 65535

    resp = client.put("/api/scan/settings", json={"scan_batch_size": -5})
    assert resp.status_code == 200
    assert resp.json()["scan_batch_size"] == 0


# === NOWE TESTY: community-worker settings ===

def test_scan_settings_contains_community_worker_fields(client):
    """GET /api/scan/settings zawiera pola community-worker."""
    resp = client.get("/api/scan/settings")
    assert resp.status_code == 200
    data = resp.json()
    assert "community_interval_s"   in data
    assert "community_workers"      in data
    assert "community_recheck_days" in data
    assert "snmp_community_delay_s" in data


def test_scan_settings_community_interval_default(client):
    """community_interval_s domyslnie 3600."""
    resp = client.get("/api/scan/settings")
    assert resp.json()["community_interval_s"] == 3600


def test_scan_settings_community_workers_default(client):
    """community_workers domyslnie 5."""
    resp = client.get("/api/scan/settings")
    assert resp.json()["community_workers"] == 5


def test_scan_settings_put_community_interval(client):
    """PUT community_interval_s zapisuje i zwraca nowa wartosc."""
    resp = client.put("/api/scan/settings", json={"community_interval_s": 7200})
    assert resp.status_code == 200
    assert resp.json()["community_interval_s"] == 7200


def test_scan_settings_put_community_interval_min(client):
    """community_interval_s nie moze byc ponizej 60."""
    resp = client.put("/api/scan/settings", json={"community_interval_s": 5})
    assert resp.status_code == 200
    assert resp.json()["community_interval_s"] == 60


def test_scan_settings_put_community_workers_clamped(client):
    """community_workers ograniczone do 1-50."""
    resp = client.put("/api/scan/settings", json={"community_workers": 200})
    assert resp.status_code == 200
    assert resp.json()["community_workers"] == 50

    resp = client.put("/api/scan/settings", json={"community_workers": 0})
    assert resp.status_code == 200
    assert resp.json()["community_workers"] == 1


def test_scan_settings_put_community_recheck_days(client):
    """community_recheck_days zapisuje sie poprawnie."""
    resp = client.put("/api/scan/settings", json={"community_recheck_days": 14})
    assert resp.status_code == 200
    assert resp.json()["community_recheck_days"] == 14


def test_scan_settings_put_snmp_community_delay(client):
    """snmp_community_delay_s ograniczone do 0-60."""
    resp = client.put("/api/scan/settings", json={"snmp_community_delay_s": 10})
    assert resp.status_code == 200
    assert resp.json()["snmp_community_delay_s"] == 10

    resp = client.put("/api/scan/settings", json={"snmp_community_delay_s": 100})
    assert resp.status_code == 200
    assert resp.json()["snmp_community_delay_s"] == 60
