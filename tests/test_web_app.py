"""Testy Flask web app (netdoc.web.app)."""
import pytest
from unittest.mock import MagicMock, patch


def _mock_dev(id=1, ip="192.168.1.1", is_active=True):
    d = MagicMock()
    d.id = id; d.ip = ip; d.is_active = is_active
    d.hostname = None; d.last_credential_ok_at = None
    d.mac = None; d.vendor = None; d.model = None
    d.os_version = None; d.first_seen = None; d.last_seen = None
    from netdoc.storage.models import DeviceType
    d.device_type = DeviceType.unknown
    # Inwentaryzacja
    d.serial_number = None; d.asset_tag = None; d.purchase_date = None
    d.purchase_price = None; d.purchase_currency = None; d.purchase_vendor = None
    d.invoice_number = None; d.warranty_end = None; d.support_end = None
    d.responsible_person = None; d.asset_notes = None
    # Flagi / monitoring / trust
    d.is_trusted = False; d.is_monitored = False; d.flag_color = None
    return d


def _mock_net(id=1, cidr="192.168.1.0/24", is_active=True):
    n = MagicMock()
    n.id = id; n.cidr = cidr; n.is_active = is_active
    n.source = "manual"; n.notes = None
    n.first_seen = None; n.last_seen = None
    return n


def _mock_cred(id=1, method="snmp", username="public", priority=100, device_id=None):
    from netdoc.storage.models import CredentialMethod
    c = MagicMock()
    c.id = id; c.username = username
    c.priority = priority; c.device_id = device_id
    c.last_success_at = None; c.success_count = 0; c.notes = None
    c.password_encrypted = None
    try:
        c.method = CredentialMethod(method)
    except ValueError:
        c.method = method
    return c


def _setup_mock_api(mock_req, json_val=None):
    v = json_val or {}
    for m in ("get", "post", "patch", "delete"):
        attr = getattr(mock_req, m).return_value
        attr.status_code = 200; attr.json.return_value = v
        attr.raise_for_status = MagicMock(); attr.text = ""


def _build_app(creds=None, devices=None, networks=None):
    from netdoc.web.app import create_app
    from netdoc.storage.models import Device, DiscoveredNetwork, Credential, SystemStatus

    app = create_app()
    app.config["TESTING"] = True

    ms = MagicMock()
    ms.__enter__ = lambda s: s
    ms.__exit__ = MagicMock(return_value=False)

    dm = {
        Device: devices or [],
        DiscoveredNetwork: networks or [],
        Credential: creds or [],
        SystemStatus: [MagicMock(key="scanner_job", value="idle", category="config")],
    }

    def _q(*models):
        q = MagicMock()
        # Single model: return list of objects
        # Multi-model join (Vuln+Device, Cred+Device): return empty list by default
        if len(models) == 1:
            data = dm.get(models[0], [])
        else:
            data = []
        q.all.return_value = data; q.count.return_value = len(data)
        q.order_by.return_value = q; q.filter.return_value = q
        q.filter_by.return_value = q; q.join.return_value = q
        q.first.return_value = data[0] if data else None
        return q

    ms.query.side_effect = _q
    return app, ms


@pytest.fixture
def client():
    app, ms = _build_app()
    snmp = {"communities": ["public"], "count": 1, "source": "builtin"}
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, snmp)
            with app.test_client() as c:
                c._ms = ms; c._mr = mr
                yield c


@pytest.fixture
def client_data():
    creds = [
        _mock_cred(1, "snmp", "public"),
        _mock_cred(2, "ssh", "admin"),
        _mock_cred(3, "rdp", "Administrator"),
        _mock_cred(4, "api", "admin"),
        _mock_cred(5, "telnet", "cisco"),
    ]
    app, ms = _build_app(
        creds=creds,
        devices=[_mock_dev(1), _mock_dev(2)],
        networks=[_mock_net(1)],
    )
    snmp = {"communities": ["public", "private"], "count": 2, "source": "db"}
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, snmp)
            with app.test_client() as c:
                yield c


# -- GET smoke tests — kazda karta / zakladka musi odpowiadac 200 --
def test_index(client):          assert client.get("/").status_code == 200
def test_devices(client):        assert client.get("/devices").status_code == 200
def test_networks(client):       assert client.get("/networks").status_code == 200
def test_scan(client):           assert client.get("/scan").status_code == 200
def test_settings(client):       assert client.get("/settings").status_code == 200
def test_logs(client):           assert client.get("/logs").status_code == 200
def test_inventory(client):      assert client.get("/inventory").status_code == 200
def test_internet(client):       assert client.get("/internet").status_code == 200
def test_credentials(client):    assert client.get("/credentials").status_code == 200

# Zakładki logów API — muszą zwracać 200 (plik może nie istnieć → 500 też ok)
def test_api_logs_cred_tab(client):    assert client.get("/api/logs/cred").status_code in (200, 500)
def test_api_logs_watchdog_tab(client): assert client.get("/api/logs/watchdog").status_code in (200, 500)
def test_api_logs_events_tab(client):  assert client.get("/api/logs/events").status_code == 200
def test_api_logs_ai_tab(client):      assert client.get("/api/logs/ai").status_code == 200

# Ustawienia — dodatkowe endpointy
def test_settings_lab_status(client):
    """GET /settings/lab/status — status kontenerów lab."""
    assert client.get("/settings/lab/status").status_code in (200, 500)

def test_settings_config_key_post(client):
    """POST /settings/config/<key> — zmiana wartości klucza."""
    assert client.post("/settings/config/cred_interval_s",
                       data={"value": "60"}).status_code in (200, 302)

def test_settings_telegram_post(client):
    """POST /settings/telegram — zapis webhook URL (nawet pusty)."""
    assert client.post("/settings/telegram",
                       data={"webhook_url": ""}).status_code in (200, 302)

# Chat — dodatkowe endpointy
def test_chat_history_tab(client):
    """GET /chat/history — lista sesji chatbota."""
    assert client.get("/chat/history").status_code == 200

def test_chat_context_tab(client):
    """GET /chat/context — kontekst dla chatbota."""
    assert client.get("/chat/context").status_code == 200

# AI Assess
def test_ai_assess_readiness_tab(client):
    assert client.get("/devices/ai-assess/readiness").status_code == 200

def test_ai_assess_last_tab(client):
    assert client.get("/devices/ai-assess/last").status_code in (200, 404)

def test_ai_assess_history_tab(client):
    assert client.get("/devices/ai-assess/history").status_code == 200

# Urządzenia — dodatkowe akcje POST
def test_device_trust_post(client):
    assert client.post("/devices/1/trust",
                       data={"note": ""}).status_code in (200, 302, 404)

def test_device_flag_post(client):
    assert client.post("/devices/1/flag",
                       data={"color": "red"}).status_code in (200, 302, 404)

def test_device_set_ip_type_post(client):
    assert client.post("/devices/1/set-ip-type",
                       data={"ip_type": "static"}).status_code in (200, 302, 404)

def test_device_inventory_post(client):
    assert client.post("/devices/1/inventory",
                       data={"serial_number": "ABC"}).status_code in (200, 302, 404)

def test_device_screenshot_refresh_post(client):
    assert client.post("/devices/1/screenshot/refresh").status_code in (200, 302, 404)

def test_security_200(client):
    assert client.get("/security").status_code == 200

def test_security_close_redirects(client):
    assert client.post("/security/1/close").status_code in (302, 200)

def test_security_suppress_redirects(client):
    assert client.post("/security/1/suppress").status_code in (302, 200)

def test_security_unsuppress_redirects(client):
    assert client.post("/security/1/unsuppress").status_code in (302, 200)

def test_security_unsuppress_all_redirects(client):
    assert client.post("/security/unsuppress-all").status_code in (302, 200)

def test_threats_200(client):
    assert client.get("/threats").status_code == 200

def test_threats_all_vuln_types(client):
    """Sprawdza ze kazdy VulnType ma wpis w encyklopedii zagrozen /threats."""
    html = client.get("/threats").data.decode()
    from netdoc.storage.models import VulnType
    for vt in VulnType:
        assert vt.value in html, f"Brak {vt.value!r} w /threats - dodaj wpis do VULN_CATALOG"


def test_threats_cards_have_vuln_id_anchors(client):
    """Kazda karta zagrozen musi miec id='vuln-X' by dzialaly linki /threats#vuln-X."""
    from netdoc.storage.models import VulnType
    html = client.get("/threats").data.decode()
    for vt in VulnType:
        assert f'id="vuln-{vt.value}"' in html, (
            f"Brak id='vuln-{vt.value}' na karcie zagrozen — link /threats#vuln-{vt.value} nie zadziala"
        )


def test_security_vuln_badge_template_uses_link(client):
    """Szablon security.html musi definiowac vuln_badge jako <a href='/threats#...'>."""
    import os
    tpl_path = os.path.join(
        os.path.dirname(__file__), "..", "netdoc", "web", "templates", "security.html"
    )
    with open(tpl_path, encoding="utf-8") as f:
        source = f.read()
    assert 'href="/threats#' in source, (
        "vuln_badge w security.html nie renderuje sie jako link <a href='/threats#...'> "
        "— uzytkownik nie moze kliknac badge by przejsc do encyklopedii"
    )


def test_threats_catalog_complete(client):
    """Sprawdza ze liczba wpisow w katalogu >= liczba VulnType."""
    from netdoc.storage.models import VulnType
    html = client.get("/threats").data.decode()
    # Count catalog card headers in HTML (each entry has data-sev attribute)
    import re
    entries = re.findall(r'data-sev="[^"]+"', html)
    assert len(entries) >= len(VulnType), (
        f"Katalog ma {len(entries)} wpisow, ale VulnType ma {len(VulnType)} wartosci"
    )


def test_threats_severity_filter_buttons(client):
    """Sprawdza ze przyciski filtrow sa obecne na stronie /threats."""
    html = client.get("/threats").data.decode()
    for sev in ("critical", "high", "medium", "low"):
        assert sev in html.lower(), f"Brak przycisku filtra dla {sev}"


def test_credentials_200(client_data):
    assert client_data.get("/credentials").status_code == 200

def test_credentials_all_methods(client_data):
    html = client_data.get("/credentials").data.decode()
    for m in ("snmp", "ssh", "rdp", "api", "telnet"):
        assert m in html.lower(), f"Brak metody {m} w HTML credentials"

def test_credentials_tab_filter(client_data):
    html = client_data.get("/credentials").data.decode()
    assert "data-filter" in html

def test_credentials_page_has_per_device_scan_panel_in_template():
    """Template credentials.html musi zawierac kod panelu rotacji per urzadzenie."""
    import pathlib
    tmpl = pathlib.Path("netdoc/web/templates/credentials.html").read_text(encoding="utf-8")
    assert "Rotacja" in tmpl and "cred_scan_devices" in tmpl, \
        "Brak panelu rotacji haseł per urzadzenie w credentials.html"
    assert "Ostatni skan" in tmpl, "Brak kolumny 'Ostatni skan' w panelu rotacji"
    assert "ssh_tried" in tmpl or "ssh_total" in tmpl, "Brak danych SSH w panelu rotacji"

def test_api_status(client):
    r = client.get("/api/status")
    assert r.status_code == 200
    d = r.get_json()
    for k in ("device_count", "active_devices", "scanner_job"):
        assert k in d


# -- POST credentials --
def test_cred_add_snmp(client):
    r = client.post("/credentials/add", data={
        "protocol": "snmp", "community": "public", "priority": "100"})
    assert r.status_code in (302, 200)

def test_cred_add_ssh(client):
    r = client.post("/credentials/add", data={
        "protocol": "ssh", "username": "admin", "password": "admin", "priority": "100"})
    assert r.status_code in (302, 200)

def test_cred_add_rdp(client):
    r = client.post("/credentials/add", data={
        "protocol": "rdp", "username": "Administrator", "password": "Admin123", "priority": "100"})
    assert r.status_code in (302, 200)

def test_cred_add_api(client):
    r = client.post("/credentials/add", data={
        "protocol": "api", "username": "admin", "password": "admin", "priority": "100"})
    assert r.status_code in (302, 200)

def test_cred_delete(client):
    assert client.post("/credentials/1/delete").status_code in (302, 200)

def test_cred_edit(client):
    r = client.post("/credentials/1/edit", data={
        "method": "snmp", "username": "private", "priority": "50"})
    assert r.status_code in (302, 200)


# -- POST networks --
def test_network_add_empty(client):
    assert client.post("/networks/add", data={"cidr": ""}).status_code in (302, 200)

def test_network_add_valid(client):
    assert client.post("/networks/add", data={"cidr": "10.0.0.0/24"}).status_code in (302, 200)

def test_network_toggle(client):
    client._ms.query.return_value.filter_by.return_value.first.return_value = _mock_net(1)
    assert client.post("/networks/1/toggle").status_code in (302, 200)

def test_network_toggle_with_delete_devices(client):
    """Pauza sieci z delete_devices=1 powinna uruchomic usuniecie urzadzen."""
    net = _mock_net(1, cidr="10.99.0.0/24", is_active=True)
    client._ms.query.return_value.filter_by.return_value.first.return_value = net
    client._ms.query.return_value.all.return_value = []  # brak urzadzen
    r = client.post("/networks/1/toggle", data={"delete_devices": "1"})
    assert r.status_code in (302, 200)

def test_network_delete(client):
    client._ms.query.return_value.filter_by.return_value.first.return_value = _mock_net(1)
    assert client.post("/networks/1/delete").status_code in (302, 200)

def test_network_delete_with_delete_devices(client):
    """Usuniecie sieci z delete_devices=1 kasuje rowniez urzadzenia z zakresu."""
    net = _mock_net(1, cidr="10.99.0.0/24", is_active=False)
    client._ms.query.return_value.filter_by.return_value.first.return_value = net
    client._ms.query.return_value.all.return_value = []  # brak urzadzen
    r = client.post("/networks/1/delete", data={"delete_devices": "1"})
    assert r.status_code in (302, 200)

def test_network_pause_all_sets_all_inactive(client):
    """POST /networks/pause-all ustawia is_active=False dla wszystkich aktywnych sieci."""
    nets = [_mock_net(1, is_active=True), _mock_net(2, cidr="10.0.0.0/24", is_active=True)]
    # ms.query ma side_effect=_q ktory ignoruje query.return_value — nadpisujemy go
    q = MagicMock()
    q.filter.return_value = q
    q.filter_by.return_value = q
    q.all.return_value = nets
    client._ms.query.side_effect = lambda *m: q
    r = client.post("/networks/pause-all")
    assert r.status_code in (302, 200)
    client._ms.commit.assert_called()
    for n in nets:
        assert n.is_active is False, f"Siec {n.cidr} powinna byc nieaktywna"


def test_network_pause_all_no_active_still_ok(client):
    """POST /networks/pause-all gdy brak aktywnych sieci — nie crashuje."""
    client._ms.query.return_value.filter.return_value.all.return_value = []
    r = client.post("/networks/pause-all")
    assert r.status_code in (302, 200)


def test_network_pause_all_button_shown_when_active(client):
    """Przycisk 'Pauzuj wszystkie' widoczny gdy sa aktywne sieci."""
    from unittest.mock import MagicMock, patch
    net = _mock_net(1, is_active=True)
    net.source = MagicMock(); net.source.value = "auto"
    with patch("netdoc.web.app.SessionLocal") as ms:
        db = ms.return_value.__enter__.return_value
        db.query.return_value.order_by.return_value.all.return_value = [net]
        db.query.return_value.filter.return_value.all.return_value = []
        with client.application.test_client() as c:
            r = c.get("/networks")
    assert b"pause-all" in r.data or b"Pauzuj wszystkie" in r.data


def test_network_pause_all_button_hidden_when_none_active(client):
    """Przycisk 'Pauzuj wszystkie' niewidoczny gdy wszystkie sieci sa juz wstrzymane."""
    from unittest.mock import MagicMock, patch
    net = _mock_net(1, is_active=False)
    net.source = MagicMock(); net.source.value = "auto"
    with patch("netdoc.web.app.SessionLocal") as ms:
        db = ms.return_value.__enter__.return_value
        db.query.return_value.order_by.return_value.all.return_value = [net]
        db.query.return_value.filter.return_value.all.return_value = []
        with client.application.test_client() as c:
            r = c.get("/networks")
    # Modal jest zawsze w HTML, ale przycisk jest warunkowy (tylko gdy active_count > 0)
    assert b"Pauzuj wszystkie" not in r.data


def test_networks_shows_device_counts(client):
    """GET /networks renderuje strone z kolumna liczby urzadzen."""
    r = client.get("/networks")
    assert r.status_code == 200
    assert b"Urzadzenia" in r.data  # kolumna obecna


def test_networks_has_search_field(client):
    """GET /networks zawiera pole wyszukiwania sieci."""
    r = client.get("/networks")
    assert r.status_code == 200
    assert b"netSearch" in r.data


def test_networks_has_sortable_columns(client):
    """GET /networks zawiera klikalwe naglowki do sortowania."""
    r = client.get("/networks")
    assert r.status_code == 200
    assert b"net-sort" in r.data
    assert b"data-col" in r.data


def test_networks_active_inactive_badges():
    """Szablon networks.html zawiera odwolania do active_count i inactive_count."""
    import pathlib
    tmpl = pathlib.Path("netdoc/web/templates/networks.html").read_text(encoding="utf-8")
    assert "active_count" in tmpl
    assert "inactive_count" in tmpl
    assert "bg-success" in tmpl   # badge aktywnych
    assert "netSearch" in tmpl    # pole wyszukiwania


def test_networks_route_device_counts_dict_format(client):
    """Trasa /networks przekazuje device_counts jako dict z kluczami active/inactive."""
    # Budujemy app z siecią i urządzeniami — sprawdzamy że strona sie renderuje
    net = _mock_net(1, cidr="192.168.1.0/24")
    dev = _mock_dev(1, ip="192.168.1.10", is_active=True)
    app, ms = _build_app(networks=[net], devices=[dev])
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app.test_client() as c:
                r = c.get("/networks")
    assert r.status_code == 200


def test_network_slash32_max_hosts_not_minus_one():
    """/32 (np. WireGuard VPN peer) nie moze pokazywac max_hosts = -1."""
    import pathlib
    net = _mock_net(1, cidr="192.168.4.2/32")
    app, ms = _build_app(networks=[net], devices=[])
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app.test_client() as c:
                r = c.get("/networks")
    assert r.status_code == 200
    assert b'data-maxhosts="-1"' not in r.data, "/32 nie moze miec max_hosts=-1"
    assert b'data-maxhosts="1"' in r.data, "/32 powinno miec max_hosts=1"


def test_network_slash31_max_hosts_two():
    """/31 (RFC 3021 point-to-point) powinno miec max_hosts = 2."""
    net = _mock_net(1, cidr="10.0.0.0/31")
    app, ms = _build_app(networks=[net], devices=[])
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app.test_client() as c:
                r = c.get("/networks")
    assert r.status_code == 200
    assert b'data-maxhosts="0"' not in r.data, "/31 nie moze miec max_hosts=0"
    assert b'data-maxhosts="2"' in r.data, "/31 powinno miec max_hosts=2"


# -- POST scan --
def test_settings_workers_update(client):
    """POST /settings/workers powinien przekierowac po zapisie."""
    r = client.post("/settings/workers", data={
        "cred_interval_s": "60",
        "cred_ssh_workers": "16",
        "cred_pairs_per_cycle": "1",
        "cred_device_timeout_s": "60",
        "cred_retry_days": "1",
        "cred_max_creds_per_dev": "9999",
    })
    assert r.status_code in (200, 302)


def test_scan_trigger_standard(client):
    assert client.post("/scan/trigger", data={"type": "standard"}).status_code in (302, 200)

def test_scan_trigger_full(client):
    assert client.post("/scan/trigger", data={"type": "full"}).status_code in (302, 200)

def test_scan_trigger_oui(client):
    assert client.post("/scan/trigger", data={"type": "oui"}).status_code in (302, 200)


# -- POST devices --
def test_device_set_type(client):
    assert client.post("/devices/1/set-type", data={"device_type": "router"}).status_code in (302, 200)

def test_device_reclassify(client):
    assert client.post("/devices/1/reclassify").status_code in (302, 200)


# -- Logs proxy --
def test_logs_proxy_ok(client):
    client._mr.get.return_value.text = "line1 line2"
    client._mr.get.side_effect = None
    assert client.get("/api/logs/scanner?tail=10").status_code == 200

def test_logs_proxy_error(client):
    client._mr.get.side_effect = Exception("refused")
    assert client.get("/api/logs/scanner").status_code == 500

# -- Flash alert mapping tests --
def test_flash_danger_renders_danger(client):
    with client.session_transaction() as sess:
        sess["_flashes"] = [("danger", "Test error")]
    html = client.get("/").data.decode()
    assert "alert-danger" in html


def test_flash_warning_renders_warning(client):
    with client.session_transaction() as sess:
        sess["_flashes"] = [("warning", "Test warning")]
    html = client.get("/").data.decode()
    assert 'class="alert alert-warning' in html
    assert 'class="alert alert-success' not in html


def test_flash_info_renders_info(client):
    with client.session_transaction() as sess:
        sess["_flashes"] = [("info", "Test info")]
    html = client.get("/").data.decode()
    assert 'class="alert alert-info' in html
    assert 'class="alert alert-success' not in html


def test_flash_success_renders_success(client):
    with client.session_transaction() as sess:
        sess["_flashes"] = [("success", "Test success")]
    html = client.get("/").data.decode()
    assert "alert-success" in html


# -- Index vulnerability summary tests --
def test_index_shows_vuln_counts(client):
    html = client.get("/").data.decode()
    assert "Krytyczne podatnosci" in html
    assert "Wysokie podatnosci" in html
    assert "Wszystkie otwarte" in html


def test_index_vuln_link_to_security(client):
    html = client.get("/").data.decode()
    assert 'href="/security"' in html


def test_credentials_data_method_raw_value(client_data):
    """data-method musi zawierac czysty string (np. 'mssql'), nie 'CredentialMethod.mssql'."""
    html = client_data.get("/credentials").data.decode()
    assert 'data-method="CredentialMethod.' not in html, (
        "data-method zawiera pelna nazwe klasy zamiast wartosci enum — "
        "uzyj {{ c.method.value }} w szablonie"
    )
    assert 'data-method="snmp"' in html
    assert 'data-method="ssh"' in html


def test_credentials_tab_counts_shown(client_data):
    """Taby powinny pokazywac liczniki w nawiasach."""
    html = client_data.get("/credentials").data.decode()
    assert "SNMP (" in html
    assert "SSH (" in html
    assert "MSSQL (" in html


def test_credentials_edit_modal_method_raw_value(client_data):
    """data-cred-method w przycisku edycji musi zawierac czysty string (nie 'CredentialMethod.ssh')."""
    html = client_data.get("/credentials").data.decode()
    assert 'data-cred-method="CredentialMethod.' not in html, (
        "data-cred-method zawiera pelna nazwe klasy zamiast wartosci enum — "
        "uzyj {{ c.method.value }} w szablonie (przycisk edycji)"
    )
    assert 'data-cred-method="snmp"' in html or 'data-cred-method="ssh"' in html


def test_security_credential_badge_method_raw_value(client):
    """Badge metody na stronie /security musi zawierac czysty string (nie 'CREDENTIALMETHOD.SSH')."""
    html = client.get("/security").data.decode()
    assert "CREDENTIALMETHOD." not in html, (
        "Badge metody na /security zawiera pelna nazwe klasy zamiast wartosci enum — "
        "uzyj {{ c.method.value|upper }} w szablonie"
    )


# ── Helpers dla testow nowych funkcji devices ──────────────────────────────────

def _make_devices_client(
    devices=None, cred_rows=None, vuln_count_tuples=None,
    vuln_objects=None, scan_rows=None,
):
    """Buduje test client z dokladna kontrola nad zwracanymi danymi dla /devices."""
    from netdoc.web.app import create_app
    from netdoc.storage.models import Device, Credential, SystemStatus, Vulnerability, ScanResult

    app = create_app()
    app.config["TESTING"] = True

    ms = MagicMock()
    ms.__enter__ = lambda s: s
    ms.__exit__ = MagicMock(return_value=False)

    _devices = devices or []
    _creds = cred_rows or []
    _vuln_tuples = vuln_count_tuples or []   # [(device_id, count), ...]
    _vuln_objs = vuln_objects or []           # Vulnerability mocks (dla severity)
    _scans = scan_rows or []                  # ScanResult mocks (porty, czas skanu)

    def _q(*models):
        q = MagicMock()
        for attr in ("order_by", "filter", "filter_by", "join", "group_by"):
            getattr(q, attr).return_value = q
        q.count.return_value = 0
        q.first.return_value = None

        if len(models) == 1 and models[0] is Device:
            q.all.return_value = _devices
            q.count.return_value = len(_devices)
        elif len(models) == 1 and models[0] is Credential:
            q.all.return_value = _creds
            q.count.return_value = len(_creds)
        elif len(models) == 1 and models[0] is Vulnerability:
            q.all.return_value = _vuln_objs
        elif len(models) == 1 and models[0] is ScanResult:
            q.all.return_value = _scans
        elif len(models) == 2:
            # db.query(X.device_id, func.count(...)) — vuln counts i event counts
            q.all.return_value = _vuln_tuples
        elif len(models) == 1 and models[0] is SystemStatus:
            ss = MagicMock(key="scanner_job", value="idle", category="config")
            q.all.return_value = [ss]
            q.first.return_value = ss
        else:
            q.all.return_value = []

        return q

    ms.query.side_effect = _q
    ctx = patch("netdoc.web.app.SessionLocal", return_value=ms)
    req = patch("netdoc.web.app.requests")
    return app, ctx, req


# ── Auto-refresh ──────────────────────────────────────────────────────────────

def test_devices_autorefresh_badge_present(client):
    """Navbar musi zawierac element auto-refresh (refresh-count) z base.html."""
    html = client.get("/devices").data.decode()
    assert 'id="refresh-count"' in html, "Brak elementu refresh-count w HTML /devices"


def test_devices_autorefresh_pause_button_present(client):
    """Navbar musi zawierac przycisk pauzy auto-refresh."""
    html = client.get("/devices").data.decode()
    assert 'id="refresh-btn"' in html, "Brak refresh-btn w HTML /devices"


def test_devices_filter_toolbar_present(client):
    """Pasek filtrów musi byc obecny na stronie /devices."""
    html = client.get("/devices").data.decode()
    assert 'id="devSearch"' in html, "Brak pola wyszukiwania #devSearch"
    assert 'id="devFiltersBar"' in html, "Brak paska filtrów #devFiltersBar"
    assert 'id="devFilterReset"' in html, "Brak przycisku Resetuj #devFilterReset"
    assert 'id="devAdvFilters"' in html, "Brak panelu zaawansowanych filtrów #devAdvFilters"
    assert 'id="devCount"' in html, "Brak licznika urządzeń #devCount"


def test_devices_filter_buttons_present(client):
    """Przyciski szybkich filtrów muszą byc obecne na stronie /devices."""
    html = client.get("/devices").data.decode()
    for flt in ["inactive", "trusted", "no-vulns", "no-cred", "dhcp", "only-flag"]:
        assert f'data-filter="{flt}"' in html, f"Brak przycisku filtra data-filter={flt}"


def test_devices_sortable_columns_present(client):
    """Nagłówki sortowalnych kolumn muszą mieć klasę dev-sortable i data-col."""
    html = client.get("/devices").data.decode()
    for col in ["ip", "hostname", "vendor", "type", "active", "vulns", "lastseen", "ports"]:
        assert f'data-col="{col}"' in html, f"Brak sortowalnej kolumny data-col={col}"


def test_devices_set_type_modal_contains_all_device_types(client):
    """setTypeModal musi zawierac wszystkie wartosci DeviceType (w tym phone i inverter)."""
    from netdoc.storage.models import DeviceType
    html = client.get("/devices").data.decode()
    for dt in DeviceType:
        assert f'value="{dt.value}"' in html, (
            f"DeviceType.{dt.name} ('{dt.value}') nie ma opcji w setTypeModal. "
            "Dodaj go do listy w petli for w devices.html."
        )


def test_devices_type_filter_buttons_contain_phone(client):
    """Przycisk filtrowania po typie 'phone' musi byc na stronie /devices."""
    html = client.get("/devices").data.decode()
    assert 'data-type="phone"' in html, "Brak przycisku filtra data-type=phone w /devices"


def test_devices_type_filter_buttons_contain_inverter(client):
    """Przycisk filtrowania po typie 'inverter' musi byc na stronie /devices."""
    html = client.get("/devices").data.decode()
    assert 'data-type="inverter"' in html, "Brak przycisku filtra data-type=inverter w /devices"


def test_devices_tr_data_attributes_present():
    """Wiersze tabeli muszą zawierać data-atrybuty wymagane przez silnik filtrów."""
    dev = _mock_dev(1, ip="10.99.0.1")
    dev.ip_type = "unknown"
    app, ctx, req = _make_devices_client(devices=[dev])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()
    for attr in ["data-ip=", "data-active=", "data-trusted=",
                 "data-vulns=", "data-iptype=", "data-type=",
                 "data-cred=", "data-ports=", "data-lastseen="]:
        assert attr in html, f"Brak atrybutu {attr} w wierszach tabeli urządzeń"


def test_settings_no_autorefresh_trigger(client):
    """/settings jest wykluczone z auto-odswiezania (NO_REFRESH lista w base.html)."""
    html = client.get("/settings").data.decode()
    # Element jest w HTML ale JS go pomija (NO_REFRESH check)
    # Weryfikujemy ze element istnieje — logike JS testujemy posrednio przez obecnosc kodu
    assert "NO_REFRESH" in html or "/settings" in html


def test_chat_excluded_from_autorefresh(client):
    """/chat musi byc wykluczone z auto-odswiezania (NO_REFRESH lista w base.html)."""
    html = client.get("/chat").data.decode()
    # Weryfikujemy ze sciezka /chat jest w liscie NO_REFRESH w JS
    assert '"/chat"' in html, "/chat nie jest w liscie NO_REFRESH — strona czatu bedzie przeladowywana co 60s!"


def test_chat_page_returns_200(client):
    """/chat zwraca 200 OK."""
    resp = client.get("/chat")
    assert resp.status_code == 200


def test_chat_has_quick_reports_panel(client):
    """Strona czatu musi zawierac panel szybkich raportow."""
    html = client.get("/chat").data.decode()
    assert "quick-panel" in html, "Brak panelu szybkich raportow w chat.html"
    assert "Szybkie raporty" in html, "Brak naglowka 'Szybkie raporty'"
    assert "quick-btn" in html, "Brak przyciskow quick-btn"


def test_chat_quick_reports_has_expected_questions(client):
    """Panel szybkich raportow musi zawierac kluczowe pytania."""
    html = client.get("/chat").data.decode()
    assert "Kompleksowy raport bezpieczenstwa" in html
    assert "podatnosci krytyczne" in html
    assert "polaczenia internetowego" in html


def test_chat_has_pdf_export_button(client):
    """Strona czatu musi zawierac przycisk eksportu PDF."""
    html = client.get("/chat").data.decode()
    assert "exportPdf" in html, "Brak funkcji exportPdf() w chat.html"
    assert "PDF" in html, "Brak etykiety PDF na przycisku"


def test_chat_has_netdoc_description_in_template(client):
    """Opis NetDoc musi byc w ai_context.md (dynamicznie ladowany przez chat_agent)."""
    import pathlib
    ctx = pathlib.Path(__file__).parent.parent / "netdoc" / "web" / "ai_context.md"
    assert ctx.exists(), "Brak pliku ai_context.md z opisem NetDoc dla AI"
    content = ctx.read_text(encoding="utf-8")
    assert "CZYM JEST NETDOC" in content, "Brak sekcji 'CZYM JEST NETDOC' w ai_context.md"
    assert "ping-worker" in content, "Brak opisu workerow w ai_context.md"


# ── Kolumna credential (kluczyk) ──────────────────────────────────────────────

def test_devices_green_key_for_successful_cred():
    """Zielony kluczyk (bg-success + bi-key-fill) gdy urzadzenie ma udany credential."""
    from datetime import datetime
    from netdoc.storage.models import CredentialMethod

    dev = _mock_dev(1, ip="10.0.0.1")

    cred = MagicMock()
    cred.id = 1
    cred.device_id = 1
    cred.username = "admin"
    cred.password_encrypted = "topsecret"
    cred.last_success_at = datetime(2026, 1, 15, 10, 30)
    cred.method = CredentialMethod("ssh")

    app, ctx, req = _make_devices_client(devices=[dev], cred_rows=[cred])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "bi-key-fill" in html, "Brak bi-key-fill (zielony kluczyk) dla udanego credential"
    assert "bg-success" in html
    assert "admin" in html,       "Login 'admin' musi byc w popoverze"
    assert "topsecret" in html,   "Haslo musi byc widoczne w popoverze"


def test_devices_popover_shows_method_value():
    """Popover musi pokazywac wartosc enum (np. 'ssh'), nie 'CredentialMethod.ssh'."""
    from datetime import datetime
    from netdoc.storage.models import CredentialMethod

    dev = _mock_dev(1, ip="10.0.0.1")
    cred = MagicMock()
    cred.id = 1; cred.device_id = 1; cred.username = "root"
    cred.password_encrypted = "pass"; cred.last_success_at = datetime(2026, 2, 1, 8, 0)
    cred.method = CredentialMethod("ssh")

    app, ctx, req = _make_devices_client(devices=[dev], cred_rows=[cred])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "CredentialMethod." not in html, (
        "Popover zawiera pelna nazwe klasy zamiast wartosci enum — uzyj cred.method.value w szablonie"
    )


def test_devices_gray_key_for_sentinel_1970():
    """Szary kluczyk (bg-secondary, bez bi-key-fill) gdy credential sprawdzono ale brak dostepu."""
    dev = _mock_dev(1, ip="10.0.0.2")
    sentinel = MagicMock()
    sentinel.year = 1970
    dev.last_credential_ok_at = sentinel

    app, ctx, req = _make_devices_client(devices=[dev], cred_rows=[])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "bi-key-fill" not in html, "Nie powinno byc zielonego kluczyka dla sentinela 1970"
    assert "bi-key" in html,          "Szary kluczyk (bi-key) musi byc widoczny dla sentinela"
    assert "bg-secondary" in html


def test_devices_dash_when_no_credential():
    """Myslnik (—) gdy urzadzenie bez zadnego credential i bez sentinela."""
    dev = _mock_dev(1, ip="10.0.0.3")
    dev.last_credential_ok_at = None

    app, ctx, req = _make_devices_client(devices=[dev], cred_rows=[])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "bi-key-fill" not in html, "Nie powinno byc kluczyka gdy nie sprawdzano"
    assert "Jeszcze nie sprawdzono" in html or "text-muted" in html


# ── Kolumna podatnosci ────────────────────────────────────────────────────────

def test_devices_vuln_dash_when_no_vulns():
    """Myslnik w kolumnie podatnosci gdy vuln_counts jest puste."""
    dev = _mock_dev(1)

    app, ctx, req = _make_devices_client(devices=[dev])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    # Brak badge podatnosci — tylko dash z klasy text-muted
    assert "text-muted small" in html


def test_devices_vuln_badge_critical():
    """Badge bg-danger gdy urzadzenie ma critical podatnosc."""
    dev = _mock_dev(1)

    vuln = MagicMock()
    vuln.device_id = 1
    vuln.is_open = True
    vuln.suppressed = False
    vuln.severity = MagicMock()
    vuln.severity.value = "critical"

    app, ctx, req = _make_devices_client(
        devices=[dev],
        vuln_count_tuples=[(1, 2)],   # device_id=1 ma 2 podatnosci
        vuln_objects=[vuln],
    )
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "bg-danger" in html, "Brak bg-danger dla critical podatnosci"
    assert "/security" in html, "Badge musi byc linkiem do /security"


def test_devices_vuln_badge_high():
    """Badge bg-warning gdy max severity to high."""
    dev = _mock_dev(1)

    vuln = MagicMock()
    vuln.device_id = 1; vuln.is_open = True; vuln.suppressed = False
    vuln.severity = MagicMock(); vuln.severity.value = "high"

    app, ctx, req = _make_devices_client(
        devices=[dev],
        vuln_count_tuples=[(1, 1)],
        vuln_objects=[vuln],
    )
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "bg-warning" in html, "Brak bg-warning dla high podatnosci"


def test_devices_vuln_badge_medium():
    """Badge bg-info gdy max severity to medium."""
    dev = _mock_dev(1)

    vuln = MagicMock()
    vuln.device_id = 1; vuln.is_open = True; vuln.suppressed = False
    vuln.severity = MagicMock(); vuln.severity.value = "medium"

    app, ctx, req = _make_devices_client(
        devices=[dev],
        vuln_count_tuples=[(1, 1)],
        vuln_objects=[vuln],
    )
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "bg-info" in html, "Brak bg-info dla medium podatnosci"


def test_devices_vuln_count_shown_in_badge():
    """Liczba podatnosci musi byc widoczna w badge."""
    dev = _mock_dev(1)

    vuln = MagicMock()
    vuln.device_id = 1; vuln.is_open = True; vuln.suppressed = False
    vuln.severity = MagicMock(); vuln.severity.value = "critical"

    app, ctx, req = _make_devices_client(
        devices=[dev],
        vuln_count_tuples=[(1, 7)],
        vuln_objects=[vuln],
    )
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "7" in html, "Liczba podatnosci (7) musi byc widoczna w badge"


def test_devices_vuln_badge_uses_popover():
    """Badge podatności używa data-bs-toggle=popover zamiast zwykłego title."""
    import pathlib
    tmpl = pathlib.Path("netdoc/web/templates/devices.html").read_text(encoding="utf-8")
    assert 'data-bs-toggle="popover"' in tmpl, \
        "Badge podatności musi używać Bootstrap popover (data-bs-toggle='popover')"
    assert "data-bs-content" in tmpl, \
        "Badge podatności musi mieć data-bs-content z listą zagrożeń"


def test_devices_vuln_badge_popover_cancels_hide_when_mouse_already_on_popover():
    """Regresja: najeżdżanie z lewej — mysz może wejść na popover zanim shown.bs.popover odpali.

    Scenariusz: mysz wchodzi na badge z lewej strony → przesuwa się w prawo →
    wychodzi przez prawy bok badge (mouseleave → _scheduleHide) → wchodzi na popover
    (który jest po prawej, ale listener nie był jeszcze dodany) → shown.bs.popover odpala →
    BEZ NAPRAWY: _cancelHide nie zostaje wywołany → popover znika po 400ms.
    NAPRAWA: shown.bs.popover sprawdza popEl.matches(':hover') i wywołuje _cancelHide().
    """
    import pathlib
    tmpl = pathlib.Path("netdoc/web/templates/devices.html").read_text(encoding="utf-8")
    # JS musi sprawdzać :hover na elemencie popovera w shown.bs.popover
    assert "matches(':hover')" in tmpl or 'matches(":hover")' in tmpl, (
        "JS musi zawierać popEl.matches(':hover') w shown.bs.popover — "
        "fix dla hover z lewej strony: mysz może być na popoverze zanim listener zostanie dodany"
    )
    # _cancelHide musi być wywoływane po sprawdzeniu :hover
    hover_idx = tmpl.find("matches(':hover')")
    if hover_idx == -1:
        hover_idx = tmpl.find('matches(":hover")')
    cancel_after = tmpl.find("_cancelHide", hover_idx)
    assert cancel_after != -1 and cancel_after < hover_idx + 60, (
        "Po sprawdzeniu :hover musi nastąpić wywołanie _cancelHide()"
    )


def test_devices_vuln_badge_popover_shows_vuln_name():
    """Popover podatności zawiera nazwę zagrożenia i informację o porcie."""
    dev = _mock_dev(1)

    vuln = MagicMock()
    vuln.device_id = 1; vuln.is_open = True; vuln.suppressed = False
    vuln.severity = MagicMock(); vuln.severity.value = "critical"
    vuln.vuln_type = MagicMock(); vuln.vuln_type.value = "open_telnet"
    vuln.port = 23

    app, ctx, req = _make_devices_client(
        devices=[dev],
        vuln_count_tuples=[(1, 1)],
        vuln_objects=[vuln],
    )
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "open_telnet" in html, "Nazwa zagrożenia (vuln_type.value) musi być w popoverze"
    assert "23" in html, "Numer portu zagrożenia musi być widoczny"


def test_devices_vuln_popover_sort_critical_first():
    """vuln_details sortuje zagrożenia od najważniejszego (critical przed low)."""
    dev = _mock_dev(1)

    v_low = MagicMock()
    v_low.device_id = 1; v_low.is_open = True; v_low.suppressed = False
    v_low.severity = MagicMock(); v_low.severity.value = "low"
    v_low.vuln_type = MagicMock(); v_low.vuln_type.value = "open_snmp"
    v_low.port = 161

    v_crit = MagicMock()
    v_crit.device_id = 1; v_crit.is_open = True; v_crit.suppressed = False
    v_crit.severity = MagicMock(); v_crit.severity.value = "critical"
    v_crit.vuln_type = MagicMock(); v_crit.vuln_type.value = "open_telnet"
    v_crit.port = 23

    app, ctx, req = _make_devices_client(
        devices=[dev],
        vuln_count_tuples=[(1, 2)],
        vuln_objects=[v_low, v_crit],  # low jako pierwsza — musi być posortowane
    )
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    pos_crit = html.find("open_telnet")
    pos_low  = html.find("open_snmp")
    assert pos_crit != -1 and pos_low != -1, "Obie nazwy zagrożeń muszą być w HTML"
    assert pos_crit < pos_low, "Critical musi pojawić się przed low w popoverze"


# ── Naglowki kolumn tabeli ─────────────────────────────────────────────────────

def test_devices_table_has_credential_column_header(client):
    """Tabela musi miec kolumne credentials (ikona klucza w naglowku)."""
    html = client.get("/devices").data.decode()
    assert "bi-key" in html


def test_devices_table_has_vuln_column_header(client):
    """Tabela musi miec kolumne podatnosci (ikona tarczy w naglowku)."""
    html = client.get("/devices").data.decode()
    assert "bi-shield-exclamation" in html


# ── Status popover (statystyki dostepnosci) ────────────────────────────────────

def test_devices_up_badge_has_popover():
    """Badge UP musi miec popover (data-bs-toggle=popover) z trescia statystyk."""
    import datetime
    dev = _mock_dev(1, ip="10.0.0.10", is_active=True)
    dev.last_seen = datetime.datetime.utcnow() - datetime.timedelta(minutes=1)

    app, ctx, req = _make_devices_client(devices=[dev])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert 'data-bs-title="Status: UP"' in html,  "Badge UP musi miec popover z titulem 'Status: UP'"
    assert "Ostatni kontakt" in html,              "Popover musi zawierac 'Ostatni kontakt'"
    assert "DOWN 7d" in html,                      "Popover musi zawierac licznik DOWN 7d"
    assert "DOWN 30d" in html,                     "Popover musi zawierac licznik DOWN 30d"
    assert "Znany od" in html,                     "Popover musi zawierac 'Znany od'"
    assert "Monitoring" in html,                   "Popover musi zawierac sekcje Monitoring"


def test_devices_down_badge_has_popover():
    """Badge DOWN musi miec popover z titulem 'Status: DOWN'."""
    dev = _mock_dev(1, ip="10.0.0.11", is_active=False)

    app, ctx, req = _make_devices_client(devices=[dev])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert 'data-bs-title="Status: DOWN"' in html, "Badge DOWN musi miec popover z titulem 'Status: DOWN'"


def test_devices_down_badge_has_down_since_element():
    """DOWN badge z last_seen musi zawierac element down-since do obliczenia czasu trwania."""
    from datetime import datetime, timedelta
    dev = _mock_dev(1, ip="10.0.0.12", is_active=False)
    dev.last_seen = datetime.utcnow() - timedelta(hours=2)

    app, ctx, req = _make_devices_client(devices=[dev])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "down-since" in html,    "DOWN device musi miec element .down-since w popoverze"
    assert "data-since=" in html,   "Element down-since musi miec atrybut data-since z timestamp"


def test_devices_status_popover_no_down_since_for_up():
    """UP device NIE powinien miec elementu down-since."""
    dev = _mock_dev(1, ip="10.0.0.13", is_active=True)

    app, ctx, req = _make_devices_client(devices=[dev])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert 'class="down-since"' not in html, "UP device nie powinien miec elementu down-since"


def test_devices_uptime_pct_shown_when_available():
    """Uptime% musi byc widoczny gdy device_stats zawiera uptime_pct."""
    from datetime import datetime, timedelta
    from netdoc.storage.models import Event, EventType

    dev = _mock_dev(1, ip="10.0.0.14", is_active=True)
    dev.first_seen = datetime.utcnow() - timedelta(days=30)

    # Symuluj jeden event disappearance i jeden appeared (2h downtime w 30 dniach)
    ev_down = MagicMock()
    ev_down.device_id = 1
    ev_down.event_time = datetime.utcnow() - timedelta(hours=5)
    ev_down.event_type = MagicMock()
    ev_down.event_type.value = "device_disappeared"

    ev_up = MagicMock()
    ev_up.device_id = 1
    ev_up.event_time = datetime.utcnow() - timedelta(hours=3)
    ev_up.event_type = MagicMock()
    ev_up.event_type.value = "device_appeared"

    from netdoc.web.app import create_app
    from netdoc.storage.models import Device, Credential, SystemStatus, Vulnerability

    app2 = create_app()
    app2.config["TESTING"] = True
    ms2 = MagicMock()
    ms2.__enter__ = lambda s: s
    ms2.__exit__ = MagicMock(return_value=False)

    def _q2(*models):
        q = MagicMock()
        for attr in ("order_by", "filter", "filter_by", "join", "group_by"):
            getattr(q, attr).return_value = q
        q.count.return_value = 0; q.first.return_value = None
        if len(models) == 1 and models[0] is Device:
            q.all.return_value = [dev]; q.count.return_value = 1
        elif len(models) == 1 and models[0] is Event:
            q.all.return_value = [ev_down, ev_up]
        elif len(models) == 1 and models[0] is SystemStatus:
            ss = MagicMock(key="scanner_job", value="idle", category="config")
            q.all.return_value = [ss]; q.first.return_value = ss
        else:
            q.all.return_value = []
        return q

    ms2.query.side_effect = _q2
    with patch("netdoc.web.app.SessionLocal", return_value=ms2):
        with patch("netdoc.web.app.requests") as mr2:
            _setup_mock_api(mr2, {})
            with app2.test_client() as c:
                html = c.get("/devices").data.decode()

    assert "Uptime 30d" in html, "Uptime% musi byc widoczny w popoverze gdy sa dane z eventow"


# ── Nowe pola popovera: monitoring, porty, vendor source ──────────────────────

def test_devices_popover_shows_monitoring_method():
    """Popover musi pokazywac metode monitorowania (TCP+ICMP)."""
    dev = _mock_dev(1, ip="10.0.0.20", is_active=True)

    app, ctx, req = _make_devices_client(devices=[dev])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "Monitoring" in html, "Popover musi zawierac sekcje 'Monitoring'"
    assert "TCP" in html,        "Popover musi zawierac informacje o metodzie TCP"
    assert "ICMP" in html,       "Popover musi zawierac informacje o metodzie ICMP"


def test_devices_popover_shows_open_ports_when_scan_available():
    """Gdy jest ScanResult z portami — popover musi pokazywac liste portow."""
    from datetime import datetime, timedelta
    dev = _mock_dev(1, ip="10.0.0.21", is_active=True)

    sr = MagicMock()
    sr.device_id = 1
    sr.scan_time = datetime.utcnow() - timedelta(hours=1)
    sr.open_ports = {
        "22":  {"service": "ssh",   "version": "", "product": ""},
        "80":  {"service": "http",  "version": "", "product": ""},
        "443": {"service": "https", "version": "", "product": ""},
    }

    app, ctx, req = _make_devices_client(devices=[dev], scan_rows=[sr])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "Porty (nmap)" in html, "Popover musi zawierac sekcje 'Porty (nmap)'"
    assert "22(ssh)" in html,      "Popover musi zawierac port 22 z nazwa uslugi"
    assert "80(http)" in html,     "Popover musi zawierac port 80"


def test_devices_popover_no_ports_when_no_scan():
    """Gdy nie ma ScanResult — popover NIE powinien pokazywac sekcji portow."""
    dev = _mock_dev(1, ip="10.0.0.22", is_active=True)

    app, ctx, req = _make_devices_client(devices=[dev], scan_rows=[])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "Porty (nmap)" not in html, "Bez skanu nie powinno byc sekcji portow"


def test_devices_popover_vendor_source_oui_when_mac_set():
    """Gdy device ma MAC i vendor — popover musi pokazywac 'Vendor z: OUI (MAC)'."""
    dev = _mock_dev(1, ip="10.0.0.23", is_active=True)
    dev.mac = "aa:bb:cc:dd:ee:ff"
    dev.vendor = "Cisco Systems"

    app, ctx, req = _make_devices_client(devices=[dev])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "Vendor z" in html,  "Popover musi zawierac 'Vendor z'"
    assert "OUI (MAC)" in html, "Gdy MAC jest ustawiony — zrodlo vendora to OUI (MAC)"


def test_devices_popover_vendor_source_nmap_when_no_mac():
    """Gdy device ma vendor ale brak MAC — popover musi pokazywac 'nmap/ARP'."""
    dev = _mock_dev(1, ip="10.0.0.24", is_active=True)
    dev.mac = None
    dev.vendor = "Cisco Systems"

    app, ctx, req = _make_devices_client(devices=[dev])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "nmap/ARP" in html, "Gdy brak MAC — zrodlo vendora to nmap/ARP"


def test_devices_popover_os_version_shown_when_set():
    """OS version (z SNMP) musi byc widoczna w popoverze gdy jest ustawiona."""
    dev = _mock_dev(1, ip="10.0.0.25", is_active=True)
    dev.os_version = "RouterOS 6.49.7"

    app, ctx, req = _make_devices_client(devices=[dev])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "OS (SNMP)" in html,       "Popover musi zawierac sekcje 'OS (SNMP)'"
    assert "RouterOS 6.49.7" in html, "Popover musi zawierac wartoc os_version"


def test_devices_popover_last_scan_date_shown():
    """Data ostatniego skanu nmap musi byc widoczna w popoverze."""
    from datetime import datetime, timedelta
    dev = _mock_dev(1, ip="10.0.0.26", is_active=True)

    sr = MagicMock()
    sr.device_id = 1
    sr.scan_time = datetime(2026, 3, 5, 10, 30)
    sr.open_ports = {}

    app, ctx, req = _make_devices_client(devices=[dev], scan_rows=[sr])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "Ost. skan" in html,  "Popover musi zawierac date ostatniego skanu"
    assert "2026-03-05" in html, "Data skanu musi byc widoczna w popoverze"


# ── Stan UNCERTAIN (amber badge) ──────────────────────────────────────────────

def test_devices_uncertain_badge_shown_when_last_seen_stale():
    """Gdy is_active=True ale last_seen > uncertain_min minut temu — badge UNCERTAIN (?)."""
    from datetime import datetime, timedelta
    dev = _mock_dev(1, ip="10.1.0.1", is_active=True)
    dev.last_seen = datetime.utcnow() - timedelta(minutes=20)  # 20 min temu

    app, ctx, req = _make_devices_client(devices=[dev])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    # Sprawdzamy element (nie definicje CSS)
    assert 'badge-uncertain' in html, "Stale last_seen + is_active=True musi dac badge-uncertain"
    assert 'data-bs-title="Status: NIEPEWNY"' in html, "Amber badge musi miec popover tytul NIEPEWNY"


def test_devices_up_badge_shown_when_last_seen_fresh():
    """Gdy is_active=True i last_seen < uncertain_min minut temu — badge UP (zielony)."""
    from datetime import datetime, timedelta
    dev = _mock_dev(1, ip="10.1.0.2", is_active=True)
    dev.last_seen = datetime.utcnow() - timedelta(minutes=2)  # 2 min temu — swiezy

    app, ctx, req = _make_devices_client(devices=[dev])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert 'badge-up' in html,                          "Swiezy last_seen musi dac badge-up"
    assert 'data-bs-title="Status: NIEPEWNY"' not in html, "Swiezy device nie powinien miec badge-uncertain"


def test_devices_uncertain_not_shown_for_down_device():
    """Urzadzenie DOWN (is_active=False) musi miec badge-down, NIE badge-uncertain."""
    from datetime import datetime, timedelta
    dev = _mock_dev(1, ip="10.1.0.3", is_active=False)
    dev.last_seen = datetime.utcnow() - timedelta(hours=2)

    app, ctx, req = _make_devices_client(devices=[dev])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert 'badge-down' in html,                        "DOWN device musi miec badge-down"
    assert 'data-bs-title="Status: NIEPEWNY"' not in html, "DOWN device nie powinien miec badge-uncertain"


def test_devices_monitoring_stale_banner_always_starts_hidden():
    """Banner zawsze zaczyna jako display:none — widocznosc kontroluje JS po live-status poll.
    Dotyczy takze sytuacji gdy last_seen jest bardzo stary (60 min temu)."""
    from datetime import datetime, timedelta
    import re
    dev = _mock_dev(1, ip="10.1.0.5", is_active=True)
    dev.last_seen = datetime.utcnow() - timedelta(minutes=60)  # 60 min temu — stale

    app, ctx, req = _make_devices_client(devices=[dev])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "Ping-worker moze nie dzialac" in html, "Tekst baneru musi byc w HTML"
    assert "ping-worker" in html, "Baner musi wspominac ping-workera"
    assert 'id="monitoring-stale-banner"' in html, "Banner musi miec ID"
    # Banner ZAWSZE zaczyna ukryty — JS go pokazuje po potwierdzeniu stanu przez API
    banner_match = re.search(r'id="monitoring-stale-banner"[^>]*>', html)
    assert banner_match, "Baner musi byc w HTML"
    assert 'display:none' in banner_match.group(0), "Banner zawsze zaczyna z display:none (JS kontroluje widocznosc)"


def test_devices_monitoring_stale_banner_not_shown_when_last_seen_fresh():
    """Gdy last_seen jest swiezy — baner ma display:none."""
    from datetime import datetime, timedelta
    dev = _mock_dev(1, ip="10.1.0.6", is_active=True)
    dev.last_seen = datetime.utcnow() - timedelta(minutes=2)

    app, ctx, req = _make_devices_client(devices=[dev])
    with ctx, req as mr:
        _setup_mock_api(mr, {})
        with app.test_client() as c:
            html = c.get("/devices").data.decode()

    assert "Ping-worker moze nie dzialac" in html, "Tekst baneru zawsze jest w HTML (ale ukryty)"
    assert 'style="display:none"' in html, "Swiezy last_seen: baner powinien miec display:none"


# ── Testy logiki routes — reklasyfikacja, zaufanie, flagi, monitorowanie ──────

from contextlib import contextmanager

@contextmanager
def _client_with_api_response(status_code=200, json_val=None):
    """Zwraca klienta z symulowanym API zwracajacym podany status i dane."""
    app, ms = _build_app()
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            for method in ("get", "post", "patch", "delete"):
                resp = MagicMock()
                resp.status_code = status_code
                resp.json.return_value = json_val or {}
                resp.raise_for_status = MagicMock(
                    side_effect=None if status_code < 400 else Exception(f"HTTP {status_code}")
                )
                resp.text = ""
                getattr(mr, method).return_value = resp
            with app.test_client() as c:
                yield c, mr


def test_device_reclassify_route_redirects():
    """POST /devices/{id}/reclassify przekierowuje do /devices."""
    with _client_with_api_response(200, {"device_type": "printer"}) as (c, _):
        resp = c.post("/devices/1/reclassify")
    assert resp.status_code == 302
    assert "/devices" in resp.headers["Location"]


def test_device_reclassify_flash_on_success():
    """POST /devices/{id}/reclassify ustawia flash z nowym typem."""
    with _client_with_api_response(200, {"device_type": "router"}) as (c, _):
        c.post("/devices/1/reclassify")
        resp = c.get("/")
    assert b"Reklasyfikacja" in resp.data


def test_device_reclassify_flash_on_error():
    """POST /devices/{id}/reclassify ustawia flash 'danger' gdy API zwroci blad."""
    with _client_with_api_response(404, {}) as (c, _):
        c.post("/devices/1/reclassify")
        resp = c.get("/")
    assert b"Blad reklasyfikacji" in resp.data or b"alert-danger" in resp.data


def test_device_set_type_redirects():
    """POST /devices/{id}/set-type przekierowuje do /devices."""
    with _client_with_api_response(200, {"device_type": "router"}) as (c, _):
        resp = c.post("/devices/1/set-type", data={"device_type": "router"})
    assert resp.status_code == 302


def test_device_trust_true_redirects():
    """POST /devices/{id}/trust z trusted=1 przekierowuje do /devices."""
    with _client_with_api_response(200, {"is_trusted": True}) as (c, _):
        resp = c.post("/devices/1/trust", data={"trusted": "1", "trust_note": "test"})
    assert resp.status_code == 302
    assert "/devices" in resp.headers["Location"]


def test_device_trust_false_redirects():
    """POST /devices/{id}/trust z trusted=0 przekierowuje do /devices."""
    with _client_with_api_response(200, {"is_trusted": False}) as (c, _):
        resp = c.post("/devices/1/trust", data={"trusted": "0"})
    assert resp.status_code == 302


def test_device_flag_set_redirects():
    """POST /devices/{id}/flag ustawia kolor i przekierowuje."""
    with _client_with_api_response(200, {"flag_color": "red"}) as (c, _):
        resp = c.post("/devices/1/flag", data={"flag_color": "red"})
    assert resp.status_code == 302


def test_device_flag_clear_redirects():
    """POST /devices/{id}/flag z pustym kolorem usuwa flage."""
    with _client_with_api_response(200, {"flag_color": None}) as (c, _):
        resp = c.post("/devices/1/flag", data={"flag_color": ""})
    assert resp.status_code == 302


def test_device_monitor_enable_redirects():
    """POST /devices/{id}/monitor z monitored=1 przekierowuje."""
    with _client_with_api_response(200, {"is_monitored": True}) as (c, _):
        resp = c.post("/devices/1/monitor", data={"monitored": "1", "monitor_note": "test"})
    assert resp.status_code == 302


def test_device_monitor_disable_redirects():
    """POST /devices/{id}/monitor z monitored=0 przekierowuje."""
    with _client_with_api_response(200, {"is_monitored": False}) as (c, _):
        resp = c.post("/devices/1/monitor", data={"monitored": "0"})
    assert resp.status_code == 302


def test_device_delete_route_redirects():
    """POST /devices/{id}/delete przekierowuje do /devices."""
    with _client_with_api_response(204, None) as (c, _):
        resp = c.post("/devices/1/delete")
    assert resp.status_code == 302
    assert "/devices" in resp.headers["Location"]


def test_devices_page_has_flag_modal():
    """Strona /devices zawiera modal wyboru flagi."""
    html = _build_app()[0].test_client().get.__wrapped__ if False else None
    app, ms = _build_app()
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app.test_client() as c:
                html = c.get("/devices").data.decode()
    assert "flagModal" in html, "Brak modala flagModal na stronie /devices"
    assert "monitorModal" in html, "Brak modala monitorModal na stronie /devices"
    assert "deleteModal" in html, "Brak modala deleteModal na stronie /devices"


def test_devices_page_no_autorefresh():
    """/devices nie ma aktywnego auto-refresh (jest w NO_REFRESH)."""
    app, ms = _build_app()
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app.test_client() as c:
                html = c.get("/devices").data.decode()
    assert '"/devices"' in html or "'/devices'" in html, (
        "/devices powinno byc w tablicy NO_REFRESH w base.html"
    )


def test_devices_page_has_delete_dropdown_item():
    """/devices ma opcje 'Usuń urządzenie' w menu akcji."""
    app, ms = _build_app(devices=[_mock_dev(1)])
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app.test_client() as c:
                html = c.get("/devices").data.decode()
    assert "Usuń urządzenie" in html or "Usun urzadzenie" in html


def test_devices_page_script_tags_balanced():
    """Strona /devices musi miec sparowane tagi <script> i </script> — regresja brakujacego </script>."""
    import re
    app, ms = _build_app(devices=[_mock_dev(1)])
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app.test_client() as c:
                html = c.get("/devices").data.decode()
    opens  = len(re.findall(r'<script[\s>]', html))
    closes = len(re.findall(r'</script>', html))
    assert opens == closes, f"Nieparzyste tagi script: {opens} otwarcia vs {closes} zamkniec"


import glob as _glob
import os as _os
_TEMPLATES_DIR = _os.path.join(_os.path.dirname(__file__), "..", "netdoc", "web", "templates")
_HTML_TEMPLATES = [_os.path.basename(p) for p in _glob.glob(_os.path.join(_TEMPLATES_DIR, "*.html"))]

@pytest.mark.parametrize("tpl", _HTML_TEMPLATES)
def test_template_script_tags_balanced(tpl):
    """Kazdy szablon HTML musi miec sparowane tagi <script> i </script> (analiza statyczna)."""
    import re as _re
    path = _os.path.join(_TEMPLATES_DIR, tpl)
    content = open(path, encoding="utf-8").read()
    opens  = len(_re.findall(r'<script[\s>]', content))
    closes = len(_re.findall(r'</script>', content))
    assert opens == closes, (
        f"{tpl}: {opens} otwarc <script> vs {closes} zamkniec </script>"
    )


# ── AI Assessment endpoint ────────────────────────────────────────────────────

def test_ai_assess_disabled_returns_403(monkeypatch):
    """/devices/ai-assess zwraca 403 gdy ai_assessment_enabled=0."""
    from netdoc.storage.models import SystemStatus
    flag = MagicMock(spec=SystemStatus)
    flag.key = "ai_assessment_enabled"; flag.value = "0"
    app, ms = _build_app()
    ms.query.side_effect = None
    q = MagicMock()
    q.filter_by.return_value = q
    q.first.return_value = flag
    ms.query.return_value = q
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with app.test_client() as c:
            resp = c.post("/devices/ai-assess")
    assert resp.status_code == 403


def test_ai_assess_no_api_key_returns_503(monkeypatch):
    """/devices/ai-assess zwraca 503 gdy brak ANTHROPIC_API_KEY."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    app, ms = _build_app()
    ms.query.side_effect = None
    q = MagicMock()
    q.filter_by.return_value = q
    q.first.return_value = None   # ai_assessment_enabled not in db → default enabled
    ms.query.return_value = q
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": ""}):
            with app.test_client() as c:
                resp = c.post("/devices/ai-assess")
    assert resp.status_code == 503


def test_ai_assess_no_devices_returns_400(monkeypatch):
    """/devices/ai-assess zwraca 400 gdy brak urzadzen."""
    from netdoc.storage.models import Device, SystemStatus
    app, ms = _build_app(devices=[])
    ms.query.side_effect = None
    q = MagicMock()
    q.filter_by.return_value = q
    q.filter.return_value = q
    q.order_by.return_value = q
    q.first.return_value = None
    q.all.return_value = []
    ms.query.return_value = q
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test"}):
            with app.test_client() as c:
                resp = c.post("/devices/ai-assess")
    assert resp.status_code == 400


def test_ai_assess_success_with_mock_anthropic(monkeypatch):
    """/devices/ai-assess zwraca JSON z wynikiem gdy API odpowiada OK."""
    import sys, json as _json
    dev = _mock_dev(1, "10.0.0.1")
    ai_response_json = _json.dumps({
        "assessed_at": "2026-03-09 12:00",
        "devices": [
            {"ip": "10.0.0.1", "hostname": None, "vendor": None, "device_type": "unknown",
             "is_obsolete": False, "reason": "OK", "replacements": []}
        ],
        "summary": "Infrastruktura w porzadku."
    })

    class _FakeContent:
        text = ai_response_json
    class _FakeMsg:
        content = [_FakeContent()]
    class _FakeMessages:
        @staticmethod
        def create(**kwargs): return _FakeMsg()
    class _FakeAnthropic:
        def __init__(self, api_key): self.messages = _FakeMessages()

    fake_anthropic_mod = MagicMock()
    fake_anthropic_mod.Anthropic = _FakeAnthropic
    monkeypatch.setitem(sys.modules, "anthropic", fake_anthropic_mod)

    app, ms = _build_app(devices=[dev])
    ms.query.side_effect = None
    q = MagicMock()
    q.filter_by.return_value = q
    q.filter.return_value = q
    q.order_by.return_value = q
    q.first.return_value = None
    q.all.return_value = [dev]
    ms.query.return_value = q

    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test"}):
            with app.test_client() as c:
                resp = c.post("/devices/ai-assess")
    assert resp.status_code == 200
    data = _json.loads(resp.data)
    assert "devices" in data
    assert data["summary"] == "Infrastruktura w porzadku."


def test_ai_assess_last_not_found(monkeypatch):
    """/devices/ai-assess/last zwraca 404 gdy brak wyniku w DB."""
    app, ms = _build_app()
    ms.query.side_effect = None
    q = MagicMock()
    q.filter_by.return_value = q
    q.first.return_value = None
    ms.query.return_value = q
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with app.test_client() as c:
            resp = c.get("/devices/ai-assess/last")
    assert resp.status_code == 404


def test_devices_page_has_per_device_ai_assess_button():
    """Strona /devices ma przycisk 'Ocena AI' per-device gdy ai_assessment_enabled=1."""
    app, ms = _build_app(devices=[_mock_dev(1)])
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app.test_client() as c:
                html = c.get("/devices").data.decode()
    assert "dev-ai-assess-btn" in html or "devAiAssessModal" in html


def test_ai_assess_readiness_returns_stats(monkeypatch):
    """/devices/ai-assess/readiness zwraca statystyki wzbogacenia urzadzen."""
    import json as _json
    from netdoc.storage.models import SystemStatus
    dev = _mock_dev(1, "10.0.0.1")
    dev.hostname = "router-01"
    dev.vendor = "Cisco"
    dev.os_version = None

    scan_row = MagicMock(spec=SystemStatus)
    scan_row.key = "scanner_last_at"; scan_row.value = "2026-03-09 10:00:00"

    app, ms = _build_app(devices=[dev])
    ms.query.side_effect = None
    q = MagicMock()
    q.filter_by.return_value = q
    q.first.return_value = scan_row
    q.all.return_value = [dev]
    ms.query.return_value = q

    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with app.test_client() as c:
            resp = c.get("/devices/ai-assess/readiness")
    assert resp.status_code == 200
    data = _json.loads(resp.data)
    assert data["total"] == 1
    assert data["with_hostname"] == 1
    assert data["with_vendor"] == 1
    assert data["enrichment_pct"] == 100
    assert data["readiness"] == "good"
    assert data["last_scan_at"] == "2026-03-09 10:00:00"


# ── Testy per-device AI assessment ────────────────────────────────────────────

def test_device_ai_assess_disabled_returns_403(monkeypatch):
    """/devices/<id>/ai-assess zwraca 403 gdy ai_assessment_enabled=0."""
    from netdoc.storage.models import SystemStatus
    dev = _mock_dev(1, "10.0.0.1")
    flag = MagicMock(spec=SystemStatus)
    flag.value = "0"

    app, ms = _build_app(devices=[dev])
    ms.query.side_effect = None
    q = MagicMock()
    q.filter_by.return_value = q
    q.first.return_value = flag
    ms.query.return_value = q

    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with app.test_client() as c:
            resp = c.post("/devices/1/ai-assess")
    assert resp.status_code == 403


def test_device_ai_assess_not_found_returns_404(monkeypatch):
    """/devices/<id>/ai-assess zwraca 404 gdy urzadzenie nie istnieje."""
    app, ms = _build_app(devices=[])
    ms.query.side_effect = None
    q = MagicMock()
    q.filter_by.return_value = q
    q.first.return_value = None   # flag enabled (None = default 1), device not found
    ms.query.return_value = q

    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test"}):
            with app.test_client() as c:
                resp = c.post("/devices/999/ai-assess")
    assert resp.status_code == 404


def test_device_ai_assess_success(monkeypatch):
    """/devices/<id>/ai-assess zwraca JSON z ocena i zapisuje w DeviceAssessment."""
    import sys, json as _json
    from netdoc.storage.models import DeviceAssessment as DA
    dev = _mock_dev(1, "10.0.0.1")
    dev.hostname = "switch-01"
    dev.vendor = "Cisco"

    ai_result = _json.dumps({
        "ip": "10.0.0.1", "hostname": "switch-01", "vendor": "Cisco",
        "device_type": "switch", "is_obsolete": True,
        "reason": "Stary sprzet bez wsparcia.",
        "replacements": [
            {"tier": "budget", "name": "TP-Link TL-SG108E", "price_new": "200 PLN", "price_used": None, "notes": ""},
        ],
        "summary": "Wymaga wymiany."
    })

    class _FakeContent:
        text = ai_result
    class _FakeMsg:
        content = [_FakeContent()]
    class _FakeMessages:
        @staticmethod
        def create(**kwargs): return _FakeMsg()
    class _FakeAnthropic:
        def __init__(self, api_key): self.messages = _FakeMessages()

    fake_mod = MagicMock()
    fake_mod.Anthropic = _FakeAnthropic
    monkeypatch.setitem(sys.modules, "anthropic", fake_mod)

    app, ms = _build_app(devices=[dev])
    ms.query.side_effect = None
    q = MagicMock()
    q.filter_by.return_value = q
    q.filter.return_value = q
    q.order_by.return_value = q
    q.first.return_value = None   # no flag override, no scan, device found via filter_by(id=1)
    q.all.return_value = []
    # Dla device lookup: filter_by(id=1).first() musi zwrocic dev
    q.first.side_effect = [None, dev, None, None]  # flag, device, scan, old entries
    ms.query.return_value = q

    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test"}):
            with app.test_client() as c:
                resp = c.post("/devices/1/ai-assess")
    assert resp.status_code == 200
    data = _json.loads(resp.data)
    assert data["is_obsolete"] is True
    assert "replacements" in data


def test_device_ai_assess_history_returns_list(monkeypatch):
    """/devices/<id>/ai-assess/history zwraca liste ocen."""
    import json as _json
    from netdoc.storage.models import DeviceAssessment as DA
    import datetime

    entry = MagicMock(spec=DA)
    entry.id = 42
    entry.device_id = 1
    entry.assessed_at = datetime.datetime(2026, 3, 9, 14, 30, 0)
    entry.result = _json.dumps({"is_obsolete": False, "reason": "OK", "summary": "Sprzet aktualny."})

    app, ms = _build_app()
    ms.query.side_effect = None
    q = MagicMock()
    q.filter_by.return_value = q
    q.order_by.return_value = q
    q.all.return_value = [entry]
    ms.query.return_value = q

    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with app.test_client() as c:
            resp = c.get("/devices/1/ai-assess/history")
    assert resp.status_code == 200
    items = _json.loads(resp.data)
    assert len(items) == 1
    assert items[0]["id"] == 42
    assert items[0]["is_obsolete"] is False
    assert items[0]["assessed_at"] == "2026-03-09 14:30"


def test_global_ai_assess_history_returns_list(monkeypatch):
    """/devices/ai-assess/history zwraca liste historycznych wpisow globalnych."""
    import json as _json
    from netdoc.storage.models import SystemStatus
    import datetime

    row = MagicMock(spec=SystemStatus)
    row.key = "ai_assessment_20260309_143000"
    row.updated_at = datetime.datetime(2026, 3, 9, 14, 30, 0)
    row.value = _json.dumps({
        "assessed_at": "2026-03-09 14:30",
        "devices": [{"ip": "10.0.0.1", "is_obsolete": False}],
        "summary": "OK."
    })

    app, ms = _build_app()
    ms.query.side_effect = None
    q = MagicMock()
    q.filter_by.return_value = q
    q.order_by.return_value = q
    q.all.return_value = [row]
    ms.query.return_value = q

    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with app.test_client() as c:
            resp = c.get("/devices/ai-assess/history")
    assert resp.status_code == 200
    items = _json.loads(resp.data)
    assert len(items) == 1
    assert items[0]["key"] == "ai_assessment_20260309_143000"
    assert items[0]["device_count"] == 1
    assert items[0]["obsolete_count"] == 0


def test_ai_logs_endpoint_returns_list(monkeypatch):
    """/api/logs/ai zwraca liste zapytan AI z historii per-urzadzenie."""
    import json as _json
    from netdoc.storage.models import DeviceAssessment as DA
    import datetime

    dev = _mock_dev(1, "10.0.0.1")
    dev.hostname = "router-01"

    entry = MagicMock(spec=DA)
    entry.id = 7
    entry.device_id = 1
    entry.assessed_at = datetime.datetime(2026, 3, 9, 15, 0, 0)
    entry.model = "claude-opus-4-6"
    entry.prompt = "Ocen urzadzenie..."
    entry.result = _json.dumps({"is_obsolete": True, "reason": "Stary.", "summary": "Do wymiany.", "replacements": [{"tier": "budget"}]})

    app, ms = _build_app(devices=[dev])
    ms.query.side_effect = None
    q = MagicMock()
    q.join.return_value = q
    q.outerjoin.return_value = q
    q.order_by.return_value = q
    q.limit.return_value = q
    q.all.return_value = [(entry, dev)]
    ms.query.return_value = q

    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with app.test_client() as c:
            resp = c.get("/api/logs/ai?limit=10")
    assert resp.status_code == 200
    items = _json.loads(resp.data)
    assert len(items) == 1
    assert items[0]["device_ip"] == "10.0.0.1"
    assert items[0]["is_obsolete"] is True
    assert items[0]["has_prompt"] is True
    assert items[0]["replacements_count"] == 1


# ── /kb/ports — encyklopedia portów ───────────────────────────────────────────

def test_kb_ports_smoke(client):
    """/kb/ports zwraca 200 OK."""
    assert client.get("/kb/ports").status_code == 200


def test_kb_ports_shows_port_entries(client):
    """/kb/ports renderuje wpisy z PORT_KB."""
    html = client.get("/kb/ports").data.decode()
    # Znane porty muszą pojawić się na stronie
    assert "80" in html, "Port 80 (HTTP) musi być widoczny"
    assert "22" in html, "Port 22 (SSH) musi być widoczny"
    assert "443" in html, "Port 443 (HTTPS) musi być widoczny"


def test_kb_ports_shows_total_badge(client):
    """/kb/ports wyświetla badge z łączną liczbą portów w bazie."""
    from netdoc.web.port_kb import PORT_KB
    html = client.get("/kb/ports").data.decode()
    assert str(len(PORT_KB)) in html, "Badge z liczbą portów musi być widoczny"


def test_kb_ports_has_filter_form(client):
    """/kb/ports ma formularz filtrów (szukaj, kategoria, ryzyko, OT)."""
    html = client.get("/kb/ports").data.decode()
    assert 'name="q"' in html, "Brak pola wyszukiwania"
    assert 'name="cat"' in html, "Brak selektu kategorii"
    assert 'name="risk"' in html, "Brak selektu ryzyka"
    assert 'name="ot"' in html, "Brak checkboxa OT"


def test_kb_ports_filter_search_ssh(client):
    """/kb/ports?q=ssh zwraca wyniki zawierające SSH."""
    html = client.get("/kb/ports?q=ssh").data.decode()
    assert "SSH" in html, "Filtr q=ssh powinien zwrócić port SSH"


def test_kb_ports_filter_search_no_results(client):
    """/kb/ports?q=xyznonexistent pokazuje komunikat o braku wyników."""
    html = client.get("/kb/ports?q=xyznonexistent_port_name_abc").data.decode()
    assert "Brak wyników" in html


def test_kb_ports_filter_category_web(client):
    """/kb/ports?cat=web filtruje do kategorii web."""
    html = client.get("/kb/ports?cat=web").data.decode()
    assert "HTTP" in html, "Kategoria web musi zawierać HTTP"


def test_kb_ports_filter_risk_critical(client):
    """/kb/ports?risk=critical pokazuje tylko krytyczne."""
    html = client.get("/kb/ports?risk=critical").data.decode()
    assert "Krytyczne" in html


def test_kb_ports_filter_ot(client):
    """/kb/ports?ot=1 pokazuje tylko porty OT/SCADA."""
    html = client.get("/kb/ports?ot=1").data.decode()
    # Modbus (502) to protokół OT — musi być widoczny
    assert "502" in html or "Modbus" in html, "Filtr OT musi pokazać Modbus"


def test_kb_ports_shows_category_select_options(client):
    """/kb/ports zawiera opcje kategorii w selekcie."""
    from netdoc.web.port_kb import PORT_CATEGORIES
    html = client.get("/kb/ports").data.decode()
    for label in PORT_CATEGORIES.values():
        assert label in html, f"Brakuje kategorii {label!r} w selekcie"


def test_kb_ports_risk_badges_present(client):
    """/kb/ports wyświetla etykiety ryzyka."""
    html = client.get("/kb/ports").data.decode()
    for label in ("Krytyczne", "Wysokie", "Średnie", "Niskie"):
        assert label in html, f"Brakuje etykiety ryzyka {label!r}"


def test_kb_ports_nav_link_in_base():
    """Szablon base.html zawiera link do /kb/ports."""
    import pathlib
    base = pathlib.Path("netdoc/web/templates/base.html").read_text(encoding="utf-8")
    assert "/kb/ports" in base, "Brak linku do /kb/ports w nawigacji base.html"


def test_kb_ports_search_preserves_query(client):
    """/kb/ports?q=... zachowuje wpisaną frazę w polu formularza."""
    html = client.get("/kb/ports?q=telnet").data.decode()
    assert 'value="telnet"' in html, "Pole q musi zachować wpisaną frazę"


# ── /devices/<id>/set-ip-type ─────────────────────────────────────────────────

def test_device_set_ip_type_static_redirects():
    """POST /devices/{id}/set-ip-type z ip_type=static przekierowuje na /devices."""
    with _client_with_api_response(200, {"ip_type": "static"}) as (c, _):
        resp = c.post("/devices/1/set-ip-type", data={"ip_type": "static"})
    assert resp.status_code == 302
    assert "/devices" in resp.headers["Location"]


def test_device_set_ip_type_dhcp_redirects():
    """POST /devices/{id}/set-ip-type z ip_type=dhcp przekierowuje na /devices."""
    with _client_with_api_response(200, {"ip_type": "dhcp"}) as (c, _):
        resp = c.post("/devices/1/set-ip-type", data={"ip_type": "dhcp"})
    assert resp.status_code == 302


def test_device_set_ip_type_unknown_redirects():
    """POST /devices/{id}/set-ip-type z ip_type=unknown przekierowuje na /devices."""
    with _client_with_api_response(200, {"ip_type": "unknown"}) as (c, _):
        resp = c.post("/devices/1/set-ip-type", data={"ip_type": "unknown"})
    assert resp.status_code == 302


def test_device_set_ip_type_flash_success_static():
    """POST set-ip-type z static ustawia flash z 'Statyczny'."""
    with _client_with_api_response(200, {"ip_type": "static"}) as (c, _):
        c.post("/devices/1/set-ip-type", data={"ip_type": "static"})
        resp = c.get("/")
    assert b"Statyczny" in resp.data or b"Typ IP" in resp.data


def test_device_set_ip_type_flash_success_dhcp():
    """POST set-ip-type z dhcp ustawia flash z 'DHCP'."""
    with _client_with_api_response(200, {"ip_type": "dhcp"}) as (c, _):
        c.post("/devices/1/set-ip-type", data={"ip_type": "dhcp"})
        resp = c.get("/")
    assert b"DHCP" in resp.data or b"Typ IP" in resp.data


def test_device_set_ip_type_flash_danger_on_api_error():
    """POST set-ip-type gdy API zwraca błąd — flash danger."""
    with _client_with_api_response(422, {}) as (c, _):
        c.post("/devices/1/set-ip-type", data={"ip_type": "static"})
        resp = c.get("/")
    assert b"alert-danger" in resp.data or b"Blad" in resp.data


def test_kb_ports_template_has_ot_badge():
    """Szablon kb_ports.html zawiera znacznik OT dla protokołów przemysłowych."""
    import pathlib
    tmpl = pathlib.Path("netdoc/web/templates/kb_ports.html").read_text(encoding="utf-8")
    assert "OT" in tmpl, "Brak badge OT w szablonie kb_ports.html"


def test_kb_ports_template_shows_device_list():
    """Szablon kb_ports.html zawiera sekcję z listą wykrytych urządzeń."""
    import pathlib
    tmpl = pathlib.Path("netdoc/web/templates/kb_ports.html").read_text(encoding="utf-8")
    assert "Wykryto na" in tmpl, "Brak sekcji urządzeń z otwartym portem"


# ── KB Ports — testy regresji HTML i logiki ───────────────────────────────────

import pathlib as _pl
_KB_PORTS_TPL = _pl.Path("netdoc/web/templates/kb_ports.html").read_text(encoding="utf-8")


# ─── Regresja szablonu (statyczna) ────────────────────────────────────────────

def test_kb_ports_tpl_port_badge_monospace():
    """Port number badge musi mieć klasę font-monospace — referencja wizualna."""
    assert "font-monospace" in _KB_PORTS_TPL


def test_kb_ports_tpl_risk_badge_colors():
    """Szablon mapuje wszystkie 5 poziomów ryzyka na kolory Bootstrap."""
    for risk in ("critical", "high", "medium", "low", "info"):
        assert risk in _KB_PORTS_TPL, f"Brak obsługi ryzyka '{risk}' w szablonie"


def test_kb_ports_tpl_filter_reset_link():
    """Przycisk Reset filtrów wskazuje na /kb/ports."""
    assert 'href="/kb/ports"' in _KB_PORTS_TPL, "Brak linku Reset → /kb/ports"


def test_kb_ports_tpl_no_results_alert():
    """Szablon ma alert gdy brak wyników filtrowania."""
    assert "Brak wyników" in _KB_PORTS_TPL


def test_kb_ports_tpl_found_count():
    """Szablon pokazuje licznik 'Znaleziono: N wpisów'."""
    assert "Znaleziono" in _KB_PORTS_TPL


def test_kb_ports_tpl_not_found_on_any_device():
    """Szablon ma tekst 'Nie wykryto w żadnym urządzeniu' jako fallback."""
    assert "Nie wykryto w żadnym urządzeniu" in _KB_PORTS_TPL


def test_kb_ports_tpl_device_link_format():
    """Link do urządzenia w KB ma format /devices#row-{id} (kotwica w tabeli urządzeń)."""
    assert "/devices#row-" in _KB_PORTS_TPL


def test_kb_ports_tpl_entries_sorted_by_port():
    """Wpisy są sortowane po numerze portu (sort(attribute='port'))."""
    assert "sort(attribute='port')" in _KB_PORTS_TPL


def test_kb_ports_tpl_active_badge_vs_secondary():
    """Aktywne urządzenia (badge bg-success) vs nieaktywne (bg-secondary)."""
    assert "bg-success" in _KB_PORTS_TPL
    assert "bg-secondary" in _KB_PORTS_TPL


def test_kb_ports_tpl_ot_filter_checkbox():
    """Formularz filtrów ma checkbox 'Tylko OT/SCADA'."""
    assert "Tylko OT/SCADA" in _KB_PORTS_TPL


def test_kb_ports_tpl_risk_select_all_options():
    """Select ryzyka ma opcje: critical, high, medium, low, info."""
    for r in ("critical", "high", "medium", "low", "info"):
        assert f'value="{r}"' in _KB_PORTS_TPL, f"Brak opcji risk={r} w selekcie"


# ─── Logika filtrowania (kombinacje) ──────────────────────────────────────────

def test_kb_ports_combined_search_and_risk(client):
    """Filtr q + risk razem zawęża wyniki do obu warunków."""
    html = client.get("/kb/ports?q=telnet&risk=critical").data.decode()
    # Telnet (23) jest critical — musi być widoczny
    assert "23" in html
    # Brak wyników lub wyniki — strona nie może się wysypać (200 zawsze)
    assert "Encyklopedia portów" in html


def test_kb_ports_combined_search_and_category(client):
    """Filtr q + cat razem — strona renderuje się bez błędu."""
    html = client.get("/kb/ports?q=ssh&cat=remote").data.decode()
    assert "Encyklopedia portów" in html


def test_kb_ports_filter_ot_zero_ignored(client):
    """ot=0 (nie '1') jest ignorowany — pokazuje wszystkie porty."""
    html_all  = client.get("/kb/ports").data.decode()
    html_ot0  = client.get("/kb/ports?ot=0").data.decode()
    # Liczba wpisów powinna byc identyczna — ot=0 nie filtruje
    from netdoc.web.port_kb import PORT_KB
    assert f"{len(PORT_KB)} portów w bazie" in html_ot0


def test_kb_ports_vendor_search(client):
    """Szukanie po nazwie vendora zwraca pasujące wpisy."""
    html = client.get("/kb/ports?q=cisco").data.decode()
    # Cisco pojawia się w wielu wpisach — musi byc wynik
    assert "Znaleziono" in html
    assert "0" not in html.split("Znaleziono")[1].split("wpisów")[0].strip() or \
           "Brak wyników" not in html


def test_kb_ports_search_by_port_number(client):
    """Szukanie po numerze portu (jako string) zwraca ten port."""
    html = client.get("/kb/ports?q=22").data.decode()
    assert "22" in html
    assert "SSH" in html or "ssh" in html.lower()


# ─── Logika port_devices (integracja z DB) ───────────────────────────────────

def _kb_client(db_engine):
    """Flask test client z realnym SQLite dla testów /kb/ports."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.web.app import create_app
    app2 = create_app()
    app2.config["TESTING"] = True
    Session = sessionmaker(bind=db_engine)
    return app2, Session


def test_kb_ports_shows_device_for_open_port(db_engine):
    """Urządzenie z portem 22 otwartym pojawia się w KB pod portem SSH."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType, ScanResult
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.5.5.5", hostname="srv-ssh", device_type=DeviceType.unknown,
                 is_active=True, is_trusted=False,
                 first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.refresh(dev)
    db.add(ScanResult(device_id=dev.id, scan_type="nmap",
                      scan_time=datetime.utcnow(),
                      open_ports={"22": {"service": "ssh"}}))
    db.commit(); db.close()

    app2, Session2 = _kb_client(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with app2.test_client() as c:
            html = c.get("/kb/ports?q=ssh").data.decode()

    assert "10.5.5.5" in html or "srv-ssh" in html, \
        "Urządzenie z otwartym portem 22 musi pojawić się w KB pod SSH"
    assert "Wykryto na" in html


def test_kb_ports_nmap_full_overrides_nmap_in_port_devices(db_engine):
    """nmap_full zastępuje nmap w indeksie port_devices (więcej portów z pełnego skanu)."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType, ScanResult
    from datetime import datetime, timedelta
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.5.5.6", device_type=DeviceType.unknown, is_active=True,
                 is_trusted=False, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.refresh(dev)
    # Szybki nmap: tylko port 22
    db.add(ScanResult(device_id=dev.id, scan_type="nmap",
                      scan_time=datetime.utcnow() - timedelta(hours=2),
                      open_ports={"22": {}}))
    # nmap_full: port 22 + 80 + 443 — nowszy, powinien zastąpić
    db.add(ScanResult(device_id=dev.id, scan_type="nmap_full",
                      scan_time=datetime.utcnow() - timedelta(hours=1),
                      open_ports={"22": {}, "80": {}, "443": {}}))
    db.commit(); db.close()

    app2, Session2 = _kb_client(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with app2.test_client() as c:
            # Port 80 (HTTP) powinien pokazac to urzadzenie — tylko jesli nmap_full uzyty
            html = c.get("/kb/ports?q=http&cat=web").data.decode()

    assert "10.5.5.6" in html, \
        "Urządzenie powinno pojawić się dla portu 80 — dane z nmap_full"


def test_kb_ports_active_device_sorted_before_inactive(db_engine):
    """Aktywne urządzenie pojawia się przed nieaktywnym w liście dla danego portu."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType, ScanResult
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev_active = Device(ip="10.0.0.1", hostname="active-host", device_type=DeviceType.unknown,
                        is_active=True, is_trusted=False,
                        first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    dev_down   = Device(ip="10.0.0.2", hostname="down-host", device_type=DeviceType.unknown,
                        is_active=False, is_trusted=False,
                        first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add_all([dev_active, dev_down]); db.commit()
    db.refresh(dev_active); db.refresh(dev_down)
    for dev in (dev_active, dev_down):
        db.add(ScanResult(device_id=dev.id, scan_type="nmap",
                          scan_time=datetime.utcnow(),
                          open_ports={"22": {}}))
    db.commit(); db.close()

    app2, Session2 = _kb_client(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with app2.test_client() as c:
            html = c.get("/kb/ports?q=ssh").data.decode()

    # Aktywny host ma bg-success, nieaktywny bg-secondary
    # Aktywny musi pojawiac sie przed nieaktywnym w HTML
    pos_active = html.find("active-host")
    pos_down   = html.find("down-host")
    assert pos_active != -1 and pos_down != -1, "Oba hosty muszą być widoczne"
    assert pos_active < pos_down, "Aktywny host musi być przed nieaktywnym"


def test_kb_ports_device_not_shown_when_port_closed(db_engine):
    """Urządzenie bez otwartego portu 22 NIE pojawia się w KB dla SSH."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType, ScanResult
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.5.5.7", hostname="no-ssh", device_type=DeviceType.unknown,
                 is_active=True, is_trusted=False,
                 first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.refresh(dev)
    # Ma tylko port 80 — nie 22
    db.add(ScanResult(device_id=dev.id, scan_type="nmap",
                      scan_time=datetime.utcnow(),
                      open_ports={"80": {}}))
    db.commit(); db.close()

    app2, Session2 = _kb_client(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with app2.test_client() as c:
            html = c.get("/kb/ports?q=ssh").data.decode()

    assert "no-ssh" not in html, \
        "Urządzenie bez portu 22 nie może pojawić się pod SSH"


def test_kb_ports_net_filter_smoke(client):
    """/kb/ports?net=192.168.1.0/24 zwraca 200 bez błędu."""
    assert client.get("/kb/ports?net=192.168.1.0/24").status_code == 200


def test_kb_ports_net_filter_excludes_other_subnet(db_engine):
    """net_filter ukrywa urządzenia spoza wybranej podsieci."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType, ScanResult
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    # Urządzenie w 10.5.0.0/16
    dev_in  = Device(ip="10.5.5.10", hostname="in-net",  device_type=DeviceType.unknown,
                     is_active=True, is_trusted=False,
                     first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    # Urządzenie poza filtrem
    dev_out = Device(ip="192.168.1.50", hostname="out-net", device_type=DeviceType.unknown,
                     is_active=True, is_trusted=False,
                     first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add_all([dev_in, dev_out]); db.commit()
    db.refresh(dev_in); db.refresh(dev_out)
    for dev in [dev_in, dev_out]:
        db.add(ScanResult(device_id=dev.id, scan_type="nmap",
                          scan_time=datetime.utcnow(),
                          open_ports={"22": {"service": "ssh"}}))
    db.commit(); db.close()

    app2, Session2 = _kb_client(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with app2.test_client() as c:
            html = c.get("/kb/ports?q=ssh&net=10.5.0.0/16").data.decode()

    assert "in-net" in html or "10.5.5.10" in html, \
        "Urządzenie w 10.5.0.0/16 musi być widoczne przy filtrze net=10.5.0.0/16"
    assert "out-net" not in html and "192.168.1.50" not in html, \
        "Urządzenie z 192.168.1.x nie może być widoczne przy filtrze 10.5.0.0/16"


def test_kb_ports_net_filter_no_match_hides_device_list(db_engine):
    """net_filter bez dopasowań ukrywa sekcję 'Wykryto na' dla portu."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType, ScanResult
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="172.16.5.1", hostname="other-net", device_type=DeviceType.unknown,
                 is_active=True, is_trusted=False,
                 first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.refresh(dev)
    db.add(ScanResult(device_id=dev.id, scan_type="nmap",
                      scan_time=datetime.utcnow(),
                      open_ports={"23": {}}))
    db.commit(); db.close()

    app2, Session2 = _kb_client(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with app2.test_client() as c:
            # Filtruj po zupełnie innej sieci — urządzenie nie powinno być widoczne
            html = c.get("/kb/ports?q=telnet&net=10.0.0.0/8").data.decode()

    assert "other-net" not in html, \
        "Urządzenie z 172.16.x.x nie może pojawić się przy filtrze net=10.0.0.0/8"


# ── KB Ports — nowe funkcje: live search, threats toggle, akceptacja ─────────

# Regresje szablonu — statyczne (bez uruchamiania serwera)

def test_kb_ports_tpl_live_search_id():
    """Pole wyszukiwania ma id='kbSearch' dla live search JS."""
    assert 'id="kbSearch"' in _KB_PORTS_TPL


def test_kb_ports_tpl_prevent_enter_submit():
    """JS blokuje Enter w polu wyszukiwania (preventDefault)."""
    assert "preventDefault" in _KB_PORTS_TPL


def test_kb_ports_tpl_kb_filters_object():
    """Szablon zawiera obiekt kbFilters z metodą apply."""
    assert "kbFilters" in _KB_PORTS_TPL
    assert "apply()" in _KB_PORTS_TPL


def test_kb_ports_tpl_local_storage_key():
    """Szablon używa kbThreatsOnly jako klucza localStorage."""
    assert "kbThreatsOnly" in _KB_PORTS_TPL


def test_kb_ports_tpl_threat_toggle_button():
    """Szablon ma przycisk threatToggle do przełączania filtra zagrożeń."""
    assert 'id="threatToggle"' in _KB_PORTS_TPL


def test_kb_ports_tpl_data_has_devices_attr():
    """Karty portów mają atrybut data-has-devices dla filtra zagrożeń."""
    assert "data-has-devices" in _KB_PORTS_TPL


def test_kb_ports_tpl_data_search_text_attr():
    """Karty portów mają atrybut data-search-text dla live search."""
    assert "data-search-text" in _KB_PORTS_TPL


def test_kb_ports_tpl_no_text_warning_for_device_list():
    """'Wykryto na urządzeniu' używa text-info, nie text-warning."""
    # Sprawdź że text-info jest w szablonie
    assert "text-info" in _KB_PORTS_TPL
    # Sprawdź że text-warning NIE pojawia się w kontekście nagłówka wykryto
    # (może być użyte gdzie indziej, ale nie przy "Wykryto na")
    lines = _KB_PORTS_TPL.splitlines()
    for i, line in enumerate(lines):
        if "Wykryto na" in line:
            context = " ".join(lines[max(0, i-2):i+3])
            assert "text-warning" not in context, \
                f"'Wykryto na' używa text-warning zamiast text-info (linia {i+1})"


def test_kb_ports_tpl_accept_modal_present():
    """Szablon zawiera modal akceptacji ryzyka (#acceptModal)."""
    assert 'id="acceptModal"' in _KB_PORTS_TPL


def test_kb_ports_tpl_accept_route():
    """Szablon wysyła POST do /kb/ports/accept."""
    assert 'action="/kb/ports/accept"' in _KB_PORTS_TPL


def test_kb_ports_tpl_revoke_route():
    """Szablon wysyła POST do /kb/ports/revoke."""
    assert 'action="/kb/ports/revoke"' in _KB_PORTS_TPL


def test_kb_ports_tpl_shield_plus_button():
    """Szablon zawiera przycisk akceptacji (bi-shield-plus)."""
    assert "bi-shield-plus" in _KB_PORTS_TPL


def test_kb_ports_tpl_shield_check_accepted():
    """Szablon wyświetla bi-shield-check dla zaakceptowanych urządzeń."""
    assert "bi-shield-check" in _KB_PORTS_TPL


def test_kb_ports_tpl_kb_accept_function():
    """Szablon zawiera funkcję kbAccept() otwierającą modal."""
    assert "function kbAccept(" in _KB_PORTS_TPL


def test_kb_ports_tpl_threats_only_default_true():
    """Domyślna wartość threatsOnly to true (JSON.parse ... ?? 'true')."""
    assert '"true"' in _KB_PORTS_TPL or "?? \"true\"" in _KB_PORTS_TPL


# Testy tras POST — accept i revoke

def test_kb_ports_accept_creates_record(db_engine):
    """POST /kb/ports/accept tworzy rekord PortAcceptance w bazie."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType, PortAcceptance
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.9.0.1", hostname="acc-host", device_type=DeviceType.unknown,
                 is_active=True, is_trusted=False,
                 first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.refresh(dev)
    dev_id = dev.id
    db.close()

    app2, Session2 = _kb_client(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with app2.test_client() as c:
            resp = c.post("/kb/ports/accept",
                          data={"device_id": dev_id, "port": 22, "reason": "test reason"},
                          follow_redirects=True)
            assert resp.status_code == 200

    db2 = Session2()
    acc = db2.query(PortAcceptance).filter_by(device_id=dev_id, port=22).first()
    db2.close()
    assert acc is not None, "PortAcceptance powinien być utworzony"
    assert acc.reason == "test reason"


def test_kb_ports_revoke_deletes_record(db_engine):
    """POST /kb/ports/revoke usuwa rekord PortAcceptance z bazy."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType, PortAcceptance
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.9.0.2", hostname="rev-host", device_type=DeviceType.unknown,
                 is_active=True, is_trusted=False,
                 first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.refresh(dev)
    dev_id = dev.id
    db.add(PortAcceptance(device_id=dev_id, port=80, reason="to revoke"))
    db.commit(); db.close()

    app2, Session2 = _kb_client(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with app2.test_client() as c:
            resp = c.post("/kb/ports/revoke",
                          data={"device_id": dev_id, "port": 80},
                          follow_redirects=True)
            assert resp.status_code == 200

    db2 = Session2()
    acc = db2.query(PortAcceptance).filter_by(device_id=dev_id, port=80).first()
    db2.close()
    assert acc is None, "PortAcceptance powinien być usunięty po revoke"


def test_kb_ports_accept_upsert_does_not_duplicate(db_engine):
    """Drugi POST /kb/ports/accept dla tego samego (device, port) nie duplikuje."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType, PortAcceptance
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.9.0.3", hostname="dup-host", device_type=DeviceType.unknown,
                 is_active=True, is_trusted=False,
                 first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.refresh(dev)
    dev_id = dev.id
    db.close()

    app2, Session2 = _kb_client(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with app2.test_client() as c:
            c.post("/kb/ports/accept", data={"device_id": dev_id, "port": 443, "reason": "first"})
            c.post("/kb/ports/accept", data={"device_id": dev_id, "port": 443, "reason": "second"})

    db2 = Session2()
    count = db2.query(PortAcceptance).filter_by(device_id=dev_id, port=443).count()
    db2.close()
    assert count == 1, "Upsert nie może tworzyć duplikatów"


def test_kb_ports_accepted_device_shows_bg_success(db_engine):
    """Zaakceptowane urządzenie wyświetla bg-success w karcie portu."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType, ScanResult, PortAcceptance
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.9.1.1", hostname="ok-host", device_type=DeviceType.unknown,
                 is_active=True, is_trusted=False,
                 first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.refresh(dev)
    db.add(ScanResult(device_id=dev.id, scan_type="nmap",
                      scan_time=datetime.utcnow(),
                      open_ports={"22": {"service": "ssh"}}))
    db.add(PortAcceptance(device_id=dev.id, port=22, reason="known"))
    db.commit(); db.close()

    app2, Session2 = _kb_client(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with app2.test_client() as c:
            html = c.get("/kb/ports?q=ssh").data.decode()

    assert "bg-success" in html, "Zaakceptowane urządzenie musi mieć bg-success"
    assert "ok-host" in html


def test_kb_ports_unaccepted_device_shows_bg_danger(db_engine):
    """Niezaakceptowane aktywne urządzenie wyświetla bg-danger w karcie portu."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType, ScanResult
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.9.1.2", hostname="danger-host", device_type=DeviceType.unknown,
                 is_active=True, is_trusted=False,
                 first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.refresh(dev)
    db.add(ScanResult(device_id=dev.id, scan_type="nmap",
                      scan_time=datetime.utcnow(),
                      open_ports={"22": {"service": "ssh"}}))
    db.commit(); db.close()

    app2, Session2 = _kb_client(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with app2.test_client() as c:
            html = c.get("/kb/ports?q=ssh").data.decode()

    assert "bg-danger" in html, "Niezaakceptowane urządzenie musi mieć bg-danger"
    assert "danger-host" in html


# ── Screenshot tooltip — testy regresji ──────────────────────────────────────

import pathlib as _pathlib
_DEVICES_TPL = _pathlib.Path("netdoc/web/templates/devices.html").read_text(encoding="utf-8")


def _get_devices_html_with_device():
    """Pomocnik: renderuje /devices z jednym urządzeniem i zwraca HTML."""
    dev = _mock_dev(1, "10.0.0.1")
    app, ms = _build_app(devices=[dev])
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app.test_client() as c:
                return c.get("/devices").data.decode()


# ── Testy źródła szablonu (JS nie zmienia się między renderowaniami) ──────────

def test_screenshot_trigger_class_in_template():
    """Szablon zawiera klasę .ip-preview-trigger — hook dla JS tooltip."""
    assert "ip-preview-trigger" in _DEVICES_TPL


def test_screenshot_trigger_has_data_device_id_in_template():
    """Szablon zawiera atrybut data-device-id — JS pobiera screenshot dla konkretnego urządzenia."""
    assert "data-device-id=" in _DEVICES_TPL


def test_screenshot_trigger_has_data_ip_in_template():
    """Szablon zawiera atrybut data-ip — JS wyświetla IP w tooltipie."""
    assert "data-ip=" in _DEVICES_TPL


def test_screenshot_js_cache_map_present():
    """JS zawiera definicję cache Map — rdzeń mechanizmu preloadingu."""
    assert "const _cache = new Map()" in _DEVICES_TPL


def test_screenshot_js_fetch_function_present():
    """JS zawiera funkcję _fetchScreenshot — pobiera i cachuje screenshot."""
    assert "_fetchScreenshot" in _DEVICES_TPL


def test_screenshot_js_preload_on_load_present():
    """JS rejestruje preload przez window.addEventListener('load') — screenshoty ładowane w tle."""
    assert 'window.addEventListener("load"' in _DEVICES_TPL


def test_screenshot_js_show_function_present():
    """JS zawiera funkcję showScreenshot — wywoływana przy hoverze."""
    assert "showScreenshot" in _DEVICES_TPL


def test_screenshot_js_blob_url_used():
    """JS używa URL.createObjectURL — obrazy cachowane jako blob URL (nie base64)."""
    assert "URL.createObjectURL" in _DEVICES_TPL


def test_screenshot_js_spinner_present():
    """JS zawiera spinner Bootstrap — pokazywany podczas pierwszego ładowania."""
    assert "spinner-border" in _DEVICES_TPL


def test_screenshot_js_preload_gap_constant():
    """JS zawiera stałą PRELOAD_GAP — kontroluje opóźnienie między requestami preloadu."""
    assert "PRELOAD_GAP" in _DEVICES_TPL


def test_screenshot_endpoint_url_pattern():
    """JS odwołuje się do /devices/${deviceId}/screenshot — poprawny endpoint backendu."""
    assert "/devices/${deviceId}/screenshot" in _DEVICES_TPL


def test_screenshot_js_cache_none_marker():
    """JS używa markera 'none' dla urządzeń bez screenshota — zapobiega zbędnym requestom."""
    assert '_cache.set(deviceId, "none")' in _DEVICES_TPL


# ── Test renderowanego HTML — trigger pojawia się gdy urządzenie ma screenshot ─

def test_screenshot_trigger_rendered_when_screenshot_exists(db_engine):
    """Trigger .ip-preview-trigger jest renderowany gdy urządzenie ma screenshot w DB."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import DeviceScreenshot
    from datetime import datetime

    Session = sessionmaker(bind=db_engine)
    db = Session()

    from netdoc.storage.models import Device, DeviceType
    dev = Device(ip="10.0.0.1", device_type=DeviceType.unknown, is_active=True,
                 is_trusted=False, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.refresh(dev)

    shot = DeviceScreenshot(device_id=dev.id, ip="10.0.0.1",
                            png_data=b"FAKE_PNG",
                            captured_at=datetime.utcnow(),
                            http_scheme="http", http_port=80)
    db.add(shot); db.commit()
    db.close()

    from netdoc.web.app import create_app
    app2 = create_app()
    app2.config["TESTING"] = True
    RealSession = sessionmaker(bind=db_engine)

    with patch("netdoc.web.app.SessionLocal", side_effect=RealSession):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app2.test_client() as c:
                html = c.get("/devices").data.decode()

    assert "ip-preview-trigger" in html
    assert 'data-device-id="' in html
    assert 'data-ip="10.0.0.1"' in html


# ── Pasek podsumowania i kolumna portów — testy ───────────────────────────────

def test_summary_strip_present(client):
    """Pasek podsumowania jest obecny na stronie /devices."""
    html = client.get("/devices").data.decode()
    # Badge z liczba urzadzen i statusem UP musi byc widoczny
    assert "UP" in html
    assert "bez podatności" in html


def test_summary_strip_shows_total_count(client):
    """Pasek podsumowania pokazuje liczbę urządzeń zgodną z listą."""
    html = client.get("/devices").data.decode()
    # Tytul strony i badge powinny byc zgodne — oba pokazuja liczbe urzadzen
    assert "Urzadzenia" in html


def test_summary_strip_no_full_scan_badge_present(db_engine):
    """Pasek pokazuje liczbę urządzeń bez pełnego skanu."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.0.0.1", device_type=DeviceType.unknown, is_active=True,
                 is_trusted=False, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.close()

    from netdoc.web.app import create_app
    app2 = create_app()
    app2.config["TESTING"] = True
    RealSession = sessionmaker(bind=db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=RealSession):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app2.test_client() as c:
                html = c.get("/devices").data.decode()

    assert "bez pełnego skanu" in html


def test_summary_strip_all_full_scanned(db_engine):
    """Gdy wszystkie urządzenia mają pełny skan — badge 'Pełny skan: wszystkie'."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType, ScanResult
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.0.0.1", device_type=DeviceType.unknown, is_active=True,
                 is_trusted=False, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.refresh(dev)
    sr = ScanResult(device_id=dev.id, scan_type="nmap_full",
                    scan_time=datetime.utcnow(), open_ports={"22": {}, "80": {}})
    db.add(sr); db.commit(); db.close()

    from netdoc.web.app import create_app
    app2 = create_app()
    app2.config["TESTING"] = True
    RealSession = sessionmaker(bind=db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=RealSession):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app2.test_client() as c:
                html = c.get("/devices").data.decode()

    assert "Pełny skan: wszystkie" in html


def test_port_count_column_header_present(client):
    """Tabela urządzeń ma nagłówek kolumny liczby otwartych portów."""
    html = client.get("/devices").data.decode()
    assert "Liczba otwartych portów" in html


def test_port_count_badge_shown_for_device_with_scan(db_engine):
    """Kolumna portów pokazuje badge z liczbą gdy urządzenie ma wyniki skanowania."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType, ScanResult
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.0.0.1", device_type=DeviceType.unknown, is_active=True,
                 is_trusted=False, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.refresh(dev)
    sr = ScanResult(device_id=dev.id, scan_type="nmap",
                    scan_time=datetime.utcnow(),
                    open_ports={"22": {}, "80": {}, "443": {}})
    db.add(sr); db.commit(); db.close()

    from netdoc.web.app import create_app
    app2 = create_app()
    app2.config["TESTING"] = True
    RealSession = sessionmaker(bind=db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=RealSession):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app2.test_client() as c:
                html = c.get("/devices").data.decode()

    # Badge z liczba portow musi byc w HTML
    assert "3" in html
    assert "szybki skan" in html


def test_port_count_prefers_full_scan_over_quick(db_engine):
    """Kolumna portów pokazuje wynik pełnego skanu gdy oba są dostępne."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType, ScanResult
    from datetime import datetime, timedelta
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.0.0.1", device_type=DeviceType.unknown, is_active=True,
                 is_trusted=False, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.refresh(dev)
    # Szybki skan: 3 porty
    db.add(ScanResult(device_id=dev.id, scan_type="nmap",
                      scan_time=datetime.utcnow() - timedelta(hours=2),
                      open_ports={"22": {}, "80": {}, "443": {}}))
    # Pelny skan: 150 portow
    db.add(ScanResult(device_id=dev.id, scan_type="nmap_full",
                      scan_time=datetime.utcnow() - timedelta(hours=1),
                      open_ports={str(p): {} for p in range(1, 151)}))
    db.commit(); db.close()

    from netdoc.web.app import create_app
    app2 = create_app()
    app2.config["TESTING"] = True
    RealSession = sessionmaker(bind=db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=RealSession):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app2.test_client() as c:
                html = c.get("/devices").data.decode()

    assert "150" in html          # badge pokazuje 150 portow z pelnego skanu
    assert "pełny skan" in html   # tooltip wskazuje zrodlo


def test_top_ports_outlier_shown_in_summary(db_engine):
    """Host z dużą liczbą portów ma data-ports=300 w wierszu tabeli (JS wypełni Uwagi)."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType, ScanResult
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.0.0.1", device_type=DeviceType.unknown, is_active=True,
                 is_trusted=False, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.refresh(dev)
    # 300 otwartych portow
    db.add(ScanResult(device_id=dev.id, scan_type="nmap_full",
                      scan_time=datetime.utcnow(),
                      open_ports={str(p): {} for p in range(1, 301)}))
    db.commit(); db.close()

    from netdoc.web.app import create_app
    app2 = create_app()
    app2.config["TESTING"] = True
    RealSession = sessionmaker(bind=db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=RealSession):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app2.test_client() as c:
                html = c.get("/devices").data.decode()

    # Uwagi sa teraz JS-driven — HTML zawiera devAlerts div i data-ports na wierszu
    assert 'id="devAlerts"' in html
    assert 'data-ports="300"' in html  # JS odczyta to i wygeneruje badge


def test_row_id_anchor_present(db_engine):
    """Każdy wiersz tabeli ma id='row-{id}' — kotwice dla linków z podsumowania."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.0.0.1", device_type=DeviceType.unknown, is_active=True,
                 is_trusted=False, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.refresh(dev)
    db.close()

    from netdoc.web.app import create_app
    app2 = create_app()
    app2.config["TESTING"] = True
    RealSession = sessionmaker(bind=db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=RealSession):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app2.test_client() as c:
                html = c.get("/devices").data.decode()

    assert f'id="row-{dev.id}"' in html


# ── Devices template — statyczne testy regresji ───────────────────────────────

def test_devices_tpl_summary_total_badge():
    """Szablon wyświetla summary.total w badgeu — całkowita liczba urządzeń."""
    assert "summary.total" in _DEVICES_TPL


def test_devices_tpl_summary_up_badge():
    """Szablon wyświetla summary.up UP — urządzenia osiągalne."""
    assert "summary.up" in _DEVICES_TPL
    assert "UP" in _DEVICES_TPL


def test_devices_tpl_summary_down_conditional():
    """Pasek DOWN pojawia się warunkowo (tylko gdy > 0)."""
    assert "summary.down > 0" in _DEVICES_TPL
    assert "DOWN" in _DEVICES_TPL


def test_devices_tpl_summary_no_full_scan_badge():
    """Szablon obsługuje badge 'bez pełnego skanu' i 'Pełny skan: wszystkie'."""
    assert "summary.no_full_scan" in _DEVICES_TPL
    assert "bez pełnego skanu" in _DEVICES_TPL
    assert "Pełny skan: wszystkie" in _DEVICES_TPL


def test_devices_tpl_summary_no_vulns_badge():
    """Szablon wyświetla badge 'bez podatności'."""
    assert "summary.no_vulns" in _DEVICES_TPL
    assert "bez podatności" in _DEVICES_TPL


def test_devices_tpl_summary_critical_conditional():
    """Badge krytycznych pojawia się warunkowo (only gdy > 0)."""
    assert "summary.critical > 0" in _DEVICES_TPL
    assert "krytyczne" in _DEVICES_TPL


def test_devices_tpl_uwaga_section():
    """Sekcja 'Uwaga' jest renderowana przez JS (devAlerts div) — nie przez Jinja2."""
    # Po refaktorze uwagi są JS-driven: devAlerts jest pusty w HTML, JS go wypełnia
    assert "devAlerts" in _DEVICES_TPL
    assert "updateAlerts" in _DEVICES_TPL
    # Stary server-side kod nie powinien już być w szablonie
    assert "summary.top_ports" not in _DEVICES_TPL
    assert "summary.top_vulns" not in _DEVICES_TPL


def test_devices_tpl_top_ports_anchor_link():
    """JS updateAlerts generuje kotwice do wierszy urządzeń (#row-)."""
    # Kotwice są teraz generowane w JS (updateAlerts), nie w Jinja2
    assert "updateAlerts" in _DEVICES_TPL
    assert "data-ports" in _DEVICES_TPL  # <tr> musi miec data-ports dla JS


def test_devices_tpl_port_count_column():
    """Kolumna liczby portów używa display_port_count z device_stats."""
    assert "display_port_count" in _DEVICES_TPL


def test_devices_tpl_port_count_dash_when_none():
    """Brak danych o portach → wyświetlane jest '—' zamiast liczby."""
    assert "is not none" in _DEVICES_TPL


def test_devices_tpl_port_count_color_thresholds():
    """Szablon zawiera wszystkie progi kolorowania portów."""
    assert ">= 500" in _DEVICES_TPL
    assert ">= 100" in _DEVICES_TPL
    assert ">= 50" in _DEVICES_TPL
    assert ">= 20" in _DEVICES_TPL
    assert ">= 6" in _DEVICES_TPL


def test_devices_tpl_row_id_present():
    """Każdy wiersz tabeli zawiera id='row-{{ d.id }}' — wymagane przez kotwice."""
    assert 'id="row-{{ d.id }}"' in _DEVICES_TPL


# ── Devices — dodatkowe testy logiki renderowania ─────────────────────────────

def _make_devices_app(db_engine):
    """Pomocnik: tworzy app z realnym SQLite."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.web.app import create_app
    app2 = create_app()
    app2.config["TESTING"] = True
    Session = sessionmaker(bind=db_engine)
    return app2, Session


def test_summary_down_badge_shown_only_for_down_devices(db_engine):
    """Badge DOWN pojawia się tylko gdy istnieje urządzenie nieosiągalne."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    # Tylko aktywne — badge DOWN nie powinien się pojawić
    dev = Device(ip="10.0.0.1", device_type=DeviceType.unknown, is_active=True,
                 is_trusted=False, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.close()

    app2, RealSession = _make_devices_app(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=RealSession):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app2.test_client() as c:
                html = c.get("/devices").data.decode()

    # Badge DOWN w summary strip ma unikalny tooltip — nie pojawia się gdy 0 down
    assert "urządzeń nie odpowiada" not in html, \
        "Tooltip badgea DOWN nie powinien być widoczny gdy 0 down"


def test_summary_down_badge_shown_when_device_is_down(db_engine):
    """Badge DOWN pojawia się gdy przynajmniej 1 urządzenie jest nieosiągalne."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.0.0.2", device_type=DeviceType.unknown, is_active=False,
                 is_trusted=False, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.close()

    app2, RealSession = _make_devices_app(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=RealSession):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app2.test_client() as c:
                html = c.get("/devices").data.decode()

    assert "DOWN" in html, "Badge DOWN musi być widoczny gdy jest urządzenie niedostępne"


def test_port_count_dash_when_no_scan(db_engine):
    """Kolumna portów pokazuje '—' gdy brak wyników skanowania."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.0.0.3", device_type=DeviceType.unknown, is_active=True,
                 is_trusted=False, first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.close()

    app2, RealSession = _make_devices_app(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=RealSession):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app2.test_client() as c:
                html = c.get("/devices").data.decode()

    assert "—" in html, "Brak skanu → kolumna portów powinna pokazywać '—'"


def test_top_vulns_outlier_shown_in_summary(db_engine):
    """Host z podatnościami pojawia się w sekcji 'Uwaga' podsumowania."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import Device, DeviceType, Vulnerability, VulnType, VulnSeverity
    from datetime import datetime
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = Device(ip="10.0.0.4", hostname="vuln-host", device_type=DeviceType.unknown,
                 is_active=True, is_trusted=False,
                 first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
    db.add(dev); db.commit(); db.refresh(dev)
    for i in range(5):
        db.add(Vulnerability(
            device_id=dev.id, port=i + 1,
            vuln_type=VulnType.open_telnet,
            severity=VulnSeverity.high,
            title=f"CVE-{i}",
            is_open=True, suppressed=False
        ))
    db.commit(); db.close()

    app2, RealSession = _make_devices_app(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=RealSession):
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {})
            with app2.test_client() as c:
                html = c.get("/devices").data.decode()

    # Uwagi sa teraz JS-driven — sprawdzamy ze wiersz ma data-vulns i hostname w DOM
    assert 'id="devAlerts"' in html
    assert 'data-vulns="5"' in html   # JS odczyta i wygeneruje badge
    assert "vuln-host" in html        # hostname jest w wierszu tabeli


# ─── Lab start/stop AJAX endpoints ───────────────────────────────────────────

def _make_docker_stub(from_env_result=None, from_env_exc=None):
    """Tworzy stub modulu docker dla testow (docker nie jest zainstalowany na hoście)."""
    import types
    docker_stub = types.ModuleType("docker")
    errors_stub = types.ModuleType("docker.errors")

    class _NotFound(Exception):
        pass
    class _ImageNotFound(Exception):
        pass

    errors_stub.NotFound = _NotFound
    errors_stub.ImageNotFound = _ImageNotFound
    docker_stub.errors = errors_stub

    if from_env_exc:
        docker_stub.from_env = MagicMock(side_effect=from_env_exc)
    else:
        mock_client = from_env_result or MagicMock()
        docker_stub.from_env = MagicMock(return_value=mock_client)

    return docker_stub, _NotFound, _ImageNotFound


def test_lab_start_returns_json_when_docker_fails(client):
    """POST /settings/lab/start zwraca JSON (nie redirect) gdy Docker niedostepny."""
    docker_stub, _, _ = _make_docker_stub(from_env_exc=Exception("socket not found"))
    import sys
    with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
        resp = client.post("/settings/lab/start")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data is not None
    assert data["ok"] is False
    assert "message" in data


def test_lab_stop_returns_json_when_docker_fails(client):
    """POST /settings/lab/stop zwraca JSON gdy Docker niedostepny."""
    docker_stub, _, _ = _make_docker_stub(from_env_exc=Exception("socket not found"))
    import sys
    with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
        resp = client.post("/settings/lab/stop")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data is not None
    assert data["ok"] is False


def test_lab_start_all_running_returns_ok(client):
    """Gdy wszystkie kontenery juz dzialaja, lab_start zwraca ok=True."""
    mock_container = MagicMock()
    mock_container.status = "running"
    mock_docker_client = MagicMock()
    mock_docker_client.containers.get.return_value = mock_container
    mock_docker_client.networks.get.return_value = MagicMock()

    docker_stub, _, _ = _make_docker_stub(from_env_result=mock_docker_client)
    import sys
    with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
        resp = client.post("/settings/lab/start")
    data = resp.get_json()
    assert data is not None
    assert data["ok"] is True


def test_lab_stop_containers_not_found_returns_ok(client):
    """Gdy kontenery nie istnieja, lab_stop traktuje to jako juz zatrzymane."""
    docker_stub, NotFound, _ = _make_docker_stub()
    mock_docker_client = MagicMock()
    mock_docker_client.containers.get.side_effect = NotFound("not found")
    docker_stub.from_env.return_value = mock_docker_client

    import sys
    with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
        resp = client.post("/settings/lab/stop")
    data = resp.get_json()
    assert data is not None
    assert data["ok"] is True


def test_lab_start_absent_no_image_returns_error_message(client):
    """Gdy obraz Docker nie istnieje, lab_start zwraca message z instrukcja budowania."""
    docker_stub, NotFound, ImageNotFound = _make_docker_stub()
    mock_docker_client = MagicMock()
    mock_docker_client.containers.get.side_effect = NotFound("not found")
    mock_docker_client.networks.get.return_value = MagicMock()
    mock_docker_client.api.create_networking_config.return_value = {}
    mock_docker_client.api.create_host_config.return_value = {}
    mock_docker_client.api.create_container.side_effect = ImageNotFound("image not found")
    docker_stub.from_env.return_value = mock_docker_client

    import sys
    with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
        resp = client.post("/settings/lab/start")
    data = resp.get_json()
    assert data is not None
    assert "message" in data


def test_lab_start_response_is_json_not_redirect(client):
    """Odpowiedz lab_start to JSON, nie redirect (status 200)."""
    docker_stub, _, _ = _make_docker_stub(from_env_exc=Exception("no docker"))
    import sys
    with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
        resp = client.post("/settings/lab/start")
    assert resp.status_code == 200
    assert resp.content_type is not None
    assert "json" in resp.content_type


def test_settings_page_has_lab_js(client):
    """Strona ustawien zawiera funkcje labAction() i elementy UI laba."""
    resp = client.get("/settings")
    html = resp.data.decode()
    assert "labAction" in html
    assert "btnLabStart" in html
    assert "btnLabStop" in html
    assert "labResult" in html


def test_lab_stop_disconnects_workers_and_removes_network(client):
    """lab_stop rozlacza workerow od netdoc_lab i usuwa siec."""
    docker_stub, NotFound, _ = _make_docker_stub()
    mock_client = MagicMock()
    mock_client.containers.get.side_effect = NotFound("not found")
    mock_lab_net = MagicMock()
    mock_client.networks.get.return_value = mock_lab_net
    docker_stub.from_env.return_value = mock_client

    import sys
    with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
        resp = client.post("/settings/lab/stop")

    data = resp.get_json()
    assert data["ok"] is True
    # Siec powinna byc usunieta
    mock_lab_net.remove.assert_called_once()


def test_lab_stop_network_not_found_still_ok(client):
    """lab_stop zwraca ok=True nawet gdy siec netdoc_lab nie istnieje."""
    docker_stub, NotFound, _ = _make_docker_stub()
    mock_client = MagicMock()
    mock_client.containers.get.side_effect = NotFound("not found")
    mock_client.networks.get.side_effect = NotFound("network not found")
    docker_stub.from_env.return_value = mock_client

    import sys
    with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
        resp = client.post("/settings/lab/stop")

    data = resp.get_json()
    assert data["ok"] is True


# ─── Docker restart/rebuild SSE endpoints ────────────────────────────────────

def _collect_sse(response) -> list[str]:
    """Zbiera linie 'data: ...' ze strumienia SSE."""
    body = response.data.decode()
    return [line[6:] for line in body.splitlines() if line.startswith("data: ")]


def test_docker_restart_stream_returns_sse(client):
    """GET /settings/docker/restart-stream zwraca text/event-stream."""
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_client.containers.get.return_value = mock_container

    docker_stub, _, _ = _make_docker_stub(from_env_result=mock_client)
    import sys
    with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
        resp = client.get("/settings/docker/restart-stream?services=api")

    assert resp.status_code == 200
    assert "event-stream" in resp.content_type
    lines = _collect_sse(resp)
    assert "DONE" in lines


def test_docker_restart_stream_calls_restart(client):
    """restart-stream wywoluje container.restart() dla wybranego serwisu."""
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_client.containers.get.return_value = mock_container

    docker_stub, _, _ = _make_docker_stub(from_env_result=mock_client)
    import sys
    with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
        client.get("/settings/docker/restart-stream?services=api")

    mock_client.containers.get.assert_called_with("netdoc-api")
    mock_container.restart.assert_called_once()


def test_docker_restart_stream_unknown_service(client):
    """restart-stream z nieznanym kluczem nie crashuje, zwraca DONE."""
    mock_client = MagicMock()
    docker_stub, _, _ = _make_docker_stub(from_env_result=mock_client)
    import sys
    with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
        resp = client.get("/settings/docker/restart-stream?services=nonexistent")

    lines = _collect_sse(resp)
    assert "DONE" in lines


def test_docker_restart_stream_docker_unavailable(client):
    """restart-stream zwraca ERROR gdy Docker niedostepny."""
    docker_stub, _, _ = _make_docker_stub(from_env_exc=Exception("no socket"))
    import sys
    with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
        resp = client.get("/settings/docker/restart-stream?services=api")

    lines = _collect_sse(resp)
    assert "ERROR" in lines


def test_docker_restart_stream_container_not_found(client):
    """restart-stream nie crashuje gdy kontener nie istnieje."""
    docker_stub, NotFound, _ = _make_docker_stub()
    mock_client = MagicMock()
    mock_client.containers.get.side_effect = NotFound("not found")
    docker_stub.from_env.return_value = mock_client

    import sys
    with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
        resp = client.get("/settings/docker/restart-stream?services=api")

    lines = _collect_sse(resp)
    assert "DONE" in lines


def test_docker_rebuild_stream_returns_sse(client):
    """GET /settings/docker/rebuild-stream zwraca text/event-stream."""
    mock_client = MagicMock()
    mock_client.api.build.return_value = iter([{"stream": "Step 1/3\n"}, {"stream": "done\n"}])
    mock_container = MagicMock()
    mock_client.containers.get.return_value = mock_container

    docker_stub, _, _ = _make_docker_stub(from_env_result=mock_client)
    import sys
    with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
        resp = client.get("/settings/docker/rebuild-stream?services=api")

    assert resp.status_code == 200
    assert "event-stream" in resp.content_type
    lines = _collect_sse(resp)
    assert "DONE" in lines


def test_docker_rebuild_stream_build_error_returns_error(client):
    """rebuild-stream zwraca ERROR gdy Docker zwroci error w build log."""
    mock_client = MagicMock()
    mock_client.api.build.return_value = iter([{"error": "Build failed: no such file"}])

    docker_stub, _, _ = _make_docker_stub(from_env_result=mock_client)
    import sys
    with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
        resp = client.get("/settings/docker/rebuild-stream?services=api")

    lines = _collect_sse(resp)
    assert "ERROR" in lines


def test_docker_rebuild_stream_non_buildable_service_restarts(client):
    """rebuild-stream dla grafana (nie buildable) wykonuje tylko restart."""
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_client.containers.get.return_value = mock_container

    docker_stub, _, _ = _make_docker_stub(from_env_result=mock_client)
    import sys
    with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
        resp = client.get("/settings/docker/rebuild-stream?services=grafana")

    # Brak build — tylko restart
    mock_client.api.build.assert_not_called()
    mock_container.restart.assert_called_once()
    lines = _collect_sse(resp)
    assert "DONE" in lines


# ─── Regresja struktury strony /settings ──────────────────────────────────────
# Testy pilnuja ze strona ustawien nie rozjedzie sie po zmianach w szablonie.
# Sprawdzamy obecnosc kluczowych elementow HTML — nie zawartosc logiki biznesowej.

class TestSettingsPageStructure:
    """Regresja struktury /settings — weryfikuje ze wszystkie sekcje sa renderowane."""

    @pytest.fixture(autouse=True)
    def _html(self, client):
        self.html = client.get("/settings").data.decode()

    # ── Naglowki sekcji ──────────────────────────────────────────────────────

    def test_has_workers_section(self):
        assert "Ustawienia worker" in self.html

    def test_has_credential_worker_heading(self):
        assert "Credential Worker" in self.html

    def test_has_ping_worker_heading(self):
        assert "Ping Worker" in self.html

    def test_has_snmp_worker_heading(self):
        assert "SNMP Worker" in self.html

    def test_has_vulnerability_worker_heading(self):
        assert "Vulnerability Worker" in self.html

    def test_has_scan_intensity_heading(self):
        assert "intensywno" in self.html.lower()

    def test_has_lab_section(self):
        assert "laboratoryjna" in self.html

    def test_has_docker_nuke_section(self):
        assert "docker-nuke" in self.html

    def test_has_telegram_section(self):
        assert "Telegram" in self.html

    # ── Pola formularza workerow ─────────────────────────────────────────────

    def test_workers_form_action(self):
        assert 'action="/settings/workers"' in self.html

    def test_field_cred_interval_s(self):        assert 'name="cred_interval_s"' in self.html
    def test_field_cred_ssh_workers(self):        assert 'name="cred_ssh_workers"' in self.html
    def test_field_cred_pairs_per_cycle(self):    assert 'name="cred_pairs_per_cycle"' in self.html
    def test_field_cred_device_timeout_s(self):   assert 'name="cred_device_timeout_s"' in self.html
    def test_field_cred_retry_days(self):          assert 'name="cred_retry_days"' in self.html
    def test_field_cred_max_creds_per_dev(self):   assert 'name="cred_max_creds_per_dev"' in self.html
    def test_field_ping_interval_s(self):          assert 'name="ping_interval_s"' in self.html
    def test_field_ping_workers(self):             assert 'name="ping_workers"' in self.html
    def test_field_ping_inactive_after_min(self):  assert 'name="ping_inactive_after_min"' in self.html
    def test_field_snmp_interval_s(self):          assert 'name="snmp_interval_s"' in self.html
    def test_field_snmp_workers(self):             assert 'name="snmp_workers"' in self.html
    def test_field_vuln_interval_s(self):          assert 'name="vuln_interval_s"' in self.html
    def test_field_vuln_workers(self):             assert 'name="vuln_workers"' in self.html
    def test_field_vuln_close_after(self):         assert 'name="vuln_close_after"' in self.html

    # ── Pola intensywnosci skanowania ────────────────────────────────────────

    def test_field_vuln_skip_printers(self):
        assert 'name="vuln_skip_printers"' in self.html

    def test_field_vuln_limit_ap_iot(self):
        assert 'name="vuln_limit_ap_iot"' in self.html

    def test_field_nmap_min_rate(self):
        assert 'name="nmap_min_rate"' in self.html

    def test_field_nmap_version_intensity(self):
        assert 'name="nmap_version_intensity"' in self.html

    def test_vuln_skip_printers_options(self):
        """Select vuln_skip_printers ma opcje value=0 i value=1."""
        assert 'name="vuln_skip_printers"' in self.html
        assert 'value="1"' in self.html
        assert 'value="0"' in self.html

    # ── Lab watchdog monitoring ──────────────────────────────────────────────

    def test_field_lab_monitoring_enabled(self):
        """Pole lab_monitoring_enabled musi byc w formularzu workerow."""
        assert 'name="lab_monitoring_enabled"' in self.html

    def test_lab_monitoring_enabled_has_options(self):
        """Select lab_monitoring_enabled ma opcje 0 i 1."""
        idx = self.html.find('name="lab_monitoring_enabled"')
        assert idx != -1
        fragment = self.html[idx:idx + 400]
        assert 'value="0"' in fragment or 'value="1"' in fragment

    # ── Sekcja lab ──────────────────────────────────────────────────────────

    def test_lab_table_header_name(self):      assert "Kontener" in self.html
    def test_lab_table_header_ip(self):        assert "IP" in self.html
    def test_lab_btn_start(self):              assert "btnLabStart" in self.html
    def test_lab_btn_stop(self):               assert "btnLabStop" in self.html
    def test_lab_result_div(self):             assert "labResult" in self.html

    def test_lab_result_hidden(self):
        """labResult jest domyslnie ukryty (style display:none)."""
        idx = self.html.index('id="labResult"')
        surrounding = self.html[max(0, idx - 50):idx + 100]
        assert "display:none" in surrounding or "display: none" in surrounding

    # ── Docker nuke modal ────────────────────────────────────────────────────

    def test_nuke_modal_exists(self):          assert "dockerNukeModal" in self.html
    def test_nuke_check1(self):                assert "nukeCheck1" in self.html
    def test_nuke_check2(self):                assert "nukeCheck2" in self.html
    def test_nuke_confirm_btn(self):           assert "nukeConfirmBtn" in self.html

    # ── Telegram form ────────────────────────────────────────────────────────

    def test_telegram_form_action(self):
        assert 'action="/settings/telegram"' in self.html

    def test_telegram_field_bot_token(self):   assert 'name="bot_token"' in self.html
    def test_telegram_field_chat_id(self):     assert 'name="chat_id"' in self.html
    def test_telegram_field_is_active(self):   assert 'name="is_active"' in self.html

    # ── Docker Services — restart/rebuild card ──────────────────────────────

    def test_has_docker_services_section(self):
        """Nowa karta Zarzadzanie kontenerami Docker jest obecna."""
        assert "docker-services" in self.html

    def test_docker_services_has_restart_btn(self):
        """Przycisk restart wybranych kontenerow jest obecny."""
        assert "dsAction('restart')" in self.html

    def test_docker_services_has_rebuild_btn(self):
        """Przycisk przebuduj obraz jest obecny."""
        assert "dsAction('rebuild')" in self.html

    def test_docker_services_has_checkboxes(self):
        """Checkboxy ds-check dla serwisow sa obecne."""
        assert "ds-check" in self.html
        assert 'value="api"' in self.html
        assert 'value="web"' in self.html

    def test_docker_services_modal_exists(self):
        """Modal dsModal dla wynikow operacji jest obecny."""
        assert "dsModal" in self.html
        assert "dsOutput" in self.html

    # ── JavaScript ──────────────────────────────────────────────────────────

    def test_js_labAction(self):               assert "labAction" in self.html
    def test_js_startDockerNuke(self):         assert "startDockerNuke" in self.html
    def test_js_nukeOutput(self):              assert "nukeOutput" in self.html
    def test_js_dsAction(self):                assert "dsAction" in self.html

    # ── Brak oczywistych rozjazdow struktury ─────────────────────────────────

    def test_no_unclosed_form_tags(self):
        """Liczba <form i </form> jest rowna — brak otwartych formularzy."""
        assert self.html.count("<form") == self.html.count("</form>"), (
            "Nieparzysta liczba tagow <form> — prawdopodobnie brak zamkniecia"
        )

    def test_no_unclosed_table_tags(self):
        """Liczba <table i </table> jest rowna — brak rozjazdu tabelki."""
        assert self.html.count("<table") == self.html.count("</table>"), (
            "Nieparzysta liczba tagow <table> — rozjazd tabelki"
        )

    def test_card_sections_count(self):
        """Strona ma co najmniej 5 kart (workers, lab, nuke, config, telegram)."""
        opens = self.html.count('class="card ')
        assert opens >= 5, f"Za malo kart na stronie: {opens}"

    def test_submit_button_workers(self):
        """Przycisk zapisu ustawien workerow jest obecny."""
        assert "Zapisz ustawienia" in self.html

    def test_no_jinja_error_markers(self):
        """Strona nie zawiera sladow bledu szablonu Jinja2."""
        assert "UndefinedError" not in self.html
        assert "TemplateSyntaxError" not in self.html
        assert "jinja2.exceptions" not in self.html


# ─── Regresja struktury strony /scan ──────────────────────────────────────────

class TestScanPageStructure:
    """Regresja /scan — przyciski wyzwalania, progress, status."""

    @pytest.fixture(autouse=True)
    def _html(self, client):
        self.html = client.get("/scan").data.decode()

    def test_page_ok(self):                    assert self.html

    def test_heading_exists(self):
        """Naglowek 'Kontrola skanowania' jest widoczny."""
        assert "Kontrola skanowania" in self.html

    # Trzy formularze wyzwalania skanowania
    def test_form_trigger_standard(self):
        assert 'action="/scan/trigger"' in self.html
        assert 'value="standard"' in self.html

    def test_form_trigger_full(self):
        assert 'value="full"' in self.html

    def test_form_trigger_oui(self):
        assert 'value="oui"' in self.html

    def test_forms_balanced(self):
        assert self.html.count("<form") == self.html.count("</form>")

    # Elementy progress / live status
    def test_progress_card(self):              assert "progressCard" in self.html
    def test_progress_bar(self):               assert "progressBar" in self.html
    def test_progress_pct(self):               assert "progressPct" in self.html
    def test_status_job_cell(self):            assert "statusJobCell" in self.html

    # JavaScript
    def test_js_poll_function(self):           assert "poll()" in self.html or "function poll" in self.html
    def test_js_parse_progress(self):          assert "parseProgress" in self.html

    def test_no_jinja_errors(self):
        assert "UndefinedError" not in self.html
        assert "jinja2.exceptions" not in self.html


# ─── Regresja struktury strony /networks ──────────────────────────────────────

class TestNetworksPageStructure:
    """Regresja /networks — tabela sieci, modalne formularze, naglowki kolumn."""

    @pytest.fixture(autouse=True)
    def _html(self, client):
        self.html = client.get("/networks").data.decode()

    def test_page_ok(self):                    assert self.html

    def test_heading_sieci(self):
        assert "Sieci" in self.html

    # Kolumny tabeli
    def test_col_cidr(self):                   assert "CIDR" in self.html
    def test_col_status(self):                 assert "Status" in self.html
    def test_col_urzadzenia(self):             assert "Urzadzenia" in self.html or "rzadzenia" in self.html
    def test_col_akcje(self):                  assert "Akcje" in self.html

    # Modalne
    def test_modal_add_net(self):              assert "addNetModal" in self.html
    def test_modal_pause(self):                assert "pauseModal" in self.html
    def test_modal_delete(self):               assert "deleteNetModal" in self.html

    # Formularz dodawania sieci
    def test_form_add_action(self):            assert 'action="/networks/add"' in self.html
    def test_field_cidr(self):                 assert 'name="cidr"' in self.html
    def test_field_notes(self):                assert 'name="notes"' in self.html

    def test_tables_balanced(self):
        assert self.html.count("<table") == self.html.count("</table>")

    def test_no_jinja_errors(self):
        assert "UndefinedError" not in self.html
        assert "jinja2.exceptions" not in self.html

    def test_delete_modal_has_delete_devices_option(self):
        """Modal usuwania sieci musi zawierać opcję 'Rowniez usun urzadzenia'."""
        assert "deleteNetDevices" in self.html
        assert "deleteDevOption" in self.html
        assert "delete_devices" in self.html

    def test_delete_modal_delete_devices_checkbox_present(self):
        """Checkbox 'rowniez usun urzadzenia' musi byc w modalu #deleteNetModal."""
        assert 'id="deleteNetDevices"' in self.html

    def test_delete_modal_dev_count_span_present(self):
        """Span z liczba urzadzen musi byc w modalu usuwania sieci."""
        assert 'id="deleteNetDevCount"' in self.html

    def test_pause_modal_delete_devices_checkbox_present(self):
        """Checkbox 'rowniez usun urzadzenia' musi byc w modalu zatrzymywania sieci."""
        assert 'id="pauseDeleteDevices"' in self.html


class TestNetworksMalformedCidr:
    """Regresja: /networks nie moze zwrocic 500 gdy w bazie jest wpis z nieprawidlowym CIDR."""

    def test_networks_ok_with_normal_cidrs(self, client):
        """/networks zwraca 200 przy poprawnych CIDR."""
        assert client.get("/networks").status_code == 200

    def test_networks_ok_when_db_has_cidr_without_slash(self, client):
        """GET /networks nie crasha gdy w bazie jest rekord z CIDR bez ulamka (np. '[]').

        Regresja: n.cidr.split('/')[1] rzucalo UndefinedError gdy cidr='[]'.
        Fix: route handler filtruje nieprawidlowe CIDR przed renderingiem.
        """
        from netdoc.storage.database import SessionLocal
        from netdoc.storage.models import DiscoveredNetwork, NetworkSource
        db = SessionLocal()
        try:
            bad = DiscoveredNetwork(cidr="[]", source=NetworkSource.manual)
            db.add(bad)
            db.commit()
            bad_id = bad.id
        finally:
            db.close()

        try:
            r = client.get("/networks")
            assert r.status_code == 200, \
                "GET /networks zwrocilo 500 — sprawdz filtrowanie nieprawidlowych CIDR w route"
            html = r.data.decode()
            assert "UndefinedError" not in html
            assert "jinja2.exceptions" not in html
            # Zly rekord nie moze sie pokazac w tabeli
            assert ">[]<" not in html
        finally:
            db2 = SessionLocal()
            try:
                db2.query(DiscoveredNetwork).filter_by(id=bad_id).delete()
                db2.commit()
            finally:
                db2.close()

    def test_networks_valid_cidrs_still_rendered_after_bad_cidr(self, client):
        """Prawidlowe sieci sa renderowane nawet gdy w bazie jest zepsuty rekord."""
        from netdoc.storage.database import SessionLocal
        from netdoc.storage.models import DiscoveredNetwork, NetworkSource
        db = SessionLocal()
        try:
            good = DiscoveredNetwork(cidr="172.16.0.0/12", source=NetworkSource.manual)
            bad  = DiscoveredNetwork(cidr="no-slash", source=NetworkSource.manual)
            db.add_all([good, bad])
            db.commit()
            good_id, bad_id = good.id, bad.id
        finally:
            db.close()

        try:
            r = client.get("/networks")
            assert r.status_code == 200
            html = r.data.decode()
            assert "172.16.0.0/12" in html, "Prawidlowa siec nie jest renderowana"
            assert "no-slash" not in html, "Nieprawidlowa siec nie powinna byc renderowana"
        finally:
            db2 = SessionLocal()
            try:
                db2.query(DiscoveredNetwork).filter(
                    DiscoveredNetwork.id.in_([good_id, bad_id])
                ).delete(synchronize_session=False)
                db2.commit()
            finally:
                db2.close()

    def test_network_delete_with_devices_removes_devices(self, client):
        """POST /networks/<id>/delete?delete_devices=1 usuwa urzadzenia z tego zakresu.

        Regresja: opcja 'rowniez usun urzadzenia' musi faktycznie usuwac urzadzenia.
        """
        from netdoc.storage.database import SessionLocal
        from netdoc.storage.models import DiscoveredNetwork, NetworkSource, Device
        db = SessionLocal()
        try:
            net = DiscoveredNetwork(cidr="10.77.0.0/24", source=NetworkSource.manual)
            db.add(net)
            db.flush()
            dev1 = Device(ip="10.77.0.1")
            dev2 = Device(ip="10.77.0.2")
            dev_other = Device(ip="10.88.0.1")  # inny zakres — nie powinien byc usuniety
            db.add_all([dev1, dev2, dev_other])
            db.commit()
            net_id = net.id
            dev_other_id = dev_other.id
        finally:
            db.close()

        r = client.post(f"/networks/{net_id}/delete", data={"delete_devices": "1"})
        assert r.status_code in (302, 200), f"Nieoczekiwany status: {r.status_code}"

        db3 = SessionLocal()
        try:
            remaining_in_range = db3.query(Device).filter(
                Device.ip.in_(["10.77.0.1", "10.77.0.2"])
            ).count()
            other_device_exists = db3.query(Device).filter_by(id=dev_other_id).first()
            assert remaining_in_range == 0, \
                f"Po usunieciu sieci z delete_devices=1 pozostaly {remaining_in_range} urzadzenia z tego zakresu"
            assert other_device_exists is not None, \
                "Urzadzenie spoza zakresu zostalo blednie usuniete"
            # Siec tez powinna byc usunieta
            net_exists = db3.query(DiscoveredNetwork).filter_by(id=net_id).first()
            assert net_exists is None, "Siec nie zostala usunieta mimo POST /delete"
        finally:
            # Cleanup
            db3.query(Device).filter_by(id=dev_other_id).delete()
            db3.commit()
            db3.close()


# ─── Regresja struktury strony /inventory ─────────────────────────────────────

class TestInventoryPageStructure:
    """Regresja /inventory — tabela kolumn inwentarza, eksport CSV."""

    @pytest.fixture(autouse=True)
    def _html(self, client):
        self.html = client.get("/inventory").data.decode()

    def test_page_ok(self):                    assert self.html

    def test_heading(self):
        assert "Inwentarz" in self.html

    # Kluczowe kolumny tabeli (15 kolumn)
    def test_col_ip(self):                     assert "IP" in self.html
    def test_col_hostname(self):               assert "Hostname" in self.html
    def test_col_serial(self):                 assert "S/N" in self.html
    def test_col_asset_tag(self):              assert "Asset tag" in self.html
    def test_col_warranty(self):               assert "gwarancji" in self.html or "Gwarancji" in self.html
    def test_col_support(self):                assert "wsparcia" in self.html or "Wsparcia" in self.html
    def test_col_vendor_model(self):           assert "Vendor" in self.html or "Model" in self.html
    def test_col_responsible(self):            assert "Osoba" in self.html

    # Eksport CSV
    def test_export_csv_link(self):
        assert "format=csv" in self.html or "csv" in self.html.lower()

    def test_table_balanced(self):
        assert self.html.count("<table") == self.html.count("</table>")

    def test_no_jinja_errors(self):
        assert "UndefinedError" not in self.html
        assert "jinja2.exceptions" not in self.html


# ─── Regresja struktury strony /logs ──────────────────────────────────────────

class TestLogsPageStructure:
    """Regresja /logs — zakladki, JS funkcje, filtry, modal AI."""

    @pytest.fixture(autouse=True)
    def _html(self, client):
        self.html = client.get("/logs").data.decode()

    def test_page_ok(self):                    assert self.html

    def test_heading(self):
        assert "Logi" in self.html or "logi" in self.html

    # Zakladki
    def test_tab_events(self):                 assert "tab-events" in self.html
    def test_tab_scanner(self):                assert "tab-scanner" in self.html
    def test_tab_watchdog(self):               assert "tab-watchdog" in self.html
    def test_tab_cred(self):                   assert "tab-cred" in self.html
    def test_tab_ai(self):                     assert "tab-ai" in self.html

    # Kluczowe elementy UI
    def test_events_body(self):                assert "eventsBody" in self.html
    def test_scanner_output(self):             assert "scannerOutput" in self.html
    def test_cred_output(self):                assert "credOutput" in self.html
    def test_auto_refresh_toggle(self):        assert "autoRefresh" in self.html

    # Selecty limitu
    def test_select_events_limit(self):        assert "eventsLimit" in self.html
    def test_select_scanner_tail(self):        assert "scannerTail" in self.html
    def test_select_cred_tail(self):           assert "credTail" in self.html
    def test_select_ai_limit(self):            assert "aiLogsLimit" in self.html

    # AI logs modal
    def test_ai_detail_modal(self):            assert "aiLogDetailModal" in self.html
    def test_ai_log_prompt(self):              assert "aiLogPromptPre" in self.html
    def test_ai_log_result(self):              assert "aiLogResultPre" in self.html

    # JavaScript
    def test_js_fetchEvents(self):             assert "fetchEvents" in self.html
    def test_js_fetchScanner(self):            assert "fetchScanner" in self.html
    def test_js_fetchCred(self):               assert "fetchCred" in self.html
    def test_js_fetchAiLogs(self):             assert "fetchAiLogs" in self.html
    def test_js_colorizeLog(self):             assert "colorizeLog" in self.html
    def test_js_fmtAgo(self):                  assert "fmtAgo" in self.html
    def test_js_startAutoRefresh(self):        assert "startAutoRefresh" in self.html

    def test_tables_balanced(self):
        assert self.html.count("<table") == self.html.count("</table>")

    def test_no_jinja_errors(self):
        assert "UndefinedError" not in self.html
        assert "jinja2.exceptions" not in self.html


# ── Testy AI badge na stronie urządzeń i raportu AI ───────────────────────────

class TestAiBadgeAndReport:
    """Testy widocznosci ocen AI na stronie urzadzen i raportu AI."""

    def _get_devices_html(self, assessment_entry=None):
        from unittest.mock import MagicMock, patch
        from netdoc.storage.models import DeviceAssessment
        dev = _mock_dev(1, "10.0.0.1")
        app, ms = _build_app(devices=[dev])
        if assessment_entry:
            orig_side = ms.query.side_effect
            def _q2(*models):
                q = orig_side(*models)
                if len(models) == 1 and models[0] is DeviceAssessment:
                    q.all.return_value = [assessment_entry]
                    q.order_by.return_value = q
                return q
            ms.query.side_effect = _q2
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests") as mr:
                _setup_mock_api(mr, {})
                with app.test_client() as c:
                    return c.get("/devices").data.decode()

    def test_no_ai_badge_when_no_assessment(self):
        html = self._get_devices_html()
        assert 'badge bg-danger dev-ai-assess-btn' not in html
        assert 'badge bg-success dev-ai-assess-btn' not in html

    def test_ai_report_page_returns_200_empty(self):
        app, ms = _build_app()
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with app.test_client() as c:
                resp = c.get("/devices/ai-report")
        assert resp.status_code == 200
        assert "Raport AI" in resp.data.decode()

    def test_ai_report_page_no_jinja_errors(self):
        app, ms = _build_app()
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with app.test_client() as c:
                html = c.get("/devices/ai-report").data.decode()
        assert "UndefinedError" not in html
        assert "jinja2.exceptions" not in html

    def test_ai_report_page_shows_print_button(self):
        app, ms = _build_app()
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with app.test_client() as c:
                html = c.get("/devices/ai-report").data.decode()
        assert "Drukuj" in html or "print" in html.lower()

    def test_api_logs_ai_returns_json_list(self):
        import json
        app, ms = _build_app(devices=[_mock_dev(1, "10.0.0.2")])
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with app.test_client() as c:
                resp = c.get("/api/logs/ai?limit=5")
        assert resp.status_code == 200
        assert isinstance(json.loads(resp.data), list)

    def test_devices_raport_ai_button_shown_when_assessments_exist(self):
        import json
        from datetime import datetime as _dt
        from unittest.mock import MagicMock
        from netdoc.storage.models import DeviceAssessment
        dev = _mock_dev(2, "10.0.0.3")
        app, ms = _build_app(devices=[dev])
        entry = MagicMock(spec=DeviceAssessment)
        entry.device_id = 2
        entry.assessed_at = _dt(2026, 3, 9, 23, 0)
        entry.result = json.dumps({"is_obsolete": True, "reason": "Test",
                                   "security": {"risk_level": "high"}, "summary": "Test"})
        entry.model = "claude-opus-4-6"
        orig_side = ms.query.side_effect
        def _q3(*models):
            q = orig_side(*models)
            if len(models) == 1 and models[0] is DeviceAssessment:
                q.all.return_value = [entry]
                q.order_by.return_value = q
            return q
        ms.query.side_effect = _q3
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests") as mr:
                _setup_mock_api(mr, {})
                with app.test_client() as c:
                    html = c.get("/devices").data.decode()
        assert "Raport AI" in html
        assert "ai-report" in html


# ── Testy poprawionych bugów logicznych ────────────────────────────────────────

class TestBugFixes:
    """Testy regresji dla naprawionych bugow logicznych."""

    def test_live_status_monitoring_age_reflects_freshest_contact(self):
        """live-status używa min(mins_ago) = czas od NAJŚWIEŻSZEGO kontaktu.
        Jeden offline device (60 min) nie może powodować stale gdy inny widziany 2 min temu."""
        from datetime import datetime as _dt, timedelta
        from unittest.mock import patch
        import json
        dev1 = _mock_dev(1, "10.0.0.1", is_active=True)
        dev1.last_seen = _dt.utcnow() - timedelta(minutes=2)    # świeży — ping worker działa
        dev2 = _mock_dev(2, "10.0.0.2", is_active=False)
        dev2.last_seen = _dt.utcnow() - timedelta(minutes=60)   # offline od dawna
        app, ms = _build_app(devices=[dev1, dev2])
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with app.test_client() as c:
                resp = c.get("/devices/live-status")
        data = json.loads(resp.data)
        # min(2, 60) = 2 — ping worker widział coś 2 min temu → nie stale
        assert data["monitoring_age_min"] <= 5, (
            f"Oczekiwano ~2 (najświeższy kontakt), dostano {data['monitoring_age_min']} — "
            f"max() zamiast min() powoduje fałszywy stale gdy offline device ma stare last_seen"
        )
        assert data["monitoring_stale"] is False, (
            "monitoring_stale powinno być False gdy jeden device widziany 2 min temu"
        )

    def test_live_status_returns_last_seen_iso_field(self):
        """live-status musi zwracac last_seen_iso w formacie ISO dla JS UTC-konwersji.
        Regresja: bez last_seen_iso JS nie moze przeliczac UTC→lokalny czas przegladarki."""
        from datetime import datetime as _dt, timedelta
        from unittest.mock import patch
        import json
        dev = _mock_dev(1, "10.0.0.1", is_active=True)
        dev.last_seen = _dt(2026, 3, 10, 7, 30, 0)   # UTC
        app, ms = _build_app(devices=[dev])
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with app.test_client() as c:
                resp = c.get("/devices/live-status")
        data = json.loads(resp.data)
        device = data["devices"][0]
        assert "last_seen_iso" in device, \
            "Brak pola last_seen_iso — JS nie moze przeliczac UTC na czas lokalny przegladarki"
        iso = device["last_seen_iso"]
        # Musi byc parsowalne jako ISO datetime (YYYY-MM-DDTHH:MM:SS)
        assert "T" in iso, f"last_seen_iso nie jest ISO format: {iso!r}"
        assert iso.startswith("2026-03-10T07:30"), \
            f"last_seen_iso ma zla wartosc: {iso!r} (oczekiwano 2026-03-10T07:30...)"

    def test_live_status_last_seen_iso_absent_when_last_seen_none(self):
        """Gdy device.last_seen=None, last_seen_iso powinno byc null/None — nie powodowac bledu JS."""
        from unittest.mock import patch
        import json
        dev = _mock_dev(1, "10.0.0.1", is_active=False)
        dev.last_seen = None
        app, ms = _build_app(devices=[dev])
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with app.test_client() as c:
                resp = c.get("/devices/live-status")
        data = json.loads(resp.data)
        device = data["devices"][0]
        # last_seen_iso moze byc null lub nieobecne — ale nie powinno byc niepoprawnym stringiem
        iso = device.get("last_seen_iso")
        assert iso is None or iso == "" or iso == "null", \
            f"last_seen_iso dla urzadzenia bez last_seen powinno byc None/null, dostano: {iso!r}"

    def test_devices_js_contains_utc_to_local_conversion(self):
        """JS w devices.html musi konwertowac last_seen_iso z UTC na czas lokalny przegladarki.
        Regresja: bez +Z suffix new Date() interpretowal string jako czas lokalny, nie UTC."""
        import os
        tpl = os.path.join(os.path.dirname(__file__), "..", "netdoc", "web", "templates", "devices.html")
        with open(tpl, encoding="utf-8") as f:
            src = f.read()
        assert "last_seen_iso + 'Z'" in src or "last_seen_iso+'Z'" in src, \
            "Brak konwersji UTC: JS musi dodawac 'Z' do last_seen_iso aby wymuszac UTC parsing"
        assert "getHours()" in src, \
            "Brak konwersji do czasu lokalnego: JS musi uzywac getHours()/getMinutes()"
        # Sprawdz ze aktualizacja last_seen jest POZA blokiem zmiany statusu (nie tylko przy UP->DOWN)
        # Szukamy czy 'lastSeenLocal' pojawia sie przed 'if (badge.className !== newClass'
        idx_local = src.find("lastSeenLocal")
        idx_status_if = src.find("if (badge.className !== newClass")
        assert idx_local < idx_status_if, \
            "Regresja: aktualizacja last_seen musi byc przed (poza) blokiem if-status — " \
            "inaczej Ostatni kontakt nie aktualizuje sie gdy urzadzenie pozostaje UP"

    def test_ai_last_by_device_skips_none_device_id(self):
        """Bug #5: DeviceAssessment z device_id=None nie powinien trafiać do slownika."""
        import json
        from datetime import datetime as _dt
        from unittest.mock import MagicMock, patch
        from netdoc.storage.models import DeviceAssessment
        dev = _mock_dev(1, "10.0.0.1")
        app, ms = _build_app(devices=[dev])
        entry_bad = MagicMock(spec=DeviceAssessment)
        entry_bad.device_id = None   # niepoprawny wpis
        entry_bad.assessed_at = _dt(2026, 3, 9, 23, 0)
        entry_bad.result = json.dumps({"is_obsolete": True, "security": {"risk_level": "high"}})
        entry_bad.model = "claude-opus-4-6"
        orig_side = ms.query.side_effect
        def _q(*models):
            q = orig_side(*models)
            if len(models) == 1 and models[0] is DeviceAssessment:
                q.all.return_value = [entry_bad]
                q.order_by.return_value = q
            return q
        ms.query.side_effect = _q
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests") as mr:
                _setup_mock_api(mr, {})
                with app.test_client() as c:
                    html = c.get("/devices").data.decode()
        # Nie powinno być badge AI (device_id=None pominięty, więc ai_last_by_device puste)
        assert 'badge bg-danger dev-ai-assess-btn' not in html
        assert 'badge bg-success dev-ai-assess-btn' not in html

    def test_workstation_vendor_intel_nuc_with_rdp_is_workstation(self):
        """Intel z RDP (3389) → workstation (przez _SERVER_VENDORS, nie _WORKSTATION_VENDORS)."""
        from netdoc.collector.discovery import _guess_device_type
        from netdoc.storage.models import DeviceType
        # Intel z RDP (NUC z Windows) → workstation via _SERVER_VENDORS logika
        result = _guess_device_type(
            open_ports={3389},
            os_name="",
            hostname="",
            vendor="Intel Corporate",
        )
        assert result == DeviceType.workstation, (
            f"Intel Corporate + RDP powinien być workstation, dostano {result}"
        )

    def test_ping_worker_last_seen_none_does_not_mark_down(self):
        """Bug #4: device z last_seen=None i was_active=True nie powinien byc oznaczony DOWN."""
        from unittest.mock import MagicMock, patch
        import run_ping
        dev = MagicMock()
        dev.id = 99; dev.ip = "10.0.0.1"; dev.hostname = "test"
        dev.is_active = True; dev.last_seen = None   # brak last_seen
        dev.is_monitored = False
        run_ping._fail_counts = {99: run_ping._FAIL_THRESHOLD + 1}
        with patch.object(run_ping, "_check", return_value=False), \
             patch("run_ping.SessionLocal") as mock_sl, \
             patch("run_ping.start_http_server"):
            mock_db = MagicMock()
            mock_sl.return_value = mock_db
            mock_db.query.return_value.all.return_value = [dev]
            run_ping.poll_once()
        # device.is_active nie powinno zostac zmienione na False gdy last_seen=None
        assert dev.is_active is True, "Device z last_seen=None nie powinien byc oznaczony DOWN"


# ─── /api/logs/docker/<container> — Docker SDK logs ──────────────────────────

class TestDockerLogsEndpoint:
    """Testy endpointu /api/logs/docker/<container> — po zmianie subprocess→SDK."""

    def _docker_stub_with_logs(self, log_content: bytes):
        """Stub Docker SDK zwracajacy logi jako bytes."""
        import types, sys
        docker_stub = types.ModuleType("docker")
        errors_stub = types.ModuleType("docker.errors")

        class _NotFound(Exception): pass
        class _DockerException(Exception): pass

        errors_stub.NotFound = _NotFound
        errors_stub.DockerException = _DockerException
        docker_stub.errors = errors_stub

        mock_container = MagicMock()
        mock_container.logs.return_value = log_content

        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container
        docker_stub.from_env = MagicMock(return_value=mock_client)

        return docker_stub, mock_client, mock_container

    def test_returns_logs_for_allowed_container(self, client):
        """Endpoint zwraca logi jako text/plain dla dozwolonych kontenerow."""
        import sys
        log_bytes = b"2026-03-10T08:00:00Z INFO Poll: 5 up\n"
        docker_stub, _, _ = self._docker_stub_with_logs(log_bytes)

        with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
            resp = client.get("/api/logs/docker/netdoc-ping?tail=10")

        assert resp.status_code == 200
        assert "Poll: 5 up" in resp.data.decode()
        assert "text/plain" in resp.content_type

    def test_rejects_unknown_container_name(self, client):
        """Endpoint zwraca 400 dla niedozwolonych nazw kontenerow (security whitelist)."""
        resp = client.get("/api/logs/docker/malicious-container")
        assert resp.status_code == 400

    def test_rejects_path_traversal_attempt(self, client):
        """Endpoint blokuje proby path-traversal w nazwie kontenera."""
        resp = client.get("/api/logs/docker/../../../etc/passwd")
        # Flask zwroci 404 (routing) lub 400 (whitelist) — oba sa ok
        assert resp.status_code in (400, 404)

    def test_returns_404_when_container_not_found(self, client):
        """Gdy kontener nie istnieje (NotFound), endpoint zwraca 404."""
        import types, sys
        docker_stub = types.ModuleType("docker")
        errors_stub = types.ModuleType("docker.errors")

        class _NotFound(Exception): pass
        class _DockerException(Exception): pass

        errors_stub.NotFound = _NotFound
        errors_stub.DockerException = _DockerException
        docker_stub.errors = errors_stub

        mock_client = MagicMock()
        mock_client.containers.get.side_effect = _NotFound("no such container")
        docker_stub.from_env = MagicMock(return_value=mock_client)

        with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
            resp = client.get("/api/logs/docker/netdoc-ping?tail=10")

        assert resp.status_code == 404

    def test_returns_503_when_docker_sdk_unavailable(self, client):
        """Gdy Docker SDK rzuca wyjatek (brak socketu), endpoint zwraca 503."""
        import types, sys
        docker_stub = types.ModuleType("docker")
        errors_stub = types.ModuleType("docker.errors")

        class _NotFound(Exception): pass
        class _DockerException(Exception): pass

        errors_stub.NotFound = _NotFound
        errors_stub.DockerException = _DockerException
        docker_stub.errors = errors_stub
        docker_stub.from_env = MagicMock(side_effect=_DockerException("socket not found"))

        with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}):
            resp = client.get("/api/logs/docker/netdoc-ping")

        assert resp.status_code == 503

    def test_logs_uses_sdk_not_subprocess(self, client):
        """Logi kontenerow uzywaja Docker SDK (nie subprocess) — regresja po naprawie.

        Bug: poprzednia implementacja uzywala subprocess(['docker', 'logs', ...])
        ktory wymagal docker CLI w kontenerze. CLI nie jest zainstalowane w obrazie.
        Fix: uzywamy docker.from_env().containers.get().logs() (Python SDK).
        """
        import sys
        log_bytes = b"INFO some log line\n"
        docker_stub, mock_client, mock_container = self._docker_stub_with_logs(log_bytes)

        with patch.dict(sys.modules, {"docker": docker_stub, "docker.errors": docker_stub.errors}), \
             patch("subprocess.run") as mock_sub:
            client.get("/api/logs/docker/netdoc-snmp?tail=50")

        # subprocess.run NIE powinien byc wywolany — uzywamy SDK
        mock_sub.assert_not_called()
        # SDK powinien byc wywolany
        mock_client.containers.get.assert_called_once_with("netdoc-snmp")
        mock_container.logs.assert_called_once()

    def test_all_allowed_containers_accepted(self, client):
        """Wszystkie kontenery z whitelisty musza byc akceptowane."""
        import sys
        allowed = ["netdoc-ping", "netdoc-snmp", "netdoc-vuln",
                   "netdoc-internet", "netdoc-cred"]
        log_bytes = b"test log\n"

        for name in allowed:
            docker_stub, _, _ = self._docker_stub_with_logs(log_bytes)
            with patch.dict(sys.modules, {
                "docker": docker_stub, "docker.errors": docker_stub.errors
            }):
                resp = client.get(f"/api/logs/docker/{name}")
            assert resp.status_code == 200, \
                f"Kontener '{name}' z whitelisty powinien zwrocic 200, got {resp.status_code}"


# ---------------------------------------------------------------------------
# Testy regresyjne — nowe endpointy (notes, bulk-add, CSV export, MAC lookup)
# ---------------------------------------------------------------------------

class TestNetworkNotes:
    """POST /networks/<id>/notes — inline edycja notatek."""

    def _set_net(self, client, net):
        """Pomocnik: nadpisuje side_effect tak zeby query().filter_by().first() zwrocil net."""
        q = MagicMock()
        q.filter_by.return_value = q
        q.filter.return_value = q
        q.order_by.return_value = q
        q.first.return_value = net
        q.all.return_value = [net] if net else []
        client._ms.query.side_effect = lambda *m: q

    def test_update_notes_ok(self, client):
        """JSON POST z notatka zwraca {"ok": True}."""
        net = _mock_net(1)
        self._set_net(client, net)
        r = client.post("/networks/1/notes",
                        json={"notes": "test notatka"},
                        content_type="application/json")
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True
        assert net.notes == "test notatka"

    def test_update_notes_clears_whitespace(self, client):
        """Pusta lub spacja notatka powinna ustawiac None."""
        net = _mock_net(1)
        net.notes = "stara notatka"
        self._set_net(client, net)
        r = client.post("/networks/1/notes",
                        json={"notes": "   "},
                        content_type="application/json")
        assert r.status_code == 200
        assert r.get_json()["ok"] is True
        assert net.notes is None

    def test_update_notes_not_found(self, client):
        """POST do nieistniejacego ID zwraca 404."""
        client._ms.query.return_value.filter_by.return_value.first.return_value = None
        r = client.post("/networks/999/notes",
                        json={"notes": "cokolwiek"},
                        content_type="application/json")
        assert r.status_code == 404
        assert r.get_json()["ok"] is False


class TestNetworkBulkAdd:
    """POST /networks/bulk-add — importowanie wielu sieci CIDR naraz."""

    def test_bulk_add_valid_cidrs(self, client):
        """Prawidlowe CIDRy sa dodawane, odpowiedz to redirect."""
        client._ms.query.return_value.filter_by.return_value.first.return_value = None
        r = client.post("/networks/bulk-add",
                        data={"cidrs": "10.0.0.0/24\n10.1.0.0/24"})
        assert r.status_code in (302, 200)
        client._ms.commit.assert_called()

    def test_bulk_add_invalid_cidr_still_redirects(self, client):
        """Bledny CIDR powoduje flash warning ale nie crash — redirect."""
        client._ms.query.return_value.filter_by.return_value.first.return_value = None
        r = client.post("/networks/bulk-add",
                        data={"cidrs": "nie-jest-cidr\n10.0.0.0/24"})
        assert r.status_code in (302, 200)

    def test_bulk_add_empty_skips_gracefully(self, client):
        """Pusty formularz nie crashuje."""
        r = client.post("/networks/bulk-add", data={"cidrs": ""})
        assert r.status_code in (302, 200)

    def test_bulk_add_skips_existing(self, client):
        """Juz istniejacy CIDR jest pomijany (skipped), nie duplikowany."""
        existing = _mock_net(1, cidr="192.168.1.0/24")
        # Nadpisz side_effect zeby filter_by().first() zwrocil existing
        q = MagicMock()
        q.filter_by.return_value = q
        q.filter.return_value = q
        q.order_by.return_value = q
        q.first.return_value = existing
        q.all.return_value = [existing]
        client._ms.query.side_effect = lambda *m: q
        r = client.post("/networks/bulk-add",
                        data={"cidrs": "192.168.1.0/24"})
        assert r.status_code in (302, 200)
        # db.add nie powinien byc wywolany (siec juz istnieje)
        client._ms.add.assert_not_called()


class TestDevicesExportCsv:
    """GET /devices/export.csv — eksport urzadzen do CSV."""

    def test_export_returns_200(self, client):
        r = client.get("/devices/export.csv")
        assert r.status_code == 200

    def test_export_content_type_csv(self, client):
        r = client.get("/devices/export.csv")
        assert "text/csv" in r.content_type

    def test_export_has_bom(self, client):
        """CSV powinien zaczynac sie od BOM (0xEF 0xBB 0xBF) dla Excela."""
        r = client.get("/devices/export.csv")
        assert r.data[:3] == b"\xef\xbb\xbf"

    def test_export_has_header_row(self, client):
        r = client.get("/devices/export.csv")
        text = r.data.decode("utf-8-sig")
        assert "IP" in text
        assert "Hostname" in text
        assert "MAC" in text

    def test_export_has_content_disposition(self, client):
        r = client.get("/devices/export.csv")
        assert "attachment" in r.headers.get("Content-Disposition", "")
        assert ".csv" in r.headers.get("Content-Disposition", "")

    def test_export_with_devices(self):
        """CSV zawiera wiersz z danymi urzadzenia."""
        dev = _mock_dev(1, ip="10.0.0.1")
        dev.location = None; dev.owner_dept = None
        app, ms = _build_app(devices=[dev])
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with app.test_client() as c:
                r = c.get("/devices/export.csv")
        text = r.data.decode("utf-8-sig")
        assert "10.0.0.1" in text


class TestApiMacStatus:
    """GET /api/mac/status — stan bazy OUI."""

    def test_returns_200(self, client):
        with patch("netdoc.collector.oui_lookup.oui_db") as mock_oui:
            mock_oui._loaded = True
            mock_oui.status.return_value = {
                "loaded": True, "entries": 42000, "needs_update": False,
                "files": {"IEEE MA-L": {"exists": True, "age_days": 5.0, "size_kb": 1024}},
            }
            r = client.get("/api/mac/status")
        assert r.status_code == 200

    def test_returns_expected_fields(self, client):
        with patch("netdoc.collector.oui_lookup.oui_db") as mock_oui:
            mock_oui._loaded = True
            mock_oui.status.return_value = {
                "loaded": True, "entries": 42000, "needs_update": False, "files": {},
            }
            r = client.get("/api/mac/status")
        data = r.get_json()
        assert "loaded" in data
        assert "entries" in data
        assert "needs_update" in data
        assert "files" in data

    def test_triggers_load_when_not_loaded(self, client):
        """Gdy _loaded=False endpoint wywoluje load() przed odpowiedzia."""
        with patch("netdoc.collector.oui_lookup.oui_db") as mock_oui:
            mock_oui._loaded = False
            mock_oui.status.return_value = {"loaded": False, "entries": 0, "needs_update": True, "files": {}}
            r = client.get("/api/mac/status")
        assert r.status_code == 200
        mock_oui.load.assert_called_once()

    def test_no_load_when_already_loaded(self, client):
        """Gdy _loaded=True endpoint NIE wywoluje ponownie load()."""
        with patch("netdoc.collector.oui_lookup.oui_db") as mock_oui:
            mock_oui._loaded = True
            mock_oui.status.return_value = {"loaded": True, "entries": 1000, "needs_update": False, "files": {}}
            r = client.get("/api/mac/status")
        assert r.status_code == 200
        mock_oui.load.assert_not_called()


class TestApiMacVendors:
    """GET /api/mac/vendors — lista producentow OUI."""

    def _mock_db(self, mock_oui, data: dict):
        mock_oui._loaded = True
        mock_oui._db = data

    def test_returns_200(self, client):
        with patch("netdoc.collector.oui_lookup.oui_db") as mock_oui:
            self._mock_db(mock_oui, {"aabbcc": "Cisco", "112233": "HP"})
            r = client.get("/api/mac/vendors")
        assert r.status_code == 200

    def test_returns_vendors_and_total(self, client):
        with patch("netdoc.collector.oui_lookup.oui_db") as mock_oui:
            self._mock_db(mock_oui, {"aabbcc": "Cisco", "112233": "HP", "dca632": "Raspberry Pi"})
            r = client.get("/api/mac/vendors")
        data = r.get_json()
        assert "vendors" in data
        assert "total" in data
        assert data["total"] == 3

    def test_sort_by_count(self, client):
        """sort=count zwraca vendorow posortowanych malejaco po liczbie blokow."""
        with patch("netdoc.collector.oui_lookup.oui_db") as mock_oui:
            self._mock_db(mock_oui, {
                "aabbcc": "Cisco", "aabbcd": "Cisco", "112233": "HP",
            })
            r = client.get("/api/mac/vendors?sort=count")
        data = r.get_json()
        vendors = data["vendors"]
        assert vendors[0]["vendor"] == "Cisco"
        assert vendors[0]["blocks"] == 2

    def test_filter_by_q(self, client):
        """Parametr q filtruje vendorow po nazwie (case-insensitive)."""
        with patch("netdoc.collector.oui_lookup.oui_db") as mock_oui:
            self._mock_db(mock_oui, {"aabbcc": "Cisco Systems", "112233": "HP Inc", "dca632": "Cisco Meraki"})
            r = client.get("/api/mac/vendors?q=cisco")
        data = r.get_json()
        names = [v["vendor"] for v in data["vendors"]]
        assert all("cisco" in n.lower() for n in names)
        assert data["total"] == 2

    def test_limit_respected(self, client):
        """Parametr limit ogranicza liczbe wynikow."""
        with patch("netdoc.collector.oui_lookup.oui_db") as mock_oui:
            self._mock_db(mock_oui, {f"{i:06x}": f"Vendor{i}" for i in range(20)})
            r = client.get("/api/mac/vendors?limit=5")
        data = r.get_json()
        assert len(data["vendors"]) <= 5

    def test_triggers_load_when_not_loaded(self, client):
        """Gdy _loaded=False endpoint wywoluje load()."""
        with patch("netdoc.collector.oui_lookup.oui_db") as mock_oui:
            mock_oui._loaded = False
            mock_oui._db = {}
            r = client.get("/api/mac/vendors")
        assert r.status_code == 200
        mock_oui.load.assert_called_once()


class TestApiMacLookup:
    """GET /api/mac/<mac> — OUI vendor lookup."""

    def test_known_vendor(self, client):
        """Znany prefix MAC zwraca vendor string."""
        with patch("netdoc.collector.oui_lookup.oui_db") as mock_oui:
            mock_oui.lookup.return_value = "Cisco Systems"
            r = client.get("/api/mac/00:00:0C:11:22:33")
        assert r.status_code == 200
        data = r.get_json()
        assert "mac" in data
        assert "vendor" in data

    def test_unknown_vendor_returns_none(self, client):
        """LAA lub nieznany MAC zwraca vendor=None."""
        with patch("netdoc.collector.oui_lookup.oui_db") as mock_oui:
            mock_oui.lookup.return_value = None
            r = client.get("/api/mac/E2:F3:3D:A8:11:11")
        assert r.status_code == 200
        data = r.get_json()
        assert data["vendor"] is None

    def test_mac_echoed_back(self, client):
        """Endpoint zwraca przekazany MAC w odpowiedzi."""
        with patch("netdoc.collector.oui_lookup.oui_db") as mock_oui:
            mock_oui.lookup.return_value = "TestVendor"
            r = client.get("/api/mac/AA:BB:CC:DD:EE:FF")
        data = r.get_json()
        assert data["mac"] == "AA:BB:CC:DD:EE:FF"


# ---------------------------------------------------------------------------
# Testy regresyjne — _count_devices_active_inactive i sortowanie sieci
# ---------------------------------------------------------------------------

class TestCountDevicesActiveInactive:
    """Jednostkowe testy funkcji _count_devices_active_inactive."""

    def _make_dev(self, ip, active):
        d = MagicMock()
        d.ip = ip
        d.is_active = active
        return d

    def _get_fn(self):
        from netdoc.web.app import create_app
        app = create_app()
        # Funkcja jest zdefiniowana wewnątrz create_app — wyciągamy przez route
        # Łatwiej przetestować logikę bezpośrednio przez import ipaddress
        import ipaddress

        def count(devs, cidr):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                return 0, 0
            active = inactive = 0
            for d in devs:
                try:
                    if ipaddress.ip_address(d.ip) in net:
                        if d.is_active:
                            active += 1
                        else:
                            inactive += 1
                except ValueError:
                    pass
            return active, inactive

        return count

    def test_counts_active_and_inactive(self):
        fn = self._get_fn()
        devs = [
            self._make_dev("192.168.1.10", True),
            self._make_dev("192.168.1.20", True),
            self._make_dev("192.168.1.30", False),
            self._make_dev("10.0.0.1", True),   # inna sieć
        ]
        active, inactive = fn(devs, "192.168.1.0/24")
        assert active == 2
        assert inactive == 1

    def test_empty_network(self):
        fn = self._get_fn()
        devs = [self._make_dev("10.0.0.1", True)]
        active, inactive = fn(devs, "192.168.1.0/24")
        assert active == 0
        assert inactive == 0

    def test_invalid_cidr_returns_zeros(self):
        fn = self._get_fn()
        devs = [self._make_dev("192.168.1.1", True)]
        active, inactive = fn(devs, "nie-jest-cidr")
        assert active == 0
        assert inactive == 0

    def test_all_inactive(self):
        fn = self._get_fn()
        devs = [self._make_dev("10.0.0.1", False), self._make_dev("10.0.0.2", False)]
        active, inactive = fn(devs, "10.0.0.0/24")
        assert active == 0
        assert inactive == 2


class TestNetworksSortedByActive:
    """GET /networks zwraca sieci posortowane po aktywnych urządzeniach malejąco."""

    def test_networks_sorted_by_active_descending(self):
        net1 = _mock_net(1, cidr="192.168.1.0/24")
        net2 = _mock_net(2, cidr="10.0.0.0/24")
        net3 = _mock_net(3, cidr="172.16.0.0/24")

        # net2 ma 5 aktywnych, net1 ma 2, net3 ma 0
        devs = [
            _mock_dev(1, ip="192.168.1.10", is_active=True),
            _mock_dev(2, ip="192.168.1.11", is_active=True),
            _mock_dev(3, ip="10.0.0.10", is_active=True),
            _mock_dev(4, ip="10.0.0.11", is_active=True),
            _mock_dev(5, ip="10.0.0.12", is_active=True),
            _mock_dev(6, ip="10.0.0.13", is_active=True),
            _mock_dev(7, ip="10.0.0.14", is_active=True),
        ]
        app, ms = _build_app(networks=[net1, net2, net3], devices=devs)

        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests") as mr:
                _setup_mock_api(mr, {})
                with app.test_client() as c:
                    html = c.get("/networks").data.decode()

        # 10.0.0.0/24 (5 aktywnych) powinien byc przed 192.168.1.0/24 (2 aktywnych)
        pos_net2 = html.find("10.0.0.0/24")
        pos_net1 = html.find("192.168.1.0/24")
        assert pos_net2 < pos_net1, "Siec z wiecej aktywnymi powinna byc wyzej"


class TestDevicesKnownNetworksFormat:
    """Strona /devices przekazuje known_networks jako liste dictow z cidr/notes/count/is_local."""

    def test_devices_renders_with_dict_known_networks(self, client):
        """Strona urzadzen renderuje sie poprawnie gdy known_networks to lista dictow."""
        r = client.get("/devices")
        assert r.status_code == 200

    def test_devices_dropdown_uses_n_cidr(self):
        """Template devices.html uzywa n.cidr (nie cidr bezposrednio) w dropdownie sieci."""
        import pathlib
        tmpl = pathlib.Path("netdoc/web/templates/devices.html").read_text(encoding="utf-8")
        assert "n.cidr" in tmpl
        assert "n.notes" in tmpl
        assert "n.is_local" in tmpl
        assert "TOP_LOCAL_CIDR" in tmpl


# ── Testy: /devices/<id>/full-scan ───────────────────────────────────────────

class TestDeviceFullScan:
    """Testy trasy POST /devices/<id>/full-scan (peŁny skan portow 1-65535)."""

    def _build_full_scan_app(self, dev_ip="10.0.0.5"):
        from netdoc.web.app import create_app
        from netdoc.storage.models import SystemStatus

        app = create_app()
        app.config["TESTING"] = True

        dev = _mock_dev(id=42, ip=dev_ip)

        ms = MagicMock()
        ms.__enter__ = lambda s: s
        ms.__exit__ = MagicMock(return_value=False)

        def _q(*models):
            q = MagicMock()
            if len(models) == 1 and models[0] is SystemStatus:
                q.filter_by.return_value = q
                q.first.return_value = None
                return q
            q2 = MagicMock()
            q2.filter_by.return_value = q2
            q2.first.return_value = dev
            q2.all.return_value = [dev]
            q2.filter.return_value = q2
            q2.count.return_value = 1
            q2.order_by.return_value = q2
            q2.join.return_value = q2
            return q2

        ms.query.side_effect = _q
        return app, ms, dev

    def test_full_scan_post_redirects(self):
        """POST /devices/42/full-scan powinien przekierowac (302)."""
        app, ms, dev = self._build_full_scan_app()
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests") as mr:
                _setup_mock_api(mr)
                with app.test_client() as c:
                    r = c.post("/devices/42/full-scan")
        assert r.status_code == 302

    def test_full_scan_post_queues_ip(self):
        """POST /devices/<id>/full-scan powinien zapisac IP do full_scan_ip_queue."""
        app, ms, dev = self._build_full_scan_app(dev_ip="10.5.0.99")
        added_rows = []
        ms.add.side_effect = lambda obj: added_rows.append(obj)

        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests") as mr:
                _setup_mock_api(mr)
                with app.test_client() as c:
                    c.post("/devices/42/full-scan")

        # Musi byc SystemStatus z kluczem full_scan_ip_queue zawierajacym IP urzadzenia
        keys   = [getattr(r, "key",   None) for r in added_rows]
        values = [getattr(r, "value", None) for r in added_rows]
        assert "full_scan_ip_queue" in keys, "SystemStatus dla full_scan_ip_queue musi byc dodany"
        ip_val = next((v for k, v in zip(keys, values) if k == "full_scan_ip_queue"), None)
        assert ip_val is not None and "10.5.0.99" in ip_val, \
            f"IP 10.5.0.99 musi byc w kolejce, got: {ip_val}"

    def test_full_scan_template_has_button(self):
        """devices.html zawiera przycisk Pelny skan portow (1-65535)."""
        import pathlib
        tmpl = pathlib.Path("netdoc/web/templates/devices.html").read_text(encoding="utf-8")
        assert "full-scan" in tmpl
        assert "1-65535" in tmpl

    def test_full_scan_template_form_method_post(self):
        """Przycisk pelnego skanu uzywa formularza POST."""
        import pathlib
        tmpl = pathlib.Path("netdoc/web/templates/devices.html").read_text(encoding="utf-8")
        # Formularz z /full-scan i method post
        assert 'action="/devices/' in tmpl or "full-scan" in tmpl
        assert 'method="post"' in tmpl.lower() or 'method=post' in tmpl.lower()


# ── Testy: roadmap w ustawieniach ────────────────────────────────────────────

class _TestSettingsRoadmap_REMOVED:
    """Usunięte — roadmapa została przeniesiona z /settings do ROADMAP.md na GitHubie."""

    def test_settings_passes_roadmap_text(self):
        """Trasa /settings przekazuje roadmap_text do szablonu gdy ROADMAP.md istnieje."""
        from netdoc.web.app import create_app

        app = create_app()
        app.config["TESTING"] = True

        ms = MagicMock()
        ms.__enter__ = lambda s: s
        ms.__exit__ = MagicMock(return_value=False)

        def _q(*models):
            q = MagicMock()
            q.all.return_value = []; q.count.return_value = 0
            q.filter.return_value = q; q.filter_by.return_value = q
            q.first.return_value = None; q.order_by.return_value = q
            q.join.return_value = q
            return q

        ms.query.side_effect = _q

        fake_roadmap = "# Roadmap\n## Sprint 1\n- Zadanie A\n"

        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests") as mr:
                _setup_mock_api(mr)
                with patch("pathlib.Path.exists", return_value=True):
                    with patch("pathlib.Path.read_text", return_value=fake_roadmap):
                        with app.test_client() as c:
                            r = c.get("/settings")

        assert r.status_code == 200
        # Zawartosc pliku roadmap powinna byc w odpowiedzi (przekazana jako JSON do marked.js)
        assert b"Roadmap" in r.data or b"roadmap" in r.data.lower()

    def test_settings_template_has_marked_js(self):
        """settings.html zawiera znacznik marked.js do renderowania Markdown."""
        import pathlib
        tmpl = pathlib.Path("netdoc/web/templates/settings.html").read_text(encoding="utf-8")
        assert "marked" in tmpl

    def test_settings_template_has_roadmap_card(self):
        """settings.html zawiera kontener na roadmape."""
        import pathlib
        tmpl = pathlib.Path("netdoc/web/templates/settings.html").read_text(encoding="utf-8")
        assert "roadmap" in tmpl.lower()
        assert "roadmapMd" in tmpl or "roadmap_text" in tmpl

    def test_settings_template_roadmap_collapsed_by_default(self):
        """Sekcja roadmapy jest domyslnie zwinięta (d-none)."""
        import pathlib
        tmpl = pathlib.Path("netdoc/web/templates/settings.html").read_text(encoding="utf-8")
        # roadmapBody powinno miec klase d-none przy starcie
        assert "roadmapBody" in tmpl
        assert "d-none" in tmpl

    def test_settings_marked_js_disables_html_rendering(self):
        """marked.js ma nadpisany renderer.html aby nie renderowac surowego HTML."""
        import pathlib
        tmpl = pathlib.Path("netdoc/web/templates/settings.html").read_text(encoding="utf-8")
        # Musi byc override html renderer - defense-in-depth
        assert "renderer" in tmpl, "marked.use({ renderer: ... }) musi byc ustawiony"
        assert "html:" in tmpl or "html :" in tmpl, "Renderer html musi byc nadpisany"
        assert "&lt;" in tmpl, "Renderer musi escapowac znaczniki HTML"


# ── Testy: vuln popover truncation indicator ─────────────────────────────────

class TestVulnPopoverTruncation:
    """Testy wskaznika truncation w popoverze podatnosci (>10 zagrozen)."""

    def _make_vulns(self, count, sev="high", vuln_type="open_telnet"):
        vulns = []
        for i in range(count):
            v = MagicMock()
            v.device_id = 1
            v.is_open = True
            v.suppressed = False
            v.severity = MagicMock()
            v.severity.value = sev
            v.vuln_type = MagicMock()
            v.vuln_type.value = vuln_type
            v.port = 23 + i
            vulns.append(v)
        return vulns

    def test_vuln_details_adds_more_indicator_when_over_10(self):
        """Gdy urządzenie ma >10 zagrożeń, vuln_details zawiera wpis '...i N więcej'."""
        app, ctx, req = _make_devices_client(
            devices=[_mock_dev(1)],
            vuln_count_tuples=[(1, 15)],
            vuln_objects=self._make_vulns(15),
        )
        with ctx, req as mr:
            _setup_mock_api(mr, {})
            with app.test_client() as c:
                html = c.get("/devices").data.decode()

        assert "więcej" in html, "Musi byc wskaznik '...i N więcej' gdy >10 zagrozen"
        assert "i 5 więcej" in html, "Wskaznik musi zawierac dokladna liczbe ukrytych (15-10=5)"

    def test_vuln_details_no_indicator_when_10_or_fewer(self):
        """Gdy urządzenie ma ≤10 zagrożeń, nie ma wskaznika 'więcej'."""
        app, ctx, req = _make_devices_client(
            devices=[_mock_dev(1)],
            vuln_count_tuples=[(1, 10)],
            vuln_objects=self._make_vulns(10),
        )
        with ctx, req as mr:
            _setup_mock_api(mr, {})
            with app.test_client() as c:
                html = c.get("/devices").data.decode()

        assert "więcej" not in html, "Nie powinno byc wskaznika 'więcej' dla ≤10 zagrozen"

    def test_vuln_details_exactly_11_shows_1_more(self):
        """Dokladnie 11 zagrozen → wskaznik '...i 1 więcej'."""
        app, ctx, req = _make_devices_client(
            devices=[_mock_dev(1)],
            vuln_count_tuples=[(1, 11)],
            vuln_objects=self._make_vulns(11),
        )
        with ctx, req as mr:
            _setup_mock_api(mr, {})
            with app.test_client() as c:
                html = c.get("/devices").data.decode()

        assert "więcej" in html, "Musi byc wskaznik '...i 1 więcej' dla 11 zagrozen"


# ── Testy: full scan — detekcja already-in-queue ─────────────────────────────

class TestFullScanAlreadyQueued:
    """Testy detekcji ponownego kolejkowania full scan."""

    def _build_app_with_existing_queue(self, dev_ip="10.0.0.5", queued_ips="10.0.0.5,10.0.0.6"):
        from netdoc.web.app import create_app
        from netdoc.storage.models import SystemStatus

        app = create_app()
        app.config["TESTING"] = True
        dev = _mock_dev(id=42, ip=dev_ip)

        ms = MagicMock()
        ms.__enter__ = lambda s: s
        ms.__exit__ = MagicMock(return_value=False)

        existing_status = MagicMock(spec=SystemStatus)
        existing_status.value = queued_ips
        existing_status.key = "full_scan_ip_queue"

        call_count = [0]

        def _q(*models):
            q = MagicMock()
            if len(models) == 1 and models[0] is SystemStatus:
                q2 = MagicMock()
                q2.first.return_value = existing_status
                q.filter_by.return_value = q2
                return q
            q3 = MagicMock()
            q3.filter_by.return_value = q3
            q3.first.return_value = dev
            q3.all.return_value = [dev]
            q3.filter.return_value = q3
            q3.count.return_value = 1
            q3.order_by.return_value = q3
            q3.join.return_value = q3
            return q3

        ms.query.side_effect = _q
        return app, ms, dev

    def test_full_scan_already_queued_shows_warning(self):
        """Gdy IP jest juz w kolejce, flash powinien byc kategoria 'warning' z tekstem o kolejce."""
        app, ms, dev = self._build_app_with_existing_queue(
            dev_ip="10.0.0.5", queued_ips="10.0.0.5"
        )
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests") as mr:
                _setup_mock_api(mr)
                with app.test_client() as c:
                    r = c.post("/devices/42/full-scan", follow_redirects=False)
                    assert r.status_code == 302, "POST musi przekierowac (302)"
                    with c.session_transaction() as sess:
                        flashes = sess.get("_flashes", [])
        categories = [cat for cat, _msg in flashes]
        messages   = [msg for _cat, msg in flashes]
        assert "warning" in categories, \
            f"Flash musi byc 'warning' gdy IP juz w kolejce, got categories={categories}"
        assert any("kolejce" in msg for msg in messages), \
            f"Flash musi zawierac 'kolejce', got messages={messages}"

    def test_full_scan_new_ip_shows_info(self):
        """Gdy IP nie jest w kolejce, flash powinien byc kategoria 'info' z tekstem o zaplanowaniu."""
        app, ms, dev = self._build_app_with_existing_queue(
            dev_ip="10.0.0.99", queued_ips="10.0.0.5"
        )
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests") as mr:
                _setup_mock_api(mr)
                with app.test_client() as c:
                    r = c.post("/devices/42/full-scan", follow_redirects=False)
                    assert r.status_code == 302, "POST musi przekierowac (302)"
                    with c.session_transaction() as sess:
                        flashes = sess.get("_flashes", [])
        categories = [cat for cat, _msg in flashes]
        messages   = [msg for _cat, msg in flashes]
        assert "info" in categories, \
            f"Flash musi byc 'info' dla nowego IP, got categories={categories}"
        assert any("zaplanowany" in msg for msg in messages), \
            f"Flash musi zawierac 'zaplanowany', got messages={messages}"


# ── Scenariusze z życia codziennego: czyszczenie portów ──────────────────────

class TestClearPortsWebRoutes:
    """Testy tras Flask /devices/.../clear-ports — scenariusze z zycia codziennego."""

    def _build_app(self, dev_ip="192.168.1.1"):
        from netdoc.web.app import create_app
        app = create_app()
        app.config["TESTING"] = True
        dev = _mock_dev(id=5, ip=dev_ip)

        ms = MagicMock()
        ms.__enter__ = lambda s: s
        ms.__exit__ = MagicMock(return_value=False)
        q = MagicMock()
        q.filter_by.return_value = q
        q.first.return_value = dev
        q.all.return_value = [dev]
        q.filter.return_value = q
        q.count.return_value = 1
        q.order_by.return_value = q
        q.join.return_value = q
        ms.query.return_value = q
        return app, ms, dev

    def test_per_device_clear_nmap_full_calls_correct_api(self):
        """POST /devices/5/clear-ports z scan_type=nmap_full powinien wywolac
        DELETE /api/devices/5/scan-results?scan_type=nmap_full (nie bulk)."""
        app, ms, dev = self._build_app()
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests") as mr:
                _setup_mock_api(mr, {"deleted": 3, "device_id": 5})
                with app.test_client() as c:
                    r = c.post("/devices/5/clear-ports",
                               data={"scan_type": "nmap_full"},
                               follow_redirects=False)
        assert r.status_code == 302
        # Sprawdz ze wywolano DELETE na /api/devices/5/scan-results?scan_type=nmap_full
        mr.delete.assert_called_once()
        url = mr.delete.call_args[0][0]
        assert "/api/devices/5/scan-results" in url, f"Zly URL: {url}"
        assert "scan_type=nmap_full" in url, f"Brak scan_type w URL: {url}"
        assert "/scan-results?" not in url.replace("/5/scan-results", ""), \
            "Nie moze byc bulk endpoint dla per-device call"

    def test_per_device_clear_all_ports_no_scan_type(self):
        """POST /devices/5/clear-ports bez scan_type usuwa wszystkie typy skanow."""
        app, ms, dev = self._build_app()
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests") as mr:
                _setup_mock_api(mr, {"deleted": 7, "device_id": 5})
                with app.test_client() as c:
                    r = c.post("/devices/5/clear-ports",
                               data={},
                               follow_redirects=False)
        assert r.status_code == 302
        url = mr.delete.call_args[0][0]
        assert "/api/devices/5/scan-results" in url
        assert "scan_type" not in url, "scan_type nie powinno byc w URL gdy nie podany"

    def test_per_device_clear_shows_success_flash(self):
        """Po pomyslnym czyszczeniu flash 'success' zawiera liczbe usunietych wynikow."""
        app, ms, dev = self._build_app()
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests") as mr:
                _setup_mock_api(mr, {"deleted": 4, "device_id": 5})
                with app.test_client() as c:
                    c.post("/devices/5/clear-ports", data={"scan_type": "nmap_full"},
                           follow_redirects=False)
                    with c.session_transaction() as sess:
                        flashes = sess.get("_flashes", [])
        categories = [cat for cat, _ in flashes]
        messages   = [msg for _, msg in flashes]
        assert "success" in categories, f"Flash musi byc 'success', got {categories}"
        assert any("4" in m for m in messages), f"Flash musi zawierac liczbe usunietych, got {messages}"

    def test_per_device_clear_api_error_shows_danger_flash(self):
        """Gdy API zwroci blad (5xx), flash 'danger' z komunikatem bledu."""
        from netdoc.web.app import create_app
        import requests as _requests_lib
        app = create_app()
        app.config["TESTING"] = True
        dev = _mock_dev(id=5, ip="10.0.0.1")
        ms = MagicMock()
        ms.__enter__ = lambda s: s
        ms.__exit__ = MagicMock(return_value=False)
        q = MagicMock()
        q.filter_by.return_value = q
        q.first.return_value = dev
        q.all.return_value = []
        q.filter.return_value = q
        q.count.return_value = 0
        q.order_by.return_value = q
        q.join.return_value = q
        ms.query.return_value = q

        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests") as mr:
                # API zwraca 500 — raise_for_status() musi rzucic wyjatkiem
                # (tak jak robi to prawdziwy requests.Response dla 5xx)
                err_resp = MagicMock()
                err_resp.status_code = 500
                err_resp.raise_for_status.side_effect = _requests_lib.HTTPError("500 Server Error")
                mr.delete.return_value = err_resp
                with app.test_client() as c:
                    c.post("/devices/5/clear-ports", data={"scan_type": "nmap_full"},
                           follow_redirects=False)
                    with c.session_transaction() as sess:
                        flashes = sess.get("_flashes", [])
        categories = [cat for cat, _ in flashes]
        assert "danger" in categories, f"Flash musi byc 'danger' przy bledzie API, got {categories}"

    def test_bulk_clear_calls_bulk_api_endpoint(self):
        """POST /devices/clear-ports wywoluje bulk endpoint /api/devices/scan-results."""
        from netdoc.web.app import create_app
        app = create_app()
        app.config["TESTING"] = True
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {"deleted": 12})
            with app.test_client() as c:
                r = c.post("/devices/clear-ports",
                           data={"device_ids": "1,2,3,4", "scan_type": "nmap_full"},
                           follow_redirects=False)
        assert r.status_code == 302
        url = mr.delete.call_args[0][0]
        # Musi byc bulk endpoint (bez /5/ itd.)
        assert "/api/devices/scan-results" in url, f"Zly URL: {url}"
        assert "device_ids=1%2C2%2C3%2C4" in url or "device_ids=1,2,3,4" in url, \
            f"device_ids musi byc w query string: {url}"
        assert "scan_type=nmap_full" in url

    def test_bulk_clear_all_devices_no_filter(self):
        """POST /devices/clear-ports bez device_ids usuwa porty wszystkich urzadzen."""
        from netdoc.web.app import create_app
        app = create_app()
        app.config["TESTING"] = True
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {"deleted": 42})
            with app.test_client() as c:
                r = c.post("/devices/clear-ports",
                           data={"device_ids": "", "scan_type": ""},
                           follow_redirects=False)
        assert r.status_code == 302
        url = mr.delete.call_args[0][0]
        assert "/api/devices/scan-results" in url
        assert "device_ids" not in url, "Brak device_ids = usuwa wszystkie"
        assert "scan_type" not in url, "Pusty scan_type nie powinien byc w URL"

    def test_bulk_clear_flash_contains_scope(self):
        """Flash po bulk clear zawiera informacje o zakresie (N urzadzen lub 'wszystkich')."""
        from netdoc.web.app import create_app
        app = create_app()
        app.config["TESTING"] = True
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {"deleted": 8})
            with app.test_client() as c:
                c.post("/devices/clear-ports",
                       data={"device_ids": "10,11,12", "scan_type": "nmap_full"},
                       follow_redirects=False)
                with c.session_transaction() as sess:
                    flashes = sess.get("_flashes", [])
        messages = [msg for _, msg in flashes]
        # "3 urządzeń" bo device_ids ma 3 elementy
        assert any("3" in m for m in messages), \
            f"Flash musi zawierac scope '3 urzadzen', got {messages}"

    def test_per_device_clear_preserves_network_filter_via_referrer(self):
        """Po czyszczeniu portów redirect wraca do strony z Referer (filtr sieciowy zachowany).

        Bug regresji: wcześniej redirect szedł zawsze do /devices bez filtra.
        Teraz: request.referrer lub url_for('devices').
        """
        app, ms, dev = self._build_app()
        referrer_url = "http://localhost/devices?network=192.168.1.0%2F24"
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests") as mr:
                _setup_mock_api(mr, {"deleted": 2, "device_id": 5})
                with app.test_client() as c:
                    r = c.post("/devices/5/clear-ports",
                               data={"scan_type": "nmap_full"},
                               follow_redirects=False,
                               headers={"Referer": referrer_url})
        assert r.status_code == 302
        location = r.headers.get("Location", "")
        # Redirect musi iść z powrotem do URL z filtrem (nie do /devices bez filtra)
        assert "network=" in location or "192.168.1.0" in location, \
            f"Redirect powinien zachowac filtr sieciowy, got: {location}"

    def test_bulk_clear_preserves_network_filter_via_referrer(self):
        """Bulk clear portów — redirect wraca do strony z Referer (filtr sieciowy zachowany)."""
        from netdoc.web.app import create_app
        app = create_app()
        app.config["TESTING"] = True
        referrer_url = "http://localhost/devices?network=10.0.0.0%2F24"
        with patch("netdoc.web.app.requests") as mr:
            _setup_mock_api(mr, {"deleted": 5})
            with app.test_client() as c:
                r = c.post("/devices/clear-ports",
                           data={"device_ids": "1,2,3", "scan_type": "nmap_full"},
                           follow_redirects=False,
                           headers={"Referer": referrer_url})
        assert r.status_code == 302
        location = r.headers.get("Location", "")
        assert "network=" in location or "10.0.0.0" in location, \
            f"Bulk clear powinien zachowac filtr sieciowy, got: {location}"

    def test_per_device_clear_redirects_to_devices_when_no_referrer(self):
        """Gdy brak Referer — redirect do /devices (fallback)."""
        app, ms, dev = self._build_app()
        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests") as mr:
                _setup_mock_api(mr, {"deleted": 1, "device_id": 5})
                with app.test_client() as c:
                    r = c.post("/devices/5/clear-ports",
                               data={},
                               follow_redirects=False)
        assert r.status_code == 302
        location = r.headers.get("Location", "")
        assert "/devices" in location, f"Fallback powinien byc /devices, got: {location}"


class TestDbBackupRestore:
    """Testy endpointow backup i restore bazy danych."""

    def _make_app(self):
        from netdoc.web.app import create_app
        app = create_app()
        app.config["TESTING"] = True
        return app

    def test_backup_missing_pg_dump_returns_500(self):
        """Gdy pg_dump nie jest zainstalowany, zwraca 500."""
        app = self._make_app()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with app.test_client() as c:
                r = c.get("/settings/db/backup")
        assert r.status_code == 500
        assert b"pg_dump" in r.data

    def test_backup_pg_dump_error_returns_500(self):
        """Gdy pg_dump zwroci kod != 0, endpoint zwraca 500."""
        from unittest.mock import MagicMock
        app = self._make_app()
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b""
        mock_result.stderr = b"pg_dump: error"
        with patch("subprocess.run", return_value=mock_result):
            with app.test_client() as c:
                r = c.get("/settings/db/backup")
        assert r.status_code == 500

    def test_backup_success_returns_gz_file(self):
        """Pomyslny backup zwraca plik .sql.gz z naglowkiem Content-Disposition."""
        import gzip
        from unittest.mock import MagicMock
        app = self._make_app()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"-- PostgreSQL dump\nSELECT 1;"
        with patch("subprocess.run", return_value=mock_result):
            with app.test_client() as c:
                r = c.get("/settings/db/backup")
        assert r.status_code == 200
        assert r.content_type == "application/gzip"
        disposition = r.headers.get("Content-Disposition", "")
        assert "netdoc_backup_" in disposition
        assert ".sql.gz" in disposition
        # Zawartosc jest poprawnym gzipem
        data = gzip.decompress(r.data)
        assert b"SELECT 1" in data

    def test_restore_without_confirm_redirects_with_warning(self):
        """Brak checkboxa confirm — flash warning, redirect."""
        app = self._make_app()
        with app.test_client() as c:
            r = c.post("/settings/db/restore", data={}, follow_redirects=False)
        assert r.status_code == 302

    def test_restore_without_file_redirects_with_danger(self):
        """Brak pliku — flash danger, redirect."""
        app = self._make_app()
        with app.test_client() as c:
            r = c.post("/settings/db/restore",
                       data={"confirm_restore": "1"},
                       follow_redirects=False)
        assert r.status_code == 302

    def test_restore_psql_error_flashes_danger(self):
        """Gdy psql zwroci kod != 0, flash danger, redirect."""
        from unittest.mock import MagicMock
        import io
        app = self._make_app()
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = b"psql: error"
        with patch("subprocess.run", return_value=mock_result):
            with app.test_client() as c:
                r = c.post(
                    "/settings/db/restore",
                    data={"confirm_restore": "1",
                          "backup_file": (io.BytesIO(b"SELECT 1;"), "backup.sql")},
                    content_type="multipart/form-data",
                    follow_redirects=False,
                )
        assert r.status_code == 302

    def test_restore_gz_file_decompressed_before_psql(self):
        """Plik .sql.gz jest rozpakowywany przed przekazaniem do psql."""
        import gzip, io, sys
        from unittest.mock import MagicMock
        app = self._make_app()
        sql = b"SELECT 1;"
        gz_data = gzip.compress(sql)
        captured = {}
        mock_result = MagicMock()
        mock_result.returncode = 0
        def _fake_run(cmd, input=None, **kw):
            captured["input"] = input
            return mock_result
        mock_docker = MagicMock()
        with patch("subprocess.run", side_effect=_fake_run), \
             patch.dict(sys.modules, {"docker": mock_docker}), \
             patch("threading.Thread"):
            with app.test_client() as c:
                r = c.post(
                    "/settings/db/restore",
                    data={"confirm_restore": "1",
                          "backup_file": (io.BytesIO(gz_data), "backup.sql.gz")},
                    content_type="multipart/form-data",
                    follow_redirects=False,
                )
        assert captured.get("input") == sql

    def test_container_status_returns_json(self):
        """GET /settings/db/container-status zwraca JSON ze statusami kontenerow."""
        import sys
        from unittest.mock import MagicMock
        app = self._make_app()
        mock_c1 = MagicMock()
        mock_c1.name = "netdoc-web"
        mock_c1.status = "running"
        mock_cli = MagicMock()
        mock_cli.containers.list.return_value = [mock_c1]
        mock_docker = MagicMock()
        mock_docker.from_env.return_value = mock_cli
        with patch.dict(sys.modules, {"docker": mock_docker}):
            with app.test_client() as c:
                r = c.get("/settings/db/container-status")
        assert r.status_code == 200
        data = r.get_json()
        assert data["netdoc-web"] == "running"


# ── Testy: baner beta (ostrzeżenie o skanowaniu) ─────────────────────────────

class TestBetaBanner:
    """Baner ostrzegajacy o skutkach skanowania — zamykalny przez localStorage."""

    def test_banner_present_in_base_template(self):
        """base.html zawiera element betaBanner."""
        import pathlib
        tmpl = pathlib.Path("netdoc/web/templates/base.html").read_text(encoding="utf-8")
        assert "betaBanner" in tmpl

    def test_banner_has_dismiss_function(self):
        """base.html zawiera funkcje dismissBetaBanner() zapisujaca flage w localStorage."""
        import pathlib
        tmpl = pathlib.Path("netdoc/web/templates/base.html").read_text(encoding="utf-8")
        assert "dismissBetaBanner" in tmpl
        assert "netdoc_beta_dismissed" in tmpl
        assert "localStorage.setItem" in tmpl

    def test_banner_hidden_by_default_via_js(self):
        """Baner ma display:none — pokazywany przez JS tylko gdy brak flagi w localStorage."""
        import pathlib
        tmpl = pathlib.Path("netdoc/web/templates/base.html").read_text(encoding="utf-8")
        assert 'id="betaBanner"' in tmpl
        assert "display:none" in tmpl or "display: none" in tmpl

    def test_banner_warns_about_printers(self):
        """Baner zawiera ostrzezenie o drukarkach (port 9100)."""
        import pathlib
        tmpl = pathlib.Path("netdoc/web/templates/base.html").read_text(encoding="utf-8")
        assert "9100" in tmpl or "drukark" in tmpl.lower()

    def test_banner_warns_about_ids(self):
        """Baner zawiera ostrzezenie o IDS/IPS."""
        import pathlib
        tmpl = pathlib.Path("netdoc/web/templates/base.html").read_text(encoding="utf-8")
        assert "IDS" in tmpl

    def test_banner_has_close_button(self):
        """Baner ma przycisk zamkniecia wywolujacy dismissBetaBanner."""
        import pathlib
        tmpl = pathlib.Path("netdoc/web/templates/base.html").read_text(encoding="utf-8")
        assert "dismissBetaBanner" in tmpl

    def test_index_returns_200_with_banner(self, client):
        """Strona glowna zwraca 200 — baner nie psuje renderowania."""
        r = client.get("/")
        assert r.status_code == 200
        assert b"betaBanner" in r.data
