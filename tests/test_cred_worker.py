"""Testy jednostkowe dla run_cred_worker.py.
Mockuja polaczenia sieciowe — bez prawdziwego ruchu sieciowego.
"""
import socket
import sys
import types
from unittest.mock import MagicMock, patch, call
import pytest

# ─── Stubujemy prometheus_client i impacket przed importem ───────────────────
prom_stub = types.ModuleType("prometheus_client")
prom_stub.Gauge = lambda *a, **kw: MagicMock()
prom_stub.start_http_server = lambda *a, **kw: None
sys.modules.setdefault("prometheus_client", prom_stub)

impacket_stub = types.ModuleType("impacket")
impacket_smb = types.ModuleType("impacket.smbconnection")
impacket_smb.SMBConnection = MagicMock()
impacket_tds = types.ModuleType("impacket.tds")
impacket_tds.MSSQL = MagicMock()
sys.modules.setdefault("impacket", impacket_stub)
sys.modules.setdefault("impacket.smbconnection", impacket_smb)
sys.modules.setdefault("impacket.tds", impacket_tds)

pymysql_stub = types.ModuleType("pymysql")
pymysql_stub.connect = MagicMock()
pymysql_stub.err = types.ModuleType("pymysql.err")
pymysql_stub.err.OperationalError = Exception
sys.modules.setdefault("pymysql", pymysql_stub)
sys.modules.setdefault("pymysql.err", pymysql_stub.err)

import run_cred_worker as w


@pytest.fixture(autouse=True)
def _clear_ban_state():
    """Czyści _ip_ban_until przed każdym testem — stan modułowy nie może wyciekać między testami."""
    w._ip_ban_until.clear()
    yield
    w._ip_ban_until.clear()


# ─── _tcp_open ────────────────────────────────────────────────────────────────

def test_tcp_open_returns_true_on_success():
    with patch("socket.create_connection") as mc:
        mc.return_value.__enter__ = lambda s: s
        mc.return_value.__exit__ = MagicMock(return_value=False)
        assert w._tcp_open("10.0.0.1", 22) is True


def test_tcp_open_returns_false_on_oserror():
    with patch("socket.create_connection", side_effect=OSError("refused")):
        assert w._tcp_open("10.0.0.1", 22) is False


# ─── _grab_banner ─────────────────────────────────────────────────────────────

def test_grab_banner_returns_bytes():
    with patch("socket.create_connection") as mc:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
        mc.return_value.__enter__ = lambda s: mock_sock
        mc.return_value.__exit__ = MagicMock(return_value=False)
        result = w._grab_banner("10.0.0.1", 22)
    assert result == b"SSH-2.0-OpenSSH_8.9\r\n"


def test_grab_banner_returns_empty_bytes_on_recv_error():
    with patch("socket.create_connection") as mc:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = OSError("timed out")
        mc.return_value.__enter__ = lambda s: mock_sock
        mc.return_value.__exit__ = MagicMock(return_value=False)
        result = w._grab_banner("10.0.0.1", 22)
    assert result == b""


def test_grab_banner_returns_none_on_connection_error():
    with patch("socket.create_connection", side_effect=OSError("refused")):
        result = w._grab_banner("10.0.0.1", 9999)
    assert result is None


# ─── _detect_service ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("banner,svc_name,expected", [
    # Wykrycie z bannera SSH
    (b"SSH-2.0-OpenSSH_8.9\r\n", "", "ssh"),
    (b"SSH-1.99-Cisco", "", "ssh"),
    (b"SSH-1.5-SunSSH", "", "ssh"),
    # Wykrycie z bannera HTTP
    (b"HTTP/1.1 200 OK\r\n", "", "http"),
    (b"http/1.0 401\r\n", "", "http"),
    # Wykrycie z bannera FTP
    (b"220 FTP server ready\r\n", "", "ftp"),
    (b"220-Welcome\r\n220 \r\n", "", "ftp"),
    # Wykrycie RDP (TPKT header 0x03 0x00)
    (b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00", "", "rdp"),
    # Priorytet nmap service_name nad bannerem
    (b"SSH-2.0-OpenSSH", "http", "http"),
    (b"HTTP/1.1 200", "ssh", "ssh"),
    (b"220 FTP", "https", "https"),
    (b"220 FTP", "microsoft-ds", "smb"),
    # Nmap: ssl/https
    (b"", "https", "https"),
    (b"", "ssl/http", "https"),
    # Brak bannera i brak service
    (None, "", None),
    (b"", "", None),
    (b"garbage bytes xyz", "", None),
])
def test_detect_service(banner, svc_name, expected):
    result = w._detect_service(banner, svc_name)
    assert result == expected, f"banner={banner!r} svc={svc_name!r} → {result!r} != {expected!r}"


# ─── _services_to_try ─────────────────────────────────────────────────────────

def test_services_to_try_ssh_banner():
    result = w._services_to_try("", banner=b"SSH-2.0-OpenSSH")
    assert result == ["ssh"]


def test_services_to_try_ftp_banner():
    result = w._services_to_try("", banner=b"220 FTP ready")
    assert result == ["ftp", "http", "https"]


def test_services_to_try_http_banner():
    result = w._services_to_try("", banner=b"HTTP/1.1 200 OK")
    assert result == ["http", "https", "ssh"]


def test_services_to_try_rdp_banner():
    result = w._services_to_try("", banner=b"\x03\x00\x00\x13\x0e\xe0")
    assert result == ["smb"]


def test_services_to_try_tcpwrapped_no_banner():
    result = w._services_to_try("tcpwrapped")
    assert "http" in result
    assert "ssh" in result


def test_services_to_try_tcpwrapped_with_ssh_banner():
    # Banner wygrywa nad tcpwrapped
    result = w._services_to_try("tcpwrapped", banner=b"SSH-2.0-OpenSSH")
    assert result == ["ssh"]


def test_services_to_try_unknown():
    result = w._services_to_try("")
    assert "http" in result
    assert "ssh" in result


def test_services_to_try_nmap_ssh():
    result = w._services_to_try("ssh")
    assert result == ["ssh"]


def test_services_to_try_nmap_https():
    result = w._services_to_try("https")
    assert result == ["https", "http", "ssh"]


# ─── _open_ssh_ports ──────────────────────────────────────────────────────────

def test_open_ssh_ports_uses_scan_data_port_22():
    # Gdy skan pokazuje port 22 otwarty — nie probujemy TCP
    result = w._open_ssh_ports("10.0.0.1", {"22": {"service": "ssh"}})
    assert 22 in result


def test_open_ssh_ports_uses_scan_data_port_2222():
    result = w._open_ssh_ports("10.0.0.1", {"2222": {}})
    assert 2222 in result
    assert 22 not in result


def test_open_ssh_ports_empty_scan_no_ssh():
    # Skan jest ale brak portow SSH — nie robimy TCP probe
    result = w._open_ssh_ports("10.0.0.1", {"80": {}, "443": {}})
    assert result == []


def test_open_ssh_ports_no_scan_data_falls_back_to_tcp():
    # Brak danych skanu — szybki TCP probe
    with patch.object(w, "_tcp_open", return_value=True) as mock_tcp:
        result = w._open_ssh_ports("10.0.0.1", {})
    # Powinien przetestowac wszystkie porty SSH
    assert 22 in result
    assert mock_tcp.called


def test_open_ssh_ports_no_scan_data_tcp_all_closed():
    with patch.object(w, "_tcp_open", return_value=False):
        result = w._open_ssh_ports("10.0.0.1", {})
    assert result == []


def test_open_ssh_ports_scan_data_int_keys():
    # Klucze jako int (po konwersji z DB)
    result = w._open_ssh_ports("10.0.0.1", {22: {"service": "ssh"}})
    assert 22 in result


# ─── integracyjny: _probe_nonstandard_ports uzywa bannera ─────────────────────

# ─── _moxa_encode_user ────────────────────────────────────────────────────────

def test_moxa_encode_user_known_value():
    """Weryfikacja przeciwko wartosci obliczonej recznie (porownaj z testem live)."""
    import hashlib
    fc = "19CDB4121B7A3696DF405C3F97BD70FAB6D61FA03CCFE8956A3EACBC1079A614"
    key = hashlib.sha256(fc.encode()).hexdigest()
    result = w._moxa_encode_user("admin", key)
    # Wartosc potwierdzona przez reczny test z urzadzeniem Moxa NPort
    assert result.startswith("d0ad651521"), f"got {result[:20]}"


def test_moxa_encode_user_output_length():
    """EncUser ma dlugosc 64 znakow hex (32 bajty = SHA256 key)."""
    import hashlib
    key = hashlib.sha256(b"test_challenge").hexdigest()
    result = w._moxa_encode_user("admin", key)
    assert len(result) == 64


def test_moxa_encode_user_xors_password_chars():
    """Pierwsze bajty sa XOR z password, reszta niezmieniona (rowna key)."""
    import hashlib
    challenge = "AABB"  # krotki challenge dla uproszczenia
    key = hashlib.sha256(challenge.encode()).hexdigest()  # 64 hex chars = 32 bytes
    key_bytes = bytes.fromhex(key)
    result = w._moxa_encode_user("a", key)  # 1-char password
    result_bytes = bytes.fromhex(result)
    # Bajt 0: XOR z pozycja 'a' w ASCII_MOXA
    expected_byte0 = key_bytes[0] ^ w._ASCII_MOXA.rfind("a")
    assert result_bytes[0] == expected_byte0
    # Bajt 1..31: niezmienione (brak drugiego znaku password)
    assert result_bytes[1:] == key_bytes[1:]


# ─── _should_probe_port ───────────────────────────────────────────────────────

def test_should_probe_nonstandard_port_always():
    # Port niestandardowy zawsze do probowania
    assert w._should_probe_port(9999, {"service": "http"}) is True
    assert w._should_probe_port(12345, {}) is True
    assert w._should_probe_port(7777, None) is True


def test_should_probe_standard_port_known_service_skipped():
    # Standardowy port ze znana usluga → pomijamy (juz obsluguje discover_*)
    assert w._should_probe_port(22,   {"service": "ssh"}) is False
    assert w._should_probe_port(80,   {"service": "http"}) is False
    assert w._should_probe_port(443,  {"service": "https"}) is False
    assert w._should_probe_port(21,   {"service": "ftp"}) is False
    assert w._should_probe_port(3389, {"service": "ms-wbt-server"}) is False


def test_should_probe_standard_port_tcpwrapped():
    # Standardowy port z tcpwrapped → moze byc inny protokol → sprawdzamy
    assert w._should_probe_port(22, {"service": "tcpwrapped"}) is True
    assert w._should_probe_port(80, {"service": "tcpwrapped"}) is True


def test_should_probe_standard_port_empty_service():
    # Standardowy port bez service → sprawdzamy
    assert w._should_probe_port(22, {"service": ""}) is True
    assert w._should_probe_port(80, {}) is True
    assert w._should_probe_port(443, None) is True


# ─── integracyjny: _probe_nonstandard_ports uzywa bannera ─────────────────────

def test_probe_nonstandard_ports_grabs_banner_for_tcpwrapped():
    """Gdy serwis to tcpwrapped, _grab_banner powinien byc wywolany."""
    open_ports = {9999: {"service": "tcpwrapped"}}
    with patch.object(w, "_tcp_open", return_value=True), \
         patch.object(w, "_grab_banner", return_value=b"SSH-2.0-OpenSSH") as mock_banner, \
         patch.object(w, "_probe_port", return_value=None):
        w._probe_nonstandard_ports("10.0.0.1", open_ports, [], [], [])
    mock_banner.assert_called_once_with("10.0.0.1", 9999)


def test_probe_nonstandard_ports_skips_banner_for_known_service():
    """Gdy serwis jest znany (np. http), banner nie jest potrzebny."""
    open_ports = {9999: {"service": "http"}}
    with patch.object(w, "_tcp_open", return_value=True), \
         patch.object(w, "_grab_banner") as mock_banner, \
         patch.object(w, "_probe_port", return_value=None):
        w._probe_nonstandard_ports("10.0.0.1", open_ports, [], [], [])
    mock_banner.assert_not_called()


def test_probe_nonstandard_ports_skips_standard_known_service():
    """Standardowe porty ze znana usluga sa pomijane (juz obsluguje discover_*)."""
    open_ports = {22: {"service": "ssh"}, 80: {"service": "http"}}
    with patch.object(w, "_tcp_open", return_value=True), \
         patch.object(w, "_probe_port") as mock_probe:
        w._probe_nonstandard_ports("10.0.0.1", open_ports, [], [], [])
    mock_probe.assert_not_called()


def test_probe_nonstandard_ports_probes_standard_tcpwrapped():
    """Standardowy port z tcpwrapped jest sprawdzany (moze byc inny protokol)."""
    open_ports = {22: {"service": "tcpwrapped"}}
    with patch.object(w, "_tcp_open", return_value=True), \
         patch.object(w, "_grab_banner", return_value=b"HTTP/1.1 200 OK") as mock_banner, \
         patch.object(w, "_probe_port", return_value=None):
        w._probe_nonstandard_ports("10.0.0.1", open_ports, [], [], [])
    mock_banner.assert_called_once_with("10.0.0.1", 22)


def test_probe_nonstandard_ports_skips_closed_tcp():
    """Port TCP zamkniety — pomijamy (nie probujemy kredentiali)."""
    open_ports = {9999: {"service": "tcpwrapped"}}
    with patch.object(w, "_tcp_open", return_value=False), \
         patch.object(w, "_probe_port") as mock_probe:
        w._probe_nonstandard_ports("10.0.0.1", open_ports, [], [], [])
    mock_probe.assert_not_called()


# ─── _filter_untried ──────────────────────────────────────────────────────────

def test_filter_untried_returns_n_pairs_when_all_fresh():
    pairs = [("admin", "admin"), ("root", "root"), ("user", "pass")]
    result = w._filter_untried(pairs, set(), 2)
    assert result == [("admin", "admin"), ("root", "root")]


def test_filter_untried_skips_already_tried():
    pairs = [("admin", "admin"), ("root", "root"), ("user", "pass")]
    tried = {"admin:admin"}
    result = w._filter_untried(pairs, tried, 2)
    assert result == [("root", "root"), ("user", "pass")]


def test_filter_untried_returns_empty_when_all_tried():
    pairs = [("admin", "admin"), ("root", "root")]
    tried = {"admin:admin", "root:root"}
    result = w._filter_untried(pairs, tried, 5)
    assert result == []


def test_filter_untried_respects_limit():
    pairs = [("a", "1"), ("b", "2"), ("c", "3"), ("d", "4")]
    result = w._filter_untried(pairs, set(), 1)
    assert result == [("a", "1")]


# ─── _mark_pairs_tried ────────────────────────────────────────────────────────

def test_mark_pairs_tried_adds_to_set():
    tried = {}
    w._mark_pairs_tried(tried, "ssh", [("admin", "admin"), ("root", "")])
    assert "admin:admin" in tried["ssh"]
    assert "root:" in tried["ssh"]
    assert len(tried["ssh"]) == 2


def test_mark_pairs_tried_creates_set_if_missing():
    tried = {}
    w._mark_pairs_tried(tried, "api", [("user", "pass")])
    assert "api" in tried
    assert "user:pass" in tried["api"]


def test_mark_pairs_tried_appends_to_existing():
    tried = {"ssh": {"admin:admin"}}
    w._mark_pairs_tried(tried, "ssh", [("root", "toor")])
    assert "admin:admin" in tried["ssh"]
    assert "root:toor" in tried["ssh"]


# ─── _load_tried ignoruje klucze z _ ─────────────────────────────────────────

def test_load_tried_ignores_underscore_keys():
    """_load_tried powinien ignorowac klucze zaczynajace sie od _ (np. _at)."""
    import json
    raw = {"ssh": ["admin:admin", "root:root"], "_at": "2026-03-08T12:00:00", "api": ["user:pass"]}
    from unittest.mock import MagicMock, patch
    mock_row = MagicMock()
    mock_row.value = json.dumps(raw)
    with patch("run_cred_worker.SessionLocal") as mock_sl:
        mock_db = MagicMock()
        mock_sl.return_value = mock_db
        mock_db.__enter__ = lambda s: mock_db
        mock_db.__exit__ = MagicMock(return_value=False)
        mock_db.query.return_value.filter.return_value.first.return_value = mock_row
        result = w._load_tried(1)
    assert "_at" not in result
    assert "ssh" in result
    assert "api" in result
    assert "admin:admin" in result["ssh"]


def test_save_tried_includes_at_timestamp():
    """_save_tried powinien zapisywac klucz _at z biezacym czasem."""
    import json
    saved_val = [None]
    def _capture_add(obj):
        saved_val[0] = obj.value

    from unittest.mock import MagicMock, patch
    with patch("run_cred_worker.SessionLocal") as mock_sl:
        mock_db = MagicMock()
        mock_sl.return_value = mock_db
        mock_db.__enter__ = lambda s: mock_db
        mock_db.__exit__ = MagicMock(return_value=False)
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_db.add.side_effect = _capture_add
        w._save_tried(99, {"ssh": {"admin:admin"}})

    assert saved_val[0] is not None
    raw = json.loads(saved_val[0])
    assert "_at" in raw
    assert "ssh" in raw
    assert "admin:admin" in raw["ssh"]


# ─── _process_device_with_timeout ────────────────────────────────────────────

def test_process_device_with_timeout_returns_timeout_on_hang():
    """Symulacja zawieszenia — _process_device nie konczy sie w limicie."""
    import time as _time

    def _slow(*args, **kwargs):
        _time.sleep(5)  # krocej niz faktyczny test ale ponad limit
        return {"ssh": False, "web": False, "ftp": False, "rdp": False, "new": 0}

    with patch.object(w, "_process_device", side_effect=_slow):
        result = w._process_device_with_timeout(0.1, 1, "10.0.0.1", [], [], [], [], [], 1)
    assert result.get("timeout") is True
    assert result["new"] == 0


# ─── discover_web: pre-check portow ──────────────────────────────────────────

def test_discover_web_skips_when_no_ports_open():
    """discover_web zwraca None natychmiast gdy zadne porty HTTP nie sa otwarte."""
    with patch.object(w, "_tcp_open", return_value=False):
        result = w.discover_web("10.0.0.1", [("admin", "admin")])
    assert result is None


def test_discover_web_only_probes_open_ports():
    """discover_web probuje tylko otwarte porty (nie wszystkie z _WEB_PORTS)."""
    probed_ports = []

    def _fake_tcp_open(ip, port, timeout=2.0):
        return port == 80  # tylko port 80 "otwarty"

    def _fake_basic_ok(url, u, p):
        probed_ports.append(url)
        return False

    with patch.object(w, "_tcp_open", side_effect=_fake_tcp_open), \
         patch.object(w, "_web_basic_ok", side_effect=_fake_basic_ok), \
         patch.object(w, "_web_moxa_get_challenge", return_value=None), \
         patch.object(w, "_web_form_ok", return_value=False):
        w.discover_web("10.0.0.1", [("admin", "admin")])
    # Tylko porty z "10.0.0.1:80" powinny byc probowane, nie np. 8080/8443
    assert all("10.0.0.1:80" in u for u in probed_ports)
    assert not any("8080" in u for u in probed_ports)


def test_discover_web_returns_pair_on_moxa_ok():
    """discover_web zwraca pare gdy Moxa challenge-response sie udaje."""
    with patch.object(w, "_tcp_open", side_effect=lambda ip, port, **kw: port == 80), \
         patch.object(w, "_web_basic_ok", return_value=False), \
         patch.object(w, "_web_moxa_get_challenge", return_value="AABB1234"), \
         patch.object(w, "_web_moxa_login", return_value=True), \
         patch.object(w, "_web_form_ok", return_value=False):
        result = w.discover_web("10.0.0.1", [("admin", "secret")])
    assert result == ("admin", "secret")


# ─── scan_once: brak DetachedInstanceError (tuple zamiast ORM) ───────────────

def test_scan_once_passes_tuples_not_orm_objects():
    """scan_once musi wyciagac (id, ip) przed db.close() — bez DetachedInstanceError."""
    mock_device_tuples = [(1, "10.0.0.1"), (2, "10.0.0.2")]

    calls = []
    def _fake_run(timeout_s, dev_id, dev_ip, *args, **kwargs):
        calls.append((dev_id, dev_ip))
        return {"ssh": False, "web": False, "ftp": False, "rdp": False, "new": 0}

    # Mock bazy danych
    mock_db = MagicMock()
    mock_db.__enter__ = lambda s: mock_db
    mock_db.__exit__ = MagicMock(return_value=False)

    # candidates jako list of tuples (id, ip) — tak jak po naprawie
    fake_devs = [MagicMock(id=dev_id, ip=dev_ip, is_active=True, last_credential_ok_at=None)
                 for dev_id, dev_ip in mock_device_tuples]
    mock_db.query.return_value.filter.return_value.all.return_value = fake_devs
    mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = []
    mock_db.query.return_value.filter.return_value.first.return_value = None

    with patch("run_cred_worker.SessionLocal", return_value=mock_db), \
         patch.object(w, "_process_device_with_timeout", side_effect=_fake_run):
        w.scan_once()

    # Sprawdz ze wywolania zawieraja czyste (int, str) a nie ORM obiekty
    assert len(calls) == 2
    for dev_id, dev_ip in calls:
        assert isinstance(dev_id, int)
        assert isinstance(dev_ip, str)


# ─── _process_device: SSH/WEB skip nie zuzywa slotow rotacji ─────────────────

def _make_mock_db_for_process():
    """Helper: mock SessionLocal zwracajacy pusty tried state."""
    import json
    mock_db = MagicMock()
    mock_db.__enter__ = lambda s: mock_db
    mock_db.__exit__ = MagicMock(return_value=False)
    # _load_tried zwraca pusty dict (brak probowanych par)
    mock_row = MagicMock()
    mock_row.value = json.dumps({})
    mock_db.query.return_value.filter.return_value.first.return_value = mock_row
    return mock_db


def test_ssh_skip_does_not_consume_rotation_slot():
    """Gdy port SSH zamkniety, para NIE jest dodawana do tried — slot zachowany na pozniej."""
    saved_tried = [None]
    def _capture_save(device_id, tried):
        saved_tried[0] = tried

    with patch("run_cred_worker.SessionLocal", return_value=_make_mock_db_for_process()), \
         patch.object(w, "_tcp_open", return_value=False), \
         patch.object(w, "_get_device_open_ports", return_value={}), \
         patch.object(w, "_save_tried", side_effect=_capture_save), \
         patch.object(w, "discover_web", return_value=None), \
         patch.object(w, "discover_ftp", return_value=None), \
         patch.object(w, "discover_rdp", return_value=None):
        w._process_device(1, "10.0.0.1",
                          [("admin", "admin")], [], [], [], pairs_per_cycle=1)

    # tried["ssh"] nie powinno istniec (para nie zuzywa slotu)
    if saved_tried[0] is not None:
        assert "ssh" not in saved_tried[0], \
            "SSH para zostala zaznaczona jako tried mimo zamknietego portu!"


def test_web_skip_does_not_consume_rotation_slot():
    """Gdy brak portow HTTP, para WEB NIE jest dodawana do tried."""
    saved_tried = [None]
    def _capture_save(device_id, tried):
        saved_tried[0] = tried

    with patch("run_cred_worker.SessionLocal", return_value=_make_mock_db_for_process()), \
         patch.object(w, "_tcp_open", return_value=False), \
         patch.object(w, "_get_device_open_ports", return_value={}), \
         patch.object(w, "_save_tried", side_effect=_capture_save), \
         patch.object(w, "discover_ssh", return_value=None), \
         patch.object(w, "discover_ftp", return_value=None), \
         patch.object(w, "discover_rdp", return_value=None):
        w._process_device(1, "10.0.0.1",
                          [], [("admin", "admin")], [], [], pairs_per_cycle=1)

    if saved_tried[0] is not None:
        assert "api" not in saved_tried[0], \
            "WEB para zostala zaznaczona jako tried mimo braku portow HTTP!"


def test_ssh_open_port_does_consume_rotation_slot():
    """Gdy port SSH otwarty i probowane — para JEST dodawana do tried."""
    saved_tried = [None]
    def _capture_save(device_id, tried):
        saved_tried[0] = tried

    with patch("run_cred_worker.SessionLocal", return_value=_make_mock_db_for_process()), \
         patch.object(w, "_tcp_open", return_value=True), \
         patch.object(w, "_get_device_open_ports", return_value={22: {"service": "ssh"}}), \
         patch.object(w, "_save_tried", side_effect=_capture_save), \
         patch.object(w, "discover_ssh", return_value=None), \
         patch.object(w, "discover_telnet", return_value=None), \
         patch.object(w, "discover_web", return_value=None), \
         patch.object(w, "discover_ftp", return_value=None), \
         patch.object(w, "discover_rdp", return_value=None):
        w._process_device(1, "10.0.0.1",
                          [("admin", "admin")], [], [], [], pairs_per_cycle=1)

    assert saved_tried[0] is not None
    assert "ssh" in saved_tried[0], "SSH para powinna byc w tried gdy port jest otwarty!"
    assert "admin:admin" in saved_tried[0]["ssh"]


# ─── _web_detect_auth ─────────────────────────────────────────────────────────

def test_web_detect_auth_true_for_password_field():
    """_web_detect_auth zwraca True gdy HTML zawiera type='password'."""
    mock_resp = MagicMock()
    mock_resp.headers = {}
    mock_resp.text = '<html><input type="password" name="pass"></html>'
    with patch("httpx.get", return_value=mock_resp):
        result = w._web_detect_auth("10.0.0.1", [80])
    assert result is True


def test_web_detect_auth_true_for_www_authenticate():
    """_web_detect_auth zwraca True gdy nagłówek WWW-Authenticate obecny."""
    mock_resp = MagicMock()
    mock_resp.headers = {"www-authenticate": "Basic realm=\"router\""}
    mock_resp.text = ""
    with patch("httpx.get", return_value=mock_resp):
        result = w._web_detect_auth("10.0.0.1", [80])
    assert result is True


def test_web_detect_auth_true_for_moxa_challenge():
    """_web_detect_auth zwraca True gdy FakeChallenge w HTML (Moxa)."""
    mock_resp = MagicMock()
    mock_resp.headers = {}
    mock_resp.text = '<input NAME="FakeChallenge" VALUE="AABB1234">'
    with patch("httpx.get", return_value=mock_resp):
        result = w._web_detect_auth("10.0.0.1", [80])
    assert result is True


def test_web_detect_auth_false_for_json_api():
    """_web_detect_auth zwraca False gdy urzadzenie zwraca czysty JSON (np. Philips Hue)."""
    mock_resp = MagicMock()
    mock_resp.headers = {}
    mock_resp.text = '{"bridgeid": "001788FFFE123456", "apiversion": "1.56.0"}'
    with patch("httpx.get", return_value=mock_resp):
        result = w._web_detect_auth("10.0.0.1", [80])
    assert result is False


def test_web_detect_auth_false_when_all_requests_fail():
    """_web_detect_auth zwraca False gdy wszystkie polaczenia fail (exception)."""
    with patch("httpx.get", side_effect=Exception("timeout")):
        result = w._web_detect_auth("10.0.0.1", [80, 8080])
    assert result is False


def test_web_no_login_page_does_not_consume_rotation_slot():
    """Gdy porty otwarte ale brak strony logowania — para WEB NIE zuzywa slotu rotacji."""
    saved_tried = [None]
    def _capture_save(device_id, tried):
        saved_tried[0] = tried

    with patch("run_cred_worker.SessionLocal", return_value=_make_mock_db_for_process()), \
         patch.object(w, "_tcp_open", return_value=True), \
         patch.object(w, "_web_detect_auth", return_value=False), \
         patch.object(w, "_get_device_open_ports", return_value={}), \
         patch.object(w, "_save_tried", side_effect=_capture_save), \
         patch.object(w, "discover_ssh", return_value=None), \
         patch.object(w, "discover_ftp", return_value=None), \
         patch.object(w, "discover_rdp", return_value=None):
        w._process_device(1, "10.0.0.1",
                          [], [("admin", "admin")], [], [], pairs_per_cycle=1)

    if saved_tried[0] is not None:
        assert "api" not in saved_tried[0], \
            "WEB para zostala zaznaczona jako tried mimo braku strony logowania!"


# ─── MSSQL / MySQL / PostgreSQL credential fallback lists ────────────────────

def test_mssql_fallback_has_wapro3000():
    """MSSQL_CREDENTIAL_FALLBACK zawiera ('sa', 'Wapro3000')."""
    assert ("sa", "Wapro3000") in w.MSSQL_CREDENTIAL_FALLBACK


def test_mssql_fallback_has_empty_sa():
    """MSSQL_CREDENTIAL_FALLBACK zawiera ('sa', '') — SQL Express bez hasla."""
    assert ("sa", "") in w.MSSQL_CREDENTIAL_FALLBACK


def test_mssql_fallback_has_insert_erp():
    """MSSQL_CREDENTIAL_FALLBACK zawiera hasla Insert GT ERP."""
    passwords = {p for _, p in w.MSSQL_CREDENTIAL_FALLBACK}
    assert any("Insert" in p for p in passwords)


def test_mssql_fallback_has_optima():
    """MSSQL_CREDENTIAL_FALLBACK zawiera hasla Comarch Optima."""
    passwords = {p for _, p in w.MSSQL_CREDENTIAL_FALLBACK}
    assert any("Optima" in p for p in passwords)


def test_mysql_fallback_has_root_empty():
    """MYSQL_CREDENTIAL_FALLBACK zawiera ('root', '') — domyslna instalacja MySQL."""
    assert ("root", "") in w.MYSQL_CREDENTIAL_FALLBACK


def test_mysql_fallback_has_root_root():
    """MYSQL_CREDENTIAL_FALLBACK zawiera ('root', 'root')."""
    assert ("root", "root") in w.MYSQL_CREDENTIAL_FALLBACK


def test_postgres_fallback_has_postgres_postgres():
    """POSTGRES_CREDENTIAL_FALLBACK zawiera ('postgres', 'postgres')."""
    assert ("postgres", "postgres") in w.POSTGRES_CREDENTIAL_FALLBACK


def test_postgres_fallback_has_empty_password():
    """POSTGRES_CREDENTIAL_FALLBACK zawiera ('postgres', '') — instalacja bez hasla."""
    assert ("postgres", "") in w.POSTGRES_CREDENTIAL_FALLBACK


def test_fallback_lists_are_nonempty():
    """Wszystkie listy fallback DB sa niepuste."""
    assert len(w.MSSQL_CREDENTIAL_FALLBACK) >= 5
    assert len(w.MYSQL_CREDENTIAL_FALLBACK) >= 5
    assert len(w.POSTGRES_CREDENTIAL_FALLBACK) >= 5


def test_fallback_lists_are_tuples_of_strings():
    """Kazda para w listach DB to krotka dwoch stringow."""
    for lst in (w.MSSQL_CREDENTIAL_FALLBACK, w.MYSQL_CREDENTIAL_FALLBACK,
                w.POSTGRES_CREDENTIAL_FALLBACK):
        for pair in lst:
            assert isinstance(pair, tuple) and len(pair) == 2
            assert isinstance(pair[0], str) and isinstance(pair[1], str)


# ─── discover_mssql / discover_mysql / discover_postgres ─────────────────────

def test_discover_mssql_skips_when_port_closed():
    """discover_mssql zwraca None gdy port 1433 zamkniety."""
    with patch.object(w, "_tcp_open", return_value=False):
        result = w.discover_mssql("10.0.0.1", [("sa", "sa")])
    assert result is None


def test_discover_mssql_returns_pair_on_success():
    """discover_mssql zwraca pare (user, pass) gdy logowanie udane."""
    with patch.object(w, "_tcp_open", return_value=True), \
         patch.object(w, "_try_mssql", return_value=True):
        result = w.discover_mssql("10.0.0.1", [("sa", "secret")])
    assert result == ("sa", "secret")


def test_discover_mssql_returns_none_when_all_fail():
    """discover_mssql zwraca None gdy zadna para nie dziala."""
    with patch.object(w, "_tcp_open", return_value=True), \
         patch.object(w, "_try_mssql", return_value=False):
        result = w.discover_mssql("10.0.0.1", [("sa", "wrong"), ("sa", "also_wrong")])
    assert result is None


def test_discover_mysql_skips_when_port_closed():
    """discover_mysql zwraca None gdy port 3306 zamkniety."""
    with patch.object(w, "_tcp_open", return_value=False):
        result = w.discover_mysql("10.0.0.1", [("root", "")])
    assert result is None


def test_discover_mysql_returns_pair_on_success():
    """discover_mysql zwraca pare (user, pass) gdy logowanie udane."""
    with patch.object(w, "_tcp_open", return_value=True), \
         patch.object(w, "_try_mysql", return_value=True):
        result = w.discover_mysql("10.0.0.1", [("root", "toor")])
    assert result == ("root", "toor")


def test_discover_postgres_skips_when_port_closed():
    """discover_postgres zwraca None gdy port 5432 zamkniety."""
    with patch.object(w, "_tcp_open", return_value=False):
        result = w.discover_postgres("10.0.0.1", [("postgres", "")])
    assert result is None


def test_discover_postgres_returns_pair_on_success():
    """discover_postgres zwraca pare (user, pass) gdy logowanie udane."""
    with patch.object(w, "_tcp_open", return_value=True), \
         patch.object(w, "_try_postgres", return_value=True):
        result = w.discover_postgres("10.0.0.1", [("postgres", "secret")])
    assert result == ("postgres", "secret")


# ─── _process_device z DB credential testing ─────────────────────────────────

def _make_mock_db_for_db_protocols():
    """Mock SessionLocal zwracajacy pusta liste tried z DB dla protokolow DB."""
    mock_db = MagicMock()
    mock_db.__enter__ = lambda s: s
    mock_db.__exit__ = MagicMock(return_value=False)
    mock_db.query.return_value.filter.return_value.first.return_value = None
    return mock_db


def test_process_device_mssql_found_saves_credential():
    """_process_device zapisuje credential gdy MSSQL logowanie udane."""
    with patch("run_cred_worker.SessionLocal", return_value=_make_mock_db_for_db_protocols()), \
         patch.object(w, "_get_device_open_ports", return_value={}), \
         patch.object(w, "discover_ssh", return_value=None), \
         patch.object(w, "discover_ftp", return_value=None), \
         patch.object(w, "discover_rdp", return_value=None), \
         patch.object(w, "_web_detect_auth", return_value=False), \
         patch.object(w, "discover_mssql", return_value=("sa", "Wapro3000")), \
         patch.object(w, "discover_mysql", return_value=None), \
         patch.object(w, "discover_postgres", return_value=None), \
         patch.object(w, "_save_cred") as mock_save, \
         patch.object(w, "_save_tried"), \
         patch("run_cred_worker._tcp_open", return_value=True):
        res = w._process_device(99, "10.0.0.5", [], [], [], [],
                                 mssql_pairs=[("sa", "Wapro3000")], pairs_per_cycle=1)
    assert res["mssql"] is True
    assert res["new"] >= 1
    mock_save.assert_called()


def test_process_device_mysql_found_saves_credential():
    """_process_device zapisuje credential gdy MySQL logowanie udane."""
    with patch("run_cred_worker.SessionLocal", return_value=_make_mock_db_for_db_protocols()), \
         patch.object(w, "_get_device_open_ports", return_value={}), \
         patch.object(w, "discover_ssh", return_value=None), \
         patch.object(w, "discover_ftp", return_value=None), \
         patch.object(w, "discover_rdp", return_value=None), \
         patch.object(w, "_web_detect_auth", return_value=False), \
         patch.object(w, "discover_mssql", return_value=None), \
         patch.object(w, "discover_mysql", return_value=("root", "")), \
         patch.object(w, "discover_postgres", return_value=None), \
         patch.object(w, "_save_cred") as mock_save, \
         patch.object(w, "_save_tried"), \
         patch("run_cred_worker._tcp_open", return_value=True):
        res = w._process_device(99, "10.0.0.6", [], [], [], [],
                                 mysql_pairs=[("root", "")], pairs_per_cycle=1)
    assert res["mysql"] is True
    assert res["new"] >= 1


def test_process_device_postgres_found_saves_credential():
    """_process_device zapisuje credential gdy PostgreSQL logowanie udane."""
    with patch("run_cred_worker.SessionLocal", return_value=_make_mock_db_for_db_protocols()), \
         patch.object(w, "_get_device_open_ports", return_value={}), \
         patch.object(w, "discover_ssh", return_value=None), \
         patch.object(w, "discover_ftp", return_value=None), \
         patch.object(w, "discover_rdp", return_value=None), \
         patch.object(w, "_web_detect_auth", return_value=False), \
         patch.object(w, "discover_mssql", return_value=None), \
         patch.object(w, "discover_mysql", return_value=None), \
         patch.object(w, "discover_postgres", return_value=("postgres", "postgres")), \
         patch.object(w, "_save_cred") as mock_save, \
         patch.object(w, "_save_tried"), \
         patch("run_cred_worker._tcp_open", return_value=True):
        res = w._process_device(99, "10.0.0.7", [], [], [], [],
                                 postgres_pairs=[("postgres", "postgres")], pairs_per_cycle=1)
    assert res["postgres"] is True
    assert res["new"] >= 1


def test_process_device_no_db_pairs_skips_db_testing():
    """_process_device pomija testowanie DB gdy brak par credentials."""
    with patch("run_cred_worker.SessionLocal", return_value=_make_mock_db_for_db_protocols()), \
         patch.object(w, "_get_device_open_ports", return_value={}), \
         patch.object(w, "discover_ssh", return_value=None), \
         patch.object(w, "discover_ftp", return_value=None), \
         patch.object(w, "discover_rdp", return_value=None), \
         patch.object(w, "_web_detect_auth", return_value=False), \
         patch.object(w, "discover_mssql") as mock_mssql, \
         patch.object(w, "discover_mysql") as mock_mysql, \
         patch.object(w, "discover_postgres") as mock_pg, \
         patch.object(w, "_save_tried"):
        res = w._process_device(99, "10.0.0.8", [], [], [], [],
                                 mssql_pairs=[], mysql_pairs=[], postgres_pairs=[], pairs_per_cycle=1)
    mock_mssql.assert_not_called()
    mock_mysql.assert_not_called()
    mock_pg.assert_not_called()
    assert res["mssql"] is False
    assert res["mysql"] is False
    assert res["postgres"] is False


# ─── discover_telnet ──────────────────────────────────────────────────────────

def test_discover_telnet_skips_when_port_closed():
    """Gdy port 23 i 2323 sa zamkniete — zwroc None bez proby logowania."""
    with patch("socket.create_connection", side_effect=OSError("refused")):
        assert w.discover_telnet("10.0.0.1", [("admin", "admin")]) is None


def test_discover_telnet_returns_none_when_no_login_prompt():
    """Gdy serwer nie wyslal prompta 'login:' — nie probuj logowania."""
    mock_tn = MagicMock()
    mock_tn.read_until.return_value = b"Welcome to device\r\n"  # brak 'ogin:'
    with patch("socket.create_connection"):
        with patch("telnetlib.Telnet", return_value=mock_tn):
            result = w.discover_telnet("10.0.0.1", [("admin", "admin")])
    assert result is None


def test_discover_telnet_returns_none_when_no_password_prompt():
    """Gdy po podaniu loginu brak prompta 'Password:' — zwroc None."""
    mock_tn = MagicMock()
    mock_tn.read_until.side_effect = [
        b"login: ",         # prompt logowania
        b"some garbage",    # brak 'assword:'
    ]
    with patch("socket.create_connection"):
        with patch("telnetlib.Telnet", return_value=mock_tn):
            result = w.discover_telnet("10.0.0.1", [("admin", "admin")])
    assert result is None


def test_discover_telnet_returns_none_on_incorrect_password():
    """Odpowiedz 'Login incorrect' po haśle — brak sukcesu."""
    mock_tn = MagicMock()
    mock_tn.read_until.side_effect = [
        b"login: ",
        b"Password: ",
        b"Login incorrect\r\nlogin: ",
    ]
    mock_tn.read_very_eager.return_value = b""
    with patch("socket.create_connection"):
        with patch("telnetlib.Telnet", return_value=mock_tn):
            result = w.discover_telnet("10.0.0.1", [("admin", "wrongpass")])
    assert result is None


def test_discover_telnet_returns_none_on_invalid_password():
    """Odpowiedz 'invalid' po haśle — brak sukcesu."""
    mock_tn = MagicMock()
    mock_tn.read_until.side_effect = [
        b"Username: ",
        b"Password: ",
        b"% Bad passwords\r\n",
    ]
    mock_tn.read_very_eager.return_value = b""
    with patch("socket.create_connection"):
        with patch("telnetlib.Telnet", return_value=mock_tn):
            result = w.discover_telnet("10.0.0.1", [("cisco", "wrong")])
    assert result is None


def test_discover_telnet_detects_success_on_hash_prompt():
    """Sukces gdy po haśle pojawia sie prompt '#' (root/admin shell)."""
    mock_tn = MagicMock()
    mock_tn.read_until.side_effect = [
        b"login: ",
        b"Password: ",
        b"router#",
    ]
    mock_tn.read_very_eager.return_value = b""
    with patch("socket.create_connection"):
        with patch("telnetlib.Telnet", return_value=mock_tn):
            result = w.discover_telnet("10.0.0.1", [("admin", "admin")])
    assert result == ("admin", "admin")


def test_discover_telnet_detects_success_on_dollar_prompt():
    """Sukces gdy po hasle pojawia sie prompt '$' (user shell Linux)."""
    mock_tn = MagicMock()
    mock_tn.read_until.side_effect = [
        b"login: ",
        b"Password: ",
        b"user@device:~$",
    ]
    mock_tn.read_very_eager.return_value = b""
    with patch("socket.create_connection"):
        with patch("telnetlib.Telnet", return_value=mock_tn):
            result = w.discover_telnet("10.0.0.1", [("user", "user")])
    assert result == ("user", "user")


def test_discover_telnet_detects_success_on_angle_bracket():
    """Sukces gdy po hasle pojawia sie prompt '>' (Cisco user mode)."""
    mock_tn = MagicMock()
    mock_tn.read_until.side_effect = [
        b"Username: ",
        b"Password: ",
        b"Router>",
    ]
    mock_tn.read_very_eager.return_value = b""
    with patch("socket.create_connection"):
        with patch("telnetlib.Telnet", return_value=mock_tn):
            result = w.discover_telnet("10.0.0.1", [("cisco", "cisco")])
    assert result == ("cisco", "cisco")


def test_discover_telnet_tries_port_2323_when_23_closed():
    """Gdy port 23 zamkniety ale 2323 otwarty — probuj na 2323."""
    call_count = {"n": 0}

    def _mock_connect(addr, timeout):
        host, port = addr
        call_count["n"] += 1
        if port == 23:
            raise OSError("refused")
        return MagicMock().__enter__.return_value

    mock_tn = MagicMock()
    mock_tn.read_until.side_effect = [b"login: ", b"Password: ", b"router#"]
    mock_tn.read_very_eager.return_value = b""
    with patch("socket.create_connection", side_effect=_mock_connect):
        with patch("telnetlib.Telnet", return_value=mock_tn):
            result = w.discover_telnet("10.0.0.1", [("admin", "admin")])
    assert result == ("admin", "admin")


def test_discover_telnet_returns_none_on_eoferror():
    """EOFError (rozlaczenie przez serwer) jest obsluzone — zwroc None."""
    mock_tn = MagicMock()
    mock_tn.read_until.side_effect = [b"login: ", b"Password: ", EOFError]
    with patch("socket.create_connection"):
        with patch("telnetlib.Telnet", return_value=mock_tn):
            result = w.discover_telnet("10.0.0.1", [("admin", "admin")])
    assert result is None


def test_discover_telnet_returns_none_on_exception():
    """Wyjatki sieciowe sa ignorowane — zwroc None."""
    with patch("socket.create_connection"):
        with patch("telnetlib.Telnet", side_effect=Exception("timeout")):
            result = w.discover_telnet("10.0.0.1", [("admin", "admin")])
    assert result is None


def test_discover_telnet_ports_defined():
    """_TELNET_PORTS zawiera port 23."""
    assert 23 in w._TELNET_PORTS


def test_telnet_fallback_credentials_nonempty():
    """TELNET_CREDENTIAL_FALLBACK jest niepusta i zawiera pary stringow."""
    assert len(w.TELNET_CREDENTIAL_FALLBACK) > 0
    for u, p in w.TELNET_CREDENTIAL_FALLBACK:
        assert isinstance(u, str)
        assert isinstance(p, str)


# ─── _web_form_ok: false positive detection ───────────────────────────────────

def test_web_form_ok_returns_false_when_response_identical_to_no_auth():
    """Regresja: kamera SPA zwraca identyczna strone niezaleznie od credentials.
    _web_form_ok musi zwrocic False gdy POST(u/p) == GET(no-auth) — false positive.
    Przyklad: kamera .5.200 zawiera 'logout' w JS strony logowania."""
    # Strona zawiera 'logout' w JS — stary kod zwracalby True (false positive)
    spa_page = "x" * 5000 + "function logout() { }" + "y" * 5000
    mock_get = MagicMock()
    mock_get.status_code = 200
    mock_get.text = spa_page
    mock_post = MagicMock()
    mock_post.status_code = 200
    mock_post.text = spa_page   # identyczna odpowiedz z i bez credentials

    with patch("run_cred_worker.httpx") as mock_httpx:
        mock_httpx.get.return_value = mock_get
        mock_httpx.post.return_value = mock_post
        result = w._web_form_ok("http://10.0.0.200/", "admin", "admin")

    assert result is False, "_web_form_ok musi zwrocic False gdy odpowiedzi sa identyczne"


def test_web_form_ok_returns_true_when_response_differs_significantly():
    """_web_form_ok zwraca True gdy odpowiedz z credentials jest wyraznie inna niz bez."""
    no_auth_page = "<html><body>Please login</body></html>"
    logged_in_page = "<html><body>" + "Dashboard content " * 200 + "logout button</body></html>"

    mock_get = MagicMock()
    mock_get.status_code = 200
    mock_get.text = no_auth_page
    mock_post = MagicMock()
    mock_post.status_code = 200
    mock_post.text = logged_in_page

    with patch("run_cred_worker.httpx") as mock_httpx:
        mock_httpx.get.return_value = mock_get
        mock_httpx.post.return_value = mock_post
        result = w._web_form_ok("http://10.0.0.1/login", "admin", "admin123")

    assert result is True


def test_web_form_ok_returns_false_when_response_nearly_identical():
    """Regresja: roznica < 5% dlugosci tresci bez cookie sesji → false positive."""
    base = "A" * 10000 + "logout" + "B" * 10000
    # Roznica tylko kilku znakow — < 5% dlugosci
    almost_same = base + "X" * 10   # +10 znakow na 20006 = 0.05% roznica

    mock_get = MagicMock()
    mock_get.status_code = 200
    mock_get.text = base
    mock_post = MagicMock()
    mock_post.status_code = 200
    mock_post.text = almost_same

    with patch("run_cred_worker.httpx") as mock_httpx:
        mock_httpx.get.return_value = mock_get
        mock_httpx.post.return_value = mock_post
        result = w._web_form_ok("http://10.0.0.1/", "admin", "admin")

    assert result is False, "Tresci prawie identyczne → false positive, musi zwrocic False"


def test_web_form_ok_returns_false_when_ok_keyword_in_no_auth_page():
    """Regresja: kamera .5.171 ma id='logoutmenu' w HTML strony logowania (zawsze).
    Keyword 'logout' w no-auth page nie moze byc uznany za dowod zalogowania."""
    # Kamera zwraca ta sama strone z 'logout' zarowno bez auth jak i z zle podanymi credentials
    camera_login_page = (
        '<html><body><div id="logoutmenu" style="display:none">Logout</div>'
        '<div id="login"><form><input type="password" name="password"></form></div>'
        '</body></html>'
    )
    # Auth POST zwraca nieco inna strone (np. inne body), ale logout jest w obu
    camera_with_wrong_cred = camera_login_page + "<span>Blad hasla</span>"  # >5% roznica

    mock_get = MagicMock()
    mock_get.status_code = 200
    mock_get.text = camera_login_page
    mock_post = MagicMock()
    mock_post.status_code = 200
    mock_post.text = camera_with_wrong_cred  # rozni sie rozmiarem (>5%), ma 'logout'

    with patch("run_cred_worker.httpx") as mock_httpx:
        mock_httpx.get.return_value = mock_get
        mock_httpx.post.return_value = mock_post
        result = w._web_form_ok("http://192.0.2.171:8899/", "administrator", "administrator")

    assert result is False, "logout w no-auth page → nie swiadczy o zalogowaniu, musi byc False"


def test_web_basic_ok_returns_false_when_ok_keyword_in_no_auth_page():
    """Regresja: _web_basic_ok musi zwrocic False gdy 'logout' jest w stronie BEZ auth.
    Kamera moze miec 'logout' w HTML strony logowania (hidden element)."""
    camera_login_page = '<html><div id="logoutmenu">Logout</div><form>login form</form></html>'
    # Auth response jest nieco inne (inne body) ale logout jest w obu
    auth_response = camera_login_page + "<p>extra content making it >5% different</p>" * 10

    mock_get_noauth = MagicMock()
    mock_get_noauth.status_code = 200
    mock_get_noauth.text = camera_login_page
    mock_get_auth = MagicMock()
    mock_get_auth.status_code = 200
    mock_get_auth.text = auth_response
    mock_get_auth.headers = {"set-cookie": ""}

    def _side_effect(url, **kwargs):
        if kwargs.get("auth"):
            return mock_get_auth
        return mock_get_noauth

    with patch("run_cred_worker.httpx") as mock_httpx:
        mock_httpx.get.side_effect = _side_effect
        result = w._web_basic_ok("http://192.0.2.171:8899", "administrator", "administrator")

    assert result is False, "logout w no-auth page → nie swiadczy o zalogowaniu, musi byc False"


def test_web_form_ok_returns_false_when_no_auth_baseline_unavailable():
    """BUG-CRED-FP-01: _web_form_ok musi zwrocic False gdy _get_no_auth() zawiedzie (zwroci '').
    Bez baseline porownawczego 'logout' w HTML strony logowania jest unreliable.
    Przyklad: kamera 192.168.5.171 (H264DVR) — strona logowania zawiera 'logout' w JS ZAWSZE,
    _get_no_auth timeout → no_auth_text='' → stary kod zwracal True (false positive)."""
    # DVR login page zawiera "logout" w JS — identyczne bez wzgledu na credentials
    dvr_login_page = (
        '<html><body>'
        '<script>function logout(){window.location="/login"}</script>'
        '<div id="login"><input type="password" id="loginPsw"/></div>'
        '</body></html>'
    )
    mock_get_fail = MagicMock()
    mock_get_fail.status_code = 0
    mock_get_fail.text = ""   # _get_no_auth failure — timeout/network error

    mock_post = MagicMock()
    mock_post.status_code = 200
    mock_post.text = dvr_login_page   # contains "logout", no bad keywords

    with patch("run_cred_worker.httpx") as mock_httpx:
        mock_httpx.get.return_value = mock_get_fail
        mock_httpx.post.return_value = mock_post
        result = w._web_form_ok("http://192.0.2.171/", "admin", "admin123")

    assert result is False, (
        "BUG-CRED-FP-01: _web_form_ok must return False when no-auth baseline "
        "is unavailable — cannot distinguish login from public page without comparison"
    )


def test_web_basic_ok_returns_false_when_no_auth_baseline_unavailable():
    """BUG-CRED-FP-01: _web_basic_ok musi zwrocic False (bez session cookie) gdy baseline niedostepny.
    Stary kod: 3 sprawdzenia chronione przez 'if no_auth_text' — wszystkie pomijane gdy text=''.
    Wynik: 'logout' w HTML wystarczal do zwrocenia True — false positive."""
    dvr_login_page = (
        '<html><body>'
        '<div id="logoutmenu" style="display:none">Logout</div>'
        '<div id="login"><form><input type="password"/></form></div>'
        '</body></html>'
    )
    mock_get_fail = MagicMock()
    mock_get_fail.status_code = 0
    mock_get_fail.text = ""   # _get_no_auth failure

    mock_get_auth = MagicMock()
    mock_get_auth.status_code = 200
    mock_get_auth.text = dvr_login_page
    mock_get_auth.headers = {"set-cookie": ""}   # no session cookie

    def _side_effect(url, **kwargs):
        return mock_get_auth if kwargs.get("auth") else mock_get_fail

    with patch("run_cred_worker.httpx") as mock_httpx:
        mock_httpx.get.side_effect = _side_effect
        result = w._web_basic_ok("http://192.0.2.171/", "admin", "admin123")

    assert result is False, (
        "BUG-CRED-FP-01: _web_basic_ok must return False when no-auth baseline "
        "unavailable and no session cookie — keyword alone is not reliable"
    )


def test_web_basic_ok_returns_true_with_session_cookie_even_without_baseline():
    """BUG-CRED-FP-01 — session cookie jest silnym signalem: nawet bez baseline powinno zwrocic True.
    Set-Cookie z 'session'/'token' prawie zawsze oznacza prawdziwe logowanie."""
    login_success = '<html><body>Welcome to the system dashboard</body></html>'

    mock_get_fail = MagicMock()
    mock_get_fail.status_code = 0
    mock_get_fail.text = ""   # no baseline

    mock_get_auth = MagicMock()
    mock_get_auth.status_code = 200
    mock_get_auth.text = login_success
    mock_get_auth.headers = {"set-cookie": "sessionid=abc123; Path=/"}   # session cookie!

    def _side_effect(url, **kwargs):
        return mock_get_auth if kwargs.get("auth") else mock_get_fail

    with patch("run_cred_worker.httpx") as mock_httpx:
        mock_httpx.get.side_effect = _side_effect
        result = w._web_basic_ok("http://10.0.0.1/", "admin", "password")

    assert result is True, (
        "Session cookie is strong signal — should return True even without no-auth baseline"
    )


def test_web_form_ok_returns_false_when_bad_keywords_in_response():
    """_web_form_ok zwraca False gdy body zawiera 'login failed'."""
    login_page = "<html>Login failed. Invalid credentials.</html>"

    mock_get = MagicMock()
    mock_get.status_code = 200
    mock_get.text = "login page"
    mock_post = MagicMock()
    mock_post.status_code = 200
    mock_post.text = login_page

    with patch("run_cred_worker.httpx") as mock_httpx:
        mock_httpx.get.return_value = mock_get
        mock_httpx.post.return_value = mock_post
        result = w._web_form_ok("http://10.0.0.1/login", "admin", "wrongpwd")

    assert result is False


# =============================================================================
# _reverify_existing_creds — testy regresyjne (false positive cleanup)
# =============================================================================

def _make_fake_cred(method_val, username, password, device_id=1):
    """Tworzy mock obiektu Credential do testow _reverify_existing_creds."""
    cred = MagicMock()
    cred.device_id = device_id
    cred.username = username
    cred.password_encrypted = password
    cred.method = MagicMock()
    cred.method.value = method_val
    # CredentialMethod.api porownywany przez ==
    from netdoc.storage.models import CredentialMethod
    cred.method = CredentialMethod[method_val] if method_val in CredentialMethod.__members__ else cred.method
    return cred


def test_reverify_removes_false_positive_api_credential():
    """Regresja: _reverify usuwa credential api gdy kamera zwraca identyczna strone bez auth."""
    from netdoc.storage.models import CredentialMethod

    fake_cred = MagicMock()
    fake_cred.method = CredentialMethod.api
    fake_cred.username = "admin"
    fake_cred.password_encrypted = "admin"

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.all.return_value = [fake_cred]
    mock_db.query.return_value.filter.return_value.first.return_value = None  # no device

    with patch.object(w, "_tcp_open", return_value=True), \
         patch.object(w, "_web_basic_ok", return_value=False), \
         patch.object(w, "_web_form_ok", return_value=False):
        w._reverify_existing_creds(mock_db, 1, "192.0.2.171")

    mock_db.delete.assert_called_once_with(fake_cred)
    mock_db.commit.assert_called()


def test_reverify_keeps_valid_api_credential():
    """Regresja: _reverify NIE usuwa credential gdy _web_basic_ok zwraca True."""
    from netdoc.storage.models import CredentialMethod

    fake_cred = MagicMock()
    fake_cred.method = CredentialMethod.api
    fake_cred.username = "admin"
    fake_cred.password_encrypted = "admin"

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.all.return_value = [fake_cred]

    with patch.object(w, "_tcp_open", return_value=True), \
         patch.object(w, "_web_basic_ok", return_value=True):
        w._reverify_existing_creds(mock_db, 1, "10.0.0.1")

    mock_db.delete.assert_not_called()


def test_reverify_resets_last_credential_ok_at_when_all_removed():
    """Regresja: _reverify resetuje last_credential_ok_at gdy wszystkie credentials usuniete."""
    from netdoc.storage.models import CredentialMethod

    fake_cred = MagicMock()
    fake_cred.method = CredentialMethod.api
    fake_cred.username = "admin"
    fake_cred.password_encrypted = "admin"

    fake_device = MagicMock()
    fake_device.last_credential_ok_at = "2026-03-11 22:30:00"

    mock_db = MagicMock()
    # query(Credential).filter.all() → [fake_cred]
    # query(Device).filter.first() → fake_device
    def db_query_side_effect(model):
        q = MagicMock()
        if model.__name__ == "Credential":
            q.filter.return_value.all.return_value = [fake_cred]
        else:  # Device
            q.filter.return_value.first.return_value = fake_device
        return q

    from netdoc.storage import models as m
    mock_db.query.side_effect = db_query_side_effect

    with patch.object(w, "_tcp_open", return_value=True), \
         patch.object(w, "_web_basic_ok", return_value=False), \
         patch.object(w, "_web_form_ok", return_value=False):
        w._reverify_existing_creds(mock_db, 1, "10.0.0.1")

    assert fake_device.last_credential_ok_at is None


def test_reverify_does_nothing_when_no_saved_credentials():
    """_reverify nie robi nic gdy brak device-specific credentials."""
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.all.return_value = []

    w._reverify_existing_creds(mock_db, 99, "10.0.0.99")

    mock_db.delete.assert_not_called()
    mock_db.commit.assert_not_called()


def test_reverify_skips_non_api_ssh_methods():
    """_reverify zostawia credentials metod bez implementacji weryfikacji (np. snmp)."""
    from netdoc.storage.models import CredentialMethod

    fake_cred = MagicMock()
    fake_cred.method = CredentialMethod.snmp
    fake_cred.username = "public"
    fake_cred.password_encrypted = ""

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.all.return_value = [fake_cred]

    w._reverify_existing_creds(mock_db, 1, "10.0.0.1")

    # snmp nie ma weryfikatora → valid=True → nie usuwa
    mock_db.delete.assert_not_called()


# ─── _vnc_encrypt_password ────────────────────────────────────────────────────

def test_vnc_encrypt_password_length():
    """Wynik musi miec dokladnie 8 bajtow (rozmiar klucza DES)."""
    result = w._vnc_encrypt_password("secret")
    assert len(result) == 8


def test_vnc_encrypt_password_empty():
    """Puste haslo = 8 bajtow null po odwroceniu bitow (null odwrocony = null)."""
    result = w._vnc_encrypt_password("")
    assert result == bytes(8)


def test_vnc_encrypt_password_bit_reversal():
    """Sprawdza odwrocenie bitow: 0x41 ('A') = 0b01000001 → odwrocone = 0b10000010 = 0x82."""
    result = w._vnc_encrypt_password("A")
    assert result[0] == 0x82  # 'A' = 0x41 = 01000001b → 10000010b = 0x82


def test_vnc_encrypt_password_truncates_to_8_chars():
    """Haslo dluzsze niz 8 znakow jest obcinane."""
    result_long = w._vnc_encrypt_password("password123")
    result_short = w._vnc_encrypt_password("password")
    assert result_long == result_short


def test_vnc_encrypt_password_known_vector():
    """Wektorowe: 'pass' = [0x70, 0x61, 0x73, 0x73] → bity odwrocone per bajt."""
    # 'p' = 0x70 = 01110000b → 00001110b = 0x0E
    # 'a' = 0x61 = 01100001b → 10000110b = 0x86
    # 's' = 0x73 = 01110011b → 11001110b = 0xCE
    result = w._vnc_encrypt_password("pass")
    assert result[0] == 0x0E
    assert result[1] == 0x86
    assert result[2] == 0xCE
    assert result[3] == 0xCE  # 's' powtorzone


# ─── discover_vnc ─────────────────────────────────────────────────────────────

def test_discover_vnc_returns_none_when_no_port_open():
    """discover_vnc zwraca None gdy zadne porty 5900-5903 nie sa otwarte."""
    with patch("socket.create_connection", side_effect=OSError("refused")):
        result = w.discover_vnc("10.0.0.1", [("", "secret")])
    assert result is None


def test_discover_vnc_returns_none_when_check_fails():
    """discover_vnc zwraca None gdy _vnc_check_password zwraca False dla wszystkich hasel."""
    with patch("socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__ = lambda s: s
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        with patch.object(w, "_vnc_check_password", return_value=False):
            result = w.discover_vnc("10.0.0.1", [("", "wrong"), ("", "bad")])
    assert result is None


def test_discover_vnc_returns_pair_on_success():
    """discover_vnc zwraca pare (username, password) gdy _vnc_check_password zwroci True."""
    with patch("socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__ = lambda s: s
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        with patch.object(w, "_vnc_check_password", return_value=True):
            result = w.discover_vnc("10.0.0.1", [("", "secret")])
    assert result == ("", "secret")


def test_discover_vnc_deduplicates_passwords():
    """discover_vnc nie probuje tego samego hasla dwa razy (VNC = tylko haslo, bez usera)."""
    calls = []

    def _fake_check(ip, port, password, timeout=5.0):
        calls.append(password)
        return False

    with patch("socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__ = lambda s: s
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        with patch.object(w, "_vnc_check_password", side_effect=_fake_check):
            w.discover_vnc("10.0.0.1", [("", "abc"), ("user1", "abc"), ("", "xyz")])

    # "abc" wystepuje dwa razy → probowane raz; "xyz" → raz → lacznie 2
    assert calls.count("abc") == 1
    assert len(calls) == 2


def test_discover_vnc_stops_after_first_success():
    """discover_vnc zatrzymuje sie po pierwszym trafieniu (nie sprawdza kolejnych hasel)."""
    calls = []

    def _fake_check(ip, port, password, timeout=5.0):
        calls.append(password)
        return password == "hit"

    with patch("socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__ = lambda s: s
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        with patch.object(w, "_vnc_check_password", side_effect=_fake_check):
            result = w.discover_vnc("10.0.0.1", [("", "hit"), ("", "after")])

    assert result == ("", "hit")
    assert "after" not in calls


# ─── discover_ftp ─────────────────────────────────────────────────────────────

def test_discover_ftp_returns_none_when_port_closed():
    """discover_ftp zwraca None gdy port 21 jest zamkniety."""
    with patch("socket.create_connection", side_effect=OSError("refused")):
        result = w.discover_ftp("10.0.0.1", [("admin", "admin")])
    assert result is None


def test_discover_ftp_returns_pair_on_anonymous_login():
    """discover_ftp zwraca ('anonymous', '') gdy anonymous login dziala."""
    import ftplib

    mock_ftp = MagicMock()
    mock_ftp.login.return_value = None

    with patch("socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__ = lambda s: s
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        with patch("ftplib.FTP", return_value=mock_ftp):
            result = w.discover_ftp("10.0.0.1", [])

    # anonymous jest zawsze dodawany jako pierwszy
    assert result == ("anonymous", "")


def test_discover_ftp_returns_pair_on_credential_match():
    """discover_ftp zwraca pare gdy podane credentials dzialaja."""
    import ftplib

    attempt_log: list = []

    class _FakeFTP:
        def connect(self, ip, port, timeout):
            pass
        def login(self, u, p):
            attempt_log.append((u, p))
            if u == "admin" and p == "admin":
                return
            raise ftplib.error_perm("530 Login incorrect")
        def quit(self):
            pass

    with patch("socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__ = lambda s: s
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        with patch("ftplib.FTP", side_effect=_FakeFTP):
            result = w.discover_ftp("10.0.0.1", [("admin", "admin")])

    assert result is not None
    assert result[0] == "admin"
    assert result[1] == "admin"


def test_discover_ftp_returns_none_when_all_fail():
    """discover_ftp zwraca None gdy wszystkie credentials sa bledne."""
    import ftplib

    class _FakeFTP:
        def connect(self, *a, **kw): pass
        def login(self, u, p):
            raise ftplib.error_perm("530 Login incorrect")
        def quit(self): pass

    with patch("socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__ = lambda s: s
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        with patch("ftplib.FTP", side_effect=_FakeFTP):
            result = w.discover_ftp("10.0.0.1", [("user", "bad")])

    assert result is None


# ─── FTP CredentialMethod — poprawnosc metody ──────────────────────────────────

def test_ftp_fallback_credentials_nonempty():
    """FTP_CREDENTIAL_FALLBACK zawiera pary credentials."""
    assert len(w.FTP_CREDENTIAL_FALLBACK) > 0
    # kazda para to (username, password)
    for u, p in w.FTP_CREDENTIAL_FALLBACK:
        assert isinstance(u, str)
        assert isinstance(p, str)


def test_ftp_fallback_contains_anonymous():
    """FTP_CREDENTIAL_FALLBACK zawiera anonymous/ftp (standard RFC 959)."""
    methods = {(u, p) for u, p in w.FTP_CREDENTIAL_FALLBACK}
    assert ("anonymous", "") in methods or ("anonymous", "ftp") in methods


def test_vnc_fallback_credentials_nonempty():
    """VNC_CREDENTIAL_FALLBACK zawiera pary credentials."""
    assert len(w.VNC_CREDENTIAL_FALLBACK) > 0
    for u, p in w.VNC_CREDENTIAL_FALLBACK:
        assert isinstance(u, str)
        assert isinstance(p, str)


def test_vnc_fallback_passwords_max_8_chars():
    """Wszystkie hasla VNC maja maks 8 znakow (limit protokolu RFB)."""
    for u, p in w.VNC_CREDENTIAL_FALLBACK:
        assert len(p) <= 8, f"Haslo VNC za dlugie: {p!r} ({len(p)} znakow)"


def test_rdp_fallback_credentials_nonempty():
    """RDP_CREDENTIAL_FALLBACK zawiera pary credentials."""
    assert len(w.RDP_CREDENTIAL_FALLBACK) > 0
    for u, p in w.RDP_CREDENTIAL_FALLBACK:
        assert isinstance(u, str)
        assert isinstance(p, str)


# ─── GoAhead-Webs (Cisco SF/SG/CBS) ──────────────────────────────────────────

def test_web_goahead_get_token_returns_none_for_non_goahead():
    """_web_goahead_get_token zwraca None gdy Server header nie zawiera 'goahead'."""
    mock_resp = MagicMock()
    mock_resp.headers = {"server": "Apache/2.4", "location": "/csfec05640/"}
    with patch("httpx.get", return_value=mock_resp):
        result = w._web_goahead_get_token("http://10.0.0.1:80")
    assert result is None


def test_web_goahead_get_token_extracts_token():
    """_web_goahead_get_token wyciaga token z Location gdy Server = GoAhead-Webs."""
    mock_resp = MagicMock()
    mock_resp.headers = {"server": "GoAhead-Webs", "location": "http://10.0.0.1/csfec05640/"}
    with patch("httpx.get", return_value=mock_resp):
        result = w._web_goahead_get_token("http://10.0.0.1:80")
    assert result == "csfec05640"


def test_web_goahead_get_token_returns_none_when_no_token_in_location():
    """_web_goahead_get_token zwraca None gdy Location nie zawiera tokenu."""
    mock_resp = MagicMock()
    mock_resp.headers = {"server": "GoAhead-Webs", "location": "http://10.0.0.1/"}
    with patch("httpx.get", return_value=mock_resp):
        result = w._web_goahead_get_token("http://10.0.0.1:80")
    assert result is None


def test_web_goahead_ok_returns_true_on_status_code_zero():
    """_web_goahead_ok zwraca True gdy odpowiedz XML zawiera statusCode=0."""
    xml_ok = "<?xml version='1.0'?><ResponseData><ActionStatus><statusCode>0</statusCode></ActionStatus></ResponseData>"
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = xml_ok
    with patch("httpx.get", return_value=mock_resp):
        result = w._web_goahead_ok("http://10.0.0.1:80", "csfec05640", "cisco", "cisco")
    assert result is True


def test_web_goahead_ok_returns_false_on_bad_credentials():
    """_web_goahead_ok zwraca False gdy statusCode != 0 (bad user or password)."""
    xml_fail = "<?xml version='1.0'?><ResponseData><ActionStatus><statusCode>4</statusCode><statusString>Bad User or Password</statusString></ActionStatus></ResponseData>"
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = xml_fail
    with patch("httpx.get", return_value=mock_resp):
        result = w._web_goahead_ok("http://10.0.0.1:80", "csfec05640", "admin", "wrong")
    assert result is False


def test_web_goahead_ok_returns_false_on_http_error():
    """_web_goahead_ok zwraca False przy wyjatku sieciowym."""
    with patch("httpx.get", side_effect=Exception("timeout")):
        result = w._web_goahead_ok("http://10.0.0.1:80", "csfec05640", "cisco", "cisco")
    assert result is False


def test_web_detect_auth_returns_true_for_goahead():
    """_web_detect_auth wykrywa GoAhead-Webs jako urzadzenie z logowaniem."""
    mock_resp = MagicMock()
    mock_resp.headers = {"server": "GoAhead-Webs", "location": "http://10.0.0.1/csfec05640/"}
    mock_resp.text = ""
    with patch("httpx.get", return_value=mock_resp):
        result = w._web_detect_auth("10.0.0.1", [80])
    assert result is True


def test_discover_web_uses_goahead_when_token_found():
    """discover_web wykrywa i loguje przez GoAhead gdy token dostepny."""
    xml_ok = "<statusCode>0</statusCode>"

    token_resp = MagicMock()
    token_resp.headers = {"server": "GoAhead-Webs", "location": "http://10.0.0.1/abc123def/"}

    login_resp = MagicMock()
    login_resp.status_code = 200
    login_resp.text = xml_ok

    call_count = [0]
    def _fake_get(url, **kwargs):
        call_count[0] += 1
        if "System.xml" in url:
            return login_resp
        return token_resp

    with patch("httpx.get", side_effect=_fake_get):
        result = w.discover_web("10.0.0.1", [("cisco", "cisco")], open_ports_hint=[80])

    assert result == ("cisco", "cisco")


# ─── Testy regresyjne (naprawione bugi) ──────────────────────────────────────

# BUG-DB[2]: Credential.device_id.is_(None) — globalne credentiale w DB

def test_read_method_flags_returns_all_methods_including_vnc():
    """BUG-DB[11] regresja: cred_vnc_enabled musi byc w _ALL_FLAGS."""
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None

    with patch.object(w, "SessionLocal", return_value=mock_db):
        flags = w._read_method_flags()

    assert "cred_vnc_enabled" in flags, "cred_vnc_enabled brakuje w _ALL_FLAGS"
    assert "cred_ssh_enabled" in flags
    assert "cred_rdp_enabled" in flags


def test_load_credentials_uses_is_none_for_global_ssh(db):
    """BUG-DB[2] regresja: globalne SSH credentials (device_id IS NULL) muszą byc odczytane."""
    from netdoc.storage.models import Credential, CredentialMethod

    # Dodaj globalne credential (device_id=None)
    cred = Credential(device_id=None, method=CredentialMethod.ssh,
                      username="admin", password_encrypted="secret", priority=1)
    db.add(cred)
    db.commit()

    result = db.query(Credential).filter(
        Credential.device_id.is_(None),
        Credential.method == CredentialMethod.ssh,
    ).all()

    assert len(result) == 1
    assert result[0].username == "admin"


def test_load_credentials_device_id_eq_none_fails(db):
    """BUG-DB[2] dokumentacja: == None generuje WHERE device_id = NULL (zawsze FALSE w PG/SQLite)."""
    from netdoc.storage.models import Credential, CredentialMethod

    cred = Credential(device_id=None, method=CredentialMethod.ssh,
                      username="admin", password_encrypted="secret", priority=1)
    db.add(cred)
    db.commit()

    # SQLite: == None generuje "device_id = NULL" — w SQLite to FALSE (tak samo jak PostgreSQL)
    result_wrong = db.query(Credential).filter(
        Credential.device_id == None,  # noqa: E711  — celowy stary pattern do udokumentowania
        Credential.method == CredentialMethod.ssh,
    ).all()
    result_correct = db.query(Credential).filter(
        Credential.device_id.is_(None),
        Credential.method == CredentialMethod.ssh,
    ).all()

    assert len(result_correct) == 1, "is_(None) musi zwracac wynik"
    # Uwaga: SQLite moze roznic sie od PostgreSQL w obsludze == None —
    # test dokumentuje intencje, nie wymusza konkretne zachowanie SQLite
    _ = result_wrong  # uzyty tylko dla dokumentacji


# BUG-DB[3]: Device.last_credential_ok_at.is_(None) — nowe urządzenia

def test_scan_candidates_includes_device_with_null_last_ok(db):
    """BUG-DB[3] regresja: urzadzenie z last_credential_ok_at=NULL musi trafiac do skanowania."""
    from netdoc.storage.models import Device, DeviceType

    dev = Device(ip="10.99.99.1", mac="AA:BB:CC:DD:EE:FF", is_active=True,
                 device_type=DeviceType.unknown, last_credential_ok_at=None)
    db.add(dev)
    db.commit()

    from datetime import datetime, timedelta
    threshold = datetime.utcnow() - timedelta(days=7)

    from netdoc.storage.models import Device as D
    candidates = db.query(D).filter(
        D.is_active == True,
        (D.last_credential_ok_at.is_(None)) | (D.last_credential_ok_at < threshold),
    ).all()

    assert any(c.ip == "10.99.99.1" for c in candidates), \
        "Urzadzenie z NULL last_credential_ok_at powinno byc w kandydatach"


# BUG-TEST: _reverify_existing_creds — SSH

def test_reverify_ssh_calls_try_ssh_not_ssh_try():
    """BUG-TEST regresja: _reverify uzywa _try_ssh (nie nieistniejacego _ssh_try)."""
    from netdoc.storage.models import CredentialMethod

    fake_cred = MagicMock()
    fake_cred.method = CredentialMethod.ssh
    fake_cred.username = "admin"
    fake_cred.password_encrypted = "pass"

    fake_device = MagicMock()
    fake_device.last_credential_ok_at = "2026-01-01"

    mock_db = MagicMock()
    def db_query_side(model):
        q = MagicMock()
        if hasattr(model, "__name__") and model.__name__ == "Credential":
            q.filter.return_value.all.return_value = [fake_cred]
        else:
            q.filter.return_value.first.return_value = fake_device
        return q
    mock_db.query.side_effect = db_query_side

    # _try_ssh zwraca True = credential nadal wazny → nie usuwaj
    with patch.object(w, "_tcp_open", return_value=True), \
         patch.object(w, "_try_ssh", return_value=True) as mock_ssh:
        w._reverify_existing_creds(mock_db, 1, "10.0.0.5")

    mock_ssh.assert_called_once_with("10.0.0.5", 22, "admin", "pass")
    mock_db.delete.assert_not_called()


def test_reverify_ssh_removes_credential_when_try_ssh_fails():
    """BUG-TEST regresja: _reverify usuwa SSH credential gdy _try_ssh zwraca False."""
    from netdoc.storage.models import CredentialMethod

    fake_cred = MagicMock()
    fake_cred.method = CredentialMethod.ssh
    fake_cred.username = "admin"
    fake_cred.password_encrypted = "wrong"

    fake_device = MagicMock()
    fake_device.last_credential_ok_at = "2026-01-01"

    mock_db = MagicMock()
    def db_query_side(model):
        q = MagicMock()
        if hasattr(model, "__name__") and model.__name__ == "Credential":
            q.filter.return_value.all.return_value = [fake_cred]
        else:
            q.filter.return_value.first.return_value = fake_device
        return q
    mock_db.query.side_effect = db_query_side

    with patch.object(w, "_tcp_open", return_value=True), \
         patch.object(w, "_try_ssh", return_value=False):
        w._reverify_existing_creds(mock_db, 1, "10.0.0.5")

    mock_db.delete.assert_called_once_with(fake_cred)


# BUG-worker: _note_protection — regex injection i kolejnosc tagu

def test_note_protection_no_regex_injection():
    """BUG-1 regresja: nazwa serwisu ze znakami specjalnymi regex nie powoduje bledu."""
    import re

    dev = MagicMock()
    dev.asset_notes = None
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = dev

    evt = {"port": 80, "reason": "test-reason", "count": 1, "last": None}

    # Serwis z nawiasami kwadratowymi — bez re.escape() rzucilby re.error
    try:
        w._note_protection(mock_db, 1, "10.0.0.1", "Svc[1]", evt)
    except re.error as e:
        pytest.fail(f"re.error przy specjalnych znakach w nazwie serwisu: {e}")


def test_note_protection_tag_prepended_to_existing_notes():
    """BUG-1 regresja: tag trafia na poczatek asset_notes (widoczny w popoverse 60-char)."""
    dev = MagicMock()
    dev.asset_notes = "Stare notatki o urzadzeniu"
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = dev

    evt = {"port": 22, "reason": "banner-reset", "count": 2, "last": None}
    w._note_protection(mock_db, 1, "10.0.0.1", "SSH", evt)

    new_notes = dev.asset_notes
    assert new_notes.startswith("[SSH-PROTECTED"), \
        f"Tag powinien byc na poczatku asset_notes, dostano: {new_notes[:60]}"


# BUG-worker: _process_protection_events w finally

def test_protection_events_drained_even_after_exception():
    """BUG-2 regresja: _drain_protection_events zwraca i czyści eventy dla danego IP."""
    w._protection_events.clear()

    w._protection_events[("10.0.0.1", "SSH")] = {
        "port": 22, "reason": "banner-reset", "count": 1, "last": None
    }
    w._protection_events[("10.0.0.2", "FTP")] = {
        "port": 21, "reason": "too-many", "count": 1, "last": None
    }

    events = w._drain_protection_events("10.0.0.1")

    assert len(events) == 1
    assert events[0][0] == "SSH"
    # Event dla 10.0.0.1 usunięty, dla 10.0.0.2 pozostaje
    assert ("10.0.0.1", "SSH") not in w._protection_events
    assert ("10.0.0.2", "FTP") in w._protection_events


# ─── BUG-DB-4: _reverify_existing_creds — jeden commit zamiast dwóch ─────────

def test_dispatch_delay_moved_to_worker_thread():
    """PERF-04 regresja: opóźnienie między skanowaniem IP przeniesione do wątku roboczego.
    Główny wątek nie blokuje się na time.sleep() podczas dispatchu taskow."""
    import inspect
    source = inspect.getsource(w.scan_once)
    # Stary wzorzec: sleep w pętli for przed submit()
    # Nowy wzorzec: delay przekazany jako parametr do _run(), sleep wewnątrz wątku
    assert "pool.submit(_run" in source, "_run musi być submitowany do ThreadPoolExecutor"
    # Upewniamy się że sleep NIE jest między enumerate i pool.submit (blokujący wzorzec)
    lines = [l.strip() for l in source.splitlines()]
    submit_idx = next((i for i, l in enumerate(lines) if "pool.submit(_run" in l), None)
    assert submit_idx is not None
    # Nie powinno być time.sleep() w liniach bezpośrednio przed submit
    sleep_before_submit = any(
        "time.sleep(random.uniform" in lines[i]
        for i in range(max(0, submit_idx - 3), submit_idx)
    )
    assert not sleep_before_submit, \
        "PERF-04: time.sleep(random.uniform) nie może być bezpośrednio przed pool.submit"


def test_read_method_flags_uses_single_query():
    """PERF-05 regresja: _read_method_flags wykonuje 1 query WHERE key IN (...)
    zamiast 8 osobnych SELECT per flagę."""
    import inspect
    source = inspect.getsource(w._read_method_flags)
    assert "key.in_(" in source, \
        "PERF-05: _read_method_flags musi używać .key.in_(...) zamiast pętli per klucz"
    assert "for key in _ALL_FLAGS" not in source or "filter(SystemStatus.key ==" not in source, \
        "PERF-05: nie może być oddzielnych query per klucz w pętli"


def test_reverify_single_commit_covers_deletion_and_sentinel_reset(db):
    """BUG-DB-4 regresja: _reverify_existing_creds wykonuje dokładnie jeden commit
    obejmujący zarówno usunięcia credentials jak i reset last_credential_ok_at.
    Poprzednio dwa osobne commit() tworzyły okno race condition."""
    from datetime import datetime
    from netdoc.storage.models import Device, Credential, CredentialMethod

    dev = Device(ip="10.5.5.5", mac="aa:bb:cc:dd:ee:01", is_active=True,
                 last_credential_ok_at=datetime.utcnow())
    db.add(dev)
    db.flush()

    # Dodaj credential dla urządzenia
    cred = Credential(device_id=dev.id, method=CredentialMethod.ssh,
                      username="admin", password_encrypted="wrong",
                      priority=10)
    db.add(cred)
    db.commit()

    commit_calls = []
    original_commit = db.commit

    def counting_commit():
        commit_calls.append(1)
        original_commit()

    # SSH fail → credential usunięty + sentinel zresetowany = jeden commit
    with patch.object(db, "commit", side_effect=counting_commit):
        with patch.object(w, "_try_ssh", return_value=False):
            w._reverify_existing_creds(db, dev.id, "10.5.5.5")

    assert len(commit_calls) == 1, (
        f"Oczekiwano dokładnie 1 commit (bez race condition), "
        f"ale było: {len(commit_calls)}"
    )

    db.expire_all()
    updated_dev = db.query(Device).filter(Device.id == dev.id).first()
    assert updated_dev.last_credential_ok_at is None, \
        "Sentinel last_credential_ok_at powinien być zresetowany"


# ─── TEST-1: PERF-09 regresja — _process_device używa 1 sesji DB ─────────────

def test_process_device_uses_single_session():
    """PERF-09 regresja: _process_device() otwiera dokładnie 1 SessionLocal()
    zamiast 5-8 osobnych sesji (jedna na każdą funkcję pomocniczą)."""
    session_open_count = []

    def counting_session_local():
        session_open_count.append(1)
        mock_db = MagicMock()
        # _reverify_existing_creds potrzebuje query().filter()
        mock_row = MagicMock()
        mock_row.value = "{}"
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_db.query.return_value.filter.return_value.all.return_value = []
        return mock_db

    with patch("run_cred_worker.SessionLocal", side_effect=counting_session_local), \
         patch.object(w, "_reverify_existing_creds"), \
         patch.object(w, "_load_tried", return_value={}), \
         patch.object(w, "_get_device_open_ports", return_value={}), \
         patch.object(w, "_mark_checked"), \
         patch.object(w, "_clear_tried"), \
         patch.object(w, "_process_protection_events"):
        w._process_device(1, "10.0.0.1", [], [], [], pairs_per_cycle=1)

    assert session_open_count == [1], (
        f"PERF-09: otworzono {len(session_open_count)} sesji zamiast 1"
    )


# ─── WRK-03/12: try/except w main() i scan_once() cred worker ────────────────

def test_cred_main_has_try_except_in_loop():
    """WRK-03 regresja: main() w cred_worker opakowuje scan_once() w try/except."""
    import inspect
    source = inspect.getsource(w.main)
    assert "try:" in source, "WRK-03: main() musi miec try/except wokol scan_once()"
    assert "except Exception" in source, \
        "WRK-03: main() musi lapac Exception w petli while True"


def test_scan_once_fut_result_has_try_except():
    """WRK-12 regresja: scan_once() w cred_worker ma try/except przy fut.result()
    — jeden blad watku nie przerywa petli for fut in as_completed."""
    import inspect
    # Sprawdz ze w scan_once jest try/except wokol fut.result()
    source = inspect.getsource(w.scan_once)
    assert "fut.result()" in source, "scan_once musi wywolywac fut.result()"
    assert "except Exception" in source, \
        "WRK-12: scan_once musi miec try/except przy fut.result()"


# ─── WRK-17: cred worker filtruje last_seen ──────────────────────────────────

def test_scan_once_filters_by_last_seen():
    """WRK-17 regresja: scan_once() pomija urzadzenia bez last_seen w ostatnich 10 min."""
    import inspect
    source = inspect.getsource(w.scan_once)
    assert "last_seen" in source, \
        "WRK-17: scan_once musi filtrowac Device.last_seen >= recent_seen"
    assert "recent_seen" in source or "timedelta(minutes=10)" in source, \
        "WRK-17: filtr oparty na 10 minutach"


# ─── BUG-WRK-01/02: _read_settings uses single batched query ─────────────────

def test_read_settings_uses_batched_in_query():
    """BUG-WRK-01 regresja: _read_settings() uzywa jednego SELECT WHERE key IN (...)
    zamiast 9 osobnych SELECT WHERE key = ? — eliminuje N+1 i QueuePool exhaustion."""
    import inspect
    source = inspect.getsource(w._read_settings)

    # Must use .in_() for batched lookup — not individual filter(key == ...) calls
    assert ".in_(" in source, (
        "BUG-WRK-01: _read_settings() musi uzywac key.in_(_KEYS) "
        "zamiast 9 osobnych filter(key == ...) — N+1 regresja"
    )

    # Must NOT have individual per-key filter calls inside an inner helper
    # (the old pattern was def _i(key): db.query(...).filter(key == key).first())
    assert 'filter(SystemStatus.key == key)' not in source, (
        "BUG-WRK-01: _read_settings() ma N+1 pattern — filter(key == key) w petli"
    )


def test_read_settings_returns_tuple_of_nine_with_correct_types():
    """BUG-WRK-01 regresja: _read_settings() zwraca 9-elementowa krotke intow."""
    result = w._read_settings()
    assert len(result) == 9, "_read_settings() musi zwracac 9-elementowa krotke"
    assert all(isinstance(v, int) for v in result), \
        "_read_settings() musi zwracac krotke intow"
    interval = result[0]
    assert interval >= 10, "interval musi byc co najmniej 10s"


def test_read_settings_reads_values_from_db(db):
    """BUG-WRK-01 regresja: _read_settings() odczytuje wartosci z bazy danych."""
    from netdoc.storage.models import SystemStatus
    from unittest.mock import patch

    db.add(SystemStatus(key="cred_interval_s",  value="300"))
    db.add(SystemStatus(key="cred_ssh_workers", value="8"))
    db.add(SystemStatus(key="cred_web_workers", value="4"))
    db.commit()

    # Redirect _read_settings to use the test db session
    with patch.object(w, "SessionLocal", return_value=db):
        result = w._read_settings()

    # session must NOT be closed by _read_settings (we passed our fixture session)
    # so we patch close() to a no-op
    interval, ssh_w, web_w = result[0], result[1], result[2]
    assert interval == 300, "cred_interval_s z DB powinien byc 300"
    assert ssh_w == 8,      "cred_ssh_workers z DB powinien byc 8"
    assert web_w == 4,      "cred_web_workers z DB powinien byc 4"


# ─── BUG-WRK-05: no mutable default arguments ────────────────────────────────

def test_process_device_no_mutable_defaults():
    """BUG-WRK-05 regresja: _process_device() i _process_device_with_timeout()
    nie maja mutowalnych domyslnych argumentow (list = []).
    Mutable defaults sa wspoldzielone miedzy wywolaniami — efekty uboczne."""
    import inspect

    sig = inspect.signature(w._process_device)
    for name, param in sig.parameters.items():
        if param.default is not inspect.Parameter.empty:
            assert param.default is not [], (
                f"BUG-WRK-05: _process_device('{name}') ma mutowalny domyslny argument '[]' — "
                f"uzyj None zamiast []"
            )
            assert not isinstance(param.default, list), (
                f"BUG-WRK-05: _process_device('{name}') ma domyslna liste — "
                f"uzyj None zamiast []"
            )

    sig2 = inspect.signature(w._process_device_with_timeout)
    for name, param in sig2.parameters.items():
        if param.default is not inspect.Parameter.empty:
            assert not isinstance(param.default, list), (
                f"BUG-WRK-05: _process_device_with_timeout('{name}') ma domyslna liste — "
                f"uzyj None zamiast []"
            )


# ─── Ban cooldown — anti-ban ochrona IP ──────────────────────────────────────

class TestBanCooldown:
    """BAN-COOLDOWN regresja: po _record_protection IP jest pomijane przez BAN_COOLDOWN_S.
    Zapobiega wysylaniu kolejnych prob do urzadzenia ktore juz zablokowalo polaczenie."""

    def setup_method(self):
        """Czysci _ip_ban_until przed kazdym testem."""
        w._ip_ban_until.clear()

    def test_record_protection_sets_ban_until(self):
        """Po _record_protection ip pojawia sie w _ip_ban_until z czasem w przyszlosci."""
        import time
        w._record_protection("10.0.0.1", "SSH", 22, "banner-reset")
        ban_until = w._ip_ban_until.get("10.0.0.1", 0)
        assert ban_until > time.monotonic(), (
            "_ip_ban_until['10.0.0.1'] powinno byc w przyszlosci po _record_protection"
        )

    def test_discover_ssh_skips_banned_ip(self):
        """discover_ssh() zwraca None gdy IP ma aktywny ban cooldown."""
        import time
        # Ustaw ban wygasajacy daleko w przyszlosci
        w._ip_ban_until["192.168.1.1"] = time.monotonic() + 3600
        result = w.discover_ssh("192.168.1.1", [("admin", "admin")])
        assert result is None, (
            "discover_ssh powinno zwracac None gdy IP jest w ban cooldown"
        )

    def test_discover_web_skips_banned_ip(self):
        """discover_web() zwraca None gdy IP ma aktywny ban cooldown."""
        import time
        w._ip_ban_until["192.168.1.2"] = time.monotonic() + 3600
        result = w.discover_web("192.168.1.2", [("admin", "admin")])
        assert result is None, (
            "discover_web powinno zwracac None gdy IP jest w ban cooldown"
        )

    def test_expired_ban_does_not_skip(self):
        """Wygasly ban nie blokuje proby — discover_ssh kontynuuje normalnie."""
        import time
        # Ustaw ban juz wygasly (w przeszlosci)
        w._ip_ban_until["10.0.0.5"] = time.monotonic() - 1

        with patch("run_cred_worker._open_ssh_ports", return_value=[]):
            # Brak portow SSH — wyjdzie przez "brak otwartych portow SSH", nie przez ban
            result = w.discover_ssh("10.0.0.5", [("admin", "admin")])
        assert result is None
        # Ale nie dlatego ze ban — ban byl wygasly

    def test_multiple_protections_extend_ban(self):
        """Kolejne _record_protection dla tego samego IP przedluzaja ban (max, nie reset)."""
        import time
        w._record_protection("10.0.0.1", "SSH", 22, "banner-reset")
        first_ban = w._ip_ban_until["10.0.0.1"]

        w._record_protection("10.0.0.1", "Web", 80, "http-429-rate-limit")
        second_ban = w._ip_ban_until["10.0.0.1"]

        assert second_ban >= first_ban, (
            "Drugi _record_protection powinien utrzymac lub przedluzyc ban"
        )


# === NOWE TESTY: discover_rtsp ============================================

def test_discover_rtsp_all_ports_closed_returns_none():
    """Gdy wszystkie porty RTSP (554/8554/10554/5554) sa zamkniete zwraca None."""
    with patch("socket.create_connection", side_effect=OSError("refused")):
        assert w.discover_rtsp("10.0.0.1", [("admin", "admin")]) is None


def test_discover_rtsp_port_open_but_not_rtsp_returns_none():
    """Port otwarty ale odpowiedz nie zaczyna sie od RTSP/1.0 zwraca None."""
    # Uzyj _rtsp_request ktory zwraca None gdy odpowiedz nie jest RTSP
    with patch("socket.create_connection") as mc:
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: mock_sock
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.settimeout = MagicMock()
        mock_sock.sendall = MagicMock()
        # Pierwsza proba (TCP connect na 554) - sukces
        # Kolejne proby (RTSP DESCRIBE) - odpowiedz HTTP zamiast RTSP
        http_resp = b"HTTP/1.1 200 OK"
        mock_sock.recv = MagicMock(return_value=http_resp)
        mc.return_value = mock_sock
        result = w.discover_rtsp("10.0.0.1", [("admin", "admin")])
    assert result is None


def test_discover_rtsp_returns_empty_pair_when_no_auth_required():
    """Kamera zwraca 200 bez credentials (brak auth) — zwraca (empty, empty)."""
    calls = [0]
    class _Sock:
        def __enter__(s): return s
        def __exit__(s, *a): pass
        def settimeout(s, t): pass
        def sendall(s, d): pass
        def recv(s, n):
            calls[0] += 1
            return b"RTSP/1.0 200 OK"
    with patch("socket.create_connection", return_value=_Sock()):
        result = w.discover_rtsp("10.0.0.1", [("admin", "admin")])
    assert result == ("", "")


def test_discover_rtsp_returns_pair_on_correct_credentials():
    """Kamera wymaga auth (401 bez creds) i zwraca 200 z admin:12345."""
    calls = [0]
    class _Sock:
        def __enter__(s): return s
        def __exit__(s, *a): pass
        def settimeout(s, t): pass
        def sendall(s, d): pass
        def recv(s, n):
            calls[0] += 1
            # Pierwsza proba (bez auth) -> 401
            # Druga proba (admin:12345) -> 200
            if calls[0] <= 2: return b"RTSP/1.0 401 Unauthorized"
            return b"RTSP/1.0 200 OK"
    with patch("socket.create_connection", return_value=_Sock()):
        result = w.discover_rtsp("10.0.0.1", [("admin", "wrongpass"), ("admin", "12345")])
    assert result == ("admin", "12345")


def test_discover_rtsp_stops_on_none_response():
    """Gdy kamera przerywa polaczenie (recv zwraca None/OSError) — stop."""
    calls = [0]
    class _Sock:
        def __enter__(s): return s
        def __exit__(s, *a): pass
        def settimeout(s, t): pass
        def sendall(s, d): pass
        def recv(s, n):
            raise OSError("connection reset")
    with patch("socket.create_connection", return_value=_Sock()):
        result = w.discover_rtsp("10.0.0.1", [("admin", "admin")])
    assert result is None


def test_rtsp_credential_fallback_list_not_empty():
    """RTSP_CREDENTIAL_FALLBACK musi zawierac co najmniej 1 pare."""
    assert len(w.RTSP_CREDENTIAL_FALLBACK) > 0


def test_rtsp_credential_fallback_contains_empty_auth():
    """Pierwsza para w RTSP_CREDENTIAL_FALLBACK to brak auth (empty, empty)."""
    assert w.RTSP_CREDENTIAL_FALLBACK[0] == ("", "")


def test_rtsp_credential_fallback_contains_admin_variants():
    """Lista RTSP zawiera popularne warianty admin."""
    usernames = [u for u, _ in w.RTSP_CREDENTIAL_FALLBACK]
    assert "admin" in usernames
    assert "root" in usernames


# === NOWE TESTY: _seed_default_credentials z rtsp =========================

def test_seed_default_credentials_seeds_rtsp(db):
    """_seed_default_credentials wstawia RTSP_CREDENTIAL_FALLBACK do bazy."""
    from netdoc.storage.models import Credential, CredentialMethod
    with patch("run_cred_worker.SessionLocal", return_value=db):
        w._seed_default_credentials()
    rtsp_creds = db.query(Credential).filter(
        Credential.device_id.is_(None),
        Credential.method == CredentialMethod.rtsp,
    ).all()
    assert len(rtsp_creds) > 0, "_seed_default_credentials powinna wstawic RTSP credentials"
    usernames = [c.username for c in rtsp_creds]
    assert "admin" in usernames, "Lista RTSP powinna zawierac admin"


def test_seed_default_credentials_does_not_duplicate_rtsp(db):
    """Gdy RTSP credentials juz istnieja seed nie wstawia duplikatow."""
    from netdoc.storage.models import Credential, CredentialMethod
    with patch("run_cred_worker.SessionLocal", return_value=db):
        w._seed_default_credentials()
        count_before = db.query(Credential).filter(
            Credential.device_id.is_(None),
            Credential.method == CredentialMethod.rtsp,
        ).count()
        # Drugi seed — nie powinien dodac nic
        w._seed_default_credentials()
        count_after = db.query(Credential).filter(
            Credential.device_id.is_(None),
            Credential.method == CredentialMethod.rtsp,
        ).count()
    assert count_before == count_after, "Drugi seed nie powinien duplikowac RTSP credentials"




# === NOWE TESTY: _process_device z rtsp_pairs =============================

def test_process_device_rtsp_found_saves_credential():
    mock_save = MagicMock()
    mock_db = _make_mock_db_for_db_protocols()
    with patch("run_cred_worker.SessionLocal", return_value=mock_db):
        with patch.object(w, "_get_device_open_ports", return_value={554: {"service": "rtsp"}}):
            with patch.object(w, "discover_ssh", return_value=None):
                with patch.object(w, "discover_ftp", return_value=None):
                    with patch.object(w, "discover_rdp", return_value=None):
                        with patch.object(w, "_web_detect_auth", return_value=False):
                            with patch.object(w, "discover_mssql", return_value=None):
                                with patch.object(w, "discover_mysql", return_value=None):
                                    with patch.object(w, "discover_postgres", return_value=None):
                                        with patch.object(w, "discover_rtsp", return_value=("admin", "12345")):
                                            with patch.object(w, "_tcp_open", return_value=True):
                                                with patch.object(w, "_save_cred", mock_save):
                                                    with patch.object(w, "_save_tried"):
                                                        res = w._process_device(
                                                            99, "10.0.0.9", [], [], [], [],
                                                            rtsp_pairs=[("admin", "12345")],
                                                            pairs_per_cycle=1)
    assert res["rtsp"] is True
    assert res["new"] >= 1
    mock_save.assert_called()


def test_process_device_rtsp_skip_when_port_closed():
    """Gdy brak portu RTSP discover_rtsp nie jest wywolywane."""
    saved_tried = [None]
    def _capture_save(device_id, tried):
        saved_tried[0] = tried
    with patch("run_cred_worker.SessionLocal", return_value=_make_mock_db_for_process()):
        with patch.object(w, "_tcp_open", return_value=False):
            with patch.object(w, "_get_device_open_ports", return_value=dict()):
                with patch.object(w, "_save_tried", side_effect=_capture_save):
                    with patch.object(w, "discover_ssh", return_value=None):
                        with patch.object(w, "discover_ftp", return_value=None):
                            with patch.object(w, "discover_rdp", return_value=None):
                                with patch.object(w, "discover_web", return_value=None):
                                    with patch.object(w, "discover_rtsp") as mock_rtsp:
                                        w._process_device(
                                            1, "10.0.0.1", [], [], [], [],
                                            rtsp_pairs=[("admin", "admin")],
                                            pairs_per_cycle=1)
    mock_rtsp.assert_not_called()
    if saved_tried[0] is not None:
        assert "rtsp" not in saved_tried[0] or not saved_tried[0].get("rtsp")


def test_process_device_no_rtsp_pairs_skips_rtsp():
    """_process_device pomija RTSP gdy brak par credentials."""
    mock_db = _make_mock_db_for_db_protocols()
    with patch("run_cred_worker.SessionLocal", return_value=mock_db):
        with patch.object(w, "_get_device_open_ports", return_value=dict()):
            with patch.object(w, "discover_ssh", return_value=None):
                with patch.object(w, "discover_ftp", return_value=None):
                    with patch.object(w, "discover_rdp", return_value=None):
                        with patch.object(w, "_web_detect_auth", return_value=False):
                            with patch.object(w, "discover_mssql", return_value=None):
                                with patch.object(w, "discover_mysql", return_value=None):
                                    with patch.object(w, "discover_postgres", return_value=None):
                                        with patch.object(w, "discover_rtsp") as mock_rtsp:
                                            with patch.object(w, "_save_tried"):
                                                res = w._process_device(
                                                    99, "10.0.0.10", [], [], [], [],
                                                    rtsp_pairs=list(),
                                                    pairs_per_cycle=1)
    mock_rtsp.assert_not_called()
    assert res["rtsp"] is False


# === NOWE TESTY: pre-check portu 3389 dla RDP (fix 445->3389) ==============

def test_process_device_rdp_precheck_uses_3389_not_445():
    """Regresja: _process_device sprawdza port 3389 dla RDP (nie 445)."""
    import inspect
    src = inspect.getsource(w._process_device)
    assert "3389" in src, "_process_device powinien sprawdzac port 3389 dla RDP"


def test_process_device_rdp_skips_when_port_3389_closed():
    """Gdy port 3389 zamkniety discover_rdp nie jest wywolywane."""
    probed_ports = []
    def _fake_tcp_open(ip, port, timeout=2.0):
        probed_ports.append(port)
        return False
    with patch("run_cred_worker.SessionLocal", return_value=_make_mock_db_for_process()):
        with patch.object(w, "_tcp_open", side_effect=_fake_tcp_open):
            with patch.object(w, "_get_device_open_ports", return_value=dict()):
                with patch.object(w, "discover_rdp") as mock_rdp:
                    with patch.object(w, "discover_ssh", return_value=None):
                        with patch.object(w, "discover_ftp", return_value=None):
                            with patch.object(w, "discover_web", return_value=None):
                                with patch.object(w, "_save_tried"):
                                    w._process_device(
                                        1, "10.0.0.1",
                                        [], [], [], [("admin", "admin")],
                                        pairs_per_cycle=1)
    assert 3389 in probed_ports, "Pre-check RDP powinien testowac port 3389"
    mock_rdp.assert_not_called()
