"""Testy endpoint-ow screenshot: GET /devices/<id>/screenshot i POST .../refresh.

Testujemy:
- cache hit  (swiezy rekord w DB — nie wywoluje playwright, nie skanuje portow)
- cache miss (brak rekordu — pobiera open_ports z ScanResult, capture, zapisuje)
- znany port (wygasly cache z http_port) — recapture bez skanowania portow
- brak portu HTTP (urzadzenie bez web — 204)
- nieznane urzadzenie (404)
- refresh    (usuwa rekord, zwraca {ok: true})
- _find_http_port: candidate_ports z DB, HTTPS priorytet, TLS detection, fallback
- _is_tls: pozytywny i negatywny
"""
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
import pytest


# ─── helpers ──────────────────────────────────────────────────────────────────

def _make_dev(id=1, ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff"):
    d = MagicMock()
    d.id = id; d.ip = ip; d.mac = mac
    return d


_VALID_PNG = b"\x89PNG\r\n" + b"X" * 6000  # > _MIN_VALID_PNG_BYTES (5000)


def _make_shot(device_id=1, png=None, age_s=0,
               http_port=443, http_scheme="https"):
    if png is None:
        png = _VALID_PNG
    s = MagicMock()
    s.device_id  = device_id
    s.png_data   = png
    s.ip         = "192.168.1.1"
    s.mac        = "aa:bb:cc:dd:ee:ff"
    s.http_port  = http_port
    s.http_scheme = http_scheme
    s.captured_at = datetime.utcnow() - timedelta(seconds=age_s)
    return s


def _make_scan(open_ports: dict | None = None):
    """Mock ScanResult z open_ports dict."""
    s = MagicMock()
    s.open_ports = open_ports
    return s


def _build_app():
    from netdoc.web.app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app


def _db_mock(dev=None, shot=None, scan=None, rtsp_vuln=None):
    """Mock SessionLocal rozrozniajacy modele po ich klasie."""
    from netdoc.storage.models import Device, DeviceScreenshot, ScanResult, Vulnerability

    db = MagicMock()
    db.__enter__ = lambda s: s
    db.__exit__  = MagicMock(return_value=False)

    def _q(model):
        q = MagicMock()
        q.filter.return_value = q
        q.filter_by.return_value = q
        q.order_by.return_value = q
        if model is Device:
            q.first.return_value = dev
        elif model is DeviceScreenshot:
            q.first.return_value = shot
        elif model is ScanResult:
            q.first.return_value = scan
        elif model is Vulnerability:
            q.first.return_value = rtsp_vuln
        else:
            q.first.return_value = None
        return q

    db.query.side_effect = _q
    return db


def _make_rtsp_vuln(vuln_type="rtsp_noauth", port=554, evidence=None):
    from netdoc.storage.models import VulnType
    v = MagicMock()
    v.device_id = 1
    v.port = port
    v.evidence = evidence
    v.vuln_type = VulnType.rtsp_noauth if vuln_type == "rtsp_noauth" else VulnType.rtsp_weak_creds
    return v


def _make_socket_class(open_ports: set):
    class FakeSock:
        def __init__(self, *a, **kw): pass
        def settimeout(self, t): pass
        def close(self): pass
        def connect(self, addr):
            if addr[1] not in open_ports:
                raise OSError("Connection refused")
    return FakeSock


def _patch_tcp_open(open_ports: set):
    """Patchuje _tcp_open i _is_tls (brak TLS) w netdoc.web.app."""
    import contextlib
    from unittest.mock import patch as _patch

    @contextlib.contextmanager
    def _ctx():
        with _patch("netdoc.web.app._tcp_open",
                    side_effect=lambda ip, port: port in open_ports):
            with _patch("netdoc.web.app._is_tls", return_value=False):
                yield

    return _ctx()


def _patch_tcp_with_tls(open_ports: set, tls_ports: set):
    """Patchuje _tcp_open i _is_tls (TLS na tls_ports) w netdoc.web.app."""
    import contextlib
    from unittest.mock import patch as _patch

    @contextlib.contextmanager
    def _ctx():
        with _patch("netdoc.web.app._tcp_open",
                    side_effect=lambda ip, port: port in open_ports):
            with _patch("netdoc.web.app._is_tls",
                        side_effect=lambda ip, port: port in tls_ports):
                yield

    return _ctx()


# ─── GET /devices/<id>/screenshot — cache hit ────────────────────────────────

def test_screenshot_cache_hit_returns_png():
    """Swiezy rekord w DB — zwraca PNG bez skanowania portow ani playwright."""
    app  = _build_app()
    dev  = _make_dev()
    shot = _make_shot(age_s=100)
    db   = _db_mock(dev=dev, shot=shot)

    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with patch("netdoc.web.app._capture_screenshot") as mock_cap:
            with patch("netdoc.web.app._find_http_port") as mock_find:
                with app.test_client() as c:
                    resp = c.get("/devices/1/screenshot")

    assert resp.status_code == 200
    assert resp.content_type == "image/png"
    assert resp.data == shot.png_data
    mock_cap.assert_not_called()
    mock_find.assert_not_called()


def test_screenshot_cache_hit_sets_age_header():
    app  = _build_app()
    dev  = _make_dev()
    shot = _make_shot(age_s=3600)
    db   = _db_mock(dev=dev, shot=shot)

    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with app.test_client() as c:
            resp = c.get("/devices/1/screenshot")

    assert "X-Screenshot-Age" in resp.headers
    age = int(resp.headers["X-Screenshot-Age"])
    assert 3590 <= age <= 3620


# ─── GET — expired cache z zapisanym portem ──────────────────────────────────

def test_screenshot_expired_uses_cached_port_no_port_scan():
    """Wygasly cache z http_port — recapture bez skanowania portow."""
    app      = _build_app()
    dev      = _make_dev()
    old_shot = _make_shot(age_s=90000, http_port=443, http_scheme="https")
    fresh    = b"\x89PNG" + b"\xff" * 50
    db       = _db_mock(dev=dev, shot=old_shot)

    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with patch("netdoc.web.app._find_http_port") as mock_find:
            with patch("netdoc.web.app._capture_screenshot", return_value=fresh) as mock_cap:
                with app.test_client() as c:
                    resp = c.get("/devices/1/screenshot")

    assert resp.status_code == 200
    assert resp.data == fresh
    # Port NIE byl skanowany — uzyto zapisanego
    mock_find.assert_not_called()
    mock_cap.assert_called_once_with(dev.ip, 443, "https")


def test_screenshot_expired_cached_port_missing_scheme_probes_tls():
    """Wygasly cache z http_port ale bez http_scheme — probe TLS na jednym porcie."""
    app      = _build_app()
    dev      = _make_dev()
    old_shot = _make_shot(age_s=90000, http_port=8080, http_scheme=None)
    fresh    = b"\x89PNG" + b"\xee" * 50
    db       = _db_mock(dev=dev, shot=old_shot)

    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with patch("netdoc.web.app._is_tls", return_value=True) as mock_tls:
            with patch("netdoc.web.app._capture_screenshot", return_value=fresh):
                with app.test_client() as c:
                    resp = c.get("/devices/1/screenshot")

    assert resp.status_code == 200
    mock_tls.assert_called_once_with(dev.ip, 8080)


# ─── GET — brak cache, odkrycie portu z ScanResult ──────────────────────────

def test_screenshot_no_cache_uses_scan_result_ports():
    """Brak screenshota — open_ports z ScanResult uzyte jako candidate_ports."""
    app      = _build_app()
    dev      = _make_dev()
    scan     = _make_scan(open_ports={"9090": {}, "443": {}})
    fake_png = b"\x89PNG" + b"\x00" * 80
    db       = _db_mock(dev=dev, shot=None, scan=scan)

    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with patch("netdoc.web.app._find_http_port",
                   return_value=(443, "https")) as mock_find:
            with patch("netdoc.web.app._capture_screenshot", return_value=fake_png):
                with app.test_client() as c:
                    resp = c.get("/devices/1/screenshot")

    assert resp.status_code == 200
    # Kandidaci z ScanResult (kolejnosc nieokreslona — sprawdzamy ze zostaly przekazane)
    called_ports = mock_find.call_args[0][1]  # drugi argument: candidate_ports
    assert set(called_ports) == {9090, 443}


def test_screenshot_no_cache_no_scan_result_uses_default_list():
    """Brak screenshota i brak ScanResult — uzywa _DEFAULT_PORT_ORDER."""
    app      = _build_app()
    dev      = _make_dev()
    fake_png = b"\x89PNG"
    db       = _db_mock(dev=dev, shot=None, scan=None)

    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with patch("netdoc.web.app._find_http_port",
                   return_value=(80, "http")) as mock_find:
            with patch("netdoc.web.app._capture_screenshot", return_value=fake_png):
                with app.test_client() as c:
                    c.get("/devices/1/screenshot")

    # candidate_ports powinien byc None (uzycie listy domyslnej)
    called_ports = mock_find.call_args[0][1]
    assert called_ports is None


def test_screenshot_saves_http_scheme_to_db():
    """Po capture — http_scheme jest zapisywany w DeviceScreenshot."""
    app      = _build_app()
    dev      = _make_dev()
    fake_png = b"\x89PNG"
    db       = _db_mock(dev=dev, shot=None, scan=None)

    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with patch("netdoc.web.app._find_http_port", return_value=(8080, "https")):
            with patch("netdoc.web.app._capture_screenshot", return_value=fake_png):
                with app.test_client() as c:
                    c.get("/devices/1/screenshot")

    added = db.add.call_args[0][0]
    assert added.http_port   == 8080
    assert added.http_scheme == "https"


# ─── GET — nieznane urzadzenie ───────────────────────────────────────────────

def test_screenshot_unknown_device_returns_404():
    app = _build_app()
    db  = _db_mock(dev=None, shot=None)
    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with app.test_client() as c:
            resp = c.get("/devices/999/screenshot")
    assert resp.status_code == 404


# ─── GET — brak portu HTTP ───────────────────────────────────────────────────

def test_screenshot_no_http_port_returns_204():
    app = _build_app()
    dev = _make_dev()
    db  = _db_mock(dev=dev, shot=None, scan=None)
    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with patch("netdoc.web.app._find_http_port", return_value=(None, None)):
            with app.test_client() as c:
                resp = c.get("/devices/1/screenshot")
    assert resp.status_code == 204


# ─── GET — capture failure ───────────────────────────────────────────────────

def test_screenshot_capture_failure_returns_204():
    """Gdy capture HTTP i RTSP nie powiedzie sie, endpoint zwraca 204.
    JS traktuje 204 tak samo jak 404 (cache 'none', tooltip ukryty).
    Zwracanie 500 byloby bledne — nie ma serwera ktory odpowiada, to normalny stan.
    """
    app = _build_app()
    dev = _make_dev()
    db  = _db_mock(dev=dev, shot=None, scan=None)
    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with patch("netdoc.web.app._find_http_port", return_value=(80, "http")):
            with patch("netdoc.web.app._capture_screenshot", return_value=None):
                with patch("netdoc.web.app._capture_rtsp_frame", return_value=None):
                    with app.test_client() as c:
                        resp = c.get("/devices/1/screenshot")
    assert resp.status_code == 204


# ─── POST /devices/<id>/screenshot/refresh ───────────────────────────────────

def test_screenshot_refresh_deletes_record():
    app  = _build_app()
    shot = _make_shot()
    db   = MagicMock()
    db.__enter__ = lambda s: s
    db.__exit__  = MagicMock(return_value=False)
    q = MagicMock(); q.filter.return_value = q; q.first.return_value = shot
    db.query.return_value = q

    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with app.test_client() as c:
            resp = c.post("/devices/1/screenshot/refresh")

    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True}
    db.delete.assert_called_once_with(shot)
    db.commit.assert_called_once()


def test_screenshot_refresh_no_record_still_ok():
    app = _build_app()
    db  = MagicMock()
    db.__enter__ = lambda s: s
    db.__exit__  = MagicMock(return_value=False)
    q = MagicMock(); q.filter.return_value = q; q.first.return_value = None
    db.query.return_value = q

    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with app.test_client() as c:
            resp = c.post("/devices/1/screenshot/refresh")

    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True}
    db.delete.assert_not_called()


# ─── _find_http_port — testy jednostkowe ─────────────────────────────────────

def test_find_http_port_https_priority_over_http():
    """443 i 80 oba otwarte — zwraca (443, 'https')."""
    import netdoc.web.app as web_app
    with _patch_tcp_open({443, 80}):
        port, scheme = web_app._find_http_port("192.168.1.1")
    assert (port, scheme) == (443, "https")


def test_find_http_port_http_fallback():
    """Tylko 80 — zwraca (80, 'http')."""
    import netdoc.web.app as web_app
    with _patch_tcp_open({80}):
        port, scheme = web_app._find_http_port("192.168.1.1")
    assert (port, scheme) == (80, "http")


def test_find_http_port_8443_before_ambiguous():
    """8443 i 8080 oba otwarte — 8443 (znany HTTPS) przed 8080."""
    import netdoc.web.app as web_app
    with _patch_tcp_open({8443, 8080}):
        port, scheme = web_app._find_http_port("192.168.1.1")
    assert (port, scheme) == (8443, "https")


def test_find_http_port_none_when_all_closed():
    import netdoc.web.app as web_app
    with _patch_tcp_open(set()):
        port, scheme = web_app._find_http_port("10.0.0.1")
    assert (port, scheme) == (None, None)


def test_find_http_port_8080_http_when_no_tls():
    """8080 bez TLS — http."""
    import netdoc.web.app as web_app
    with _patch_tcp_open({8080}):
        port, scheme = web_app._find_http_port("10.0.0.2")
    assert (port, scheme) == (8080, "http")


def test_find_http_port_8080_https_when_tls():
    """8080 z TLS — https (jak 192.168.5.144:8080)."""
    import netdoc.web.app as web_app
    with _patch_tcp_with_tls(open_ports={8080}, tls_ports={8080}):
        port, scheme = web_app._find_http_port("192.168.5.144")
    assert (port, scheme) == (8080, "https")


def test_find_http_port_candidate_ports_from_db():
    """candidate_ports z DB — skanuje tylko te porty (nie domyslna liste)."""
    import netdoc.web.app as web_app
    # Tylko port 9090 otwarty (nie ma w domyslnej liscie)
    with _patch_tcp_with_tls(open_ports={9090}, tls_ports={9090}):
        port, scheme = web_app._find_http_port("10.0.0.5", candidate_ports=[9090, 7000])
    assert (port, scheme) == (9090, "https")


def test_find_http_port_candidate_ports_none_uses_default():
    """candidate_ports=None — uzywa _DEFAULT_PORT_ORDER."""
    import netdoc.web.app as web_app
    # 443 jest w liscie domyslnej
    with _patch_tcp_open({443}):
        port, scheme = web_app._find_http_port("10.0.0.6", candidate_ports=None)
    assert (port, scheme) == (443, "https")


def test_find_http_port_all_candidates_closed():
    """Wszystkie candidate_ports niedostepne — (None, None)."""
    import netdoc.web.app as web_app
    with _patch_tcp_open(set()):
        port, scheme = web_app._find_http_port("10.0.0.7", candidate_ports=[9090, 5000, 3000])
    assert (port, scheme) == (None, None)


def test_find_http_port_filters_non_http_ports():
    """candidate_ports zawierajace SSH(22)/Telnet(23) sa ignorowane.

    Regresja: Dahua kamera z portami [23, 80] dostawala screenshot
    z portu 23 (Telnet) zamiast 80 (HTTP) — wynikalo z braku filtrowania.
    """
    import netdoc.web.app as web_app
    # Porty 22 (SSH) i 23 (Telnet) otwarte + port 80 (HTTP)
    with _patch_tcp_open({22, 23, 80}):
        port, scheme = web_app._find_http_port("192.168.5.200", candidate_ports=[23, 22, 80])
    # Powinno wybrać 80 (HTTP), nie 23 (Telnet)
    assert port == 80
    assert scheme == "http"


def test_find_http_port_non_http_only_fallback_to_default():
    """Gdy candidate_ports zawiera wylacznie nie-HTTP porty, uzywa _DEFAULT_PORT_ORDER."""
    import netdoc.web.app as web_app
    # Tylko SSH i Telnet w scan results, ale port 443 otwarty (domyslna lista)
    with _patch_tcp_open({22, 23, 443}):
        port, scheme = web_app._find_http_port("10.0.0.8", candidate_ports=[22, 23])
    # Fallback do _DEFAULT_PORT_ORDER — 443 jest na liscie
    assert port == 443
    assert scheme == "https"


def test_find_http_port_mixed_hint_and_non_hint():
    """candidate_ports z mieszanina — tylko HTTP-hint porty sa uzywane."""
    import netdoc.web.app as web_app
    # 22, 23, 25 — nie HTTP; 8080 — HTTP hint
    with _patch_tcp_open({22, 23, 25, 8080}), \
         patch("netdoc.web.app._is_tls", return_value=False):
        port, scheme = web_app._find_http_port("10.0.0.9", candidate_ports=[22, 23, 25, 8080])
    assert port == 8080
    assert scheme == "http"


# ── Testy: walidacja fałszywych screenshotów (MIN_VALID_PNG_BYTES) ─────────────

def test_cache_hit_small_png_deleted_returns_204():
    """Jezeli przechowywany PNG jest za maly (< 5KB) — zostaje usuniety, endpoint 204.
    Nowy bug: Google Chrome error page lub biala strona moze byc mala. Po usunieciu
    rekord znika z DB i IP traci dashed underline przy nastepnym odswiezeniu strony.
    """
    app = _build_app()
    dev = _make_dev()
    # Maly PNG (< _MIN_VALID_PNG_BYTES = 5000)
    small_png = b"\x89PNG\r\n" + b"X" * 100
    shot = _make_shot(png=small_png, age_s=10)  # swiezy cache
    db  = _db_mock(dev=dev, shot=shot)
    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with _build_app().test_client():
            pass  # only need app built
    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with app.test_client() as c:
            resp = c.get("/devices/1/screenshot")
    assert resp.status_code == 204
    db.delete.assert_called_once_with(shot)


def test_cache_hit_valid_png_returns_200():
    """Przechowywany PNG >= 5KB — serwowany bez ponownego capture."""
    app = _build_app()
    dev = _make_dev()
    shot = _make_shot(png=_VALID_PNG, age_s=10)
    db  = _db_mock(dev=dev, shot=shot)
    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with app.test_client() as c:
            resp = c.get("/devices/1/screenshot")
    assert resp.status_code == 200
    assert resp.data == _VALID_PNG


def test_cache_hit_returns_screenshot_source_header():
    """Endpoint zwraca naglowek X-Screenshot-Source z wartoscia schematu."""
    app = _build_app()
    dev = _make_dev()
    shot = _make_shot(png=_VALID_PNG, age_s=10, http_scheme="https", http_port=443)
    db  = _db_mock(dev=dev, shot=shot)
    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with app.test_client() as c:
            resp = c.get("/devices/1/screenshot")
    assert resp.status_code == 200
    assert resp.headers.get("X-Screenshot-Source") == "https"
    assert resp.headers.get("X-Screenshot-Port") == "443"


def test_rtsp_cached_screenshot_returns_rtsp_source_header():
    """Screenshot z RTSP ma X-Screenshot-Source: rtsp."""
    app = _build_app()
    dev = _make_dev()
    shot = _make_shot(png=_VALID_PNG, age_s=10, http_scheme="rtsp", http_port=554)
    db  = _db_mock(dev=dev, shot=shot)
    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with app.test_client() as c:
            resp = c.get("/devices/1/screenshot")
    assert resp.status_code == 200
    assert resp.headers.get("X-Screenshot-Source") == "rtsp"
    assert resp.headers.get("X-Screenshot-Port") == "554"


# ── Testy: RTSP fallback w device_screenshot endpoint ─────────────────────────

def test_rtsp_fallback_used_when_http_capture_fails():
    """Gdy HTTP capture zwraca None a urzadzenie ma rtsp_noauth — probuje RTSP."""
    app = _build_app()
    dev = _make_dev()
    rtsp_vuln = _make_rtsp_vuln("rtsp_noauth", port=554)
    db  = _db_mock(dev=dev, shot=None, scan=None, rtsp_vuln=rtsp_vuln)
    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with patch("netdoc.web.app._find_http_port", return_value=(None, None)):
            with patch("netdoc.web.app._capture_rtsp_frame", return_value=_VALID_PNG) as mock_rtsp:
                with app.test_client() as c:
                    resp = c.get("/devices/1/screenshot")
    assert resp.status_code == 200
    mock_rtsp.assert_called_once()
    assert resp.headers.get("X-Screenshot-Source") == "rtsp"


def test_rtsp_fallback_not_used_when_no_vuln():
    """Gdy brak RTSP vuln — RTSP nie jest probowane."""
    app = _build_app()
    dev = _make_dev()
    db  = _db_mock(dev=dev, shot=None, scan=None, rtsp_vuln=None)
    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with patch("netdoc.web.app._find_http_port", return_value=(None, None)):
            with patch("netdoc.web.app._capture_rtsp_frame") as mock_rtsp:
                with app.test_client() as c:
                    resp = c.get("/devices/1/screenshot")
    assert resp.status_code == 204
    mock_rtsp.assert_not_called()


def test_rtsp_weak_creds_parses_username_from_evidence():
    """Dla rtsp_weak_creds: username jest parsowany z pola evidence."""
    app = _build_app()
    dev = _make_dev()
    rtsp_vuln = _make_rtsp_vuln("rtsp_weak_creds", port=554,
                                 evidence="DESCRIBE Basic auth user='admin' pwd=*** -> 200 OK")
    db  = _db_mock(dev=dev, shot=None, scan=None, rtsp_vuln=rtsp_vuln)
    captured_args = {}

    def _fake_rtsp(ip, port, username=None, password=None):
        captured_args["username"] = username
        return _VALID_PNG

    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with patch("netdoc.web.app._find_http_port", return_value=(None, None)):
            with patch("netdoc.web.app._capture_rtsp_frame", side_effect=_fake_rtsp):
                with app.test_client() as c:
                    c.get("/devices/1/screenshot")
    assert captured_args.get("username") == "admin"


def test_rtsp_fallback_used_after_http_capture_fails():
    """Gdy HTTP port znaleziony ale capture zwraca None — RTSP jest probowane."""
    app = _build_app()
    dev = _make_dev()
    rtsp_vuln = _make_rtsp_vuln("rtsp_noauth", port=554)
    db  = _db_mock(dev=dev, shot=None, scan=None, rtsp_vuln=rtsp_vuln)
    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with patch("netdoc.web.app._find_http_port", return_value=(80, "http")):
            with patch("netdoc.web.app._capture_screenshot", return_value=None):
                with patch("netdoc.web.app._capture_rtsp_frame", return_value=_VALID_PNG) as mock_rtsp:
                    with app.test_client() as c:
                        resp = c.get("/devices/1/screenshot")
    assert resp.status_code == 200
    mock_rtsp.assert_called_once()


# ── Testy: _capture_screenshot — walidacja URL i rozmiaru PNG ─────────────────

import sys
import types as _types


def _inject_playwright_mock(page_url="http://192.168.1.1/", screenshot_data=None,
                             goto_raises=None):
    """Wstrzykuje falszywy modul playwright do sys.modules, zwraca kontekst manager
    ktory przywraca stan po wyjsciu.
    Umozliwia testowanie _capture_screenshot bez zainstalowanego Playwright.
    """
    from contextlib import contextmanager

    @contextmanager
    def _ctx():
        # Zbuduj fake strone
        _scr_data = screenshot_data or b""
        _url = page_url
        _goto_raises = goto_raises

        class FakePage:
            def goto(self, url, **kw):
                if _goto_raises:
                    raise _goto_raises
            def wait_for_load_state(self, state, **kw): pass
            def wait_for_selector(self, sel, **kw): pass
            def wait_for_timeout(self, ms): pass
            @property
            def url(self): return _url
            def screenshot(self, **kw): return _scr_data

        class FakeCtx:
            def new_page(self): return FakePage()

        class FakeBrowser:
            def new_context(self, **kw): return FakeCtx()
            def close(self): pass

        class FakePW:
            chromium = MagicMock()
            def __enter__(self): return self
            def __exit__(self, *a): pass

        FakePW.chromium.launch.return_value = FakeBrowser()

        def _fake_sync_playwright():
            return FakePW()

        fake_mod = _types.ModuleType("playwright.sync_api")
        fake_mod.sync_playwright = _fake_sync_playwright
        fake_playwright = _types.ModuleType("playwright")

        orig = {k: sys.modules.get(k) for k in ("playwright", "playwright.sync_api")}
        sys.modules["playwright"] = fake_playwright
        sys.modules["playwright.sync_api"] = fake_mod
        try:
            yield
        finally:
            for k, v in orig.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v

    return _ctx()


def test_capture_screenshot_returns_none_for_small_png():
    """_capture_screenshot zwraca None jesli PNG < _MIN_VALID_PNG_BYTES."""
    import netdoc.web.app as _app
    tiny_png = b"\x89PNG" + b"X" * 100
    with _inject_playwright_mock(screenshot_data=tiny_png):
        result = _app._capture_screenshot("192.168.1.1", 80, "http")
    assert result is None


def test_capture_screenshot_returns_none_for_chrome_error_url():
    """_capture_screenshot zwraca None gdy page.url to chrome-error://."""
    import netdoc.web.app as _app
    large_but_error = b"\x89PNG" + b"X" * 8000
    with _inject_playwright_mock(page_url="chrome-error://chromewebdata",
                                  screenshot_data=large_but_error,
                                  goto_raises=Exception("ERR_CONNECTION_REFUSED")):
        result = _app._capture_screenshot("192.168.1.1", 80, "http")
    assert result is None


def test_capture_screenshot_returns_valid_png():
    """_capture_screenshot zwraca PNG gdy strona sie zaladowala poprawnie."""
    import netdoc.web.app as _app
    large_png = b"\x89PNG\r\n" + b"A" * 10000
    with _inject_playwright_mock(screenshot_data=large_png):
        result = _app._capture_screenshot("192.168.1.1", 80, "http")
    assert result == large_png


# ── Testy: _capture_rtsp_frame ────────────────────────────────────────────────

def test_capture_rtsp_frame_returns_none_when_ffmpeg_missing():
    """Gdy ffmpeg nie jest zainstalowany (FileNotFoundError) — zwraca None bez wyjatku."""
    import netdoc.web.app as _app
    with patch("subprocess.run", side_effect=FileNotFoundError("ffmpeg not found")):
        result = _app._capture_rtsp_frame("192.168.1.100")
    assert result is None


def test_capture_rtsp_frame_returns_none_on_timeout():
    """Gdy ffmpeg timeout — zwraca None."""
    import subprocess
    import netdoc.web.app as _app
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["ffmpeg"], 10)):
        result = _app._capture_rtsp_frame("192.168.1.100")
    assert result is None


def test_capture_rtsp_frame_returns_none_when_output_too_small():
    """Gdy ffmpeg tworzy plik za maly (< _MIN_VALID_PNG_BYTES) — zwraca None."""
    import os
    import netdoc.web.app as _app

    def _fake_run(cmd, **kw):
        # Znajdz tmpfile w cmd (ostatni argument przed -y)
        for i, arg in enumerate(cmd):
            if arg == "-y" and i > 0:
                tmpfile = cmd[i - 1]
                with open(tmpfile, "wb") as f:
                    f.write(b"\x89PNG" + b"X" * 100)  # Za maly
        return MagicMock()

    with patch("subprocess.run", side_effect=_fake_run):
        result = _app._capture_rtsp_frame("192.168.1.100")
    assert result is None


def test_capture_rtsp_frame_returns_png_on_success():
    """Gdy ffmpeg tworzy poprawny PNG — zwraca bytes."""
    import netdoc.web.app as _app
    valid_data = b"\x89PNG\r\n" + b"B" * 8000

    def _fake_run(cmd, **kw):
        # Zapisz dane do tmpfile
        for i, arg in enumerate(cmd):
            if arg == "-y" and i > 0:
                tmpfile = cmd[i - 1]
                with open(tmpfile, "wb") as f:
                    f.write(valid_data)
        return MagicMock()

    with patch("subprocess.run", side_effect=_fake_run):
        result = _app._capture_rtsp_frame("192.168.1.100", port=554)
    assert result == valid_data


def test_capture_rtsp_frame_builds_rtsp_url_with_credentials():
    """Gdy podano username/password, URL zawiera te dane."""
    import netdoc.web.app as _app
    called_urls = []

    def _fake_run(cmd, **kw):
        # Znajdz URL w komendzie (po -i)
        for i, arg in enumerate(cmd):
            if arg == "-i" and i + 1 < len(cmd):
                called_urls.append(cmd[i + 1])
        return MagicMock()

    with patch("subprocess.run", side_effect=_fake_run):
        _app._capture_rtsp_frame("192.168.5.100", port=554, username="admin", password="1234")

    # Przynajmniej jedna proba powinna zawierac credentials w URL
    assert any("admin:1234@" in url for url in called_urls)


def test_capture_rtsp_frame_tries_multiple_paths():
    """_capture_rtsp_frame probuje wiele sciezek RTSP zanim sie podda."""
    import netdoc.web.app as _app
    call_count = [0]

    def _fake_run(cmd, **kw):
        call_count[0] += 1
        return MagicMock()  # nie tworzy pliku — zawsze nieudana proba

    with patch("subprocess.run", side_effect=_fake_run):
        result = _app._capture_rtsp_frame("192.168.5.100")

    assert result is None
    # Powinna byc proba dla kazdej sciezki z _RTSP_PATHS
    assert call_count[0] >= len(_app._RTSP_PATHS)


# ── Testy: scan_progress w /api/status ────────────────────────────────────────

def test_api_status_returns_scan_progress():
    """GET /api/status zwraca scan_progress i scanning_ips."""
    app = _build_app()
    from netdoc.storage.models import SystemStatus, Device
    from unittest.mock import MagicMock

    db = MagicMock()
    db.__enter__ = lambda s: s
    db.__exit__  = MagicMock(return_value=False)

    status_data = {
        "scanner_job": "full scan (5 urzadzen)",
        "scan_progress": "3/5 batchy",
        "scanning_ips": "10.0.0.1,10.0.0.2",
    }

    def _q(model):
        q = MagicMock()
        if model is SystemStatus:
            rows = [MagicMock(key=k, value=v) for k, v in status_data.items()]
            q.all.return_value = rows
        elif model is Device:
            q.count.return_value = 5
            q.filter.return_value = q
        else:
            q.all.return_value = []
            q.count.return_value = 0
        return q

    db.query.side_effect = _q

    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with app.test_client() as c:
            resp = c.get("/api/status")

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["scan_progress"] == "3/5 batchy"
    assert data["scanning_ips"] == "10.0.0.1,10.0.0.2"


def test_api_status_scan_progress_empty_when_idle():
    """GET /api/status zwraca puste scan_progress gdy skaner idle."""
    app = _build_app()
    from netdoc.storage.models import SystemStatus, Device

    db = MagicMock()
    db.__enter__ = lambda s: s
    db.__exit__  = MagicMock(return_value=False)

    status_data = {"scanner_job": "-"}

    def _q(model):
        q = MagicMock()
        if model is SystemStatus:
            rows = [MagicMock(key=k, value=v) for k, v in status_data.items()]
            q.all.return_value = rows
        elif model is Device:
            q.count.return_value = 3
            q.filter.return_value = q
        else:
            q.all.return_value = []
            q.count.return_value = 0
        return q

    db.query.side_effect = _q

    with patch("netdoc.web.app.SessionLocal", return_value=db):
        with app.test_client() as c:
            resp = c.get("/api/status")

    data = resp.get_json()
    assert data.get("scan_progress", "") == ""
    assert data.get("scanning_ips", "") == ""
