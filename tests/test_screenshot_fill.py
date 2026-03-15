"""Testy _fill_missing_screenshots — worker uzupelniajacy screenshoty w tle.

Testujemy:
- pomija urzadzenia ktore juz maja screenshot
- pomija urzadzenia bez ScanResult
- pomija urzadzenia bez HTTP-hint portow (tylko np. 22, 25)
- przetwarza kandydatow z HTTP-hint portem
- zapisuje DeviceScreenshot z poprawnym http_port i http_scheme
- zwraca liczbe wykonanych capture
- respektuje limit max_devices
- pomija urzadzenia nieaktywne (is_active=False)
- po capture urzadzenie nie jest przetwarzane ponownie (idempotentnosc)
"""
from datetime import datetime
from unittest.mock import patch, MagicMock
import pytest


# ─── helpers ──────────────────────────────────────────────────────────────────

def _make_device(db, ip="10.0.0.1", is_active=True):
    from netdoc.storage.models import Device, DeviceType
    d = Device(ip=ip, device_type=DeviceType.unknown, is_active=is_active,
               is_trusted=False, first_seen=datetime.utcnow(),
               last_seen=datetime.utcnow())
    db.add(d); db.commit(); db.refresh(d)
    return d


def _add_scan(db, device_id, ports: list, scan_type="nmap"):
    from netdoc.storage.models import ScanResult
    sr = ScanResult(
        device_id  = device_id,
        scan_type  = scan_type,
        scan_time  = datetime.utcnow(),
        open_ports = {str(p): {} for p in ports},
    )
    db.add(sr); db.commit()
    return sr


def _add_screenshot(db, device_id, ip="10.0.0.1"):
    from netdoc.storage.models import DeviceScreenshot
    s = DeviceScreenshot(
        device_id   = device_id,
        ip          = ip,
        http_port   = 443,
        http_scheme = "https",
        png_data    = b"\x89PNG",
        captured_at = datetime.utcnow(),
    )
    db.add(s); db.commit()
    return s


FAKE_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50


def _run_fill(db, max_devices=10, delay_s=0.0):
    """Uruchamia _fill_missing_screenshots z podmienioną bazą."""
    import netdoc.web.app as web_app
    with patch("netdoc.web.app.SessionLocal", return_value=db):
        return web_app._fill_missing_screenshots(max_devices=max_devices, delay_s=delay_s)


# ─── pomijanie ────────────────────────────────────────────────────────────────

def test_fill_skips_device_with_existing_screenshot(db):
    """Urzadzenie z istniejacym screenshotem jest pomijane."""
    dev = _make_device(db)
    _add_scan(db, dev.id, ports=[443])
    _add_screenshot(db, dev.id)

    with patch("netdoc.web.app._find_http_port") as mock_find:
        n = _run_fill(db)

    assert n == 0
    mock_find.assert_not_called()


def test_fill_tries_early_device_without_scan_result(db):
    """Nowe urzadzenie bez ScanResult (odkryte < 2h) jest probowane na domyslnych portach."""
    dev = _make_device(db)  # brak ScanResult, first_seen=now → early candidate

    with patch("netdoc.web.app._find_http_port", return_value=(None, None)):
        n = _run_fill(db)

    # Nie wykonano zdjecia (brak HTTP), ale proba byla podjeta
    assert n == 0


def test_fill_early_device_without_scan_captures_screenshot(db):
    """Nowe urzadzenie bez ScanResult — screenshot wykonany gdy HTTP dostepny."""
    dev = _make_device(db)  # brak ScanResult, early candidate

    with patch("netdoc.web.app._find_http_port", return_value=(80, "http")):
        with patch("netdoc.web.app._capture_screenshot", return_value=FAKE_PNG):
            n = _run_fill(db)

    assert n == 1
    from netdoc.storage.models import DeviceScreenshot
    scr = db.query(DeviceScreenshot).filter_by(device_id=dev.id).first()
    assert scr is not None
    assert scr.http_port == 80


def test_fill_skips_old_device_without_scan_result(db):
    """Stare urzadzenie bez ScanResult (odkryte > 2h temu) jest pomijane w early path."""
    from datetime import timedelta
    dev = _make_device(db)
    # Cofnij first_seen poza okno early
    dev.first_seen = datetime.utcnow() - timedelta(hours=3)
    db.commit()

    with patch("netdoc.web.app._find_http_port", return_value=(None, None)) as mock_find:
        n = _run_fill(db)

    assert n == 0
    # Jesli mock_find nie byl wywolany — stare urzadzenie zostalo pominiete
    mock_find.assert_not_called()


def test_fill_skips_device_without_http_hint_ports(db):
    """Urzadzenie z portami spoza _HTTP_HINT_PORTS (np. tylko SSH) jest pomijane."""
    dev = _make_device(db)
    _add_scan(db, dev.id, ports=[22, 23, 25])  # SSH, Telnet, SMTP — brak HTTP

    with patch("netdoc.web.app._find_http_port") as mock_find:
        n = _run_fill(db)

    assert n == 0
    mock_find.assert_not_called()


def test_fill_skips_inactive_device(db):
    """Urzadzenie nieaktywne (is_active=False) jest pomijane."""
    dev = _make_device(db, is_active=False)
    _add_scan(db, dev.id, ports=[80, 443])

    with patch("netdoc.web.app._find_http_port", return_value=(443, "https")):
        with patch("netdoc.web.app._capture_screenshot", return_value=FAKE_PNG):
            n = _run_fill(db)

    assert n == 0


def test_fill_skips_when_no_http_port_found(db):
    """_find_http_port zwraca (None, None) — capture nie jest wywolywane."""
    dev = _make_device(db)
    _add_scan(db, dev.id, ports=[80, 443])

    with patch("netdoc.web.app._find_http_port", return_value=(None, None)):
        with patch("netdoc.web.app._capture_screenshot") as mock_cap:
            n = _run_fill(db)

    assert n == 0
    mock_cap.assert_not_called()


def test_fill_skips_when_capture_fails(db):
    """_capture_screenshot zwraca None — rekord nie jest zapisywany."""
    dev = _make_device(db)
    _add_scan(db, dev.id, ports=[443])

    with patch("netdoc.web.app._find_http_port", return_value=(443, "https")):
        with patch("netdoc.web.app._capture_screenshot", return_value=None):
            n = _run_fill(db)

    assert n == 0
    from netdoc.storage.models import DeviceScreenshot
    assert db.query(DeviceScreenshot).count() == 0


# ─── poprawny capture ─────────────────────────────────────────────────────────

def test_fill_captures_device_with_http_port(db):
    """Urzadzenie z portem 443 w skanach — capture wykonany, rekord zapisany."""
    dev = _make_device(db, ip="192.168.1.10")
    dev_id = dev.id  # zapisz przed zamknieciem sesji przez fill
    _add_scan(db, dev_id, ports=[22, 443])

    with patch("netdoc.web.app._find_http_port", return_value=(443, "https")):
        with patch("netdoc.web.app._capture_screenshot", return_value=FAKE_PNG):
            n = _run_fill(db)

    assert n == 1
    from netdoc.storage.models import DeviceScreenshot
    shot = db.query(DeviceScreenshot).filter_by(device_id=dev_id).first()
    assert shot is not None
    assert shot.http_port   == 443
    assert shot.http_scheme == "https"
    assert shot.png_data    == FAKE_PNG
    assert shot.ip          == "192.168.1.10"


def test_fill_captures_device_with_8080_port(db):
    """Port 8080 (HTTP-hint) — capture wykonany."""
    dev = _make_device(db, ip="10.0.0.5")
    dev_id = dev.id
    _add_scan(db, dev_id, ports=[8080])

    with patch("netdoc.web.app._find_http_port", return_value=(8080, "https")):
        with patch("netdoc.web.app._capture_screenshot", return_value=FAKE_PNG):
            n = _run_fill(db)

    assert n == 1
    from netdoc.storage.models import DeviceScreenshot
    shot = db.query(DeviceScreenshot).filter_by(device_id=dev_id).first()
    assert shot.http_port   == 8080
    assert shot.http_scheme == "https"


def test_fill_passes_scan_ports_to_find_http_port(db):
    """Porty z ScanResult sa przekazywane jako candidate_ports do _find_http_port."""
    dev = _make_device(db)
    _add_scan(db, dev.id, ports=[22, 443, 9090])

    captured_args = {}

    def _fake_find(ip, candidate_ports=None):
        captured_args["ports"] = candidate_ports
        return (443, "https")

    with patch("netdoc.web.app._find_http_port", side_effect=_fake_find):
        with patch("netdoc.web.app._capture_screenshot", return_value=FAKE_PNG):
            _run_fill(db)

    assert set(captured_args["ports"]) == {22, 443, 9090}


def test_fill_returns_count_of_captured(db):
    """Zwraca dokladna liczbe wykonanych capture."""
    dev1 = _make_device(db, ip="10.0.0.1")
    dev2 = _make_device(db, ip="10.0.0.2")
    dev3 = _make_device(db, ip="10.0.0.3")  # brak HTTP portu
    _add_scan(db, dev1.id, ports=[443])
    _add_scan(db, dev2.id, ports=[80])
    _add_scan(db, dev3.id, ports=[22])  # brak HTTP-hint

    with patch("netdoc.web.app._find_http_port", return_value=(443, "https")):
        with patch("netdoc.web.app._capture_screenshot", return_value=FAKE_PNG):
            n = _run_fill(db)

    assert n == 2


# ─── limit max_devices ────────────────────────────────────────────────────────

def test_fill_respects_max_devices_limit(db):
    """max_devices=2 — przetwarza najwyzej 2 urzadzenia."""
    for i in range(5):
        dev = _make_device(db, ip=f"10.0.0.{i+1}")
        _add_scan(db, dev.id, ports=[443])

    with patch("netdoc.web.app._find_http_port", return_value=(443, "https")):
        with patch("netdoc.web.app._capture_screenshot", return_value=FAKE_PNG):
            n = _run_fill(db, max_devices=2)

    assert n == 2
    from netdoc.storage.models import DeviceScreenshot
    assert db.query(DeviceScreenshot).count() == 2


# ─── idempotentnosc ───────────────────────────────────────────────────────────

def test_fill_idempotent_second_run_skips_done(db):
    """Drugi przebieg nie duplikuje screenshotow."""
    dev = _make_device(db)
    _add_scan(db, dev.id, ports=[443])

    with patch("netdoc.web.app._find_http_port", return_value=(443, "https")):
        with patch("netdoc.web.app._capture_screenshot", return_value=FAKE_PNG):
            n1 = _run_fill(db)
            n2 = _run_fill(db)

    assert n1 == 1
    assert n2 == 0
    from netdoc.storage.models import DeviceScreenshot
    assert db.query(DeviceScreenshot).count() == 1


# ─── mieszane scenariusze ─────────────────────────────────────────────────────

def test_fill_mixed_devices(db):
    """Mix: jedno z screenshot, jedno bez HTTP, jedno gotowe do capture."""
    dev_done   = _make_device(db, ip="10.0.0.1")
    dev_nohttp = _make_device(db, ip="10.0.0.2")
    dev_ready  = _make_device(db, ip="10.0.0.3")

    id_done   = dev_done.id
    id_nohttp = dev_nohttp.id
    id_ready  = dev_ready.id

    _add_scan(db, id_done,   ports=[443])
    _add_scan(db, id_nohttp, ports=[22, 25])
    _add_scan(db, id_ready,  ports=[80])
    _add_screenshot(db, id_done)

    with patch("netdoc.web.app._find_http_port", return_value=(80, "http")):
        with patch("netdoc.web.app._capture_screenshot", return_value=FAKE_PNG):
            n = _run_fill(db)

    assert n == 1
    from netdoc.storage.models import DeviceScreenshot
    assert db.query(DeviceScreenshot).filter_by(device_id=id_ready).count() == 1
    assert db.query(DeviceScreenshot).filter_by(device_id=id_nohttp).count() == 0
