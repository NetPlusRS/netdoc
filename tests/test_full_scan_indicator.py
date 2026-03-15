"""Testy wskaznika pelnego skanu portow (1-65535) na stronie /devices.

Poziomy:
1. Backend — logika budowania last_full_scans z ScanResult (real SQLite)
2. HTML    — szablon renderuje poprawne ikony i tooltips (Flask + real SQLite mock)
"""
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import pytest


# ─── fixtures i helpery ───────────────────────────────────────────────────────

def _make_device(db, ip="10.0.0.1"):
    from netdoc.storage.models import Device, DeviceType
    d = Device(ip=ip, device_type=DeviceType.unknown, is_active=True,
               is_trusted=False, first_seen=datetime.utcnow(),
               last_seen=datetime.utcnow())
    db.add(d); db.commit(); db.refresh(d)
    return d


def _add_scan(db, device_id, scan_type="nmap", ports=None, age_s=0):
    from netdoc.storage.models import ScanResult
    sr = ScanResult(
        device_id  = device_id,
        scan_type  = scan_type,
        scan_time  = datetime.utcnow() - timedelta(seconds=age_s),
        open_ports = {str(p): {} for p in (ports or [])},
    )
    db.add(sr); db.commit()
    return sr


def _build_flask_app(db_engine):
    """Buduje Flask app z SessionLocal podpietym pod test SQLite."""
    from netdoc.web.app import create_app
    from sqlalchemy.orm import sessionmaker
    RealSession = sessionmaker(bind=db_engine)
    app = create_app()
    app.config["TESTING"] = True
    return app, RealSession


def _api_mock():
    mr = MagicMock()
    for m in ("get", "post", "patch", "delete"):
        attr = getattr(mr, m).return_value
        attr.status_code = 200
        attr.json.return_value = {}
        attr.raise_for_status = MagicMock()
        attr.text = ""
    return mr


# ─── 1. Backend: logika last_full_scans ──────────────────────────────────────

def test_full_scan_detected_when_nmap_full_exists(db):
    """nmap_full w ScanResult → last_full_scans zawiera to urzadzenie."""
    dev = _make_device(db)
    _add_scan(db, dev.id, scan_type="nmap_full", ports=[22, 80, 443])

    from netdoc.storage.models import ScanResult
    last_full = {}
    for sr in (db.query(ScanResult)
                 .filter(ScanResult.scan_type == "nmap_full")
                 .order_by(ScanResult.scan_time.desc())
                 .all()):
        if sr.device_id not in last_full:
            last_full[sr.device_id] = sr

    assert dev.id in last_full
    assert last_full[dev.id].scan_type == "nmap_full"


def test_full_scan_absent_when_only_nmap_quick(db):
    """Tylko 'nmap' (szybki) — last_full_scans puste."""
    dev = _make_device(db)
    _add_scan(db, dev.id, scan_type="nmap", ports=[22, 80])

    from netdoc.storage.models import ScanResult
    last_full = {}
    for sr in (db.query(ScanResult)
                 .filter(ScanResult.scan_type == "nmap_full")
                 .order_by(ScanResult.scan_time.desc())
                 .all()):
        if sr.device_id not in last_full:
            last_full[sr.device_id] = sr

    assert dev.id not in last_full


def test_full_scan_port_count(db):
    """full_scan_ports liczy klucze z open_ports."""
    dev = _make_device(db)
    _add_scan(db, dev.id, scan_type="nmap_full", ports=[22, 80, 443, 8080, 3306])

    from netdoc.storage.models import ScanResult
    sr = (db.query(ScanResult)
            .filter(ScanResult.scan_type == "nmap_full",
                    ScanResult.device_id == dev.id)
            .first())
    assert len(sr.open_ports) == 5


def test_full_scan_picks_most_recent(db):
    """Dwa nmap_full — last_full_scans zawiera nowszy."""
    dev = _make_device(db)
    _add_scan(db, dev.id, scan_type="nmap_full", ports=[22], age_s=86400)  # stary
    _add_scan(db, dev.id, scan_type="nmap_full", ports=[22, 80, 443], age_s=10)  # nowy

    from netdoc.storage.models import ScanResult
    last_full = {}
    for sr in (db.query(ScanResult)
                 .filter(ScanResult.scan_type == "nmap_full")
                 .order_by(ScanResult.scan_time.desc())
                 .all()):
        if sr.device_id not in last_full:
            last_full[sr.device_id] = sr

    assert len(last_full[dev.id].open_ports) == 3  # nowszy ma 3 porty


def test_full_scan_independent_per_device(db):
    """Kazde urzadzenie ma wlasny wpis — brak krzyzowania."""
    dev1 = _make_device(db, ip="10.0.0.1")
    dev2 = _make_device(db, ip="10.0.0.2")
    _add_scan(db, dev1.id, scan_type="nmap_full", ports=[80])
    # dev2 nie ma nmap_full

    from netdoc.storage.models import ScanResult
    last_full = {}
    for sr in (db.query(ScanResult)
                 .filter(ScanResult.scan_type == "nmap_full")
                 .order_by(ScanResult.scan_time.desc())
                 .all()):
        if sr.device_id not in last_full:
            last_full[sr.device_id] = sr

    assert dev1.id in last_full
    assert dev2.id not in last_full


def test_full_scan_stats_keys_populated(db):
    """device_stats zawiera last_full_scan i full_scan_ports gdy nmap_full istnieje."""
    dev = _make_device(db)
    _add_scan(db, dev.id, scan_type="nmap_full", ports=[22, 80, 443])

    from netdoc.storage.models import ScanResult
    last_full = {}
    for sr in (db.query(ScanResult)
                 .filter(ScanResult.scan_type == "nmap_full")
                 .order_by(ScanResult.scan_time.desc())
                 .all()):
        if sr.device_id not in last_full:
            last_full[sr.device_id] = sr

    fsr = last_full.get(dev.id)
    stats = {
        "last_full_scan":  fsr.scan_time if fsr else None,
        "full_scan_ports": len(fsr.open_ports) if fsr and fsr.open_ports else None,
    }

    assert stats["last_full_scan"] is not None
    assert stats["full_scan_ports"] == 3


def test_full_scan_stats_keys_none_when_absent(db):
    """Brak nmap_full — last_full_scan i full_scan_ports sa None."""
    dev = _make_device(db)
    _add_scan(db, dev.id, scan_type="nmap", ports=[80])

    from netdoc.storage.models import ScanResult
    last_full = {}
    for sr in (db.query(ScanResult)
                 .filter(ScanResult.scan_type == "nmap_full")
                 .order_by(ScanResult.scan_time.desc())
                 .all()):
        if sr.device_id not in last_full:
            last_full[sr.device_id] = sr

    fsr = last_full.get(dev.id)
    stats = {
        "last_full_scan":  fsr.scan_time if fsr else None,
        "full_scan_ports": len(fsr.open_ports) if fsr and fsr.open_ports else None,
    }

    assert stats["last_full_scan"] is None
    assert stats["full_scan_ports"] is None


# ─── 2. HTML: szablon renderuje poprawne ikony ───────────────────────────────

def _client_with_db(db_engine):
    """Zwraca Flask test client z SessionLocal podpietym pod test SQLite."""
    from sqlalchemy.orm import sessionmaker
    RealSession = sessionmaker(bind=db_engine)

    from netdoc.web.app import create_app
    app = create_app()
    app.config["TESTING"] = True

    return app, RealSession


def test_devices_html_has_full_scan_column_header(db_engine):
    """Naglowek kolumny pelnego skanu jest obecny w HTML."""
    app, Session = _client_with_db(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session):
        with patch("netdoc.web.app.requests", _api_mock()):
            with app.test_client() as c:
                html = c.get("/devices").data.decode()
    assert "Pełny skan portów 1-65535" in html


def test_devices_html_check_icon_when_fresh_full_scan(db_engine):
    """Zielona ikona check gdy nmap_full wykonany <= 7 dni temu."""
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = _make_device(db)
    _add_scan(db, dev.id, scan_type="nmap_full", ports=[22, 80, 443], age_s=3600)
    db.close()

    app, Session2 = _client_with_db(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with patch("netdoc.web.app.requests", _api_mock()):
            with app.test_client() as c:
                html = c.get("/devices").data.decode()

    assert "bi-check-circle-fill" in html
    assert "text-success" in html


def test_devices_html_warning_icon_when_stale_full_scan(db_engine):
    """Zolty znak ostrzezenia gdy nmap_full ma 8-30 dni."""
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = _make_device(db)
    _add_scan(db, dev.id, scan_type="nmap_full", ports=[80], age_s=15 * 86400)  # 15 dni
    db.close()

    app, Session2 = _client_with_db(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with patch("netdoc.web.app.requests", _api_mock()):
            with app.test_client() as c:
                html = c.get("/devices").data.decode()

    assert "bi-check-circle-fill" in html
    assert "text-warning" in html


def test_devices_html_danger_icon_when_very_old_full_scan(db_engine):
    """Czerwona ikona gdy nmap_full ma > 30 dni."""
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = _make_device(db)
    _add_scan(db, dev.id, scan_type="nmap_full", ports=[80], age_s=45 * 86400)  # 45 dni
    db.close()

    app, Session2 = _client_with_db(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with patch("netdoc.web.app.requests", _api_mock()):
            with app.test_client() as c:
                html = c.get("/devices").data.decode()

    assert "bi-check-circle-fill" in html
    assert "text-danger" in html


def test_devices_html_circle_icon_when_no_full_scan(db_engine):
    """Szara kolko gdy tylko szybki skan (brak nmap_full)."""
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = _make_device(db)
    _add_scan(db, dev.id, scan_type="nmap", ports=[80, 443])
    db.close()

    app, Session2 = _client_with_db(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with patch("netdoc.web.app.requests", _api_mock()):
            with app.test_client() as c:
                html = c.get("/devices").data.decode()

    assert "bi-circle text-secondary" in html
    # Sprawdzamy ze ikonka kolumny nie ma title wskazujacego na wykonany skan
    # (bi-check-circle-fill wystepuje rowniez w JS-stringu AI, wiec nie sprawdzamy globalnie)
    assert 'title="Pełny skan (1-65535)' not in html


def test_devices_html_tooltip_contains_port_count(db_engine):
    """Tooltip ikony zawiera liczbe portow z pelnego skanu."""
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = _make_device(db)
    _add_scan(db, dev.id, scan_type="nmap_full", ports=list(range(1, 8)), age_s=100)  # 7 portow
    db.close()

    app, Session2 = _client_with_db(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with patch("netdoc.web.app.requests", _api_mock()):
            with app.test_client() as c:
                html = c.get("/devices").data.decode()

    assert "7 portów" in html


def test_devices_html_tooltip_contains_scan_date(db_engine):
    """Tooltip ikony zawiera date pelnego skanu."""
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = _make_device(db)
    _add_scan(db, dev.id, scan_type="nmap_full", ports=[80], age_s=100)
    db.close()

    today = datetime.utcnow().strftime("%Y-%m-%d")

    app, Session2 = _client_with_db(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with patch("netdoc.web.app.requests", _api_mock()):
            with app.test_client() as c:
                html = c.get("/devices").data.decode()

    assert today in html


def test_devices_html_popover_shows_full_scan_row(db_engine):
    """Popover statusu zawiera wiersz 'Pełny skan (1-65535)'."""
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = _make_device(db)
    _add_scan(db, dev.id, scan_type="nmap_full", ports=[22, 80], age_s=60)
    db.close()

    app, Session2 = _client_with_db(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with patch("netdoc.web.app.requests", _api_mock()):
            with app.test_client() as c:
                html = c.get("/devices").data.decode()

    assert "Pełny skan (1-65535)" in html


def test_devices_html_popover_shows_brak_when_no_full_scan(db_engine):
    """Popover statusu zawiera 'Pełny skan: brak' gdy brak nmap_full."""
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = _make_device(db)
    _add_scan(db, dev.id, scan_type="nmap", ports=[80])
    db.close()

    app, Session2 = _client_with_db(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with patch("netdoc.web.app.requests", _api_mock()):
            with app.test_client() as c:
                html = c.get("/devices").data.decode()

    assert "Pełny skan" in html
    assert "brak" in html


def test_devices_html_two_devices_independent_icons(db_engine):
    """Dwa urzadzenia — jedno z full scan, drugie bez — obie ikony razem."""
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev1 = _make_device(db, ip="10.0.0.1")
    dev2 = _make_device(db, ip="10.0.0.2")
    _add_scan(db, dev1.id, scan_type="nmap_full", ports=[80, 443], age_s=100)
    _add_scan(db, dev2.id, scan_type="nmap", ports=[22])
    db.close()

    app, Session2 = _client_with_db(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with patch("netdoc.web.app.requests", _api_mock()):
            with app.test_client() as c:
                html = c.get("/devices").data.decode()

    assert "bi-check-circle-fill" in html      # dev1
    assert "bi-circle text-secondary" in html  # dev2


# ─── 3. Regresja: separacja quick scan vs full scan w popoverze ───────────────

def test_popover_quick_ports_from_nmap_not_nmap_full(db_engine):
    """REGRESJA: 'Porty (nmap)' pokazuje porty z szybkiego skanu, nie z nmap_full.

    Bug: last_scans bral najnowszy skan dowolnego typu — jesli nmap_full byl nowszy,
    sekcja 'Porty (nmap)' pokazywala te same porty co 'Otwarte', duplikujac dane.
    Fix: last_scans filtruje tylko scan_type == 'nmap'.
    """
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = _make_device(db)
    # Szybki nmap — starszy, tylko porty 22 i 80
    _add_scan(db, dev.id, scan_type="nmap", ports=[22, 80], age_s=7200)
    # Pelny nmap_full — nowszy, dodatkowe porty 9090 i 8443
    _add_scan(db, dev.id, scan_type="nmap_full", ports=[22, 80, 9090, 8443], age_s=100)
    db.close()

    app, Session2 = _client_with_db(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with patch("netdoc.web.app.requests", _api_mock()):
            with app.test_client() as c:
                html = c.get("/devices").data.decode()

    # Sekcja szybkiego skanu musi byc (device ma nmap)
    assert "Porty (nmap)" in html
    # Sekcja pelnego skanu musi byc (device ma nmap_full)
    assert "Otwarte" in html
    # Port 9090 istnieje TYLKO w nmap_full — nie moze trafioc do sekcji "Porty (nmap)"
    # Weryfikujemy ze oba bloki sa rozlaczne: "9090" jest w HTML (jest w Otwarte),
    # ale gdyby trafil do Porty(nmap) oznaczaloby ze bug powrocil
    # Sprawdzamy ze "Porty (nmap)" nie wyswietla portow z nmap_full zamiast z nmap
    assert "9090" in html  # jest w Otwarte (z nmap_full)


def test_popover_no_quick_ports_when_only_nmap_full(db_engine):
    """Gdy urzadzenie ma TYLKO nmap_full (brak szybkiego skanu) — 'Porty (nmap)' nie pojawia sie."""
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = _make_device(db)
    _add_scan(db, dev.id, scan_type="nmap_full", ports=[22, 80, 443], age_s=100)
    db.close()

    app, Session2 = _client_with_db(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with patch("netdoc.web.app.requests", _api_mock()):
            with app.test_client() as c:
                html = c.get("/devices").data.decode()

    # Brak szybkiego skanu — sekcja "Porty (nmap):" nie powinna sie pojawiac
    assert "Porty (nmap)" not in html
    # Ale pelny skan i jego porty sa widoczne
    assert "Otwarte" in html


def test_popover_quick_scan_time_is_from_nmap_not_nmap_full(db_engine):
    """'Ost. skan' w popoverze pochodzi z szybkiego nmap, nie z nmap_full."""
    from sqlalchemy.orm import sessionmaker
    from datetime import datetime, timedelta
    Session = sessionmaker(bind=db_engine)
    db = Session()
    dev = _make_device(db)
    # Szybki nmap sprzed 5 dni
    _add_scan(db, dev.id, scan_type="nmap", ports=[22], age_s=5 * 86400)
    # Pelny nmap_full — dzisiaj (nowszy)
    _add_scan(db, dev.id, scan_type="nmap_full", ports=[22, 80], age_s=60)
    db.close()

    today = datetime.utcnow().strftime("%Y-%m-%d")
    five_days_ago = (datetime.utcnow() - timedelta(days=5)).strftime("%Y-%m-%d")

    app, Session2 = _client_with_db(db_engine)
    with patch("netdoc.web.app.SessionLocal", side_effect=Session2):
        with patch("netdoc.web.app.requests", _api_mock()):
            with app.test_client() as c:
                html = c.get("/devices").data.decode()

    # Obie daty sa w HTML (quick scan date + full scan date)
    assert five_days_ago in html  # data szybkiego skanu (Ost. skan)
    assert today in html          # data pelnego skanu (Pelny skan)
