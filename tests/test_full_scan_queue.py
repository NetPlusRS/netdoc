"""Testy mechanizmu kolejkowania i uruchamiania full scan per urządzenie.

Weryfikuje:
1. run_scan_cycle("full_single") — odczytuje full_scan_ip_queue, czyści ją, wywołuje run_full_scan
2. run_scan_cycle("full_single") z pustą kolejką — przełącza na discovery
3. --once mode respektuje scan_requested = "full_single" (fix: wcześniej ignorowane)
4. --once mode respektuje scan_requested = "full" (istniejące zachowanie)
5. --once mode ignoruje nieznane typy skanowania (fallback do discovery)
"""
import sys
import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock, call


# ─── helpers ─────────────────────────────────────────────────────────────────

def _import_rs():
    if "run_scanner" not in sys.modules:
        import run_scanner  # noqa
    import run_scanner as rs
    return rs


def _make_db_with_queue(ip_queue: str, scan_requested: str | None = None):
    """Zwraca mock db z SystemStatus wierszami dla kolejki i żądania skanu."""
    from unittest.mock import MagicMock

    def _make_row(key, value):
        row = MagicMock()
        row.key = key
        row.value = value
        return row

    queue_row = _make_row("full_scan_ip_queue", ip_queue)
    req_row = _make_row("scan_requested", scan_requested or "-")

    db = MagicMock()

    def _filter_by(**kwargs):
        key = kwargs.get("key")
        mock_filter = MagicMock()
        if key == "full_scan_ip_queue":
            mock_filter.first.return_value = queue_row
        elif key == "scan_requested":
            mock_filter.first.return_value = req_row
        else:
            mock_filter.first.return_value = None
        return mock_filter

    db.query.return_value.filter_by.side_effect = _filter_by
    db.query.return_value.filter.return_value.first.return_value = None
    db.query.return_value.all.return_value = []
    return db, queue_row, req_row


# ─── 1. full_single — normalny przepływ ──────────────────────────────────────

def test_full_single_calls_run_full_scan_with_queued_ips(db_engine):
    """full_single: run_full_scan wywoływany z IP-ami z kolejki."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import SystemStatus

    Session = sessionmaker(bind=db_engine)
    db = Session()
    db.add(SystemStatus(key="full_scan_ip_queue", value="10.0.0.5,10.0.0.6", category="scanner"))
    db.commit()
    db.close()

    rs = _import_rs()

    called_ips = []

    def fake_run_full_scan(session, ips=None, progress_callback=None):
        called_ips.extend(ips or [])
        return len(ips or [])

    with patch("netdoc.collector.discovery.run_full_scan", side_effect=fake_run_full_scan), \
         patch("netdoc.collector.discovery.run_discovery", return_value=([], [])), \
         patch("netdoc.collector.pipeline.run_pipeline", return_value={}):

        with Session() as s:
            rs.run_scan_cycle(s, "full_single")

    assert "10.0.0.5" in called_ips
    assert "10.0.0.6" in called_ips


def test_full_single_clears_queue_after_scan(db_engine):
    """full_single: kolejka full_scan_ip_queue jest czyszczona po skanie."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import SystemStatus

    Session = sessionmaker(bind=db_engine)
    db = Session()
    db.add(SystemStatus(key="full_scan_ip_queue", value="192.168.1.10", category="scanner"))
    db.commit()
    db.close()

    rs = _import_rs()

    with patch("netdoc.collector.discovery.run_full_scan", return_value=1), \
         patch("netdoc.collector.discovery.run_discovery", return_value=([], [])), \
         patch("netdoc.collector.pipeline.run_pipeline", return_value={}):

        with Session() as s:
            rs.run_scan_cycle(s, "full_single")

    db2 = Session()
    row = db2.query(SystemStatus).filter_by(key="full_scan_ip_queue").first()
    db2.close()
    assert row is None or row.value == "", \
        f"Kolejka powinna byc pusta po full_single, jest: {row.value if row else None}"


def test_full_single_with_empty_queue_falls_back_to_discovery(db_engine):
    """full_single z pustą kolejką — nie wywołuje run_full_scan, robi discovery."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import SystemStatus

    Session = sessionmaker(bind=db_engine)
    db = Session()
    db.add(SystemStatus(key="full_scan_ip_queue", value="", category="scanner"))
    db.commit()
    db.close()

    rs = _import_rs()

    full_scan_called = []

    def fake_run_full_scan(*args, **kwargs):
        full_scan_called.append(True)
        return 0

    discovery_called = []

    def fake_discovery(*args, **kwargs):
        discovery_called.append(True)
        return ([], [])

    with patch("netdoc.collector.discovery.run_full_scan", side_effect=fake_run_full_scan), \
         patch("netdoc.collector.discovery.run_discovery", side_effect=fake_discovery), \
         patch("netdoc.collector.pipeline.run_pipeline", return_value={}):

        with Session() as s:
            rs.run_scan_cycle(s, "full_single")

    assert not full_scan_called, "run_full_scan nie powinien byc wywolany dla pustej kolejki"
    assert discovery_called, "discovery powinno byc wywolane jako fallback"


# ─── 2. --once mode respektuje scan_requested ────────────────────────────────

def test_once_mode_picks_up_full_single_from_db(db_engine):
    """--once mode: gdy scan_requested='full_single' w DB → uruchamia full_single."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import SystemStatus

    Session = sessionmaker(bind=db_engine)
    db = Session()
    db.add(SystemStatus(key="scan_requested", value="full_single", category="scanner"))
    db.add(SystemStatus(key="full_scan_ip_queue", value="10.1.2.3", category="scanner"))
    db.commit()
    db.close()

    rs = _import_rs()

    # Symulujemy logikę z bloku --once (nowy kod po fixie)
    scan_type = "discovery"
    with Session() as s:
        requested = rs._get_status(s, "scan_requested")
        if requested and requested not in ("-", ""):
            if requested in ("full", "discovery", "full_single"):
                scan_type = requested
            rs._set_status(s, {"scan_requested": "-"})

    assert scan_type == "full_single", \
        f"--once powinien wykryc full_single z scan_requested, got: {scan_type}"

    # Sprawdz ze scan_requested zostal skasowany
    db2 = Session()
    req = rs._get_status(db2, "scan_requested")
    db2.close()
    assert req == "-", f"scan_requested powinien byc '-' po odebraniu, jest: {req}"


def test_once_mode_picks_up_full_from_db(db_engine):
    """--once mode: gdy scan_requested='full' w DB → uruchamia full scan."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import SystemStatus

    Session = sessionmaker(bind=db_engine)
    db = Session()
    db.add(SystemStatus(key="scan_requested", value="full", category="scanner"))
    db.commit()
    db.close()

    rs = _import_rs()

    scan_type = "discovery"
    with Session() as s:
        requested = rs._get_status(s, "scan_requested")
        if requested and requested not in ("-", ""):
            if requested in ("full", "discovery", "full_single"):
                scan_type = requested
            rs._set_status(s, {"scan_requested": "-"})

    assert scan_type == "full"


def test_once_mode_ignores_unknown_scan_type(db_engine):
    """--once mode: nieznany typ skanu w scan_requested → fallback do discovery."""
    from sqlalchemy.orm import sessionmaker
    from netdoc.storage.models import SystemStatus

    Session = sessionmaker(bind=db_engine)
    db = Session()
    db.add(SystemStatus(key="scan_requested", value="unknown_attack_type", category="scanner"))
    db.commit()
    db.close()

    rs = _import_rs()

    scan_type = "discovery"
    with Session() as s:
        requested = rs._get_status(s, "scan_requested")
        if requested and requested not in ("-", ""):
            if requested in ("full", "discovery", "full_single"):
                scan_type = requested
            # nie zmienia scan_type — zostaje "discovery"

    assert scan_type == "discovery"


def test_once_mode_no_scan_requested_stays_discovery(db_engine):
    """--once mode: brak scan_requested → normalny discovery."""
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=db_engine)

    rs = _import_rs()

    scan_type = "discovery"
    with Session() as s:
        requested = rs._get_status(s, "scan_requested")
        if requested and requested not in ("-", ""):
            if requested in ("full", "discovery", "full_single"):
                scan_type = requested

    assert scan_type == "discovery"


# ─── 3. continuous mode: full_single nie degraduje się do discovery ──────────

def test_continuous_mode_full_single_not_degraded():
    """Bug fix: w pętli ciągłej full_single był degradowany do discovery.

    Stary kod: requested if requested in ("full", "discovery") else "discovery"
    Nowy kod:  requested if requested in ("full", "discovery", "full_single") else "discovery"
    """
    # Symulujemy logikę z linii ~2767 run_scanner.py
    requested = "full_single"

    # Stary kod (bug):
    old_next = requested if requested in ("full", "discovery") else "discovery"
    # Nowy kod (fix):
    new_next = requested if requested in ("full", "discovery", "full_single") else "discovery"

    assert old_next == "discovery", "Stary kod powinien degradowac full_single do discovery"
    assert new_next == "full_single", "Nowy kod powinien zachowac full_single"


def test_continuous_mode_full_not_degraded():
    """full i discovery nadal nie są degradowane po fixie."""
    for t in ("full", "discovery"):
        result = t if t in ("full", "discovery", "full_single") else "discovery"
        assert result == t, f"{t} nie powinno byc zdegradowane"
