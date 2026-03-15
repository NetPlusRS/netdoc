"""
Prometheus metrics endpoint.

Jezeli biblioteka prometheus_client nie jest zainstalowana,
endpoint /metrics zwraca 503 z informacja — reszta systemu dziala normalnie.
"""
import logging
from fastapi import APIRouter
from fastapi.responses import Response, JSONResponse

logger = logging.getLogger(__name__)
router = APIRouter()

try:
    from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
    _PROMETHEUS_AVAILABLE = True

    devices_total = Gauge("netdoc_devices_total", "Laczna liczba znanych urzadzen")
    devices_active = Gauge("netdoc_devices_active", "Liczba aktywnych urzadzen")
    discovery_runs_total = Counter("netdoc_discovery_runs_total", "Liczba wykonanych discovery")
    discovery_duration_seconds = Histogram(
        "netdoc_discovery_duration_seconds",
        "Czas trwania discovery w sekundach",
        buckets=[5, 15, 30, 60, 120, 300],
    )
    full_scan_pending = Gauge(
        "netdoc_full_scan_pending",
        "Liczba urzadzen bez aktualnego pelnego skanu portow (oczekujace w kolejce)",
    )
    scan_results_total = Counter(
        "netdoc_scan_results_total",
        "Liczba wynikow security scan",
        labelnames=["scan_type"],
    )

except ImportError:
    _PROMETHEUS_AVAILABLE = False
    logger.warning(
        "prometheus_client nie jest zainstalowany — endpoint /metrics niedostepny. "
        "Discovery i zbieranie danych dziala normalnie. "
        "Aby wlaczyc: pip install prometheus-client"
    )

    # Zaślepki — uzywane przez scheduler zeby nie crashowac przy update metryk
    class _Noop:
        def inc(self, *a, **kw): pass
        def set(self, *a, **kw): pass
        def observe(self, *a, **kw): pass
        def labels(self, *a, **kw): return self
        def time(self): return self
        def __enter__(self): return self
        def __exit__(self, *a): pass

    _noop = _Noop()
    devices_total = _noop
    devices_active = _noop
    discovery_runs_total = _noop
    discovery_duration_seconds = _noop
    full_scan_pending = _noop
    scan_results_total = _noop


@router.get("/metrics", include_in_schema=False)
def prometheus_metrics(db=None):
    """Endpoint Prometheus — scrapuj co 60s.

    Przy kazdym scrape oblicza aktualne wartosci z DB (szybkie zapytania SQL).
    """
    if not _PROMETHEUS_AVAILABLE:
        return JSONResponse(
            status_code=503,
            content={
                "detail": "prometheus_client nie jest zainstalowany",
                "hint": "pip install prometheus-client",
                "collector_status": "running",
            },
        )

    # Pobierz DB session jezeli nie przekazano (normalny flow przez FastAPI DI)
    _db = db
    if _db is None:
        try:
            from netdoc.storage.database import SessionLocal
            _db = SessionLocal()
            _close_db = True
        except Exception:
            _close_db = False
    else:
        _close_db = False

    try:
        if _db is not None:
            _refresh_gauges(_db)
    finally:
        if _close_db and _db is not None:
            _db.close()

    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


def _refresh_gauges(db) -> None:
    """Oblicza i ustawia aktualne wartosci Gauge z bazy danych."""
    try:
        from netdoc.storage.models import Device, SystemStatus
        from netdoc.collector.discovery import get_stale_full_scan_ips

        total = db.query(Device).count()
        active = db.query(Device).filter(Device.is_active == True).count()
        devices_total.set(total)
        devices_active.set(active)

        # Ile urzadzen czeka na pelny skan portow
        max_age_row = db.query(SystemStatus).filter(SystemStatus.key == "full_scan_max_age_days").first()
        max_age_days = int(max_age_row.value) if max_age_row and max_age_row.value else 7
        if max_age_days > 0:
            pending = len(get_stale_full_scan_ips(db, max_age_days))
        else:
            pending = 0
        full_scan_pending.set(pending)
    except Exception:
        pass  # metryki opcjonalne
