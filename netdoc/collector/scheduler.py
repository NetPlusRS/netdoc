"""
Scheduler — harmonogram zadan collectora.

Zadania:
  - discovery + pipeline: co SCAN_INTERVAL_MINUTES (domyslnie 60 min)

Tryby pracy (automatycznie):
  - Bez .env / bez credentials: tylko nmap discovery (IP, porty, OS)
  - Z credentials w DB / settings: dodatkowo SSH/SNMP/API enrichment

Niezaleznosc:
  - Nie wymaga uruchomionego Prometheusa ani Grafany
  - Nie wymaga FastAPI — mozna uruchamiac samodzielnie:
      python -m netdoc.collector.scheduler
"""
import logging
import time as _time
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from netdoc.config.settings import settings
from netdoc.storage.database import SessionLocal, init_db
from netdoc.storage.models import Device
from netdoc.collector.discovery import (
    run_discovery, run_full_scan,
    FULL_SCAN_WORKERS, FULL_SCAN_BATCH_SIZE, TARGET_PORTS,
)
from netdoc.storage.models import SystemStatus
from netdoc.collector.oui_lookup import oui_db
from netdoc.collector.pipeline import run_pipeline

logger = logging.getLogger(__name__)
_scheduler: BackgroundScheduler = None


def _set_status(db, updates: dict, category: str = "scheduler") -> None:
    """Upsert do tabeli system_status. updates = {key: value}."""
    from datetime import datetime
    for key, value in updates.items():
        row = db.query(SystemStatus).filter(SystemStatus.key == key).first()
        if row is None:
            row = SystemStatus(key=key, category=category, value=str(value))
            db.add(row)
        else:
            row.value = str(value)
            row.updated_at = datetime.utcnow()
    db.commit()


def write_config_status(db) -> None:
    """Zapisuje statyczne ustawienia konfiguracji do system_status."""
    from netdoc.collector.oui_lookup import oui_db
    if not oui_db._loaded:
        oui_db.load()
    _set_status(db, {
        "scan_interval_minutes":  settings.scan_interval_minutes,
        "full_scan_workers":      FULL_SCAN_WORKERS,
        "full_scan_batch_size":   FULL_SCAN_BATCH_SIZE,
        "targeted_ports_count":   len(TARGET_PORTS.split(",")),
        "targeted_ports":         TARGET_PORTS,
        "oui_db_entries":         oui_db.status()["entries"],
    }, category="config")
    _set_status(db, {"current_job": "-", "scheduler_running": "true"}, category="scheduler")


def _update_metrics(db, stats: dict) -> None:
    """Aktualizuje metryki Prometheus jezeli biblioteka dostepna (opcjonalne)."""
    try:
        from netdoc.api.metrics import devices_total, devices_active, discovery_runs_total
        total = db.query(Device).count()
        active = db.query(Device).filter(Device.is_active == True).count()
        devices_total.set(total)
        devices_active.set(active)
        discovery_runs_total.inc()
    except Exception:
        pass  # metryki opcjonalne — blad nie przerywa pracy


def _full_scan_job() -> None:
    """Discovery + pipeline enrichment. Uruchamiany cyklicznie."""
    logger.info("Scheduler: start discovery")
    t0 = _time.monotonic()

    with SessionLocal() as db:
        _set_status(db, {"current_job": "discovery"})
        try:
            devices = run_discovery(db)
            stats = {}
            if devices:
                stats = run_pipeline(db, devices)
                logger.info(
                    "Scheduler: zakonczono — %d urzadzen, %d wzbogaconych, %d tylko discovery (%.1fs)",
                    stats["total"], stats["enriched"], stats["basic_only"],
                    _time.monotonic() - t0,
                )
            _update_metrics(db, stats)
            from datetime import datetime
            _set_status(db, {
                "last_discovery_at":       datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "last_discovery_devices":  stats.get("total", len(devices)),
                "last_discovery_enriched": stats.get("enriched", 0),
                "last_discovery_duration_s": round(_time.monotonic() - t0, 1),
            }, category="last_run")
        finally:
            _set_status(db, {"current_job": "-"})


def _oui_update_job() -> None:
    """Cotygodniowa aktualizacja bazy IEEE OUI (MA-L/MA-M/MA-S)."""
    logger.info("OUI update: start")
    with SessionLocal() as db:
        _set_status(db, {"current_job": "oui_update"})
    try:
        results = oui_db.update(timeout=60)
        ok = sum(1 for v in results.values() if v.get("ok"))
        fail = len(results) - ok
        logger.info("OUI update: %d OK, %d bledy", ok, fail)
        from datetime import datetime
        with SessionLocal() as db:
            _set_status(db, {
                "last_oui_update_at":      datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "last_oui_update_entries": oui_db.status()["entries"],
                "last_oui_update_ok":      ok,
            }, category="last_run")
    finally:
        with SessionLocal() as db:
            _set_status(db, {"current_job": "-"})


def _full_port_scan_job() -> None:
    """Dzienny pelny skan portow TCP 1-65535 wszystkich aktywnych urzadzen."""
    logger.info("Scheduler: start full port scan")
    t0 = _time.monotonic()
    with SessionLocal() as db:
        _set_status(db, {"current_job": "full_port_scan"})
    try:
        with SessionLocal() as db:
            n = run_full_scan(db)
        elapsed = round(_time.monotonic() - t0, 1)
        logger.info("Scheduler: full port scan zakonczono — %d urzadzen (%.1fs)", n, elapsed)
        from datetime import datetime
        with SessionLocal() as db:
            _set_status(db, {
                "last_full_scan_at":         datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "last_full_scan_devices":    n,
                "last_full_scan_duration_s": elapsed,
            }, category="last_run")
    finally:
        with SessionLocal() as db:
            _set_status(db, {"current_job": "-"})


def start_scheduler() -> BackgroundScheduler:
    """Tworzy i uruchamia scheduler. Zwraca instancje schedulera."""
    global _scheduler

    init_db()

    _scheduler = BackgroundScheduler(timezone="Europe/Warsaw")
    _scheduler.add_job(
        func=_full_scan_job,
        trigger=IntervalTrigger(minutes=settings.scan_interval_minutes),
        id="full_scan",
        name="Discovery + Pipeline",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    _scheduler.add_job(
        func=_oui_update_job,
        trigger="interval",
        weeks=1,
        id="oui_update",
        name="IEEE OUI database update",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    _scheduler.add_job(
        func=_full_port_scan_job,
        trigger="interval",
        hours=24,
        id="full_port_scan",
        name="Full TCP port scan (1-65535)",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    _scheduler.start()
    logger.info("Scheduler uruchomiony. Skan co %d minut.", settings.scan_interval_minutes)

    # Zapisz konfiguracje i harmonogram do bazy
    with SessionLocal() as db:
        write_config_status(db)
        from datetime import timezone
        jobs_next = {}
        for job in _scheduler.get_jobs():
            if job.next_run_time:
                jobs_next[f"next_{job.id}_at"] = job.next_run_time.astimezone(
                    timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        if jobs_next:
            _set_status(db, jobs_next, category="scheduler")

    return _scheduler


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Scheduler zatrzymany.")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    scheduler = start_scheduler()
    _full_scan_job()  # uruchom od razu przy starcie
    try:
        while True:
            _time.sleep(30)
    except KeyboardInterrupt:
        stop_scheduler()
