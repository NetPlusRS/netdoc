"""Netdoc SNMP Worker — szybki poller SNMP dla urzadzen ze ZNANA community (co 300s).

Odpowiedzialnosc:
  - Odpytuje sysName/sysDescr/sysLocation dla urzadzen z ustawiona snmp_community
  - Aktualizuje hostname, os_version, location jesli puste
  - Odswierza snmp_ok_at przy kazdym udanym pollu

NIE wykonuje autodiscovery community — to robi community-worker (run_community_worker.py).
Eksportuje metryki Prometheus na porcie 8002.
"""
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from prometheus_client import Gauge, start_http_server

from netdoc.storage.database import SessionLocal, init_db
from netdoc.storage.models import Device, Credential, CredentialMethod, DeviceType

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SNMP-W] %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)
logging.getLogger("asyncio").setLevel(logging.CRITICAL)  # pysnmp pending tasks noise

_DEFAULT_SNMP_INTERVAL = int(os.getenv("SNMP_INTERVAL", "300"))
_DEFAULT_SNMP_WORKERS  = int(os.getenv("SNMP_WORKERS", "32"))  # PERF-12: 10→32 (limit 1600 vs 500 urz.)
METRICS_PORT  = int(os.getenv("SNMP_METRICS_PORT", "8002"))

g_polled   = Gauge("netdoc_snmp_polled",    "Urzadzenia przeskanowane w ostatnim cyklu")
g_success  = Gauge("netdoc_snmp_success",   "Urzadzenia z dzialajacym SNMP")
g_failed   = Gauge("netdoc_snmp_failed",    "Urzadzenia bez odpowiedzi SNMP")
g_new_cred = Gauge("netdoc_snmp_new_creds", "Nowe credentiale odkryte w ostatnim cyklu")
g_duration = Gauge("netdoc_snmp_duration_s","Czas trwania ostatniego cyklu [s]")



def _poll_device(device_id: int, ip: str, community: str,
                 hostname: str | None, os_version: str | None, location: str | None,
                 snmp_timeout: int = 2) -> dict:
    """Odpytuje urzadzenie ze ZNANA community — bez autodiscovery.
    PERF-03: dane device przekazane bezposrednio (nie re-query per watek).
    Otwiera DB tylko do zapisu wyniku, nie do odczytu device.
    """
    from netdoc.collector.drivers.snmp import _snmp_get, OID_SYSNAME, OID_SYSDESCR, OID_SYSLOCATION

    result = {"device_id": device_id, "success": False, "community": None}
    if not community:
        return result  # scan_once() filtruje community=None, ale na wszelki wypadek
    try:
        sysname = _snmp_get(ip, community, OID_SYSNAME, timeout=snmp_timeout)
    except Exception as exc:
        logger.debug("SNMP get error %s: %s", ip, exc)
        return result  # wyjątek sieci — nie dotykamy DB, community pozostaje nienaruszone

    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return result

        if not sysname:
            # Community przestalo dzialac — wyczysc, community-worker znajdzie nowe
            logger.info("Community '%s' no longer responds for %s — clearing", community, ip)
            device.snmp_community = None
            device.snmp_ok_at     = None
            db.commit()
            return result

        result["success"]   = True
        result["community"] = community

        sysdescr = _snmp_get(ip, community, OID_SYSDESCR,   timeout=snmp_timeout)
        sysloc   = _snmp_get(ip, community, OID_SYSLOCATION, timeout=snmp_timeout)

        if sysname  and not hostname:   device.hostname    = sysname
        if sysdescr and not os_version: device.os_version  = sysdescr[:120]
        if sysloc   and not location:   device.location    = sysloc
        device.snmp_ok_at = datetime.utcnow()

        # Zaktualizuj last_success_at na credentialu jesli istnieje
        existing = (
            db.query(Credential)
            .filter(Credential.device_id == device_id, Credential.method == CredentialMethod.snmp)
            .first()
        ) or (
            db.query(Credential)
            .filter(Credential.device_id.is_(None), Credential.method == CredentialMethod.snmp,
                    Credential.username == community)
            .first()
        )
        if existing:
            existing.last_success_at = datetime.utcnow()
            existing.success_count   = (existing.success_count or 0) + 1

        db.commit()  # jeden atomowy commit: device + credential razem

    except Exception as exc:
        logger.warning("SNMP poll error device_id=%s: %s", device_id, exc)
        db.rollback()
    finally:
        db.close()
    return result



_DEFAULT_SNMP_TIMEOUT = int(os.getenv("SNMP_TIMEOUT_S", "2"))


def _read_snmp_settings() -> tuple:
    """Czyta ustawienia z system_status (zmiana skutkuje w nastepnym cyklu).
    PERF-14: jedna query WHERE key IN (...) zamiast 4 osobnych SELECT.
    """
    from netdoc.storage.models import SystemStatus
    _KEYS = ("snmp_interval_s", "snmp_workers", "snmp_timeout_s", "snmp_community_delay_s")
    db = SessionLocal()
    try:
        rows = db.query(SystemStatus).filter(SystemStatus.key.in_(_KEYS)).all()
        vals = {r.key: r.value for r in rows}
        def _i(key, default):
            v = vals.get(key)
            try:
                return int(v) if (v not in (None, "")) else default
            except (ValueError, TypeError):
                return default
        return (max(10, _i("snmp_interval_s",        _DEFAULT_SNMP_INTERVAL)),
                max(1,  _i("snmp_workers",           _DEFAULT_SNMP_WORKERS)),
                max(1,  _i("snmp_timeout_s",         _DEFAULT_SNMP_TIMEOUT)),
                max(0,  _i("snmp_community_delay_s", 3)))
    except Exception:
        return _DEFAULT_SNMP_INTERVAL, _DEFAULT_SNMP_WORKERS, _DEFAULT_SNMP_TIMEOUT, 3
    finally:
        db.close()


def scan_once() -> None:
    interval, workers, snmp_timeout, _unused_delay = _read_snmp_settings()
    t0 = time.monotonic()
    db = SessionLocal()
    try:
        # Tylko urzadzenia ze znana community — autodiscovery robi community-worker
        devices = (
            db.query(Device)
            .filter(Device.is_active == True, Device.snmp_community.isnot(None))
            .all()
        )
    finally:
        db.close()

    if not devices:
        logger.info("No devices with known community — nothing to poll")
        g_polled.set(0); g_success.set(0); g_failed.set(0)
        return

    logger.info("SNMP poll: %d devices with known community | workers=%d", len(devices), workers)

    polled = success = failed = 0
    with ThreadPoolExecutor(max_workers=min(workers, len(devices))) as pool:
        # PERF-03: przekazujemy dane device bezposrednio — eliminuje N re-query per watek
        futures = {
            pool.submit(
                _poll_device, d.id, d.ip, d.snmp_community,
                d.hostname, d.os_version, d.location, snmp_timeout
            ): d.id
            for d in devices
        }
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception as exc:
                logger.error("SNMP poll thread error: %s", exc)
                polled += 1
                failed += 1
                continue
            polled += 1
            if res["success"]:
                success += 1
            else:
                failed += 1

    elapsed = time.monotonic() - t0
    g_polled.set(polled); g_success.set(success)
    g_failed.set(failed); g_new_cred.set(0); g_duration.set(round(elapsed, 1))
    logger.info("SNMP poll done: %d ok / %d failed  %.1fs", success, failed, elapsed)


def _wait_for_schema(max_retries: int = 12, wait_s: int = 10) -> None:
    """Czeka az tabela devices bedzie dostepna (race condition przy swiezej bazie)."""
    from sqlalchemy import text
    from netdoc.storage.database import engine
    for attempt in range(1, max_retries + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1 FROM devices LIMIT 1"))
            return
        except Exception:
            logger.warning("Schema not ready (attempt %d/%d) — waiting %ds...", attempt, max_retries, wait_s)
            time.sleep(wait_s)
    logger.warning("Schema still unavailable after %ds — continuing anyway", max_retries * wait_s)


def main() -> None:
    logger.info("Netdoc SNMP Worker — default_interval=%ds workers=%d metrics=:%d",
                _DEFAULT_SNMP_INTERVAL, _DEFAULT_SNMP_WORKERS, METRICS_PORT)
    _wait_for_schema()
    init_db()
    start_http_server(METRICS_PORT)
    logger.info("Metrics: http://0.0.0.0:%d/metrics", METRICS_PORT)
    # PERF-02: sleep-until-next-run zamiast sleep-after-work
    interval = _DEFAULT_SNMP_INTERVAL
    while True:
        next_run = time.monotonic() + interval
        try:
            scan_once()
        except Exception as exc:
            logger.exception("Unhandled exception in scan_once: %s", exc)
        interval, *_ = _read_snmp_settings()
        time.sleep(max(0.0, next_run - time.monotonic()))


if __name__ == "__main__":
    main()
