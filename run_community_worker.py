"""Netdoc Community Worker — autodiscovery community SNMP (domyslnie co 3600s).

Odpowiedzialnosc:
  - Wyszukuje dzialajaca community dla urzadzen BEZ snmp_community (nowe urzadzenia)
  - Ponownie sprawdza urzadzenia z przeterminowanym snmp_ok_at (domyslnie >7 dni)
  - Rotacyjne skanowanie: community po community, kazde IP odpytywane raz na runde
    (nie burst: kazde urzadzenie dostaje 1 sonde na delay sekund, nie setki z rzedu)
  - Po znalezieniu: zapisuje snmp_community + snmp_ok_at + tworzy/aktualizuje credential

Eksportuje metryki Prometheus na porcie 8006.

Zaprojektowany do pracy z duza baza community (setki wpisow) i setkami urzadzen.
snmp-worker odpytuje juz znane community (szybki poll), community-worker szuka nowych.
"""
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

from prometheus_client import Gauge, start_http_server

from netdoc.storage.database import SessionLocal, init_db
from netdoc.storage.models import Device, Credential, CredentialMethod, DeviceType, ScanResult

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [COMM-W] %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)
logging.getLogger("asyncio").setLevel(logging.CRITICAL)

_DEFAULT_INTERVAL   = int(os.getenv("COMMUNITY_INTERVAL_S",   "3600"))
_DEFAULT_WORKERS    = int(os.getenv("COMMUNITY_WORKERS",          "5"))
_DEFAULT_SNMP_TIMEOUT = int(os.getenv("SNMP_TIMEOUT_S",           "2"))
METRICS_PORT        = int(os.getenv("COMMUNITY_METRICS_PORT",   "8006"))

g_scanned   = Gauge("netdoc_comm_scanned",   "Urzadzenia przeskanowane w ostatnim cyklu")
g_found     = Gauge("netdoc_comm_found",     "Urzadzenia z nowo znaleziona community")
g_stale     = Gauge("netdoc_comm_stale",     "Urzadzenia re-sprawdzone (przeterminowane)")
g_total_q   = Gauge("netdoc_comm_total_q",   "Liczba community w bazie w ostatnim cyklu")
g_duration  = Gauge("netdoc_comm_duration_s","Czas trwania ostatniego cyklu [s]")


_SETTINGS_KEYS = (
    "community_interval_s", "community_workers", "snmp_community_delay_s",
    "community_recheck_days", "snmp_timeout_s",
)

def _get_settings() -> tuple:
    """Czyta ustawienia z system_status jednym zapytaniem WHERE key IN (...)."""
    from netdoc.storage.models import SystemStatus
    db = SessionLocal()
    try:
        rows = db.query(SystemStatus).filter(SystemStatus.key.in_(_SETTINGS_KEYS)).all()
        vals = {r.key: r.value for r in rows}

        def _i(key, default):
            v = vals.get(key)
            try:
                return int(v) if (v not in (None, "")) else default
            except (ValueError, TypeError):
                return default

        return (
            max(60,  _i("community_interval_s",   _DEFAULT_INTERVAL)),
            max(1,   _i("community_workers",       _DEFAULT_WORKERS)),
            max(0,   _i("snmp_community_delay_s",  3)),
            max(1,   _i("community_recheck_days",  7)),
            max(1,   _i("snmp_timeout_s",          _DEFAULT_SNMP_TIMEOUT)),
        )
    except Exception:
        return _DEFAULT_INTERVAL, _DEFAULT_WORKERS, 3, 7, _DEFAULT_SNMP_TIMEOUT
    finally:
        db.close()


def _get_db_communities(db) -> list:
    return [
        c.username for c in
        db.query(Credential)
          .filter(Credential.device_id.is_(None), Credential.method == CredentialMethod.snmp)
          .order_by(Credential.priority)
          .all()
        if c.username
    ]


def _probe_community(device_id: int, ip: str, community: str, snmp_timeout: int) -> dict:
    """Probuje JEDNA community na jednym urzadzeniu. Zwraca found=True jesli odpowiada.

    Celowo nie zapisuje do DB — zapis wykonuje scan_once() po potwierdzeniu.
    Oddzielamy probe (UDP) od transakcji DB dla jasnosci i wydajnosci.
    """
    from netdoc.collector.drivers.snmp import _snmp_get, OID_SYSNAME

    result = {"device_id": device_id, "ip": ip, "found": False, "community": community}
    try:
        sysname = _snmp_get(ip, community, OID_SYSNAME, timeout=snmp_timeout)
        result["found"] = bool(sysname)
    except Exception as exc:
        logger.debug("SNMP probe %s community='%s': %s", ip, community, exc)
    return result


def _save_found_community(device_id: int, community: str, snmp_timeout: int) -> None:
    """Zapisuje znaleziona community do DB: device + credential + enrichment SNMP."""
    from netdoc.collector.drivers.snmp import _snmp_get, OID_SYSNAME, OID_SYSDESCR, OID_SYSLOCATION

    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return

        # Enrichment — pobierz dodatkowe dane (opcjonalne, nie blokuje zapisu)
        ip = device.ip
        sysname  = _snmp_get(ip, community, OID_SYSNAME,    timeout=snmp_timeout)
        sysdescr = _snmp_get(ip, community, OID_SYSDESCR,   timeout=snmp_timeout)
        sysloc   = _snmp_get(ip, community, OID_SYSLOCATION, timeout=snmp_timeout)

        if sysname  and not device.hostname:   device.hostname    = sysname
        if sysdescr and not device.os_version: device.os_version  = sysdescr[:120]
        if sysloc   and not device.location:   device.location    = sysloc

        device.snmp_community = community
        device.snmp_ok_at     = datetime.utcnow()

        # Znajdz lub stworz global credential
        global_cred = db.query(Credential).filter(
            Credential.device_id.is_(None),
            Credential.method    == CredentialMethod.snmp,
            Credential.username  == community,
        ).first()
        if global_cred:
            global_cred.last_success_at = datetime.utcnow()
            global_cred.success_count   = (global_cred.success_count or 0) + 1
        else:
            db.add(Credential(
                device_id=None, method=CredentialMethod.snmp,
                username=community, priority=50,
                notes=f"Auto (community-worker): {community}",
                last_success_at=datetime.utcnow(),
            ))

        db.commit()
        logger.info("Found community '%s' for %s", community, ip)

    except Exception as exc:
        logger.debug("Error saving community for device_id=%s: %s", device_id, exc)
        db.rollback()
    finally:
        db.close()


def scan_once() -> None:
    interval, workers, delay, recheck_days, snmp_timeout = _get_settings()
    t0 = time.monotonic()

    db = SessionLocal()
    try:
        communities = _get_db_communities(db)
        if not communities:
            logger.warning("No communities in database — skipping cycle")
            return

        stale_threshold = datetime.utcnow() - timedelta(days=recheck_days)
        stale_count = 0   # inicjalizacja przed try — zabezpieczenie przed NameError przy błędzie DB

        # Urzadzenia do sprawdzenia community SNMP:
        #   - typ = znane urzadzenie sieciowe (router/switch/ap/firewall)
        #   - LUB wczesniej odpowiadalo na SNMP (snmp_ok_at IS NOT NULL — re-weryfikacja)
        #   - LUB ma otwarty port 161 w ostatnim skanie (kamera/IoT/industrial z SNMP)
        _snmp_types = (
            DeviceType.router, DeviceType.switch, DeviceType.ap, DeviceType.firewall,
        )
        from sqlalchemy import func
        latest_scan_sq = (
            db.query(ScanResult.device_id, func.max(ScanResult.scan_time).label("last"))
            .group_by(ScanResult.device_id)
            .subquery()
        )
        latest_scans = db.query(ScanResult).join(
            latest_scan_sq,
            (ScanResult.device_id == latest_scan_sq.c.device_id) &
            (ScanResult.scan_time == latest_scan_sq.c.last),
        ).all()
        snmp_port_ids = {
            s.device_id for s in latest_scans
            if s.open_ports and ("161" in s.open_ports or 161 in s.open_ports)
        }
        devices = (
            db.query(Device)
            .filter(Device.is_active == True)
            .filter(
                (Device.snmp_community.is_(None)) |
                (Device.snmp_ok_at < stale_threshold)
            )
            .filter(
                Device.device_type.in_(_snmp_types) |
                (Device.snmp_ok_at.isnot(None)) |
                Device.id.in_(snmp_port_ids)
            )
            .all()
        )
        stale_count = sum(
            1 for d in devices
            if d.snmp_community is not None and d.snmp_ok_at is not None
               and d.snmp_ok_at < stale_threshold
        )
        # Slownik id -> ip dla szybkiego dostepu (bez otwartej sesji DB)
        device_map = {d.id: d.ip for d in devices}
    finally:
        db.close()

    if not device_map:
        logger.info("No devices to check (all have up-to-date community)")
        g_scanned.set(0); g_found.set(0); g_stale.set(stale_count)
        return

    logger.info(
        "Community scan (rotacyjny): %d urzadzen x %d community | workers=%d delay=%ds",
        len(device_map), len(communities), workers, delay,
    )

    # ── Rotacyjna petla: community po community ──────────────────────────────────
    # Kazde urzadzenie dostaje maksymalnie 1 sonde na runde (co delay sekund).
    # Urzadzenia, dla ktorych znaleziono community, sa usuwane z kolejki.
    remaining = dict(device_map)   # {device_id: ip} jeszcze bez odpowiedzi
    found = 0

    with ThreadPoolExecutor(max_workers=min(workers, len(remaining))) as pool:
        for round_idx, community in enumerate(communities):
            if not remaining:
                logger.info("All devices found after %d communities", round_idx)
                break

            # Rownolegle odpytaj wszystkie pozostale urzadzenia ta sama community
            futures = {
                pool.submit(_probe_community, did, ip, community, snmp_timeout): did
                for did, ip in remaining.items()
            }
            found_this_round = []
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                except Exception as exc:
                    logger.error("Probe thread error: %s", exc)
                    continue
                if res["found"]:
                    found_this_round.append((res["device_id"], res["community"]))

            # Zapisz znalezione (sekwencyjnie — bez wyścigu na DB)
            for did, comm in found_this_round:
                _save_found_community(did, comm, snmp_timeout)
                remaining.pop(did, None)
                found += 1

            if delay > 0 and remaining and round_idx < len(communities) - 1:
                time.sleep(delay)

    scanned = len(device_map)
    elapsed = time.monotonic() - t0
    g_scanned.set(scanned)
    g_found.set(found)
    g_stale.set(stale_count)
    g_total_q.set(len(communities))
    g_duration.set(round(elapsed, 1))
    logger.info(
        "Community done: %d urzadzen / %d znaleziono / %d stale  %.1fs",
        scanned, found, stale_count, elapsed,
    )


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
    logger.info(
        "Netdoc Community Worker — interval=%ds workers=%d metrics=:%d",
        _DEFAULT_INTERVAL, _DEFAULT_WORKERS, METRICS_PORT,
    )
    _wait_for_schema()
    init_db()
    start_http_server(METRICS_PORT)
    logger.info("Metrics: http://0.0.0.0:%d/metrics", METRICS_PORT)
    # PERF-02: sleep-until-next-run zamiast sleep-after-work
    interval = _DEFAULT_INTERVAL
    while True:
        next_run = time.monotonic() + interval
        try:
            scan_once()
        except Exception as exc:
            logger.exception("Unhandled exception in scan_once (community): %s", exc)
        interval, *_ = _get_settings()
        sleep_time = max(0.0, next_run - time.monotonic())
        logger.info("Next cycle in %.0fs", sleep_time)
        time.sleep(sleep_time)


if __name__ == "__main__":
    main()
