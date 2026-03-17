"""Netdoc Ping Worker — szybki poller dostepnosci urzadzen.

Sprawdza kazde urzadzenie co POLL_INTERVAL sekund (domyslnie 30s) przez:
  1. TCP connect do popularnych portow (22, 80, 443 ...) — bez uprawnien root
  2. ICMP ping przez ping3 — wymaga NET_RAW (dodane w docker-compose)

Aktualizuje Device.is_active i Device.last_seen.
Eksportuje metryki Prometheus na porcie 8001.
"""
import logging
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

from prometheus_client import Gauge, start_http_server

from netdoc.storage.database import SessionLocal, init_db
from netdoc.storage.models import Device, ScanResult

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PING] %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

_DEFAULT_INTERVAL = int(os.getenv("PING_INTERVAL", "18"))  # 18s domyslnie
TCP_TIMEOUT     = float(os.getenv("PING_TCP_TIMEOUT",      "1.5"))
_DEFAULT_WORKERS  = int(os.getenv("PING_WORKERS", "64"))
_DEFAULT_INACT    = int(os.getenv("PING_INACTIVE_AFTER_MIN", "5"))
METRICS_PORT    = int(os.getenv("PING_METRICS_PORT",       "8001"))
# Ile kolejnych niepowodzen probe zanim urzadzenie oznaczone DOWN (zapobiega false-positive)
_FAIL_THRESHOLD = int(os.getenv("PING_FAIL_THRESHOLD", "3"))

PROBE_PORTS = [22, 80, 443, 23, 8080, 8443, 8888, 554, 21, 3389, 5000, 10000]

# Maks. dodatkowych portow device-specific (z ostatniego skanu) probowanych PRZED PROBE_PORTS.
# Zabezpieczenie przed sytuacja: urzadzenie ma odkryty tylko port 9090 (nie ma w PROBE_PORTS),
# ICMP jest blokowane → bez tego bylby falszywie DOWN pomimo ze jest osiagalny.
_MAX_DEVICE_EXTRA_PORTS = int(os.getenv("PING_MAX_DEVICE_PORTS", "20"))

g_up        = Gauge("netdoc_ping_up",              "Urzadzenia dostepne")
g_down      = Gauge("netdoc_ping_down",            "Urzadzenia niedostepne")
g_total     = Gauge("netdoc_ping_total",           "Wszystkie urzadzenia w bazie")
g_poll_time = Gauge("netdoc_ping_poll_duration_s", "Czas trwania ostatniego cyklu [s]")
g_ev_up     = Gauge("netdoc_ping_events_up_total", "Suma zdarzen UP od startu")
g_ev_down   = Gauge("netdoc_ping_events_down_total","Suma zdarzen DOWN od startu")

_events_up   = 0
_events_down = 0
# Licznik kolejnych niepowodzen per urzadzenie (in-memory, reset przy restarcie workera)
_fail_counts: dict = {}   # device_id (int) -> liczba kolejnych nieudanych prob




def _icmp_alive(ip: str):
    """Zwraca RTT w ms (float) lub None jesli brak odpowiedzi."""
    # Metoda 1: ping3 (raw socket, wymaga NET_RAW)
    try:
        import ping3
        result = ping3.ping(ip, timeout=2, unit="ms")
        if result is not None and result is not False and result >= 0:
            return round(result, 1)
    except Exception:
        pass
    # Metoda 2: subprocess ping — parsujemy czas z outputu
    try:
        import subprocess, re
        r = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ip],
            capture_output=True, timeout=5,
        )
        if r.returncode == 0:
            m = re.search(r"time[=<]([\d.]+)\s*ms", r.stdout.decode("utf-8", errors="replace"))
            return round(float(m.group(1)), 1) if m else 1.0
    except Exception:
        pass
    return None


def _tcp_alive_rtt(ip: str, device_ports: list = None):
    """Sprawdza TCP connect i zwraca RTT w ms lub None.

    Kolejnosc: device-specific (maks. _MAX_DEVICE_EXTRA_PORTS) → generyczne PROBE_PORTS.
    """
    seen: set = set()
    ordered: list = []
    for p in (device_ports or []):
        if p not in seen and len(ordered) < _MAX_DEVICE_EXTRA_PORTS:
            ordered.append(p)
            seen.add(p)
    for p in PROBE_PORTS:
        if p not in seen:
            ordered.append(p)
            seen.add(p)
    for port in ordered:
        try:
            t0 = time.monotonic()
            with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
                rtt = round((time.monotonic() - t0) * 1000, 1)
                if device_ports and port in device_ports and port not in PROBE_PORTS:
                    logger.debug("TCP alive via device-specific port %d: %s", port, ip)
                return rtt
        except OSError:
            pass
    return None


def _check(ip: str, device_ports: list = None):
    """Sprawdza dostepnosc. Zwraca RTT w ms (float) lub None (niedostepny).

    Kolejnosc: ICMP najpierw (szybki, krotki timeout) → TCP jako fallback
    dla urzadzen blokujacych ICMP. Dzieki temu DOWN device odpada po ~2s
    zamiast probowac wszystkich portow TCP (nawet 30s+).
    """
    rtt = _icmp_alive(ip)
    if rtt is not None:
        return rtt
    return _tcp_alive_rtt(ip, device_ports)



def _read_settings() -> tuple:
    """Czyta ustawienia z system_status.
    PERF-14: jedna query WHERE key IN (...) zamiast 5 osobnych SELECT.
    """
    from netdoc.storage.models import SystemStatus
    _KEYS = ("ping_interval_s", "ping_workers", "ping_inactive_after_min",
             "ping_tcp_timeout", "ping_fail_threshold")
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
        def _f(key, default):
            v = vals.get(key)
            try:
                return float(v) if (v not in (None, "")) else default
            except (ValueError, TypeError):
                return default
        return (max(1,   _i("ping_interval_s",        _DEFAULT_INTERVAL)),
                max(1,   _i("ping_workers",            _DEFAULT_WORKERS)),
                max(1,   _i("ping_inactive_after_min", _DEFAULT_INACT)),
                max(0.1, _f("ping_tcp_timeout",        TCP_TIMEOUT)),
                max(1,   _i("ping_fail_threshold",     _FAIL_THRESHOLD)))
    except Exception:
        return _DEFAULT_INTERVAL, _DEFAULT_WORKERS, _DEFAULT_INACT, TCP_TIMEOUT, _FAIL_THRESHOLD
    finally:
        db.close()


def poll_once() -> int:
    """Wykonaj jeden cykl pollingu. Zwraca interval (sekundy) odczytany z ustawien."""
    global _events_up, _events_down, TCP_TIMEOUT, _FAIL_THRESHOLD

    interval, workers, inactive_after, tcp_timeout, fail_threshold = _read_settings()
    # Propaguj do globali uzywanych przez _tcp_alive_rtt / logike DOWN
    TCP_TIMEOUT     = tcp_timeout
    _FAIL_THRESHOLD = fail_threshold
    t0 = time.monotonic()
    db = SessionLocal()
    try:
        devices = db.query(Device).all()
        if not devices:
            return

        now                = datetime.utcnow()
        inactive_threshold = now - timedelta(minutes=inactive_after)

        # Bulk query: najnowszy skan per urzadzenie → znane otwarte porty.
        # Uzywamy do sprawdzenia portow device-specific przed PROBE_PORTS,
        # zeby urzadzenie z portem 9090 (nie w PROBE_PORTS, ICMP blokowany)
        # nie bylo falszywie oznaczone jako DOWN.
        device_known_ports: dict = {}  # device_id -> [port, ...]
        try:
            from sqlalchemy import func as _sqlfunc
            _sr_subq = (
                db.query(ScanResult.device_id,
                         _sqlfunc.max(ScanResult.scan_time).label("max_st"))
                .filter(ScanResult.open_ports.isnot(None))
                .group_by(ScanResult.device_id)
                .subquery()
            )
            _sr_rows = (
                db.query(ScanResult)
                .join(_sr_subq,
                      (ScanResult.device_id == _sr_subq.c.device_id) &
                      (ScanResult.scan_time  == _sr_subq.c.max_st))
                .all()
            )
            for _sr in _sr_rows:
                if _sr.open_ports and _sr.device_id:
                    try:
                        device_known_ports[_sr.device_id] = [
                            int(p) for p in _sr.open_ports.keys()
                        ]
                    except (ValueError, TypeError):
                        pass
        except Exception as _exc:
            logger.warning("Blad pobierania znanych portow: %s — uzywam tylko PROBE_PORTS", _exc)

        results: dict = {}  # device_id -> RTT ms (float) lub None
        with ThreadPoolExecutor(max_workers=min(workers, len(devices))) as pool:
            futures = {
                pool.submit(_check, d.ip, device_known_ports.get(d.id)): d.id
                for d in devices
            }
            for fut in as_completed(futures):
                try:
                    results[futures[fut]] = fut.result()
                except Exception as exc:
                    logger.debug("Blad watku ping device_id=%s: %s", futures[fut], exc)
                    results[futures[fut]] = None  # traktuj jak timeout, nie DOWN (chroni _FAIL_THRESHOLD)

        up = down = 0
        up_lines = []   # "IP(RTT ms)"
        down_lines = [] # "IP"
        monitored_alerts = []  # (device, alert_type) — wyslane po db.commit()
        for device in devices:
            rtt        = results.get(device.id)   # float ms lub None
            alive      = rtt is not None
            was_active = device.is_active

            if alive:
                device.last_seen = now
                up_lines.append(f"{device.ip}({rtt}ms)")
                if not was_active:
                    device.is_active = True
                    _events_up += 1
                    logger.info("UP:   %s (%s)  RTT=%.1fms", device.ip, device.hostname or "?", rtt)
                    if device.is_monitored:
                        monitored_alerts.append((device, "online"))
                _fail_counts[device.id] = 0   # reset licznika po sukcesie
                up += 1
            else:
                _fail_counts[device.id] = _fail_counts.get(device.id, 0) + 1
                fails = _fail_counts[device.id]
                down_lines.append(device.ip)
                down += 1
                # Oznaczamy DOWN tylko po _FAIL_THRESHOLD kolejnych nieudanych probach
                # ORAZ gdy urzadzenie nie bylo widziane od dluzszego czasu
                if (was_active
                        and fails >= _FAIL_THRESHOLD
                        and device.last_seen is not None
                        and device.last_seen < inactive_threshold):
                    device.is_active = False
                    _events_down += 1
                    logger.info("DOWN: %s (%s) fail#%d od %s",
                                device.ip, device.hostname or "?",
                                fails, device.last_seen.strftime("%H:%M:%S"))
                    if device.is_monitored:
                        monitored_alerts.append((device, "offline"))
                elif was_active and fails > 0:
                    logger.debug("UNCERTAIN: %s fail#%d/%d (czekam na %d kolejnych niepowodzen)",
                                 device.ip, fails, _FAIL_THRESHOLD, _FAIL_THRESHOLD)

        db.commit()

        # Wyslij alerty dla monitorowanych urzadzen (po commit zeby device_id byl wazny)
        if monitored_alerts:
            try:
                from netdoc.notifications.telegram import send_monitoring_alert
                for dev, alert_type in monitored_alerts:
                    # Revaliduj device po commit — moglby zostac usuniety miedzy commit a alert
                    dev_live = db.query(Device).filter_by(id=dev.id).first()
                    if dev_live:
                        send_monitoring_alert(db, dev_live, alert_type)
                    else:
                        logger.warning("Alert pominieto — device %d usuniety po commit", dev.id)
            except Exception as exc:
                logger.warning("Blad wysylania alertow monitorowania: %s", exc)

        elapsed = time.monotonic() - t0
        g_up.set(up)
        g_down.set(down)
        g_total.set(len(devices))
        g_poll_time.set(round(elapsed, 2))
        g_ev_up.set(_events_up)
        g_ev_down.set(_events_down)

        up_str   = "  ".join(up_lines)   or "—"
        down_str = "  ".join(down_lines) or "—"
        logger.info(
            "Poll %d↑ %d↓ / %d  %.1fs | UP: %s | DOWN: %s",
            up, down, len(devices), elapsed, up_str, down_str,
        )

    except Exception as exc:
        logger.exception("Blad pollingu: %s", exc)
        db.rollback()
    finally:
        db.close()
    return interval  # PERF-01: zwracamy interval aby main() nie musialo go odczytywac drugi raz


def main() -> None:
    logger.info("Netdoc Ping Worker start — default_interval=%ds workers=%d metrics=:%d",
                _DEFAULT_INTERVAL, _DEFAULT_WORKERS, METRICS_PORT)
    init_db()
    start_http_server(METRICS_PORT)
    logger.info("Metryki: http://0.0.0.0:%d/metrics", METRICS_PORT)

    # PERF-02: sleep-until-next-run zamiast sleep-after-work
    # PERF-01: poll_once() zwraca interval — eliminuje drugie _read_settings()
    interval = _DEFAULT_INTERVAL
    while True:
        next_run = time.monotonic() + interval
        try:
            interval = poll_once() or interval
        except Exception as exc:
            logger.exception("Nieobsluzony wyjatek w poll_once: %s", exc)
        time.sleep(max(0.0, next_run - time.monotonic()))


if __name__ == "__main__":
    main()
