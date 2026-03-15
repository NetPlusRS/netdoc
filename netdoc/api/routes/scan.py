"""Endpoint do recznego uruchomienia discovery + pipeline.

Architektura:
  - Skanowanie dziala na hoscie Windows (run_scanner.py) — pelny dostep do sieci, ARP, nmap.
  - API zapisuje flage scan_requested do system_status, skaner ja odbiera i uruchamia scan.
  - Status skanowania dostepny przez GET /api/scan/status (odczyt z system_status).
"""
from fastapi import APIRouter, Depends, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime

from netdoc.storage.database import get_db
from netdoc.storage.models import Device, SystemStatus
from netdoc.collector.oui_lookup import oui_db

router = APIRouter(prefix="/api/scan", tags=["scan"])


class ScanStatus(BaseModel):
    status: str
    total_devices: int
    active_devices: int
    enriched_last_scan: int | None = None
    basic_only_last_scan: int | None = None
    scanner_mode: str | None = None       # "host" jesli run_scanner.py aktywny
    scanner_last_at: str | None = None    # kiedy ostatni skan
    scanner_last_devices: int | None = None
    full_scan_pending: int | None = None  # ile IP czeka na pelny skan portow


def _set_status(db, updates: dict, category: str = "scanner") -> None:
    for key, value in updates.items():
        row = db.query(SystemStatus).filter(SystemStatus.key == key).first()
        if row is None:
            row = SystemStatus(key=key, category=category, value=str(value))
            db.add(row)
        else:
            row.value = str(value)
            row.updated_at = datetime.utcnow()
    db.commit()


def _get_status(db, key: str) -> str | None:
    row = db.query(SystemStatus).filter(SystemStatus.key == key).first()
    return row.value if row else None


@router.post("/", response_model=ScanStatus, status_code=202)
def trigger_scan(db: Session = Depends(get_db)):
    """
    Zleca discovery + pipeline skanerowi hosta.
    run_scanner.py musi byc uruchomiony na hoscie Windows.
    """
    _set_status(db, {"scan_requested": "discovery"}, category="scanner")
    total = db.query(Device).count()
    active = db.query(Device).filter(Device.is_active == True).count()
    scanner_mode = _get_status(db, "scanner_mode")
    return ScanStatus(
        status="requested" if scanner_mode == "host" else "no_scanner",
        total_devices=total,
        active_devices=active,
        scanner_mode=scanner_mode,
        scanner_last_at=_get_status(db, "scanner_last_at"),
        scanner_last_devices=_safe_int(_get_status(db, "scanner_last_devices")),
    )


@router.get("/status", response_model=ScanStatus)
def scan_status(db: Session = Depends(get_db)):
    """Aktualny stan bazy + status skanera hosta."""
    total = db.query(Device).count()
    active = db.query(Device).filter(Device.is_active == True).count()
    scanner_job = _get_status(db, "scanner_job") or "-"
    status = "scanning" if scanner_job not in ("-", "", None) else "idle"
    # Ile urzadzen czeka na pelny skan portow
    try:
        from netdoc.collector.discovery import get_stale_full_scan_ips
        max_age_days = int(_get_status(db, "full_scan_max_age_days") or 7)
        full_scan_pending = len(get_stale_full_scan_ips(db, max_age_days)) if max_age_days > 0 else 0
    except Exception:
        full_scan_pending = None

    return ScanStatus(
        status=status,
        total_devices=total,
        active_devices=active,
        enriched_last_scan=_safe_int(_get_status(db, "scanner_last_enriched")),
        basic_only_last_scan=_safe_int(_get_status(db, "scanner_last_devices")),
        scanner_mode=_get_status(db, "scanner_mode"),
        scanner_last_at=_get_status(db, "scanner_last_at"),
        scanner_last_devices=_safe_int(_get_status(db, "scanner_last_devices")),
        full_scan_pending=full_scan_pending,
    )


def _safe_int(value) -> int | None:
    try:
        return int(value) if value not in (None, "-", "") else None
    except (ValueError, TypeError):
        return None


@router.post("/update-oui")
def update_oui_database(background_tasks: BackgroundTasks):
    """Pobiera aktualne bazy IEEE OUI (MA-L/MA-M/MA-S) w tle."""
    def _do_update():
        oui_db.update(timeout=60)

    background_tasks.add_task(_do_update)
    status = oui_db.status()
    return {
        "status": "update_started",
        "current_entries": status["entries"],
        "needs_update": status["needs_update"],
        "files": status["files"],
    }


@router.get("/oui-status")
def oui_status():
    """Status bazy OUI: liczba wpisow, wiek plikow, czy wymagana aktualizacja."""
    s = oui_db.status()
    ages = [f["age_days"] for f in s.get("files", {}).values() if f.get("exists") and "age_days" in f]
    s["age_days"] = round(min(ages), 1) if ages else None
    return s


@router.post("/full", status_code=202)
def trigger_full_scan(db: Session = Depends(get_db)):
    """Zleca pelny skan portow TCP 1-65535 skanerowi hosta (wolny — 10-30 min)."""
    _set_status(db, {"scan_requested": "full"}, category="scanner")
    scanner_mode = _get_status(db, "scanner_mode")
    return {
        "status": "requested" if scanner_mode == "host" else "no_scanner",
        "note": "Pelny skan TCP 1-65535 zlecony. Uruchom run_scanner.py na hoscie Windows.",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Settings — interwaly workerow (ping / SNMP)
# ─────────────────────────────────────────────────────────────────────────────

class WorkerSettings(BaseModel):
    # Ping worker
    ping_interval_s:         int   | None = None   # interwal ping workera [s], min 1
    ping_workers:            int   | None = None   # liczba rownoleglych watkow ping
    ping_inactive_after_min: int   | None = None   # po ilu minutach ciszy -> inactive
    ping_tcp_timeout:        float | None = None   # TCP timeout per port [s], domyslnie 1.5
    ping_fail_threshold:     int   | None = None   # ile kolejnych bledow = DOWN, domyslnie 3
    # SNMP worker
    snmp_interval_s:         int   | None = None   # interwal SNMP workera [s], min 10
    snmp_workers:            int   | None = None   # liczba rownoleglych watkow SNMP (urzadzenia)
    snmp_timeout_s:          int   | None = None   # timeout jednego SNMP GET [s], domyslnie 2
    snmp_community_delay_s:  int   | None = None   # opoznienie miedzy kolejnymi community [s], domyslnie 3
    snmp_debug:              int   | None = None   # loguj kazda probe community (1=tak, 0=nie)
    # Community worker
    community_interval_s:    int   | None = None   # interwal community workera [s], min 60
    community_workers:       int   | None = None   # liczba urzadzen sprawdzanych rownolegle
    community_recheck_days:  int   | None = None   # ponowne sprawdzenie po N dniach bez odpowiedzi
    # Credential worker
    cred_interval_s:         int   | None = None   # interwal cred workera [s], min 10
    cred_ssh_workers:        int   | None = None   # liczba rownoleglosci urzadzen (SSH/RDP)
    cred_web_workers:        int   | None = None   # rownoleglosc Web (wewnatrz urzadzenia)
    cred_retry_days:         int   | None = None   # co ile dni ponawiac probe
    cred_max_creds_per_dev:  int   | None = None   # max par do testowania per urzadzenie
    cred_pairs_per_cycle:    int   | None = None   # ile par probowac per urzadzenie per cykl
    cred_device_timeout_s:   int   | None = None   # max czas testowania 1 urzadzenia [s]
    cred_min_delay_s:        int   | None = None   # min opoznienie miedzy IP [s], domyslnie 2
    cred_max_delay_s:        int   | None = None   # max opoznienie miedzy IP [s], domyslnie 10
    # Vuln worker
    vuln_interval_s:         int   | None = None   # interwal vuln workera [s], min 10
    vuln_workers:            int   | None = None   # liczba rownoleglych watkow vuln
    vuln_close_after:        int   | None = None   # ile skanow bez wykrycia zamyka podatnosc
    vuln_skip_printers:      int   | None = None   # 1=pomijaj drukarki (zapobiega drukowaniu smeci)
    vuln_limit_ap_iot:       int   | None = None   # 1=ogranicz skan AP/kamer/IoT do portow sieciowych
    vuln_tcp_timeout:        float | None = None   # TCP connect timeout [s], domyslnie 3.0
    vuln_http_timeout:       float | None = None   # HTTP request timeout [s], domyslnie 5.0
    # Scanner / nmap
    nmap_min_rate:           int   | None = None   # --min-rate nmap (pakiety/s), domyslnie 100
    nmap_version_intensity:  int   | None = None   # --version-intensity nmap (0-9), domyslnie 9
    full_scan_max_age_days:  int   | None = None   # co ile dni robic pelny skan portow
    # Skanowanie partiami i rownolegle
    scan_concurrency:        int   | None = None   # max hostow jednoczesnie (0=bez limitu)
    scan_batch_size:         int   | None = None   # portow na partie — quick i full scan (0=wylaczone)
    scan_batch_pause_s:      float | None = None   # pauza miedzy partiami [s]
    scan_resume_enabled:     int   | None = None   # 1=wznawia od miejsca przerwania
    # Lab
    lab_monitoring_enabled:  int   | None = None   # 1=watchdog pilnuje kontenerow lab
    # Network discovery (nadpisuje .env gdy niepuste)
    network_ranges:          str   | None = None   # CSV zakresow CIDR do skanowania
    scan_vpn_networks:       int   | None = None   # 1=skanuj interfejsy VPN
    scan_virtual_networks:   int   | None = None   # 1=skanuj Docker/VMware/Hyper-V
    ignore_laa_macs:         int   | None = None   # 1=ignoruj MAC z lokalnie nadanym adresem (LAA)


@router.get("/settings", response_model=WorkerSettings)
def get_worker_settings(db: Session = Depends(get_db)):
    """Zwraca aktualne ustawienia workerow z bazy (system_status)."""
    def _int(key, default=None):
        v = _get_status(db, key)
        try:
            return int(v) if v not in (None, "", "-") else default
        except (ValueError, TypeError):
            return default

    def _float(key, default=None):
        v = _get_status(db, key)
        try:
            return float(v) if v not in (None, "", "-") else default
        except (ValueError, TypeError):
            return default

    def _str(key, default=None):
        v = _get_status(db, key)
        return v if v not in (None, "-") else default

    return WorkerSettings(
        ping_interval_s         = _int("ping_interval_s",          1),
        ping_workers            = _int("ping_workers",             64),
        ping_inactive_after_min = _int("ping_inactive_after_min",   5),
        ping_tcp_timeout        = _float("ping_tcp_timeout",       1.5),
        ping_fail_threshold     = _int("ping_fail_threshold",       3),
        snmp_interval_s         = _int("snmp_interval_s",         300),
        snmp_workers            = _int("snmp_workers",              10),
        snmp_timeout_s          = _int("snmp_timeout_s",             2),
        snmp_community_delay_s  = _int("snmp_community_delay_s",     3),
        snmp_debug              = _int("snmp_debug",                 1),
        community_interval_s    = _int("community_interval_s",    3600),
        community_workers       = _int("community_workers",           5),
        community_recheck_days  = _int("community_recheck_days",      7),
        cred_interval_s         = _int("cred_interval_s",          60),
        cred_ssh_workers        = _int("cred_ssh_workers",         16),
        cred_web_workers        = _int("cred_web_workers",         16),
        cred_retry_days         = _int("cred_retry_days",           1),
        cred_max_creds_per_dev  = _int("cred_max_creds_per_dev",  9999),
        cred_pairs_per_cycle    = _int("cred_pairs_per_cycle",      1),
        cred_device_timeout_s   = _int("cred_device_timeout_s",   120),
        cred_min_delay_s        = _int("cred_min_delay_s",          2),
        cred_max_delay_s        = _int("cred_max_delay_s",         10),
        full_scan_max_age_days  = _int("full_scan_max_age_days",    7),
        vuln_interval_s         = _int("vuln_interval_s",         120),
        vuln_workers            = _int("vuln_workers",             16),
        vuln_close_after        = _int("vuln_close_after",          3),
        vuln_skip_printers      = _int("vuln_skip_printers",        1),
        vuln_limit_ap_iot       = _int("vuln_limit_ap_iot",         1),
        vuln_tcp_timeout        = _float("vuln_tcp_timeout",       3.0),
        vuln_http_timeout       = _float("vuln_http_timeout",      5.0),
        nmap_min_rate           = _int("nmap_min_rate",            100),
        nmap_version_intensity  = _int("nmap_version_intensity",    9),
        scan_concurrency           = _int("scan_concurrency",              0),
        scan_batch_size            = _int("scan_batch_size",           5000),
        scan_batch_pause_s         = _float("scan_batch_pause_s",         3.0),
        scan_resume_enabled        = _int("scan_resume_enabled",          1),
        lab_monitoring_enabled  = _int("lab_monitoring_enabled",    0),
        network_ranges          = _str("network_ranges",            ""),
        scan_vpn_networks       = _int("scan_vpn_networks",         0),
        scan_virtual_networks   = _int("scan_virtual_networks",     0),
        ignore_laa_macs         = _int("ignore_laa_macs",           1),
    )


@router.put("/settings", response_model=WorkerSettings)
def update_worker_settings(body: WorkerSettings, db: Session = Depends(get_db)):
    """Zapisuje ustawienia workerow do bazy (odczytywane przez ping/snmp worker w kolejnym cyklu)."""
    updates = {}
    if body.ping_interval_s is not None:
        updates["ping_interval_s"] = max(1, body.ping_interval_s)
    if body.snmp_interval_s is not None:
        updates["snmp_interval_s"] = max(10, body.snmp_interval_s)
    if body.ping_workers is not None:
        updates["ping_workers"] = max(1, min(256, body.ping_workers))
    if body.snmp_workers is not None:
        updates["snmp_workers"] = max(1, min(100, body.snmp_workers))
    if body.ping_inactive_after_min is not None:
        updates["ping_inactive_after_min"] = max(1, body.ping_inactive_after_min)
    if body.cred_interval_s is not None:
        updates["cred_interval_s"] = max(10, body.cred_interval_s)
    if body.cred_ssh_workers is not None:
        updates["cred_ssh_workers"] = max(1, min(50, body.cred_ssh_workers))
    if body.cred_web_workers is not None:
        updates["cred_web_workers"] = max(1, min(100, body.cred_web_workers))
    if body.cred_retry_days is not None:
        updates["cred_retry_days"] = max(0, body.cred_retry_days)
    if body.cred_max_creds_per_dev is not None:
        updates["cred_max_creds_per_dev"] = max(1, body.cred_max_creds_per_dev)
    if body.cred_pairs_per_cycle is not None:
        updates["cred_pairs_per_cycle"] = max(1, min(50, body.cred_pairs_per_cycle))
    if body.cred_device_timeout_s is not None:
        updates["cred_device_timeout_s"] = max(30, min(3600, body.cred_device_timeout_s))
    if body.full_scan_max_age_days is not None:
        updates["full_scan_max_age_days"] = max(0, body.full_scan_max_age_days)
    if body.vuln_interval_s is not None:
        updates["vuln_interval_s"] = max(10, body.vuln_interval_s)
    if body.vuln_workers is not None:
        updates["vuln_workers"] = max(1, min(64, body.vuln_workers))
    if body.vuln_close_after is not None:
        updates["vuln_close_after"] = max(1, min(20, body.vuln_close_after))
    if body.vuln_skip_printers is not None:
        updates["vuln_skip_printers"] = 1 if body.vuln_skip_printers else 0
    if body.vuln_limit_ap_iot is not None:
        updates["vuln_limit_ap_iot"] = 1 if body.vuln_limit_ap_iot else 0
    if body.nmap_min_rate is not None:
        updates["nmap_min_rate"] = max(50, min(5000, body.nmap_min_rate))
    if body.nmap_version_intensity is not None:
        updates["nmap_version_intensity"] = max(0, min(9, body.nmap_version_intensity))
    if body.scan_concurrency is not None:
        updates["scan_concurrency"] = max(0, min(64, body.scan_concurrency))
    if body.scan_batch_size is not None:
        updates["scan_batch_size"] = max(0, min(65535, body.scan_batch_size))
    if body.scan_batch_pause_s is not None:
        updates["scan_batch_pause_s"] = max(0.0, min(60.0, round(body.scan_batch_pause_s, 1)))
    if body.scan_resume_enabled is not None:
        updates["scan_resume_enabled"] = 1 if body.scan_resume_enabled else 0
    if body.lab_monitoring_enabled is not None:
        updates["lab_monitoring_enabled"] = 1 if body.lab_monitoring_enabled else 0
    if body.ping_tcp_timeout is not None:
        updates["ping_tcp_timeout"] = max(0.1, min(10.0, round(body.ping_tcp_timeout, 2)))
    if body.ping_fail_threshold is not None:
        updates["ping_fail_threshold"] = max(1, min(10, body.ping_fail_threshold))
    if body.snmp_timeout_s is not None:
        updates["snmp_timeout_s"] = max(1, min(30, body.snmp_timeout_s))
    if body.snmp_community_delay_s is not None:
        updates["snmp_community_delay_s"] = max(0, min(60, body.snmp_community_delay_s))
    if body.snmp_debug is not None:
        updates["snmp_debug"] = 1 if body.snmp_debug else 0
    if body.community_interval_s is not None:
        updates["community_interval_s"] = max(60, body.community_interval_s)
    if body.community_workers is not None:
        updates["community_workers"] = max(1, min(50, body.community_workers))
    if body.community_recheck_days is not None:
        updates["community_recheck_days"] = max(1, min(365, body.community_recheck_days))
    if body.vuln_tcp_timeout is not None:
        updates["vuln_tcp_timeout"] = max(0.5, min(30.0, round(body.vuln_tcp_timeout, 2)))
    if body.vuln_http_timeout is not None:
        updates["vuln_http_timeout"] = max(0.5, min(60.0, round(body.vuln_http_timeout, 2)))
    if body.cred_min_delay_s is not None:
        updates["cred_min_delay_s"] = max(0, min(60, body.cred_min_delay_s))
    if body.cred_max_delay_s is not None:
        updates["cred_max_delay_s"] = max(1, min(120, body.cred_max_delay_s))
    if body.network_ranges is not None:
        updates["network_ranges"] = body.network_ranges.strip()
    if body.scan_vpn_networks is not None:
        updates["scan_vpn_networks"] = 1 if body.scan_vpn_networks else 0
    if body.scan_virtual_networks is not None:
        updates["scan_virtual_networks"] = 1 if body.scan_virtual_networks else 0
    if body.ignore_laa_macs is not None:
        updates["ignore_laa_macs"] = 1 if body.ignore_laa_macs else 0

    if updates:
        _set_status(db, updates, category="worker_settings")

    return get_worker_settings(db)


@router.get("/ip-batch-status")
def get_ip_batch_status():
    """Zwraca aktualny postep skanowania per IP (z pliku scan_batch_status.json).

    Uzywa: tooltips przy IP w widoku postep skanowania.
    Format: {ip: {batch: int, total: int, ports: str}}
    """
    import json
    from pathlib import Path
    path = Path(__file__).resolve().parent.parent.parent.parent / "scan_batch_status.json"
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}
