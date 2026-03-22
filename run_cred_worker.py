"""Netdoc Credential Worker - testuje SSH/Telnet/Web/FTP credentiale na urzadzeniach.

Logika:
  - Urzadzenie jest kandydatem gdy last_credential_ok_at IS NULL lub stare > RETRY_DAYS
  - SSH: paramiko, max_creds par, 8 watkow per urzadzenie
  - Web: httpx Basic Auth + form-login, porty 80/443/8080/8443
  - FTP: ftplib, anonymous + credentiale z bazy
  - Znaleziony credential zapisywany per-device
  - Interwaly przestawialne przez PUT /api/scan/settings
"""
import ftplib
import hashlib
import json as _json
import random
import re
import logging
import os
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Optional

import httpx
import paramiko
from prometheus_client import Gauge, start_http_server

from netdoc.storage.database import SessionLocal, init_db
from netdoc.storage.models import Device, Credential, CredentialMethod, SystemStatus

_LOG_FMT = "%(asctime)s [CRED] %(levelname)s %(message)s"
logging.basicConfig(level=logging.INFO, format=_LOG_FMT, stream=sys.stdout)
logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)    # wycisz INFO o kazdym HTTP request
logging.getLogger("paramiko").setLevel(logging.CRITICAL)  # wycisz "Error reading SSH protocol banner" i inne wewn. bledy paramiko

# Detekcja ochrony usług (fail2ban, rate-limit, host-block, lockout, TCP wrapper...)
# Klucz: (ip, service) → {"count": N, "port": P, "reason": str, "last": datetime}
# Wypełniany przez funkcje _try_*/discover_*, opróżniany przez _process_device().
_protection_events: dict = {}
_protection_lock = threading.Lock()

# In-memory cooldown: ip → time.monotonic() when ban expires.
# Gdy _record_protection wykryje blokadę, IP jest pomijane przez BAN_COOLDOWN_S sekund.
# Zapobiega natychmiastowemu ponawianiu prób po ban/rate-limit, co gwarantuje odblokowanie.
_ip_ban_until: dict[str, float] = {}
_BAN_COOLDOWN_S = int(os.getenv("CRED_BAN_COOLDOWN_S", "300"))  # 5 minut domyślnie


def _record_protection(ip: str, service: str, port: int, reason: str) -> None:
    """Rejestruje wykrycie ochrony aktywnej na porcie serwisu (thread-safe).
    Ustawia in-memory cooldown — IP jest pomijane przez BAN_COOLDOWN_S sekund.
    """
    with _protection_lock:
        key = (ip, service)
        evt = _protection_events.setdefault(
            key, {"count": 0, "port": port, "reason": reason, "last": None}
        )
        evt["count"] += 1
        evt["port"] = port
        evt["reason"] = reason
        evt["last"] = datetime.utcnow()
        # Cooldown: przesuń granicę do przodu (max, nie nadpisuj krótszym)
        _ip_ban_until[ip] = max(
            _ip_ban_until.get(ip, 0.0),
            time.monotonic() + _BAN_COOLDOWN_S,
        )
        logger.info(
            "PROTECTION %s service=%s reason=%s → cooldown %ds (until +%.0fs)",
            ip, service, reason, _BAN_COOLDOWN_S,
            _ip_ban_until[ip] - time.monotonic(),
        )


def _drain_protection_events(ip: str) -> list:
    """Pobiera i usuwa wszystkie zdarzenia ochrony dla danego IP."""
    with _protection_lock:
        keys = [k for k in _protection_events if k[0] == ip]
        return [(_svc, _protection_events.pop((ip, _svc))) for _svc in [k[1] for k in keys]]

# Zapisuj rowniez do pliku (dostepnego przez panel www)
_LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(_LOG_DIR, exist_ok=True)
from logging.handlers import RotatingFileHandler as _RotatingFileHandler


class _WinSafeRotatingFileHandler(_RotatingFileHandler):
    """Ignoruje PermissionError przy rotacji (Windows: OneDrive/AV blokuje plik)."""
    def doRollover(self):
        try:
            super().doRollover()
        except PermissionError:
            pass


_file_handler = _WinSafeRotatingFileHandler(
    os.path.join(_LOG_DIR, "cred.log"), encoding="utf-8",
    maxBytes=1 * 1024 * 1024, backupCount=1,  # 1MB × 1 kopia
)
_file_handler.setFormatter(logging.Formatter(_LOG_FMT))
logging.getLogger().addHandler(_file_handler)

_DEFAULT_INTERVAL        = int(os.getenv("CRED_INTERVAL_S",        "60"))
_DEFAULT_SSH_W           = int(os.getenv("CRED_SSH_WORKERS",       "16"))
_DEFAULT_WEB_W           = int(os.getenv("CRED_WEB_WORKERS",       "16"))
_DEFAULT_RETRY           = int(os.getenv("CRED_RETRY_DAYS",        "1"))
_DEFAULT_MAX_CREDS       = int(os.getenv("CRED_MAX_CREDS_PER_DEV", "9999"))  # brak limitu domyslnie
# Rotacja credentiali — stealth scanning
_DEFAULT_PAIRS_PER_CYCLE = int(os.getenv("CRED_PAIRS_PER_CYCLE",   "1"))    # par per urzadzenie per cykl
_DEFAULT_MIN_DELAY_S     = int(os.getenv("CRED_MIN_DELAY_S",       "2"))     # min opoznienie miedzy IP [s]
_DEFAULT_MAX_DELAY_S     = int(os.getenv("CRED_MAX_DELAY_S",       "10"))    # max opoznienie miedzy IP [s]
_DEFAULT_DEV_TIMEOUT_S   = int(os.getenv("CRED_DEVICE_TIMEOUT_S", "120"))   # max czas per urzadzenie [s]

# Domyslne pary SSH/Telnet probowane gdy baza nie ma global credentials
SSH_CREDENTIAL_FALLBACK = [
    ("admin",   "admin"),        ("admin",   ""),
    ("admin",   "password"),     ("admin",   "1234"),
    ("admin",   "12345"),        ("admin",   "admin123"),
    ("admin",   "cisco"),        ("admin",   "ubnt"),
    ("root",    "root"),         ("root",    ""),
    ("root",    "admin"),        ("root",    "password"),
    ("root",    "toor"),         ("root",    "alpine"),
    ("cisco",   "cisco"),        ("cisco",   "cisco123"),
    ("cisco",   "Cisco"),        ("ubnt",    "ubnt"),
    ("pi",      "raspberry"),    ("pi",      "pi"),
    ("user",    "user"),         ("user",    "password"),
    ("guest",   "guest"),        ("guest",   ""),
    ("support", "support"),      ("operator","operator"),
    ("manager", "manager"),      ("service", "service"),
]

# Telnet - te same pary co SSH (port 23)
TELNET_CREDENTIAL_FALLBACK = SSH_CREDENTIAL_FALLBACK

# API/HTTP - pary do paneli www urzadzen sieciowych i kamer
API_CREDENTIAL_FALLBACK = [
    ("admin",         "admin"),        ("admin",         ""),
    ("admin",         "password"),     ("admin",         "1234"),
    ("admin",         "12345"),        ("admin",         "admin123"),
    ("admin",         "admin1234"),    ("admin",         "cisco"),
    ("Administrator", ""),             ("Administrator", "admin"),
    ("administrator", "administrator"),("root",          ""),
    ("root",          "root"),         ("root",          "admin"),
    ("cisco",         "cisco"),        ("ubnt",          "ubnt"),
    ("supervisor",    "supervisor"),   ("admin",         "supervisor"),
    ("guest",         "guest"),        ("guest",         ""),
    ("webmaster",     "webmaster"),    ("service",       "service"),
    ("monitor",       "monitor"),      ("user",          "user"),
]

# RDP - najpopularniejsze domyslne Windows credentials
RDP_CREDENTIAL_FALLBACK = [
    # --- Brak hasla ---
    ("Administrator", ""),             ("admin",         ""),
    # --- Popularne slabe hasla Windows ---
    ("Administrator", "administrator"),("Administrator", "Admin"),
    ("Administrator", "Admin123"),     ("Administrator", "Admin@123"),
    ("Administrator", "Password1"),    ("Administrator", "P@ssw0rd"),
    ("Administrator", "Welcome1"),     ("Administrator", "changeme"),
    ("Administrator", "1234"),         ("Administrator", "12345"),
    ("Administrator", "123456"),       ("Administrator", "password"),
    ("Administrator", "Password123"),  ("Administrator", "Passw0rd"),
    ("administrator", "administrator"),("Admin",         "Admin"),
    # --- admin konto ---
    ("admin",         "admin"),        ("admin",         "Admin"),
    ("admin",         "Admin123"),     ("admin",         "password"),
    ("admin",         "Password1"),    ("admin",         "P@ssw0rd"),
    ("admin",         "1234"),         ("admin",         "12345"),
    ("admin",         "123456"),       ("admin",         "admin123"),
    # --- Vendor Windows defaults ---
    ("Administrator", "Passw0rd!"),    ("Administrator", "Dell1234"),
    ("Administrator", "HP@dmin"),      ("Administrator", "Lenovo1234"),
    ("Administrator", "Wyse"),         ("Administrator", "scada"),
    # --- NVR / VMS / OT HMI ---
    ("Administrator", "12345"),        ("Administrator", "Admin12345"),
    ("Administrator", "supervisor"),   ("operator",      "operator"),
    ("engineer",      "engineer"),     ("service",       "service"),
    # --- Sezonowe / popularne schematy ---
    ("Administrator", "Summer2023"),   ("Administrator", "Spring2024"),
    ("Administrator", "Winter2024"),   ("Administrator", "Polska1"),
    # --- Konta uzytkownikow ---
    ("user",          "user"),         ("user",          "User1234"),
    ("guest",         ""),             ("guest",         "guest"),
    ("test",          "test"),         ("test",          ""),
    ("support",       "support"),      ("helpdesk",      "helpdesk"),
    ("vagrant",       "vagrant"),      ("ansible",       "ansible"),
    ("backup",        "backup"),       ("deploy",        "deploy"),
]

# VNC - hasla (VNC nie ma nazwy uzytkownika — username="", password=haslo VNC max 8 znakow)
# Zrodla: SecLists/VNC, Shodan research, vendor HMI docs, CIRT.net
VNC_CREDENTIAL_FALLBACK = [
    # --- Brak hasla ---
    ("",  ""),
    # --- Najczestsze ---
    ("",  "password"),   ("",  "admin"),      ("",  "1234"),
    ("",  "12345"),      ("",  "123456"),     ("",  "vnc"),
    # --- Vendor HMI/SCADA ---
    ("",  "Siemens"),    ("",  "1"),          ("",  "100"),
    ("",  "Schneid"),    ("",  "Rockwell"),   ("",  "scada"),   # Schneider→8
    # --- NVR / thin client ---
    ("",  "Admin123"),   ("",  "12345"),      ("",  "TightVNC"),  # Admin12345→8
    ("",  "realvnc"),    ("",  "vncpassw"),                       # vncpasswd→8
    # --- Popularne krotkie hasla ---
    ("",  "secret"),     ("",  "pass"),       ("",  "0000"),
    ("",  "1111"),       ("",  "qwerty"),     ("",  "letmein"),
    ("",  "test"),       ("",  "root"),       ("",  "access"),
    ("",  "remote"),     ("",  "support"),    ("",  "desktop"),
    # --- Kamery/DVR piny ---
    ("",  "666666"),     ("",  "888888"),     ("",  "000000"),
    ("",  "111111"),
    # --- Raspberry Pi / IoT ---
    ("",  "raspberr"),   ("",  "pi"),         ("",  "kiosk"),    # raspberry→8
    # --- Obciecione do 8 znakow (VNC limit!) ---
    ("",  "Password"),   ("",  "passw0rd"),   ("",  "changeme"),
    ("",  "Welcome1"),
]

# FTP - dedykowana lista (poprzednio uzywano SSH_CREDENTIAL_FALLBACK — blednie!)
# Zrodla: SecLists/FTP, CIRT.net, vendor manuals, CVE research
FTP_CREDENTIAL_FALLBACK = [
    # --- Anonimowe (najczestszy problem — drukarki, NAS, kamery!) ---
    ("anonymous", ""),             ("anonymous", "anonymous"),
    ("anonymous", "ftp"),          ("ftp",       ""),
    ("ftp",       "ftp"),
    # --- Brak hasla ---
    ("admin",     ""),             ("root",      ""),
    # --- Podstawowe pary ---
    ("admin",     "admin"),        ("admin",     "password"),
    ("admin",     "1234"),         ("admin",     "12345"),
    ("root",      "root"),         ("root",      "password"),
    ("user",      "user"),         ("guest",     "guest"),
    ("guest",     ""),
    # --- Drukarki (scan-to-FTP) ---
    ("administrator",""),          ("JetDirect", ""),
    ("admin",     "hp"),           ("supervisor","supervisor"),
    ("admin",     "1111"),         ("admin",     "access"),
    # --- Kamery IP ---
    ("admin",     "12345"),        ("admin",     "Admin12345"),
    ("root",      "pass"),
    # --- NAS ---
    ("admin",     "infrant1"),     ("root",      ""),
    # --- Serwery / Windows ---
    ("Administrator",""),          ("ftpuser",   "ftpuser"),
    ("upload",    "upload"),       ("backup",    "backup"),
    # --- Routery ---
    ("cisco",     "cisco"),        ("ubnt",      "ubnt"),
    ("mikrotik",  ""),
    # --- Generic slabe ---
    ("test",      "test"),         ("support",   "support"),
    ("service",   "service"),      ("ftp",       "ftp123"),
]

# MSSQL (SQL Server) - domyslne i popularne slabe hasla
# Zrodlo: SecLists mssql-betterdefaultpasslist.txt + polskie ERP (Wapro, Insert, Optima)
# Konto 'sa' = SQL Server System Administrator (domyslne konto admin)
MSSQL_CREDENTIAL_FALLBACK = [
    # sa — domyslne konto administratora SQL Server
    ("sa",    ""),            # SQL Express — puste haslo (czeste po instalacji)
    ("sa",    "sa"),          # klasyczne slabe haslo
    ("sa",    "Wapro3000"),   # Wapro ERP (Asseco) — domyslne haslo instalatora
    ("sa",    "password"),
    ("sa",    "Password1"),
    ("sa",    "P@ssw0rd"),
    ("sa",    "Admin123"),
    ("sa",    "admin"),
    ("sa",    "admin123"),
    ("sa",    "1234"),
    ("sa",    "12345"),
    ("sa",    "sqlserver"),
    ("sa",    "Password123"),
    ("sa",    "Passw0rd"),
    ("sa",    "changeme"),
    ("sa",    "Welcome1"),
    ("sa",    "Microsoft"),
    ("sa",    "mssql"),
    ("sa",    "MSSQLSvc"),
    ("sa",    "MSSQLService"),
    # Polskie systemy ERP — domyslne hasla instalatora
    ("sa",    "Insert2019"),  # Insert GT (Subiekt GT, Rachmistrz GT)
    ("sa",    "Insert2020"),
    ("sa",    "Insert2021"),
    ("sa",    "Insert2022"),
    ("sa",    "Insert2023"),
    ("sa",    "Optima2022"),  # Comarch Optima
    ("sa",    "OptimaSA"),
    ("sa",    "Symfonia1"),   # Sage Symfonia
    # Inne konta dostawcow oprogramowania
    ("admin", "admin"),
    ("admin", ""),
    ("sa",    "Sa123456"),
    ("sa",    "Sql123456"),
]

# MySQL - domyslne i slabe credentiale
# Zrodlo: SecLists mysql-betterdefaultpasslist.txt + popularne instalacje
MYSQL_CREDENTIAL_FALLBACK = [
    ("root",  ""),            # MySQL domyslnie puste haslo root (niebezpieczne!)
    ("root",  "root"),
    ("root",  "mysql"),
    ("root",  "password"),
    ("root",  "toor"),
    ("root",  "admin"),
    ("root",  "Password1"),
    ("root",  "P@ssw0rd"),
    ("root",  "1234"),
    ("root",  "12345"),
    ("root",  "123456"),
    ("root",  "root123"),
    ("root",  "mysql123"),
    ("mysql", "mysql"),
    ("mysql", ""),
    ("admin", "admin"),
    ("admin", ""),
]

# PostgreSQL - domyslne i slabe credentiale
# Zrodlo: SecLists postgres-betterdefaultpasslist.txt
POSTGRES_CREDENTIAL_FALLBACK = [
    ("postgres", "postgres"),
    ("postgres", ""),
    ("postgres", "password"),
    ("postgres", "postgres123"),
    ("postgres", "secret"),
    ("postgres", "changeme"),
    ("postgres", "admin"),
    ("postgres", "Password1"),
    ("postgres", "P@ssw0rd"),
    ("admin",    "admin"),
    ("admin",    ""),
    ("root",     "root"),
    ("root",     ""),
]

METRICS_PORT       = int(os.getenv("CRED_METRICS_PORT",      "8003"))
_VERBOSE           = os.getenv("CRED_VERBOSE", "0").lower() not in ("0", "false", "no")

_WEB_PORTS = [80, 443, 8080, 8443, 8888, 5000, 8000, 10000]

# Porty juz obslugiwane przez standardowe discover_* - nie duplikujemy
_STANDARD_COVERED = {
    21, 22, 23, 80, 161, 443, 445, 554, 623, 1883, 2375, 2222,
    3389, 5000, 6379, 8000, 8080, 8443, 8888, 9200, 9201, 10000, 22222,
}


def _tcp_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> Optional[bytes]:
    """Probuje pobrac banner TCP (pierwsze bajty bez wysylania danych).
    Zwraca bajty (moze byc puste b"") lub None jesli port niedostepny.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(64)
            except OSError:
                return b""
    except OSError:
        return None


def _detect_service(banner: Optional[bytes], service_name: str) -> Optional[str]:
    """Wykrywa protokol na podstawie bannera TCP i nazwy serwisu (nmap).
    Zwraca: 'ssh' | 'http' | 'https' | 'ftp' | 'rdp' | 'smb' | None.
    """
    s = (service_name or "").lower()
    # Nmap rozpoznal serwis — ufamy mu (poza tcpwrapped)
    if "ssh" in s:
        return "ssh"
    if "ftp" in s:
        return "ftp"
    if "https" in s or "ssl" in s:
        return "https"
    if "http" in s or "www" in s:
        return "http"
    if "microsoft-ds" in s or "netbios" in s or "smb" in s:
        return "smb"
    # Nmap nie wiedzial — analizujemy banner
    if banner is None or not banner:
        return None
    if banner[:7] in (b"SSH-2.0", b"SSH-1.9", b"SSH-1.5"):
        return "ssh"
    if banner[:3] == b"SSH":
        return "ssh"
    if banner[:4] in (b"HTTP", b"http"):
        return "http"
    if banner[:4] in (b"220 ", b"220-"):
        return "ftp"
    # RDP: TPKT header — bajt 0=0x03, bajt 1=0x00
    if len(banner) >= 2 and banner[0] == 0x03 and banner[1] == 0x00:
        return "rdp"
    return None

g_scanned    = Gauge("netdoc_cred_scanned",      "Urzadzenia przeskanowane")
g_ssh_ok     = Gauge("netdoc_cred_ssh_ok",       "Urzadzenia z odkrytym SSH")
g_web_ok     = Gauge("netdoc_cred_web_ok",       "Urzadzenia z odkrytym Web")
g_ftp_ok     = Gauge("netdoc_cred_ftp_ok",       "Urzadzenia z odkrytym FTP")
g_rdp_ok     = Gauge("netdoc_cred_rdp_ok",       "Urzadzenia z odkrytym RDP")
g_mssql_ok   = Gauge("netdoc_cred_mssql_ok",     "Urzadzenia z odkrytym MSSQL")
g_mysql_ok   = Gauge("netdoc_cred_mysql_ok",     "Urzadzenia z odkrytym MySQL")
g_postgres_ok= Gauge("netdoc_cred_postgres_ok",  "Urzadzenia z odkrytym PostgreSQL")
g_new        = Gauge("netdoc_cred_new_total",    "Nowe credentiale lacznie")
g_duration   = Gauge("netdoc_cred_duration_s",   "Czas trwania cyklu [s]")
_total_new = 0


def _read_settings() -> tuple:
    _KEYS = (
        "cred_interval_s", "cred_ssh_workers", "cred_web_workers",
        "cred_retry_days", "cred_max_creds_per_dev", "cred_pairs_per_cycle",
        "cred_min_delay_s", "cred_max_delay_s", "cred_device_timeout_s",
    )
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

        return (max(10, _i("cred_interval_s",         _DEFAULT_INTERVAL)),
                max(1,  _i("cred_ssh_workers",        _DEFAULT_SSH_W)),
                max(1,  _i("cred_web_workers",        _DEFAULT_WEB_W)),
                max(0,  _i("cred_retry_days",         _DEFAULT_RETRY)),
                max(1,  _i("cred_max_creds_per_dev",  _DEFAULT_MAX_CREDS)),
                max(1,  _i("cred_pairs_per_cycle",    _DEFAULT_PAIRS_PER_CYCLE)),
                max(0,  _i("cred_min_delay_s",        _DEFAULT_MIN_DELAY_S)),
                max(0,  _i("cred_max_delay_s",        _DEFAULT_MAX_DELAY_S)),
                max(30, _i("cred_device_timeout_s",   _DEFAULT_DEV_TIMEOUT_S)))
    except Exception:
        return (_DEFAULT_INTERVAL, _DEFAULT_SSH_W, _DEFAULT_WEB_W,
                _DEFAULT_RETRY, _DEFAULT_MAX_CREDS,
                _DEFAULT_PAIRS_PER_CYCLE, _DEFAULT_MIN_DELAY_S,
                _DEFAULT_MAX_DELAY_S, _DEFAULT_DEV_TIMEOUT_S)
    finally:
        db.close()


def _read_method_flags() -> dict:
    """Odczytuje flagi wlaczenia/wylaczenia metod testowania (SSH/FTP/Web/RDP/DB) z DB.
    PERF-05: jedna query WHERE key IN (...) zamiast 8 osobnych SELECT.
    """
    _ALL_FLAGS = (
        "cred_ssh_enabled", "cred_ftp_enabled", "cred_web_enabled",
        "cred_rdp_enabled", "cred_vnc_enabled",
        "cred_mssql_enabled", "cred_mysql_enabled", "cred_postgres_enabled",
    )
    db = SessionLocal()
    try:
        rows = db.query(SystemStatus).filter(SystemStatus.key.in_(_ALL_FLAGS)).all()
        vals = {r.key: r.value for r in rows}
        return {k: (vals.get(k, "1") or "1") != "0" for k in _ALL_FLAGS}
    except Exception:
        return {k: True for k in _ALL_FLAGS}
    finally:
        db.close()


# Rotacja prób credentiali ─────────────────────────────────────────────────────

def _tried_db_key(device_id: int) -> str:
    return f"tried_{device_id}"


def _load_tried(device_id: int, db=None) -> dict:
    """Wczytuje juz probowane pary {method_key: set("user:pass")} z SystemStatus.
    PERF-09: opcjonalny parametr db — gdy podany, nie otwiera własnej sesji.
    """
    from netdoc.storage.models import SystemStatus
    _own_db = db is None
    if _own_db:
        db = SessionLocal()
    try:
        row = db.query(SystemStatus).filter(
            SystemStatus.key == _tried_db_key(device_id)).first()
        if row and row.value:
            raw = _json.loads(row.value)
            return {k: set(v) for k, v in raw.items()
                    if not k.startswith("_") and isinstance(v, list)}
        return {}
    except Exception:
        return {}
    finally:
        if _own_db:
            db.close()


def _save_tried(device_id: int, tried: dict) -> None:
    """Zapisuje probowane pary do SystemStatus (z timestampem ostatniej proby)."""
    from netdoc.storage.models import SystemStatus
    db = SessionLocal()
    try:
        raw = {k: list(v) for k, v in tried.items() if not k.startswith("_")}
        raw["_at"] = datetime.utcnow().isoformat()   # znacznik czasu ostatniej proby
        val = _json.dumps(raw)
        row = db.query(SystemStatus).filter(
            SystemStatus.key == _tried_db_key(device_id)).first()
        if row:
            row.value = val
        else:
            db.add(SystemStatus(key=_tried_db_key(device_id),
                                category="cred_tried", value=val))
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def _clear_tried(device_id: int, db=None) -> None:
    """Resetuje rotacje — nastepny cykl zaczyna od poczatku listy.
    PERF-09: opcjonalny parametr db — gdy podany, nie otwiera własnej sesji (nie commituje).
    """
    from netdoc.storage.models import SystemStatus
    _own_db = db is None
    if _own_db:
        db = SessionLocal()
    try:
        row = db.query(SystemStatus).filter(
            SystemStatus.key == _tried_db_key(device_id)).first()
        if row:
            db.delete(row)
            if _own_db:
                db.commit()
    except Exception:
        if _own_db:
            db.rollback()
    finally:
        if _own_db:
            db.close()


def _filter_untried(pairs: list, tried: set, n: int) -> list:
    """Zwraca pierwsze n par ktore nie zostaly jeszcze probowane."""
    result = []
    for u, p in pairs:
        if f"{u}:{p}" not in tried:
            result.append((u, p))
            if len(result) >= n:
                break
    return result


def _mark_pairs_tried(tried: dict, method_key: str, pairs: list) -> None:
    """Oznacza pary jako probowane (in-memory, przed zapisem do DB)."""
    tried.setdefault(method_key, set())
    for u, p in pairs:
        tried[method_key].add(f"{u}:{p}")


# SSH -------------------------------------------------------------------------
def _try_ssh(ip: str, port: int, username: str, password: str) -> bool:
    if _VERBOSE:
        logger.info("SSH proba %-18s port=%-5d u=%-15s p=%s", ip, port, username, password or "(puste)")
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(ip, port=port, username=username, password=password,
                  timeout=8, auth_timeout=8, banner_timeout=10,
                  allow_agent=False, look_for_keys=False)
        c.close()
        return True
    except paramiko.AuthenticationException:
        if _VERBOSE:
            logger.info("SSH FAIL  %-18s port=%-5d u=%s", ip, port, username)
        return False
    except (paramiko.ssh_exception.SSHException, EOFError) as e:
        # Połączenie zresetowane/przerwane przed banerem SSH — sygnał ochrony aktywnej
        # (fail2ban, TCP wrapper, IDS, rate-limit)
        msg = str(e).lower()
        if "banner" in msg or "eof" in msg or "reset" in msg or isinstance(e, EOFError):
            _record_protection(ip, "SSH", port, "banner-reset")
        return False
    except Exception:
        return False


def _note_protection(db, device_id: int, ip: str, service: str, evt: dict) -> None:
    """Loguje i zapisuje do asset_notes wykrycie aktywnej ochrony serwisu.

    Każdy serwis ma własny tag [SVC-PROTECTED ...] w asset_notes.
    Tagi serwisów są aktualizowane niezależnie — nie nadpisują się wzajemnie
    ani nie usuwają ręcznych notatek użytkownika.
    Pierwszy tag zawsze na początku — widoczny w popoverze MAC (limit 60 znaków).
    """
    ts  = evt["last"].strftime("%Y-%m-%d %H:%M") if evt.get("last") else "?"
    port   = evt.get("port", 0)
    count  = evt.get("count", 1)
    reason = evt.get("reason", "protection-detected")
    logger.info("PROTECTED: %-18s %s port=%d — %s x%d",
                ip, service, port, reason, count)

    tag_key  = f"{service.upper()}-PROTECTED"
    note_tag = f"[{tag_key} port={port} reason={reason} detected={ts}]"
    pattern  = rf"\[{re.escape(tag_key)}[^\]]*\]"
    try:
        import re as _re
        dev = db.query(Device).filter(Device.id == device_id).first()
        if dev is None:
            return
        current = dev.asset_notes or ""
        if _re.search(pattern, current):
            dev.asset_notes = _re.sub(pattern, note_tag, current)
        else:
            # Nowy tag — wstaw na początku żeby był widoczny w popoverze MAC
            rest = current.strip()
            dev.asset_notes = note_tag + ("\n" + rest if rest else "")
        db.commit()
        logger.info("PROTECTED: %-18s %s — zapisano w asset_notes id=%d", ip, service, device_id)
    except Exception as exc:
        logger.warning("PROTECTED: nie udało się zapisać notatki %s %s: %s", service, ip, exc)
        db.rollback()


def _process_protection_events(db, device_id: int, ip: str) -> None:
    """Przetwarza wszystkie zdarzenia ochrony zebrane podczas testu usług dla danego IP."""
    for service, evt in _drain_protection_events(ip):
        _note_protection(db, device_id, ip, service, evt)


_SSH_PORTS = (22, 2222, 22222)


def _open_ssh_ports(ip: str, open_ports: dict) -> list:
    """Zwraca liste portow SSH faktycznie otwartych.
    Najpierw sprawdza dane z ostatniego skanu, potem szybki TCP check.
    """
    if open_ports:
        # Porty SSH znane ze skanu — zaufane, nie ma potrzeby TCP probe
        known = [p for p in _SSH_PORTS if str(p) in open_ports or p in open_ports]
        if known:
            return known
        # Skan nie wykazal portow SSH — na pewno nie sa otwarte
        return []
    # Brak danych skanu — szybki TCP probe (timeout 1s)
    return [p for p in _SSH_PORTS if _tcp_open(ip, p, timeout=1.0)]


def discover_ssh(ip: str, pairs: list, open_ports: dict | None = None) -> Optional[tuple]:
    """Zwraca (user, pass) pierwszego dzialajacego SSH lub None.
    open_ports: dict z ostatniego ScanResult (klucze to numery portow jako str lub int).
    Jesli podany, testuje tylko faktycznie otwarte porty SSH.
    """
    ban_until = _ip_ban_until.get(ip, 0.0)
    if ban_until > time.monotonic():
        remaining = ban_until - time.monotonic()
        logger.info("SSH skip:  %-18s ban cooldown aktywny (jeszcze %.0fs)", ip, remaining)
        return None
    ports = _open_ssh_ports(ip, open_ports if open_ports is not None else {})
    if not ports:
        logger.info("SSH skip:  %-18s brak otwartych portow SSH", ip)
        return None
    found: list = []
    def _probe(pair):
        if found:
            return None
        for port in ports:
            if _try_ssh(ip, port, pair[0], pair[1]):
                return pair
        return None
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(pairs)))) as pool:
        for fut in as_completed({pool.submit(_probe, p): p for p in pairs}):
            r = fut.result()
            if r and not found:
                found.append(r)
    return found[0] if found else None


# Cache odpowiedzi bez auth — porownujemy z odpowiedzia z credentials
_no_auth_cache: dict = {}          # url -> (status_code, text_lower, timestamp)
_NO_AUTH_CACHE_TTL  = 300          # 5 min — odswiezaj po restarcie urzadzenia
_NO_AUTH_CACHE_MAX  = 500          # limit wpisow — zapobiega nieograniczonemu wzrostowi


def _get_no_auth(url: str) -> tuple:
    """Zwraca (status, text_lower) dla URL bez credentials (cachowane z TTL)."""
    import time as _time
    now = _time.monotonic()
    cached = _no_auth_cache.get(url)
    if cached and (now - cached[2]) < _NO_AUTH_CACHE_TTL:
        return cached[0], cached[1]
    # Evict najstarszy wpis jesli przekroczono limit
    if len(_no_auth_cache) >= _NO_AUTH_CACHE_MAX:
        oldest = min(_no_auth_cache, key=lambda k: _no_auth_cache[k][2])
        del _no_auth_cache[oldest]
    try:
        r = httpx.get(url, timeout=5, follow_redirects=True, verify=False)
        _no_auth_cache[url] = (r.status_code, r.text.lower(), now)
        return r.status_code, r.text.lower()
    except Exception:
        # Nie cachuj bledow — ponow probe przy nastepnym wywolaniu
        return 0, ""


# Web — Moxa NPort challenge-response SHA256 ------------------------------------
_ASCII_MOXA = (
    "01234567890123456789012345678901"
    " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
)
_TBL_MOXA = "0123456789abcdef"


def _moxa_encode_user(username: str, key_hex: str) -> str:
    """Reimplementacja Moxa encodePassword(username, SHA256(FakeChallenge))."""
    md_tbl = [_TBL_MOXA.rindex(key_hex[i].lower()) * 16 +
              _TBL_MOXA.rindex(key_hex[i + 1].lower())
              for i in range(0, len(key_hex), 2)]
    # rfind zwraca -1 dla znakow spoza tablicy — zastap 0 (XOR neutralny)
    pw_tbl = [max(0, _ASCII_MOXA.rfind(ch)) for ch in username]
    result = list(md_tbl)
    # Ogranicz do len(result) — username dluzszy niz klucz (32B) spowodowalby IndexError
    for i in range(min(len(pw_tbl), len(result))):
        result[i] = md_tbl[i] ^ pw_tbl[i]
    return "".join(f"{b & 0xFF:02x}" for b in result)


def _web_moxa_get_challenge(base_url: str) -> Optional[str]:
    """Pobiera FakeChallenge z panelu Moxa (1 GET). Zwraca hex lub None."""
    try:
        r0 = httpx.get(base_url + "/", timeout=4, verify=False,
                       follow_redirects=True)
        # Moxa rozne wersje: NAME="FakeChallenge" VALUE="abc" lub name=FakeChallenge value=abc
        fc_m = re.search(
            r'[Nn][Aa][Mm][Ee]=["\']?FakeChallenge["\']?\s+[Vv][Aa][Ll][Uu][Ee]=["\']?([a-fA-F0-9]+)',
            r0.text,
        )
        challenge = fc_m.group(1) if fc_m else None
        if _VERBOSE:
            logger.info("MOXA challenge %-18s port=%s -> %s",
                        base_url, base_url.rsplit(":", 1)[-1],
                        challenge[:8] + "..." if challenge else "BRAK (nie wykryto FakeChallenge)")
        return challenge
    except Exception as e:
        if _VERBOSE:
            logger.info("MOXA challenge %-18s blad: %s", base_url, e)
        return None


def _web_moxa_login(base_url: str, u: str, p: str, fake_challenge: str) -> bool:
    """Logowanie Moxa SHA256 z gotowym challenge. Zwraca True przy sukcesie."""
    try:
        enc_passwd = hashlib.sha256((u + p + fake_challenge).encode()).hexdigest()
        key = hashlib.sha256(fake_challenge.encode()).hexdigest()
        enc_user = _moxa_encode_user(u, key)
        # Probuj rozne endpointy logowania Moxa (rozne wersje firmware)
        for login_path in ("/", "/goform/formLogin", "/cgi-bin/login"):
            try:
                r1 = httpx.post(
                    base_url + login_path,
                    data={"EncPasswd": enc_passwd, "EncUser": enc_user,
                          "FakeChallenge": fake_challenge},
                    timeout=5, verify=False, follow_redirects=False,
                )
                if r1.status_code in (307, 302):
                    loc = r1.headers.get("location", "").lower()
                    if "loginok" in loc or "main" in loc or "index" in loc:
                        if _VERBOSE:
                            logger.info("MOXA login OK %-18s path=%s u=%s redirect->%s",
                                        base_url, login_path, u, loc)
                        return True
                cookie = r1.headers.get("set-cookie", "").lower()
                if "challid" in cookie or "session" in cookie:
                    if _VERBOSE:
                        logger.info("MOXA login OK %-18s path=%s u=%s cookie=%s",
                                    base_url, login_path, u, cookie[:40])
                    return True
                if _VERBOSE:
                    logger.info("MOXA login FAIL %-18s path=%s u=%s status=%d cookie=%r",
                                base_url, login_path, u, r1.status_code, cookie[:40])
            except Exception:
                continue
        return False
    except Exception:
        return False


# Web -------------------------------------------------------------------------
def _web_basic_ok(url: str, u: str, p: str) -> bool:
    try:
        r = httpx.get(url, auth=(u, p), timeout=3, follow_redirects=True, verify=False)
        if r.status_code == 429:
            # 429 Too Many Requests = rate-limit / WAF aktywny
            from urllib.parse import urlparse as _up
            _h = _up(url).hostname or ""
            if _h:
                _record_protection(_h, "Web", _up(url).port or 80, "http-429-rate-limit")
            return False
        if r.status_code not in (200, 201, 204):
            return False
        t = r.text.lower()
        bad = ("invalid password", "login failed", "access denied",
               "authentication failed", "unauthorized", "incorrect password",
               "wrong password", "bad credentials", "bledne haslo", "bledny login")
        ok  = ("logout", "dashboard", "hostname", "system info",
               "sign out", "wyloguj", "configuration", "firmware", "uptime")
        if any(w in t for w in bad):
            return False

        # Silny sygnal: Set-Cookie z nazwa sesji — prawie zawsze oznacza prawdziwe logowanie
        set_cookie = r.headers.get("set-cookie", "").lower()
        session_cookie = any(kw in set_cookie for kw in
                             ("session", "sid", "token", "auth", "jsessionid", "phpsessid"))

        # Sygnal sredni: slowa kluczowe w tresci
        has_ok_keyword = any(w in t for w in ok)

        if not session_cookie and not has_ok_keyword:
            return False

        # Sprawdz ze odpowiedz z credentials jest INNA niz bez credentials
        # (zapobiega false positive gdy urzadzenie zawsze zwraca 200)
        no_auth_status, no_auth_text = _get_no_auth(url)
        if no_auth_status == r.status_code and no_auth_text == t:
            return False   # identyczna odpowiedz → brak prawdziwej autoryzacji

        # Dodatkowe sprawdzenie: odpowiedz musi byc wyraznie rozna (min. 5% roznica dlugosci)
        if no_auth_text and len(t) > 0:
            ratio = abs(len(t) - len(no_auth_text)) / max(len(t), len(no_auth_text))
            if ratio < 0.05 and not session_cookie:
                return False  # tresci prawie identyczne i brak cookie sesji → false positive

        # Jesli OK-keyword jest tez w no-auth page — samo slowo nie wystarczy (wymaga cookie sesji)
        # Przyklad: strony logowania z id="logoutmenu" w HTML zawsze maja "logout" w tresci
        if has_ok_keyword and not session_cookie:
            if any(w in no_auth_text for w in ok):
                return False  # keyword obecny takze bez auth → nie swiadczy o zalogowaniu

        return True
    except Exception:
        pass
    return False


def _web_form_ok(url: str, u: str, p: str) -> bool:
    # Pobierz odpowiedz bez credentials (baseline do porownania — zapobiega false positive)
    no_auth_status, no_auth_text = _get_no_auth(url)
    # Tylko 2 najpopularniejsze kombinacje pol formularza (minimalizuje czas skanowania)
    for uf in ("username", "user"):
        for pf in ("password", "pass"):
            try:
                r = httpx.post(url, data={uf: u, pf: p},
                               timeout=2, follow_redirects=True, verify=False)
                if r.status_code == 429:
                    from urllib.parse import urlparse as _up2
                    _h2 = _up2(url).hostname or ""
                    if _h2:
                        _record_protection(_h2, "Web", _up2(url).port or 80, "http-429-rate-limit")
                    return False
                if r.status_code == 200:
                    t = r.text.lower()
                    ok_  = ("logout", "dashboard", "welcome", "hostname")
                    bad_ = ("login failed", "invalid", "incorrect")
                    if any(w in t for w in ok_) and not any(w in t for w in bad_):
                        # Sprawdz ze odpowiedz z credentials jest INNA niz bez credentials
                        # (zapobiega false positive gdy SPA zawiera "logout" w JS na stronie logowania)
                        if no_auth_text and t == no_auth_text:
                            continue  # identyczna odpowiedz → brak prawdziwej autoryzacji
                        ratio = (abs(len(t) - len(no_auth_text)) / max(len(t), len(no_auth_text), 1)
                                 if no_auth_text else 1.0)
                        if ratio < 0.05:
                            continue  # tresci prawie identyczne → false positive
                        # Jesli OK-keyword jest tez w no-auth page — nie swiadczy o zalogowaniu
                        if no_auth_text and any(w in no_auth_text for w in ok_):
                            continue
                        return True
                elif r.status_code in (302, 301):
                    # Redirect po POST = prawdopodobnie sukces logowania
                    loc = r.headers.get("location", "").lower()
                    if any(w in loc for w in ("main", "index", "dashboard", "home")):
                        return True
            except Exception:
                pass
    return False


def _web_goahead_get_token(base: str) -> Optional[str]:
    """Pobiera token sesji GoAhead-Webs z naglowka Location (np. /csfec05640/).
    Cisco SF/SG/CBS switche uzywaja GoAhead — redirect do /<token>/ zamiast strony logowania.
    Zwraca token (np. 'csfec05640') lub None jesli nie jest GoAhead."""
    try:
        r = httpx.get(f"{base}/", timeout=3, verify=False, follow_redirects=False)
        srv = r.headers.get("server", "").lower()
        if "goahead" not in srv:
            return None
        loc = r.headers.get("location", "")
        # Token: segment sciezki alfanumeryczny 6+ znakow (np. csfec05640, a1b2c3d4)
        m = re.search(r'/([a-zA-Z0-9]{6,})/?(?:\?|$)', loc)
        if not m:
            m = re.search(r'/([a-zA-Z0-9]{6,})/', loc)
        return m.group(1) if m else None
    except Exception:
        return None


def _web_goahead_ok(base: str, token: str, u: str, p: str) -> bool:
    """Logowanie do Cisco SF/SG/CBS (GoAhead-Webs) przez XML API.
    Endpoint: GET /<token>/System.xml?action=login&user=USER&password=PASS&ssd=true
    Sukces: <statusCode>0</statusCode> w odpowiedzi XML."""
    try:
        url = f"{base}/{token}/System.xml?action=login&user={u}&password={p}&ssd=true&"
        r = httpx.get(url, timeout=5, verify=False, follow_redirects=False)
        return r.status_code == 200 and "<statusCode>0</statusCode>" in r.text
    except Exception:
        return False


def _web_detect_auth(ip: str, open_ports: list) -> bool:
    """Quick probe bez credentials: czy urzadzenie ma jakikolwiek mechanizm logowania?
    Sprawdza: WWW-Authenticate header, pola type=password, FakeChallenge (Moxa), GoAhead-Webs.
    Zwraca True jesli wykryto dowolny wskaznik — warto probowac credentials.
    Zwraca False jesli brak strony logowania (np. Philips Hue API, czysty JSON itp.)."""
    for port in open_ports:
        scheme = "https" if port in (443, 8443) else "http"
        base = f"{scheme}://{ip}:{port}"
        try:
            r = httpx.get(f"{base}/", timeout=3, verify=False,
                          follow_redirects=False)
            if r.headers.get("www-authenticate"):
                return True
            if "goahead" in r.headers.get("server", "").lower():
                return True  # GoAhead-Webs: Cisco SF/SG/CBS — redirect bez body
            r2 = httpx.get(f"{base}/", timeout=3, verify=False,
                           follow_redirects=True)
            body = r2.text
            if re.search(r'type=["\']?password', body, re.IGNORECASE):
                return True
            if re.search(r'FakeChallenge', body, re.IGNORECASE):
                return True
        except Exception:
            pass
    return False


def discover_web(ip: str, pairs: list,
                 open_ports_hint: Optional[list] = None) -> Optional[tuple]:
    # Wykryj Moxa challenge raz per port — unikamy N GET-ow dla N par
    _moxa_challenge: dict = {}   # port -> challenge str lub None

    def _get_challenge(base: str, port: int) -> Optional[str]:
        if port not in _moxa_challenge:
            _moxa_challenge[port] = _web_moxa_get_challenge(base)
        return _moxa_challenge[port]

    ban_until = _ip_ban_until.get(ip, 0.0)
    if ban_until > time.monotonic():
        remaining = ban_until - time.monotonic()
        logger.info("WEB skip:  %-18s ban cooldown aktywny (jeszcze %.0fs)", ip, remaining)
        return None
    # Uzyj portow przekazanych przez wywolujacego (juz sprawdzonych) albo sprawdz sam
    _open_web_ports: list = open_ports_hint if open_ports_hint is not None \
        else [p for p in _WEB_PORTS if _tcp_open(ip, p, timeout=1.5)]
    if not _open_web_ports:
        return None
    if _VERBOSE:
        logger.info("WEB porty %-18s otwarte: %s", ip, _open_web_ports)

    # Wykryj GoAhead token raz per port (Cisco SF/SG/CBS switche)
    _goahead_token: dict = {}  # port -> token str lub None
    def _get_goahead_token(base: str, port: int) -> Optional[str]:
        if port not in _goahead_token:
            _goahead_token[port] = _web_goahead_get_token(base)
        return _goahead_token[port]

    found: list = []
    def _probe(pair):
        if found:
            return None
        u, p = pair
        if _VERBOSE:
            logger.info("WEB proba %-18s u=%-15s p=%s", ip, u, p or "(puste)")
        for port in _open_web_ports:
            scheme = "https" if port in (443, 8443) else "http"
            base = f"{scheme}://{ip}:{port}"
            if _web_basic_ok(base, u, p):
                if _VERBOSE:
                    logger.info("WEB OK    %-18s port=%-5d u=%s (basic auth)", ip, port, u)
                return pair
            challenge = _get_challenge(base, port)
            if challenge and _web_moxa_login(base, u, p, challenge):
                if _VERBOSE:
                    logger.info("WEB OK    %-18s port=%-5d u=%s (moxa challenge)", ip, port, u)
                return pair
            token = _get_goahead_token(base, port)
            if token and _web_goahead_ok(base, token, u, p):
                if _VERBOSE:
                    logger.info("WEB OK    %-18s port=%-5d u=%s (goahead/cisco)", ip, port, u)
                return pair
            for path in ("/", "/login", "/admin", "/management"):
                if _web_form_ok(f"{base}{path}", u, p):
                    if _VERBOSE:
                        logger.info("WEB OK    %-18s port=%-5d u=%s (form %s)", ip, port, u, path)
                    return pair
        return None
    with ThreadPoolExecutor(max_workers=min(16, max(1, len(pairs)))) as pool:
        for fut in as_completed({pool.submit(_probe, p): p for p in pairs}):
            r = fut.result()
            if r and not found:
                found.append(r)
    return found[0] if found else None


# FTP -------------------------------------------------------------------------
def discover_ftp(ip: str, pairs: list) -> Optional[tuple]:
    try:
        with socket.create_connection((ip, 21), timeout=2):
            pass
    except OSError:
        return None
    found: list = []
    all_pairs = [("anonymous", "")] + [(u, p) for u, p in pairs if u != "anonymous"]
    def _probe(pair):
        if found:
            return None
        u, p = pair
        if _VERBOSE:
            logger.info("FTP proba %-18s port=21    u=%-15s p=%s", ip, u, p or "(puste)")
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, 21, timeout=5)
            ftp.login(u, p)
            ftp.quit()
            if _VERBOSE:
                logger.info("FTP OK    %-18s u=%s", ip, u)
            return pair
        except ftplib.error_perm:
            if _VERBOSE:
                logger.info("FTP FAIL  %-18s u=%s (error_perm)", ip, u)
            return None
        except ftplib.error_temp as e:
            # Kod 421 "Too many connections" = rate-limit aktywny
            if "421" in str(e) or "too many" in str(e).lower():
                _record_protection(ip, "FTP", 21, "too-many-connections")
            return None
        except Exception:
            return None
    with ThreadPoolExecutor(max_workers=min(8, len(all_pairs))) as pool:
        for fut in as_completed({pool.submit(_probe, p): p for p in all_pairs}):
            r = fut.result()
            if r and not found:
                found.append(r)
    return found[0] if found else None



# VNC (porty 5900-5909) --------------------------------------------------------
# Protokol RFB (Remote Framebuffer). Autentykacja VNC Security (type 2):
#   serwer wysyla 16B challenge → klient szyfruje DES(password, challenge) → serwer ocenia.
# DES key = haslo VNC (max 8 znakow), bity kazdego bajtu odwrocone (MSB→LSB).
_VNC_PORTS = (5900, 5901, 5902, 5903)


def _vnc_encrypt_password(password: str) -> bytes:
    """Przygotowuje 8-bajtowy klucz DES z hasla VNC (bity odwrocone per bajt)."""
    key = (password[:8] + "\x00" * 8)[:8].encode("latin-1", errors="replace")
    reversed_key = bytes(int(f"{b:08b}"[::-1], 2) for b in key)
    return reversed_key


def _vnc_check_password(ip: str, port: int, password: str, timeout: float = 5.0) -> bool:
    """Probuje haslo VNC na danym porcie. Zwraca True jesli zalogowano.

    Implementacja RFB 3.3 / 3.7 / 3.8 VNC Security (type 2).
    Puste haslo: probujemy typ 1 (None auth) — serwer nie wymaga hasla.
    """
    try:
        from Crypto.Cipher import DES  # pycryptodome

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            # Handshake: serwer wysyla wersje "RFB 003.NNN\n"
            server_ver = sock.recv(12)
            if not server_ver.startswith(b"RFB "):
                return False
            # Wyslij ta sama wersje (lub 3.3)
            sock.sendall(server_ver if server_ver[4:7] >= b"003" else b"RFB 003.003\n")

            if server_ver[4:11] >= b"003.007":
                # RFB 3.7+: serwer wysyla liste typow bezpieczenstwa
                n_types = sock.recv(1)[0]
                if n_types == 0:
                    return False  # serwer odrzucil polaczenie
                sec_types = list(sock.recv(n_types))
                if not password and 1 in sec_types:
                    # Typ 1 = None auth — brak hasla
                    sock.sendall(bytes([1]))
                    if server_ver[4:11] >= b"003.008":
                        result = int.from_bytes(sock.recv(4), "big")
                        return result == 0
                    return True
                if 2 not in sec_types:
                    return False  # serwer nie oferuje VNC auth
                sock.sendall(bytes([2]))  # wybieramy VNC Security
            else:
                # RFB 3.3: serwer wysyla 4-bajtowy typ
                sec_type = int.from_bytes(sock.recv(4), "big")
                if sec_type == 1 and not password:
                    return True  # None auth — brak hasla
                if sec_type != 2:
                    return False

            # VNC Security: serwer wysyla 16B challenge
            challenge = sock.recv(16)
            if len(challenge) != 16:
                return False

            # Szyfrowanie DES: zaszyfruj challenge kluczem (odwrocone bity hasla)
            key = _vnc_encrypt_password(password or "")
            cipher = DES.new(key, DES.MODE_ECB)
            response = cipher.encrypt(challenge[:8]) + cipher.encrypt(challenge[8:])
            sock.sendall(response)

            # Wynik autoryzacji (4B: 0=OK, 1=fail)
            auth_result = int.from_bytes(sock.recv(4), "big")
            return auth_result == 0

    except Exception:
        return False


def discover_vnc(ip: str, pairs: list, ports: tuple = _VNC_PORTS) -> Optional[tuple]:
    """Sprawdza hasla VNC na portach 5900-5903. Zwraca (username, password) lub None.

    VNC nie uzywa nazwy uzytkownika — pairs zawieraja ("", haslo).
    Najpierw sprawdza brak hasla (None auth), potem probuje po kolei.
    """
    # Znajdz otwarty port VNC
    open_port = None
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=2):
                open_port = port
                break
        except OSError:
            continue
    if open_port is None:
        return None

    # Zbierz unikalne hasla (VNC = tylko haslo, bez usera)
    passwords = []
    seen: set = set()
    for u, p in pairs:
        if p not in seen:
            seen.add(p)
            passwords.append((u, p))

    for u, p in passwords:
        if _VERBOSE:
            logger.info("VNC proba %-18s port=%-5d p=%s", ip, open_port, p or "(puste)")
        if _vnc_check_password(ip, open_port, p):
            if _VERBOSE:
                logger.info("VNC OK    %-18s port=%-5d p=%s", ip, open_port, p or "(puste)")
            return (u, p)
    return None


# Telnet (port 23) -------------------------------------------------------------
_TELNET_PORTS = (23, 2323)


def discover_telnet(ip: str, pairs: list) -> Optional[tuple]:
    """Sprawdza Telnet credentials (port 23, 2323). Zwraca (user, pass) lub None.

    Telnet jest nieszyfrowany — dane logowania przesylane plaintext.
    Typowe urzadzenia: starsze routery/switche Cisco, MikroTik, kamery IP,
    drukarki, UPS-y i inne urzadzenia sieciowe bez SSH.

    Strategia: wyslij username + password i sprawdz czy baner powitalny
    wskazuje na sukces (prompt '$', '#', '>', brak 'Login incorrect' itp.).
    """
    open_port = None
    for port in _TELNET_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=2):
                open_port = port
                break
        except OSError:
            continue
    if open_port is None:
        return None

    found: list = []

    def _probe(pair):
        if found:
            return None
        u, p = pair
        if _VERBOSE:
            logger.info("TEL proba %-18s port=%-5d u=%-15s p=%s", ip, open_port, u, p or "(puste)")
        try:
            import telnetlib
            tn = telnetlib.Telnet(ip, open_port, timeout=6)
            # Czekaj na prompt logowania (max 4s)
            banner = tn.read_until(b"ogin:", timeout=4)
            if b"ogin:" not in banner and b"sername:" not in banner:
                # Brak prompta logowania — moze byc otwarty shell lub nieznany protokol
                tn.close()
                return None
            tn.write(u.encode("latin-1", errors="replace") + b"\n")
            # Czekaj na prompt hasla
            pw_prompt = tn.read_until(b"assword:", timeout=4)
            if b"assword:" not in pw_prompt:
                tn.close()
                return None
            tn.write(p.encode("latin-1", errors="replace") + b"\n")
            # Czekaj na odpowiedz (max 4s) — sukces lub blad
            response = tn.read_until(b"#", timeout=4)
            if not response:
                response = tn.read_very_eager()
            tn.close()
            resp_lower = response.lower()
            # Sprawdz negatywne wskazniki
            deny_keywords = (
                b"incorrect", b"invalid", b"failed", b"denied",
                b"bad password", b"wrong", b"failure",
            )
            if any(kw in resp_lower for kw in deny_keywords):
                if _VERBOSE:
                    logger.info("TEL FAIL  %-18s u=%s (deny keyword)", ip, u)
                return None
            # Sprawdz pozytywne wskazniki — prompt CLI
            ok_patterns = (b"#", b"$", b">", b"~", b"% ")
            if any(response.endswith(p2) or p2 in response[-20:] for p2 in ok_patterns):
                if _VERBOSE:
                    logger.info("TEL OK    %-18s u=%s", ip, u)
                return pair
            return None
        except EOFError:
            # Serwer rozlaczyl bez prompta — zly login lub timeout
            return None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=min(4, len(pairs))) as pool:
        for fut in as_completed({pool.submit(_probe, p): p for p in pairs}):
            r = fut.result()
            if r and not found:
                found.append(r)
    return found[0] if found else None


# RDP (via SMB port 445 - same Windows credentials) ---------------------------
def discover_rdp(ip: str, pairs: list) -> Optional[tuple]:
    """Sprawdza Windows credentials przez SMB (port 445). Zwraca (user, pass) lub None."""
    try:
        with socket.create_connection((ip, 445), timeout=2):
            pass
    except OSError:
        return None
    found: list = []
    def _probe(pair):
        if found:
            return None
        u, p = pair
        if _VERBOSE:
            logger.info("RDP proba %-18s port=445   u=%-15s p=%s", ip, u, p or "(puste)")
        try:
            from impacket.smbconnection import SMBConnection
            smb = SMBConnection(ip, ip, timeout=5)
            smb.login(u, p)
            smb.logoff()
            if _VERBOSE:
                logger.info("RDP OK    %-18s u=%s (SMB login)", ip, u)
            return pair
        except Exception as exc:
            # STATUS_ACCOUNT_LOCKED_OUT = konto zablokowane po zbyt wielu próbach logowania
            err_str = str(exc)
            if "ACCOUNT_LOCKED_OUT" in err_str or "0xC0000234" in err_str:
                _record_protection(ip, "RDP", 445, "account-locked-out")
            if _VERBOSE:
                logger.info("RDP FAIL  %-18s u=%-15s err=%s", ip, u, type(exc).__name__)
            return None
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(pairs)))) as pool:
        for fut in as_completed({pool.submit(_probe, pr): pr for pr in pairs}):
            r = fut.result()
            if r and not found:
                found.append(r)
    return found[0] if found else None



# Non-standard port discovery ------------------------------------------------
def _get_device_open_ports(device_id: int, db=None) -> dict:
    """Zwraca {int_port: info_dict} z ostatniego ScanResult urzadzenia.
    PERF-09: opcjonalny parametr db — gdy podany, nie otwiera własnej sesji.
    """
    from netdoc.storage.models import ScanResult
    _own_db = db is None
    if _own_db:
        db = SessionLocal()
    try:
        sr = (db.query(ScanResult)
              .filter(ScanResult.device_id == device_id)
              .order_by(ScanResult.scan_time.desc()).first())
        if sr and sr.open_ports:
            return {int(p): v for p, v in sr.open_ports.items()}
        return {}
    finally:
        if _own_db:
            db.close()


def _ports_hash(ports: dict) -> str:
    return hashlib.md5(_json.dumps(sorted(ports.keys())).encode()).hexdigest()[:12]


def _get_port_hash(device_id: int, db=None) -> str:
    from netdoc.storage.models import SystemStatus
    _own = db is None
    if _own:
        db = SessionLocal()
    try:
        r = db.query(SystemStatus).filter(
            SystemStatus.key == f"portcred_{device_id}_hash").first()
        return r.value if r else ""
    finally:
        if _own:
            db.close()


def _set_port_hash(device_id: int, h: str, db=None) -> None:
    from netdoc.storage.models import SystemStatus
    _own = db is None
    if _own:
        db = SessionLocal()
    try:
        r = db.query(SystemStatus).filter(
            SystemStatus.key == f"portcred_{device_id}_hash").first()
        if r:
            r.value = h
        else:
            db.add(SystemStatus(key=f"portcred_{device_id}_hash",
                                category="portcred", value=h))
        if _own:
            db.commit()
    except Exception:
        if _own:
            db.rollback()
    finally:
        if _own:
            db.close()


def _services_to_try(service_name: str, banner: Optional[bytes] = None) -> list:
    """Na podstawie nazwy serwisu (nmap) i opcjonalnego bannera TCP
    zwraca liste protokolow do przetestowania (od najbardziej prawdopodobnego).
    """
    detected = _detect_service(banner, service_name)
    if detected == "ssh":
        return ["ssh"]
    if detected == "ftp":
        return ["ftp", "http", "https"]
    if detected == "https":
        return ["https", "http", "ssh"]
    if detected == "http":
        return ["http", "https", "ssh"]
    if detected == "rdp":
        return ["smb"]
    if detected == "smb":
        return ["smb"]
    # Banner nie pomogł — heurystyki po nazwie
    s = (service_name or "").lower()
    if "tcpwrapped" in s:
        return ["http", "https", "ssh", "ftp"]
    # Całkowicie nieznana usluga
    return ["http", "https", "ssh", "ftp", "smb"]


def _probe_port(ip: str, port: int, service_name: str,
                ssh_pairs: list, web_pairs: list, rdp_pairs: list,
                banner: Optional[bytes] = None) -> Optional[tuple]:
    """Probuje wszystkie sensowne uslugi na podanym porcie.
    banner: opcjonalny wynik _grab_banner() dla lepszego wykrycia protokolu.
    Zwraca (CredentialMethod, user, pass) lub None.
    """
    MAX = 8  # max par per service type (ograniczamy by nie bylo za wolno)
    for svc in _services_to_try(service_name, banner=banner):
        if svc == "ssh":
            for u, p in ssh_pairs[:MAX]:
                if _try_ssh(ip, port, u, p):
                    return (CredentialMethod.ssh, u, p)
        elif svc in ("http", "https"):
            base = f"{svc}://{ip}:{port}"
            for u, p in web_pairs[:MAX]:
                try:
                    if _web_basic_ok(base, u, p):
                        return (CredentialMethod.api, u, p)
                    for path in ("/", "/login", "/admin", "/management"):
                        if _web_form_ok(f"{base}{path}", u, p):
                            return (CredentialMethod.api, u, p)
                except Exception:
                    pass
        elif svc == "ftp":
            for u, p in ssh_pairs[:MAX]:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(ip, port, timeout=4)
                    ftp.login(u, p)
                    ftp.quit()
                    return (CredentialMethod.api, u, p)
                except ftplib.error_perm:
                    pass
                except Exception:
                    break  # port nie jest FTP
        elif svc == "smb":
            for u, p in rdp_pairs[:MAX]:
                try:
                    from impacket.smbconnection import SMBConnection
                    smb = SMBConnection(ip, ip, sess_port=port, timeout=4)
                    smb.login(u, p)
                    smb.logoff()
                    return (CredentialMethod.rdp, u, p)
                except Exception:
                    pass
    return None


def _should_probe_port(port: int, info) -> bool:
    """Czy dany port powinien byc sprawdzony przez banner-based probe?
    - Niestandardowe porty: zawsze
    - Standardowe porty: tylko gdy service nieznany (tcpwrapped lub brak)
    """
    svc = (info or {}).get("service", "") if isinstance(info, dict) else ""
    if port not in _STANDARD_COVERED:
        return True   # niestandardowy → zawsze sprawdzamy
    # Standardowy port ze ZNANA usluga → juz obslugiwany przez discover_*
    if svc and "tcpwrapped" not in svc.lower():
        return False
    # Standardowy port z tcpwrapped / pustym service → moze byc inny protokol
    return True


def _probe_nonstandard_ports(ip: str, open_ports: dict,
                              ssh_pairs: list, web_pairs: list,
                              rdp_pairs: list) -> list:
    """Probuje porty z nieznanym serwisem (niestandardowe i standardowe z tcpwrapped).
    Uzywa banner TCP do wykrycia prawdziwego protokolu.
    Zwraca liste (CredentialMethod, user, pass).
    """
    candidates = {p: v for p, v in open_ports.items() if _should_probe_port(p, v)}
    if not candidates:
        return []
    results = []
    for port, info in candidates.items():
        if not _tcp_open(ip, port, timeout=2.0):
            continue
        svc_name = (info or {}).get("service", "") if isinstance(info, dict) else ""
        # Dla nieznanych / tcpwrapped portow probujemy wykryc serwis z bannera
        banner = None
        if not svc_name or "tcpwrapped" in svc_name.lower():
            banner = _grab_banner(ip, port)
            detected = _detect_service(banner, svc_name)
            logger.info("BANNER %d %-18s svc=%r banner=%r detected=%s",
                        port, ip, svc_name or "-", (banner or b"")[:16], detected or "?")
        r = _probe_port(ip, port, svc_name, ssh_pairs, web_pairs, rdp_pairs, banner=banner)
        if r:
            logger.info("PORT %d OK: %-18s method=%s user=%s", port, ip, r[0], r[1])
            results.append(r)
    return results

# MSSQL -----------------------------------------------------------------------
def _try_mssql(ip: str, port: int, username: str, password: str) -> bool:
    """Proba logowania do SQL Server przez TDS (impacket). Zwraca True jesli OK."""
    try:
        from impacket.tds import MSSQL
        ms = MSSQL(ip, port)
        ms.connect()
        result = ms.login("master", username, password, None, None, False)
        ms.disconnect()
        return bool(result)
    except ImportError:
        return False
    except Exception:
        return False


def discover_mssql(ip: str, pairs: list, port: int = 1433) -> Optional[tuple]:
    """Zwraca (user, pass) pierwszego dzialajacego MSSQL lub None."""
    if not _tcp_open(ip, port, timeout=2.0):
        return None
    for u, p in pairs:
        if _VERBOSE:
            logger.info("MSSQL proba %-18s port=%-5d u=%-15s p=%s", ip, port, u, p or "(puste)")
        if _try_mssql(ip, port, u, p):
            logger.info("MSSQL OK:  %-18s user=%s", ip, u)
            return (u, p)
    return None


# MySQL -----------------------------------------------------------------------
def _try_mysql(ip: str, port: int, username: str, password: str) -> bool:
    """Proba logowania do MySQL przez pymysql. Zwraca True jesli OK."""
    try:
        import pymysql
        conn = pymysql.connect(
            host=ip, port=port, user=username, password=password,
            database="mysql", connect_timeout=4, read_timeout=4,
        )
        conn.close()
        return True
    except ImportError:
        return False
    except pymysql.err.OperationalError as e:
        # errno 1129: "Host is blocked because of many connection errors" = ochrona aktywna
        if e.args and e.args[0] == 1129:
            _record_protection(ip, "MySQL", port, "host-blocked")
        # errno 1045: "Access denied" — normalny zły login
        return False
    except Exception:
        return False


def discover_mysql(ip: str, pairs: list, port: int = 3306) -> Optional[tuple]:
    """Zwraca (user, pass) pierwszego dzialajacego MySQL lub None."""
    if not _tcp_open(ip, port, timeout=2.0):
        return None
    for u, p in pairs:
        if _VERBOSE:
            logger.info("MySQL proba %-18s port=%-5d u=%-15s p=%s", ip, port, u, p or "(puste)")
        if _try_mysql(ip, port, u, p):
            logger.info("MySQL OK:  %-18s user=%s", ip, u)
            return (u, p)
    return None


# PostgreSQL ------------------------------------------------------------------
def _try_postgres(ip: str, port: int, username: str, password: str) -> bool:
    """Proba logowania do PostgreSQL przez psycopg2. Zwraca True jesli OK."""
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=ip, port=port, user=username, password=password,
            dbname="postgres", connect_timeout=4,
        )
        conn.close()
        return True
    except ImportError:
        return False
    except psycopg2.OperationalError as e:
        msg = str(e).lower()
        # "pg_hba.conf rejects connection" = IP nie na whitelist = celowa blokada
        if "pg_hba" in msg:
            _record_protection(ip, "PgSQL", port, "pg-hba-reject")
        return False
    except Exception:
        return False


def discover_postgres(ip: str, pairs: list, port: int = 5432) -> Optional[tuple]:
    """Zwraca (user, pass) pierwszego dzialajacego PostgreSQL lub None."""
    if not _tcp_open(ip, port, timeout=2.0):
        return None
    for u, p in pairs:
        if _VERBOSE:
            logger.info("PgSQL proba %-18s port=%-5d u=%-15s p=%s", ip, port, u, p or "(puste)")
        if _try_postgres(ip, port, u, p):
            logger.info("PgSQL OK:  %-18s user=%s", ip, u)
            return (u, p)
    return None


# DB --------------------------------------------------------------------------
def _reverify_existing_creds(db, device_id: int, ip: str) -> None:
    """Re-weryfikuje zapisane credentials dla urzadzenia.

    Gdy urzadzenie wraca do skanowania (po retry_days), sprawdza czy wczesniej
    wykryte credentials nadal dzialaja. Usuwa te ktore sa false positive lub
    przeterminowane. Jesli wszystkie usuniete → resetuje last_credential_ok_at.
    """
    saved = db.query(Credential).filter(Credential.device_id == device_id).all()
    if not saved:
        return

    open_web: list = []
    any_valid = False

    for cred in list(saved):
        u = cred.username or ""
        p = cred.password_encrypted or ""
        valid = False

        try:
            if cred.method == CredentialMethod.api:
                if not open_web:
                    open_web = [port for port in _WEB_PORTS if _tcp_open(ip, port, timeout=1.5)]
                for port in open_web:
                    scheme = "https" if port in (443, 8443) else "http"
                    if _web_basic_ok(f"{scheme}://{ip}:{port}", u, p):
                        valid = True
                        break
                    # Sprawdz tez form login jesli basic nie zadziala
                    if not valid:
                        for path in ("/", "/login", "/admin"):
                            if _web_form_ok(f"{scheme}://{ip}:{port}{path}", u, p):
                                valid = True
                                break
                    if valid:
                        break

            elif cred.method == CredentialMethod.ssh:
                valid = _try_ssh(ip, 22, u, p)

            elif cred.method == CredentialMethod.telnet:
                result = discover_telnet(ip, [(u, p)])
                valid = result is not None

            # Inne metody (snmp, rdp, mssql, itp.) — pomijamy re-weryfikacje
            # bo maja specyficzne zaleznosci; zostana wykryte na nowo w discovery
            else:
                valid = True  # nie sprawdzamy — zostawiamy jak jest
        except Exception:
            valid = True  # blad sieci → nie usuwamy (bezpieczne podejscie)

        if not valid:
            logger.warning(
                "REVERIFY FAIL %-18s method=%-6s user=%-12s → usuwam (false positive lub zmiana hasla)",
                ip, cred.method.value, u,
            )
            db.delete(cred)
        else:
            any_valid = True

    # BUG-DB-4: jeden commit obejmuje oba zmiany (usuniecia + reset sentinela)
    # zamiast dwoch osobnych commitow z oknem race condition miedzy nimi
    if not any_valid and saved:
        dev = db.query(Device).filter(Device.id == device_id).first()
        if dev and dev.last_credential_ok_at:
            logger.warning(
                "REVERIFY %-18s wszystkie credentials nieaktualne → reset last_credential_ok_at",
                ip,
            )
            dev.last_credential_ok_at = None
    db.commit()


def _save_cred(db, device_id: int, method: CredentialMethod, u: str, p: str) -> None:
    now = datetime.utcnow()
    ex = db.query(Credential).filter(
        Credential.device_id == device_id,
        Credential.method    == method,
        Credential.username  == u,
    ).first()
    if ex:
        ex.password_encrypted = p
        ex.last_success_at    = now
        ex.success_count      = (ex.success_count or 0) + 1
    else:
        db.add(Credential(
            device_id=device_id, method=method, username=u,
            password_encrypted=p, priority=10,
            notes=f"Auto (cred-worker): {u}",
            last_success_at=now, success_count=1,
        ))
    dev = db.query(Device).filter(Device.id == device_id).first()
    if dev:
        dev.last_credential_ok_at = now
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise


def _mark_checked(db, device_id: int) -> None:
    """Ustawia sentinel zeby nie ponawiac probe az do retry_days."""
    dev = db.query(Device).filter(Device.id == device_id).first()
    if dev and not dev.last_credential_ok_at:
        dev.last_credential_ok_at = datetime(1970, 1, 2)
        db.commit()


# Per-device ------------------------------------------------------------------
def _process_device(device_id: int, ip: str,
                    ssh_pairs: list, web_pairs: list, ftp_pairs: list,
                    rdp_pairs: list | None = None,
                    vnc_pairs: list | None = None,
                    mssql_pairs: list | None = None,
                    mysql_pairs: list | None = None,
                    postgres_pairs: list | None = None,
                    pairs_per_cycle: int = 1) -> dict:
    """Testuje credentials na jednym urzadzeniu.
    Uzywa rotacji: per cykl testuje max `pairs_per_cycle` nowych par (dotad nieprobowanych).
    """
    # BUG-WRK-05: mutable default arguments replaced with None — coerce here
    if rdp_pairs      is None: rdp_pairs      = []
    if vnc_pairs      is None: vnc_pairs      = []
    if mssql_pairs    is None: mssql_pairs    = []
    if mysql_pairs    is None: mysql_pairs    = []
    if postgres_pairs is None: postgres_pairs = []

    res = {"ssh": False, "telnet": False, "web": False, "ftp": False,
           "rdp": False, "vnc": False,
           "mssql": False, "mysql": False, "postgres": False, "new": 0}

    # PERF-09: jedna sesja przez całe _process_device zamiast 5-8 osobnych SessionLocal()
    db = SessionLocal()
    try:
        # Re-weryfikuj istniejace credentials (wykrywa false positive i zmiany hasel)
        _reverify_existing_creds(db, device_id, ip)

        # Wczytaj juz probowane pary dla tego urzadzenia
        tried = _load_tried(device_id, db=db)

        # Wyfiltruj do nieprobowanych (max pairs_per_cycle per protokol)
        ssh_to_try      = _filter_untried(ssh_pairs,      tried.get("ssh",      set()), pairs_per_cycle)
        telnet_to_try   = _filter_untried(ssh_pairs,      tried.get("telnet",   set()), pairs_per_cycle)
        web_to_try      = _filter_untried(web_pairs,      tried.get("api",      set()), pairs_per_cycle)
        ftp_to_try      = _filter_untried(ftp_pairs,      tried.get("ftp",      set()), pairs_per_cycle)
        rdp_to_try      = _filter_untried(rdp_pairs,      tried.get("rdp",      set()), pairs_per_cycle)
        vnc_to_try      = _filter_untried(vnc_pairs,      tried.get("vnc",      set()), pairs_per_cycle)
        mssql_to_try    = _filter_untried(mssql_pairs,    tried.get("mssql",    set()), pairs_per_cycle)
        mysql_to_try    = _filter_untried(mysql_pairs,    tried.get("mysql",    set()), pairs_per_cycle)
        postgres_to_try = _filter_untried(postgres_pairs, tried.get("postgres", set()), pairs_per_cycle)

        if not any([ssh_to_try, telnet_to_try, web_to_try, ftp_to_try, rdp_to_try, vnc_to_try,
                    mssql_to_try, mysql_to_try, postgres_to_try]):
            # Wszystkie pary wyczerpane — czekamy retry_days i resetujemy rotacje
            logger.info("WYCZERPANO %-18s wszystkie pary — reset rotacji po retry_days", ip)
            _mark_checked(db, device_id)
            _clear_tried(device_id, db=db)
            db.commit()
            return res

        # Pobierz otwarte porty raz — uzywane przez SSH i nonstandard port probe
        open_ports = _get_device_open_ports(device_id, db=db)

        if ssh_to_try:
            _open_ssh = [p for p in _SSH_PORTS
                         if open_ports.get(p) or _tcp_open(ip, p, timeout=1.5)]
            if not _open_ssh:
                logger.info("SSH skip: %-18s brak otwartych portow SSH — para NIE zuzywa slotu", ip)
            else:
                logger.info("TEST SSH  %-18s (%d/%d par, cykl=%d)",
                            ip, len(ssh_to_try), len(ssh_pairs), pairs_per_cycle)
                _mark_pairs_tried(tried, "ssh", ssh_to_try)
                pair = discover_ssh(ip, ssh_to_try, open_ports=open_ports)
                if pair:
                    _save_cred(db, device_id, CredentialMethod.ssh, pair[0], pair[1])
                    logger.info("SSH OK:   %-18s user=%s", ip, pair[0])
                    res["ssh"] = True; res["new"] += 1
                else:
                    logger.info("SSH brak: %-18s (wyprobowano %d par)", ip, len(ssh_to_try))

        if telnet_to_try:
            _open_telnet = [p for p in _TELNET_PORTS
                            if open_ports.get(p) or _tcp_open(ip, p, timeout=1.5)]
            if not _open_telnet:
                logger.info("TEL skip: %-18s brak otwartych portow Telnet — para NIE zuzywa slotu", ip)
            else:
                logger.info("TEST TEL  %-18s (%d/%d par, cykl=%d)",
                            ip, len(telnet_to_try), len(ssh_pairs), pairs_per_cycle)
                _mark_pairs_tried(tried, "telnet", telnet_to_try)
                pair = discover_telnet(ip, telnet_to_try)
                if pair:
                    _save_cred(db, device_id, CredentialMethod.telnet, pair[0], pair[1])
                    logger.info("TEL OK:   %-18s user=%s", ip, pair[0])
                    res["telnet"] = True; res["new"] += 1
                else:
                    logger.info("TEL brak: %-18s (wyprobowano %d par)", ip, len(telnet_to_try))

        if web_to_try:
            _open_web = [p for p in _WEB_PORTS if _tcp_open(ip, p, timeout=1.5)]
            if not _open_web:
                logger.info("WEB skip: %-18s brak otwartych portow HTTP — para NIE zuzywa slotu", ip)
            elif not _web_detect_auth(ip, _open_web):
                logger.info("WEB skip: %-18s brak strony logowania — para NIE zuzywa slotu", ip)
            else:
                logger.info("TEST WEB  %-18s (%d/%d par, cykl=%d)",
                            ip, len(web_to_try), len(web_pairs), pairs_per_cycle)
                _mark_pairs_tried(tried, "api", web_to_try)
                pair = discover_web(ip, web_to_try, open_ports_hint=_open_web)
                if pair:
                    _save_cred(db, device_id, CredentialMethod.api, pair[0], pair[1])
                    logger.info("WEB OK:   %-18s user=%s", ip, pair[0])
                    res["web"] = True; res["new"] += 1
                else:
                    logger.info("WEB brak: %-18s (wyprobowano %d par)", ip, len(web_to_try))

        if ftp_to_try:
            if not _tcp_open(ip, 21, timeout=1.5):
                logger.info("FTP skip: %-18s brak portu 21", ip)
            else:
                logger.info("TEST FTP  %-18s (%d/%d par, cykl=%d)",
                            ip, len(ftp_to_try), len(ftp_pairs), pairs_per_cycle)
                _mark_pairs_tried(tried, "ftp", ftp_to_try)
                pair = discover_ftp(ip, ftp_to_try)
                if pair:
                    _save_cred(db, device_id, CredentialMethod.ftp, pair[0], pair[1])
                    logger.info("FTP OK:   %-18s user=%s", ip, pair[0])
                    res["ftp"] = True; res["new"] += 1
                else:
                    logger.info("FTP brak: %-18s (wyprobowano %d par)", ip, len(ftp_to_try))

        if rdp_to_try:
            if not _tcp_open(ip, 445, timeout=1.5):
                logger.info("RDP skip: %-18s brak portu 445 (SMB)", ip)
            else:
                logger.info("TEST RDP  %-18s (%d/%d par, cykl=%d)",
                            ip, len(rdp_to_try), len(rdp_pairs), pairs_per_cycle)
                _mark_pairs_tried(tried, "rdp", rdp_to_try)
                pair = discover_rdp(ip, rdp_to_try)
                if pair:
                    _save_cred(db, device_id, CredentialMethod.rdp, pair[0], pair[1])
                    logger.info("RDP OK:   %-18s user=%s", ip, pair[0])
                    res["rdp"] = True; res["new"] += 1
                else:
                    logger.info("RDP brak: %-18s (wyprobowano %d par)", ip, len(rdp_to_try))

        if vnc_to_try:
            _open_vnc = any(
                open_ports.get(p) or _tcp_open(ip, p, timeout=1.5)
                for p in _VNC_PORTS
            )
            if not _open_vnc:
                logger.info("VNC skip: %-18s brak portow 5900-5903", ip)
            else:
                logger.info("TEST VNC  %-18s (%d/%d par, cykl=%d)",
                            ip, len(vnc_to_try), len(vnc_pairs), pairs_per_cycle)
                _mark_pairs_tried(tried, "vnc", vnc_to_try)
                pair = discover_vnc(ip, vnc_to_try)
                if pair:
                    _save_cred(db, device_id, CredentialMethod.vnc, pair[0], pair[1])
                    _masked = ("*" * min(len(pair[1] or ""), 4)) or "(puste)"
                    logger.info("VNC OK:   %-18s pass=%s", ip, _masked)  # BUG-SEC-10: maskowanie
                    res["vnc"] = True; res["new"] += 1
                else:
                    logger.info("VNC brak: %-18s (wyprobowano %d hasel)", ip, len(vnc_to_try))

        if mssql_to_try:
            logger.info("TEST MSSQL %-18s (%d/%d par, cykl=%d)",
                        ip, len(mssql_to_try), len(mssql_pairs), pairs_per_cycle)
            _mark_pairs_tried(tried, "mssql", mssql_to_try)
            pair = discover_mssql(ip, mssql_to_try)
            if pair:
                _save_cred(db, device_id, CredentialMethod.mssql, pair[0], pair[1])
                logger.info("MSSQL OK: %-18s user=%s", ip, pair[0])
                res["mssql"] = True; res["new"] += 1
            else:
                logger.info("MSSQL brak: %-18s (wyprobowano %d par)", ip, len(mssql_to_try))

        if mysql_to_try:
            logger.info("TEST MySQL %-18s (%d/%d par, cykl=%d)",
                        ip, len(mysql_to_try), len(mysql_pairs), pairs_per_cycle)
            _mark_pairs_tried(tried, "mysql", mysql_to_try)
            pair = discover_mysql(ip, mysql_to_try)
            if pair:
                _save_cred(db, device_id, CredentialMethod.mysql, pair[0], pair[1])
                logger.info("MySQL OK: %-18s user=%s", ip, pair[0])
                res["mysql"] = True; res["new"] += 1
            else:
                logger.info("MySQL brak: %-18s (wyprobowano %d par)", ip, len(mysql_to_try))

        if postgres_to_try:
            logger.info("TEST PgSQL %-18s (%d/%d par, cykl=%d)",
                        ip, len(postgres_to_try), len(postgres_pairs), pairs_per_cycle)
            _mark_pairs_tried(tried, "postgres", postgres_to_try)
            pair = discover_postgres(ip, postgres_to_try)
            if pair:
                _save_cred(db, device_id, CredentialMethod.postgres, pair[0], pair[1])
                logger.info("PgSQL OK: %-18s user=%s", ip, pair[0])
                res["postgres"] = True; res["new"] += 1
            else:
                logger.info("PgSQL brak: %-18s (wyprobowano %d par)", ip, len(postgres_to_try))

        # Niestandardowe porty — probujemy jesli lista portow sie zmienila
        if open_ports:
            cur_hash = _ports_hash(open_ports)
            if cur_hash != _get_port_hash(device_id, db=db):
                port_hits = _probe_nonstandard_ports(
                    ip, open_ports, ssh_pairs[:8], web_pairs[:8], rdp_pairs[:8])
                for method, u, p in port_hits:
                    _save_cred(db, device_id, method, u, p)
                    res["new"] += 1
                _set_port_hash(device_id, cur_hash, db=db)
                if port_hits:
                    logger.info("Nonstandard ports %s: +%d creds", ip, len(port_hits))

        # Jesli znaleziono credential → wyczysc rotacje (device bedzie pominiety az do retry_days)
        if res["new"] > 0:
            _clear_tried(device_id)
        else:
            # Zapisz aktualny stan rotacji do DB
            _save_tried(device_id, tried)

    except Exception as exc:
        logger.warning("Blad device_id=%s ip=%s: %s", device_id, ip, exc)
        db.rollback()
    finally:
        # Zawsze drenuj zdarzenia ochrony — nawet gdy wystąpił wyjątek wcześniej.
        # Bez finally: zdarzenia z poprzedniego cyklu narastają w globalnym dict
        # i przy następnym cyklu count jest fałszywie zawyżony.
        try:
            _process_protection_events(db, device_id, ip)
        except Exception:
            pass
        db.close()
    return res


_dangling_threads: list = []  # BUG-CONC-2: sledzenie watkow po timeout (daemon, nie mozna zabic)
_MAX_DANGLING = 50            # limit zanim zaczniemy spowalniać


def _process_device_with_timeout(timeout_s: int, device_id: int, ip: str,
                                  ssh_pairs: list, web_pairs: list, ftp_pairs: list,
                                  rdp_pairs: list, vnc_pairs: list, pairs_per_cycle: int,
                                  mssql_pairs: list | None = None,
                                  mysql_pairs: list | None = None,
                                  postgres_pairs: list | None = None) -> dict:
    """Uruchamia _process_device w watku z timeoutem. Jesli przekroczy — zwraca timeout=True."""
    # BUG-WRK-05: mutable default arguments replaced with None — coerce here
    if mssql_pairs    is None: mssql_pairs    = []
    if mysql_pairs    is None: mysql_pairs    = []
    if postgres_pairs is None: postgres_pairs = []

    # BUG-CONC-2: prune zakończonych wątków z listy dangling przed dodaniem nowych
    global _dangling_threads
    _dangling_threads = [t for t in _dangling_threads if t.is_alive()]
    if len(_dangling_threads) >= _MAX_DANGLING:
        logger.warning(
            "BUG-CONC-2: %d watkow nadal aktywnych po timeout — mozliwy OOM/wyczerpanie fd. "
            "Pomijam %s.", len(_dangling_threads), ip,
        )
        return {"ssh": False, "telnet": False, "web": False, "ftp": False, "rdp": False,
                "mssql": False, "mysql": False, "postgres": False, "new": 0, "timeout": True}

    result: list = [None]

    def _run():
        result[0] = _process_device(device_id, ip, ssh_pairs, web_pairs,
                                     ftp_pairs, rdp_pairs, vnc_pairs,
                                     mssql_pairs, mysql_pairs, postgres_pairs,
                                     pairs_per_cycle)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=timeout_s)
    if t.is_alive():
        logger.warning("TIMEOUT   %-18s przekroczono %ds — pomijam urzadzenie", ip, timeout_s)
        _dangling_threads.append(t)  # śledź wątek — może nadal trzymać socket SSH
        return {"ssh": False, "telnet": False, "web": False, "ftp": False, "rdp": False,
                "mssql": False, "mysql": False, "postgres": False, "new": 0, "timeout": True}
    return result[0] or {"ssh": False, "telnet": False, "web": False, "ftp": False, "rdp": False,
                          "mssql": False, "mysql": False, "postgres": False, "new": 0}


# Main loop -------------------------------------------------------------------
def scan_once() -> None:
    global _total_new
    (interval, ssh_w, web_w, retry_days, max_creds,
     pairs_per_cycle, min_delay, max_delay, dev_timeout) = _read_settings()
    method_flags = _read_method_flags()
    t0 = time.monotonic()
    db = SessionLocal()
    try:
        threshold  = datetime.utcnow() - timedelta(days=retry_days)
        # WRK-17: pomijaj urzadzenia ktore nie odpowiadaly przez ostatnie 10 minut
        # (is_active flaga zmienia sie z opoznieniem do 5 min — dodatkowe zabezpieczenie
        # przed credential testing na offline urzadzeniach i ryzykiem AD lockout)
        recent_seen = datetime.utcnow() - timedelta(minutes=10)
        # Wyciagnij (id, ip) przed zamknieciem sesji — ORM obiekty staja sie detached po db.close()
        candidates = [
            (d.id, d.ip) for d in db.query(Device).filter(
                Device.is_active == True,
                Device.last_seen >= recent_seen,
                (Device.last_credential_ok_at.is_(None)) |
                (Device.last_credential_ok_at < threshold),
            ).all()
        ]
        # SSH/Telnet — wczytaj pary lub wyczysc jesli wylaczone
        if method_flags.get("cred_ssh_enabled", True):
            _ssh_db = [(r.username or "", r.password_encrypted or "") for r in
                       db.query(Credential).filter(
                           Credential.device_id.is_(None),
                           Credential.method    == CredentialMethod.ssh,
                       ).order_by(Credential.priority).limit(max_creds).all()]
            ssh_pairs = _ssh_db if _ssh_db else SSH_CREDENTIAL_FALLBACK[:max_creds]
        else:
            logger.info("SSH credential testing WYLACZONY (cred_ssh_enabled=0)")
            ssh_pairs = []
        # Web/HTTP — wczytaj pary lub wyczysc jesli wylaczone
        if method_flags.get("cred_web_enabled", True):
            _web_db = [(r.username or "", r.password_encrypted or "") for r in
                       db.query(Credential).filter(
                           Credential.device_id.is_(None),
                           Credential.method    == CredentialMethod.api,
                       ).order_by(Credential.priority).limit(max_creds).all()]
            web_pairs = _web_db if _web_db else API_CREDENTIAL_FALLBACK[:max_creds]
        else:
            logger.info("WEB credential testing WYLACZONY (cred_web_enabled=0)")
            web_pairs = []
        # FTP — dedykowana lista credentials (nie SSH!)
        if method_flags.get("cred_ftp_enabled", True):
            _ftp_db = [(r.username or "", r.password_encrypted or "") for r in
                       db.query(Credential).filter(
                           Credential.device_id.is_(None),
                           Credential.method    == CredentialMethod.ftp,
                       ).order_by(Credential.priority).limit(max_creds).all()]
            ftp_pairs = _ftp_db if _ftp_db else FTP_CREDENTIAL_FALLBACK[:max_creds]
        else:
            logger.info("FTP credential testing WYLACZONY (cred_ftp_enabled=0)")
            ftp_pairs = []
        # VNC — wczytaj pary lub wyczysc jesli wylaczone
        if method_flags.get("cred_vnc_enabled", True):
            _vnc_db = [(r.username or "", r.password_encrypted or "") for r in
                       db.query(Credential).filter(
                           Credential.device_id.is_(None),
                           Credential.method    == CredentialMethod.vnc,
                       ).order_by(Credential.priority).limit(max_creds).all()]
            vnc_pairs = _vnc_db if _vnc_db else VNC_CREDENTIAL_FALLBACK[:max_creds]
        else:
            logger.info("VNC credential testing WYLACZONY (cred_vnc_enabled=0)")
            vnc_pairs = []
        # RDP — wczytaj pary lub wyczysc jesli wylaczone
        if method_flags.get("cred_rdp_enabled", True):
            _rdp_db = [(r.username or "", r.password_encrypted or "") for r in
                       db.query(Credential).filter(
                           Credential.device_id.is_(None),
                           Credential.method    == CredentialMethod.rdp,
                       ).order_by(Credential.priority).limit(max_creds).all()]
            rdp_pairs = _rdp_db if _rdp_db else RDP_CREDENTIAL_FALLBACK[:max_creds]
        else:
            logger.info("RDP credential testing WYLACZONY (cred_rdp_enabled=0)")
            rdp_pairs = []
        # MSSQL — wczytaj pary lub wyczysc jesli wylaczone
        if method_flags.get("cred_mssql_enabled", True):
            _mssql_db = [(r.username or "", r.password_encrypted or "") for r in
                         db.query(Credential).filter(
                             Credential.device_id.is_(None),
                             Credential.method    == CredentialMethod.mssql,
                         ).order_by(Credential.priority).limit(max_creds).all()]
            mssql_pairs = _mssql_db if _mssql_db else MSSQL_CREDENTIAL_FALLBACK[:max_creds]
        else:
            logger.info("MSSQL credential testing WYLACZONY (cred_mssql_enabled=0)")
            mssql_pairs = []
        # MySQL — wczytaj pary lub wyczysc jesli wylaczone
        if method_flags.get("cred_mysql_enabled", True):
            _mysql_db = [(r.username or "", r.password_encrypted or "") for r in
                         db.query(Credential).filter(
                             Credential.device_id.is_(None),
                             Credential.method    == CredentialMethod.mysql,
                         ).order_by(Credential.priority).limit(max_creds).all()]
            mysql_pairs = _mysql_db if _mysql_db else MYSQL_CREDENTIAL_FALLBACK[:max_creds]
        else:
            logger.info("MySQL credential testing WYLACZONY (cred_mysql_enabled=0)")
            mysql_pairs = []
        # PostgreSQL — wczytaj pary lub wyczysc jesli wylaczone
        if method_flags.get("cred_postgres_enabled", True):
            _postgres_db = [(r.username or "", r.password_encrypted or "") for r in
                            db.query(Credential).filter(
                                Credential.device_id.is_(None),
                                Credential.method    == CredentialMethod.postgres,
                            ).order_by(Credential.priority).limit(max_creds).all()]
            postgres_pairs = _postgres_db if _postgres_db else POSTGRES_CREDENTIAL_FALLBACK[:max_creds]
        else:
            logger.info("PostgreSQL credential testing WYLACZONY (cred_postgres_enabled=0)")
            postgres_pairs = []
        # Zapisz znacznik poczatku cyklu (do obliczenia ETA w panelu www)
        from netdoc.storage.models import SystemStatus as SS
        _now_iso = datetime.utcnow().isoformat()
        for _k in ("cred_last_cycle_at", "cred_interval_s_current"):
            _row = db.query(SS).filter(SS.key == _k).first()
            _val = _now_iso if _k == "cred_last_cycle_at" else str(interval)
            if _row:
                _row.value = _val
            else:
                db.add(SS(key=_k, category="cred_status", value=_val))
        db.commit()
    finally:
        db.close()
    if not candidates:
        logger.info("Brak kandydatow do sprawdzenia credentiali")
        return
    logger.info(
        "Cred scan: %d urzadzen SSH=%d Web=%d FTP=%d RDP=%d VNC=%d MSSQL=%d MySQL=%d PG=%d par"
        " | pairs_per_cycle=%d workers=%d timeout=%ds",
        len(candidates), len(ssh_pairs), len(web_pairs), len(ftp_pairs),
        len(rdp_pairs), len(vnc_pairs),
        len(mssql_pairs), len(mysql_pairs), len(postgres_pairs),
        pairs_per_cycle, ssh_w, dev_timeout,
    )
    ssh_ok = telnet_ok = web_ok = ftp_ok = rdp_ok = mssql_ok = mysql_ok = postgres_ok = new_t = timeouts = 0

    # Rownolegle testowanie ROZNYCH IP jednoczesnie (kazde IP dostaje max pairs_per_cycle par).
    # Brak ryzyka lockoutu — kazde IP odpytywane 1x per cykl,
    # a kolejny cykl dopiero po interval_s (np. 60s).
    def _run(dev_id, dev_ip, start_delay: float = 0.0):
        # PERF-04: delay przeniesiony DO watku — main thread nie jest blokowany
        if start_delay > 0:
            time.sleep(start_delay)
        return _process_device_with_timeout(
            dev_timeout, dev_id, dev_ip,
            ssh_pairs, web_pairs, ftp_pairs, rdp_pairs, vnc_pairs,
            pairs_per_cycle, mssql_pairs, mysql_pairs, postgres_pairs,
        )

    with ThreadPoolExecutor(max_workers=min(ssh_w, len(candidates))) as pool:
        # PERF-04: rozkladamy starty w czasie przez delay wewnatrz watku (nie sleep w main)
        # Zapobiega jednoczesnym logowaniom -> lockout AD / IDS rate-limit
        # Dispatch wszystkich taskow natychmiast, kazdy watek sam czeka swoj czas startu
        futures = {}
        n = len(candidates)
        for i, (dev_id, dev_ip) in enumerate(candidates):
            if min_delay > 0 and n > 1:
                # Delay rozlozony rowno w oknie [0, max_delay * (n-1)/n]
                delay = random.uniform(min_delay, max_delay) * i / n
            else:
                delay = 0.0
            futures[pool.submit(_run, dev_id, dev_ip, delay)] = dev_ip
        for fut in as_completed(futures):
            try:
                r = fut.result()
            except Exception as exc:
                logger.warning("Blad watku cred dla %s: %s", futures[fut], exc)
                continue
            if r["ssh"]:           ssh_ok      += 1
            if r.get("telnet"):    telnet_ok   += 1
            if r["web"]:           web_ok      += 1
            if r["ftp"]:           ftp_ok      += 1
            if r.get("rdp"):       rdp_ok      += 1
            if r.get("mssql"):     mssql_ok    += 1
            if r.get("mysql"):     mysql_ok    += 1
            if r.get("postgres"):  postgres_ok += 1
            if r.get("timeout"):   timeouts    += 1
            new_t += r["new"]

    _total_new += new_t
    elapsed = time.monotonic() - t0
    g_scanned.set(len(candidates)); g_ssh_ok.set(ssh_ok)
    g_web_ok.set(web_ok); g_ftp_ok.set(ftp_ok); g_rdp_ok.set(rdp_ok)
    g_mssql_ok.set(mssql_ok); g_mysql_ok.set(mysql_ok); g_postgres_ok.set(postgres_ok)
    g_new.set(_total_new); g_duration.set(round(elapsed, 1))
    logger.info("Cred done: SSH=%d TEL=%d Web=%d FTP=%d RDP=%d MSSQL=%d MySQL=%d PG=%d new=%d timeout=%d  %.1fs",
                ssh_ok, telnet_ok, web_ok, ftp_ok, rdp_ok, mssql_ok, mysql_ok, postgres_ok, new_t, timeouts, elapsed)



def _seed_default_credentials() -> None:
    """Wpisz domyslne credentials do bazy jesli jeszcze nie istnieja (global, priority=1)."""
    db = SessionLocal()
    try:
        seeds = [
            (CredentialMethod.ssh,      SSH_CREDENTIAL_FALLBACK),
            (CredentialMethod.telnet,   TELNET_CREDENTIAL_FALLBACK),
            (CredentialMethod.api,      API_CREDENTIAL_FALLBACK),
            (CredentialMethod.rdp,      RDP_CREDENTIAL_FALLBACK),
            (CredentialMethod.vnc,      VNC_CREDENTIAL_FALLBACK),
            (CredentialMethod.ftp,      FTP_CREDENTIAL_FALLBACK),
            (CredentialMethod.mssql,    MSSQL_CREDENTIAL_FALLBACK),
            (CredentialMethod.mysql,    MYSQL_CREDENTIAL_FALLBACK),
            (CredentialMethod.postgres, POSTGRES_CREDENTIAL_FALLBACK),
        ]
        for method, fallback in seeds:
            count = db.query(Credential).filter(
                Credential.device_id.is_(None),
                Credential.method == method,
            ).count()
            if count > 0:
                continue
            for u, p in fallback:
                db.add(Credential(
                    device_id=None, method=method,
                    username=u, password_encrypted=p, priority=1,
                    notes="auto-seeded default",
                ))
            logger.info("Seeded %d domyslnych %s credentials", len(fallback), method.value)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.warning("Seed creds error: %s", e)
    finally:
        db.close()


def main() -> None:
    logger.info("Netdoc Cred Worker start metrics=:%d default_interval=%ds",
                METRICS_PORT, _DEFAULT_INTERVAL)
    init_db()
    _seed_default_credentials()
    start_http_server(METRICS_PORT)
    logger.info("Metryki: http://0.0.0.0:%d/metrics", METRICS_PORT)
    # PERF-02: sleep-until-next-run zamiast sleep-after-work
    interval = _DEFAULT_INTERVAL
    while True:
        next_run = time.monotonic() + interval
        try:
            scan_once()
        except Exception as exc:
            logger.exception("Nieobsluzony wyjatek w scan_once (cred): %s", exc)
        interval, *_ = _read_settings()
        time.sleep(max(0.0, next_run - time.monotonic()))


if __name__ == "__main__":
    main()
