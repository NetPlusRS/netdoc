"""
NetDoc Web Admin — Flask application.

Dev:
    flask --app netdoc.web.app run --port 5000

Produkcja (docker-compose):
    python -m flask --app netdoc.web.app run --host 0.0.0.0 --port 5000
"""
import ipaddress
import json as _json
import os
import pathlib
import requests
from requests.exceptions import HTTPError as _RequestsHTTPError
from flask import Flask, render_template, render_template_string, request, redirect, url_for, flash, jsonify, send_file, Response

from netdoc.storage.database import SessionLocal
from netdoc.storage.models import (
    Device, DiscoveredNetwork, Credential, SystemStatus, NetworkSource, Vulnerability,
    ChatMessage, DeviceScreenshot, DeviceAssessment,
)
from netdoc.web import chat_agent

try:
    from netdoc_pro import PRO_ENABLED
except ImportError:
    PRO_ENABLED = False

try:
    from netdoc_pro.passport.generate import generate_passport
    PRO_PASSPORT = True
except ImportError:
    PRO_PASSPORT = False

API_URL = os.getenv("NETDOC_API_URL", "http://localhost:8000")
GRAFANA_URL = os.getenv("GRAFANA_URL", "/grafana")

# Short vulnerability descriptions used in tooltips (security.html)
_VULN_HINTS: dict = {
    "default_credentials":  {"short": "Device is accessible with the manufacturer's default username and password.",                            "cvss": "9.8"},
    "open_telnet":          {"short": "Device exposes management via Telnet — an unencrypted protocol.",                                       "cvss": "7.5"},
    "anonymous_ftp":        {"short": "FTP server accepts connections without any password (login: anonymous).",                               "cvss": "7.5"},
    "open_ftp":             {"short": "FTP server operates without encryption — passwords and files visible on the network.",                  "cvss": "5.9"},
    "snmp_public":          {"short": "Device responds to SNMP with the default community string 'public'.",                                   "cvss": "5.3"},
    "mqtt_noauth":          {"short": "MQTT broker accepts connections without username or password.",                                         "cvss": "8.1"},
    "redis_noauth":         {"short": "Redis database accessible without authentication.",                                                     "cvss": "9.8"},
    "elasticsearch_noauth": {"short": "Elasticsearch cluster accessible without a password — full data access.",                              "cvss": "9.8"},
    "docker_api_exposed":   {"short": "Docker daemon listening on a network port — RCE and privilege escalation possible.",                   "cvss": "9.8"},
    "http_management":      {"short": "Device web interface accessible over HTTP instead of HTTPS.",                                          "cvss": "6.5"},
    "ssl_expired":          {"short": "Security certificate for the site or service has expired.",                                            "cvss": "5.3"},
    "ssl_self_signed":      {"short": "Service uses a self-signed certificate instead of a trusted authority.",                               "cvss": "3.7"},
    "ipmi_exposed":         {"short": "Server management interface (IPMI/BMC) accessible from the network.",                                 "cvss": "9.8"},
    "rdp_exposed":          {"short": "Windows Remote Desktop (RDP) directly accessible from the network.",                                   "cvss": "8.1"},
    "vnc_noauth":           {"short": "VNC remote desktop accessible without any password.",                                                  "cvss": "9.8"},
    "mongo_noauth":         {"short": "MongoDB database accessible without a password — full access to all collections.",                    "cvss": "9.8"},
    "rtsp_noauth":          {"short": "Camera video stream accessible without username or password.",                                         "cvss": "7.5"},
    "modbus_exposed":       {"short": "Industrial Modbus protocol accessible without authentication.",                                        "cvss": "9.1"},
    "mysql_noauth":         {"short": "MySQL database server accessible without a password for the root account.",                            "cvss": "9.8"},
    "postgres_weak_creds":  {"short": "PostgreSQL server accessible with default or weak credentials.",                                      "cvss": "9.8"},
    "mssql_weak_creds":     {"short": "SQL Server with empty or weak password for the 'sa' administrator account.",                           "cvss": "9.8"},
    "vnc_weak_creds":       {"short": "VNC server is password-protected, but the password is trivially weak.",                               "cvss": "9.8"},
    "couchdb_noauth":       {"short": "CouchDB database accessible without login — full access via HTTP API.",                               "cvss": "9.8"},
    "memcached_exposed":    {"short": "Memcached cache server accessible without authentication — data leak and DDoS amplification risk.",    "cvss": "7.5"},
    "influxdb_noauth":      {"short": "InfluxDB time-series database accessible without a token — full access to metrics.",                  "cvss": "9.1"},
    "cassandra_noauth":     {"short": "Cassandra database cluster accessible via CQL without authentication.",                               "cvss": "9.8"},
    "rtsp_weak_creds":      {"short": "IP camera requires a password but accepts common default credentials.",                               "cvss": "8.1"},
    "firewall_disabled":    {"short": "Host has an excessive number of open ports — firewall missing or misconfigured.",                      "cvss": "7.5"},
    "unauth_reboot":        {"short": "Device reboot endpoint accessible without authentication — attacker can remotely restart the device.", "cvss": "9.1"},
}

_SCREENSHOT_TTL = 43200  # 12h domyslnie — nadpisywane z DB (screenshot_ttl_hours)


def _capture_screenshot(ip: str, http_port: int, scheme: str):
    """Uruchamia playwright i zwraca PNG jako bytes lub None przy bledzie.

    ignore_https_errors=True — omija ostrzezenia o self-signed certach (UniFi, MikroTik itp.)
    Strategia wczytywania strony (wieloetapowa):
      1. Probuje networkidle (SPA — React/Angular) z krotkim timeoutem
      2. Przy timeoucie probuje domcontentloaded (HTML login pages — Dahua, MikroTik itp.)
      3. Czeka na selektor formularza lub 2.5s ekstra na wyrenderowanie
    Dahua/Hikvision: uzywaja dlugich polaczen (MJPEG/polling) ktore blokuja networkidle.
    """
    try:
        from playwright.sync_api import sync_playwright
        url = f"{scheme}://{ip}:{http_port}"
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox",
                      "--disable-dev-shm-usage", "--disable-gpu"],
            )
            ctx = browser.new_context(
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
            )
            page = ctx.new_page()
            # Etap 1: probuj networkidle z timeoutem 8s (SPA / React)
            networkidle_ok = False
            try:
                page.goto(url, timeout=8000, wait_until="networkidle")
                networkidle_ok = True
            except Exception:
                pass
            # Etap 2: gdy networkidle timeout — czekaj na domcontentloaded (stary HTML, Dahua itp.)
            if not networkidle_ok:
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=5000)
                except Exception:
                    pass
            # Etap 3: czekaj na formularz logowania (HTML input/form)
            try:
                page.wait_for_selector(
                    "input, form, [class*='login'], [class*='Login'], [id*='login'], [id*='Login']",
                    timeout=5000,
                )
            except Exception:
                pass
            # Etap 4: dodatkowe 2.5s na wyrenderowanie tresci wizualnej (fonty, obrazki, CSS)
            # Szczegolnie potrzebne dla starszych interfejsow kamer (Dahua, Hikvision)
            try:
                page.wait_for_timeout(2500)
            except Exception:
                pass
            # Sprawdz URL po nawigacji — Chrome error page = fałszywy screenshot
            try:
                current_url = page.url
                if current_url.startswith(("chrome-error:", "about:blank", "data:text/html")):
                    return None
            except Exception:
                pass
            try:
                png = page.screenshot(full_page=False)
                # Odrzuc zbyt male PNG (biala strona, niezaladowana strona, blad renderowania)
                if not png or len(png) < _MIN_VALID_PNG_BYTES:
                    return None
                return png
            except Exception:
                return None
            finally:
                browser.close()
    except Exception:
        return None



# Typowe sciezki RTSP dla kamer IP (kolejnosc prób)
_RTSP_PATHS = [
    "/",
    "/stream",
    "/live",
    "/live/ch0",
    "/ch0",
    "/ch0_0",
    "/ch0_0.264",
    "/h264Preview_01_main",
    "/Streaming/Channels/101",
    "/cam/realmonitor",
    "/video1",
]


def _capture_rtsp_frame(ip: str, port: int = 554,
                         username: str = None, password: str = None) -> bytes | None:
    """Przechwytuje jedna klatke ze strumienia RTSP (przez ffmpeg) jako PNG bytes.

    Probuje kolejne typowe sciezki RTSP az do uzyskania obrazu.
    Wymaga: ffmpeg zainstalowanego w systemie (Dockerfile: apt-get install ffmpeg).
    Zwraca bytes PNG lub None gdy brak strumienia / brak ffmpeg.
    """
    import subprocess
    import tempfile
    import os

    for path in _RTSP_PATHS:
        if username and password:
            url = f"rtsp://{username}:{password}@{ip}:{port}{path}"
        else:
            url = f"rtsp://{ip}:{port}{path}"

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
            tmpfile = tf.name
        try:
            result = subprocess.run(
                [
                    "ffmpeg", "-loglevel", "quiet",
                    "-rtsp_transport", "tcp",
                    "-i", url,
                    "-frames:v", "1",
                    "-f", "image2",
                    tmpfile, "-y",
                ],
                capture_output=True,
                timeout=10,
            )
            if os.path.exists(tmpfile) and os.path.getsize(tmpfile) >= _MIN_VALID_PNG_BYTES:
                with open(tmpfile, "rb") as f:
                    return f.read()
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            # FileNotFoundError = brak ffmpeg w systemie
            pass
        finally:
            try:
                os.unlink(tmpfile)
            except OSError:
                pass
    return None


def _is_tls(ip: str, port: int) -> bool:
    """Probuje TLS handshake — True jesli port serwuje HTTPS."""
    import socket as _sock
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = _ssl.CERT_NONE
    try:
        with ctx.wrap_socket(_sock.create_connection((ip, port), timeout=1.5)):
            return True
    except Exception:
        return False


def _tcp_open(ip: str, port: int) -> bool:
    import socket as _sock
    s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
    s.settimeout(1.5)
    try:
        s.connect((ip, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


# Porty ktore sa ZAWSZE HTTPS (nie wymagaja TLS probe)
_KNOWN_HTTPS_PORTS = {443, 8443}
# Porty ktore sa ZAWSZE HTTP (nie wymagaja TLS probe)
_KNOWN_HTTP_PORTS  = {80}
# Fallback gdy brak danych z DB — standardowa lista priorytetow
_DEFAULT_PORT_ORDER = [443, 8443, 80, 8080, 8888, 8181, 8000]
# Porty kwalifikujace urzadzenie do proby screenshot (filtr wstepny w fill-worker)
_HTTP_HINT_PORTS   = {80, 443, 8080, 8443, 8888, 8181, 8000, 3000, 4443, 5000,
                      7443, 9090, 9443, 10443}
# Minimalny rozmiar validy screenshota (bytes).
# Strona Chrome z bledem (ERR_CONNECTION_REFUSED) lub pusta/biala strona
# daje PNG < 5KB — odrzucamy takie wyniki jako falszywe.
_MIN_VALID_PNG_BYTES = 5_000


def _find_http_port(ip: str, candidate_ports: list | None = None):
    """Zwraca (port, scheme) lub (None, None).

    candidate_ports — lista portow do sprawdzenia (z ScanResult DB).
    Filtrowane do _HTTP_HINT_PORTS — nie probujemy portu 22 (SSH), 23 (Telnet) itp.
    Jesli None lub zadny port nie jest HTTP-hint — uzywa _DEFAULT_PORT_ORDER jako fallback.

    Porty z _KNOWN_HTTPS_PORTS/HTTP_PORTS nie wymagaja TLS probe.
    Pozostale porty sa sprawdzane TLS handshake-iem.
    Priorytet: najpierw HTTPS (znane + wykryte), potem HTTP.
    """
    if candidate_ports:
        # Filtruj do portow ktore moga byc HTTP — odrzuc SSH/Telnet/SNMP/inne
        http_hints = [p for p in candidate_ports if p in _HTTP_HINT_PORTS]
        ports = http_hints if http_hints else _DEFAULT_PORT_ORDER
    else:
        ports = _DEFAULT_PORT_ORDER

    https_candidates = []
    http_candidates  = []

    for port in ports:
        if not _tcp_open(ip, port):
            continue
        if port in _KNOWN_HTTPS_PORTS:
            https_candidates.append(port)
        elif port in _KNOWN_HTTP_PORTS:
            http_candidates.append(port)
        else:
            if _is_tls(ip, port):
                https_candidates.append(port)
            else:
                http_candidates.append(port)

    if https_candidates:
        return https_candidates[0], "https"
    if http_candidates:
        return http_candidates[0], "http"
    return None, None


def _fill_missing_screenshots(max_devices: int = 5, delay_s: float = 3.0) -> int:
    """Capture screenshots/frames dla aktywnych urzadzen bez zdjecia.

    Priorytet:
    1. HTTP/HTTPS — urzadzenia z HTTP-hint portem w ScanResult (panel logowania)
    2. Nowe urzadzenia bez ScanResult — proba na domyslnych portach (wczesna proba po ping sweep)
    3. RTSP — urzadzenia z podatnoscia rtsp_noauth lub rtsp_weak_creds (klatka strumienia)

    Zwraca liczbe wykonanych capture.
    Wywolywane przez background thread — nie blokuje serwera.
    """
    import time as _time
    from datetime import datetime as _dt
    from netdoc.storage.models import ScanResult, DeviceScreenshot, Vulnerability, VulnType

    db = SessionLocal()
    try:
        # Urzadzenia ktore juz maja screenshot (device_id set — O(1) lookup)
        existing_ids = {r[0] for r in db.query(DeviceScreenshot.device_id).all()}

        # Najnowszy ScanResult per urzadzenie (klucz: device_id)
        latest_scan: dict = {}
        for sr in (db.query(ScanResult)
                     .filter(ScanResult.device_id.isnot(None))
                     .order_by(ScanResult.scan_time.desc())
                     .all()):
            if sr.device_id not in latest_scan:
                latest_scan[sr.device_id] = sr

        # Kandydaci HTTP: aktywne urzadzenia bez screenshota, z HTTP-hint portem
        http_candidates = []
        for device_id, sr in latest_scan.items():
            if device_id in existing_ids:
                continue
            if not sr.open_ports:
                continue
            scan_ports = {int(p) for p in sr.open_ports.keys()}
            if not (scan_ports & _HTTP_HINT_PORTS):
                continue
            http_candidates.append((device_id, sorted(scan_ports)))

        # Kandydaci EARLY: nowe aktywne urzadzenia bez ScanResult i bez screenshota
        # Proba na domyslnych portach HTTP — nie czekamy na zakonczenie port scan
        devices_with_scan = set(latest_scan.keys())
        from datetime import timedelta as _td
        _early_cutoff = _dt.utcnow() - _td(hours=2)
        early_candidates = (
            db.query(Device)
            .filter(
                Device.is_active.is_(True),
                Device.id.notin_(existing_ids),
                Device.id.notin_(devices_with_scan),
                Device.first_seen >= _early_cutoff,
            )
            .limit(max_devices)
            .all()
        )

        # Kandydaci RTSP: urzadzenia z podatnoscia rtsp_noauth/rtsp_weak_creds bez screenshota
        rtsp_vulns = (db.query(Vulnerability)
                        .filter(Vulnerability.vuln_type.in_([VulnType.rtsp_noauth, VulnType.rtsp_weak_creds]),
                                Vulnerability.device_id.isnot(None))
                        .all())
        rtsp_candidates = [
            v for v in rtsp_vulns
            if v.device_id not in existing_ids
        ]

        captured = 0

        # --- HTTP capture ---
        for device_id, port_list in http_candidates[:max_devices]:
            if captured >= max_devices:
                break
            dev = db.query(Device).filter(
                Device.id == device_id, Device.is_active.is_(True)
            ).first()
            if not dev:
                continue

            http_port, scheme = _find_http_port(dev.ip, port_list)
            if not http_port:
                continue

            png = _capture_screenshot(dev.ip, http_port, scheme)
            if not png:
                continue

            db.add(DeviceScreenshot(
                device_id   = device_id,
                mac         = dev.mac,
                ip          = dev.ip,
                http_port   = http_port,
                http_scheme = scheme,
                png_data    = png,
                captured_at = _dt.utcnow(),
            ))
            db.commit()
            existing_ids.add(device_id)
            captured += 1
            if captured < max_devices:
                _time.sleep(delay_s)

        # --- Early capture: nowe urzadzenia bez ScanResult ---
        for dev in early_candidates:
            if captured >= max_devices:
                break
            # Proba na domyslnych portach (bez znajomosci otwartych portow)
            http_port, scheme = _find_http_port(dev.ip, None)
            if not http_port:
                continue
            png = _capture_screenshot(dev.ip, http_port, scheme)
            if not png:
                continue
            db.add(DeviceScreenshot(
                device_id   = dev.id,
                mac         = dev.mac,
                ip          = dev.ip,
                http_port   = http_port,
                http_scheme = scheme,
                png_data    = png,
                captured_at = _dt.utcnow(),
            ))
            db.commit()
            existing_ids.add(dev.id)
            captured += 1
            import logging as _logging
            _logging.getLogger(__name__).info(
                "Early screenshot: %s port %d (brak ScanResult)", dev.ip, http_port)
            if captured < max_devices:
                _time.sleep(delay_s)

        # --- RTSP frame capture ---
        for vuln in rtsp_candidates:
            if captured >= max_devices:
                break
            if vuln.device_id in existing_ids:
                continue
            dev = db.query(Device).filter(
                Device.id == vuln.device_id, Device.is_active.is_(True)
            ).first()
            if not dev:
                continue

            # Parsuj credentials z evidence (rtsp_weak_creds: "user='admin'")
            username, password = None, None
            if vuln.vuln_type == VulnType.rtsp_weak_creds and vuln.evidence:
                import re as _re
                m = _re.search(r"user=['\"]?([^'\"\s]+)", vuln.evidence)
                if m:
                    username = m.group(1)

            port = vuln.port or 554
            png = _capture_rtsp_frame(dev.ip, port=port, username=username, password=password)
            if not png:
                continue

            db.add(DeviceScreenshot(
                device_id   = vuln.device_id,
                mac         = dev.mac,
                ip          = dev.ip,
                http_port   = port,
                http_scheme = "rtsp",
                png_data    = png,
                captured_at = _dt.utcnow(),
            ))
            db.commit()
            existing_ids.add(vuln.device_id)
            captured += 1
            import logging as _logging
            _logging.getLogger(__name__).info("RTSP frame captured: %s port %d", dev.ip, port)
            if captured < max_devices:
                _time.sleep(delay_s)

        return captured
    finally:
        db.close()


def _start_screenshot_fill_worker(interval_s: int = 1800, startup_delay_s: int = 60):
    """Uruchamia daemon thread uzupelniajacy screenshoty w tle.

    interval_s      — co ile sekund szukac urzadzen bez screenshota (domyslnie 30 min)
    startup_delay_s — opoznienie pierwszego uruchomienia po starcie serwera (domyslnie 60s)

    Gdy sa nowe urzadzenia (odkryte w ostatnich 2h bez ScanResult), worker powtarza
    probe co 5 min zamiast 30 min — screenshot pojawia sie krotko po odkryciu.
    """
    import threading
    import time as _time
    import logging

    _log = logging.getLogger(__name__)
    _FAST_INTERVAL_S = 300  # 5 min gdy sa nowe urzadzenia

    def _has_new_devices():
        """Sprawdza czy sa aktywne urzadzenia odkryte <2h temu bez screenshota."""
        from datetime import timedelta as _td2
        from netdoc.storage.models import ScanResult, DeviceScreenshot
        db2 = SessionLocal()
        try:
            cutoff = _dt.utcnow() - _td2(hours=2)
            existing = {r[0] for r in db2.query(DeviceScreenshot.device_id).all()}
            with_scan = {r[0] for r in db2.query(ScanResult.device_id).filter(
                ScanResult.device_id.isnot(None)).all()}
            return db2.query(Device).filter(
                Device.is_active.is_(True),
                Device.id.notin_(existing),
                Device.id.notin_(with_scan),
                Device.first_seen >= cutoff,
            ).first() is not None
        except Exception:
            return False
        finally:
            db2.close()

    def _worker():
        _time.sleep(startup_delay_s)
        while True:
            try:
                n = _fill_missing_screenshots(max_devices=5, delay_s=3.0)
                if n:
                    _log.info("Screenshot fill-worker: uzupelniono %d screenshotow", n)
            except Exception as exc:
                _log.warning("Screenshot fill-worker blad: %s", exc)
            # Szybszy cykl jesli sa nowe urzadzenia bez scanu
            try:
                wait = _FAST_INTERVAL_S if _has_new_devices() else interval_s
            except Exception:
                wait = interval_s
            _time.sleep(wait)

    t = threading.Thread(target=_worker, name="screenshot-fill", daemon=True)
    t.start()


def _localtime_filter(dt):
    """Convert a naive UTC datetime to local time for display in templates."""
    if dt is None:
        return ""
    import time as _time
    from datetime import timedelta as _td
    _offset = _td(seconds=(-_time.altzone
                            if _time.daylight and _time.localtime().tm_isdst
                            else -_time.timezone))
    return (dt + _offset).strftime("%Y-%m-%d %H:%M")


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = os.getenv("FLASK_SECRET_KEY", "netdoc-dev-secret")
    app.jinja_env.filters["localtime"] = _localtime_filter

    # Upewnij sie ze tabele istnieja + dodaj kolumny jesli brakuje (bezpieczna migracja)
    try:
        from netdoc.storage.database import engine
        from netdoc.storage.models import Base
        from sqlalchemy import text
        Base.metadata.create_all(bind=engine)
        # http_scheme — nowa kolumna; sprawdz czy istnieje zanim sprobujemy ALTER TABLE
        # (unikamy deadlocku gdy wiele instancji startuje jednoczesnie)
        with engine.connect() as _conn:
            _col_exists = _conn.execute(text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name='device_screenshots' AND column_name='http_scheme'"
            )).fetchone()
            if not _col_exists:
                _conn.execute(text(
                    "SET lock_timeout = '3s';"
                    "ALTER TABLE device_screenshots ADD COLUMN IF NOT EXISTS http_scheme VARCHAR(5)"
                ))
                _conn.commit()
    except Exception:
        pass

    # Inicjalizuj ustawienia konfiguracyjne jesli nie istnieja (idempotentne)
    # Rowniez uruchamiane przez run_scanner.py — tutaj jako fallback gdy skaner jeszcze nie startował
    try:
        _cfg_defaults_web = {
            "full_scan_max_age_days":  ("7",  "config"),
            "full_scan_enabled":       ("0",  "config"),
            "inventory_enabled":       ("1",  "config"),
            "cred_snmp_enabled":       ("1",  "config"),
            "cred_ssh_enabled":        ("1",  "config"),
            "cred_ftp_enabled":        ("1",  "config"),
            "cred_web_enabled":        ("1",  "config"),
            "cred_rdp_enabled":        ("1",  "config"),
            "cred_vnc_enabled":        ("1",  "config"),
            "cred_rtsp_enabled":       ("1",  "config"),
            "cred_mssql_enabled":      ("1",  "config"),
            "cred_mysql_enabled":      ("1",  "config"),
            "cred_postgres_enabled":   ("1",  "config"),
            "cred_scanning_enabled":   ("0",  "config"),
            "vuln_scanning_enabled":   ("0",  "config"),
            "community_scanning_enabled": ("0", "config"),
            "screenshot_ttl_hours":    ("12", "config"),
            "ai_assessment_enabled":   ("1",  "config"),
            "lab_monitoring_enabled":  ("0",  "config"),
            # Diagnostics / alerting
            "diag_enabled":                  ("1",   "config"),
            "diag_error_warn_per_hour":      ("200",  "config"),
            "diag_error_critical_per_hour":  ("1000", "config"),
            "diag_error_trend_pct":          ("50",  "config"),
            "diag_error_trend_days":         ("7",   "config"),
            "diag_cpu_warn_pct":             ("80",  "config"),
            "diag_cpu_critical_pct":         ("95",  "config"),
            "diag_mem_warn_pct":             ("80",  "config"),
            "diag_mem_critical_pct":         ("90",  "config"),
            "network_ranges":          ("",   "worker_settings"),
            "scan_vpn_networks":       ("0",  "worker_settings"),
            "scan_virtual_networks":   ("0",  "worker_settings"),
            "ignore_laa_macs":         ("1",  "worker_settings"),
            # ntopng integration
            "ntopng_enabled":    ("0", "config"),
            "ntopng_url":        ("", "config"),
            "ntopng_api_token":  ("", "config"),
            "ntopng_ifid":       ("0", "config"),
            # Wazuh integration
            "wazuh_enabled":      ("0", "config"),
            "wazuh_host":         ("", "config"),
            "wazuh_port":         ("5141", "config"),
            "wazuh_api_url":      ("https://netdoc-wazuh:55000", "config"),
            "wazuh_api_user":     ("wazuh", "config"),
            "wazuh_api_password": ("wazuh", "config"),
        }
        _db_init = SessionLocal()
        try:
            for _k, (_v, _cat) in _cfg_defaults_web.items():
                if not _db_init.query(SystemStatus).filter(SystemStatus.key == _k).first():
                    _db_init.add(SystemStatus(key=_k, category=_cat, value=_v))
            _db_init.commit()
        finally:
            _db_init.close()
    except Exception:
        pass

    # Uruchom worker uzupelniajacy screenshoty w tle (startuje po 60s, powtarza co 30min)
    _start_screenshot_fill_worker(interval_s=1800, startup_delay_s=60)

    def _api(method, path, **kwargs):
        try:
            resp = getattr(requests, method)(f"{API_URL}{path}", timeout=10, **kwargs)
            if resp.status_code == 422:
                # Zwróć czytelny opis błędu walidacji Pydantic
                try:
                    details = resp.json().get("detail", [])
                    if isinstance(details, list):
                        msgs = "; ".join(
                            f"{'.'.join(str(x) for x in e.get('loc', []))}: {e.get('msg', '')}"
                            for e in details
                        )
                        return None, f"Błąd walidacji: {msgs}"
                except Exception:
                    pass
                return None, f"422 Unprocessable Entity"
            resp.raise_for_status()
            if resp.status_code == 204 or not resp.content:
                return None, None
            return resp.json(), None
        except _RequestsHTTPError as e:
            try:
                if e.response is not None:
                    detail = e.response.json().get("detail", str(e))
                    if isinstance(detail, list):
                        detail = "; ".join(str(x.get("msg", x)) for x in detail)
                else:
                    detail = str(e)
            except Exception:
                detail = str(e)
            return None, str(detail)
        except Exception as e:
            return None, str(e)

    @app.context_processor
    def inject_globals():
        db = SessionLocal()
        try:
            inv_row = db.query(SystemStatus).filter_by(key="inventory_enabled").first()
            inv_on = (inv_row.value != "0") if inv_row else True
        except Exception:
            inv_on = True
        finally:
            db.close()
        return {"grafana_url": GRAFANA_URL, "inventory_enabled": inv_on, "PRO_ENABLED": PRO_ENABLED}

    # ── favicon ────────────────────────────────────────────────────────────────
    @app.route("/favicon.ico")
    def favicon():
        from flask import send_from_directory
        return send_from_directory(app.static_folder, "favicon.ico", mimetype="image/x-icon")

    # ── index ──────────────────────────────────────────────────────────────────
    @app.route("/")
    def index():
        from netdoc.storage.models import DevicePortAlert
        from sqlalchemy import func as _func
        import json as _json
        db = SessionLocal()
        try:
            device_count   = db.query(Device).count()
            network_count  = db.query(DiscoveredNetwork).count()
            active_devices = db.query(Device).filter(Device.is_active.is_(True)).count()
            credentialed_devices = db.query(Device).filter(
                Device.is_active.is_(True),
                Device.last_credential_ok_at.isnot(None)
            ).count()

            # Alerty diagnostyczne (aktywne, niepotwierdzane)
            alert_critical = db.query(DevicePortAlert).filter(
                DevicePortAlert.acknowledged_at.is_(None),
                DevicePortAlert.severity == "critical"
            ).count()
            alert_warning = db.query(DevicePortAlert).filter(
                DevicePortAlert.acknowledged_at.is_(None),
                DevicePortAlert.severity == "warning"
            ).count()

            # Typy urządzeń — sorted by count desc
            _type_rows = (
                db.query(Device.device_type, _func.count(Device.id))
                .group_by(Device.device_type)
                .order_by(_func.count(Device.id).desc())
                .all()
            )
            device_type_counts = {
                (t.value if hasattr(t, "value") else str(t)): c
                for t, c in _type_rows
                if t is not None
            }

            # Scanner status — tylko przydatne klucze
            _SCANNER_KEYS = {
                "scanner_last_at", "scanner_last_devices", "scanner_last_duration_s",
                "scanner_last_type", "scanner_job", "scan_progress",
                "scanner_started_at", "scanning_ips",
            }
            _status_rows = db.query(SystemStatus).filter(
                SystemStatus.key.in_(_SCANNER_KEYS | {"internet_status", "internet_speed"})
            ).all()
            _status = {r.key: r.value for r in _status_rows}

            try:
                internet_status = _json.loads(_status.get("internet_status", "{}")) or {}
            except Exception:
                internet_status = {}
            try:
                internet_speed = _json.loads(_status.get("internet_speed", "{}")) or {}
            except Exception:
                internet_speed = {}

            scanner_status = {k: _status.get(k, "") for k in _SCANNER_KEYS}

            # Detect active scan: started_at > last_at AND started within last 30 min
            _started_at_raw = _status.get("scanner_started_at", "")
            _last_at_raw    = _status.get("scanner_last_at", "")
            _scanner_is_scanning = False
            if _started_at_raw and (not _last_at_raw or _started_at_raw > _last_at_raw):
                try:
                    from datetime import datetime as _dt
                    _start = _dt.fromisoformat(_started_at_raw[:19])
                    _scanner_is_scanning = (_dt.utcnow() - _start).total_seconds() < 1800
                except Exception:
                    _scanner_is_scanning = True

            vuln_critical = db.query(Vulnerability).filter(
                Vulnerability.is_open.is_(True), Vulnerability.suppressed.is_(False),
                Vulnerability.severity == "critical"
            ).count()
            vuln_high = db.query(Vulnerability).filter(
                Vulnerability.is_open.is_(True), Vulnerability.suppressed.is_(False),
                Vulnerability.severity == "high"
            ).count()
            vuln_open = db.query(Vulnerability).filter(
                Vulnerability.is_open.is_(True), Vulnerability.suppressed.is_(False),
            ).count()
        finally:
            db.close()
        return render_template(
            "index.html",
            device_count=device_count,
            network_count=network_count,
            active_devices=active_devices,
            credentialed_devices=credentialed_devices,
            alert_critical=alert_critical,
            alert_warning=alert_warning,
            device_type_counts=device_type_counts,
            scanner_status=scanner_status,
            scanner_is_scanning=_scanner_is_scanning,
            vuln_critical=vuln_critical,
            vuln_high=vuln_high,
            vuln_open=vuln_open,
            internet_status=internet_status,
            internet_speed=internet_speed,
        )

    # ── devices ────────────────────────────────────────────────────────────────
    @app.route("/devices")
    def devices():
        from netdoc.storage.models import Credential, Vulnerability, Event, EventType
        from sqlalchemy import func
        from datetime import datetime, timedelta
        db = SessionLocal()
        try:
            devs = db.query(Device).order_by(Device.is_active.desc(), Device.ip).all()
            _all_nets = db.query(DiscoveredNetwork).order_by(DiscoveredNetwork.cidr).all()
            local_cidrs = {n.cidr for n in _all_nets if n.source == NetworkSource.auto}
            import ipaddress as _ipmod
            def _active_count(cidr):
                try:
                    net_obj = _ipmod.IPv4Network(cidr, strict=False)
                    return sum(1 for d in devs if d.is_active and d.ip and _ipmod.IPv4Address(d.ip) in net_obj)
                except Exception:
                    return 0
            local_sorted = sorted([n for n in _all_nets if n.cidr in local_cidrs],
                                  key=lambda n: -_active_count(n.cidr))
            other_sorted = sorted([n for n in _all_nets if n.cidr not in local_cidrs],
                                  key=lambda n: (-_active_count(n.cidr), n.cidr))
            def _net_dict(n, is_local):
                return {"cidr": n.cidr, "notes": n.notes or "", "count": _active_count(n.cidr), "is_local": is_local}
            known_networks = [_net_dict(n, True) for n in local_sorted] + [_net_dict(n, False) for n in other_sorted]
            local_networks = local_cidrs
            top_local_cidr = local_sorted[0].cidr if local_sorted else ""

            # Najlepszy credential per urzadzenie (ostatnio uzyty skutecznie)
            cred_rows = db.query(Credential).filter(
                Credential.last_success_at.isnot(None),
                Credential.device_id.isnot(None),
            ).order_by(Credential.last_success_at.desc()).all()
            cred_by_device = {}
            for c in cred_rows:
                if c.device_id not in cred_by_device:
                    cred_by_device[c.device_id] = c

            # Liczba otwartych podatnosci per urzadzenie
            vuln_counts = dict(
                db.query(Vulnerability.device_id, func.count(Vulnerability.id))
                  .filter(Vulnerability.is_open.is_(True), Vulnerability.suppressed.is_(False))
                  .group_by(Vulnerability.device_id)
                  .all()
            )
            # Max severity per urzadzenie (critical > high > medium > low)
            _sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            vuln_severity = {}
            vuln_details: dict = {}  # device_id → [{name, severity, port}, ...] sorted
            for v in db.query(Vulnerability).filter(
                Vulnerability.is_open.is_(True), Vulnerability.suppressed.is_(False)
            ).all():
                sev = getattr(v.severity, "value", str(v.severity))
                cur = vuln_severity.get(v.device_id, "")
                if _sev_order.get(sev, 0) > _sev_order.get(cur, 0):
                    vuln_severity[v.device_id] = sev
                vuln_details.setdefault(v.device_id, []).append({
                    "id":       v.id,
                    "name":     getattr(v.vuln_type, "value", str(v.vuln_type)),
                    "severity": sev,
                    "port":     v.port,
                })
            for _did in vuln_details:
                vuln_details[_did].sort(key=lambda x: -_sev_order.get(x["severity"], 0))
                _total = len(vuln_details[_did])
                vuln_details[_did] = vuln_details[_did][:10]
                if _total > 10:
                    vuln_details[_did].append({"name": f"...i {_total - 10} więcej", "severity": "", "port": None})

            # Alerty diagnostyczne per urządzenie (aktywne — acknowledged_at IS NULL)
            try:
                from netdoc.storage.models import DevicePortAlert
                _alert_rows = (
                    db.query(DevicePortAlert.device_id,
                             func.count(DevicePortAlert.id),
                             func.max(DevicePortAlert.severity))
                    .filter(DevicePortAlert.acknowledged_at.is_(None))
                    .group_by(DevicePortAlert.device_id)
                    .all()
                )
                alert_counts = {r[0]: r[1] for r in _alert_rows}
                alert_severity = {r[0]: r[2] for r in _alert_rows}
            except Exception:
                alert_counts = {}
                alert_severity = {}

            # Statystyki statusu per urzadzenie (z tabeli events, ostatnie 30 dni)
            now = datetime.utcnow()
            month_ago = now - timedelta(days=30)
            week_ago  = now - timedelta(days=7)

            # Liczba DOWN (disappearances) w ciagu ostatnich 7 dni
            down_7d = dict(
                db.query(Event.device_id, func.count(Event.id))
                  .filter(
                      Event.event_type == EventType.device_disappeared,
                      Event.event_time >= week_ago,
                      Event.device_id.isnot(None),
                  )
                  .group_by(Event.device_id)
                  .all()
            )

            # Liczba DOWN (disappearances) w ciagu ostatnich 30 dni
            down_30d = dict(
                db.query(Event.device_id, func.count(Event.id))
                  .filter(
                      Event.event_type == EventType.device_disappeared,
                      Event.event_time >= month_ago,
                      Event.device_id.isnot(None),
                  )
                  .group_by(Event.device_id)
                  .all()
            )

            # PERF-07: uzyj subquery GROUP BY zamiast ladowania calej tabeli ScanResult
            # (przy 200 urz. * 365 dni = ~73k rekordow; starszy wzorzec ladowal wszystkie)
            from netdoc.storage.models import ScanResult
            from sqlalchemy import func as _sqlfunc

            def _latest_scan_per_device(scan_type: str) -> dict:
                subq = (
                    db.query(ScanResult.device_id,
                             _sqlfunc.max(ScanResult.scan_time).label("max_st"))
                    .filter(ScanResult.device_id.isnot(None),
                            ScanResult.scan_type == scan_type)
                    .group_by(ScanResult.device_id)
                    .subquery()
                )
                rows = (
                    db.query(ScanResult)
                    .join(subq,
                          (ScanResult.device_id == subq.c.device_id) &
                          (ScanResult.scan_time  == subq.c.max_st))
                    .all()
                )
                return {sr.device_id: sr for sr in rows}

            last_scans: dict      = _latest_scan_per_device("nmap")
            last_full_scans: dict = _latest_scan_per_device("nmap_full")

            # PERF-11: Jedna query zamiast dwóch (last_down/last_up + uptime)
            # Ten sam zestaw eventów, posortowany ASC — używamy go do obu celów
            from collections import defaultdict
            all_status_events = db.query(Event).filter(
                Event.event_type.in_([
                    EventType.device_disappeared,
                    EventType.device_appeared,
                ]),
                Event.event_time >= month_ago,
                Event.device_id.isnot(None),
            ).order_by(Event.device_id, Event.event_time.asc()).all()

            # Grupuj per device i oblicz: last_down, last_up, uptime%
            last_down = {}
            last_up   = {}
            dev_events: dict = defaultdict(list)
            for e in all_status_events:
                dev_events[e.device_id].append(e)
                et = e.event_type.value if hasattr(e.event_type, "value") else str(e.event_type)
                if et == "device_disappeared":
                    last_down[e.device_id] = e.event_time  # nadpisuje → ostatni
                elif et == "device_appeared":
                    last_up[e.device_id] = e.event_time

            uptime_pct = {}
            period_sec = 30 * 24 * 3600
            for dev_id, evs in dev_events.items():
                total_down = 0
                pending_down = None
                for e in evs:
                    et = e.event_type.value if hasattr(e.event_type, "value") else str(e.event_type)
                    if et == "device_disappeared":
                        pending_down = e.event_time
                    elif et == "device_appeared" and pending_down:
                        total_down += (e.event_time - pending_down).total_seconds()
                        pending_down = None
                if pending_down:
                    total_down += (now - pending_down).total_seconds()
                pct = max(0.0, min(100.0, (1 - total_down / period_sec) * 100))
                uptime_pct[dev_id] = round(pct, 1)

            # Data bazy OUI (mtime pliku ieee_oui.txt — aktualizowany co 30 dni)
            try:
                from netdoc.collector.oui_lookup import _DATA_DIR, IEEE_SOURCES
                _oui_fpath = _DATA_DIR / IEEE_SOURCES[0]["file"]
                oui_db_date = (
                    datetime.fromtimestamp(_oui_fpath.stat().st_mtime).strftime("%Y-%m-%d")
                    if _oui_fpath.exists() else None
                )
            except Exception:
                oui_db_date = None

            # Zloz slownik statystyk per device
            device_stats = {}
            for d in devs:
                sr = last_scans.get(d.id)

                # Formatuj liste otwartych portow (max 6, z nazwami uslug)
                ports_str = None
                if sr and sr.open_ports:
                    ports = sorted(sr.open_ports.items(), key=lambda x: int(x[0]))
                    parts = []
                    for p, info in ports[:6]:
                        svc = (info.get("service", "") if isinstance(info, dict) else "")
                        parts.append(f"{p}({svc})" if svc else str(p))
                    if len(sr.open_ports) > 6:
                        parts.append(f"+{len(sr.open_ports) - 6}")
                    ports_str = ", ".join(parts)

                # Zrodlo informacji o producencie (przyblizenie na podstawie dostepnych danych)
                if d.vendor and d.mac:
                    vendor_source = "OUI (MAC)"
                elif d.vendor:
                    vendor_source = "nmap/ARP"
                else:
                    vendor_source = None

                fsr = last_full_scans.get(d.id)
                # Formatuj liste portow z pelnego skanu (max 15, z nazwami uslug)
                full_ports_str = None
                if fsr and fsr.open_ports:
                    fports = sorted(fsr.open_ports.items(), key=lambda x: int(x[0]))
                    fparts = []
                    for p, info in fports[:15]:
                        svc = (info.get("service", "") if isinstance(info, dict) else "")
                        fparts.append(f"{p}({svc})" if svc else str(p))
                    if len(fsr.open_ports) > 15:
                        fparts.append(f"+{len(fsr.open_ports) - 15}")
                    full_ports_str = ", ".join(fparts)
                # Liczba portow do wyswietlenia w kolumnie: full > quick > None
                _quick_cnt = len(sr.open_ports)  if sr  and sr.open_ports  else None
                _full_cnt  = len(fsr.open_ports) if fsr and fsr.open_ports else None
                _disp_cnt  = _full_cnt if _full_cnt is not None else _quick_cnt
                _disp_src  = ("pełny skan" if _full_cnt is not None
                              else ("szybki skan" if _quick_cnt is not None else None))
                _disp_time = (fsr.scan_time if _full_cnt is not None
                              else (sr.scan_time if sr else None))

                device_stats[d.id] = {
                    "down_7d":            down_7d.get(d.id, 0),
                    "down_30d":           down_30d.get(d.id, 0),
                    "last_down":          last_down.get(d.id),
                    "last_up":            last_up.get(d.id),
                    "uptime_pct":         uptime_pct.get(d.id),
                    "open_ports_str":     ports_str,
                    "last_scan_time":     sr.scan_time if sr else None,
                    "vendor_source":      vendor_source,
                    "last_full_scan":     fsr.scan_time if fsr else None,
                    "full_scan_ports":    _full_cnt,
                    "full_scan_ports_str": full_ports_str,
                    "display_port_count": _disp_cnt,
                    "display_port_source": _disp_src,
                    "display_port_time":  _disp_time,
                }

            # Pasek podsumowania — obliczenia na danych juz w pamieci (bez dodatkowych zapytan DB)
            _port_ranking = sorted(
                [(d, device_stats[d.id]["display_port_count"] or 0) for d in devs],
                key=lambda x: x[1], reverse=True,
            )
            _vuln_ranking = sorted(
                [(d, vuln_counts.get(d.id, 0)) for d in devs],
                key=lambda x: x[1], reverse=True,
            )
            summary = {
                "total":        len(devs),
                "up":           sum(1 for d in devs if d.is_active),
                "down":         sum(1 for d in devs if not d.is_active),
                "no_full_scan": sum(1 for d in devs
                                    if device_stats[d.id]["last_full_scan"] is None),
                "no_vulns":     sum(1 for d in devs if vuln_counts.get(d.id, 0) == 0),
                "critical":     sum(1 for d in devs
                                    if vuln_severity.get(d.id) == "critical"),
                # Top 3 po liczbie portow (tylko hosty z portami)
                "top_ports":    [(d, cnt) for d, cnt in _port_ranking if cnt > 0][:3],
                # Top 3 po liczbie podatnosci (tylko hosty z podatnosciami)
                "top_vulns":    [(d, cnt) for d, cnt in _vuln_ranking if cnt > 0][:3],
            }

            # Coverage: SSH — urządzenia z udanym logowaniem SSH
            from netdoc.storage.models import CredentialMethod as _CM
            _ssh_rows = (
                db.query(Credential.device_id)
                .filter(
                    Credential.method == _CM.ssh,
                    Credential.last_success_at.isnot(None),
                    Credential.device_id.isnot(None),
                )
                .distinct()
                .all()
            )
            cov_ssh_ids: set = {r[0] for r in _ssh_rows}

            # Coverage: LLDP/CDP — urządzenia z linkami w topology_links
            from netdoc.storage.models import TopologyLink as _TL
            _lldp_src = db.query(_TL.src_device_id).distinct().all()
            _lldp_dst = db.query(_TL.dst_device_id).distinct().all()
            cov_lldp_ids: set = {r[0] for r in _lldp_src} | {r[0] for r in _lldp_dst}

            # Coverage: FDB — urządzenia z wpisami w device_fdb (polled w ciągu 48h)
            from netdoc.storage.models import DeviceFdbEntry as _FDB
            _fdb_cutoff = now - timedelta(hours=48)
            _fdb_rows = (
                db.query(_FDB.device_id)
                .filter(_FDB.polled_at >= _fdb_cutoff)
                .distinct()
                .all()
            )
            cov_fdb_ids: set = {r[0] for r in _fdb_rows}

        finally:
            db.close()

        # Coverage: Syslog — urządzenia z logami w ClickHouse (ostatnie 24h)
        cov_syslog_ids: set = set()
        try:
            from netdoc.storage.clickhouse import _get_client as _ch_client
            _ch = _ch_client()
            _syslog_ips = {d.ip for d in devs if d.ip}
            if _syslog_ips:
                # SELECT DISTINCT device_id, src_ip dla wszystkich logów z ostatnich 24h
                _sysl_res = _ch.query(
                    "SELECT DISTINCT src_ip, device_id FROM netdoc_logs.syslog"
                    " WHERE timestamp >= now() - INTERVAL 24 HOUR"
                )
                _ip_to_devid = {d.ip: d.id for d in devs if d.ip}
                for row in _sysl_res.result_rows:
                    _sip, _did = row[0], row[1]
                    if _did:
                        cov_syslog_ids.add(int(_did))
                    elif _sip in _ip_to_devid:
                        cov_syslog_ids.add(_ip_to_devid[_sip])
        except Exception:
            pass  # ClickHouse niedostępny — brak ikony syslog

        # Coverage: Passport — dopasowanie YAML dla każdego urządzenia
        try:
            from netdoc.web.passport_loader import find_passports_bulk as _passports_bulk
            _dev_list = [{"id": d.id, "vendor": d.vendor,
                          "model": d.model, "os_version": d.os_version}
                         for d in devs]
            passports_by_device: dict = _passports_bulk(_dev_list)
        except Exception:
            passports_by_device = {}

        # Inferred capabilities — dla urządzeń bez YAML paszportu (zero dodatkowych zapytań)
        try:
            from netdoc.analyzer.capabilities import infer_capabilities_bulk as _infer_caps
            _no_passport = [d for d in devs if passports_by_device.get(d.id) is None]
            inferred_caps_by_device: dict = _infer_caps(
                _no_passport, cov_ssh_ids, cov_fdb_ids, cov_lldp_ids, cov_syslog_ids,
            )
        except Exception:
            inferred_caps_by_device = {}

        # Statystyki skanowania credentiali per urzadzenie
        cred_scan_data, _ = _api("get", "/api/credentials/cred-scan-stats")
        cred_scan_by_device = {}
        cred_scan_meta = {}
        if cred_scan_data:
            cred_scan_by_device = {d["device_id"]: d for d in cred_scan_data.get("devices", [])}
            cred_scan_meta = {
                "last_cycle_at": cred_scan_data.get("last_cycle_at"),
                "interval_s":    cred_scan_data.get("interval_s", 60),
                "cred_totals":   cred_scan_data.get("cred_totals", {}),
            }
        # Urzadzenia z potwierdzonym screenshotem w bazie
        db2 = SessionLocal()
        try:
            screenshot_device_ids = {
                r.device_id for r in db2.query(DeviceScreenshot.device_id).all()
            }
            # Ostatnia ocena AI per urzadzenie — subquery zamiast .all() (O(1) zamiast O(n))
            from sqlalchemy import func as _sqlfunc
            _ai_subq = (
                db2.query(
                    DeviceAssessment.device_id,
                    _sqlfunc.max(DeviceAssessment.assessed_at).label("max_at"),
                )
                .filter(DeviceAssessment.device_id.isnot(None))
                .group_by(DeviceAssessment.device_id)
                .subquery()
            )
            _ai_rows = (
                db2.query(DeviceAssessment)
                .join(
                    _ai_subq,
                    (DeviceAssessment.device_id == _ai_subq.c.device_id) &
                    (DeviceAssessment.assessed_at == _ai_subq.c.max_at),
                )
                .all()
            )
            ai_last_by_device: dict = {}
            for _ar in _ai_rows:
                if not _ar.device_id:
                    continue
                try:
                    _rd = _json.loads(_ar.result)
                except Exception:
                    _rd = {}
                ai_last_by_device[_ar.device_id] = {
                    "risk_level":  _rd.get("security", {}).get("risk_level", ""),
                    "is_obsolete": _rd.get("is_obsolete"),
                    "assessed_at": _ar.assessed_at.strftime("%Y-%m-%d %H:%M"),
                    "summary":     _rd.get("summary", "")[:120],
                    "entry_id":    _ar.id,
                }
            # Status skanowania (zapisywany przez run_scanner.py do SystemStatus)
            _scan_rows = {
                r.key: r.value
                for r in db2.query(SystemStatus).filter(
                    SystemStatus.key.in_(["scanner_job", "scan_progress", "scanning_ips",
                                          "inventory_enabled", "ai_assessment_enabled",
                                          "ping_inactive_after_min", "ping_interval_s"])
                ).all()
            }
        finally:
            db2.close()

        scan_job      = _scan_rows.get("scanner_job", "-")
        scan_progress = _scan_rows.get("scan_progress", "")
        _scanning_raw = _scan_rows.get("scanning_ips", "")
        scanning_ips  = set(_scanning_raw.split(",")) - {""}
        inventory_enabled = _scan_rows.get("inventory_enabled", "1") != "0"
        ai_assessment_enabled = _scan_rows.get("ai_assessment_enabled", "1") != "0"

        # Prog niepewnosci: lekko powyzej progu inaktywnosci ping workera,
        # zeby "?" pojawil sie gdy monitoring przestaje dzialac (ping worker padl).
        _ping_inactive_min = int(_scan_rows.get("ping_inactive_after_min", 5))
        _ping_interval_s   = int(_scan_rows.get("ping_interval_s", 18))
        uncertain_min = _ping_inactive_min + 2   # nadpisuje stala powyzej

        # Sprawdz czy monitoring jest globalnie przestarzaly (ping worker mogl pasc).
        # Bierzemy najswiezszy last_seen wsrod wszystkich urzadzen aktywnych lub nie.
        _all_last_seen = [d.last_seen for d in devs if d.last_seen]
        if _all_last_seen:
            _newest_seen = max(_all_last_seen)
            _monitoring_age_min = int((now - _newest_seen).total_seconds() / 60)
        else:
            _monitoring_age_min = 0
        # Monitoring jest przestarzaly gdy najswiezszy kontakt z jakimkolwiek hostem
        # jest starszy niz min. 30 min LUB 6x prog inaktywnosci ping workera.
        # Minimalna wartosc 30 min zapobiega falszywym alarmom po restarcie.
        _stale_threshold = max(30, _ping_inactive_min * 6)
        # Wymaga >= 2 min zeby uniknac "0 min temu" (zaokraglenie w dol przy swiezym last_seen)
        monitoring_stale = _monitoring_age_min > _stale_threshold and _monitoring_age_min >= 2
        monitoring_age_min = _monitoring_age_min
        stale_threshold_min = _stale_threshold

        return render_template("devices.html", devices=devs,
                               cred_by_device=cred_by_device,
                               vuln_counts=vuln_counts,
                               vuln_severity=vuln_severity,
                               vuln_details=vuln_details,
                               device_stats=device_stats,
                               summary=summary,
                               oui_db_date=oui_db_date,
                               now=now,
                               uncertain_min=uncertain_min,
                               cred_scan_by_device=cred_scan_by_device,
                               cred_scan_meta=cred_scan_meta,
                               screenshot_device_ids=screenshot_device_ids,
                               scan_job=scan_job,
                               scan_progress=scan_progress,
                               scanning_ips=scanning_ips,
                               inventory_enabled=inventory_enabled,
                               ai_assessment_enabled=ai_assessment_enabled,
                               monitoring_stale=monitoring_stale,
                               monitoring_age_min=monitoring_age_min,
                               stale_threshold_min=stale_threshold_min,
                               ping_interval_s=_ping_interval_s,
                               ai_last_by_device=ai_last_by_device,
                               known_networks=known_networks,
                               local_networks=local_networks,
                               top_local_cidr=top_local_cidr,
                               alert_counts=alert_counts,
                               alert_severity=alert_severity,
                               passports_by_device=passports_by_device,
                               inferred_caps_by_device=inferred_caps_by_device,
                               cov_ssh_ids=cov_ssh_ids,
                               cov_lldp_ids=cov_lldp_ids,
                               cov_fdb_ids=cov_fdb_ids,
                               cov_syslog_ids=cov_syslog_ids)

    @app.route("/devices/live-status")
    def devices_live_status():
        """Lekki endpoint JSON do odswiezania statusow bez pelnego reload strony.

        Parametr ?since=<ISO_UTC> — gdy podany, zwraca tez new_device_ids:
        liste ID urzadzen odkrytych PO tym momencie (first_seen > since).
        JS uzywa tego do dynamicznego doklejania nowych wierszy do tabeli.
        """
        from datetime import datetime as _dt
        from flask import jsonify as _jsonify, request as _req
        db = SessionLocal()
        try:
            devs = db.query(Device).all()
            _now = _dt.utcnow()
            # Parsuj parametr ?since= (UTC ISO, np. 2026-03-16T10:00:00)
            _since_str = _req.args.get("since", "")
            _since_dt = None
            if _since_str:
                try:
                    _s = _since_str.replace("Z", "").replace("+00:00", "")
                    _since_dt = _dt.fromisoformat(_s)
                except (ValueError, AttributeError):
                    pass
            # Czytaj uncertain_min z DB
            def _si(key, default):
                r = db.query(SystemStatus).filter(SystemStatus.key == key).first()
                try:
                    return int(r.value) if (r and r.value not in (None, "")) else default
                except (ValueError, TypeError):
                    return default
            _ping_inact = _si("ping_inactive_after_min", 5)
            _uncertain  = _ping_inact + 2
            items = []
            new_device_ids = []
            changed_device_ids = []
            for d in devs:
                # Uzywamy last_ping_ok_at do obliczenia mins_ago — last_seen moze byc falszywie
                # odswiezone przez discovery/ARP dla offline urzadzen (BUG-L-STATUS-03).
                # Fallback na last_seen jesli urzadzenie nie bylo jeszcze pingowane (migracja).
                _ping_ts = d.last_ping_ok_at or d.last_seen
                mins_ago = int((_now - _ping_ts).total_seconds() / 60) if _ping_ts else None
                items.append({
                    "id":        d.id,
                    "is_active": d.is_active,
                    "last_seen": d.last_seen.strftime("%Y-%m-%d %H:%M") if d.last_seen else None,
                    "last_seen_iso": d.last_seen.isoformat() if d.last_seen else None,
                    "mins_ago":  mins_ago,
                    # Dane do detekcji zmian w wierszach (JS porownuje z data-* atrybutami)
                    "hostname":  (d.hostname or "").lower(),
                    "vendor":    (d.vendor or "").lower(),
                    "snmp_ok":   2 if d.snmp_community else 0,
                })
                # Urzadzenie jest "nowe" jesli first_seen > since (odkryte po zaladowaniu strony)
                if _since_dt and d.first_seen and d.first_seen > _since_dt:
                    new_device_ids.append(d.id)
            # min() — chcemy czas od NAJŚWIEŻSZEGO kontaktu (odpowiednik max(datetimes) w devices())
            # Większe mins_ago = widziane dawniej; min(mins_ago) = urządzenie widziane najniedawniej
            # max(mins_ago) byłby błędny: zgłaszałby stale gdy JEDNO urządzenie jest offline od dawna
            _all_mins = [i["mins_ago"] for i in items if i["mins_ago"] is not None]
            mon_age   = min(_all_mins) if _all_mins else 0
            _stale_thr = max(30, _ping_inact * 6)
            return _jsonify({
                "devices":           items,
                "uncertain_min":     _uncertain,
                "monitoring_stale":  mon_age > _stale_thr and mon_age >= 2,
                "monitoring_age_min": mon_age,
                "new_device_ids":    new_device_ids,
                "total_count":       len(devs),
            })
        finally:
            db.close()

    @app.route("/devices/rows")
    def devices_rows():
        """Zwraca HTML wierszy <tr> dla podanych ID urzadzen (do dynamicznego wstrzykiwania).

        Parametr ?ids=1,2,3 — lista ID po przecinku.
        Uzywany przez JS gdy live-status zwroci new_device_ids.
        """
        from flask import request as _req
        from datetime import datetime, timedelta
        from netdoc.storage.models import (
            Credential, Vulnerability, Event, EventType, ScanResult,
            DeviceScreenshot, DeviceAssessment,
        )
        from sqlalchemy import func as _func
        from collections import defaultdict
        import json as _json2

        _ids_raw = _req.args.get("ids", "")
        try:
            device_ids = [int(x) for x in _ids_raw.split(",") if x.strip().isdigit()]
        except ValueError:
            return "", 400
        if not device_ids:
            return "", 200

        db = SessionLocal()
        try:
            devs = db.query(Device).filter(Device.id.in_(device_ids)).all()
            if not devs:
                return "", 200

            now = datetime.utcnow()
            month_ago = now - timedelta(days=30)
            dev_id_set = {d.id for d in devs}

            # Credentials (najlepszy skuteczny per urzadzenie)
            cred_rows = db.query(Credential).filter(
                Credential.last_success_at.isnot(None),
                Credential.device_id.in_(dev_id_set),
            ).order_by(Credential.last_success_at.desc()).all()
            cred_by_device = {}
            for c in cred_rows:
                if c.device_id not in cred_by_device:
                    cred_by_device[c.device_id] = c

            # Podatnosci
            vuln_counts = dict(
                db.query(Vulnerability.device_id, _func.count(Vulnerability.id))
                  .filter(Vulnerability.is_open.is_(True),
                          Vulnerability.suppressed.is_(False),
                          Vulnerability.device_id.in_(dev_id_set))
                  .group_by(Vulnerability.device_id)
                  .all()
            )
            _sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            vuln_severity = {}
            vuln_details: dict = {}
            for v in db.query(Vulnerability).filter(
                Vulnerability.is_open.is_(True), Vulnerability.suppressed.is_(False),
                Vulnerability.device_id.in_(dev_id_set),
            ).all():
                sev = getattr(v.severity, "value", str(v.severity))
                cur = vuln_severity.get(v.device_id, "")
                if _sev_order.get(sev, 0) > _sev_order.get(cur, 0):
                    vuln_severity[v.device_id] = sev
                vuln_details.setdefault(v.device_id, []).append({
                    "id": v.id, "name": getattr(v.vuln_type, "value", str(v.vuln_type)),
                    "severity": sev, "port": v.port,
                })
            for _did in vuln_details:
                vuln_details[_did].sort(key=lambda x: -_sev_order.get(x["severity"], 0))
                _total = len(vuln_details[_did])
                vuln_details[_did] = vuln_details[_did][:10]
                if _total > 10:
                    vuln_details[_did].append({"name": f"...i {_total - 10} więcej",
                                                "severity": "", "port": None})

            # Alerty diagnostyczne per urządzenie (live rows)
            try:
                from netdoc.storage.models import DevicePortAlert
                _alert_rows2 = (
                    db.query(DevicePortAlert.device_id,
                             _func.count(DevicePortAlert.id),
                             _func.max(DevicePortAlert.severity))
                    .filter(DevicePortAlert.acknowledged_at.is_(None),
                            DevicePortAlert.device_id.in_(dev_id_set))
                    .group_by(DevicePortAlert.device_id)
                    .all()
                )
                alert_counts  = {r[0]: r[1] for r in _alert_rows2}
                alert_severity = {r[0]: r[2] for r in _alert_rows2}
            except Exception:
                alert_counts = {}
                alert_severity = {}

            # Events (statystyki statusu)
            down_7d = dict(
                db.query(Event.device_id, _func.count(Event.id))
                  .filter(Event.event_type == EventType.device_disappeared,
                          Event.event_time >= (now - timedelta(days=7)),
                          Event.device_id.in_(dev_id_set))
                  .group_by(Event.device_id).all()
            )
            down_30d = dict(
                db.query(Event.device_id, _func.count(Event.id))
                  .filter(Event.event_type == EventType.device_disappeared,
                          Event.event_time >= month_ago,
                          Event.device_id.in_(dev_id_set))
                  .group_by(Event.device_id).all()
            )
            last_down = {}
            last_up = {}
            uptime_pct = {}
            dev_events_map = defaultdict(list)
            for e in db.query(Event).filter(
                Event.event_type.in_([EventType.device_disappeared, EventType.device_appeared]),
                Event.event_time >= month_ago,
                Event.device_id.in_(dev_id_set),
            ).order_by(Event.device_id, Event.event_time.asc()).all():
                et = e.event_type.value if hasattr(e.event_type, "value") else str(e.event_type)
                if et == "device_disappeared":
                    last_down[e.device_id] = e.event_time
                if et == "device_appeared":
                    last_up[e.device_id] = e.event_time
                dev_events_map[e.device_id].append(e)
            period_sec = 30 * 24 * 3600
            for dev_id, evs in dev_events_map.items():
                total_down = 0
                pending_down = None
                for e in evs:
                    et = e.event_type.value if hasattr(e.event_type, "value") else str(e.event_type)
                    if et == "device_disappeared":
                        pending_down = e.event_time
                    elif et == "device_appeared" and pending_down:
                        total_down += (e.event_time - pending_down).total_seconds()
                        pending_down = None
                if pending_down:
                    total_down += (now - pending_down).total_seconds()
                pct = max(0.0, min(100.0, (1 - total_down / period_sec) * 100))
                uptime_pct[dev_id] = round(pct, 1)

            # Skany (szybki + pelny)
            last_scans = {}
            last_full_scans = {}
            for sr in db.query(ScanResult).filter(
                ScanResult.device_id.in_(dev_id_set),
                ScanResult.scan_type.in_(["nmap", "nmap_full"]),
            ).order_by(ScanResult.scan_time.desc()).all():
                if sr.scan_type == "nmap" and sr.device_id not in last_scans:
                    last_scans[sr.device_id] = sr
                elif sr.scan_type == "nmap_full" and sr.device_id not in last_full_scans:
                    last_full_scans[sr.device_id] = sr

            # OUI db date
            try:
                from netdoc.collector.oui_lookup import _DATA_DIR, IEEE_SOURCES
                _oui_fpath = _DATA_DIR / IEEE_SOURCES[0]["file"]
                oui_db_date = (
                    datetime.fromtimestamp(_oui_fpath.stat().st_mtime).strftime("%Y-%m-%d")
                    if _oui_fpath.exists() else None
                )
            except Exception:
                oui_db_date = None

            # device_stats (taka sama logika jak w devices())
            device_stats = {}
            for d in devs:
                sr = last_scans.get(d.id)
                fsr = last_full_scans.get(d.id)
                ports_str = None
                if sr and sr.open_ports:
                    ports = sorted(sr.open_ports.items(), key=lambda x: int(x[0]))
                    parts = []
                    for p, info in ports[:6]:
                        svc = (info.get("service", "") if isinstance(info, dict) else "")
                        parts.append(f"{p}({svc})" if svc else str(p))
                    if len(sr.open_ports) > 6:
                        parts.append(f"+{len(sr.open_ports) - 6}")
                    ports_str = ", ".join(parts)
                full_ports_str = None
                if fsr and fsr.open_ports:
                    fports = sorted(fsr.open_ports.items(), key=lambda x: int(x[0]))
                    fparts = []
                    for p, info in fports[:15]:
                        svc = (info.get("service", "") if isinstance(info, dict) else "")
                        fparts.append(f"{p}({svc})" if svc else str(p))
                    if len(fsr.open_ports) > 15:
                        fparts.append(f"+{len(fsr.open_ports) - 15}")
                    full_ports_str = ", ".join(fparts)
                _quick_cnt = len(sr.open_ports)  if sr  and sr.open_ports  else None
                _full_cnt  = len(fsr.open_ports) if fsr and fsr.open_ports else None
                _disp_cnt  = _full_cnt if _full_cnt is not None else _quick_cnt
                _disp_src  = ("pełny skan" if _full_cnt is not None
                              else ("szybki skan" if _quick_cnt is not None else None))
                _disp_time = (fsr.scan_time if _full_cnt is not None
                              else (sr.scan_time if sr else None))
                vendor_source = ("OUI (MAC)" if (d.vendor and d.mac)
                                 else ("nmap/ARP" if d.vendor else None))
                device_stats[d.id] = {
                    "down_7d": down_7d.get(d.id, 0), "down_30d": down_30d.get(d.id, 0),
                    "last_down": last_down.get(d.id), "last_up": last_up.get(d.id),
                    "uptime_pct": uptime_pct.get(d.id),
                    "open_ports_str": ports_str,
                    "last_scan_time": sr.scan_time if sr else None,
                    "vendor_source": vendor_source,
                    "last_full_scan": fsr.scan_time if fsr else None,
                    "full_scan_ports": _full_cnt,
                    "full_scan_ports_str": full_ports_str,
                    "display_port_count": _disp_cnt,
                    "display_port_source": _disp_src,
                    "display_port_time": _disp_time,
                }

            # Screenshoty
            screenshot_device_ids = {
                r.device_id for r in db.query(DeviceScreenshot.device_id)
                                        .filter(DeviceScreenshot.device_id.in_(dev_id_set)).all()
            }

            # Ostatnia ocena AI
            from sqlalchemy import func as _sqlfunc2
            _ai_subq = (
                db.query(DeviceAssessment.device_id,
                         _sqlfunc2.max(DeviceAssessment.assessed_at).label("max_at"))
                  .filter(DeviceAssessment.device_id.in_(dev_id_set))
                  .group_by(DeviceAssessment.device_id).subquery()
            )
            _ai_rows = (
                db.query(DeviceAssessment)
                  .join(_ai_subq,
                        (DeviceAssessment.device_id == _ai_subq.c.device_id) &
                        (DeviceAssessment.assessed_at == _ai_subq.c.max_at))
                  .all()
            )
            ai_last_by_device = {}
            for _ar in _ai_rows:
                if not _ar.device_id:
                    continue
                try:
                    _rd = _json2.loads(_ar.result)
                except Exception:
                    _rd = {}
                ai_last_by_device[_ar.device_id] = {
                    "risk_level": _rd.get("security", {}).get("risk_level", ""),
                    "is_obsolete": _rd.get("is_obsolete"),
                    "assessed_at": _ar.assessed_at.strftime("%Y-%m-%d %H:%M"),
                    "summary": _rd.get("summary", "")[:120],
                    "entry_id": _ar.id,
                }

            # SystemStatus (scanning_ips, uncertain_min, flags)
            _scan_rows = {
                r.key: r.value
                for r in db.query(SystemStatus).filter(
                    SystemStatus.key.in_(["scanning_ips", "inventory_enabled",
                                          "ai_assessment_enabled",
                                          "ping_inactive_after_min", "ping_interval_s"])
                ).all()
            }

            # Coverage: SSH
            from netdoc.storage.models import CredentialMethod as _CM2
            _ssh_rows2 = (
                db.query(Credential.device_id)
                .filter(
                    Credential.method == _CM2.ssh,
                    Credential.last_success_at.isnot(None),
                    Credential.device_id.in_(dev_id_set),
                )
                .distinct().all()
            )
            cov_ssh_ids: set = {r[0] for r in _ssh_rows2}

            # Coverage: LLDP
            from netdoc.storage.models import TopologyLink as _TL2
            _lldp_src2 = db.query(_TL2.src_device_id).filter(_TL2.src_device_id.in_(dev_id_set)).distinct().all()
            _lldp_dst2 = db.query(_TL2.dst_device_id).filter(_TL2.dst_device_id.in_(dev_id_set)).distinct().all()
            cov_lldp_ids: set = {r[0] for r in _lldp_src2} | {r[0] for r in _lldp_dst2}

            # Coverage: FDB
            from netdoc.storage.models import DeviceFdbEntry as _FDB2
            _fdb_cutoff2 = now - timedelta(hours=48)
            _fdb_rows2 = (
                db.query(_FDB2.device_id)
                .filter(_FDB2.polled_at >= _fdb_cutoff2, _FDB2.device_id.in_(dev_id_set))
                .distinct().all()
            )
            cov_fdb_ids: set = {r[0] for r in _fdb_rows2}

        finally:
            db.close()

        # Coverage: Syslog
        cov_syslog_ids: set = set()
        try:
            from netdoc.storage.clickhouse import _get_client as _ch_client2
            _ch2 = _ch_client2()
            _sysl_res2 = _ch2.query(
                "SELECT DISTINCT src_ip, device_id FROM netdoc_logs.syslog"
                " WHERE timestamp >= now() - INTERVAL 24 HOUR"
            )
            _ip_to_devid2 = {d.ip: d.id for d in devs if d.ip}
            for row in _sysl_res2.result_rows:
                _sip2, _did2 = row[0], row[1]
                if _did2:
                    cov_syslog_ids.add(int(_did2))
                elif _sip2 in _ip_to_devid2:
                    cov_syslog_ids.add(_ip_to_devid2[_sip2])
        except Exception:
            pass

        # Coverage: Passport
        try:
            from netdoc.web.passport_loader import find_passports_bulk as _passports_bulk2
            _dev_list2 = [{"id": d.id, "vendor": d.vendor,
                           "model": d.model, "os_version": d.os_version}
                          for d in devs]
            passports_by_device: dict = _passports_bulk2(_dev_list2)
        except Exception:
            passports_by_device = {}

        # Inferred capabilities — dla urządzeń bez YAML paszportu
        try:
            from netdoc.analyzer.capabilities import infer_capabilities_bulk as _infer_caps2
            _no_passport2 = [d for d in devs if passports_by_device.get(d.id) is None]
            inferred_caps_by_device: dict = _infer_caps2(
                _no_passport2, cov_ssh_ids, cov_fdb_ids, cov_lldp_ids, cov_syslog_ids,
            )
        except Exception:
            inferred_caps_by_device = {}

        # Cred scan stats z API
        cred_scan_data, _ = _api("get", "/api/credentials/cred-scan-stats")
        cred_scan_by_device = {}
        if cred_scan_data:
            cred_scan_by_device = {d["device_id"]: d
                                   for d in cred_scan_data.get("devices", [])
                                   if d["device_id"] in dev_id_set}

        _ping_inactive_min = int(_scan_rows.get("ping_inactive_after_min", 5))
        _ping_interval_s   = int(_scan_rows.get("ping_interval_s", 18))
        _scanning_raw      = _scan_rows.get("scanning_ips", "")
        scanning_ips       = set(_scanning_raw.split(",")) - {""}
        inventory_enabled      = _scan_rows.get("inventory_enabled", "1") != "0"
        ai_assessment_enabled  = _scan_rows.get("ai_assessment_enabled", "1") != "0"
        uncertain_min = _ping_inactive_min + 2

        return render_template(
            "_devices_rows_fragment.html",
            devices=devs,
            cred_by_device=cred_by_device,
            vuln_counts=vuln_counts,
            vuln_severity=vuln_severity,
            vuln_details=vuln_details,
            device_stats=device_stats,
            oui_db_date=oui_db_date,
            now=now,
            uncertain_min=uncertain_min,
            cred_scan_by_device=cred_scan_by_device,
            screenshot_device_ids=screenshot_device_ids,
            scanning_ips=scanning_ips,
            inventory_enabled=inventory_enabled,
            ai_assessment_enabled=ai_assessment_enabled,
            ping_interval_s=_ping_interval_s,
            ai_last_by_device=ai_last_by_device,
            alert_counts=alert_counts,
            alert_severity=alert_severity,
            passports_by_device=passports_by_device,
            inferred_caps_by_device=inferred_caps_by_device,
            cov_ssh_ids=cov_ssh_ids,
            cov_lldp_ids=cov_lldp_ids,
            cov_fdb_ids=cov_fdb_ids,
            cov_syslog_ids=cov_syslog_ids,
        )

    @app.route("/devices/<int:device_id>")
    def device_detail(device_id):
        """Strona szczegółów urządzenia: parametry, historia pingów, zmiany pól, interfejsy, syslog."""
        from netdoc.storage.models import (
            DeviceFieldHistory, InterfaceHistory, Interface, ScanResult,
            Vulnerability, TopologyLink, DeviceSensor, DeviceVap,
        )
        from netdoc.storage.clickhouse import query_ping_history, query_ping_stats, query_syslog
        db = SessionLocal()
        try:
            dev = db.query(Device).filter(Device.id == device_id).first()
            if not dev:
                flash("Urządzenie nie znalezione.", "danger")
                return redirect(url_for("devices"))

            # Interfejsy bieżące (z modelu Interface)
            interfaces = (
                db.query(Interface)
                .filter(Interface.device_id == device_id)
                .order_by(Interface.name)
                .all()
            )

            # Ostatni wynik skanu (porty otwarte)
            latest_scan = (
                db.query(ScanResult)
                .filter(ScanResult.device_id == device_id)
                .order_by(ScanResult.scan_time.desc())
                .first()
            )

            # Podatności (aktywne)
            from sqlalchemy import case as _case_d
            _sev_ord = _case_d(
                (Vulnerability.severity == "critical", 0),
                (Vulnerability.severity == "high", 1),
                (Vulnerability.severity == "medium", 2),
                (Vulnerability.severity == "low", 3),
                else_=4,
            )
            vulns = (
                db.query(Vulnerability)
                .filter(Vulnerability.device_id == device_id, Vulnerability.is_open.is_(True))
                .order_by(_sev_ord, Vulnerability.title)
                .all()
            )

            # Sąsiedzi LLDP/CDP (topologia) — gdzie src lub dst = to urządzenie
            topo_links = (
                db.query(TopologyLink)
                .filter(
                    (TopologyLink.src_device_id == device_id) |
                    (TopologyLink.dst_device_id == device_id)
                )
                .order_by(TopologyLink.last_seen.desc())
                .limit(30)
                .all()
            )

            field_history = (
                db.query(DeviceFieldHistory)
                .filter(DeviceFieldHistory.device_id == device_id)
                .order_by(DeviceFieldHistory.changed_at.desc())
                .limit(50)
                .all()
            )
            iface_history = (
                db.query(InterfaceHistory)
                .filter(InterfaceHistory.device_id == device_id)
                .order_by(InterfaceHistory.changed_at.desc())
                .limit(100)
                .all()
            )

            ping_history = []
            ping_stats   = {}
            syslog_rows  = []
            try:
                ping_history = query_ping_history(ip=str(dev.ip), since_hours=24, step_minutes=5)
                ping_stats   = query_ping_stats(ip=str(dev.ip), since_hours=24)
            except Exception:
                pass
            try:
                syslog_rows = query_syslog(src_ip=str(dev.ip), since_hours=48, limit=15)
            except Exception:
                pass

            # Broadcast stats — from broadcast_stats.json (per-IP packet counters)
            # plus optional [broadcast ...] tag in asset_notes (svc/serial/upnp)
            import re as _re
            broadcast_info = {}
            _stats_file = pathlib.Path(__file__).parent.parent.parent / "logs" / "broadcast_stats.json"
            try:
                import json as _json2
                _bdata = _json2.loads(_stats_file.read_text(encoding="utf-8"))
                for _row in _bdata.get("rows", []):
                    if _row.get("ip") == str(dev.ip):
                        broadcast_info.update({
                            "total_pkts":  _row.get("total_pkts", 0),
                            "total_bytes": _row.get("total_bytes", 0),
                            "top_proto":   _row.get("top_proto", ""),
                            "protocols":   _row.get("protocols", {}),
                        })
                        break
            except Exception:
                pass
            # Enrich with asset_notes tag if present
            if dev.asset_notes:
                _bm = _re.search(r'\[broadcast ([^\]]+)\]', dev.asset_notes)
                if _bm:
                    for _part in _bm.group(1).split():
                        if '=' in _part:
                            _k, _v = _part.split('=', 1)
                            broadcast_info[_k] = _v

            # Sensors (temperature, CPU, RAM, voltage, fans)
            sensors = (
                db.query(DeviceSensor)
                .filter(DeviceSensor.device_id == device_id)
                .order_by(DeviceSensor.sensor_name)
                .all()
            )

            # WiFi VAP data (Ubiquiti UniFi APs)
            vap_data = (
                db.query(DeviceVap)
                .filter(DeviceVap.device_id == device_id)
                .order_by(DeviceVap.radio_band, DeviceVap.ssid)
                .all()
            )

            # Passports already generated for this device
            from netdoc.storage.models import DevicePassport
            passports = (
                db.query(DevicePassport)
                .filter(DevicePassport.device_id == device_id)
                .order_by(DevicePassport.generated_at.desc())
                .limit(5)
                .all()
            )

            # Passport readiness — shown in confirmation modal before generating (Pro only)
            passport_readiness = {}
            if PRO_PASSPORT:
                from netdoc.storage.models import Credential as _Cred, CredentialMethod as _CM
                from sqlalchemy import exists as _exists
                import datetime as _dt
                _now = _dt.datetime.utcnow()
                _snmp_age_h = None
                if dev.snmp_ok_at:
                    _snmp_age_h = round((_now - dev.snmp_ok_at).total_seconds() / 3600, 1)
                # SSH success: per-device credential with last_success_at (SSH-specific)
                _ssh_ok = db.query(
                    _exists().where(
                        _Cred.device_id == device_id,
                        _Cred.method == _CM.ssh,
                        _Cred.last_success_at.isnot(None),
                    )
                ).scalar()
                _has_ssh_cred = db.query(
                    _exists().where(
                        _Cred.method == _CM.ssh,
                        _Cred.device_id.is_(None),
                    )
                ).scalar()
                # Find RAM from sensors (Cisco uses mem_total_mb, others ram_total_mb)
                _sensor_map = {s.sensor_name: s.value for s in sensors}
                _ram_mb = None
                for _k in ("ram_total_mb", "mem_total_mb", "ram_total_mb_1"):
                    _v = _sensor_map.get(_k)
                    if _v and _v > 0:
                        _ram_mb = round(_v)
                        break
                if not _ram_mb:
                    _ram_mb = dev.ram_total_mb
                passport_readiness = {
                    "snmp_ok":      dev.snmp_ok_at is not None,
                    "snmp_age_h":   _snmp_age_h,
                    "snmp_ok_at":   dev.snmp_ok_at.strftime("%Y-%m-%d %H:%M") if dev.snmp_ok_at else None,
                    "ssh_ok":       _ssh_ok,
                    "ssh_cred":     _has_ssh_cred,
                    "sensor_count": len(sensors),
                    "iface_count":  len(interfaces),
                    "ram_mb":       _ram_mb,
                    "serial":       dev.serial_number,
                }

            return render_template(
                "device_detail.html",
                dev=dev,
                interfaces=interfaces,
                latest_scan=latest_scan,
                vulns=vulns,
                topo_links=topo_links,
                field_history=field_history,
                iface_history=iface_history,
                ping_history=ping_history,
                ping_stats=ping_stats,
                syslog_rows=syslog_rows,
                broadcast_info=broadcast_info,
                sensors=sensors,
                vap_data=vap_data,
                passports=passports,
                pro_passport=PRO_PASSPORT,
                passport_readiness=passport_readiness,
            )
        finally:
            db.close()

    @app.route("/device_passports/<path:filename>")
    def device_passport_file(filename):
        """Serwuje wygenerowane pliki passport HTML jako pliki statyczne."""
        import pathlib
        from flask import send_from_directory as _sfd
        passport_dir = str(pathlib.Path(__file__).parent.parent.parent / "device_passports")
        return _sfd(passport_dir, filename)

    @app.route("/devices/<int:device_id>/passport", methods=["POST"])
    def device_passport_generate(device_id):
        if not PRO_PASSPORT:
            flash("Device Passport requires NetDoc Pro.", "warning")
            return redirect(url_for("device_detail", device_id=device_id))
        db = SessionLocal()
        try:
            token, filename = generate_passport(db, device_id)
            flash(f"Passport generated: {filename}", "success")
        except Exception as exc:
            db.rollback()
            flash(f"Passport generation failed: {exc}", "danger")
        finally:
            db.close()
        return redirect(url_for("device_detail", device_id=device_id))

    @app.route("/devices/<int:device_id>/reclassify", methods=["POST"])
    def device_reclassify(device_id):
        data, err = _api("post", f"/api/devices/{device_id}/reclassify")
        if err:
            flash(f"Blad reklasyfikacji: {err}", "danger")
        else:
            flash(f"Reklasyfikacja: {data.get('device_type', '?')}", "success")
        return redirect(url_for("devices"))

    @app.route("/devices/<int:device_id>/set-type", methods=["POST"])
    def device_set_type(device_id):
        new_type = request.form.get("device_type", "").strip()
        data, err = _api("patch", f"/api/devices/{device_id}", json={"device_type": new_type})
        if err:
            flash(f"Blad: {err}", "danger")
        else:
            flash("Typ urzadzenia zaktualizowany.", "success")
        return redirect(url_for("devices"))

    @app.route("/devices/<int:device_id>/trust", methods=["POST"])
    def device_trust(device_id):
        trusted = request.form.get("trusted", "0") == "1"
        note     = request.form.get("trust_note", "").strip() or None
        category = request.form.get("trust_category", "").strip() or None
        _, err = _api("patch", f"/api/devices/{device_id}/trust",
                      json={"trusted": trusted, "note": note, "category": category})
        if err:
            flash(f"Blad: {err}", "danger")
        elif trusted:
            flash("Urządzenie oznaczone jako zaufane.", "success")
        else:
            flash("Urządzenie usunięte z listy zaufanych.", "info")
        return redirect(url_for("devices"))

    @app.route("/devices/<int:device_id>/full-scan", methods=["POST"])
    def device_full_scan(device_id):
        """Wstawia IP urządzenia do kolejki pełnego skanu portów 1-65535."""
        db = SessionLocal()
        try:
            dev = db.query(Device).filter_by(id=device_id).first()
            if not dev:
                flash("Urządzenie nie znalezione.", "danger")
                return redirect(url_for("devices"))
            # Dodaj IP do kolejki full scan (klucz full_scan_ip_queue, oddzielone przecinkami)
            existing_row = db.query(SystemStatus).filter_by(key="full_scan_ip_queue").first()
            existing = existing_row.value if existing_row else ""
            ips_set = set(x.strip() for x in existing.split(",") if x.strip())
            already_queued = dev.ip in ips_set
            ips_set.add(dev.ip)
            new_val = ",".join(sorted(ips_set))
            if existing_row:
                existing_row.value = new_val
            else:
                db.add(SystemStatus(key="full_scan_ip_queue", value=new_val, category="scanner"))
            # Wznów skaner jeśli w cooldownie
            req_row = db.query(SystemStatus).filter_by(key="scan_requested").first()
            if req_row:
                req_row.value = "full_single"
            else:
                db.add(SystemStatus(key="scan_requested", value="full_single", category="scanner"))
            db.commit()
            if already_queued:
                flash(f"{dev.ip} ({dev.hostname or 'no hostname'}) is already queued for full scan.", "warning")
            else:
                flash(f"Full port scan 1-65535 for {dev.ip} ({dev.hostname or 'no hostname'}) scheduled. It will run on the next scanner cycle.", "info")
        finally:
            db.close()
        return redirect(url_for("devices"))

    @app.route("/devices/<int:device_id>/clear-ports", methods=["POST"])
    def device_clear_ports(device_id):
        """Usuwa wyniki skanowania portow dla jednego urzadzenia (nmap + nmap_full)."""
        scan_type = request.form.get("scan_type", "")  # "" = oba typy
        param = f"?scan_type={scan_type}" if scan_type else ""
        data, err = _api("delete", f"/api/devices/{device_id}/scan-results{param}")
        if err:
            flash(f"Error clearing ports: {err}", "danger")
        else:
            deleted = (data or {}).get("deleted", 0)
            label = {"nmap_full": "pełnego skanu", "nmap": "szybkiego skanu"}.get(scan_type, "wszystkich skanów")
            flash(f"Usunięto {deleted} wyników {label} dla urządzenia.", "success")
        # Zachowaj aktywny filtr sieciowy — wróć do poprzedniej strony (Referer)
        back = request.referrer or url_for("devices")
        return redirect(back)

    @app.route("/devices/clear-ports", methods=["POST"])
    def devices_clear_ports_bulk():
        """Usuwa wyniki skanowania portow dla wielu urzadzen (wg filtra lub wszystkich)."""
        device_ids = request.form.get("device_ids", "")  # "" = wszystkie
        scan_type  = request.form.get("scan_type", "")   # "" = oba typy
        params = []
        if device_ids:
            params.append(f"device_ids={device_ids}")
        if scan_type:
            params.append(f"scan_type={scan_type}")
        qs = ("?" + "&".join(params)) if params else ""
        data, err = _api("delete", f"/api/devices/scan-results{qs}")
        if err:
            flash(f"Error clearing ports: {err}", "danger")
        else:
            deleted = (data or {}).get("deleted", 0)
            label = {"nmap_full": "pełnego skanu", "nmap": "szybkiego skanu"}.get(scan_type, "wszystkich skanów")
            scope = f"{len(device_ids.split(','))} urządzeń" if device_ids else "wszystkich urządzeń"
            flash(f"Usunięto {deleted} wyników {label} dla {scope}.", "success")
        # Zachowaj aktywny filtr sieciowy — wróć do poprzedniej strony (Referer)
        back = request.referrer or url_for("devices")
        return redirect(back)

    @app.route("/devices/<int:device_id>/delete", methods=["POST"])
    def device_delete(device_id):
        """Usuwa urzadzenie z bazy. Kolejny skan odkryje je ponownie."""
        _, err = _api("delete", f"/api/devices/{device_id}?force=true")
        if err:
            flash(f"Blad usuwania: {err}", "danger")
        else:
            flash("Device deleted. It will reappear after the next scan if it is still on the network.", "info")
        return redirect(url_for("devices"))

    @app.route("/devices/<int:device_id>/flag", methods=["POST"])
    def device_flag(device_id):
        """Ustawia lub usuwa kolorowa flage urzadzenia."""
        color = request.form.get("flag_color", "").strip() or None
        _, err = _api("patch", f"/api/devices/{device_id}/flag", json={"color": color})
        if err:
            flash(f"Blad: {err}", "danger")
        elif color:
            flash("Flaga ustawiona.", "success")
        else:
            flash("Flaga usunieta.", "info")
        return redirect(url_for("devices"))

    @app.route("/devices/<int:device_id>/monitor", methods=["POST"])
    def device_monitor(device_id):
        """Wlacza lub wylacza monitorowanie dostepnosci urzadzenia."""
        monitored = request.form.get("monitored", "0") == "1"
        note = request.form.get("monitor_note", "").strip() or None
        _, err = _api("patch", f"/api/devices/{device_id}/monitor",
                      json={"monitored": monitored, "note": note})
        if err:
            flash(f"Blad: {err}", "danger")
        elif monitored:
            flash("Monitorowanie wlaczone — alerty beda wysylane przy zmianie statusu.", "success")
        else:
            flash("Monitorowanie wylaczone.", "info")
        return redirect(url_for("devices"))

    @app.route("/devices/<int:device_id>/toggle-full-scan", methods=["POST"])
    def device_toggle_full_scan(device_id):
        """Włącza lub wyłącza automatyczny full scan portów 1-65535 dla urządzenia."""
        db = SessionLocal()
        try:
            dev = db.query(Device).filter_by(id=device_id).first()
            if not dev:
                flash("Urządzenie nie znalezione.", "danger")
                return redirect(url_for("devices"))
            new_val = not dev.no_full_scan
            dev.no_full_scan = new_val
            ip = str(dev.ip)
            db.commit()
            if new_val:
                flash(f"Full scan wyłączony dla {ip}. Automatyczne skanowanie portów 1-65535 nie będzie uruchamiane.", "info")
            else:
                flash(f"Full scan włączony dla {ip}. Urządzenie będzie automatycznie skanowane.", "success")
        except Exception as exc:
            db.rollback()
            flash(f"Błąd zapisu: {exc}", "danger")
        finally:
            db.close()
        return redirect(url_for("device_detail", device_id=device_id))

    @app.route("/devices/<int:device_id>/toggle-cred-scan", methods=["POST"])
    def device_toggle_cred_scan(device_id):
        """Włącza lub wyłącza testowanie haseł dla urządzenia."""
        db = SessionLocal()
        try:
            dev = db.query(Device).filter_by(id=device_id).first()
            if not dev:
                flash("Urządzenie nie znalezione.", "danger")
                return redirect(url_for("devices"))
            new_val = not dev.skip_cred_scan
            dev.skip_cred_scan = new_val
            ip = str(dev.ip)
            db.commit()
            if new_val:
                flash(f"Testowanie haseł zatrzymane dla {ip}.", "warning")
            else:
                flash(f"Testowanie haseł wznowione dla {ip}.", "success")
        except Exception as exc:
            db.rollback()
            flash(f"Błąd zapisu: {exc}", "danger")
        finally:
            db.close()
        return redirect(url_for("device_detail", device_id=device_id))

    @app.route("/devices/<int:device_id>/toggle-port-scan", methods=["POST"])
    def device_toggle_port_scan(device_id):
        """Włącza lub wyłącza skanowanie portów dla urządzenia."""
        db = SessionLocal()
        try:
            dev = db.query(Device).filter_by(id=device_id).first()
            if not dev:
                flash("Urządzenie nie znalezione.", "danger")
                return redirect(url_for("devices"))
            new_val = not dev.skip_port_scan
            dev.skip_port_scan = new_val
            ip = str(dev.ip)
            db.commit()
            if new_val:
                flash(f"Skanowanie portów zatrzymane dla {ip}.", "warning")
            else:
                flash(f"Skanowanie portów wznowione dla {ip}.", "success")
        except Exception as exc:
            db.rollback()
            flash(f"Błąd zapisu: {exc}", "danger")
        finally:
            db.close()
        return redirect(url_for("device_detail", device_id=device_id))

    @app.route("/devices/<int:device_id>/set-ip-type", methods=["POST"])
    def device_set_ip_type(device_id):
        """Ustawia typ adresacji IP urzadzenia."""
        ip_type = request.form.get("ip_type", "unknown")
        _, err = _api("patch", f"/api/devices/{device_id}/ip-type", json={"ip_type": ip_type})
        if err:
            flash(f"Blad: {err}", "danger")
        else:
            labels = {"static": "Statyczny", "dhcp": "DHCP", "unknown": "Nieznany"}
            flash(f"Typ IP ustawiony: {labels.get(ip_type, ip_type)}.", "success")
        return redirect(url_for("devices"))

    # ── L2 + Metrics API proxy (AJAX z przegladarki → Flask → FastAPI) ──────

    @app.route("/api/devices/<int:device_id>/if-metrics")
    def api_proxy_if_metrics(device_id):
        """Proxy: historia metryk interfejsu z ClickHouse."""
        data, err = _api("get", f"/api/devices/{device_id}/if-metrics",
                         params=request.args.to_dict())
        if err:
            return jsonify({"error": err}), 502
        return jsonify(data)

    @app.route("/api/devices/<int:device_id>/if-metrics/rates")
    def api_proxy_if_metrics_rates(device_id):
        """Proxy: biezace predkosci per interfejs."""
        data, err = _api("get", f"/api/devices/{device_id}/if-metrics/rates",
                         params=request.args.to_dict())
        if err:
            return jsonify({"error": err}), 502
        return jsonify(data)

    @app.route("/api/devices/<int:device_id>/fdb")
    def api_proxy_fdb(device_id):
        """Proxy: tablica FDB (MAC-port mapping)."""
        data, err = _api("get", f"/api/devices/{device_id}/fdb",
                         params=request.args.to_dict())
        if err:
            return jsonify({"error": err}), 502
        return jsonify(data)

    @app.route("/api/devices/<int:device_id>/ntopng-flows")
    def api_ntopng_flows(device_id):
        """PRO: top flows for this device from ntopng REST API."""
        if not PRO_ENABLED:
            return jsonify({"error": "NetDoc Pro required"}), 403
        from netdoc.integrations.ntopng import get_ntopng_config, get_host_flows
        db = SessionLocal()
        try:
            cfg = get_ntopng_config(db)
            if not cfg:
                return jsonify({"error": "ntopng not configured or disabled"}), 404
            dev = db.query(Device).filter(Device.id == device_id).first()
            if not dev:
                return jsonify({"error": "device not found"}), 404
            try:
                flows = get_host_flows(cfg, ip=str(dev.ip))
            except Exception as exc:
                logger.warning("ntopng get_host_flows failed: %s", exc)
                flows = []
            return jsonify({"flows": flows, "ip": str(dev.ip), "ntopng_url": cfg["url"]})
        finally:
            db.close()

    @app.route("/api/wazuh/alerts")
    def api_wazuh_alerts():
        """Recent Wazuh alerts from alerts.json — global security feed."""
        from netdoc.integrations.wazuh_alerts import get_recent_alerts, alerts_file_available
        try:
            since_hours = int(request.args.get("hours", 24))
            limit       = min(int(request.args.get("limit", 100)), 500)
        except (ValueError, TypeError):
            since_hours, limit = 24, 100
        if not alerts_file_available():
            return jsonify({"alerts": [], "available": False, "count": 0,
                            "since_hours": since_hours,
                            "message": "Wazuh alerts file not mounted"}), 200
        alerts = get_recent_alerts(since_hours=since_hours, limit=limit)
        return jsonify({"alerts": alerts, "available": True,
                        "since_hours": since_hours, "count": len(alerts)})

    @app.route("/api/wazuh/agents")
    def api_wazuh_agents():
        """Wazuh registered agents with status from REST API."""
        from netdoc.integrations.wazuh_alerts import get_wazuh_api_config, get_agents
        db = SessionLocal()
        try:
            try:
                cfg = get_wazuh_api_config(db)
            except Exception as exc:
                logger.warning("Wazuh API config error: %s", exc)
                return jsonify({"agents": [], "available": False, "count": 0,
                                "message": "DB error reading Wazuh config"}), 200
            if not cfg:
                return jsonify({"agents": [], "available": False, "count": 0,
                                "message": "Wazuh not enabled"}), 200
            agents = get_agents(cfg)
            return jsonify({"agents": agents, "available": True, "count": len(agents)})
        finally:
            db.close()

    @app.route("/api/devices/<int:device_id>/wazuh-alerts")
    def api_device_wazuh_alerts(device_id):
        """Wazuh alerts from alerts.json matching this device's IP."""
        from netdoc.integrations.wazuh_alerts import get_alerts_for_ip, alerts_file_available
        db = SessionLocal()
        try:
            dev = db.query(Device).filter(Device.id == device_id).first()
            if not dev:
                return jsonify({"error": "device not found"}), 404
            try:
                since_hours = int(request.args.get("hours", 72))
            except (ValueError, TypeError):
                since_hours = 72
            if not alerts_file_available():
                return jsonify({"alerts": [], "available": False, "count": 0,
                                "since_hours": since_hours, "ip": str(dev.ip)}), 200
            alerts = get_alerts_for_ip(str(dev.ip), since_hours=since_hours)
            return jsonify({"alerts": alerts, "available": True, "count": len(alerts),
                            "since_hours": since_hours, "ip": str(dev.ip)})
        finally:
            db.close()

    @app.route("/api/devices/<int:device_id>/security-events")
    def api_security_events(device_id):
        """Security events for this device stored by NetDoc (new device, vulns, conflicts)."""
        from netdoc.storage.models import SecurityEvent
        db = SessionLocal()
        try:
            dev = db.query(Device).filter(Device.id == device_id).first()
            if not dev:
                return jsonify({"error": "device not found"}), 404
            try:
                limit = min(int(request.args.get("limit", 50)), 200)
            except (ValueError, TypeError):
                limit = 50
            rows = (db.query(SecurityEvent)
                    .filter(SecurityEvent.device_id == device_id)
                    .order_by(SecurityEvent.ts.desc())
                    .limit(limit)
                    .all())
            events = [
                {
                    "id":          r.id,
                    "event_type":  r.event_type,
                    "severity":    r.severity,
                    "ip":          r.ip,
                    "description": r.description,
                    "details":     r.details or {},
                    "ts":          r.ts.strftime("%Y-%m-%d %H:%M:%S") if r.ts else "",
                }
                for r in rows
            ]
            return jsonify({"events": events, "device_id": device_id})
        finally:
            db.close()

    # ── Maintenance — clear history ───────────────────────────────────────────

    @app.route("/maintenance/clear-broadcast", methods=["POST"])
    def maintenance_clear_broadcast():
        """Truncate ClickHouse broadcast/metrics tables. Irreversible."""
        import logging as _logging
        _log = _logging.getLogger(__name__)
        try:
            from netdoc.storage.clickhouse import _get_client
            ch = _get_client()
            ch.command("TRUNCATE TABLE netdoc_logs.device_metrics")
            ch.command("TRUNCATE TABLE netdoc_logs.device_ping")
            _log.info("Maintenance: broadcast history cleared by user")
            return jsonify({"ok": True, "message": "Broadcast & ping history cleared."})
        except Exception as exc:
            _log.warning("Maintenance clear-broadcast error: %s", exc)
            return jsonify({"ok": False, "message": str(exc)}), 500

    @app.route("/maintenance/clear-syslog", methods=["POST"])
    def maintenance_clear_syslog():
        """Truncate ClickHouse syslog table. Irreversible."""
        import logging as _logging
        _log = _logging.getLogger(__name__)
        try:
            from netdoc.storage.clickhouse import _get_client
            ch = _get_client()
            ch.command("TRUNCATE TABLE netdoc_logs.syslog")
            _log.info("Maintenance: syslog history cleared by user")
            return jsonify({"ok": True, "message": "Syslog history cleared."})
        except Exception as exc:
            _log.warning("Maintenance clear-syslog error: %s", exc)
            return jsonify({"ok": False, "message": str(exc)}), 500

    @app.route("/maintenance/clear-devices", methods=["POST"])
    def maintenance_clear_devices():
        """Delete ALL devices and all dependent data via TRUNCATE CASCADE. Irreversible."""
        import logging as _logging
        from sqlalchemy import text as _text
        _log = _logging.getLogger(__name__)
        db = SessionLocal()
        try:
            count = db.execute(_text("SELECT COUNT(*) FROM devices")).scalar()
            # TRUNCATE CASCADE removes devices + all 22 FK-dependent tables in one shot
            db.execute(_text("TRUNCATE TABLE devices RESTART IDENTITY CASCADE"))
            db.commit()
            _log.info("Maintenance: %d devices (+ dependent rows) deleted by user", count)
            return jsonify({"ok": True, "message": f"{count} devices deleted (all history cleared)."})
        except Exception as exc:
            db.rollback()
            _log.warning("Maintenance clear-devices error: %s", exc)
            return jsonify({"ok": False, "message": str(exc)}), 500
        finally:
            db.close()

    @app.route("/maintenance/clear-networks", methods=["POST"])
    def maintenance_clear_networks():
        """Delete ALL discovered networks. Irreversible."""
        import logging as _logging
        from sqlalchemy import text as _text
        _log = _logging.getLogger(__name__)
        db = SessionLocal()
        try:
            count = db.execute(_text("SELECT COUNT(*) FROM discovered_networks")).scalar()
            db.execute(_text("TRUNCATE TABLE discovered_networks RESTART IDENTITY CASCADE"))
            db.commit()
            _log.info("Maintenance: %d networks deleted by user", count)
            return jsonify({"ok": True, "message": f"{count} networks deleted."})
        except Exception as exc:
            db.rollback()
            _log.warning("Maintenance clear-networks error: %s", exc)
            return jsonify({"ok": False, "message": str(exc)}), 500
        finally:
            db.close()

    @app.route("/api/devices/<int:device_id>/vlan-ports")
    def api_proxy_vlan_ports(device_id):
        """Proxy: przynaleznosc portow do VLAN-ow."""
        data, err = _api("get", f"/api/devices/{device_id}/vlan-ports",
                         params=request.args.to_dict())
        if err:
            return jsonify({"error": err}), 502
        return jsonify(data)

    @app.route("/api/devices/<int:device_id>/stp")
    def api_proxy_stp(device_id):
        """Proxy: stan STP + root bridge."""
        data, err = _api("get", f"/api/devices/{device_id}/stp", params=request.args.to_dict())
        if err:
            return jsonify({"error": err}), 502
        return jsonify(data)

    @app.route("/api/devices/<int:device_id>/port-summary")
    def api_proxy_port_summary(device_id):
        """Proxy: zestawienie portów (tryb, VLAN, STP, sąsiad)."""
        data, err = _api("get", f"/api/devices/{device_id}/port-summary")
        if err:
            return jsonify({"error": err}), 502
        return jsonify(data)

    @app.route("/api/devices/<int:device_id>/diag-alerts")
    def api_proxy_device_diag_alerts(device_id):
        """Proxy: alerty diagnostyczne urządzenia (DevicePortAlert)."""
        data, err = _api("get", f"/api/devices/{device_id}/diag-alerts", params=request.args.to_dict())
        if err:
            return jsonify({"error": err}), 502
        return jsonify(data)

    @app.route("/api/devices/<int:device_id>/resource-history")
    def api_proxy_resource_history(device_id):
        """Proxy: historia CPU/mem z ClickHouse."""
        data, err = _api("get", f"/api/devices/{device_id}/resource-history", params=request.args.to_dict())
        if err:
            return jsonify({"error": err}), 502
        return jsonify(data)

    @app.route("/api/devices/<int:device_id>/diag-alerts/<int:alert_id>/ack", methods=["POST"])
    def api_proxy_alert_ack(device_id, alert_id):
        """Proxy: potwierdzenie alertu diagnostycznego."""
        data, err = _api("post", f"/api/devices/{device_id}/diag-alerts/{alert_id}/ack")
        if err:
            return jsonify({"error": err}), 502
        return jsonify(data)

    @app.route("/api/devices/<int:device_id>/tier")
    def api_proxy_tier_get(device_id):
        """Proxy: pobierz wynik analizy tiera (GET)."""
        data, err = _api("get", f"/api/devices/{device_id}/tier")
        if err:
            return jsonify({"error": err}), 502
        return jsonify(data)

    @app.route("/api/devices/<int:device_id>/tier/override", methods=["POST"])
    def api_proxy_tier_override(device_id):
        """Proxy: ręczne nadpisanie tiera przez użytkownika."""
        body = request.get_json(silent=True)
        if not body:
            return jsonify({"error": "Wymagane body JSON z polami network_tier i tier_overridden"}), 400
        data, err = _api("post", f"/api/devices/{device_id}/tier/override", json=body)
        if err:
            return jsonify({"error": err}), 502
        return jsonify(data)

    @app.route("/api/devices/<int:device_id>/tier/analyze", methods=["POST"])
    def api_proxy_tier_analyze(device_id):
        """Proxy: wymusza natychmiastową re-analizę tiera."""
        data, err = _api("post", f"/api/devices/{device_id}/tier/analyze")
        if err:
            return jsonify({"error": err}), 502
        return jsonify(data)

    @app.route("/devices/<int:device_id>/inventory", methods=["POST"])
    def device_inventory(device_id):
        """Zapisuje pola inwentarzowe urzadzenia."""
        payload = {
            "serial_number":      request.form.get("serial_number") or None,
            "asset_tag":          request.form.get("asset_tag") or None,
            "location":           request.form.get("location") or None,
            "sys_contact":        request.form.get("sys_contact") or None,
            "responsible_person": request.form.get("responsible_person") or None,
            "asset_notes":        request.form.get("asset_notes") or None,
        }
        payload = {k: v for k, v in payload.items() if v is not None}
        _, err = _api("patch", f"/api/devices/{device_id}", json=payload)
        if err:
            flash(f"Blad zapisu: {err}", "danger")
        else:
            flash("Dane urządzenia zaktualizowane.", "success")
        return redirect(url_for("devices"))

    # ── screenshot HTTP preview — storage w PostgreSQL ────────────────────────

    @app.route("/devices/<int:device_id>/screenshot")
    def device_screenshot(device_id):
        """Zwraca zrzut ekranu / klatke z kamery (PNG) — cache w bazie danych.

        Logika:
        1. Cache swiezy (<24h)        → zwroc bezposrednio, bez skanowania
        2. Cache wygasly, port znany  → uzyj zapisanego http_port/scheme, tylko recapture
        3. Brak cache (HTTP)          → odkryj HTTP port, capture, zapisz
        4. Brak cache (RTSP fallback) → jezeli urzadzenie ma rtsp_noauth/rtsp_weak_creds,
                                        sprobuj pobrac klatke z RTSP zamiast HTTP
        """
        from datetime import datetime as _dt
        from netdoc.storage.models import ScanResult, Vulnerability, VulnType

        db = SessionLocal()
        try:
            dev = db.query(Device).filter(Device.id == device_id).first()
            if not dev:
                return Response("Not found", status=404)

            shot = db.query(DeviceScreenshot).filter(
                DeviceScreenshot.device_id == device_id
            ).first()

            # Odczytaj TTL z ustawien (screenshot_ttl_hours)
            _ttl_row = db.query(SystemStatus).filter(
                SystemStatus.key == "screenshot_ttl_hours").first()
            _ttl = _SCREENSHOT_TTL
            if _ttl_row and _ttl_row.value:
                try:
                    _ttl = max(1, int(_ttl_row.value)) * 3600
                except (ValueError, TypeError):
                    pass

            # 1. Swiezy cache — serwuj bez zadnego skanowania
            if shot and (_dt.utcnow() - shot.captured_at).total_seconds() < _ttl:
                # Walidacja przechowywanego PNG — usun jesli za maly (falszywy screenshot)
                if not shot.png_data or len(shot.png_data) < _MIN_VALID_PNG_BYTES:
                    db.delete(shot)
                    db.commit()
                    return Response("Invalid screenshot", status=204)
                src = shot.http_scheme or "http"
                return Response(shot.png_data, mimetype="image/png",
                                headers={
                                    "X-Screenshot-Age": str(int((_dt.utcnow() - shot.captured_at).total_seconds())),
                                    "X-Screenshot-Source": src,
                                    "X-Screenshot-Port": str(shot.http_port or ""),
                                    "X-Screenshot-Captured-At": shot.captured_at.strftime("%Y-%m-%d %H:%M"),
                                })

            # 2. Znany port z poprzedniego capture
            if shot and shot.http_port:
                http_port = shot.http_port
                scheme = shot.http_scheme or ("https" if _is_tls(dev.ip, http_port) else "http")
            else:
                # 3. Odkryj HTTP port z ScanResult
                scan = (db.query(ScanResult)
                          .filter(ScanResult.device_id == device_id)
                          .order_by(ScanResult.scan_time.desc())
                          .first())
                candidate_ports = None
                if scan and scan.open_ports:
                    candidate_ports = [int(p) for p in scan.open_ports.keys()]
                http_port, scheme = _find_http_port(dev.ip, candidate_ports)

            png, final_port, final_scheme = None, http_port, scheme

            if http_port:
                png = _capture_screenshot(dev.ip, http_port, scheme)

            # 4. Fallback RTSP — jezeli brak HTTP screenshot a urzadzenie ma RTSP vuln
            if not png:
                rtsp_vuln = (db.query(Vulnerability)
                               .filter(Vulnerability.device_id == device_id,
                                       Vulnerability.vuln_type.in_([VulnType.rtsp_noauth, VulnType.rtsp_weak_creds]))
                               .first())
                if rtsp_vuln:
                    username, password = None, None
                    if rtsp_vuln.vuln_type == VulnType.rtsp_weak_creds and rtsp_vuln.evidence:
                        import re as _re
                        m = _re.search(r"user=['\"]?([^'\"\s]+)", rtsp_vuln.evidence)
                        if m:
                            username = m.group(1)
                    rtsp_port = rtsp_vuln.port or 554
                    png = _capture_rtsp_frame(dev.ip, port=rtsp_port, username=username, password=password)
                    if png:
                        final_port, final_scheme = rtsp_port, "rtsp"

            if not png:
                return Response("Capture failed", status=204)

            # Zapisz / zaktualizuj w DB
            if shot:
                shot.png_data    = png
                shot.ip          = dev.ip
                shot.mac         = dev.mac
                shot.http_port   = final_port
                shot.http_scheme = final_scheme
                shot.captured_at = _dt.utcnow()
            else:
                shot = DeviceScreenshot(
                    device_id   = device_id,
                    mac         = dev.mac,
                    ip          = dev.ip,
                    http_port   = final_port,
                    http_scheme = final_scheme,
                    png_data    = png,
                    captured_at = _dt.utcnow(),
                )
                db.add(shot)
            db.commit()

            _now_str = _dt.utcnow().strftime("%Y-%m-%d %H:%M")
            return Response(png, mimetype="image/png",
                            headers={"X-Screenshot-Source": final_scheme,
                                     "X-Screenshot-Port": str(final_port or ""),
                                     "X-Screenshot-Age": "0",
                                     "X-Screenshot-Captured-At": _now_str})
        finally:
            db.close()

    @app.route("/devices/<int:device_id>/screenshot/refresh", methods=["POST"])
    def device_screenshot_refresh(device_id):
        """Wymusza nowy screenshot przez usuniecie rekordu z bazy."""
        db = SessionLocal()
        try:
            shot = db.query(DeviceScreenshot).filter(
                DeviceScreenshot.device_id == device_id
            ).first()
            if shot:
                db.delete(shot)
                db.commit()
        finally:
            db.close()
        return jsonify({"ok": True})

    # ── inventory (inwentaryzacja / środki trwałe) ───────────────────────────

    @app.route("/inventory")
    def inventory():
        """Strona inwentarza — wszystkie urzadzenia z polami majatkowymi + eksport CSV."""
        from datetime import date as _date
        db = SessionLocal()
        try:
            # Sprawdz czy modul inwentaryzacji jest wlaczony
            inv_enabled_row = db.query(SystemStatus).filter_by(key="inventory_enabled").first()
            inv_enabled = (inv_enabled_row.value != "0") if inv_enabled_row else True
            if not inv_enabled:
                flash("Modul inwentaryzacji jest wylaczony. Wlacz go w Ustawieniach.", "warning")
                return redirect(url_for("settings"))
            devs = db.query(Device).order_by(Device.ip).all()
        finally:
            db.close()

        import re as _re
        inv_rows = []
        for d in devs:
            # Uptime z dedykowanej kolumny; fallback: stary tag z asset_notes (migracja)
            uptime_str = d.snmp_uptime
            if not uptime_str and d.asset_notes:
                m = _re.search(r'\[uptime ([^\]]+)\]', d.asset_notes)
                if m:
                    uptime_str = m.group(1)
            # Notatki bez tagu [uptime ...] — tag mógł pozostać w starych rekordach
            clean_notes = _re.sub(r'\[uptime [^\]]*\]\n?', '', d.asset_notes or '').strip() or None
            inv_rows.append({"device": d, "uptime": uptime_str, "clean_notes": clean_notes})

        if request.args.get("format") == "csv":
            import csv, io
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow([
                "IP", "Hostname", "Typ", "Vendor", "Model", "OS / Firmware",
                "Numer seryjny", "Asset tag", "Lokalizacja", "SNMP contact",
                "Ostatni poll SNMP", "Uptime", "Osoba odpowiedzialna", "Notatki",
            ])
            for row in inv_rows:
                d = row["device"]
                w.writerow([
                    d.ip, d.hostname or "",
                    d.device_type.value if d.device_type else "",
                    d.vendor or "", d.model or "", d.os_version or "",
                    d.serial_number or "", d.asset_tag or "",
                    d.location or "", d.sys_contact or "",
                    d.snmp_ok_at.strftime("%Y-%m-%d %H:%M") if d.snmp_ok_at else "",
                    row["uptime"] or "",
                    d.responsible_person or "", d.asset_notes or "",
                ])
            return Response(
                buf.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment; filename=inventory.csv"},
            )

        return render_template("inventory.html", inv_rows=inv_rows)

    # ── networks (bezposrednio przez SQLAlchemy — brak endpointu API) ──────────
    def _count_devices_in_cidr(db, cidr: str) -> int:
        """Zwraca liczbe urzadzen, ktorych IP nalezy do podanego CIDR."""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return 0
        devices = db.query(Device).all()
        count = 0
        for d in devices:
            try:
                if ipaddress.ip_address(d.ip) in net:
                    count += 1
            except ValueError:
                pass
        return count

    def _count_devices_active_inactive(all_devices, cidr: str):
        """Zwraca (active, inactive) dla CIDR. Uzywa juz wczytanej listy urzadzen."""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return 0, 0
        active = inactive = 0
        for d in all_devices:
            try:
                if ipaddress.ip_address(d.ip) in net:
                    if d.is_active:
                        active += 1
                    else:
                        inactive += 1
            except ValueError:
                pass
        return active, inactive

    def _delete_devices_in_cidr(db, cidr: str) -> int:
        """Usuwa wszystkie urzadzenia nalezace do podanego CIDR. Zwraca liczbe usunietych."""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return 0
        devices = db.query(Device).all()
        deleted = 0
        for d in devices:
            try:
                if ipaddress.ip_address(d.ip) in net:
                    db.delete(d)
                    deleted += 1
            except ValueError:
                pass
        return deleted

    @app.route("/networks")
    def networks():
        db = SessionLocal()
        try:
            nets = db.query(DiscoveredNetwork).order_by(DiscoveredNetwork.cidr).all()
            # Pomijaj wpisy bez prawidlowego formatu CIDR (np. '[]' z pustej konfiguracji)
            nets = [n for n in nets if n.cidr and '/' in n.cidr]
            all_devs = db.query(Device).all()
            counts = {n.cidr: _count_devices_active_inactive(all_devs, n.cidr) for n in nets}
        finally:
            db.close()
        nets_sorted = sorted(nets, key=lambda n: -counts[n.cidr][0])
        counts = {cidr: {"active": a, "inactive": i} for cidr, (a, i) in counts.items()}
        from netdoc.config.settings import settings as _cfg
        return render_template("networks.html", networks=nets_sorted, device_counts=counts,
                               scan_interval_minutes=_cfg.scan_interval_minutes)

    @app.route("/networks/add", methods=["POST"])
    def network_add():
        cidr = request.form.get("cidr", "").strip()
        notes = request.form.get("notes", "").strip() or None
        if not cidr:
            flash("CIDR jest wymagany.", "danger")
            return redirect(url_for("networks"))
        db = SessionLocal()
        try:
            existing = db.query(DiscoveredNetwork).filter_by(cidr=cidr).first()
            if existing:
                flash(f"Siec {cidr} juz istnieje.", "warning")
            else:
                net = DiscoveredNetwork(
                    cidr=cidr,
                    source=NetworkSource.manual,
                    is_active=True,
                    notes=notes,
                )
                db.add(net)
                db.commit()
                flash(f"Dodano siec {cidr}.", "success")
        except Exception as e:
            db.rollback()
            flash(f"Blad: {e}", "danger")
        finally:
            db.close()
        return redirect(url_for("networks"))

    @app.route("/networks/<int:net_id>/toggle", methods=["POST"])
    def network_toggle(net_id):
        delete_devices = request.form.get("delete_devices") == "1"
        db = SessionLocal()
        try:
            net = db.query(DiscoveredNetwork).filter_by(id=net_id).first()
            if net:
                was_active = net.is_active
                net.is_active = not net.is_active
                if delete_devices and was_active and not net.is_active:
                    deleted = _delete_devices_in_cidr(db, net.cidr)
                    flash(f"Siec {net.cidr} zatrzymana. Usunieto {deleted} urzadzen z bazy.", "success")
                else:
                    flash(f"Siec {net.cidr}: {'aktywna' if net.is_active else 'nieaktywna'}.", "success")
                db.commit()
        except Exception as e:
            db.rollback()
            flash(f"Blad: {e}", "danger")
        finally:
            db.close()
        return redirect(url_for("networks"))

    @app.route("/networks/pause-all", methods=["POST"])
    def network_pause_all():
        db = SessionLocal()
        try:
            nets = db.query(DiscoveredNetwork).filter(DiscoveredNetwork.is_active.is_(True)).all()
            count = len(nets)
            for net in nets:
                net.is_active = False
            db.commit()
            flash(f"Wstrzymano {count} sieci. Skaner odpauzuje automatycznie te, do ktorych jestes podlaczony.", "success")
        except Exception as e:
            db.rollback()
            flash(f"Blad: {e}", "danger")
        finally:
            db.close()
        return redirect(url_for("networks"))

    @app.route("/networks/<int:net_id>/delete", methods=["POST"])
    def network_delete(net_id):
        delete_devices = request.form.get("delete_devices") == "1"
        db = SessionLocal()
        try:
            net = db.query(DiscoveredNetwork).filter_by(id=net_id).first()
            if net:
                cidr = net.cidr
                if delete_devices:
                    deleted = _delete_devices_in_cidr(db, cidr)
                    flash(f"Siec {cidr} usunieta. Usunieto {deleted} urzadzen z bazy.", "success")
                else:
                    flash(f"Siec {cidr} usunieta. Urzadzenia pozostaja w bazie.", "success")
                db.delete(net)
                db.commit()
        except Exception as e:
            db.rollback()
            flash(f"Blad: {e}", "danger")
        finally:
            db.close()
        return redirect(url_for("networks"))

    @app.route("/networks/<int:net_id>/notes", methods=["POST"])
    def network_update_notes(net_id):
        from flask import jsonify
        notes = request.json.get("notes", "") if request.is_json else request.form.get("notes", "")
        notes = notes.strip() or None
        db = SessionLocal()
        try:
            net = db.query(DiscoveredNetwork).filter_by(id=net_id).first()
            if not net:
                if request.is_json:
                    return jsonify({"ok": False, "error": "not found"}), 404
                flash("Nie znaleziono sieci.", "danger")
                return redirect(url_for("networks"))
            net.notes = notes
            db.commit()
            if request.is_json:
                return jsonify({"ok": True, "notes": net.notes or ""})
        except Exception as e:
            db.rollback()
            if request.is_json:
                return jsonify({"ok": False, "error": str(e)}), 500
        finally:
            db.close()
        return redirect(url_for("networks"))

    @app.route("/networks/bulk-add", methods=["POST"])
    def network_bulk_add():
        raw = request.form.get("cidrs", "")
        lines = [l.strip() for l in raw.replace(",", "\n").splitlines() if l.strip()]
        import ipaddress as _ip
        added, skipped, errors = 0, 0, []
        db = SessionLocal()
        try:
            for cidr in lines:
                try:
                    _ip.IPv4Network(cidr, strict=False)
                except ValueError:
                    errors.append(cidr)
                    continue
                existing = db.query(DiscoveredNetwork).filter_by(cidr=cidr).first()
                if existing:
                    skipped += 1
                    continue
                db.add(DiscoveredNetwork(cidr=cidr, source=NetworkSource.manual, is_active=True))
                added += 1
            db.commit()
            parts = []
            if added:
                parts.append(f"Dodano {added} sieci")
            if skipped:
                parts.append(f"pominicto {skipped} istniejacych")
            if errors:
                parts.append(f"blad parsowania: {', '.join(errors)}")
            flash(". ".join(parts) + ".", "success" if not errors else "warning")
        except Exception as e:
            db.rollback()
            flash(f"Blad: {e}", "danger")
        finally:
            db.close()
        return redirect(url_for("networks"))

    @app.route("/devices/export.csv")
    def devices_export_csv():
        import csv, io
        db = SessionLocal()
        try:
            devs = db.query(Device).order_by(Device.ip).all()
        finally:
            db.close()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["IP", "Hostname", "MAC", "Vendor", "Typ", "OS", "Model", "Aktywny",
                    "Pierwsze wykrycie", "Ostatnie wykrycie", "Lokalizacja", "Dzial", "Notatki"])
        for d in devs:
            w.writerow([
                d.ip, d.hostname or "", d.mac or "", d.vendor or "",
                d.device_type.value if d.device_type else "",
                d.os_version or "", d.model or "",
                "tak" if d.is_active else "nie",
                d.first_seen.strftime("%Y-%m-%d %H:%M") if d.first_seen else "",
                d.last_seen.strftime("%Y-%m-%d %H:%M") if d.last_seen else "",
                d.location or "", d.owner_dept or "", d.asset_notes or "",
            ])
        from flask import Response
        return Response(
            "\ufeff" + buf.getvalue(),  # BOM dla Excela
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=netdoc-devices.csv"},
        )

    @app.route("/api/mac/<path:mac>")
    def api_mac_lookup(mac):
        from netdoc.collector.oui_lookup import oui_db
        from flask import jsonify
        vendor = oui_db.lookup(mac)
        return jsonify({"mac": mac, "vendor": vendor})

    @app.route("/api/mac/status")
    def api_mac_status():
        """Status bazy OUI: liczba wpisow, wiek plikow, flaga needs_update."""
        from netdoc.collector.oui_lookup import oui_db
        from flask import jsonify
        if not oui_db._loaded:
            oui_db.load()
        s = oui_db.status()
        return jsonify(s)

    @app.route("/api/mac/vendors")
    def api_mac_vendors():
        """Lista vendorow z bazy OUI — wyszukiwanie i sortowanie.

        Query params:
          q     — filtr nazwy (case-insensitive substring)
          sort  — "name" (domyslnie) lub "count" (malejaco po liczbie blokow OUI)
          limit — maks. liczba wynikow (domyslnie 100, max 500)
        """
        from netdoc.collector.oui_lookup import oui_db
        from flask import jsonify, request as req
        from collections import Counter
        if not oui_db._loaded:
            oui_db.load()
        q     = (req.args.get("q", "") or "").strip().lower()
        sort  = req.args.get("sort", "name")
        try:
            limit = min(int(req.args.get("limit", 100)), 500)
        except (ValueError, TypeError):
            limit = 100
        # Agreguj: vendor_name → liczba blokow OUI
        counts = Counter(oui_db._db.values())
        rows = [{"vendor": v, "blocks": c} for v, c in counts.items()
                if not q or q in v.lower()]
        if sort == "count":
            rows.sort(key=lambda r: (-r["blocks"], r["vendor"].lower()))
        else:
            rows.sort(key=lambda r: r["vendor"].lower())
        total = len(rows)
        return jsonify({"total": total, "vendors": rows[:limit]})

    # ── credentials ────────────────────────────────────────────────────────────
    @app.route("/credentials")
    def credentials():
        db = SessionLocal()
        try:
            creds = db.query(Credential).order_by(
                Credential.priority.desc(), Credential.id
            ).all()
            def _gcreds(method):
                return [cr for cr in creds if cr.method.value == method and cr.device_id is None]
            vnc_passwords  = _gcreds("vnc")
            pg_creds       = _gcreds("postgres")
            mssql_creds    = _gcreds("mssql")
            mysql_creds    = _gcreds("mysql")
            rtsp_creds     = _gcreds("rtsp")
            snmp_fallback, _ = _api("get", "/api/credentials/snmp-fallback-list")
            _ce_row = db.query(SystemStatus).filter(
                SystemStatus.key == "cred_scanning_enabled"
            ).first()
            cred_scanning_enabled = (_ce_row.value if _ce_row else "0") != "0"
        finally:
            db.close()
        # Statystyki uzycia globalnych credentiali na urzadzeniach
        cred_scan_data, _ = _api("get", "/api/credentials/cred-scan-stats")
        global_cred_usage = {}
        cred_scan_meta = {}
        cred_scan_devices = []
        if cred_scan_data:
            global_cred_usage = {int(k): v for k, v in
                                 cred_scan_data.get("global_cred_usage", {}).items()}
            cred_scan_meta = {
                "last_cycle_at": cred_scan_data.get("last_cycle_at"),
                "interval_s":    cred_scan_data.get("interval_s", 60),
            }
            cred_scan_devices = sorted(
                cred_scan_data.get("devices", []),
                key=lambda d: d.get("ip", ""),
            )
        return render_template(
            "credentials.html",
            credentials=creds,
            snmp_fallback=snmp_fallback or [],
            vnc_passwords=vnc_passwords,
            pg_creds=pg_creds,
            mssql_creds=mssql_creds,
            mysql_creds=mysql_creds,
            rtsp_creds=rtsp_creds,
            global_cred_usage=global_cred_usage,
            cred_scan_meta=cred_scan_meta,
            cred_scan_devices=cred_scan_devices,
            cred_scanning_enabled=cred_scanning_enabled,
        )

    @app.route("/credentials/cred-scan-toggle", methods=["POST"])
    def cred_scan_toggle():
        """Włącz/wyłącz skanowanie credentiali (cred_scanning_enabled) i wróć do referrera."""
        db = SessionLocal()
        try:
            row = db.query(SystemStatus).filter(
                SystemStatus.key == "cred_scanning_enabled",
                SystemStatus.category == "config",
            ).first()
            if not row:
                row = SystemStatus(key="cred_scanning_enabled", category="config", value="0")
                db.add(row)
            row.value = "0" if row.value != "0" else "1"
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
        return redirect(request.referrer or "/credentials")

    @app.route("/credentials/add", methods=["POST"])
    def credential_add():
        # API uzywa "method" (CredentialMethod: snmp/ssh/telnet/api)
        # Dla SNMP: username = community string
        protocol = request.form.get("protocol", "snmp")
        community = (request.form.get("community") or "").strip() or None
        username = request.form.get("username") or None
        payload = {
            "method": protocol,
            "username": community if protocol == "snmp" else (request.form.get("password") or None) if protocol == "vnc" else username,
            "password": None if protocol in ("vnc", "mysql") else request.form.get("password") or None,
            "priority": int(request.form.get("priority", 100)),
            "notes": request.form.get("notes") or None,
        }
        device_id = request.form.get("device_id")
        if device_id:
            payload["device_id"] = int(device_id)
        data, err = _api("post", "/api/credentials/", json=payload)
        if err:
            flash(f"Error: {err}", "danger")
        else:
            flash("Credential added.", "success")
        return redirect(url_for("credentials"))

    @app.route("/credentials/<int:cred_id>/delete", methods=["POST"])
    def credential_delete(cred_id):
        _, err = _api("delete", f"/api/credentials/{cred_id}")
        if err:
            flash(f"Error: {err}", "danger")
        else:
            flash("Credential deleted.", "success")
        return redirect(url_for("credentials"))

    @app.route("/credentials/bulk-delete", methods=["POST"])
    def credential_bulk_delete():
        method = request.form.get("method") or None   # None = all types
        scope = request.form.get("scope", "global")   # "global" or "all"
        if scope not in ("global", "all"):
            flash("Invalid scope.", "danger")
            return redirect(url_for("credentials"))
        include_device = scope == "all"
        params = {}
        if method:
            params["method"] = method
        if include_device:
            params["include_device"] = "true"
        _, err = _api("delete", "/api/credentials/bulk/all", params=params)
        if err:
            flash(f"Error: {err}", "danger")
        else:
            label = method.upper() if method else "all"
            scope_label = " (including per-device)" if include_device else " (global only)"
            flash(f"Deleted {label} credentials{scope_label}.", "success")
        return redirect(url_for("credentials"))

    @app.route("/credentials/<int:cred_id>/edit", methods=["POST"])
    def credential_edit(cred_id):
        method = request.form.get("method", "snmp")
        username = request.form.get("username") or None
        payload = {
            "method": method,
            "username": username,
            "priority": int(request.form.get("priority", 100)),
            "notes": request.form.get("notes") or None,
        }
        password = request.form.get("password")
        if password:
            payload["password"] = password
        _, err = _api("put", f"/api/credentials/{cred_id}", json=payload)
        if err:
            flash(f"Error: {err}", "danger")
        else:
            flash("Credential updated.", "success")
        return redirect(url_for("credentials"))

    # ── scan ───────────────────────────────────────────────────────────────────
    @app.route("/scan")
    def scan():
        db = SessionLocal()
        try:
            status = {r.key: r.value for r in db.query(SystemStatus).all()}
        finally:
            db.close()
        full_scan_enabled    = status.get("full_scan_enabled",        "0") != "0"
        community_scanning_enabled = status.get("community_scanning_enabled", "0") != "0"
        oui_status, _ = _api("get", "/api/scan/oui-status")
        return render_template("scan.html", status=status, oui_status=oui_status or {},
                               full_scan_enabled=full_scan_enabled,
                               community_scanning_enabled=community_scanning_enabled)

    @app.route("/scan/trigger", methods=["POST"])
    def scan_trigger():
        scan_type = request.form.get("type", "standard")
        if scan_type == "full":
            _, err = _api("post", "/api/scan/full")
            label = "pelne skanowanie portow"
        elif scan_type == "oui":
            _, err = _api("post", "/api/scan/update-oui")
            label = "aktualizacja OUI"
        else:
            _, err = _api("post", "/api/scan/")
            label = "skanowanie sieci"
        if err:
            flash(f"Blad uruchomienia: {err}", "danger")
        else:
            flash(f"Uruchomiono {label} w tle.", "success")
        return redirect(url_for("scan"))

    def _toggle_config_flag(key: str, referrer: str) -> str:
        """Toggles a 0/1 config flag in SystemStatus and returns redirect URL."""
        db = SessionLocal()
        try:
            row = db.query(SystemStatus).filter(
                SystemStatus.key == key,
                SystemStatus.category == "config",
            ).first()
            if not row:
                row = SystemStatus(key=key, category="config", value="0")
                db.add(row)
            row.value = "0" if row.value != "0" else "1"
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
        return request.referrer or referrer

    @app.route("/scan/full-scan-toggle", methods=["POST"])
    def full_scan_toggle():
        return redirect(_toggle_config_flag("full_scan_enabled", "/scan"))

    @app.route("/scan/community-scan-toggle", methods=["POST"])
    def community_scan_toggle():
        return redirect(_toggle_config_flag("community_scanning_enabled", "/scan"))

    # ── settings ───────────────────────────────────────────────────────────────
    @app.route("/settings")
    def settings():
        from netdoc.notifications.telegram import get_telegram_config
        from netdoc.storage.models import NotificationChannel
        db = SessionLocal()
        try:
            status_rows = db.query(SystemStatus).order_by(
                SystemStatus.category, SystemStatus.key
            ).all()
            telegram_config = get_telegram_config(db)
            # is_active niezaleznie od get_telegram_config (ktory wymaga active)
            ch = db.query(NotificationChannel).filter_by(key="telegram").first()
            telegram_active = bool(ch and ch.is_active)
        finally:
            db.close()
        grouped = {}
        for r in status_rows:
            grouped.setdefault(r.category, []).append(r)
        worker_cfg, _ = _api("get", "/api/scan/settings")
        lab_containers, _ = _lab_status()
        return render_template("settings.html", grouped=grouped, worker_cfg=worker_cfg or {},
                               lab_containers=lab_containers,
                               telegram_config=telegram_config,
                               telegram_active=telegram_active,
                               PRO_ENABLED=PRO_ENABLED)

    @app.route("/settings/config/<key>", methods=["POST"])
    def settings_config_update(key):
        value = request.form.get("value", "").strip()
        db = SessionLocal()
        try:
            row = db.query(SystemStatus).filter(
                SystemStatus.key == key, SystemStatus.category == "config"
            ).first()
            if row:
                row.value = value
                row.updated_at = __import__("datetime").datetime.utcnow()
                db.commit()
                flash(f"Zapisano: {key} = {value}", "success")
            else:
                flash(f"Klucz '{key}' nie istnieje lub nie jest edytowalny.", "danger")
        finally:
            db.close()
        return redirect("/settings")

    @app.route("/settings/workers", methods=["POST"])
    def settings_workers_update():
        """Formularz ustawień workerów — wywołuje PUT /api/scan/settings."""
        # Pola całkowitoliczbowe
        _INT_FIELDS = [
            "cred_interval_s", "cred_ssh_workers", "cred_web_workers",
            "cred_retry_days", "cred_max_creds_per_dev", "cred_pairs_per_cycle",
            "cred_device_timeout_s", "cred_min_delay_s", "cred_max_delay_s",
            "ping_interval_s", "ping_workers", "ping_inactive_after_min", "ping_fail_threshold",
            "snmp_interval_s", "snmp_workers", "snmp_timeout_s", "snmp_community_delay_s", "snmp_debug",
            "community_interval_s", "community_workers", "community_recheck_days",
            "vuln_interval_s", "vuln_workers", "vuln_close_after",
            "vuln_skip_printers", "vuln_limit_ap_iot",
            "nmap_min_rate", "nmap_version_intensity",
            "scan_concurrency", "scan_batch_size", "scan_resume_enabled",
            "lab_monitoring_enabled",
            "scan_vpn_networks", "scan_virtual_networks", "ignore_laa_macs",
        ]
        # Pola zmiennoprzecinkowe
        _FLOAT_FIELDS = ["ping_tcp_timeout", "vuln_tcp_timeout", "vuln_http_timeout",
                         "scan_batch_pause_s"]
        # Pola tekstowe (niewalidowane numerycznie)
        _STR_FIELDS = ["network_ranges"]

        payload = {}
        for f in _INT_FIELDS:
            v = request.form.get(f, "").strip()
            if v.lstrip("-").isdigit():
                payload[f] = int(v)
        for f in _FLOAT_FIELDS:
            v = request.form.get(f, "").strip()
            try:
                payload[f] = float(v)
            except (ValueError, TypeError):
                pass
        for f in _STR_FIELDS:
            v = request.form.get(f, "").strip()
            payload[f] = v   # zawsze wysyłamy (nawet puste = reset)

        try:
            resp = requests.put(f"{API_URL}/api/scan/settings",
                                json=payload, timeout=5)
            if resp.status_code == 200:
                flash("Ustawienia workerów zapisane.", "success")
            else:
                flash(f"Błąd API: {resp.status_code}", "danger")
        except Exception as exc:
            flash(f"Błąd połączenia z API: {exc}", "danger")
        return redirect("/settings")

    @app.route("/settings/telegram", methods=["POST"])
    def settings_telegram_save():
        """Zapisuje konfiguracje Telegram Bot."""
        from netdoc.notifications.telegram import set_telegram_config
        bot_token = request.form.get("bot_token", "").strip()
        chat_id   = request.form.get("chat_id", "").strip()
        is_active = request.form.get("is_active") == "1"
        if not bot_token or not chat_id:
            flash("Bot token i Chat ID sa wymagane.", "danger")
            return redirect("/settings")
        db = SessionLocal()
        try:
            set_telegram_config(db, bot_token, chat_id, is_active=is_active)
        finally:
            db.close()
        flash("Konfiguracja Telegram zapisana.", "success")
        return redirect("/settings")

    @app.route("/settings/telegram/test")
    def settings_telegram_test():
        """Wysyla testowy alert Telegram."""
        from netdoc.notifications.telegram import get_telegram_config, send_telegram
        db = SessionLocal()
        try:
            cfg = get_telegram_config(db)
        finally:
            db.close()
        if not cfg:
            flash("Telegram nie skonfigurowany lub nieaktywny.", "danger")
            return redirect("/settings")
        ok = send_telegram(cfg["bot_token"], cfg["chat_id"],
                           "\U0001F9EA <b>NetDoc Test</b>\nPowiadomienia Telegram dzialaja poprawnie!")
        if ok:
            flash("Testowy alert wyslany pomyslnie.", "success")
        else:
            flash("Blad wyslania alertu — sprawdz token i chat_id.", "danger")
        return redirect("/settings")

    # ── Docker service profiles — start/stop from UI ───────────────────────────
    _DOCKER_PROFILES = {
        "workers":    ["netdoc-ping", "netdoc-snmp", "netdoc-cred", "netdoc-vuln",
                       "netdoc-community", "netdoc-internet"],
        "monitoring": ["netdoc-prometheus", "netdoc-loki", "netdoc-promtail", "netdoc-grafana"],
        "syslog":     ["netdoc-vector", "netdoc-rsyslog"],
        "pro":        ["netdoc-ntopng", "netdoc-wazuh"],
    }

    @app.route("/settings/services/status")
    def services_status():
        client, err = _docker_client()
        result = {}
        for profile, containers in _DOCKER_PROFILES.items():
            if profile == "pro" and not PRO_ENABLED:
                continue
            statuses = []
            for name in containers:
                if client:
                    try:
                        c = client.containers.get(name)
                        statuses.append({"name": name, "status": c.status})
                    except Exception:
                        statuses.append({"name": name, "status": "absent"})
                else:
                    statuses.append({"name": name, "status": "error"})
            running = sum(1 for s in statuses if s["status"] == "running")
            result[profile] = {
                "containers": statuses,
                "running": running,
                "total": len(statuses),
                "all_absent": all(s["status"] == "absent" for s in statuses),
            }
        return jsonify({"profiles": result, "docker_error": err})

    @app.route("/settings/services/<profile>/start", methods=["POST"])
    def services_start(profile):
        if profile not in _DOCKER_PROFILES:
            return jsonify({"error": "unknown profile"}), 400
        if profile == "pro" and not PRO_ENABLED:
            return jsonify({"error": "NetDoc Pro required"}), 403
        import docker as _docker_sdk
        import subprocess as _sp
        client, err = _docker_client()
        if not client:
            return jsonify({"error": err}), 500
        started, absent, errors = [], [], []
        for name in _DOCKER_PROFILES[profile]:
            try:
                c = client.containers.get(name)
                if c.status != "running":
                    c.start()
                    started.append(name)
            except _docker_sdk.errors.NotFound:
                absent.append(name)
            except Exception as e:
                errors.append(f"{name}: {str(e)[:80]}")
        if absent:
            # Kontenery nie istnieją — tworzymy je przez docker compose up automatycznie
            import logging as _lg
            _log = _lg.getLogger(__name__)
            import pathlib as _plp
            _compose_file = str(_plp.Path(__file__).parent.parent.parent / "docker-compose.yml")
            _log.info("Services start: absent containers %s — running docker compose --profile %s up -d", absent, profile)
            try:
                result = _sp.run(
                    ["docker", "compose", "-f", _compose_file, "--profile", profile, "up", "-d"],
                    capture_output=True, text=True, timeout=120,
                )
                if result.returncode != 0:
                    # Retry with --build (image may not exist yet)
                    result = _sp.run(
                        ["docker", "compose", "-f", _compose_file, "--profile", profile, "up", "-d", "--build"],
                        capture_output=True, text=True, timeout=300,
                    )
                if result.returncode == 0:
                    return jsonify({"ok": True, "started": absent, "created": True, "errors": errors})
                else:
                    err_out = (result.stderr or result.stdout or "")[:300]
                    return jsonify({"ok": False, "absent": absent, "message": err_out}), 500
            except Exception as exc:
                return jsonify({"ok": False, "absent": absent, "message": str(exc)}), 500
        return jsonify({"ok": True, "started": started, "errors": errors})

    @app.route("/settings/services/<profile>/stop", methods=["POST"])
    def services_stop(profile):
        if profile not in _DOCKER_PROFILES:
            return jsonify({"error": "unknown profile"}), 400
        if profile == "pro" and not PRO_ENABLED:
            return jsonify({"error": "NetDoc Pro required"}), 403
        import docker as _docker_sdk
        client, err = _docker_client()
        if not client:
            return jsonify({"error": err}), 500
        stopped, absent, errors = [], [], []
        for name in _DOCKER_PROFILES[profile]:
            try:
                c = client.containers.get(name)
                if c.status == "running":
                    c.stop(timeout=10)
                stopped.append(name)
            except _docker_sdk.errors.NotFound:
                absent.append(name)
            except Exception as e:
                errors.append(f"{name}: {str(e)[:80]}")
        if absent and not stopped:
            return jsonify({
                "ok": False, "stopped": stopped, "absent": absent,
                "message": f"Kontenery nie istnieją — uruchom: docker compose --profile {profile} up -d",
            })
        return jsonify({"ok": True, "stopped": stopped, "absent": absent, "errors": errors})

    # ── lab environment ────────────────────────────────────────────────────────
    # image_candidates: kolejnosc prob (compose v2 i v1 nazewnictwo)
    _LAB_CONTAINERS = [
        {
            "name": "netdoc-lab-plc-s7", "label": "Siemens S7-200 PLC", "ip": "172.28.0.10",
            "image_candidates": ["netdoc-lab-plc-s7"],
            "ports": {"502/tcp": ("0.0.0.0", 15502)},
            "environment": {
                "PLC_NAME": "S7-1200", "PLC_SNMP_DESCR": "Siemens SIMATIC S7-1200 PLC v4.5",
                "PLC_SNMP_NAME": "S7-1200-PLC", "PLC_SNMP_LOC": "Hala produkcyjna A / Szafa sterownicza 1",
            },
        },
        {
            "name": "netdoc-lab-plc-meter", "label": "Kamstrup licznik energii", "ip": "172.28.0.11",
            "image_candidates": ["netdoc-lab-plc-meter"],
            "ports": {"502/tcp": ("0.0.0.0", 15503)},
            "environment": {
                "PLC_NAME": "Modicon-M340", "PLC_SNMP_DESCR": "Schneider Electric Modicon M340 PLC",
                "PLC_SNMP_NAME": "Modicon-M340", "PLC_SNMP_LOC": "Rozdzielnia glowna / Licznik energii",
            },
        },
        {
            "name": "netdoc-lab-plc-fuel", "label": "Guardian AST zbiornik", "ip": "172.28.0.12",
            "image_candidates": ["netdoc-lab-plc-fuel"],
            "ports": {"502/tcp": ("0.0.0.0", 15504)},
            "environment": {
                "PLC_NAME": "ABB-AC500", "PLC_SNMP_DESCR": "ABB AC500 PLC v3.0 — Tank Control",
                "PLC_SNMP_NAME": "ABB-AC500-Tank", "PLC_SNMP_LOC": "Zbiornik paliwa / Sekcja B",
            },
        },
        {
            "name": "netdoc-lab-router", "label": "MikroTik RB750 router", "ip": "172.28.0.20",
            "image_candidates": ["netdoc-lab-router"],
            "ports": {"23/tcp": ("0.0.0.0", 15123)},
            "environment": {},
        },
        {
            "name": "netdoc-lab-ssh", "label": "Cisco SSH switch", "ip": "172.28.0.30",
            "image_candidates": ["netdoc-lab-ssh"],
            "ports": {"22/tcp": ("0.0.0.0", 15022)},
            "environment": {},
        },
        {
            "name": "netdoc-lab-hmi", "label": "SCADA HMI WebServer", "ip": "172.28.0.40",
            "image_candidates": ["nginx:alpine"],
            "ports": {"80/tcp": ("0.0.0.0", 15040)},
            "environment": {},
        },
        {
            "name": "netdoc-lab-cam-dahua", "label": "Dahua IP Camera", "ip": "172.28.0.50",
            "image_candidates": ["netdoc-lab-device"],
            "ports": {},
            "environment": {
                "DEV_NAME": "Dahua-IPC-HDW2831T",
                "DEV_SNMP_DESCR": "Dahua IPC-HDW2831T-AS 8MP WizSense IR Fixed-focal Dome Camera",
                "DEV_SNMP_NAME": "Dahua-IPC-HDW2831T",
                "DEV_SNMP_LOC": "Parking zewnetrzny / Wejscie A",
                "DEV_HTTP_TITLE": "Dahua IP Camera",
                "DEV_ENABLE_RTSP": "1", "DEV_ENABLE_ONVIF": "1", "DEV_ENABLE_DAHUA": "1",
            },
        },
        {
            "name": "netdoc-lab-cam-hik", "label": "Hikvision DVR", "ip": "172.28.0.51",
            "image_candidates": ["netdoc-lab-device"],
            "ports": {},
            "environment": {
                "DEV_NAME": "Hikvision-DS-2CD2143G2",
                "DEV_SNMP_DESCR": "Hikvision DS-2CD2143G2-I 4MP AcuSense Fixed Dome Network Camera",
                "DEV_SNMP_NAME": "Hikvision-DS-2CD2143G2",
                "DEV_SNMP_LOC": "Hala produkcyjna / Kamera 3",
                "DEV_HTTP_TITLE": "Hikvision IP Camera",
                "DEV_ENABLE_RTSP": "1", "DEV_ENABLE_XMEYE": "1",
            },
        },
        {
            "name": "netdoc-lab-printer", "label": "HP LaserJet M404n", "ip": "172.28.0.52",
            "image_candidates": ["netdoc-lab-device"],
            "ports": {},
            "environment": {
                "DEV_NAME": "HP-LaserJet-M404n",
                "DEV_SNMP_DESCR": "HP LaserJet Pro M404n, ROM dsj1FN1.2135140, Model Number: W1A52A",
                "DEV_SNMP_NAME": "HP-LaserJet-M404n",
                "DEV_SNMP_LOC": "Biuro / Drukarka sieciowa",
                "DEV_HTTP_TITLE": "HP LaserJet M404n",
                "DEV_ENABLE_JETDIRECT": "1",
            },
        },
        {
            "name": "netdoc-lab-nas", "label": "Synology NAS DS920+", "ip": "172.28.0.53",
            "image_candidates": ["netdoc-lab-device"],
            "ports": {},
            "environment": {
                "DEV_NAME": "Synology-DS920plus",
                "DEV_SNMP_DESCR": "Synology DiskStation DS920+ (DSM 7.2-64561 Update 1)",
                "DEV_SNMP_NAME": "Synology-DS920plus",
                "DEV_SNMP_LOC": "Serwerownia / Rack 2 / NAS backup",
                "DEV_HTTP_TITLE": "Synology DiskStation DS920+",
                "DEV_ENABLE_FTP": "1",
            },
        },
        {
            "name": "netdoc-lab-moxa", "label": "MOXA NPort W2150A", "ip": "172.28.0.54",
            "image_candidates": ["netdoc-lab-device"],
            "ports": {},
            "environment": {
                "DEV_NAME": "MOXA-NPort-W2150A",
                "DEV_SNMP_DESCR": "MOXA NPort W2150A Wireless Device Server (802.11 a/b/g/n) FW 2.3",
                "DEV_SNMP_NAME": "MOXA-NPort-W2150A",
                "DEV_SNMP_LOC": "Hala produkcyjna / Maszyna CNC-7",
                "DEV_HTTP_TITLE": "MOXA NPort W2150A Device Server",
                "DEV_ENABLE_TELNET": "1",
            },
        },
        {
            "name": "netdoc-lab-ups", "label": "APC Smart-UPS 1500", "ip": "172.28.0.55",
            "image_candidates": ["netdoc-lab-device"],
            "ports": {},
            "environment": {
                "DEV_NAME": "APC-SmartUPS-1500",
                "DEV_SNMP_DESCR": "APC Smart-UPS 1500VA LCD RM 2U 120V (SMT1500RM2UC) FW: UPS 09.8",
                "DEV_SNMP_NAME": "APC-SmartUPS-1500",
                "DEV_SNMP_LOC": "Serwerownia / Rack 1 / UPS",
                "DEV_HTTP_TITLE": "APC Smart-UPS 1500 Network Management",
                "DEV_ENABLE_TELNET": "1",
            },
        },
        {
            "name": "netdoc-lab-solar", "label": "Fronius Symo 15.0 (inwerter)", "ip": "172.28.0.56",
            "image_candidates": ["netdoc-lab-device"],
            "ports": {},
            "environment": {
                "DEV_NAME": "Fronius-Symo-15",
                "DEV_SNMP_DESCR": "Fronius Symo 15.0-3-M Solar Inverter — Datamanager 2.0 v3.21.7-1",
                "DEV_SNMP_NAME": "Fronius-Symo-15",
                "DEV_SNMP_LOC": "Dach / Instalacja PV 60kWp",
                "DEV_HTTP_TITLE": "Fronius Solar.web — Datamanager",
                "DEV_ENABLE_MODBUS": "1",
            },
        },
        {
            "name": "netdoc-lab-server", "label": "Ubuntu Server 22.04", "ip": "172.28.0.57",
            "image_candidates": ["netdoc-lab-device"],
            "ports": {},
            "environment": {
                "DEV_NAME": "ubuntu-srv-01",
                "DEV_SNMP_DESCR": "Linux ubuntu-srv-01 5.15.0-88-generic Ubuntu 22.04.3 LTS x86_64",
                "DEV_SNMP_NAME": "ubuntu-srv-01",
                "DEV_SNMP_LOC": "Serwerownia / Rack 3 / VMware ESXi",
                "DEV_HTTP_TITLE": "Ubuntu Server — Application Dashboard",
                "DEV_ENABLE_REDIS": "1", "DEV_ENABLE_MQTT": "1", "DEV_ENABLE_DOCKER_API": "1",
            },
        },
        {
            "name": "netdoc-lab-ap", "label": "Ubiquiti UniFi AP AC Pro", "ip": "172.28.0.58",
            "image_candidates": ["netdoc-lab-device"],
            "ports": {},
            "environment": {
                "DEV_NAME": "UniFi-AP-AC-Pro",
                "DEV_SNMP_DESCR": "Ubiquiti Networks UAP-AC-PRO UniFi AP-AC-Pro, Version 6.5.55.14522",
                "DEV_SNMP_NAME": "UniFi-AP-AC-Pro",
                "DEV_SNMP_LOC": "Biuro / Sufitowy AP — sala konferencyjna",
                "DEV_HTTP_TITLE": "UniFi Access Point",
            },
        },
        {
            "name": "netdoc-lab-winserver", "label": "Windows Server 2019", "ip": "172.28.0.59",
            "image_candidates": ["netdoc-lab-device"],
            "ports": {},
            "environment": {
                "DEV_NAME": "WINSERVER-2019",
                "DEV_SNMP_DESCR": "Windows Server 2019 Standard, Build 17763, Intel Xeon E5-2690",
                "DEV_SNMP_NAME": "WINSERVER-2019",
                "DEV_SNMP_LOC": "Serwerownia / Rack 2 / Domain Controller",
                "DEV_HTTP_TITLE": "Windows Server 2019 — IIS 10.0",
                "DEV_ENABLE_RDP": "1", "DEV_ENABLE_VNC_NOAUTH": "1",
            },
        },
    ]

    def _docker_client():
        try:
            import docker
            return docker.from_env(timeout=5), None
        except Exception as e:
            return None, str(e)

    def _ensure_lab_network(client):
        """Tworzy siec netdoc_lab jesli nie istnieje. Zwraca obiekt sieci."""
        import docker
        try:
            return client.networks.get("netdoc_lab")
        except docker.errors.NotFound:
            from docker.types import IPAMConfig, IPAMPool
            return client.networks.create(
                "netdoc_lab", driver="bridge",
                ipam=IPAMConfig(pool_configs=[IPAMPool(subnet="172.28.0.0/24")]),
            )

    def _create_lab_container(client, ct):
        """Tworzy kontener z obrazu gdy nie istnieje. Zwraca (ok, error_str)."""
        import docker
        for img in ct.get("image_candidates", []):
            try:
                net_config = client.api.create_networking_config({
                    "netdoc_lab": client.api.create_endpoint_config(
                        ipv4_address=ct["ip"]
                    )
                })
                host_cfg = client.api.create_host_config(
                    port_bindings=ct.get("ports", {}),
                    restart_policy={"Name": "unless-stopped"},
                )
                cinfo = client.api.create_container(
                    image=img,
                    name=ct["name"],
                    environment=ct.get("environment", {}),
                    networking_config=net_config,
                    host_config=host_cfg,
                )
                client.api.start(cinfo["Id"])
                return True, None
            except docker.errors.ImageNotFound:
                # Sprobuj pobrac obraz (standardowe obrazy jak nginx:alpine)
                try:
                    client.images.pull(img)
                    # Pobrano — sprobuj znowu
                    cinfo = client.api.create_container(
                        image=img, name=ct["name"],
                        environment=ct.get("environment", {}),
                        networking_config=net_config, host_config=host_cfg,
                    )
                    client.api.start(cinfo["Id"])
                    return True, None
                except Exception:
                    continue
            except Exception as e:
                return False, str(e)
        return False, (
            f"Brak obrazu {ct['image_candidates']}. "
            "Uruchom raz z terminala: docker compose -f docker-compose.lab.yml up -d --build"
        )

    def _lab_status():
        """Zwraca liste kontenerow z ich statusem (tylko pola widoczne w UI)."""
        client, err = _docker_client()
        result = []
        for ct in _LAB_CONTAINERS:
            # Kopiujemy tylko pola potrzebne w UI (pomijamy image_candidates, ports, environment)
            entry = {"name": ct["name"], "label": ct["label"], "ip": ct["ip"]}
            if client:
                try:
                    c = client.containers.get(ct["name"])
                    entry["status"] = c.status          # running / exited / created
                    entry["exists"] = True
                except Exception:
                    entry["status"] = "absent"
                    entry["exists"] = False
            else:
                entry["status"] = "error"
                entry["exists"] = False
                entry["error"] = err
            result.append(entry)
        return result, err

    @app.route("/settings/lab/status")
    def lab_status():
        status, err = _lab_status()
        running = sum(1 for c in status if c.get("status") == "running")
        return jsonify({"containers": status, "running": running,
                        "total": len(status), "docker_error": err})

    @app.route("/settings/lab/start", methods=["POST"])
    def lab_start():
        """Uruchamia kontenery lab. Zwraca JSON dla fetch() w UI."""
        import pathlib as _pl
        _COMPOSE_LAB = str(_pl.Path(__file__).parent.parent.parent / "docker-compose.lab.yml")
        _PROJECT_DIR = str(_pl.Path(__file__).parent.parent.parent)

        # Konteksty budowania per kontener lab (wzgledne do /app)
        _LAB_BUILD_CONTEXTS = {
            "netdoc-lab-plc-s7":    ("config/lab/plc",    "netdoc-lab-plc-s7"),
            "netdoc-lab-plc-meter": ("config/lab/plc",    "netdoc-lab-plc-meter"),
            "netdoc-lab-plc-fuel":  ("config/lab/plc",    "netdoc-lab-plc-fuel"),
            "netdoc-lab-router":    ("config/lab/router",  "netdoc-lab-router"),
            "netdoc-lab-ssh":       ("config/lab/ssh",     "netdoc-lab-ssh"),
            # All generic device containers share one image
            "netdoc-lab-cam-dahua": ("config/lab/device",  "netdoc-lab-device"),
            "netdoc-lab-cam-hik":   ("config/lab/device",  "netdoc-lab-device"),
            "netdoc-lab-printer":   ("config/lab/device",  "netdoc-lab-device"),
            "netdoc-lab-nas":       ("config/lab/device",  "netdoc-lab-device"),
            "netdoc-lab-moxa":      ("config/lab/device",  "netdoc-lab-device"),
            "netdoc-lab-ups":       ("config/lab/device",  "netdoc-lab-device"),
            "netdoc-lab-solar":     ("config/lab/device",  "netdoc-lab-device"),
            "netdoc-lab-server":    ("config/lab/device",  "netdoc-lab-device"),
            "netdoc-lab-ap":        ("config/lab/device",  "netdoc-lab-device"),
            "netdoc-lab-winserver": ("config/lab/device",  "netdoc-lab-device"),
        }

        def _auto_build_and_start(docker_client, missing_names):
            """Buduje brakujace obrazy przez Docker SDK i uruchamia kontenery."""
            import pathlib as _plb
            built, failed = [], []
            # Build each unique image only once (multiple containers may share netdoc-lab-device)
            built_tags: set = set()
            for name in missing_names:
                ctx = _LAB_BUILD_CONTEXTS.get(name)
                if not ctx:
                    continue
                rel_path, tag = ctx
                if tag in built_tags:
                    built.append(name)  # image already built — count container as done
                    continue
                build_path = str(_plb.Path(_PROJECT_DIR) / rel_path)
                if not _plb.Path(build_path).exists():
                    failed.append(f"{name}: brak katalogu {build_path} — czy config/ jest zamontowany w kontenerze?")
                    continue
                try:
                    docker_client.images.build(path=build_path, tag=tag, rm=True)
                    built_tags.add(tag)
                    built.append(name)
                except Exception as e:
                    failed.append(f"{name}: {str(e)[:100]}")
            if failed and not built:
                return False, "Budowanie obrazow nie powiodlo sie: " + "; ".join(failed)
            if failed:
                return True, f"Zbudowano {len(built)} obrazow. Bledy ({len(failed)}): {'; '.join(failed)}"
            return True, f"Zbudowano {len(built)} obrazow lab."

        try:
            import docker as _docker_mod
            client, err = _docker_client()
            if not client:
                return jsonify({"ok": False,
                                "message": f"Docker SDK niedostepny: {err}. Uruchom: docker compose -f docker-compose.lab.yml up -d --build"})
            try:
                _ensure_lab_network(client)
            except Exception as e:
                return jsonify({"ok": False, "message": f"Nie mozna stworzyc sieci netdoc_lab: {e}"})

            started = created = 0
            errors = []
            image_missing_names = []
            for ct in _LAB_CONTAINERS:
                try:
                    c = client.containers.get(ct["name"])
                    if c.status != "running":
                        c.start()
                    started += 1
                except _docker_mod.errors.NotFound:
                    ok, errmsg = _create_lab_container(client, ct)
                    if ok:
                        created += 1
                    else:
                        if "Brak obrazu" in errmsg:
                            image_missing_names.append(ct["name"])
                        else:
                            errors.append(f"{ct['name']}: {errmsg}")
                except Exception as e:
                    errors.append(f"{ct['name']}: {e}")

            # Buduj brakujace obrazy — niezaleznie od liczby juz uruchomionych kontenerow
            if image_missing_names:
                app.logger.info(
                    "lab_start: brak obrazow dla %s — probuje auto-build",
                    ", ".join(image_missing_names))
                build_ok, build_msg = _auto_build_and_start(client, image_missing_names)
                if build_ok:
                    for ct in _LAB_CONTAINERS:
                        if ct["name"] not in image_missing_names:
                            continue
                        try:
                            c = client.containers.get(ct["name"])
                            if c.status != "running":
                                c.start()
                            started += 1
                        except _docker_mod.errors.NotFound:
                            ok2, errmsg2 = _create_lab_container(client, ct)
                            if ok2:
                                created += 1
                            else:
                                errors.append(f"{ct['name']}: {errmsg2}")
                        except Exception as e2:
                            errors.append(f"{ct['name']}: {e2}")
                else:
                    errors.append(
                        f"Brak obrazow ({', '.join(image_missing_names)}). "
                        f"Auto-build nie powiodl sie: {build_msg}. "
                        f"Uruchom recznie: docker compose -f docker-compose.lab.yml up -d --build"
                    )

            # Retry — poczekaj 2s i sprobuj jeszcze raz kontenery ktore sie nie uruchomily
            if errors:
                import time as _time
                _time.sleep(2)
                retry_names = set(_e.split(":", 1)[0].strip() for _e in errors if ":" in _e)
                still_errors = []
                for ct in _LAB_CONTAINERS:
                    if ct["name"] not in retry_names:
                        continue
                    try:
                        c = client.containers.get(ct["name"])
                        if c.status != "running":
                            c.start()
                        started += 1
                    except Exception:
                        ok_r, err_r = _create_lab_container(client, ct)
                        if ok_r:
                            created += 1
                        else:
                            still_errors.append(f"{ct['name']}: {err_r}")
                errors = still_errors

            total = started + created

            # Podlacz workersy do sieci lab (jesli jeszcze nie sa)
            _WORKER_NAMES = ["netdoc-ping", "netdoc-snmp", "netdoc-cred", "netdoc-vuln"]
            net_errors = []
            try:
                lab_net = client.networks.get("netdoc_lab")
                for wname in _WORKER_NAMES:
                    try:
                        lab_net.connect(wname)
                    except Exception as e:
                        err_str = str(e)
                        if "already exists" not in err_str and "endpoint with name" not in err_str:
                            net_errors.append(f"{wname}: {err_str}")
            except Exception as e:
                net_errors.append(f"network connect: {e}")

            if errors and total == 0:
                return jsonify({"ok": False, "message": f"Blad uruchamiania: {'; '.join(errors)}"})

            # Ustaw notatke "NetDoc Lab" dla sieci 172.28.0.0/24 jesli istnieje w DB
            try:
                from netdoc.storage.models import DiscoveredNetwork
                with SessionLocal() as _db:
                    _net = _db.query(DiscoveredNetwork).filter_by(cidr="172.28.0.0/24").first()
                    if _net and not _net.notes:
                        _net.notes = "NetDoc Lab"
                        _db.commit()
                    elif not _net:
                        from netdoc.storage.models import NetworkSource
                        _db.add(DiscoveredNetwork(
                            cidr="172.28.0.0/24", notes="NetDoc Lab",
                            source=NetworkSource.manual, is_active=True,
                        ))
                        _db.commit()
            except Exception:
                pass

            msg = f"Lab aktywny — {total}/{len(_LAB_CONTAINERS)} kontenerow uruchomionych."
            if errors:
                msg += f" Bledy ({len(errors)}): {'; '.join(errors)}"
            if net_errors:
                msg += f" Siec: {'; '.join(net_errors)}"
            return jsonify({"ok": not errors, "message": msg, "started": started, "created": created})
        except Exception as exc:
            app.logger.exception("lab_start nieoczekiwany blad: %s", exc)
            return jsonify({"ok": False, "message": f"Nieoczekiwany blad: {exc}"})

    @app.route("/settings/lab/stop", methods=["POST"])
    def lab_stop():
        """Zatrzymuje kontenery lab. Zwraca JSON dla fetch() w UI."""
        try:
            import docker as _docker_mod
            client, err = _docker_client()
            if not client:
                return jsonify({"ok": False, "message": f"Docker SDK niedostepny: {err}"})

            stopped = 0
            errors = []
            for ct in _LAB_CONTAINERS:
                try:
                    c = client.containers.get(ct["name"])
                    if c.status == "running":
                        c.stop(timeout=5)
                    c.remove()  # usun kontener — status bedzie "nie utworzony"
                    stopped += 1
                except _docker_mod.errors.NotFound:
                    stopped += 1  # juz nie istnieje — ok
                except Exception as e:
                    errors.append(f"{ct['name']}: {e}")

            if errors:
                return jsonify({"ok": False,
                                "message": f"Usunieto {stopped} kontenerow. Bledy: {'; '.join(errors)}"})

            # Odlacz workerow od netdoc_lab i usun siec
            _WORKER_NAMES = ["netdoc-ping", "netdoc-snmp", "netdoc-cred", "netdoc-vuln"]
            net_removed = False
            try:
                lab_net = client.networks.get("netdoc_lab")
                for wname in _WORKER_NAMES:
                    try:
                        lab_net.disconnect(wname, force=True)
                    except Exception:
                        pass
                lab_net.remove()
                net_removed = True
            except _docker_mod.errors.NotFound:
                net_removed = True  # juz nie istnieje — ok
            except Exception as e:
                errors.append(f"network: {e}")

            msg = f"Lab zatrzymany — {stopped} kontenerow usunietych."
            if net_removed:
                msg += " Siec netdoc_lab usunieta."
            return jsonify({"ok": True, "message": msg})
        except Exception as exc:
            app.logger.exception("lab_stop nieoczekiwany blad: %s", exc)
            return jsonify({"ok": False, "message": f"Nieoczekiwany blad: {exc}"})

    # ── docker nuke (pełny reset) ───────────────────────────────────────────────
    @app.route("/settings/docker/nuke-stream")
    def docker_nuke_stream():
        """SSE — strumieniowy reset Docker: down -v + system prune -af --volumes.

        Zatrzymuje wszystkie kontenery netdoc (łącznie z netdoc-web),
        usuwa wolumeny, sieci, obrazy i build cache.
        Po zakończeniu kontener web przestaje działać.
        """
        from flask import Response
        import docker as docker_sdk

        def _generate():
            def _msg(text):
                return f"data: {text}\n\n"

            try:
                client = docker_sdk.from_env(timeout=10)
            except Exception as exc:
                yield _msg(f"✗ Błąd połączenia z Docker: {exc}")
                yield _msg("ERROR")
                return

            # 1. Zatrzymaj i usuń kontenery netdoc + lab (poza sobą — web na końcu)
            yield _msg("▶ Zatrzymywanie kontenerów netdoc i lab…")
            self_container = None
            for c in client.containers.list(all=True):
                is_netdoc = c.name.startswith("netdoc-")
                is_lab = c.name.startswith("netdoc-lab-")
                if not (is_netdoc or is_lab):
                    continue
                if c.name == "netdoc-web":
                    self_container = c
                    continue
                try:
                    if c.status == "running":
                        c.stop(timeout=8)
                    c.remove()
                    yield _msg(f"  ✓ {c.name}")
                except Exception as exc:
                    yield _msg(f"  ✗ {c.name}: {exc}")

            # 2. Usuń wolumeny netdoc
            yield _msg("▶ Usuwanie wolumenów netdoc…")
            for v in client.volumes.list():
                if v.name.startswith("netdoc_"):
                    try:
                        v.remove(force=True)
                        yield _msg(f"  ✓ {v.name}")
                    except Exception as exc:
                        yield _msg(f"  ✗ {v.name}: {exc}")

            # 3. Usuń sieci netdoc (najpierw odlacz siebie)
            yield _msg("▶ Usuwanie sieci netdoc…")
            for n in client.networks.list():
                if "netdoc" in n.name:
                    try:
                        if self_container:
                            try:
                                n.disconnect(self_container, force=True)
                            except Exception:
                                pass
                        n.remove()
                        yield _msg(f"  ✓ {n.name}")
                    except Exception as exc:
                        yield _msg(f"  ✗ {n.name}: {exc}")

            # 4. Usuń tylko obrazy netdoc (nie system-wide prune — nie dotykamy innych projektów)
            yield _msg("▶ Usuwanie obrazów netdoc…")
            try:
                freed = 0
                deleted = 0
                for img in client.images.list():
                    tags = img.tags or []
                    is_netdoc = any(
                        t.startswith("netdoc") or "/netdoc" in t or "netdoc-" in t
                        for t in tags
                    ) or not tags  # untagged (dangling) after container removal
                    if is_netdoc:
                        try:
                            size = img.attrs.get("Size", 0)
                            client.images.remove(img.id, force=True)
                            freed += size
                            deleted += 1
                            tag_str = tags[0] if tags else img.short_id
                            yield _msg(f"  ✓ {tag_str}")
                        except Exception as exc:
                            yield _msg(f"  ✗ {tags}: {exc}")
                freed_gb = freed / 1024 ** 3
                yield _msg(f"  ✓ Usunięto {deleted} obrazów — zwolniono {freed_gb:.2f} GB")
            except Exception as exc:
                yield _msg(f"  ✗ Usuwanie obrazów: {exc}")

            yield _msg("✅ Gotowe! Zatrzymuję i usuwam kontener web…")
            yield _msg("DONE")

            # 5. Na końcu zatrzymaj i usuń siebie
            import time
            time.sleep(1)
            if self_container:
                try:
                    self_container.stop(timeout=5)
                    self_container.remove()
                except Exception:
                    pass

        return Response(
            _generate(),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ── restart / rebuild kontenerow ────────────────────────────────────────────
    # Mapowanie: service-key → container_name
    _DOCKER_SERVICES = {
        "api":      "netdoc-api",
        "web":      "netdoc-web",
        "ping":     "netdoc-ping",
        "snmp":     "netdoc-snmp",
        "cred":     "netdoc-cred",
        "vuln":     "netdoc-vuln",
        "postgres": "netdoc-postgres",
        "grafana":  "netdoc-grafana",
        "prometheus": "netdoc-prometheus",
        "loki":     "netdoc-loki",
        "promtail": "netdoc-promtail",
        "internet":    "netdoc-internet",
        "community":   "netdoc-community",
        "clickhouse":  "netdoc-clickhouse",
        "rsyslog":     "netdoc-rsyslog",
        "vector":      "netdoc-vector",
        "nginx":       "netdoc-nginx",
        "ntopng":      "netdoc-ntopng",
        "wazuh":       "netdoc-wazuh",
    }

    @app.route("/settings/docker/restart-stream")
    def docker_restart_stream():
        """SSE — restart wybranych kontenerow (picks up mounted code changes)."""
        from flask import Response, request as _req
        import docker as docker_sdk

        raw = _req.args.get("services", "")
        keys = [s.strip() for s in raw.split(",") if s.strip()] if raw else list(_DOCKER_SERVICES.keys())

        def _generate():
            def _msg(t):
                return f"data: {t}\n\n"

            try:
                client = docker_sdk.from_env(timeout=10)
            except Exception as exc:
                yield _msg(f"✗ Błąd połączenia z Docker: {exc}")
                yield _msg("ERROR")
                return

            self_restart = "web" in keys
            other_keys = [k for k in keys if k != "web"]

            for key in other_keys:
                cname = _DOCKER_SERVICES.get(key)
                if not cname:
                    yield _msg(f"  ✗ Nieznany serwis: {key}")
                    continue
                try:
                    c = client.containers.get(cname)
                    c.restart(timeout=10)
                    yield _msg(f"  ✓ {cname} — zrestartowany")
                except docker_sdk.errors.NotFound:
                    yield _msg(f"  ✗ {cname} — nie znaleziony")
                except Exception as exc:
                    yield _msg(f"  ✗ {cname}: {exc}")

            if self_restart:
                yield _msg("  ✓ netdoc-web — restartuję siebie…")
                yield _msg("DONE")
                import time
                time.sleep(1)
                try:
                    self_c = client.containers.get("netdoc-web")
                    self_c.restart(timeout=5)
                except Exception:
                    pass
            else:
                yield _msg("✅ Gotowe!")
                yield _msg("DONE")

        return Response(
            _generate(),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.route("/settings/docker/rebuild-stream")
    def docker_rebuild_stream():
        """SSE — rebuild obrazow Docker + restart kontenerow.

        Uzywa Docker SDK do zbudowania nowego obrazu z /app (build context).
        Przydatne gdy zmienily sie requirements.txt lub Dockerfile.
        Dla zwyklych zmian kodu wystarczy restart (kod jest montowany jako wolumen).
        """
        from flask import Response, request as _req
        import docker as docker_sdk

        raw = _req.args.get("services", "")
        keys = [s.strip() for s in raw.split(",") if s.strip()] if raw else ["api", "web", "ping", "snmp", "cred", "vuln"]

        # Tylko serwisy budowane z ./Dockerfile (nie postgres/grafana/prometheus)
        _BUILDABLE = {"api", "web", "ping", "snmp", "cred", "vuln", "internet"}
        build_keys = [k for k in keys if k in _BUILDABLE]
        restart_keys = [k for k in keys if k not in _BUILDABLE]

        def _generate():
            def _msg(t):
                return f"data: {t}\n\n"

            try:
                client = docker_sdk.from_env(timeout=30)
            except Exception as exc:
                yield _msg(f"✗ Błąd połączenia z Docker: {exc}")
                yield _msg("ERROR")
                return

            # 1. Zbuduj nowe obrazy
            if build_keys:
                yield _msg(f"▶ Budowanie obrazu Docker z /app…")
                try:
                    build_logs = client.api.build(
                        path="/app",
                        dockerfile="Dockerfile",
                        tag="netdoc-app:latest",
                        rm=True,
                        decode=True,
                    )
                    for chunk in build_logs:
                        if "stream" in chunk:
                            line = chunk["stream"].rstrip()
                            if line:
                                yield _msg(f"  {line}")
                        elif "error" in chunk:
                            yield _msg(f"  ✗ {chunk['error']}")
                            yield _msg("ERROR")
                            return
                    yield _msg("  ✓ Obraz zbudowany")
                except Exception as exc:
                    yield _msg(f"  ✗ Build error: {exc}")
                    yield _msg("ERROR")
                    return

            # 2. Restart — pozostale serwisy (bez obrazu)
            for key in restart_keys:
                cname = _DOCKER_SERVICES.get(key)
                if not cname:
                    continue
                try:
                    c = client.containers.get(cname)
                    c.restart(timeout=10)
                    yield _msg(f"  ✓ {cname} — zrestartowany")
                except Exception as exc:
                    yield _msg(f"  ✗ {cname}: {exc}")

            # 3. Restart serwisow z nowym obrazem (poza web)
            self_rebuild = "web" in build_keys
            other_build = [k for k in build_keys if k != "web"]

            for key in other_build:
                cname = _DOCKER_SERVICES.get(key)
                if not cname:
                    continue
                yield _msg(f"▶ Restart {cname}…")
                try:
                    c = client.containers.get(cname)
                    c.restart(timeout=10)
                    yield _msg(f"  ✓ {cname} — zrestartowany z nowym obrazem")
                except Exception as exc:
                    yield _msg(f"  ✗ {cname}: {exc}")

            if self_rebuild:
                yield _msg("▶ Restartuję kontener web (siebie)…")
                yield _msg("DONE")
                import time
                time.sleep(1)
                try:
                    self_c = client.containers.get("netdoc-web")
                    self_c.restart(timeout=5)
                except Exception:
                    pass
            else:
                yield _msg("✅ Gotowe!")
                yield _msg("DONE")

        return Response(
            _generate(),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ── syslog ──────────────────────────────────────────────────────────────────
    @app.route("/syslog")
    def syslog():
        db = SessionLocal()
        try:
            devices_list = db.query(Device).filter(Device.is_active.is_(True)).order_by(Device.ip).all()
        finally:
            db.close()
        retention_days = 30
        if PRO_ENABLED:
            try:
                from netdoc.storage.clickhouse import get_syslog_retention_days
                retention_days = get_syslog_retention_days()
            except Exception:
                pass
        return render_template("syslog.html", devices=devices_list,
                               PRO_ENABLED=PRO_ENABLED,
                               syslog_retention_days=retention_days)

    @app.route("/api/syslog/retention", methods=["POST"])
    def syslog_set_retention():
        """PRO: zmienia TTL retencji syslog w ClickHouse."""
        if not PRO_ENABLED:
            return {"error": "PRO feature"}, 403
        try:
            days = int(request.json.get("days", 30))
            from netdoc.storage.clickhouse import set_syslog_retention_days
            set_syslog_retention_days(days)
            return {"ok": True, "days": max(7, min(365, days))}
        except Exception as exc:
            return {"error": str(exc)}, 500

    @app.route("/api/syslog")
    def syslog_proxy():
        """Proxy do FastAPI — zwraca logi syslog z ClickHouse (GET).
        PRO: obsługuje search, offset, rozszerzone limity i zakres czasu.
        """
        if PRO_ENABLED:
            try:
                from netdoc.storage.clickhouse import query_syslog as _qs
                args = request.args

                # Resolve device IP for syslog filtering by device_id.
                # The syslog relay preserves real src IPs — filter ClickHouse by src_ip.
                syslog_src_ip = args.get("src_ip") or None
                raw_device_id = args.get("device_id")
                if raw_device_id and not syslog_src_ip:
                    try:
                        from netdoc.storage.database import SessionLocal as _SL
                        from netdoc.storage.models import Device as _Dev
                        _db = _SL()
                        try:
                            _dev = _db.query(_Dev).filter(_Dev.id == int(raw_device_id)).first()
                            if _dev and _dev.ip:
                                syslog_src_ip = str(_dev.ip)
                        finally:
                            _db.close()
                    except Exception:
                        pass

                rows = _qs(
                    src_ip       = syslog_src_ip,
                    severity_max = int(args["severity"]) if args.get("severity") else None,
                    program      = args.get("program") or None,
                    search       = args.get("search") or None,
                    since_hours  = int(args.get("hours") or 24),
                    limit        = int(args.get("limit") or 200),
                    offset       = int(args.get("offset") or 0),
                    pro          = True,
                )
                _SEV = {0:"EMERGENCY",1:"ALERT",2:"CRITICAL",3:"ERROR",
                        4:"WARNING",5:"NOTICE",6:"INFO",7:"DEBUG"}
                return jsonify({"logs": [
                    {**r, "timestamp": str(r["timestamp"]),
                     "severity_name": _SEV.get(r.get("severity"), "UNKNOWN")} for r in rows
                ], "count": len(rows)})
            except Exception as exc:
                return jsonify({"error": str(exc), "logs": [], "count": 0}), 503
        try:
            resp = requests.get(f"{API_URL}/api/syslog", params=request.args.to_dict(), timeout=15)
            return resp.content, resp.status_code, {"Content-Type": "application/json"}
        except Exception as exc:
            return jsonify({"error": str(exc), "logs": [], "count": 0}), 503

    @app.route("/api/syslog/devices/<int:device_id>")
    def syslog_device_proxy(device_id):
        """Proxy do FastAPI — logi syslog dla konkretnego urządzenia."""
        try:
            resp = requests.get(f"{API_URL}/api/syslog/devices/{device_id}", params=request.args.to_dict(), timeout=15)
            return resp.content, resp.status_code, {"Content-Type": "application/json"}
        except Exception as exc:
            return jsonify({"error": str(exc), "logs": [], "count": 0}), 503

    # ── logs ───────────────────────────────────────────────────────────────────
    @app.route("/logs")
    def logs():
        return render_template("logs.html")

    @app.route("/api/logs/scanner")
    def logs_scanner_proxy():
        """Proxy do API — zwraca logi skanera (plain text)."""
        tail = request.args.get("tail", 200)
        try:
            resp = requests.get(f"{API_URL}/api/logs/scanner?tail={tail}", timeout=10)
            return resp.text, 200, {"Content-Type": "text/plain; charset=utf-8"}
        except Exception as exc:
            return f"Błąd połączenia z API: {exc}", 500, {"Content-Type": "text/plain; charset=utf-8"}

    @app.route("/api/logs/watchdog")
    def logs_watchdog_proxy():
        tail = request.args.get("tail", 200, type=int)
        try:
            resp = requests.get(f"{API_URL}/api/logs/watchdog?tail={tail}", timeout=10)
            return resp.text, 200, {"Content-Type": "text/plain; charset=utf-8"}
        except Exception as exc:
            return f"Błąd połączenia z API: {exc}", 500, {"Content-Type": "text/plain; charset=utf-8"}

    @app.route("/api/logs/cred")
    def logs_cred_proxy():
        tail = request.args.get("tail", 200, type=int)
        try:
            resp = requests.get(f"{API_URL}/api/logs/cred?tail={tail}", timeout=10)
            return resp.text, 200, {"Content-Type": "text/plain; charset=utf-8"}
        except Exception as exc:
            return f"Błąd połączenia z API: {exc}", 500, {"Content-Type": "text/plain; charset=utf-8"}

    @app.route("/api/logs/broadcast")
    def logs_broadcast_proxy():
        tail = request.args.get("tail", 200, type=int)
        try:
            resp = requests.get(f"{API_URL}/api/logs/broadcast?tail={tail}", timeout=10)
            return resp.text, 200, {"Content-Type": "text/plain; charset=utf-8"}
        except Exception as exc:
            return f"Error connecting to API: {exc}", 500, {"Content-Type": "text/plain; charset=utf-8"}

    @app.route("/api/logs/syslog-relay")
    def logs_syslog_relay_proxy():
        tail = request.args.get("tail", 200, type=int)
        try:
            resp = requests.get(f"{API_URL}/api/logs/syslog-relay?tail={tail}", timeout=10)
            return resp.text, 200, {"Content-Type": "text/plain; charset=utf-8"}
        except Exception as exc:
            return f"Error connecting to API: {exc}", 500, {"Content-Type": "text/plain; charset=utf-8"}

    @app.route("/api/broadcast/packet-stats")
    def broadcast_packet_stats():
        """Zwraca statystyki pakietow per urzadzenie (top spammers)."""
        stats_file = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "..", "logs", "broadcast_stats.json")
        )
        if not os.path.exists(stats_file):
            return jsonify({"generated_at": None, "uptime_s": 0, "rows": []})
        try:
            import json as _json
            with open(stats_file, encoding="utf-8") as f:
                return jsonify(_json.load(f))
        except Exception as exc:
            return jsonify({"error": str(exc), "rows": []}), 500

    @app.route("/api/broadcast/raw/toggle", methods=["POST"])
    def broadcast_raw_toggle():
        """Wlacza/wylacza surowe logowanie pakietow przez broadcast worker."""
        flag = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "..", "logs", "broadcast_raw_enabled")
        )
        if os.path.exists(flag):
            os.remove(flag)
            enabled = False
        else:
            open(flag, "w").close()
            enabled = True
        return jsonify({"enabled": enabled})

    @app.route("/api/broadcast/raw/status")
    def broadcast_raw_status():
        flag = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "..", "logs", "broadcast_raw_enabled")
        )
        return jsonify({"enabled": os.path.exists(flag)})

    @app.route("/api/broadcast/raw")
    def broadcast_raw_content():
        """Zwraca nowa zawartosc broadcast_raw.log od podanego offsetu bajtowego."""
        offset = request.args.get("offset", 0, type=int)
        raw_log = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "..", "logs", "broadcast_raw.log")
        )
        if not os.path.exists(raw_log):
            return jsonify({"content": "", "offset": 0, "size": 0})
        size = os.path.getsize(raw_log)
        # File was trimmed — reset offset
        if offset > size:
            offset = max(0, size - 65536)
        with open(raw_log, encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            content = f.read(65536)   # max 64 KB per request
            new_offset = f.tell()
        return jsonify({"content": content, "offset": new_offset, "size": size})

    @app.route("/api/broadcast/stats")
    def broadcast_stats():
        """Zwraca statystyki ostatniego cyklu broadcast discovery z SystemStatus."""
        db = SessionLocal()
        try:
            from netdoc.storage.models import SystemStatus
            keys = [
                "broadcast_last_at", "broadcast_last_discovered", "broadcast_last_saved",
                "broadcast_unifi", "broadcast_mndp", "broadcast_mdns", "broadcast_ssdp",
                "broadcast_lldp",
            ]
            rows = db.query(SystemStatus).filter(SystemStatus.key.in_(keys)).all()
            stats = {r.key: r.value for r in rows}
            return jsonify(stats)
        finally:
            db.close()

    @app.route("/broadcast-traffic")
    def broadcast_traffic():
        """Strona analizy ruchu broadcast/multicast per urzadzenie."""
        return render_template("broadcast_traffic.html")

    @app.route("/api/metrics/broadcast-summary")
    def broadcast_summary_proxy():
        """Proxy do FastAPI /api/metrics/broadcast-summary."""
        since_hours = request.args.get("since_hours", 24, type=int)
        limit = request.args.get("limit", 100, type=int)
        threshold = request.args.get("threshold", 0, type=float)
        data, err = _api("get", f"/api/metrics/broadcast-summary?since_hours={since_hours}&limit={limit}&threshold={threshold}")
        if err:
            return jsonify({"error": err, "devices": []}), 500
        return jsonify(data)

    @app.route("/api/devices/<int:device_id>/broadcast-history")
    def broadcast_history_proxy(device_id):
        """Proxy do FastAPI /api/devices/{id}/broadcast-history."""
        hours = request.args.get("hours", 24, type=int)
        step = request.args.get("step_minutes", 5, type=int)
        data, err = _api("get", f"/api/devices/{device_id}/broadcast-history?hours={hours}&step_minutes={step}")
        if err:
            return jsonify({"error": err, "buckets": []}), 500
        return jsonify(data)

    @app.route("/api/logs/docker/<container>")
    def logs_docker_proxy(container):
        """Czyta stdout/stderr kontenera Docker przez Python Docker SDK (socket /var/run/docker.sock)."""
        _ALLOWED = {"netdoc-ping", "netdoc-snmp", "netdoc-community", "netdoc-vuln",
                    "netdoc-internet", "netdoc-cred", "netdoc-web", "netdoc-api",
                    "netdoc-nginx", "netdoc-rsyslog", "netdoc-vector", "netdoc-clickhouse"}
        if container not in _ALLOWED:
            return "Niedozwolona nazwa kontenera.", 400, {"Content-Type": "text/plain; charset=utf-8"}
        tail = request.args.get("tail", 200, type=int)
        try:
            import docker as _docker_mod
            client = _docker_mod.from_env(timeout=8)
            try:
                c = client.containers.get(container)
            except _docker_mod.errors.NotFound:
                return f"Kontener '{container}' nie istnieje lub nie jest uruchomiony.", 404, \
                       {"Content-Type": "text/plain; charset=utf-8"}
            # timestamps=True dodaje timestamp przed kazda linia
            raw = c.logs(stdout=True, stderr=True, tail=tail, timestamps=True)
            out = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
            return out, 200, {"Content-Type": "text/plain; charset=utf-8"}
        except _docker_mod.errors.DockerException as exc:
            return f"Docker SDK error: {exc}", 503, {"Content-Type": "text/plain; charset=utf-8"}
        except Exception as exc:
            return f"Blad: {exc}", 500, {"Content-Type": "text/plain; charset=utf-8"}

    @app.route("/api/logs/events")
    def logs_events():
        """Ostatnie N zdarzen sieciowych z tabeli events — do zakladki Aktywnosc w /logs."""
        from netdoc.storage.models import Event, EventType
        limit = request.args.get("limit", 100, type=int)
        db = SessionLocal()
        try:
            evs = (
                db.query(Event, Device)
                  .join(Device, Event.device_id == Device.id)
                  .filter(Event.device_id.isnot(None))
                  .order_by(Event.event_time.desc())
                  .limit(limit)
                  .all()
            )
            rows = []
            for ev, dev in evs:
                rows.append({
                    "time":        ev.event_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "event_type":  ev.event_type.value if hasattr(ev.event_type, "value") else str(ev.event_type),
                    "device_ip":   dev.ip,
                    "device_type": dev.device_type.value if dev.device_type else "unknown",
                    "hostname":    dev.hostname or "",
                })
        finally:
            db.close()
        return {"events": rows}

    @app.route("/api/logs/ai")
    def logs_ai():
        """Historia zapytan i odpowiedzi AI per-urzadzenie — do zakladki AI Logs w /logs."""
        limit = request.args.get("limit", 50, type=int)
        db = SessionLocal()
        try:
            rows = (
                db.query(DeviceAssessment, Device)
                .outerjoin(Device, DeviceAssessment.device_id == Device.id)
                .order_by(DeviceAssessment.assessed_at.desc())
                .limit(limit)
                .all()
            )
            items = []
            for entry, dev in rows:
                try:
                    result_data = _json.loads(entry.result)
                except Exception:
                    result_data = {}
                items.append({
                    "id":           entry.id,
                    "device_id":    dev.id if dev else entry.device_id,
                    "device_ip":    dev.ip if dev else "(usunięte)",
                    "device_label": (dev.hostname or dev.ip) if dev else f"(Device #{entry.device_id} usunięty)",
                    "assessed_at":  entry.assessed_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "model":        entry.model or "claude-opus-4-6",
                    "is_obsolete":  result_data.get("is_obsolete"),
                    "reason":       result_data.get("reason", ""),
                    "summary":      result_data.get("summary", ""),
                    "replacements_count": len(result_data.get("replacements", [])),
                    "has_prompt":   bool(entry.prompt),
                    "prompt":       entry.prompt or "",
                    "result_json":  entry.result,
                })
            return jsonify(items)
        finally:
            db.close()

    # ── AJAX status ────────────────────────────────────────────────────────────
    @app.route("/api/status")
    def api_status():
        db = SessionLocal()
        try:
            status = {r.key: r.value for r in db.query(SystemStatus).all()}
            device_count = db.query(Device).count()
            active = db.query(Device).filter(Device.is_active.is_(True)).count()
        finally:
            db.close()
        return jsonify({
            "device_count": device_count,
            "active_devices": active,
            "scanner_job": status.get("scanner_job", "-"),
            "scanner_mode": status.get("scanner_mode"),
            "scanner_last_at": status.get("scanner_last_at"),
            "scanner_last_devices": status.get("scanner_last_devices"),
            "scanner_last_enriched": status.get("scanner_last_enriched"),
            "scanner_last_duration_s": status.get("scanner_last_duration_s"),
            "scan_progress": status.get("scan_progress", ""),
            "scanning_ips": status.get("scanning_ips", ""),
        })


    # ── security ───────────────────────────────────────────────────────────────
    @app.route("/kb/guides")
    @app.route("/kb/guides/<guide_id>")
    def kb_guides(guide_id=None):
        """Poradniki bezpieczeństwa sieciowego."""
        from netdoc.web.kb_guides import GUIDES, GUIDES_BY_ID
        current = GUIDES_BY_ID.get(guide_id) if guide_id else None
        if guide_id and not current:
            flash("Nie znaleziono artykułu.", "warning")
            return redirect(url_for("kb_guides"))
        return render_template("kb_guides.html", guides=GUIDES, current=current)

    @app.route("/kb/ports")
    def kb_ports():
        """Encyklopedia portów — baza wiedzy o znanych portach i usługach."""
        from netdoc.web.port_kb import PORT_KB, PORT_CATEGORIES
        from netdoc.storage.models import ScanResult
        from sqlalchemy import func
        import ipaddress as _ipmod

        search = request.args.get("q", "").strip().lower()
        cat_filter = request.args.get("cat", "").strip()
        risk_filter = request.args.get("risk", "").strip()
        ot_filter = request.args.get("ot", "").strip()
        net_filter = request.args.get("net", "").strip()

        # Sprawdź czy IP należy do wybranej sieci
        def _in_net(ip_str: str, cidr: str) -> bool:
            try:
                return _ipmod.IPv4Address(ip_str) in _ipmod.IPv4Network(cidr, strict=False)
            except Exception:
                return False

        entries = PORT_KB
        if search:
            entries = [e for e in entries if
                       search in str(e["port"]) or
                       search in e["service"].lower() or
                       search in e["desc"].lower() or
                       any(search in v.lower() for v in e["vendors"])]
        if cat_filter:
            entries = [e for e in entries if e["category"] == cat_filter]
        if risk_filter:
            entries = [e for e in entries if e["risk"] == risk_filter]
        if ot_filter == "1":
            entries = [e for e in entries if e.get("ot")]

        # Zbuduj indeks port → lista urzadzen na podstawie ostatnich wynikow skanow
        db = SessionLocal()
        port_devices: dict[int, list[dict]] = {}
        port_acceptances: dict[tuple, str] = {}  # (device_id, port) → reason
        known_networks_kb = []
        try:
            from netdoc.storage.models import PortAcceptance
            all_devs = {d.id: d for d in db.query(Device).all()}

            # Pobierz sieci do filtra
            _all_nets_kb = db.query(DiscoveredNetwork).order_by(DiscoveredNetwork.cidr).all()
            known_networks_kb = [{"cidr": n.cidr, "notes": n.notes or "",
                                   "is_local": n.source == NetworkSource.auto}
                                  for n in _all_nets_kb]

            for pa in db.query(PortAcceptance).all():
                port_acceptances[(pa.device_id, pa.port)] = pa.reason or ""

            # Najnowszy skan discovery per device
            subq = (db.query(ScanResult.device_id,
                             func.max(ScanResult.scan_time).label("mt"))
                    .filter(ScanResult.device_id.isnot(None))
                    .group_by(ScanResult.device_id).subquery())
            latest = (db.query(ScanResult)
                      .join(subq, (ScanResult.device_id == subq.c.device_id) &
                                  (ScanResult.scan_time == subq.c.mt))
                      .all())

            # Najnowszy pelny skan per device
            subq_f = (db.query(ScanResult.device_id,
                               func.max(ScanResult.scan_time).label("mt"))
                      .filter(ScanResult.device_id.isnot(None),
                              ScanResult.scan_type == "nmap_full")
                      .group_by(ScanResult.device_id).subquery())
            full = (db.query(ScanResult)
                    .join(subq_f, (ScanResult.device_id == subq_f.c.device_id) &
                                  (ScanResult.scan_time == subq_f.c.mt))
                    .all())

            # Scal: pelny skan nadpisuje discovery (wiecej portow)
            best: dict[int, ScanResult] = {sr.device_id: sr for sr in latest}
            for sr in full:
                best[sr.device_id] = sr

            for sr in best.values():
                if not sr.open_ports:
                    continue
                dev = all_devs.get(sr.device_id)
                if not dev:
                    continue
                info = {
                    "id":        dev.id,
                    "ip":        dev.ip,
                    "hostname":  dev.hostname or "",
                    "scan_type": sr.scan_type,
                    "scan_date": sr.scan_time.strftime("%Y-%m-%d") if sr.scan_time else "",
                    "is_active": dev.is_active,
                    "accepted":  (dev.id, 0),  # placeholder, wypelniany ponizej
                }
                for p_str in sr.open_ports.keys():
                    try:
                        p = int(p_str)
                        port_devices.setdefault(p, []).append({**info,
                            "accepted": (dev.id, p) in port_acceptances,
                            "accept_reason": port_acceptances.get((dev.id, p), ""),
                        })
                    except ValueError:
                        pass
        finally:
            db.close()

        # Filtruj urzadzenia wg wybranej sieci
        if net_filter:
            for p in list(port_devices.keys()):
                port_devices[p] = [d for d in port_devices[p] if _in_net(d["ip"], net_filter)]
                if not port_devices[p]:
                    del port_devices[p]

        # Sortuj urzadzenia w kazdym porcie: aktywne pierwsze, potem po IP
        for p in port_devices:
            port_devices[p].sort(key=lambda d: (not d["is_active"], d["ip"]))

        return render_template(
            "kb_ports.html",
            entries=entries,
            categories=PORT_CATEGORIES,
            search=search,
            cat_filter=cat_filter,
            risk_filter=risk_filter,
            ot_filter=ot_filter,
            net_filter=net_filter,
            total=len(PORT_KB),
            port_devices=port_devices,
            known_networks=known_networks_kb,
        )

    @app.route("/kb/ports/accept", methods=["POST"])
    def kb_port_accept():
        """Akceptacja ryzyka dla konkretnego portu na konkretnym urzadzeniu."""
        from netdoc.storage.models import PortAcceptance
        device_id = request.form.get("device_id", type=int)
        port      = request.form.get("port", type=int)
        reason    = request.form.get("reason", "").strip()
        if not device_id or not port:
            flash("Nieprawidłowe parametry.", "danger")
            return redirect(request.referrer or url_for("kb_ports"))
        db = SessionLocal()
        try:
            existing = db.query(PortAcceptance).filter_by(
                device_id=device_id, port=port).first()
            if existing:
                existing.reason = reason
                from datetime import datetime as _dt
                existing.accepted_at = _dt.utcnow()
            else:
                db.add(PortAcceptance(device_id=device_id, port=port, reason=reason))
            db.commit()
            flash(f"Port {port} na urządzeniu zaakceptowany.", "success")
        except Exception as e:
            db.rollback()
            flash(f"Błąd zapisu: {e}", "danger")
        finally:
            db.close()
        return redirect(request.referrer or url_for("kb_ports"))

    @app.route("/kb/ports/revoke", methods=["POST"])
    def kb_port_revoke():
        """Cofnięcie akceptacji ryzyka dla portu na urządzeniu."""
        from netdoc.storage.models import PortAcceptance
        device_id = request.form.get("device_id", type=int)
        port      = request.form.get("port", type=int)
        if not device_id or not port:
            flash("Nieprawidłowe parametry.", "danger")
            return redirect(request.referrer or url_for("kb_ports"))
        db = SessionLocal()
        try:
            db.query(PortAcceptance).filter_by(
                device_id=device_id, port=port).delete()
            db.commit()
            flash(f"Akceptacja portu {port} cofnięta.", "info")
        except Exception as e:
            db.rollback()
            flash(f"Błąd: {e}", "danger")
        finally:
            db.close()
        return redirect(request.referrer or url_for("kb_ports"))

    @app.route("/security")
    def security():
        from collections import Counter
        from datetime import datetime as dt
        from sqlalchemy import case as _case
        db = SessionLocal()
        try:
            from netdoc.storage.models import Vulnerability, Device
            _sev_order = _case(
                (Vulnerability.severity == "critical", 0),
                (Vulnerability.severity == "high", 1),
                (Vulnerability.severity == "medium", 2),
                (Vulnerability.severity == "low", 3),
                else_=4,
            )
            from datetime import datetime as _dt2, timedelta as _td
            _closed_cutoff = _dt2.utcnow() - _td(days=30)
            rows = (db.query(Vulnerability, Device)
                      .join(Device, Vulnerability.device_id == Device.id)
                      .filter(
                          (Vulnerability.is_open.is_(True)) |
                          (Vulnerability.suppressed.is_(True)) |
                          (Vulnerability.last_seen >= _closed_cutoff)
                      )
                      .order_by(_sev_order, Vulnerability.last_seen.desc())
                      .all())
            cred_rows = (db.query(Credential, Device)
                           .join(Device, Credential.device_id == Device.id)
                           .filter(Credential.last_success_at.isnot(None))
                           .order_by(Credential.last_success_at.desc())
                           .all())
            _ve_row = db.query(SystemStatus).filter(
                SystemStatus.key == "vuln_scanning_enabled"
            ).first()
            vuln_scanning_enabled = (_ve_row.value if _ve_row else "0") != "0"
        finally:
            db.close()

        class VulnRow:
            def __init__(self, v, d):
                self.id = v.id
                self.vuln_type = getattr(v.vuln_type, 'value', str(v.vuln_type))
                self.severity = getattr(v.severity, 'value', str(v.severity))
                self.title = v.title
                self.port = v.port
                self.evidence = v.evidence
                self.is_open = v.is_open
                self.first_seen = v.first_seen
                self.last_seen = v.last_seen
                self.device_ip = d.ip
                self.device_type = getattr(d.device_type, 'value', str(d.device_type))
                self.suppressed = getattr(v, 'suppressed', False)
                self.device_active = d.is_active

        class CredRow:
            def __init__(self, c, d):
                self.method = c.method if isinstance(c.method, str) else c.method.value
                self.username = c.username
                self.last_success_at = c.last_success_at
                self.device_ip = d.ip
                self.device_type = d.device_type if isinstance(d.device_type, str) else d.device_type.value

        vuln_list = [VulnRow(v, d) for v, d in rows]
        open_vulns = [v for v in vuln_list if v.is_open and not v.suppressed]
        suppressed_vulns = [v for v in vuln_list if v.suppressed]
        closed_vulns = [v for v in vuln_list if not v.is_open and not v.suppressed]
        working_creds = [CredRow(c, d) for c, d in cred_rows]

        summary = Counter(v.severity for v in open_vulns)

        type_counter = Counter(v.vuln_type for v in open_vulns)
        vuln_type_counts = sorted(type_counter.items(), key=lambda x: -x[1])

        # Wazuh data — loaded from alerts.json (mounted volume) + REST API
        from netdoc.integrations.wazuh_alerts import (
            get_recent_alerts, get_wazuh_api_config, get_agents, alerts_file_available,
        )
        db2 = SessionLocal()
        try:
            wazuh_api_cfg = get_wazuh_api_config(db2)
            wazuh_agents  = get_agents(wazuh_api_cfg) if wazuh_api_cfg else []
        except Exception:
            wazuh_api_cfg = None
            wazuh_agents  = []
        finally:
            db2.close()
        # Only load file alerts when Wazuh is enabled — respects the UI toggle.
        wazuh_file_ok     = alerts_file_available() if wazuh_api_cfg is not None else False
        wazuh_alerts_list = get_recent_alerts(since_hours=24, limit=150) if wazuh_file_ok else []

        return render_template(
            "security.html",
            open_vulns=open_vulns,
            closed_vulns=closed_vulns,
            suppressed_vulns=suppressed_vulns,
            working_creds=working_creds,
            vuln_scanning_enabled=vuln_scanning_enabled,
            vuln_hints=_VULN_HINTS,
            summary=summary,
            vuln_type_counts=vuln_type_counts,
            now=dt.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            wazuh_alerts=wazuh_alerts_list,
            wazuh_agents=wazuh_agents,
            wazuh_enabled=wazuh_api_cfg is not None,
            wazuh_file_ok=wazuh_file_ok,
        )

    @app.route("/security/<int:vuln_id>/suppress", methods=["POST"])
    def security_suppress(vuln_id):
        _, err = _api("patch", f"/api/vulnerabilities/{vuln_id}/suppress")
        if err:
            flash(f"Blad: {err}", "danger")
        else:
            flash(f"Podatnosc #{vuln_id} zaakceptowana jako znane ryzyko.", "warning")
        return redirect(url_for("security"))

    @app.route("/security/<int:vuln_id>/unsuppress", methods=["POST"])
    def security_unsuppress(vuln_id):
        _, err = _api("patch", f"/api/vulnerabilities/{vuln_id}/unsuppress")
        if err:
            flash(f"Blad: {err}", "danger")
        else:
            flash(f"Podatnosc #{vuln_id} cofnieta z akceptacji.", "info")
        return redirect(url_for("security"))

    @app.route("/security/unsuppress-all", methods=["POST"])
    def security_unsuppress_all():
        data, err = _api("patch", "/api/vulnerabilities/unsuppress-all")
        if err:
            flash(f"Blad: {err}", "danger")
        else:
            count = (data or {}).get("unsuppressed", "?")
            flash(f"Cofnieto akceptacje ryzyka dla {count} podatnosci.", "info")
        return redirect(url_for("security"))

    @app.route("/security/<int:vuln_id>/close", methods=["POST"])
    def security_close(vuln_id):
        _, err = _api("patch", f"/api/vulnerabilities/{vuln_id}/close")
        if err:
            flash(f"Blad: {err}", "danger")
        else:
            flash(f"Podatnosc #{vuln_id} zamknieta.", "success")
        return redirect(url_for("security"))

    @app.route("/security/vuln-scan-toggle", methods=["POST"])
    def vuln_scan_toggle():
        """Włącz/wyłącz skanowanie podatności (vuln_scanning_enabled) i wróć do referrera."""
        db = SessionLocal()
        try:
            row = db.query(SystemStatus).filter(
                SystemStatus.key == "vuln_scanning_enabled",
                SystemStatus.category == "config",
            ).first()
            if not row:
                row = SystemStatus(key="vuln_scanning_enabled", category="config", value="0")
                db.add(row)
            row.value = "0" if row.value != "0" else "1"
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
        return redirect(request.referrer or "/security")

    # -- Diagnostics alerts page -----------------------------------------------
    @app.route("/alerts")
    def alerts_page():
        """Strona sieciowych alertów diagnostycznych (CPU, pamięć, błędy portów)."""
        from netdoc.storage.models import DevicePortAlert
        db = SessionLocal()
        try:
            rows = (
                db.query(DevicePortAlert, Device)
                .join(Device, DevicePortAlert.device_id == Device.id)
                .filter(DevicePortAlert.acknowledged_at.is_(None))
                .order_by(
                    DevicePortAlert.severity.desc(),
                    DevicePortAlert.last_seen.desc(),
                )
                .all()
            )
            alerts = [
                {
                    "id":             a.id,
                    "device_id":      a.device_id,
                    "device_name":    dev.hostname or str(dev.ip),
                    "device_ip":      str(dev.ip),
                    "if_index":       a.if_index,
                    "interface_name": a.interface_name,
                    "alert_type":     a.alert_type,
                    "severity":       a.severity,
                    "value_current":  a.value_current,
                    "value_baseline": a.value_baseline,
                    "trend_pct":      a.trend_pct,
                    "first_seen":     a.first_seen,
                    "last_seen":      a.last_seen,
                }
                for a, dev in rows
            ]
        finally:
            db.close()
        return render_template("alerts.html", alerts=alerts)

    @app.route("/alerts/<int:alert_id>/ack", methods=["POST"])
    def alert_ack(alert_id):
        """Potwierdza alert i wraca do /alerts."""
        from netdoc.storage.models import DevicePortAlert
        db = SessionLocal()
        try:
            a = db.query(DevicePortAlert).filter_by(id=alert_id).first()
            if a:
                from datetime import datetime as _dt
                a.acknowledged_at = _dt.utcnow()
                db.commit()
        finally:
            db.close()
        return redirect(url_for("alerts_page"))

    # -- threats encyclopedia ---------------------------------------------------
    @app.route("/threats")
    def threats():
        from ipaddress import ip_network, ip_address as ip_addr
        from netdoc.storage.models import Vulnerability as VulnModel

        db = SessionLocal()
        try:
            networks = (
                db.query(DiscoveredNetwork)
                .order_by(DiscoveredNetwork.cidr)
                .all()
            )
            # Aktywne zagrożenia: pełne dane urzadzen (do listy na kartach + filtru sieci)
            open_vulns = (
                db.query(
                    VulnModel.vuln_type,
                    VulnModel.suppressed,
                    VulnModel.evidence,
                    Device.id,
                    Device.ip,
                    Device.hostname,
                    Device.is_active,
                )
                .join(Device, VulnModel.device_id == Device.id)
                .filter(VulnModel.is_open.is_(True))
                .order_by(Device.hostname, Device.ip)
                .all()
            )
        finally:
            db.close()

        # Buduj mape: vuln_type_id -> lista urzadzen z tym zagrozeniem
        threat_devices: dict[str, list[dict]] = {}
        for row in open_vulns:
            vtype_val = row.vuln_type.value if hasattr(row.vuln_type, "value") else str(row.vuln_type)
            threat_devices.setdefault(vtype_val, []).append({
                "id":         row.id,
                "ip":         row.ip,
                "hostname":   row.hostname,
                "is_active":  row.is_active,
                "suppressed": row.suppressed,
                "evidence":   row.evidence,
            })

        # Buduj mape: net.cidr -> lista id zagrozen aktywnych w tej sieci (bez suppressed)
        active_by_net: dict[str, list[str]] = {}
        for net in networks:
            try:
                net_cidr = ip_network(net.cidr, strict=False)
            except ValueError:
                continue
            types_here: set[str] = set()
            for row in open_vulns:
                if row.suppressed:
                    continue
                try:
                    if ip_addr(row.ip) in net_cidr:
                        types_here.add(row.vuln_type.value if hasattr(row.vuln_type, "value") else str(row.vuln_type))
                except ValueError:
                    pass
            active_by_net[net.cidr] = sorted(types_here)

        VULN_CATALOG = [
            {
                "id": "default_credentials",
                "title": "Domyslne hasla (Default Credentials)",
                "severity": "critical",
                "icon": "bi-key-fill",
                "short": "Urzadzenie loguje sie na domyslnym loginie i hasle producenta.",
                "why": (
                    "Kazde urzadzenie sieciowe wychodzi z fabryki z ustawionym haslem domyslnym "
                    "(np. admin/admin, cisco/cisco, root/root). Listy takich hasel sa publicznie dostepne. "
                    "Atakujacy skanujacy siec automatycznie probuje te kombinacje i w ciagu sekund uzyskuje "
                    "pelny dostep do urzadzenia bez zadnej specjalistycznej wiedzy."
                ),
                "impact": "Pelna kontrola nad urzadzeniem, mozliwosc podsluchania ruchu sieciowego, pivot do innych systemow.",
                "fix": "Zmien haslo na unikalne, silne (min. 12 znakow). Wylacz konta, ktorych nie uzywasz.",
                "cvss": "9.8",
            },
            {
                "id": "open_telnet",
                "title": "Telnet dostepny (port 23)",
                "severity": "high",
                "icon": "bi-terminal-fill",
                "short": "Urzadzenie udostepnia zarzadzanie przez Telnet - protokol bez szyfrowania.",
                "why": (
                    "Telnet przesyla wszystkie dane - w tym login i haslo - jako czysty tekst. "
                    "Kazda osoba w tej samej sieci moze uruchomiac sniffing (np. Wireshark) i odczytac "
                    "Twoje haslo w ciagu sekund. Telnet zostal zastapiony przez SSH w 1995 roku."
                ),
                "impact": "Przechwycenie hasla administratora przez kogokolwiek w sieci lokalnej lub na trasie pakietow.",
                "fix": "Wylacz Telnet, wlacz SSH. W Cisco: no service telnet, line vty 0 4 / transport input ssh.",
                "cvss": "7.5",
            },
            {
                "id": "anonymous_ftp",
                "title": "FTP anonimowy (Anonymous FTP)",
                "severity": "high",
                "icon": "bi-folder-x",
                "short": "Serwer FTP przyjmuje polaczenia bez zadnego hasla (login: anonymous).",
                "why": (
                    "FTP bez uwierzytelnienia pozwala kazdemu pobierac lub wgrywac pliki na serwer. "
                    "Dodatkowo FTP nie szyfruje danych. Anonimowe FTP bylo popularne w latach 90. "
                    "Dzisiaj jest bledem konfiguracji."
                ),
                "impact": "Wyciek poufnych plikow, mozliwosc wgrania zlosliwego oprogramowania.",
                "fix": "Wylacz anonimowy dostep FTP. Zamiast FTP uzyj SFTP (SSH) lub HTTPS z uwierzytelnieniem.",
                "cvss": "7.5",
            },
            {
                "id": "open_ftp",
                "title": "FTP niezaszyfrowany (port 21)",
                "severity": "medium",
                "icon": "bi-arrow-left-right",
                "short": "Serwer FTP dziala bez szyfrowania - hasla i pliki widoczne w sieci.",
                "why": (
                    "Standardowy FTP (port 21) przesyla hasla i dane jako czysty tekst. "
                    "Nawet jesli haslo jest wymagane, moze byc przechwycone przez sniffing. "
                    "FTPS i SFTP sa bezpiecznymi alternatywami."
                ),
                "impact": "Przechwycenie hasel i plikow przez osobe monitorujaca siec.",
                "fix": "Przejdz na SFTP (port 22, przez SSH) lub FTPS (FTP z TLS). Wylacz zwykly FTP jesli nieuzywany.",
                "cvss": "5.9",
            },
            {
                "id": "snmp_public",
                "title": "SNMP z community public",
                "severity": "medium",
                "icon": "bi-broadcast",
                "short": "Urzadzenie odpowiada na SNMP z domyslna nazwa spolecznosci public.",
                "why": (
                    "SNMP (Simple Network Management Protocol) sluzy do monitorowania urzadzen. "
                    "Community string to rodzaj hasla. Domyslna wartosc public jest znana wszystkim - "
                    "pozwala odczytac pelna konfiguracje urzadzenia: tabele routingu, listy interfejsow, "
                    "statystyki, a przy SNMPv1/v2c nawet modyfikowac ustawienia. "
                    "Dane sa przesylane bez szyfrowania."
                ),
                "impact": "Ujawnienie topologii sieci, konfiguracji i statystyk; mozliwosc zmiany konfiguracji (SNMPv2c write).",
                "fix": "Zmien community string na losowy ciag znakow. Ogranicz SNMP do konkretnych IP. Rozważ SNMPv3 z szyfrowaniem.",
                "cvss": "5.3",
            },
            {
                "id": "mqtt_noauth",
                "title": "MQTT bez uwierzytelnienia (port 1883)",
                "severity": "high",
                "icon": "bi-wifi",
                "short": "Broker MQTT akceptuje polaczenia bez loginu i hasla.",
                "why": (
                    "MQTT to protokol uzywany w IoT (czujniki, inteligentny dom, systemy przemyslowe). "
                    "Broker bez uwierzytelnienia pozwala kazdemu subskrybowac WSZYSTKIE tematy "
                    "i publikowac falszywe dane - np. falszywe odczyty czujnikow lub komendy sterujace urzadzeniami."
                ),
                "impact": "Przechwycenie danych IoT, sterowanie urzadzeniami (zamki, klimatyzacja, systemy przemyslowe).",
                "fix": "Wlacz uwierzytelnienie (username/password) w konfiguracji brokera. Rozważ TLS (port 8883) i ACL.",
                "cvss": "8.1",
            },
            {
                "id": "redis_noauth",
                "title": "Redis bez hasla (port 6379)",
                "severity": "critical",
                "icon": "bi-database-fill-x",
                "short": "Baza danych Redis dostepna bez uwierzytelnienia.",
                "why": (
                    "Redis to baza danych uzywana jako cache, kolejka zadan i przechowywanie sesji. "
                    "Bez hasla kazdy ma pelny dostep: moze odczytac wszystkie dane, wgrac klucz SSH "
                    "i uzyskac shell na serwerze, lub ustawic cron job. "
                    "Podatnosc ta jest masowo wykorzystywana przez botnety."
                ),
                "impact": "Pelny dostep do danych, Remote Code Execution (RCE) poprzez zapis klucza SSH lub cron.",
                "fix": "Ustaw haslo (requirepass w redis.conf). Ogranicz Redis do localhost. Wylacz niebezpieczne komendy (FLUSHALL, CONFIG).",
                "cvss": "9.8",
            },
            {
                "id": "elasticsearch_noauth",
                "title": "Elasticsearch bez uwierzytelnienia (port 9200)",
                "severity": "critical",
                "icon": "bi-search",
                "short": "Klaster Elasticsearch dostepny bez hasla - pelny dostep do danych.",
                "why": (
                    "Elasticsearch przechowuje czesto miliony rekordow: logi, dane uzytkownikow, "
                    "informacje medyczne, finansowe. Bez uwierzytelnienia kazdy moze pobrac, zmodyfikowac "
                    "lub usunac wszystkie dane. Tysiace baz zostalo wyczyszczonych przez atakujacych "
                    "zadajacych okupu za przywrocenie."
                ),
                "impact": "Masowy wyciek danych, zniszczenie indeksow, okup (ransomware na bazie danych).",
                "fix": "Wlacz X-Pack Security (darmowe od Elasticsearch 6.8). Ustaw hasla i ogranicz dostep przez firewall.",
                "cvss": "9.8",
            },
            {
                "id": "docker_api_exposed",
                "title": "Docker API dostepny sieciowo (port 2375/2376)",
                "severity": "critical",
                "icon": "bi-box-fill",
                "short": "Docker daemon nasluchuje na porcie sieciowym - mozliwy RCE i eskalacja uprawnien.",
                "why": (
                    "Docker API pozwala tworzyc i uruchamiac kontenery. Dostep do API = dostep do hosta. "
                    "Atakujacy uruchamia kontener z zamontowanym katalogiem glownym hosta i uzyskuje "
                    "pelny dostep do systemu plikow - kluczy SSH, hasel i konfiguracji. "
                    "To jedna z najpopularniejszych technik eskalacji uprawnien w srodowiskach chmurowych."
                ),
                "impact": "Pelna kontrola nad hostem, kradzież danych, instalacja malware, pivot do sieci wewnetrznej.",
                "fix": "Nie udostepniaj Docker API na interfejsie sieciowym bez TLS i mTLS. Uzywaj Docker socket lokalnie lub przez SSH.",
                "cvss": "9.8",
            },
            {
                "id": "http_management",
                "title": "Panel zarzadzania przez HTTP (niezaszyfrowany)",
                "severity": "medium",
                "icon": "bi-globe",
                "short": "Interfejs webowy urzadzenia dostepny przez HTTP zamiast HTTPS.",
                "why": (
                    "HTTP przesyla hasla i ciasteczka sesji jako czysty tekst. "
                    "Ktos w tej samej sieci (np. pracownik, klient WiFi) moze przechwycic "
                    "haslo do panelu administracyjnego routera, switcha lub kamery "
                    "uzywajac prostego sniffera."
                ),
                "impact": "Przechwycenie hasla administratora, przejecie kontroli nad urzadzeniem.",
                "fix": "Wlacz HTTPS z waznym certyfikatem. Wylacz HTTP lub przekieruj automatycznie na HTTPS. Ogranicz dostep do sieci zarzadzania.",
                "cvss": "6.5",
            },
            {
                "id": "ssl_expired",
                "title": "Certyfikat SSL/TLS wygasl",
                "severity": "medium",
                "icon": "bi-calendar-x",
                "short": "Certyfikat bezpieczenstwa strony lub uslugi wygasl.",
                "why": (
                    "Wygasly certyfikat to sygnal dla przegladarek i klientow, ze polaczenie "
                    "moze byc niebezpieczne. Uzytkownicy ignorujacy ostrzezenia sa podatni na "
                    "ataki man-in-the-middle. Automatyczne systemy czesto odmawiaja polaczenia "
                    "z wygaslym certyfikatem, powodujac awarie uslug."
                ),
                "impact": "Ostrzezenia bezpieczenstwa dla uzytkownikow, mozliwe ataki MITM, awarie automatycznych systemow.",
                "fix": "Odnow certyfikat. Rozważ uzycie automatycznego odnawiania (Let Encrypt, ACME).",
                "cvss": "5.3",
            },
            {
                "id": "ssl_self_signed",
                "title": "Certyfikat SSL/TLS samopodpisany",
                "severity": "low",
                "icon": "bi-patch-question",
                "short": "Usluga uzywa certyfikatu wystawionego przez siebie, a nie zaufany urzad.",
                "why": (
                    "Certyfikaty samopodpisane nie sa weryfikowane przez zadna zaufana instytucje. "
                    "Uzytkownik nie ma pewnosci, czy laczy sie z prawdziwym serwerem - atakujacy "
                    "moze podstawic wlasny certyfikat samopodpisany i przejac polaczenie. "
                    "Przegladarki pokazuja ostrzezenie o braku prywatnosci polaczenia."
                ),
                "impact": "Mozliwy atak man-in-the-middle, brak pewnosci co do tozsamosci serwera.",
                "fix": "Zastap certyfikatem od zaufanego CA (np. Let Encrypt, DigiCert). W sieci wewnetrznej uzyj Enterprise PKI.",
                "cvss": "3.7",
            },
            {
                "id": "ipmi_exposed",
                "title": "IPMI/BMC dostepny sieciowo (port 623)",
                "severity": "critical",
                "icon": "bi-cpu-fill",
                "short": "Interfejs zarzadzania serwerem (IPMI/BMC) dostepny z sieci.",
                "why": (
                    "IPMI (Intelligent Platform Management Interface) pozwala zarzadzac serwerem "
                    "na poziomie sprzetu - nawet gdy system operacyjny jest wylaczony. "
                    "Znane podatnosci pozwalaja zlamac haslo bez znajomosci starego hasla. "
                    "Dostep do IPMI = pelna kontrola nad fizycznym serwerem, mozliwosc "
                    "instalacji implantow na poziomie firmware."
                ),
                "impact": "Pelna kontrola nad sprzetem, dostep do pamieci RAM i dyskow, mozliwosc trwalego implantowania malware.",
                "fix": "Ogranicz dostep IPMI/BMC do dedykowanej sieci zarzadzania (VLAN OOB). Wymagaj silnego hasla. Aktualizuj firmware BMC.",
                "cvss": "9.8",
            },
            {
                "id": "rdp_exposed",
                "title": "RDP dostepny bez VPN (port 3389)",
                "severity": "high",
                "icon": "bi-display",
                "short": "Pulpit zdalny Windows (RDP) dostepny bezposrednio z sieci.",
                "why": (
                    "RDP (Remote Desktop Protocol) to jeden z najczesciej atakowanych protokolow w internecie. "
                    "Atakujacy uzywaja technik brute-force i slownikowych, by zgadnac haslo. "
                    "Znane podatnosci jak BlueKeep (CVE-2019-0708) pozwolily na kompromitacje "
                    "setek tysiecy systemow bez znajomosci hasla. "
                    "Kazdego dnia skanowane sa miliardy adresow IP w poszukiwaniu portu 3389."
                ),
                "impact": "Przechwycenie kontroli nad komputerem, instalacja ransomware, kradzież danych, pivot do sieci korporacyjnej.",
                "fix": "Ukryj RDP za VPN. Wlacz NLA (Network Level Authentication). Wlacz 2FA dla RDP.",
                "cvss": "8.1",
            },
            {
                "id": "vnc_noauth",
                "title": "VNC bez hasla (port 5900)",
                "severity": "critical",
                "icon": "bi-display-fill",
                "short": "Pulpit zdalny VNC dostepny bez zadnego hasla.",
                "why": (
                    "VNC (Virtual Network Computing) to protokol zdalnego pulpitu. "
                    "Jezeli serwer VNC ma ustawiony SecurityType.None (typ 1), kazdy "
                    "moze polaczyc sie i przejac pelna kontrole nad ekranem, myszka "
                    "i klawiatura. Popularny na kamerach IP z panelem podgladu, "
                    "maszynach wirtualnych i starszych systemach przemyslowych (HMI)."
                ),
                "impact": "Pelna kontrola nad pulpitem zdalnym - widok ekranu, wykonywanie komend, kradzież hasel.",
                "fix": "Ustaw silne haslo VNC lub wylacz VNC i uzyj SSH/RDP z VPN. W NX/TigerVNC: configure security type VncAuth.",
                "cvss": "9.8",
            },
            {
                "id": "mongo_noauth",
                "title": "MongoDB bez uwierzytelnienia (port 27017)",
                "severity": "critical",
                "icon": "bi-database-fill-x",
                "short": "Baza danych MongoDB dostepna bez hasla - pelny dostep do wszystkich kolekcji.",
                "why": (
                    "MongoDB domyslnie startuje bez uwierzytelnienia (--noauth). "
                    "Kazdy w sieci moze polaczyc sie i wykonac dowolne zapytania: "
                    "odczytac, zmodyfikowac lub usunac wszystkie dane. "
                    "To jeden z najczestszych wyciekow danych - miliony rekordow "
                    "medycznych, bankowych i osobowych zostalo skompromitowanych "
                    "przez MongoDB bez auth. Ransomware automatycznie skanuje i "
                    "czysci bazy zadajac okupu."
                ),
                "impact": "Pelny dostep do danych, usuniecie baz, okup (ransomware), wyciek danych osobowych.",
                "fix": "Uruchom MongoDB z --auth lub security.authorization: enabled. Dodaj uzytkownika administratora przed wlaczeniem auth.",
                "cvss": "9.8",
            },
            {
                "id": "rtsp_noauth",
                "title": "Kamera IP bez uwierzytelnienia RTSP (port 554)",
                "severity": "high",
                "icon": "bi-camera-video-fill",
                "short": "Strumien wideo z kamery dostepny bez loginu i hasla.",
                "why": (
                    "RTSP (Real Time Streaming Protocol) to standard transmisji wideo "
                    "z kamer IP. Jezeli kamera nie wymaga hasla, kazdy w sieci moze "
                    "ogladac i nagrywac obraz na zywo. Forescout 2025 wykryl ponad "
                    "40 000 kamer dostepnych publicznie bez zadnej ochrony. "
                    "Dotyczy to kamer parkingowych, biurowych, produkcyjnych i domowych."
                ),
                "impact": "Podglad i nagrywanie obrazu z kamer, naruszenie prywatnosci, szpiegostwo przemyslowe.",
                "fix": "Wlacz uwierzytelnienie RTSP w konfiguracji kamery. Zmien domyslne haslo admin. Ogranicz dostep do sieci kamer oddzielnym VLAN.",
                "cvss": "7.5",
            },
            {
                "id": "modbus_exposed",
                "title": "Modbus TCP bez auth (port 502)",
                "severity": "critical",
                "icon": "bi-lightning-charge-fill",
                "short": "Protokol przemyslowy Modbus dostepny bez uwierzytelnienia.",
                "why": (
                    "Modbus TCP to protokol komunikacji z urzadzeniami przemyslowymi: "
                    "inverterami PV, UPS, falownikami, PLC i sterownikami. "
                    "Protokol nie ma wbudowanego mechanizmu uwierzytelnienia ani szyfrowania. "
                    "Dostep bez firewalla pozwala odczytywac dane produkcyjne i moc "
                    "zmienianie parametrow pracy urzadzen - np. wylaczenie falownika "
                    "lub zmiane napiecia w UPS."
                ),
                "impact": "Odczyt i zapis parametrow urzadzenia przemyslowego, wylaczenie zasilania, uszkodzenie sprzetu.",
                "fix": "Ogranicz dostep do portu 502 przez firewall - tylko z systemow SCADA/monitoring. Uzyj VPN lub segmentacji sieci OT/IT.",
                "cvss": "9.1",
            },
            {
                "id": "mysql_noauth",
                "title": "MySQL bez hasla root (port 3306)",
                "severity": "critical",
                "icon": "bi-table",
                "short": "Serwer bazy danych MySQL dostepny bez hasla dla konta root.",
                "why": (
                    "MySQL z pustym haslem roota to jeden z najczestszych bleow "
                    "konfiguracyjnych - domyslna instalacja na wielu systemach "
                    "Linux nie wymaga ustawienia hasla. Konto root ma pelny dostep "
                    "do wszystkich baz, tabel i plikow. Atakujacy moze odczytac "
                    "wszystkie dane, usunac tabele lub uzyc MySQL do wykonania "
                    "komend systemowych (SELECT ... INTO OUTFILE, UDF exploitation)."
                ),
                "impact": "Pelny dostep do wszystkich baz danych, mozliwosc zapisu plikow na serwerze, eskalacja do Remote Code Execution.",
                "fix": "Ustaw haslo roota: ALTER USER root@localhost IDENTIFIED BY silne_haslo. Ogranicz dostep do 3306 przez firewall. Nie udostepniaj MySQL publicznie.",
                "cvss": "9.8",
            },
            {
                "id": "postgres_weak_creds",
                "title": "PostgreSQL slabe haslo (port 5432)",
                "severity": "critical",
                "icon": "bi-database-fill-exclamation",
                "short": "Serwer PostgreSQL dostepny z domyslnymi lub slabymi poswiadczeniami.",
                "why": (
                    "PostgreSQL to jedna z najpopularniejszych baz danych. "
                    "Domyslna instalacja czesto tworzy uzytkownika postgres z pustym lub oczywistym haslem. "
                    "Atakujacy probujacy kombinacji postgres/postgres, postgres/password i podobnych "
                    "w ciagu sekund moze uzyskac pelny dostep do wszystkich baz. "
                    "psycopg2 i inne biblioteki pozwalaja na automatyzacje takich prob."
                ),
                "impact": "Pelny dostep do wszystkich baz danych, eskalacja do Remote Code Execution (pg_exec, COPY TO/FROM PROGRAM).",
                "fix": "Ustaw silne haslo: ALTER USER postgres PASSWORD silne_haslo. Ogranicz pg_hba.conf do lokalnego dostepu. Blokuj port 5432 na firewall.",
                "cvss": "9.8",
            },
            {
                "id": "mssql_weak_creds",
                "title": "MSSQL slabe haslo konta sa (port 1433)",
                "severity": "critical",
                "icon": "bi-server",
                "short": "SQL Server z pustym lub slabym haslem dla konta administratora sa.",
                "why": (
                    "Microsoft SQL Server domyslnie tworzy konto sa (System Administrator) "
                    "z pustym haslem lub haslem ustawionym na czas instalacji, ktore bywa proste. "
                    "Konto sa ma pelne uprawnienia do systemu baz danych oraz - przez xp_cmdshell - "
                    "do wykonywania komend systemowych. To jedna z najczesciej atakowanych baz danych "
                    "w sieciach korporacyjnych."
                ),
                "impact": "Pelny dostep do baz danych, Remote Code Execution przez xp_cmdshell, eskalacja uprawnien systemowych.",
                "fix": "Ustaw silne haslo dla konta sa lub wylacz je. Wlacz uwierzytelnienie Windows. Blokuj port 1433 na firewall zewnetrznym.",
                "cvss": "9.8",
            },
            {
                "id": "vnc_weak_creds",
                "title": "VNC slabe haslo VncAuth (port 5900)",
                "severity": "critical",
                "icon": "bi-display-fill",
                "short": "Serwer VNC zabezpieczony haslem, ale haslo jest trywialne do zlamania.",
                "why": (
                    "VNC z wlaczonym uwierzytelnieniem VncAuth wymaga hasla, ale wiele urzadzen "
                    "ma ustawione proste hasla: 1234, password, admin, raspberry (Raspberry Pi). "
                    "Protokol VNC nie ogranicza liczby prób, wiec atakujacy moze sprawdzac "
                    "tysiac hasel na sekunde. Pelna lista popularnych hasel VNC jest publicznie znana."
                ),
                "impact": "Pelna kontrola nad pulpitem zdalnym - jak przy VNC bez hasla, tyle ze wymaga proby kilku kombinacji.",
                "fix": "Ustaw unikalne silne haslo VNC (min. 12 znakow, losowe). Lub zastap VNC tunelem SSH z kluczem.",
                "cvss": "9.8",
            },
            {
                "id": "couchdb_noauth",
                "title": "CouchDB bez uwierzytelnienia (port 5984)",
                "severity": "critical",
                "icon": "bi-database-fill-x",
                "short": "Baza danych CouchDB dostepna bez loginu - pelny dostep przez HTTP API.",
                "why": (
                    "CouchDB to baza dokumentowa z interfejsem HTTP REST. "
                    "Bez wlaczonego uwierzytelnienia kazdy moze wykonywac zapytania GET/POST/DELETE "
                    "do wszystkich baz przez przegladarke lub curl. "
                    "W 2017 roku masowe skanowanie Shodan ujawnilo ponad 4000 otwartych instancji CouchDB - "
                    "atakujacy automatycznie czyscili bazy i zostawiali noty z zadaniem okupu."
                ),
                "impact": "Pelny dostep do wszystkich dokumentow, usuniecie baz, wyciek danych, okup (ransomware na bazie).",
                "fix": "Wlacz uwierzytelnienie CouchDB: skonfiguruj administratora przez Fauxton lub HTTP API. Blokuj port 5984 na firewall.",
                "cvss": "9.8",
            },
            {
                "id": "memcached_exposed",
                "title": "Memcached bez uwierzytelnienia (port 11211)",
                "severity": "high",
                "icon": "bi-lightning-fill",
                "short": "Serwer cache Memcached dostepny bez uwierzytelnienia - wyciek danych i amplifikacja DDoS.",
                "why": (
                    "Memcached to szybki system cache uzywany przez strony www do przechowywania sesji, "
                    "tokenow i fragmentow stron. Protokol nie ma wbudowanego uwierzytelnienia. "
                    "Atakujacy moze odczytac wszystkie klucze cache (sesje uzytkownikow, tokeny API). "
                    "Dodatkowo Memcached UDP (port 11211) byl uzyty do poteznych atakow DDoS amplification "
                    "- atak na GitHub (2018) osiagnal 1.3 Tbps przez otwarte serwery Memcached."
                ),
                "impact": "Wyciek danych sesji i tokenow, mozliwosc przejecia kont uzytkownikow, uzycie jako reflektor DDoS.",
                "fix": "Uruchom Memcached tylko na localhost (--listen 127.0.0.1). Wlacz SASL auth. Blokuj port 11211 na firewall (szczegolnie UDP).",
                "cvss": "7.5",
            },
            {
                "id": "influxdb_noauth",
                "title": "InfluxDB bez uwierzytelnienia (port 8086)",
                "severity": "critical",
                "icon": "bi-graph-up",
                "short": "Baza szeregów czasowych InfluxDB dostepna bez tokenu - pełny dostep do metryk.",
                "why": (
                    "InfluxDB jest powszechnie uzywana w systemach monitoringu (Grafana + InfluxDB + Telegraf). "
                    "Bez uwierzytelnienia kazdy ma dostep do wszystkich measurement: metryk serwera, "
                    "danych produkcyjnych, odczytow czujnikow IoT i historycznych serii czasowych. "
                    "InfluxDB v1 domyslnie nie ma wlaczonego auth, v2 wymaga tokenu - ale oba bywaja "
                    "nieprawidlowo skonfigurowane jako otwarte."
                ),
                "impact": "Dostep do wszystkich metryk i serii czasowych, mozliwosc zapisywania falszyWych danych, wyciek informacji o infrastrukturze.",
                "fix": "InfluxDB v2: wlacz auth w konfiguracji (auth-enabled = true). InfluxDB v1: ustaw token operatora. Blokuj port 8086 na firewall.",
                "cvss": "9.1",
            },
            {
                "id": "cassandra_noauth",
                "title": "Apache Cassandra bez uwierzytelnienia (port 9042)",
                "severity": "critical",
                "icon": "bi-grid-3x3-gap-fill",
                "short": "Klaster bazy danych Cassandra dostepny przez CQL bez uwierzytelnienia.",
                "why": (
                    "Apache Cassandra to rozproszona baza NoSQL uzywana przez Netflix, Twitter i inne "
                    "duze platformy. Domyslna konfiguracja nie wymaga uwierzytelnienia (AllowAllAuthenticator). "
                    "Atakujacy laczacy sie przez port 9042 moze odczytywac i zapisywac dane we wszystkich "
                    "przestrzeniach kluczy bez zadnego hasla. Dotyczy to czesto duzych zbiorow "
                    "danych uzytkownikow lub transakcji."
                ),
                "impact": "Pelny dostep do wszystkich danych we wszystkich keyspace, mozliwosc modyfikacji i usuniecia danych.",
                "fix": "Ustaw authenticator: PasswordAuthenticator i authorizer: CassandraAuthorizer w cassandra.yaml. Zmien domyslne haslo cassandra/cassandra.",
                "cvss": "9.8",
            },
            {
                "id": "rtsp_weak_creds",
                "title": "Kamera IP slabe haslo RTSP (port 554)",
                "severity": "high",
                "icon": "bi-camera-video-fill",
                "short": "Kamera IP wymaga hasla, ale przyjmuje powszechne domyslne poswiadczenia.",
                "why": (
                    "Wiele kamer IP ma wbudowane domyslne haslo: admin/admin, admin/12345, root/root. "
                    "Producenci tacy jak Hikvision, Dahua, Reolink i inne uzywali tych samych hasel "
                    "w milionach urzadzen. Protokol RTSP nie ogranicza liczby prob logowania, "
                    "wiec atakujacy sprawdza kilkanascie hasel w ciagu sekund. "
                    "Masowe botnety (Mirai i jego warianty) skompromitowaly miliony kamer "
                    "uzywajac wlasnie tej metody."
                ),
                "impact": "Podglad i nagrywanie obrazu z kamery, przejecie kontroli nad urzadzeniem, wlaczenie do botnetu.",
                "fix": "Zmien domyslne haslo kamery na unikalne i silne. Ogranicz dostep do sieci kamer oddzielnym VLAN. Wlacz aktualizacje firmware.",
                "cvss": "8.1",
            },
            {
                "id": "onvif_noauth",
                "title": "ONVIF kamera — zarzadzanie bez uwierzytelnienia",
                "severity": "high",
                "icon": "bi-camera-video",
                "short": "Kamera/NVR udostepnia protokol ONVIF bez logowania — pelna kontrola nad urzadzeniem.",
                "why": (
                    "ONVIF (Open Network Video Interface Forum) to standard sterowania kamerami IP: "
                    "PTZ, podglad na zywo, zapis, konfiguracja. Kamera odpowiadajaca na "
                    "GetCapabilities bez uwierzytelnienia ujawnia caly interfejs zarzadzania. "
                    "Atakujacy moze strumieniowac obraz, wgrac firmware, zmieniac hasla i wlaczyc "
                    "karmere do botnetu (Mirai i pochodne celuja wlasnie w ONVIF bez auth)."
                ),
                "impact": "Podglad obrazu na zywo, przejecie kamery, sabotaz nagrywania, rekrutacja do botnetu.",
                "fix": "Wlacz uwierzytelnianie ONVIF (WS-Security). Ogranicz dostep do interfejsu HTTP kamery przez VLAN lub firewall. Zaktualizuj firmware.",
                "cvss": "8.6",
            },
            {
                "id": "mjpeg_noauth",
                "title": "Strumien MJPEG bez logowania",
                "severity": "high",
                "icon": "bi-camera-video-fill",
                "short": "Kamera udostepnia strumien wideo MJPEG przez HTTP bez uwierzytelnienia.",
                "why": (
                    "MJPEG (Motion JPEG) to format streamingu wideo uzywany przez tanie kamery IP, "
                    "kamery w systemach CMS i kamery do monitoringu. Strumien dostepny bez hasla "
                    "oznacza, ze kazdy w sieci moze ogladac transmisje na zywo z pomieszczen "
                    "prywatnych, magazynow, serwerowni lub kas fiskalnych."
                ),
                "impact": "Nieautoryzowany podglad pomieszczen i ludzi, naruszenie prywatnosci, ujawnienie danych biznesowych.",
                "fix": "Wlacz uwierzytelnianie HTTP Basic/Digest na interfejsie webowym kamery. Ogranicz dostep przez VLAN kamer.",
                "cvss": "7.5",
            },
            {
                "id": "rtmp_exposed",
                "title": "Serwer RTMP streaming dostepny (port 1935)",
                "severity": "medium",
                "icon": "bi-broadcast",
                "short": "Serwer RTMP (streaming wideo/audio) dostepny w sieci bez weryfikacji.",
                "why": (
                    "RTMP (Real-Time Messaging Protocol) jest uzywany do streamingu kamer, "
                    "konferencji i nagrywania. Otwarty serwer RTMP moze ujawniac prywatne transmisje "
                    "lub umozliwiac nieautoryzowane streamowanie tresci. "
                    "Serwery RTMP (np. nginx-rtmp) domyslnie akceptuja polaczenia bez auth."
                ),
                "impact": "Podglad prywatnych transmisji wideo/audio, mozliwosc wstrzykniecia strumienia.",
                "fix": "Skonfiguruj uwierzytelnianie na serwerze RTMP (token streaming). Ogranicz dostep firewallem do zaufanych adresow IP.",
                "cvss": "5.3",
            },
            {
                "id": "dahua_dvr_exposed",
                "title": "Dahua DVR/NVR — port 37777 dostepny",
                "severity": "high",
                "icon": "bi-hdd-rack",
                "short": "Rejestrator Dahua nasłuchuje na porcie 37777 (protokol wlascicielski) bez ograniczen dostepu.",
                "why": (
                    "Port 37777 to protokol binarny uzywany przez rejestratory i kamery Dahua "
                    "do zarzadzania, podgladu i pobierania nagrania. Jest aktywnie "
                    "skanowany przez botnety (Mirai, Mozi) i ugrupowania APT. "
                    "Znane exploity umozliwiaja obejscie uwierzytelnienia (CVE-2021-33045)."
                ),
                "impact": "Zdalny dostep do nagrania, live view, zarzadzanie urzadzeniem, mozliwosc RCE przez znane exploity.",
                "fix": "Zablokuj port 37777 na firewallu. Uzyj VPN lub VLAN dla systemu CCTV. Zaktualizuj firmware Dahua.",
                "cvss": "9.1",
            },
            {
                "id": "xmeye_dvr_exposed",
                "title": "XMEye/Sofia DVR — port 34567 dostepny",
                "severity": "high",
                "icon": "bi-hdd-rack-fill",
                "short": "Rejestrator z chipsetem XMEye/Sofia nasłuchuje na porcie 34567 — protokol bez szyfrowania.",
                "why": (
                    "Port 34567 jest uzywany przez setki marek DVR/NVR z chipsetem XMEye/Sofia "
                    "(Annke, Qvis, Raidon, Zmodo i no-name). Protokol jest nieszyfrowany "
                    "i podatny na ataki brute-force. CVE-2017-7577 umozliwia nieuwierzytelniony "
                    "odczyt hasla administratora. Urzadzenia sa masowo skanowane przez botnety."
                ),
                "impact": "Odczyt hasla admina bez logowania, zdalny podglad kamer, rekrutacja do botnetu.",
                "fix": "Zablokuj port 34567 na firewallu. Wyizoluj system CCTV w dedykowanym VLAN bez dostepu do internetu.",
                "cvss": "9.8",
            },
            {
                "id": "unauth_reboot",
                "title": "Restart urzadzenia bez uwierzytelnienia",
                "severity": "critical",
                "icon": "bi-power",
                "short": "Endpoint restartu panelu administracyjnego jest dostepny bez logowania.",
                "why": (
                    "Wiele routerow, AP i urzadzen sieciowych udostepnia endpoint HTTP "
                    "do zdalnego restartu (np. /reboot.cgi, /goform/Reboot). "
                    "Jesli endpoint zwraca HTTP 200 bez naglowka WWW-Authenticate, "
                    "kazdy uzytkownik sieci moze zrestartowac urzadzenie bez znajomosci hasla. "
                    "Atakujacy moze wywolac ciagle restarty paralizujac dostep do sieci (DoS) "
                    "lub zresetowac urzadzenie do ustawien fabrycznych (utrata konfiguracji). "
                    "Czesto wynika z braku ochrony endpointow admin w starszym firmware."
                ),
                "impact": "Zdalny restart/DoS urzadzenia sieciowego bez logowania, potencjalna utrata konfiguracji, przerwa w dostepie do sieci.",
                "fix": "Zaktualizuj firmware urzadzenia. Ogranicz dostep do panelu admin do konkretnych adresow IP. Wlacz uwierzytelnianie HTTP Basic lub formularz logowania dla wszystkich endpointow admin.",
                "cvss": "9.1",
            },
            {
                "id": "tftp_exposed",
                "title": "TFTP dostepny bez uwierzytelnienia (UDP 69)",
                "severity": "high",
                "icon": "bi-file-arrow-up",
                "short": "Serwer TFTP odpowiada na zapytania bez zadnego uwierzytelnienia — dowolny host w sieci moze pobierac i wysylac pliki.",
                "why": (
                    "TFTP (Trivial File Transfer Protocol) zostal zaprojektowany bez mechanizmow autoryzacji. "
                    "Urzadzenia sieciowe (routery, switche, telefony IP, kamery) czesto uruchamiaja serwer TFTP "
                    "do aktualizacji firmware lub backupu konfiguracji. "
                    "Dostepny serwer TFTP umozliwia: pobieranie plikow konfiguracyjnych zawierajacych hasla, "
                    "zastepowanie firmware zlosliwym obrazem, modyfikacje konfiguracji urzadzenia. "
                    "Protokol dziala na UDP (brak nawiazywania polaczenia) — trudniejszy do filtrowania niz TCP."
                ),
                "impact": "Nieautoryzowany dostep do plikow konfiguracyjnych, mozliwosc nadpisania firmware, ujawnienie hasel i kluczy sieci.",
                "fix": "Wylacz usluge TFTP jezeli nie jest wymagana. Ogranicz dostep do TFTP przez ACL/firewall tylko do adresow IP uprawnionych systemow (NMS, serwer backupu). Rozważ uzycie SFTP/SCP zamiast TFTP.",
                "cvss": "7.5",
            },
            {
                "id": "cisco_smart_install",
                "title": "Cisco Smart Install (TCP 4786) — zdalny dostep bez auth",
                "severity": "critical",
                "icon": "bi-cpu",
                "short": "Protokol Cisco Smart Install dostepny bez uwierzytelnienia — atakujacy moze zdalnie przejac konfiguracje switcha i wgrac dowolny firmware (CVE-2018-0171).",
                "why": (
                    "Cisco Smart Install to protokol ulatwiajacy zdalna instalacje i konfiguracje switchow Catalyst. "
                    "Po otwarciu portu TCP 4786 urzadzenie przyjmuje polecenia bez jakiegokolwiek uwierzytelnienia. "
                    "CVE-2018-0171 (CVSS 9.8) pozwala atakujacemu: pobrac lub nadpisac plik konfiguracyjny, "
                    "zmienic haslo enable, uruchomic dowolne polecenia IOS, wgrac zmodyfikowany firmware. "
                    "Skanowanie internetu ujawnilo tysiace niezabezpieczonych switchow Cisco — tata metoda "
                    "przejecia calej infrastruktury sieciowej organizacji."
                ),
                "impact": "Pelne przejecie switcha: zmiana konfiguracji, haseł, firmware. Mozliwosc wejscia do calej sieci VLAN.",
                "fix": "Wylacz Smart Install: 'no vstack' w konfiguracji IOS. Zablokuj port TCP 4786 na firewallu brzegowym. Aktualizuj IOS do wersji z fixem CVE-2018-0171.",
                "cvss": "9.8",
            },
            {
                "id": "cisco_web_exec",
                "title": "Cisco IOS HTTP — zdalne wykonanie polecen bez auth (/exec)",
                "severity": "critical",
                "icon": "bi-terminal-dash",
                "short": "Interfejs HTTP Cisco IOS umozliwia wykonanie polecen CLI z poziomem uprawnien 15 bez uwierzytelnienia przez endpoint /level/15/exec/.",
                "why": (
                    "Stare wersje Cisco IOS udostepnialy web-based command executor dostepny przez HTTP. "
                    "Endpoint /level/15/exec/-/show/version i podobne umozliwialy wykonanie polecen "
                    "z najwyzszym poziomem uprawnien (enable level 15) bez podania hasla. "
                    "Atakujacy moze: odczytac pelna konfiguracje ('show running-config'), "
                    "zmienic hasla i konfiguracje, wylaczyc interfejsy, zebrać dane o calej topologii sieci. "
                    "Blad wynika z braku sprawdzania uprawnien w module HTTP serwera IOS."
                ),
                "impact": "Pelna kontrola nad routerem/switchem: odczyt konfiguracji, haseł, mozliwosc blokowania ruchu sieciowego.",
                "fix": "Wylacz HTTP server: 'no ip http server' oraz 'no ip http secure-server' w konfiguracji IOS. Jesli HTTP jest wymagany, uzyj ip http authentication local i ogranicz dostep przez ACL.",
                "cvss": "9.8",
            },
            {
                "id": "firewall_disabled",
                "title": "Brak lub wylaczony firewall (wiele otwartych portow)",
                "severity": "high",
                "icon": "bi-shield-x",
                "short": "Host ma nadmiernie duzo otwartych portow sieciowych - brak firewalla lub blad konfiguracji.",
                "why": (
                    "Poprawnie skonfigurowany firewall blokuje wszystkie porty poza niezbednymi. "
                    "Jesli stacja robocza, serwer lub urzadzenie IoT odpowiada na dziesiatkach portow "
                    "(FTP, Telnet, RDP, SMB, bazy danych), oznacza to brak firewalla lub reguly "
                    "zezwalajace na wszystko. Atakujacy skanujacy siec natychmiast widzi taki host "
                    "jako latwy cel - kazdy otwarty port to potencjalny wektor ataku. "
                    "Windows Defender Firewall, iptables i UFW domyslnie blokuja przychodzace polaczenia."
                ),
                "impact": "Kazda usluga na otwartym porcie jest dostepna sieciowo - ryzyko ataku na kazda z nich rownoczesnie.",
                "fix": "Wlacz i skonfiguruj firewall systemowy. Stosuj zasade minimalnych uprawnien: otwieraj tylko porty niezbedne dla danego hosta. Audituj reguly firewalla regularnie.",
                "cvss": "7.5",
            },
        ]
        SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        VULN_CATALOG.sort(key=lambda x: SEV_ORDER.get(x["severity"], 9))
        return render_template(
            "threats.html",
            catalog=VULN_CATALOG,
            networks=networks,
            active_by_net=active_by_net,
            threat_devices=threat_devices,
        )

    # ── /internet ──────────────────────────────────────────────────────────────
    @app.route("/internet")
    def internet():
        db = SessionLocal()
        try:
            rows = {r.key: r.value for r in db.query(SystemStatus).filter(
                SystemStatus.key.in_(["internet_status", "internet_speed", "internet_wan"])
            ).all()}
        finally:
            db.close()

        def _parse(key):
            try:
                return _json.loads(rows.get(key) or "{}") or {}
            except Exception:
                return {}

        status = _parse("internet_status")
        speed  = _parse("internet_speed")
        wan    = _parse("internet_wan")

        updated_at = status.get("updated_at") or wan.get("updated_at")

        # Szacuj czas do kolejnego speed testu (co 30 min = 1800s)
        next_speed_min = None
        if speed.get("updated_at"):
            from datetime import datetime
            try:
                last = datetime.strptime(speed["updated_at"], "%Y-%m-%dT%H:%M:%S")
                elapsed_s = (datetime.utcnow() - last).total_seconds()
                remaining = max(0, 1800 - elapsed_s)
                next_speed_min = int(remaining / 60)
            except Exception:
                pass

        return render_template(
            "internet.html",
            status=status or None,
            speed=speed or None,
            wan=wan or None,
            updated_at=updated_at,
            next_speed_min=next_speed_min,
        )

    # ── /chat ──────────────────────────────────────────────────────────────────
    @app.route("/chat")
    def chat_page():
        if not PRO_ENABLED:
            return render_template("pro_feature.html",
                feature="Asystent AI",
                description="Zadawaj pytania o siec w jezyku naturalnym. "
                            "Analizuj podatnosci, urzadzenia i zdarzenia przez AI.")
        disabled = not chat_agent.AGENT_ENABLED
        return render_template("chat.html", disabled=disabled)

    @app.route("/chat/message", methods=["POST"])
    def chat_message():
        if not PRO_ENABLED:
            return jsonify({"error": "Dostepne wylacznie w wersji NetDoc Pro."}), 403
        if not chat_agent.AGENT_ENABLED:
            return jsonify({"error": "Agent AI jest wylaczony (AGENT_ENABLED=0)."}), 403
        data = request.get_json(force=True, silent=True) or {}
        messages = data.get("messages", [])
        session_id = (data.get("session_id") or "")[:64]
        if not messages:
            return jsonify({"error": "Brak wiadomosci."}), 400
        # Ogranicz history do ostatnich 20 wiadomosci (ochrona przed duzym kontekstem)
        if len(messages) > 20:
            messages = messages[-20:]
        # Usun pola metadanych JS (_suggestions, _tool_details itp.) — Anthropic API je odrzuca
        messages = [{k: v for k, v in m.items() if not k.startswith("_")} for m in messages]
        result = chat_agent.chat(messages)
        reply = result["reply"]
        suggestions = result.get("suggestions", [])
        tools_used = result.get("tools_used", [])
        tool_details = result.get("tool_details", [])
        # Zapisz ostatnia wiadomosc uzytkownika i odpowiedz do DB
        if session_id:
            db = SessionLocal()
            try:
                user_msg = next((m for m in reversed(messages) if m.get("role") == "user"), None)
                if user_msg:
                    user_content = user_msg.get("content", "")
                    if isinstance(user_content, list):
                        user_content = " ".join(
                            p.get("text", "") for p in user_content if isinstance(p, dict)
                        )
                    db.add(ChatMessage(
                        session_id=session_id, role="user", content=str(user_content),
                    ))
                db.add(ChatMessage(
                    session_id=session_id, role="assistant", content=reply,
                    tools_used=tool_details or None,  # pelne detale: [{tool, input, result}]
                ))
                db.commit()
            except Exception:
                db.rollback()
            finally:
                db.close()
        return jsonify({"reply": reply, "suggestions": suggestions, "tool_details": tool_details})

    @app.route("/chat/history")
    def chat_history():
        if not PRO_ENABLED:
            return render_template("pro_feature.html",
                feature="Historia rozmow AI",
                description="Przegladaj poprzednie sesje z Asystentem AI.")
        # original code below
        db = SessionLocal()
        try:
            from sqlalchemy import func
            # Pobierz ostatnie 50 sesji (session_id + czas pierwszej i ostatniej wiadomosci + liczba par)
            sessions = (
                db.query(
                    ChatMessage.session_id,
                    func.min(ChatMessage.created_at).label("started_at"),
                    func.max(ChatMessage.created_at).label("last_at"),
                    func.count(ChatMessage.id).label("msg_count"),
                )
                .group_by(ChatMessage.session_id)
                .order_by(func.max(ChatMessage.created_at).desc())
                .limit(50)
                .all()
            )
            # Dla kazdej sesji pobierz pierwsze pytanie uzytkownika jako podglad
            previews = {}
            for s in sessions:
                first_user = (
                    db.query(ChatMessage)
                    .filter(ChatMessage.session_id == s.session_id, ChatMessage.role == "user")
                    .order_by(ChatMessage.created_at)
                    .first()
                )
                previews[s.session_id] = first_user.content[:120] if first_user else ""
        finally:
            db.close()
        return render_template("chat_history.html", sessions=sessions, previews=previews)

    @app.route("/chat/history/<session_id>")
    def chat_history_session(session_id):
        db = SessionLocal()
        try:
            msgs = (
                db.query(ChatMessage)
                .filter(ChatMessage.session_id == session_id)
                .order_by(ChatMessage.created_at)
                .all()
            )
        finally:
            db.close()
        return render_template("chat_history_session.html", msgs=msgs, session_id=session_id)

    @app.route("/chat/context")
    def chat_context():
        """Wyswietla kontekst statyczny NetDoc AI (ai_context.md) jako strone HTML."""
        if not PRO_ENABLED:
            return render_template("pro_feature.html",
                feature="Kontekst AI",
                description="Konfiguracja kontekstu dla Asystenta AI.")
        ctx_text = chat_agent._load_ai_context()
        return render_template("chat_context.html", context_text=ctx_text)

    # ── AI hardware assessment ─────────────────────────────────────────────────
    @app.route("/devices/ai-assess/readiness")
    def devices_ai_assess_readiness():
        """Zwraca statystyki gotowosci danych przed wywolaniem AI assessment."""
        from datetime import datetime as _dt
        db = SessionLocal()
        try:
            devs = db.query(Device).all()
            total = len(devs)
            with_hostname = sum(1 for d in devs if d.hostname)
            with_vendor   = sum(1 for d in devs if d.vendor)
            with_os       = sum(1 for d in devs if d.os_version)
            with_any      = sum(1 for d in devs if d.hostname or d.vendor or d.os_version)

            # Czas ostatniego skanu z SystemStatus
            last_scan_row = db.query(SystemStatus).filter_by(key="scanner_last_at").first()
            last_scan_at  = last_scan_row.value if last_scan_row else None
            scan_age_min  = None
            if last_scan_at:
                try:
                    last_dt = _dt.strptime(last_scan_at, "%Y-%m-%d %H:%M:%S")
                    scan_age_min = int((_dt.utcnow() - last_dt).total_seconds() / 60)
                except Exception:
                    pass

            enrichment_pct = round(with_any / total * 100) if total > 0 else 0

            # Ocena gotowosci: poor (<30%), fair (30-70%), good (>70%)
            if total == 0:
                readiness = "no_devices"
            elif enrichment_pct < 30:
                readiness = "poor"
            elif enrichment_pct < 70:
                readiness = "fair"
            else:
                readiness = "good"

            return jsonify({
                "total": total,
                "with_hostname": with_hostname,
                "with_vendor": with_vendor,
                "with_os": with_os,
                "with_any": with_any,
                "enrichment_pct": enrichment_pct,
                "readiness": readiness,
                "last_scan_at": last_scan_at,
                "scan_age_min": scan_age_min,
            })
        finally:
            db.close()

    @app.route("/devices/ai-assess", methods=["POST"])
    def devices_ai_assess():
        """Wysyla jednorazowe zapytanie do Claude API z lista wszystkich urzadzen.

        Odpowiedz zawiera JSON z ocena kazdego urzadzenia: czy jest przestarzale,
        propozycje zamiennikow w trzech przedziałach cenowych, uwzgledniajac ekosystem.
        Wynik jest cachowany w SystemStatus (klucz: ai_assessment_result) przez 24h.
        """
        if not PRO_ENABLED:
            return jsonify({"error": "Ocena AI dostepna wylacznie w wersji NetDoc Pro."}), 403
        db = SessionLocal()
        try:
            # Sprawdz czy funkcja jest wlaczona
            flag_row = db.query(SystemStatus).filter_by(key="ai_assessment_enabled").first()
            if flag_row and flag_row.value == "0":
                return jsonify({"error": "Ocena AI jest wyłączona w ustawieniach."}), 403

            # Sprawdz czy mamy API key
            api_key = os.getenv("ANTHROPIC_API_KEY", "")
            if not api_key:
                return jsonify({"error": "Brak klucza ANTHROPIC_API_KEY w konfiguracji."}), 503

            # Pobierz wszystkie urzadzenia z bazy
            from netdoc.storage.models import ScanResult as SR
            devs = db.query(Device).order_by(Device.ip).all()
            if not devs:
                return jsonify({"error": "Brak urządzeń w bazie danych."}), 400

            # Zbuduj zwiezly opis urzadzen dla modelu
            dev_lines = []
            for d in devs:
                parts = [
                    f"IP:{d.ip}",
                    f"typ:{d.device_type.value if d.device_type else 'unknown'}",
                ]
                if d.hostname:
                    parts.append(f"hostname:{d.hostname}")
                if d.vendor:
                    parts.append(f"vendor:{d.vendor}")
                if d.os_version:
                    parts.append(f"os:{d.os_version}")
                # Dodaj liste otwartych portow z najnowszego skanu
                latest_scan = (
                    db.query(SR)
                    .filter(SR.device_id == d.id)
                    .order_by(SR.scan_time.desc())
                    .first()
                )
                if latest_scan and latest_scan.open_ports:
                    port_list = ",".join(str(p) for p in list(latest_scan.open_ports.keys())[:10])
                    parts.append(f"porty:{port_list}")
                dev_lines.append("  " + " | ".join(parts))

            dev_summary = "\n".join(dev_lines)

            prompt = f"""Jesteś ekspertem od infrastruktury sieciowej. Poniżej masz listę urządzeń sieciowych z sieci produkcyjnej.

Urządzenia ({len(devs)} szt.):
{dev_summary}

Zadanie: Dla każdego urządzenia:
1. Oceń czy sprzęt jest przestarzały/niezarządzalny/ryzykowny (True/False)
2. Podaj krótkie uzasadnienie (max 2 zdania po polsku)
3. Jeśli przestarzały — zaproponuj 3 zamienniki: tani (budżetowy), średni (dobry stosunek ceny do jakości), premium (najlepszy)
   - Uwzględnij ekosystem vendora (nie sugeruj MikroTik na miejsce Ubiquiti jeśli nie pasuje)
   - Podaj przybliżone ceny (nowy, a jeśli dostępny też używany)
   - Skup się na dostępności w Polsce/Europie
4. Dla urządzeń nowoczesnych — krótkie potwierdzenie że są OK

Odpowiedz WYŁĄCZNIE w formacie JSON (bez markdown, bez wyjaśnień poza JSON):
{{
  "assessed_at": "YYYY-MM-DD HH:MM",
  "devices": [
    {{
      "ip": "...",
      "hostname": "...",
      "vendor": "...",
      "device_type": "...",
      "is_obsolete": true/false,
      "reason": "...",
      "replacements": [
        {{"tier": "budget", "name": "...", "price_new": "...", "price_used": "...", "notes": "..."}},
        {{"tier": "mid", "name": "...", "price_new": "...", "price_used": "...", "notes": "..."}},
        {{"tier": "premium", "name": "...", "price_new": "...", "price_used": "...", "notes": "..."}}
      ]
    }}
  ],
  "summary": "Ogólne podsumowanie stanu infrastruktury (2-3 zdania)"
}}

Dla urządzeń nieobsoletes: "replacements": []"""

            # Wywolaj Claude API
            try:
                import anthropic as _anthropic
                client = _anthropic.Anthropic(api_key=api_key)
                response = client.messages.create(
                    model="claude-opus-4-6",
                    max_tokens=4096,
                    messages=[{"role": "user", "content": prompt}],
                )
                raw_text = response.content[0].text.strip()
            except Exception as exc:
                return jsonify({"error": f"Błąd API Claude: {exc}"}), 502

            # Parsuj JSON z odpowiedzi
            try:
                # Usun ewentualne owijanie markdown (```json ... ```)
                if raw_text.startswith("```"):
                    raw_text = raw_text.split("```")[1]
                    if raw_text.startswith("json"):
                        raw_text = raw_text[4:]
                    raw_text = raw_text.strip()
                result_data = _json.loads(raw_text)
            except Exception:
                # Jesli nie parsuje — zwroc raw text w wrapper
                result_data = {"raw": raw_text, "assessed_at": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%d %H:%M")}

            # Cachuj wynik w SystemStatus (latest + historia)
            result_json = _json.dumps(result_data, ensure_ascii=False)
            _dt = __import__("datetime").datetime
            now = _dt.utcnow()

            # Najnowszy wynik (stały klucz)
            cache_row = db.query(SystemStatus).filter_by(key="ai_assessment_result").first()
            if cache_row:
                cache_row.value = result_json
                cache_row.updated_at = now
            else:
                db.add(SystemStatus(key="ai_assessment_result", category="cache", value=result_json))

            # Wpis historyczny
            hist_key = "ai_assessment_" + now.strftime("%Y%m%d_%H%M%S")
            db.add(SystemStatus(key=hist_key, category="cache_history", value=result_json))

            # Ogranicz historie do 20 wpisow — usun najstarsze po updated_at
            hist_rows = (
                db.query(SystemStatus)
                .filter_by(category="cache_history")
                .order_by(SystemStatus.updated_at.desc())
                .all()
            )
            for old in hist_rows[20:]:
                db.delete(old)

            db.commit()

            return jsonify(result_data)

        except Exception as exc:
            return jsonify({"error": str(exc)}), 500
        finally:
            db.close()

    @app.route("/devices/ai-assess/last")
    def devices_ai_assess_last():
        """Zwraca ostatni zapisany wynik oceny AI (bez wywolywania modelu)."""
        db = SessionLocal()
        try:
            row = db.query(SystemStatus).filter_by(key="ai_assessment_result").first()
            if not row or not row.value:
                return jsonify({"error": "Brak zapisanego wyniku oceny AI."}), 404
            try:
                return jsonify(_json.loads(row.value))
            except Exception:
                return jsonify({"raw": row.value})
        finally:
            db.close()

    # ── AI ocena per-urządzenie ─────────────────────────────────────────────────
    @app.route("/devices/<int:device_id>/ai-assess", methods=["POST"])
    def device_ai_assess(device_id):
        """Wywoluje kompleksowa analize AI (bezpieczenstwo + modernizacja) dla jednego urzadzenia."""
        if not PRO_ENABLED:
            return jsonify({"error": "Ocena AI urządzenia dostępna wyłącznie w wersji NetDoc Pro."}), 403
        import base64 as _b64
        db = SessionLocal()
        try:
            flag_row = db.query(SystemStatus).filter_by(key="ai_assessment_enabled").first()
            if flag_row and flag_row.value == "0":
                return jsonify({"error": "Ocena AI jest wyłączona w ustawieniach."}), 403

            api_key = os.getenv("ANTHROPIC_API_KEY", "")
            if not api_key:
                return jsonify({"error": "Brak klucza ANTHROPIC_API_KEY w konfiguracji."}), 503

            dev = db.query(Device).filter_by(id=device_id).first()
            if not dev:
                return jsonify({"error": "Urządzenie nie istnieje."}), 404

            # ── Otwarte porty (najnowszy skan) ──────────────────────────────────
            from netdoc.storage.models import ScanResult as _SR, Vulnerability as _Vuln, DeviceScreenshot as _DS
            latest_scan = (
                db.query(_SR).filter(_SR.device_id == dev.id)
                .order_by(_SR.scan_time.desc()).first()
            )
            ports_detail = "(brak danych o portach)"
            if latest_scan and latest_scan.open_ports:
                _COMMON = {
                    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                    80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP",
                    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
                    5900: "VNC", 8080: "HTTP-alt", 8443: "HTTPS-alt",
                    8883: "MQTT-TLS", 1883: "MQTT", 502: "Modbus",
                    102: "Profinet/S7", 47808: "BACnet",
                }
                port_lines = []
                for p, info in list(latest_scan.open_ports.items())[:30]:
                    svc = _COMMON.get(int(p), info.get("name", "") if isinstance(info, dict) else "")
                    port_lines.append(f"  {p}/TCP — {svc or 'nieznana usługa'}")
                ports_detail = "\n".join(port_lines)
                if latest_scan.scan_time:
                    ports_detail += f"\n  (skan z {latest_scan.scan_time.strftime('%Y-%m-%d %H:%M')})"

            # ── Aktywne podatności ───────────────────────────────────────────────
            active_vulns = (
                db.query(_Vuln)
                .filter(_Vuln.device_id == dev.id, _Vuln.is_open.is_(True), _Vuln.suppressed.is_(False))
                .all()
            )
            if active_vulns:
                vulns_str = "\n".join(
                    f"  [{v.severity.value.upper()}] {v.title} (port {v.port or '?'}): {v.description or ''}"
                    for v in active_vulns[:10]
                )
            else:
                vulns_str = "  (brak wykrytych podatności)"

            # ── Znalezione credentiale ───────────────────────────────────────────
            from netdoc.storage.models import Credential as _Cred
            found_creds = (
                db.query(_Cred)
                .filter(_Cred.device_id == dev.id, _Cred.last_success_at.isnot(None))
                .all()
            )
            if found_creds:
                creds_str = "\n".join(
                    f"  {c.method.value}: login={c.username or '?'}"
                    for c in found_creds[:5]
                )
            else:
                creds_str = "  (brak uzyskanego dostępu)"

            # ── Screenshot (tylko nie-kamery) ────────────────────────────────────
            _dev_type_val  = dev.device_type.value if dev.device_type else ""
            _vendor_lower  = (dev.vendor or "").lower()
            _host_lower    = (dev.hostname or "").lower()
            _is_camera     = (
                _dev_type_val == "camera"
                or any(k in _vendor_lower for k in ("hikvision", "dahua", "axis", "vivotek", "hanwha", "bosch camera"))
                or any(k in _host_lower  for k in ("cam", "camera", "kamera", "cctv", "nvr", "dvr"))
            )
            screenshot_png = None
            if not _is_camera:
                scr = db.query(_DS).filter_by(device_id=dev.id).first()
                if scr and scr.png_data:
                    screenshot_png = _b64.b64encode(scr.png_data).decode("ascii")

            # ── Buduj prompt ─────────────────────────────────────────────────────
            prompt = f"""Jesteś ekspertem od cyberbezpieczeństwa i infrastruktury sieciowej.
Przeprowadź KOMPLEKSOWĄ analizę urządzenia sieciowego obejmującą bezpieczeństwo i modernizację.
{('Na załączonym zrzucie ekranu widać interfejs webowy tego urządzenia — uwzględnij go w analizie.' if screenshot_png else '')}

=== DANE URZĄDZENIA ===
  IP:          {dev.ip}
  Typ adresacji: {getattr(dev, 'ip_type', 'unknown')}
  Typ:         {_dev_type_val or 'unknown'}
  Hostname:    {dev.hostname or '(brak)'}
  Vendor:      {dev.vendor or '(brak)'}
  OS/Firmware: {dev.os_version or '(brak)'}
  MAC:         {dev.mac or '(brak)'}

=== OTWARTE PORTY (wykryte przez nmap) ===
{ports_detail}

=== WYKRYTE PODATNOŚCI (skaner automatyczny) ===
{vulns_str}

=== UZYSKANY DOSTĘP (credential tester) ===
{creds_str}

ZADANIE:
SEKCJA 1 — BEZPIECZEŃSTWO:
  Dla każdego otwartego portu i podatności oceń ryzyko i podaj zalecenie.
  Zwróć uwagę na: niezaszyfrowane protokoły (Telnet/FTP/HTTP), domyślne hasła,
  nieaktualne usługi, ekspozycję protokołów przemysłowych (Modbus/BACnet/S7),
  brak segmentacji sieci, otwarte porty administracyjne.

SEKCJA 2 — MODERNIZACJA SPRZĘTU:
  Oceń czy sprzęt jest przestarzały. Jeśli tak — zaproponuj 3 zamienniki
  (budżet/średni/premium) dostępne w Polsce/Europie.

Odpowiedz WYŁĄCZNIE w formacie JSON (bez markdown, bez kodu):
{{
  "ip": "{dev.ip}",
  "hostname": "{dev.hostname or ''}",
  "vendor": "{dev.vendor or ''}",
  "device_type": "{_dev_type_val}",
  "is_obsolete": true/false,
  "reason": "Uzasadnienie oceny sprzętu (max 3 zdania po polsku)",
  "replacements": [
    {{"tier": "budget",  "name": "...", "price_new": "...", "price_used": "...", "notes": "..."}},
    {{"tier": "mid",     "name": "...", "price_new": "...", "price_used": "...", "notes": "..."}},
    {{"tier": "premium", "name": "...", "price_new": "...", "price_used": "...", "notes": "..."}}
  ],
  "summary": "Ogólne podsumowanie oceny sprzętu i bezpieczeństwa (2 zdania)",
  "security": {{
    "risk_level": "critical|high|medium|low|ok",
    "overall": "Ogólna ocena bezpieczeństwa (2-3 zdania po polsku)",
    "findings": [
      {{
        "port": 23,
        "service": "Telnet",
        "severity": "critical",
        "finding": "Opis znaleziska po polsku",
        "recommendation": "Konkretne zalecenie po polsku"
      }}
    ]
  }}
}}

Dla urządzeń bez problemów bezpieczeństwa: "security": {{"risk_level": "ok", "overall": "...", "findings": []}}
Dla urządzeń nieobsoletes: "replacements": []"""

            # ── Wywołaj Claude API (z obrazem lub bez) ──────────────────────────
            try:
                import anthropic as _anthropic
                client = _anthropic.Anthropic(api_key=api_key)
                if screenshot_png:
                    msg_content = [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/png",
                                "data": screenshot_png,
                            },
                        },
                        {"type": "text", "text": prompt},
                    ]
                else:
                    msg_content = prompt
                response = client.messages.create(
                    model="claude-opus-4-6",
                    max_tokens=4096,
                    messages=[{"role": "user", "content": msg_content}],
                )
                raw_text = response.content[0].text.strip()
            except Exception as exc:
                return jsonify({"error": f"Błąd API Claude: {exc}"}), 502

            try:
                if raw_text.startswith("```"):
                    raw_text = raw_text.split("```")[1]
                    if raw_text.startswith("json"):
                        raw_text = raw_text[4:]
                    raw_text = raw_text.strip()
                result_data = _json.loads(raw_text)
            except Exception:
                result_data = {"raw": raw_text}

            # Zapisz w historii (maks. 10 wpisów na urządzenie)
            _dt = __import__("datetime").datetime
            entry = DeviceAssessment(
                device_id=device_id,
                assessed_at=_dt.utcnow(),
                prompt=prompt,
                result=_json.dumps(result_data, ensure_ascii=False),
                model="claude-opus-4-6",
            )
            db.add(entry)
            db.flush()

            old_entries = (
                db.query(DeviceAssessment)
                .filter_by(device_id=device_id)
                .order_by(DeviceAssessment.assessed_at.desc())
                .all()
            )
            for old in old_entries[10:]:
                db.delete(old)
            db.commit()

            result_data["assessed_at"] = entry.assessed_at.strftime("%Y-%m-%d %H:%M")
            return jsonify(result_data)

        except Exception as exc:
            return jsonify({"error": str(exc)}), 500
        finally:
            db.close()

    @app.route("/devices/<int:device_id>/ai-assess/history")
    def device_ai_assess_history(device_id):
        """Zwraca liste historycznych ocen AI dla jednego urzadzenia."""
        db = SessionLocal()
        try:
            rows = (
                db.query(DeviceAssessment)
                .filter_by(device_id=device_id)
                .order_by(DeviceAssessment.assessed_at.desc())
                .all()
            )
            items = []
            for row in rows:
                try:
                    data = _json.loads(row.result)
                    items.append({
                        "id": row.id,
                        "assessed_at": row.assessed_at.strftime("%Y-%m-%d %H:%M"),
                        "is_obsolete": data.get("is_obsolete"),
                        "reason": data.get("reason", ""),
                        "summary": data.get("summary", ""),
                        "replacements_count": len(data.get("replacements", [])),
                        "risk_level": (data.get("security") or {}).get("risk_level", "ok"),
                        "findings_count": len((data.get("security") or {}).get("findings", [])),
                    })
                except Exception:
                    pass
            return jsonify(items)
        finally:
            db.close()

    @app.route("/devices/<int:device_id>/ai-assess/history/<int:entry_id>")
    def device_ai_assess_history_item(device_id, entry_id):
        """Zwraca pelny wynik historycznej oceny AI dla jednego urzadzenia."""
        db = SessionLocal()
        try:
            row = db.query(DeviceAssessment).filter_by(id=entry_id, device_id=device_id).first()
            if not row:
                return jsonify({"error": "Nie znaleziono wpisu."}), 404
            try:
                data = _json.loads(row.result)
                data["assessed_at"] = row.assessed_at.strftime("%Y-%m-%d %H:%M")
                return jsonify(data)
            except Exception:
                return jsonify({"raw": row.result})
        finally:
            db.close()

    @app.route("/devices/ai-assess/history")
    def devices_ai_assess_history():
        """Zwraca liste historycznych ocen AI (bez pelnej zawartosci — tylko metadane)."""
        db = SessionLocal()
        try:
            rows = (
                db.query(SystemStatus)
                .filter_by(category="cache_history")
                .order_by(SystemStatus.updated_at.desc())
                .all()
            )
            items = []
            for row in rows:
                try:
                    data = _json.loads(row.value)
                    items.append({
                        "key": row.key,
                        "assessed_at": data.get("assessed_at", ""),
                        "updated_at": row.updated_at.strftime("%Y-%m-%d %H:%M") if row.updated_at else "",
                        "device_count": len(data.get("devices", [])),
                        "obsolete_count": sum(1 for d in data.get("devices", []) if d.get("is_obsolete")),
                        "summary": data.get("summary", ""),
                    })
                except Exception:
                    pass
            return jsonify(items)
        finally:
            db.close()

    @app.route("/devices/ai-assess/history/<key>")
    def devices_ai_assess_history_item(key):
        """Zwraca pelny wynik historycznej oceny AI po kluczu."""
        db = SessionLocal()
        try:
            row = db.query(SystemStatus).filter_by(key=key, category="cache_history").first()
            if not row:
                return jsonify({"error": "Nie znaleziono wpisu historycznego."}), 404
            try:
                return jsonify(_json.loads(row.value))
            except Exception:
                return jsonify({"raw": row.value})
        finally:
            db.close()

    @app.route("/devices/ai-report")
    def devices_ai_report():
        """Raport HTML z ocen AI per-urzadzenie — do druku i eksportu."""
        db = SessionLocal()
        try:
            rows = (
                db.query(DeviceAssessment, Device)
                .outerjoin(Device, DeviceAssessment.device_id == Device.id)
                .order_by(DeviceAssessment.assessed_at.desc())
                .all()
            )
            # Zbierz tylko najnowsza ocene per urzadzenie (klucz: device_id lub entry.id dla NULL)
            seen: set = set()
            entries = []
            for entry, dev in rows:
                key = dev.id if dev else f"null_{entry.id}"
                if key in seen:
                    continue
                seen.add(key)
                try:
                    data = _json.loads(entry.result)
                except Exception:
                    data = {}
                data["assessed_at"]   = entry.assessed_at.strftime("%Y-%m-%d %H:%M")
                data["device_ip"]     = dev.ip if dev else "(usunięte)"
                data["device_label"]  = (dev.hostname or dev.ip) if dev else f"(Device #{entry.device_id} usunięty)"
                data["device_type"]   = (dev.device_type.value if dev.device_type else "unknown") if dev else "unknown"
                data["device_id"]     = dev.id if dev else entry.device_id
                entries.append(data)
            # Sortuj: najpierw obsolete=True, potem wg risk_level
            _risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4, "": 5}
            entries.sort(key=lambda e: (
                0 if e.get("is_obsolete") else 1,
                _risk_order.get(e.get("security", {}).get("risk_level", ""), 5),
            ))
            from datetime import datetime as _dt2
            generated_at = _dt2.utcnow().strftime("%Y-%m-%d %H:%M UTC")
            return render_template("ai_report.html", entries=entries, generated_at=generated_at)
        finally:
            db.close()

    # ── Backup & Restore bazy danych ──────────────────────────────────────────
    @app.route("/settings/db/backup")
    def db_backup():
        """Pobierz zrzut bazy danych jako plik .sql.gz (pg_dump)."""
        import subprocess, gzip as _gzip, os as _os
        from urllib.parse import urlparse as _urlparse
        from datetime import datetime as _dt

        db_url = _os.environ.get("DB_URL", "")
        parsed = _urlparse(db_url.replace("postgresql+psycopg2://", "postgresql://"))
        env = _os.environ.copy()
        env["PGPASSWORD"] = parsed.password or ""
        cmd = [
            "pg_dump",
            "-h", parsed.hostname or "postgres",
            "-p", str(parsed.port or 5432),
            "-U", parsed.username or "netdoc",
            "--no-password",
            (parsed.path or "/netdoc").lstrip("/"),
        ]
        try:
            result = subprocess.run(cmd, env=env, capture_output=True, timeout=300)
        except FileNotFoundError:
            return "pg_dump nie jest zainstalowany w kontenerze (wymagany rebuild obrazu)", 500
        except subprocess.TimeoutExpired:
            return "Timeout podczas tworzenia backupu", 500
        if result.returncode != 0:
            return f"Błąd pg_dump:\n{result.stderr.decode(errors='replace')}", 500

        gz_bytes = _gzip.compress(result.stdout, compresslevel=6)
        filename = f"netdoc_backup_{_dt.utcnow().strftime('%Y%m%d_%H%M%S')}.sql.gz"
        return Response(
            gz_bytes,
            mimetype="application/gzip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.route("/settings/db/container-status")
    def db_container_status():
        """Zwraca status kontenerow Docker jako JSON {name: status_str}."""
        import docker as _docker_sdk
        try:
            cli = _docker_sdk.from_env(timeout=10)
            result = {}
            for c in cli.containers.list(all=True):
                result[c.name] = c.status
            return result
        except Exception as exc:
            return {"error": str(exc)}, 500

    @app.route("/settings/db/restore", methods=["POST"])
    def db_restore():
        """Przywróć bazę danych z pliku .sql lub .sql.gz (psql)."""
        import subprocess, gzip as _gzip, os as _os
        from urllib.parse import urlparse as _urlparse
        from flask import request as _req, redirect, url_for, flash

        confirm = _req.form.get("confirm_restore")
        if confirm != "1":
            flash("Zaznacz potwierdzenie przed przywróceniem backupu.", "warning")
            return redirect(url_for("settings") + "#dbBackup")

        f = _req.files.get("backup_file")
        if not f or not f.filename:
            flash("Nie wybrano pliku backupu.", "danger")
            return redirect(url_for("settings") + "#dbBackup")

        data = f.read()
        if f.filename.endswith(".gz"):
            try:
                data = _gzip.decompress(data)
            except Exception as exc:
                flash(f"Błąd dekompresji pliku: {exc}", "danger")
                return redirect(url_for("settings") + "#dbBackup")

        db_url = _os.environ.get("DB_URL", "")
        parsed = _urlparse(db_url.replace("postgresql+psycopg2://", "postgresql://"))
        env = _os.environ.copy()
        env["PGPASSWORD"] = parsed.password or ""
        cmd = [
            "psql",
            "-h", parsed.hostname or "postgres",
            "-p", str(parsed.port or 5432),
            "-U", parsed.username or "netdoc",
            "--no-password",
            "-v", "ON_ERROR_STOP=0",
            (parsed.path or "/netdoc").lstrip("/"),
        ]
        try:
            result = subprocess.run(cmd, input=data, env=env, capture_output=True, timeout=300)
        except FileNotFoundError:
            flash("psql nie jest zainstalowany w kontenerze (wymagany rebuild obrazu).", "danger")
            return redirect(url_for("settings") + "#dbBackup")
        except subprocess.TimeoutExpired:
            flash("Timeout podczas przywracania backupu.", "danger")
            return redirect(url_for("settings") + "#dbBackup")

        if result.returncode != 0:
            err = result.stderr.decode(errors="replace")[:600]
            flash(f"Błąd psql (kod {result.returncode}): {err}", "danger")
            return redirect(url_for("settings") + "#dbBackup")

        # Sukces — restartuj kontenery aplikacji w tle, potem self (web)
        import threading as _threading
        import docker as _docker_sdk

        _RESTORE_CONTAINERS = [
            "netdoc-api", "netdoc-ping", "netdoc-snmp",
            "netdoc-cred", "netdoc-vuln", "netdoc-internet",
        ]

        def _restart_after_restore():
            import time as _time
            _time.sleep(1)
            try:
                cli = _docker_sdk.from_env(timeout=30)
                for name in _RESTORE_CONTAINERS:
                    try:
                        cli.containers.get(name).restart(timeout=10)
                    except Exception:
                        pass
                _time.sleep(2)
                try:
                    cli.containers.get("netdoc-web").restart(timeout=10)
                except Exception:
                    pass
            except Exception:
                pass

        _threading.Thread(target=_restart_after_restore, daemon=True).start()

        # BUG-SEC-7: uzyj zmiennej Jinja2 zamiast konkatenacji w render_template_string
        container_list_json = _json.dumps(_RESTORE_CONTAINERS + ["netdoc-web"])
        return render_template_string("""
<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Restore — NetDoc</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
  <style>body{background:#121212;color:#e0e0e0;} .ci{font-size:.82rem;}</style>
</head>
<body class="p-4" style="max-width:520px;margin:0 auto">
  <div class="text-center mb-4 mt-4">
    <div class="mb-2 text-success" style="font-size:2.5rem"><i class="bi bi-check-circle-fill"></i></div>
    <h5 class="mb-1">Backup przywrócony pomyślnie</h5>
    <p class="text-muted small">Kontenery są restartowane — za chwilę wszystko wstanie.</p>
  </div>

  <div class="card bg-dark border-secondary mb-3">
    <div class="card-header small py-2"><i class="bi bi-box-seam me-2"></i>Status kontenerów</div>
    <ul class="list-group list-group-flush" id="containerList">
      <li class="list-group-item bg-dark text-muted small text-center py-2">
        <span class="spinner-border spinner-border-sm me-2"></span>Sprawdzam…
      </li>
    </ul>
  </div>

  <div class="text-center text-muted small" id="footer">
    Odświeżam za <strong id="cnt">12</strong> s…
  </div>

  <script>
  var CONTAINERS = {{ containers_json | safe }};
  var redirectAt = Date.now() + 12000;
  var allUp = false;

  function statusIcon(st) {
    if (!st) return '<i class="bi bi-hourglass-split text-warning me-2"></i>';
    if (st.toLowerCase().startsWith('up')) return '<i class="bi bi-check-circle-fill text-success me-2"></i>';
    return '<i class="bi bi-arrow-clockwise text-warning me-2 spin"></i>';
  }

  function poll() {
    fetch('/settings/db/container-status')
      .then(function(r){ return r.json(); })
      .then(function(data) {
        var html = '';
        var upCount = 0;
        CONTAINERS.forEach(function(name) {
          var st = data[name] || '';
          if (st.toLowerCase().startsWith('up')) upCount++;
          html += '<li class="list-group-item bg-dark ci d-flex justify-content-between align-items-center py-1">'
            + '<span>' + statusIcon(st) + name.replace('netdoc-','') + '</span>'
            + '<span class="badge ' + (st.toLowerCase().startsWith('up') ? 'bg-success' : 'bg-warning text-dark') + '">'
            + (st || 'restartuje…') + '</span></li>';
        });
        document.getElementById('containerList').innerHTML = html;
        if (upCount === CONTAINERS.length && !allUp) {
          allUp = true;
          redirectAt = Date.now() + 3000;
          document.getElementById('footer').innerHTML =
            '<span class="text-success"><i class="bi bi-check-circle-fill me-1"></i>'
            + 'Wszystkie kontenery działają — przekierowuję…</span>';
        }
      })
      .catch(function(){});
  }

  poll();
  setInterval(poll, 2000);

  setInterval(function() {
    var rem = Math.max(0, Math.round((redirectAt - Date.now()) / 1000));
    var el = document.getElementById('cnt');
    if (el) el.textContent = rem;
    if (Date.now() >= redirectAt) { location.href = '/settings#dbBackup'; }
  }, 500);
  </script>
  <style>.spin{animation:spin 1s linear infinite;}@keyframes spin{to{transform:rotate(360deg);}}</style>
</body>
</html>
""", containers_json=container_list_json)

    return app


import sys as _sys

if "pytest" not in _sys.modules:
    # Produkcja: Flask CLI / gunicorn / python -m flask
    app = create_app()
else:
    # Testy: kazdy plik testowy tworzy wlasny app przez create_app() z odpowiednimi mockami.
    # Pomijamy tutaj aby uniknac uruchomienia background workera podczas calej suity testow.
    app = None  # type: ignore[assignment]

if __name__ == "__main__":
    if app is None:
        app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=False)
