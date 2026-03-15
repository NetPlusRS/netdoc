"""Netdoc Internet Worker — sprawdza dostepnosc internetu, DNS, latencje i predkosc lacza.

Dwie petle niezalezne czasowo:
  - co INET_CHECK_INTERVAL_S (domyslnie 120s):
      DNS TCP (8.8.8.8, 1.1.1.1), HTTP latencja + jitter (5 prob do 1.1.1.1)
  - co INET_SPEED_INTERVAL_S (domyslnie 1800s):
      Download i Upload (Cloudflare CDN), latencja HTTP

Wyniki zapisywane do tabeli system_status (klucze internet_status, internet_speed).
Metryki Prometheus na porcie INET_METRICS_PORT.
"""
import json
import logging
import math
import os
import socket
import sys
import time
from datetime import datetime

import httpx
from prometheus_client import Gauge, start_http_server

from netdoc.storage.database import SessionLocal, init_db
from netdoc.storage.models import SystemStatus

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [INET] %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

# ── Konfiguracja ──────────────────────────────────────────────────────────────
CHECK_INTERVAL_S  = int(os.getenv("INET_CHECK_INTERVAL_S",  "120"))   # 2 min
SPEED_INTERVAL_S  = int(os.getenv("INET_SPEED_INTERVAL_S",  "1800"))  # 30 min
METRICS_PORT      = int(os.getenv("INET_METRICS_PORT",      "8005"))
DNS_TIMEOUT       = float(os.getenv("INET_DNS_TIMEOUT",     "5"))
HTTP_TIMEOUT      = float(os.getenv("INET_HTTP_TIMEOUT",    "10"))
SPEED_BYTES       = int(os.getenv("INET_SPEED_BYTES",       "5242880"))   # 5 MB download
UPLOAD_BYTES      = int(os.getenv("INET_UPLOAD_BYTES",      "2097152"))   # 2 MB upload
SPEED_TIMEOUT     = float(os.getenv("INET_SPEED_TIMEOUT",   "60"))
JITTER_PINGS      = int(os.getenv("INET_JITTER_PINGS",      "6"))         # ile prob latencji
WAN_INTERVAL_S    = int(os.getenv("INET_WAN_INTERVAL_S",    "3600"))      # publiczne IP co 1h

_HTTP_PROBE      = "https://1.1.1.1"
_SPEED_DL_URL    = f"https://speed.cloudflare.com/__down?bytes={SPEED_BYTES}"
_SPEED_UL_URL    = "https://speed.cloudflare.com/__up"
_WAN_INFO_URL    = "https://ipinfo.io/json"

# ── Prometheus metryki ────────────────────────────────────────────────────────
g_dns_google  = Gauge("netdoc_inet_dns_google_ok",   "Google DNS (8.8.8.8:53) [0/1]")
g_dns_cf      = Gauge("netdoc_inet_dns_cf_ok",       "Cloudflare DNS (1.1.1.1:53) [0/1]")
g_dns_gms     = Gauge("netdoc_inet_dns_google_ms",   "Google DNS latencja TCP [ms]")
g_dns_cfms    = Gauge("netdoc_inet_dns_cf_ms",       "Cloudflare DNS latencja TCP [ms]")
g_http_ok     = Gauge("netdoc_inet_http_ok",         "HTTP 1.1.1.1 dostepny [0/1]")
g_http_ms     = Gauge("netdoc_inet_http_avg_ms",     "HTTP srednia latencja [ms]")
g_jitter      = Gauge("netdoc_inet_jitter_ms",       "HTTP jitter (odchylenie std) [ms]")
g_dl          = Gauge("netdoc_inet_download_mbps",   "Predkosc pobierania [Mbps]")
g_ul          = Gauge("netdoc_inet_upload_mbps",     "Predkosc wysylania [Mbps]")
g_speed_ok    = Gauge("netdoc_inet_speed_ok",        "Test predkosci OK [0/1]")
g_wan_ok      = Gauge("netdoc_inet_wan_ok",          "Publiczne IP WAN dostepne [0/1]")


# ── Funkcje diagnostyczne ─────────────────────────────────────────────────────

def check_wan_ip(timeout: float = 10.0) -> dict:
    """Pobiera publiczne IP i geolokalizacje z ipinfo.io."""
    try:
        r = httpx.get(_WAN_INFO_URL, timeout=timeout,
                      headers={"User-Agent": "NetDoc-InternetWorker/1.0"})
        data = r.json()
        return {
            "ok":       True,
            "ip":       data.get("ip"),
            "city":     data.get("city"),
            "region":   data.get("region"),
            "country":  data.get("country"),
            "org":      data.get("org"),       # np. "AS5617 Orange Polska"
            "timezone": data.get("timezone"),
            "loc":      data.get("loc"),       # "lat,lon"
            "updated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
        }
    except Exception as e:
        logger.warning("WAN IP lookup blad: %s", e)
        return {"ok": False, "err": str(e)[:80]}


def check_dns(ip: str, port: int = 53, timeout: float = DNS_TIMEOUT) -> dict:
    """TCP connect do serwera DNS — sprawdza osiagalnosc bez dnspython."""
    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            ms = round((time.monotonic() - t0) * 1000)
        return {"ok": True, "ms": ms}
    except OSError as e:
        return {"ok": False, "ms": None, "err": str(e)[:80]}


def check_http(url: str, timeout: float = HTTP_TIMEOUT) -> dict:
    """Pojedyncza proba HTTP GET z pomiarem czasu."""
    t0 = time.monotonic()
    try:
        r = httpx.get(url, timeout=timeout, follow_redirects=True,
                      headers={"User-Agent": "NetDoc-InternetWorker/1.0"})
        ms = round((time.monotonic() - t0) * 1000)
        return {"ok": r.status_code < 500, "ms": ms, "code": r.status_code}
    except Exception as e:
        return {"ok": False, "ms": None, "err": str(e)[:80]}


def measure_latency_and_jitter(url: str, pings: int = JITTER_PINGS,
                                timeout: float = HTTP_TIMEOUT) -> dict:
    """Wykonuje N prob HTTP i oblicza srednia latencje, jitter (std dev), min i max.

    Jitter definiowany jako odchylenie standardowe czasow odpowiedzi.
    """
    samples = []
    errors  = 0
    for _ in range(pings):
        r = check_http(url, timeout=timeout)
        if r["ok"] and r["ms"] is not None:
            samples.append(r["ms"])
        else:
            errors += 1

    if not samples:
        return {"ok": False, "avg_ms": None, "min_ms": None, "max_ms": None,
                "jitter_ms": None, "errors": errors, "pings": pings}

    avg = round(sum(samples) / len(samples), 1)
    mn  = min(samples)
    mx  = max(samples)
    # Odchylenie standardowe (jitter)
    variance = sum((s - avg) ** 2 for s in samples) / len(samples)
    jitter   = round(math.sqrt(variance), 1)

    return {
        "ok":        True,
        "avg_ms":    avg,
        "min_ms":    mn,
        "max_ms":    mx,
        "jitter_ms": jitter,
        "errors":    errors,
        "pings":     pings,
    }


def speed_download(url: str = _SPEED_DL_URL, timeout: float = SPEED_TIMEOUT) -> dict:
    """Pobiera plik testowy z Cloudflare CDN streaming i mierzy predkosc."""
    t0 = time.monotonic()
    try:
        with httpx.stream("GET", url, timeout=timeout,
                          headers={"User-Agent": "NetDoc-InternetWorker/1.0"}) as r:
            received = 0
            for chunk in r.iter_bytes(chunk_size=65536):
                received += len(chunk)
        elapsed = time.monotonic() - t0
        mbps = round((received * 8) / elapsed / 1_000_000, 2)
        return {"ok": True, "download_mbps": mbps,
                "received_bytes": received, "elapsed_s": round(elapsed, 2)}
    except Exception as e:
        logger.warning("Download speed test blad: %s", e)
        return {"ok": False, "download_mbps": None, "err": str(e)[:80]}


def speed_upload(url: str = _SPEED_UL_URL, bytes_count: int = UPLOAD_BYTES,
                 timeout: float = SPEED_TIMEOUT) -> dict:
    """Wysyla dane testowe do Cloudflare i mierzy predkosc uploadu.

    Uzywa POST z body = bytes_count zerow. Cloudflare __up akceptuje dowolny payload.
    """
    payload = b"\x00" * bytes_count
    t0 = time.monotonic()
    try:
        r = httpx.post(url, content=payload, timeout=timeout,
                       headers={"User-Agent": "NetDoc-InternetWorker/1.0",
                                "Content-Type": "application/octet-stream"})
        elapsed = time.monotonic() - t0
        mbps = round((bytes_count * 8) / elapsed / 1_000_000, 2)
        return {"ok": r.status_code < 500, "upload_mbps": mbps,
                "sent_bytes": bytes_count, "elapsed_s": round(elapsed, 2)}
    except Exception as e:
        logger.warning("Upload speed test blad: %s", e)
        return {"ok": False, "upload_mbps": None, "err": str(e)[:80]}


# ── Zapis do DB ───────────────────────────────────────────────────────────────

def _save(key: str, category: str, value: dict) -> None:
    """Upsert do system_status — klucz glowny to key."""
    db = SessionLocal()
    try:
        row = db.query(SystemStatus).filter_by(key=key).first()
        serialized = json.dumps(value, ensure_ascii=False)
        if row:
            row.value = serialized
            row.category = category
        else:
            db.add(SystemStatus(key=key, category=category, value=serialized))
        db.commit()
    except Exception as exc:
        logger.error("DB save blad (%s): %s", key, exc)
        db.rollback()
    finally:
        db.close()


# ── Cykle glowne ─────────────────────────────────────────────────────────────

def run_checks() -> None:
    """Sprawdza DNS (8.8.8.8, 1.1.1.1) oraz latencje i jitter HTTP do 1.1.1.1."""
    dns_google = check_dns("8.8.8.8")
    dns_cf     = check_dns("1.1.1.1")
    latency    = measure_latency_and_jitter(_HTTP_PROBE, pings=JITTER_PINGS)

    # Prometheus
    g_dns_google.set(1 if dns_google["ok"] else 0)
    g_dns_cf.set(1    if dns_cf["ok"]      else 0)
    g_http_ok.set(1   if latency["ok"]     else 0)
    if dns_google.get("ms")     is not None: g_dns_gms.set(dns_google["ms"])
    if dns_cf.get("ms")         is not None: g_dns_cfms.set(dns_cf["ms"])
    if latency.get("avg_ms")    is not None: g_http_ms.set(latency["avg_ms"])
    if latency.get("jitter_ms") is not None: g_jitter.set(latency["jitter_ms"])

    status = {
        "dns_google":     dns_google,
        "dns_cloudflare": dns_cf,
        "http_cloudflare": latency,
        "updated_at":     datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
    }
    _save("internet_status", "internet", status)

    parts = []
    if dns_google["ok"]: parts.append(f"DNS-G {dns_google['ms']}ms")
    if dns_cf["ok"]:     parts.append(f"DNS-CF {dns_cf['ms']}ms")
    if latency["ok"]:    parts.append(f"HTTP avg={latency['avg_ms']}ms jitter={latency['jitter_ms']}ms")
    logger.info("Checks: %s", " | ".join(parts) if parts else "WSZYSTKIE FAIL")


def run_speed_test() -> None:
    """Test predkosci: download + upload, zapisuje wyniki do internet_speed."""
    logger.info("Test predkosci: download ~%dMB + upload ~%dMB...",
                SPEED_BYTES // 1_000_000, UPLOAD_BYTES // 1_000_000)
    dl = speed_download()
    ul = speed_upload()

    ok = dl["ok"] and ul["ok"]
    g_speed_ok.set(1 if ok else 0)
    if dl.get("download_mbps") is not None: g_dl.set(dl["download_mbps"])
    if ul.get("upload_mbps")   is not None: g_ul.set(ul["upload_mbps"])

    payload = {
        "ok":             ok,
        "download_mbps":  dl.get("download_mbps"),
        "upload_mbps":    ul.get("upload_mbps"),
        "dl_elapsed_s":   dl.get("elapsed_s"),
        "ul_elapsed_s":   ul.get("elapsed_s"),
        "updated_at":     datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
    }
    _save("internet_speed", "internet", payload)
    logger.info("Speed: dl=%.1f Mbps ul=%.1f Mbps",
                dl.get("download_mbps") or 0, ul.get("upload_mbps") or 0)


def run_wan_check() -> None:
    """Pobiera publiczne IP WAN i geolokalizacje, zapisuje do internet_wan."""
    wan = check_wan_ip()
    g_wan_ok.set(1 if wan["ok"] else 0)
    _save("internet_wan", "internet", wan)
    if wan["ok"]:
        logger.info("WAN: ip=%s kraj=%s miasto=%s isp=%s",
                    wan.get("ip"), wan.get("country"), wan.get("city"), wan.get("org"))
    else:
        logger.warning("WAN lookup blad: %s", wan.get("err"))


def main() -> None:
    logger.info("Netdoc Internet Worker start — checks co %ds, speed co %ds, wan co %ds, metrics :%d",
                CHECK_INTERVAL_S, SPEED_INTERVAL_S, WAN_INTERVAL_S, METRICS_PORT)
    init_db()
    start_http_server(METRICS_PORT)

    last_speed = -SPEED_INTERVAL_S   # uruchom test predkosci od razu przy starcie
    last_wan   = -WAN_INTERVAL_S     # pobierz WAN IP od razu przy starcie

    while True:
        run_checks()

        now_mono = time.monotonic()
        if now_mono - last_speed >= SPEED_INTERVAL_S:
            run_speed_test()
            last_speed = now_mono

        if now_mono - last_wan >= WAN_INTERVAL_S:
            run_wan_check()
            last_wan = now_mono

        time.sleep(CHECK_INTERVAL_S)


if __name__ == "__main__":
    main()
