"""
Discovery Module - skanowanie sieci i odkrywanie urzadzen.

Etapy:
  1. Ustal zakresy do skanowania:
     a) NETWORK_RANGES z .env (jesli podane)
     b) Auto-wykryte lokalne podsieci prywatne (psutil)
     c) Podsieci zapisane w tabeli discovered_networks
  2. Ping sweep (nmap -sn)
  3. Port scan aktywnych hostow
  4. OS + service fingerprinting
  5. Zapis/aktualizacja w bazie danych
"""
import hashlib
import json
import logging
import os
import re
import socket as _socket
import subprocess
import threading
import time
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timedelta

import nmap

from concurrent.futures import ThreadPoolExecutor, as_completed
from netdoc.collector.oui_lookup import oui_db
from sqlalchemy.orm import Session

from netdoc.collector.normalizer import DeviceData, normalize_mac
from netdoc.collector.network_detect import scan_local_interfaces, detect_local_networks, is_private
from netdoc.collector.snmp_walk import snmp_discover_networks, mask_to_prefix, _is_valid_private_ip
from netdoc.config.settings import settings
from netdoc.storage.models import (
    Device, DeviceType, Event, EventType,
    DiscoveredNetwork, NetworkSource, ScanResult,
    Credential, CredentialMethod,
)

logger = logging.getLogger(__name__)


def _read_nmap_settings() -> tuple:
    """Odczytuje ustawienia intensywnosci nmap z bazy danych.

    Zwraca (min_rate, version_intensity).
    Ustawienia sa zmieniane przez uzytkownika z panelu Ustawienia.
    Domyslnie: min_rate=100, version_intensity=1 (bezpieczne dla AP i urzadzen sieciowych).
    Niska wartosc min_rate zapobiega wieszaniu sie access pointow podczas skanu.
    """
    try:
        from netdoc.storage.database import SessionLocal
        from netdoc.storage.models import SystemStatus
        db = SessionLocal()
        try:
            def _i(key, default):
                row = db.query(SystemStatus).filter(SystemStatus.key == key).first()
                try:
                    return int(row.value) if (row and row.value not in (None, "")) else default
                except (ValueError, TypeError):
                    return default
            return (
                max(50,  min(5000, _i("nmap_min_rate",          100))),
                max(0,   min(9,    _i("nmap_version_intensity",    9))),
            )
        finally:
            db.close()
    except Exception:
        return 100, 1   # BUG-L3: bezpieczny fallback — intensity=9 moglo destabilizowac urzadzenia embedded


# Porty drukarek wykluczone z fazy version detection (-sV).
# TCP connect do 9100/515/631 moze spowodowac wydruk smieci na niektorych drukarkach
# (HP JetDirect reaguje na samo polaczenie TCP). Wykluczenie z -sV nie wplywa na
# wykrywanie urzadzenia jako drukarki — port nadal jest skanowany w fazie port scan.
# Nmap wyklucza 9100 z probowania przez domyslna dyrektywe Exclude w nmap-service-probes,
# ale konfiguracje uzytkownikow moga sie roznic — wiec filtrujemy jawnie w kodzie.
_PRINTER_PORTS_SKIP_VERSION: frozenset = frozenset([9100, 515, 631])


# ── Skanowanie partiami i wznawianie ─────────────────────────────────────────

# Plik stanu wznowienia — w katalogu glownym projektu (obok run_scanner.py).
# Przechowuje informacje o ukonczonych partiach portow miedzy uruchomieniami skanera.
_SCAN_STATE_PATH = Path(__file__).resolve().parent.parent.parent / "scan_progress.json"
# Plik zywy-status — krotki opis "partia X/Y [porty]" per IP, czytany przez API do tooltipow w UI.
_SCAN_BATCH_STATUS_PATH = Path(__file__).resolve().parent.parent.parent / "scan_batch_status.json"
_SCAN_STATE_LOCK = threading.Lock()

# Plik stanu wznowienia dla pelnego skanu 1-65535 (osobny, bo inna struktura danych).
_FULL_SCAN_STATE_PATH = Path(__file__).resolve().parent.parent.parent / "full_scan_progress.json"
_FULL_SCAN_STATE_LOCK = threading.Lock()


def _read_batch_scan_settings() -> dict:
    """Odczytuje ustawienia skanowania partiami i rownoleglosci z bazy."""
    try:
        from netdoc.storage.database import SessionLocal
        from netdoc.storage.models import SystemStatus
        db = SessionLocal()
        try:
            def _i(key, default):
                row = db.query(SystemStatus).filter(SystemStatus.key == key).first()
                try:
                    return int(row.value) if (row and row.value not in (None, "")) else default
                except (ValueError, TypeError):
                    return default

            def _f(key, default):
                row = db.query(SystemStatus).filter(SystemStatus.key == key).first()
                try:
                    return float(row.value) if (row and row.value not in (None, "")) else default
                except (ValueError, TypeError):
                    return default

            return {
                # 0 = bez limitu (jak dotychczas); > 0 = max N hostow jednoczesnie
                "concurrency":     max(0, _i("scan_concurrency",       0)),
                # 0 = wylaczone (jeden nmap dla wszystkich); > 0 = N portow na partie
                # Wspolne dla quick scan i full scan 1-65535
                "batch_size":      max(0, _i("scan_batch_size",      5000)),
                # Pauza miedzy partiami portow [s] — wspolna dla quick i full scan
                "batch_pause_s":   max(0.0, _f("scan_batch_pause_s",   3.0)),
                # 1 = wznawia od miejsca przerwania; 0 = zawsze od poczatku
                "resume_enabled":  bool(_i("scan_resume_enabled",       1)),
                # Portow na partie podczas pelnego skanu — to samo ustawienie co batch_size
                "full_port_batch": max(0, _i("scan_batch_size",      5000)),
            }
        finally:
            db.close()
    except Exception:
        return {"concurrency": 0, "batch_size": 5000, "batch_pause_s": 2.0, "resume_enabled": True, "full_port_batch": 5000}


def _compute_full_run_id(hosts: list, port_batch_size: int) -> str:
    """Hash identyfikujacy przebieg pelnego skanu.

    Zmiana hostow lub wielkosc partii = nowy run_id = brak wznowienia.
    """
    key = ",".join(sorted(hosts)) + f"|full_batch={port_batch_size}"
    return hashlib.sha256(key.encode()).hexdigest()[:14]


def _load_full_scan_state(run_id: str, all_hosts: list) -> dict:
    """Wczytuje stan wznowienia pelnego skanu.

    Zwraca dict {ip: {done_ranges: [...], found_ports: [int, ...]}}
    lub pusty dict gdy brak pliku / niezgodny run_id.
    """
    try:
        if not _FULL_SCAN_STATE_PATH.exists():
            return {}
        data = json.loads(_FULL_SCAN_STATE_PATH.read_text(encoding="utf-8"))
        if data.get("run_id") != run_id:
            logger.info("Full scan: nowy run_id (%s != %s) — ignoruje poprzedni stan",
                        run_id, data.get("run_id", "?"))
            return {}
        result = {}
        for ip in all_hosts:
            if ip in data.get("hosts", {}):
                h = data["hosts"][ip]
                result[ip] = {
                    "done_ranges": h.get("done_ranges", []),
                    "found_ports": [int(p) for p in h.get("found_ports", [])],
                }
        if result:
            logger.info("Full scan: wczytano stan dla %d hostow z poprzedniego przebiegu", len(result))
        return result
    except Exception as exc:
        logger.debug("_load_full_scan_state error: %s", exc)
        return {}


def _save_full_scan_state_host(run_id: str, ip: str, done_ranges: list, found_ports: list) -> None:
    """Thread-safe zapis stanu pojedynczego hosta do pliku pelnego skanu."""
    with _FULL_SCAN_STATE_LOCK:
        try:
            data = {"run_id": run_id, "hosts": {}}
            if _FULL_SCAN_STATE_PATH.exists():
                try:
                    loaded = json.loads(_FULL_SCAN_STATE_PATH.read_text(encoding="utf-8"))
                    if loaded.get("run_id") == run_id:
                        data = loaded
                    # else: nowy run_id — zaczynamy od czystego stanu (data juz = pusty dict)
                except (json.JSONDecodeError, ValueError):
                    # Uszkodzony plik — resetuj (zostanie nadpisany ponizej)
                    logger.debug("_save_full_scan_state_host: uszkodzony JSON, resetuje stan")
            data["run_id"] = run_id
            data.setdefault("hosts", {})[ip] = {
                "done_ranges": done_ranges,
                "found_ports": found_ports,
            }
            # Atomowy zapis: temp file + rename zapobiega obcinam pliku przy awarii
            _tmp = _FULL_SCAN_STATE_PATH.with_suffix(".tmp")
            _tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            _tmp.replace(_FULL_SCAN_STATE_PATH)
        except Exception as exc:
            logger.debug("_save_full_scan_state_host error: %s", exc)


def _clear_full_scan_state() -> None:
    """Usuwa plik stanu pelnego skanu po zakonczeniu."""
    with _FULL_SCAN_STATE_LOCK:
        try:
            if _FULL_SCAN_STATE_PATH.exists():
                _FULL_SCAN_STATE_PATH.unlink()
        except Exception:
            pass


def _make_full_port_range_batches(port_batch_size: int) -> list:
    """Dzieli zakres 1-65535 na partie jako stringi nmap.

    Przyklad: port_batch_size=5000 → ['1-5000', '5001-10000', ..., '65001-65535'].
    port_batch_size=0 → ['1-65535'] (jedna partia, brak podzialu).
    """
    if port_batch_size <= 0:
        return ["1-65535"]
    ranges = []
    start = 1
    while start <= 65535:
        end = min(start + port_batch_size - 1, 65535)
        ranges.append(f"{start}-{end}")
        start = end + 1
    return ranges


def _make_port_batches(port_list: list, batch_size: int) -> list:
    """Dzieli liste portow na partie po batch_size portow.

    Przyklad: 50 portow, batch_size=15 → 4 partie (15+15+15+5).
    Jesli batch_size=0 lub >= len(port_list) → jedna partia (bez podzialu).
    """
    if batch_size <= 0 or batch_size >= len(port_list):
        return [port_list]
    return [port_list[i:i + batch_size] for i in range(0, len(port_list), batch_size)]


def _compute_run_id(hosts: list, batch_size: int) -> str:
    """Hash identyfikujacy przebieg skanowania.

    Jesli te same hosty i ta sama konfiguracja — ten sam run_id → mozna wznowic.
    Jesli hosty sie zmienily (nowa siec) lub batch_size zmieniony → nowy run_id.
    """
    key = ",".join(sorted(hosts)) + f"|batch={batch_size}"
    return hashlib.sha256(key.encode()).hexdigest()[:14]


def _load_scan_state(run_id: str, port_batches: list) -> dict:
    """Wczytuje stan wznowienia z pliku lub zwraca pusty stan dla nowego przebiegu."""
    try:
        if _SCAN_STATE_PATH.exists():
            with open(_SCAN_STATE_PATH, "r", encoding="utf-8") as f:
                state = json.load(f)
            if state.get("run_id") == run_id:
                done_hosts = sum(
                    1 for h in state.get("hosts", {}).values()
                    if len(h.get("done_batches", [])) >= len(port_batches)
                )
                logger.info(
                    "Resume: wznawiam skan (run_id=%s). Gotowych hostow: %d/%d",
                    run_id, done_hosts, len(state.get("hosts", {}))
                )
                return state
            logger.info(
                "Resume: nowy run_id=%s (poprzedni=%s) — zaczynam od nowa",
                run_id, state.get("run_id", "?")
            )
    except Exception as exc:
        logger.warning("Resume: blad odczytu stanu skanowania: %s", exc)
    return {"run_id": run_id, "port_batches": [list(b) for b in port_batches], "hosts": {}}


def _save_scan_state(state: dict) -> None:
    """Zapisuje stan skanowania do pliku (thread-safe przez lock)."""
    try:
        with _SCAN_STATE_LOCK:
            with open(_SCAN_STATE_PATH, "w", encoding="utf-8") as f:
                json.dump(state, f)
    except Exception as exc:
        logger.warning("Resume: blad zapisu stanu skanowania: %s", exc)


def _clear_scan_state() -> None:
    """Usuwa plik stanu po pomyslnym zakonczeniu skanowania."""
    try:
        if _SCAN_STATE_PATH.exists():
            _SCAN_STATE_PATH.unlink()
            logger.debug("Resume: plik stanu usuniety po pomyslnym skanowaniu")
    except Exception:
        pass
    # Wyczysc rowniez live-status tooltipow
    try:
        if _SCAN_BATCH_STATUS_PATH.exists():
            _SCAN_BATCH_STATUS_PATH.unlink()
    except Exception:
        pass


def _update_batch_live_status(ip: str, batch_idx: int, total_batches: int, port_str: str) -> None:
    """Zapisuje aktualny progress skanowania per IP do pliku live-statusu.

    Plik czytany przez /api/scan/ip-batch-status → tooltips w UI.
    Thread-safe: uzywamy globalnego locka.
    """
    try:
        with _SCAN_STATE_LOCK:
            existing: dict = {}
            if _SCAN_BATCH_STATUS_PATH.exists():
                try:
                    existing = json.loads(_SCAN_BATCH_STATUS_PATH.read_text(encoding="utf-8"))
                except Exception:
                    existing = {}
            existing[ip] = {
                "batch": batch_idx + 1,
                "total": total_batches,
                "ports": port_str,
            }
            _SCAN_BATCH_STATUS_PATH.write_text(json.dumps(existing), encoding="utf-8")
    except Exception:
        pass


def _port_scan_one_host_batched(ip: str, port_batches: list,
                                batch_pause_s: float, nmap_rate: int, nmap_vi: int,
                                state: dict) -> dict:
    """Skanuje jeden host w partiach portow z pauzami miedzy partiami.

    Obsluguje wznawianie: partie juz zeskanowane (done_batches) sa pomijane.
    Zwraca host_data dict identyczny z port_scan():
      {"open_ports": {port: {service, version, product}}, "os": str|None, "vendor": str|None}
    """
    with _SCAN_STATE_LOCK:
        host_state = state["hosts"].setdefault(ip, {"done_batches": [], "open_ports": {}})
        # Kopiuj done_batches i open_ports bezpiecznie (poza lockiem bedziemy modyfikowac lokalnie).
        # JSON serializuje klucze jako stringi — konwertuj z powrotem na int (numery portow).
        done_set = set(host_state["done_batches"])
        accumulated = {int(k): v for k, v in host_state.get("open_ports", {}).items()}
    os_detected: str | None = None
    vendor_detected: str | None = None

    for batch_idx, batch_ports in enumerate(port_batches):
        if batch_idx in done_set:
            logger.info("Resume: %s — partia %d/%d pominięta (juz zeskanowana)",
                        ip, batch_idx + 1, len(port_batches))
            continue

        port_str = ",".join(str(p) for p in batch_ports)
        logger.info("Batch scan: %s — partia %d/%d porty [%s]",
                    ip, batch_idx + 1, len(port_batches), port_str)
        _update_batch_live_status(ip, batch_idx, len(port_batches), port_str)

        nm = nmap.PortScanner(nmap_search_path=_NMAP_SEARCH_PATH)
        try:
            nm.scan(hosts=ip,
                    arguments=f"-p {port_str} -sV --version-intensity {nmap_vi} "
                               f"-O --min-rate {nmap_rate}")
        except UnicodeDecodeError as exc:
            # nmap na Windows zwraca bajty CP1250 (np. ³) w nazwach serwisów mimo XML UTF-8.
            # Ponów bez -sV — tracimy wersję serwisu, ale zachowujemy stany portów.
            logger.warning("Batch scan: %s partia %d — encoding error: %s — retry bez -sV", ip, batch_idx + 1, exc)
            try:
                nm2 = nmap.PortScanner(nmap_search_path=_NMAP_SEARCH_PATH)
                nm2.scan(hosts=ip, arguments=f"-p {port_str} --min-rate {nmap_rate}")
                if ip in nm2.all_hosts() and "tcp" in nm2[ip]:
                    for port, info in nm2[ip]["tcp"].items():
                        if info["state"] == "open":
                            accumulated[port] = {"service": info.get("name", ""),
                                                 "version": "", "product": ""}
            except Exception as retry_exc:
                logger.debug("Batch scan: %s partia %d — retry bez -sV nieudany: %s", ip, batch_idx + 1, retry_exc)
        except nmap.PortScannerError as exc:
            logger.warning("Batch scan: %s partia %d — nmap error: %s", ip, batch_idx + 1, exc)
        else:
            if ip in nm.all_hosts():
                if "tcp" in nm[ip]:
                    for port, info in nm[ip]["tcp"].items():
                        if info["state"] == "open":
                            accumulated[port] = {
                                "service": info.get("name", ""),
                                "version": info.get("version", ""),
                                "product": info.get("product", ""),
                            }
                if os_detected is None and nm[ip].get("osmatch"):
                    os_detected = nm[ip]["osmatch"][0].get("name")
                if vendor_detected is None and nm[ip].get("vendor"):
                    vendor_detected = next(iter(nm[ip]["vendor"].values()), None)

        # Aktualizuj stan po kazdej partii (takze po bledzie — notujemy jako wykonana)
        with _SCAN_STATE_LOCK:
            host_state["done_batches"].append(batch_idx)
            host_state["open_ports"] = accumulated
        _save_scan_state(state)

        # Pauza miedzy partiami (nie po ostatniej)
        if batch_idx < len(port_batches) - 1 and batch_pause_s > 0:
            logger.info("Batch scan: %s — pauza %.1fs po partii %d/%d",
                        ip, batch_pause_s, batch_idx + 1, len(port_batches))
            time.sleep(batch_pause_s)

    return {"open_ports": accumulated, "os": os_detected, "vendor": vendor_detected}


def ssdp_scan(timeout: float = 4.0) -> dict:
    """SSDP/UPnP multicast discovery — zwraca {ip: {server, location, usn, st}}.

    Wysyla M-SEARCH na 239.255.255.250:1900 (UDP multicast) i zbiera odpowiedzi.
    Odkrywa routery, NAS, IoT, smart TV, drukarki bez aktywnego skanowania TCP.
    Szybki: pierwsze urzadzenia odpowiadaja w < 1s.
    """
    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 3\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()
    results: dict = {}
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM, _socket.IPPROTO_UDP)
        sock.setsockopt(_socket.IPPROTO_IP, _socket.IP_MULTICAST_TTL, 4)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        sock.settimeout(0.5)
        sock.sendto(msg, (SSDP_ADDR, SSDP_PORT))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                if ip in results:
                    continue
                text = data.decode("utf-8", errors="replace")
                meta: dict = {}
                for line in text.splitlines():
                    low = line.lower()
                    if low.startswith("server:"):
                        meta["server"] = line[7:].strip()
                    elif low.startswith("location:"):
                        meta["location"] = line[9:].strip()
                    elif low.startswith("usn:"):
                        meta["usn"] = line[4:].strip()
                    elif low.startswith("st:"):
                        meta["st"] = line[3:].strip()
                results[ip] = meta
                logger.debug("SSDP: %s -> %s", ip, meta.get("server", "?"))
            except _socket.timeout:
                pass
        sock.close()
        if results:
            logger.info("SSDP discovery: %d urzadzen odpowiedzialo", len(results))
    except Exception as exc:
        logger.debug("SSDP scan blad: %s", exc)
    return results


def nbns_scan(timeout: float = 2.0) -> dict:
    """NetBIOS Name Service — zwraca {ip: netbios_name}.

    Wysyla NBSTAT broadcast na 255.255.255.255:137 (UDP).
    Odpowiadaja: Windows, NAS (Synology/QNAP z SMB), drukarki HP/Brother/Xerox.
    Uzupelnia ping sweep o hosty z ICMP DROP + daje hostname bezposrednio.
    """
    HEADER = b'\xa8\x6e\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00'
    NBNAME = b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00'
    QUESTION = NBNAME + b'\x00\x21\x00\x01'
    packet = HEADER + QUESTION

    results: dict = {}
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        sock.settimeout(0.4)
        sock.sendto(packet, ("255.255.255.255", 137))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(1024)
                ip = addr[0]
                if ip in results or len(data) < 57:
                    continue
                num_names = data[56]
                if len(data) >= 57 + num_names * 18:
                    raw_name = data[57:72].decode("ascii", errors="replace").rstrip()
                    name_type = data[72]
                    if name_type == 0x00:
                        name = raw_name.strip()
                        if name and name != "*":
                            results[ip] = name
                            logger.debug("NBNS: %s -> %s", ip, name)
            except _socket.timeout:
                pass
        sock.close()
    except Exception as exc:
        logger.debug("NBNS scan blad: %s", exc)
    if results:
        logger.info("NBNS discovery: %d urzadzen odpowiedzialo", len(results))
    return results


def mdns_scan(timeout: float = 3.0) -> dict:
    """mDNS (Multicast DNS) — zwraca {ip: {"hostname": str, "services": [str]}}.

    Wysyla zapytanie PTR na 224.0.0.251:5353.
    Odpowiadaja: macOS, Linux/Avahi, AirPrint, Android, Synology/QNAP z mDNS,
    Chromecast, smart TV, Raspberry Pi, IoT z Bonjour.
    Daje hostname (.local) i wskazniki uslug do _guess_device_type().
    """
    MDNS_ADDR = "224.0.0.251"
    MDNS_PORT = 5353

    def _encode_name(name: str) -> bytes:
        out = b""
        for label in name.split("."):
            enc = label.encode("ascii")
            out += bytes([len(enc)]) + enc
        return out + b"\x00"

    qname = _encode_name("_services._dns-sd._udp.local")
    query = (b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
             + qname + b'\x00\x0c\x00\x01')

    results: dict = {}
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM, _socket.IPPROTO_UDP)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        sock.setsockopt(_socket.IPPROTO_IP, _socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.5)
        sock.sendto(query, (MDNS_ADDR, MDNS_PORT))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                if not is_private(ip):
                    continue
                entry = results.setdefault(ip, {"hostname": None, "services": []})
                m = re.search(rb'([\w][\w\-]{1,62})\.local', data)
                if m and not entry["hostname"]:
                    candidate = m.group(1).decode("ascii", errors="replace")
                    if not candidate.startswith("_"):
                        entry["hostname"] = candidate
                for svc in (b"_airprint", b"_ipp", b"_printer", b"_ssh", b"_afp",
                            b"_smb", b"_http", b"_googlecast", b"_nvstream",
                            b"_device-info", b"_raop", b"_daap"):
                    if svc in data and svc.decode() not in entry["services"]:
                        entry["services"].append(svc.decode())
                logger.debug("mDNS: %s hostname=%s svc=%s",
                             ip, entry["hostname"], entry["services"])
            except _socket.timeout:
                pass
        sock.close()
    except Exception as exc:
        logger.debug("mDNS scan blad: %s", exc)
    if results:
        logger.info("mDNS discovery: %d urzadzen odpowiedzialo", len(results))
    return results


def wsd_scan(timeout: float = 3.0) -> dict:
    """WS-Discovery (UDP 3702) — zwraca {ip: {"xaddrs": [str], "types": str}}.

    Wysyla Probe na multicast 239.255.255.250:3702 (WSD/DPWS).
    Odpowiadaja: drukarki HP/Canon/Epson/Ricoh/Konica, kamery IP Axis/Bosch/Hikvision,
    kopiarki, Windows hosts z WSD (Print Spooler), skanery sieciowe.
    Uzupelnia SSDP o urzadzenia z WSD (bez UPnP/SSDP), szczegolnie drukarki biurowe.
    """
    import uuid as _uuid

    WSD_MULTICAST = "239.255.255.250"
    WSD_PORT = 3702
    msg_id = str(_uuid.uuid4())
    probe = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope '
        'xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        '<soap:Header>'
        '<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
        f'<wsa:MessageID>uuid:{msg_id}</wsa:MessageID>'
        '<wsa:Action>'
        'http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe'
        '</wsa:Action>'
        '</soap:Header>'
        '<soap:Body><wsd:Probe/></soap:Body>'
        '</soap:Envelope>'
    ).encode("utf-8")

    results: dict = {}
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM, _socket.IPPROTO_UDP)
        sock.setsockopt(_socket.IPPROTO_IP, _socket.IP_MULTICAST_TTL, 4)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        sock.settimeout(0.5)
        sock.sendto(probe, (WSD_MULTICAST, WSD_PORT))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(65535)
                ip = addr[0]
                if ip in results:
                    continue
                text = data.decode("utf-8", errors="replace")
                # XAddrs zawiera URL z IP urzadzenia: "http://192.168.1.10:3911/wsd"
                xaddrs_raw = re.findall(r'<[^>]*XAddrs[^>]*>([^<]+)</', text)
                types_raw = re.findall(r'<[^>]*Types[^>]*>([^<]+)</', text)
                meta = {
                    "xaddrs": xaddrs_raw[0].split() if xaddrs_raw else [],
                    "types": types_raw[0] if types_raw else "",
                }
                results[ip] = meta
                logger.debug("WSD: %s -> types=%s", ip, meta["types"][:80])
            except _socket.timeout:
                pass
    except Exception as exc:
        logger.debug("WSD scan blad: %s", exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    if results:
        logger.info("WS-Discovery: %d urzadzen odpowiedzialo", len(results))
    return results


def apipa_from_arp() -> dict:
    """Wykrywa hosty z adresami APIPA (169.254.x.x) z lokalnej tablicy ARP.

    Adresy 169.254.0.0/16 (RFC 3927) sa automatycznie przydzielane przez OS
    gdy brak serwera DHCP lub brak odpowiedzi DHCP — "IPv4 Link-Local".
    Wskazuje na: problem z DHCP, izolowane urzadzenia OT/IoT, statyczne
    konfiguracje na kamerach/PLC bez bramy, lub nowe urzadzenie bez konfiguracji.
    Zwraca {ip: mac}.
    """
    APIPA_PREFIX = "169.254."
    arp = read_arp_table()
    apipa = {ip: mac for ip, mac in arp.items() if ip.startswith(APIPA_PREFIX)}
    if apipa:
        logger.info(
            "APIPA (169.254.x.x): %d urzadzen bez DHCP — mozliwy problem z DHCP lub "
            "urzadzenie OT/IoT ze statyczna konfiguracja link-local",
            len(apipa),
        )
    return apipa


def check_dns_responds(ip: str, timeout: float = 2.0) -> dict:
    """Aktywna weryfikacja serwera DNS — wysyla UDP query i analizuje odpowiedz.

    Wysyla standardowe DNS A query z bitem RD=1 (Recursion Desired) dla
    nieistniejacego hostname. Rozroznia:
      - recursive resolver (open DNS, Pi-hole, Windows DNS): RCODE 0/3 + RA=1
      - authoritative-only (internal zone DNS): RA=0
      - REFUSED (5): serwer aktywny ale odmawia external queries
      - brak odpowiedzi: nie jest DNS lub firewall blokuje UDP 53

    Zwraca {"responds": bool, "recursive": bool, "rcode": int}.
    """
    # Minimalne DNS query: A record dla "scan.netdoc.local" (nie istnieje w DNS)
    # Flags: QR=0, Opcode=0 (QUERY), RD=1
    query = (
        b"\xab\xcd"   # Transaction ID
        b"\x01\x00"   # Flags: standard query, Recursion Desired=1
        b"\x00\x01"   # QDCOUNT = 1
        b"\x00\x00"   # ANCOUNT = 0
        b"\x00\x00"   # NSCOUNT = 0
        b"\x00\x00"   # ARCOUNT = 0
        b"\x04scan\x06netdoc\x05local\x00"  # QNAME: scan.netdoc.local.
        b"\x00\x01"   # QTYPE = A
        b"\x00\x01"   # QCLASS = IN
    )
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (ip, 53))
        data, _ = sock.recvfrom(512)
        if len(data) < 12 or data[0:2] != b"\xab\xcd":
            return {"responds": False, "recursive": False, "rcode": -1}
        flags = int.from_bytes(data[2:4], "big")
        if not (flags >> 15) & 1:  # QR bit musi byc 1 (to jest odpowiedz)
            return {"responds": False, "recursive": False, "rcode": -1}
        is_ra = bool((flags >> 7) & 1)  # RA = Recursion Available
        rcode = flags & 0xF             # RCODE: 0=NOERROR, 3=NXDOMAIN, 5=REFUSED
        return {"responds": True, "recursive": is_ra, "rcode": rcode}
    except Exception:
        return {"responds": False, "recursive": False, "rcode": -1}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def ldap_query_rootdse(ip: str, timeout: float = 3.0) -> dict:
    """LDAP anonymous bind do rootDSE — zwraca metadane domeny Active Directory.

    rootDSE w Windows AD jest zawsze dostepne bez uwierzytelnienia (RFC 4512).
    Wysyla minimalne BER-encoded SearchRequest (baseObject="", scope=base)
    z atrybutami defaultNamingContext i dnsHostName.
    Parsuje odpowiedz regexem — szuka wzorca DC=domena,DC=tld.

    Dziala rowniez z Samba 4 AD DC na Linux/FreeBSD.

    Zwraca {"domain": "firma.local", "dc_hostname": "dc01.firma.local"}
    lub {} jesli brak odpowiedzi, non-AD LDAP lub blad polaczenia.
    """
    def _ber_len(n):
        if n < 0x80:
            return bytes([n])
        return bytes([0x81, n]) if n < 0x100 else bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

    def _tlv(tag, val):
        b = val if isinstance(val, (bytes, bytearray)) else val.encode()
        return bytes([tag]) + _ber_len(len(b)) + b

    # Atrybuty do odpytania
    attrs = _tlv(0x30,
        _tlv(0x04, b"defaultNamingContext") +
        _tlv(0x04, b"dnsHostName"))

    # SearchRequest body
    search_body = (
        _tlv(0x04, b"")           # baseObject = "" → rootDSE
        + b"\x0a\x01\x00"        # scope = baseObject (0)
        + b"\x0a\x01\x00"        # derefAliases = neverDeref (0)
        + b"\x02\x01\x00"        # sizeLimit = 0
        + b"\x02\x01\x00"        # timeLimit = 0
        + b"\x01\x01\x00"        # typesOnly = FALSE
        + _tlv(0x87, b"objectClass")  # filter: present(objectClass)
        + attrs
    )
    # LDAPMessage: SEQUENCE { messageID=1, SearchRequest [APPLICATION 3] }
    ldap_msg = _tlv(0x30, b"\x02\x01\x01" + _tlv(0x63, search_body))

    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 389))
        sock.sendall(ldap_msg)
        data = b""
        while len(data) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        if not data:
            return {}
        # Parsuj odpowiedz — szukaj DC=xxx,DC=yyy (naming context)
        text = data.decode("latin-1", errors="replace")
        nc_idx = text.find("defaultNamingContext")
        domain = ""
        if nc_idx >= 0:
            segment = text[nc_idx: nc_idx + 200]
            nc_m = re.search(r"(?i)(DC=[A-Za-z0-9-]+(?:,DC=[A-Za-z0-9-]+)+)", segment)
            if nc_m:
                dc_parts = re.findall(r"(?i)DC=([A-Za-z0-9-]+)", nc_m.group(1))
                domain = ".".join(dc_parts)
        # Parsuj dnsHostName
        hn_idx = text.find("dnsHostName")
        dc_hostname = ""
        if hn_idx >= 0:
            segment = text[hn_idx: hn_idx + 120]
            hn_m = re.search(r"\b([A-Za-z0-9-]+\.[A-Za-z0-9][A-Za-z0-9.-]+)\b", segment)
            if hn_m:
                dc_hostname = hn_m.group(1)
        if not domain and not dc_hostname:
            return {}
        result: dict = {}
        if domain:
            result["domain"] = domain
        if dc_hostname:
            result["dc_hostname"] = dc_hostname
        return result
    except Exception:
        return {}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def reverse_dns_lookup(ips: list, timeout: float = 2.0) -> dict:
    """Masowy odwrotny DNS (PTR lookup) — zwraca {ip: hostname}.

    Uzywa socket.gethostbyaddr() z rownolegloscia watkow (max 24).
    Serwery, drukarki i sprzet sieciowy prawie zawsze maja rekordy PTR w DNS.
    """
    def _lookup(ip):
        try:
            hostname, _, _ = _socket.gethostbyaddr(ip)
            short = hostname.split(".")[0] if "." in hostname else hostname
            return ip, short
        except Exception:
            return ip, None

    results = {}
    if not ips:
        return results
    # gethostbyaddr() na Windows moze trwac 3-5s per IP gdy brak PTR rekordu.
    # Timeout dla as_completed: minimum 30s lub 1.5s per host (rownoleglosc = szybciej).
    _as_timeout = max(30.0, len(ips) * 1.5)
    with ThreadPoolExecutor(max_workers=min(len(ips), 24)) as pool:
        futures = {pool.submit(_lookup, ip): ip for ip in ips}
        try:
            for future in as_completed(futures, timeout=_as_timeout):
                try:
                    ip, name = future.result(timeout=timeout + 1)
                    if name:
                        results[ip] = name
                        logger.debug("PTR: %s -> %s", ip, name)
                except Exception:
                    pass
        except TimeoutError:
            # Czesc wyszukiwan nie zdazyla — zwracamy czesciowe wyniki bez crashu
            logger.debug("reverse_dns_lookup: timeout (%ds) — %d/%d IP rozwiazanych",
                         _as_timeout, len(results), len(ips))
    if results:
        logger.info("Reverse DNS: %d/%d IP ma PTR rekord", len(results), len(ips))
    return results


# Porty do skanowania — siec, serwery, bazy, VPN, monitoring
TARGET_PORTS = ",".join([
    # Siec i zarzadzanie
    "22", "23", "80", "443", "161", "830", "8080", "8443",
    # Bazy danych
    "1433", "1521", "3306", "5432", "6379", "27017",
    # Uslugi serwerowe
    "21", "25", "53", "110", "143", "389", "445", "636", "3389", "5985", "5986",
    # Active Directory / Kerberos / LDAP Global Catalog
    "88", "3268", "3269",
    # Windows / NetBIOS / MSRPC (fingerprint OS, workstation vs server)
    "135", "139",
    # VPN / tunele
    "500", "1194", "1701", "1723", "4500",
    # Monitoring / DevOps
    "514", "2055", "9100", "9200", "2376", "2379", "6443", "8888",
    # OT / Modbus
    "502",
    # UPnP/SSDP (1900) — rozglos urzadzen IoT, router, NAS, smart TV
    "1900",
    # Drukarki sieciowe: LPD (515), IPP (631), JetDirect juz jest (9100)
    "515", "631",
    # Apple Bonjour / mDNS (5353) — wykrywanie MacOS / iOS / AirPrint
    "5353",
    # Intel AMT (623, 16992) — workstation klasy enterprise z vPro
    "623", "16992",
    # Kamery IP / streaming video
    "554",   # RTSP — silny sygnał kamery/NVR
    "8554",  # RTSP alternate (kamery Reolink, TP-Link, generic)
    "37777", # Dahua DVR/NVR/kamera — protokół proprietary
    "34567", # XMEye / generic H.264 DVR/NVR (Annke, Qvis, Raidon itd.)
    "1935",  # RTMP — streaming serwer / niektóre kamery
    "8000",  # Dahua HTTP management / kamery IoT
])

# Absolutne sciezki do nmap — dziala niezaleznie od PATH (Git Bash, NSSM, etc.)
_NMAP_SEARCH_PATH = (
    "C:/Program Files (x86)/Nmap/nmap.exe",
    "C:/Program Files/Nmap/nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "nmap",
)


def lookup_vendor_from_mac(mac):
    """Zwraca nazwe producenta na podstawie adresu MAC (OUI lookup).
    Korzysta z bazy IEEE MA-L/MA-M/MA-S + manuf fallback.
    """
    return oui_db.lookup(mac)



def _is_laa_mac(mac: str) -> bool:
    """Zwraca True jesli MAC ma ustawiony bit Locally Administered (bit 1 pierwszego oktetu).

    LAA MAC (np. 26:12:AC:...) wskazuje na MAC wirtualny, randomizowany lub nadany
    przez oprogramowanie (Docker bridge, Hyper-V, VPN, Windows 11 MAC randomization).
    Nie jest to OUI producenta sprzetowego.
    """
    try:
        first_byte = int(mac.replace("-", ":").split(":")[0], 16)
        return bool(first_byte & 0x02)
    except Exception:
        return False


def read_arp_table(ignore_laa: bool = True) -> dict:
    """Czyta lokalna tablice ARP systemu operacyjnego.

    Zwraca slownik {ip: mac} dla dynamicznych wpisow.
    Dziala na Windows i Linux/macOS.

    ignore_laa: jesli True (domyslnie), pomija wpisy z MAC Locally Administered Address
    (wirtualne/randomizowane MAC — Docker, Hyper-V, Windows 11 privacy MAC).
    """
    arp_map = {}
    laa_skipped = 0
    try:
        out = subprocess.check_output(
            ["arp", "-a"], text=True, errors="replace", timeout=5
        )
        # Windows: "  192.168.1.1    aa-bb-cc-dd-ee-ff    dynamic"
        # Linux:   "192.168.1.1 ether aa:bb:cc:dd:ee:ff C eth0"
        for line in out.splitlines():
            m = re.search(
                r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
                r"\s+([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}"
                r"[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})",
                line,
            )
            if m and "dynamic" in line.lower() or (m and "ether" in line.lower()):
                mac_raw = normalize_mac(m.group(2))
                if ignore_laa and _is_laa_mac(mac_raw):
                    laa_skipped += 1
                    logger.debug("ARP: pomijam LAA MAC %s dla %s", mac_raw, m.group(1))
                    continue
                arp_map[m.group(1)] = mac_raw
    except Exception as exc:
        logger.debug("ARP table read failed: %s", exc)
    if laa_skipped:
        logger.info("ARP: pominięto %d wpisów z LAA MAC (wirtualne/randomizowane)", laa_skipped)
    return arp_map


def _is_infrastructure_cidr(cidr: str) -> bool:
    """Zwraca True dla zakresów infrastrukturalnych, które nie powinny być skanowane:
    - 172.16.0.0/12  — Docker bridge / overlay (172.16–172.31)
    - 100.64.0.0/10  — CGNAT / Tailscale / VPN (100.64–100.127)
    - 127.0.0.0/8    — loopback
    - 169.254.0.0/16 — link-local / APIPA
    """
    import ipaddress as _ip
    _INFRA = [
        _ip.IPv4Network("172.16.0.0/12"),
        _ip.IPv4Network("100.64.0.0/10"),
        _ip.IPv4Network("127.0.0.0/8"),
        _ip.IPv4Network("169.254.0.0/16"),
    ]
    try:
        net = _ip.IPv4Network(cidr, strict=False)
        return any(net.subnet_of(infra) or net.supernet_of(infra) for infra in _INFRA)
    except (ValueError, TypeError):
        return False


def _upsert_network(db, cidr, source):
    if _is_infrastructure_cidr(cidr):
        logger.debug("Pomijam infrastrukturalny zakres: %s (%s)", cidr, source.value if hasattr(source, 'value') else source)
        return None
    net = db.query(DiscoveredNetwork).filter(DiscoveredNetwork.cidr == cidr).first()
    if net is None:
        net = DiscoveredNetwork(cidr=cidr, source=source, is_active=True)
        db.add(net)
        logger.info("Nowa siec w rejestrze: %s (zrodlo: %s)", cidr, source.value)
    else:
        net.last_seen = datetime.utcnow()
        net.is_active = True
    db.commit()
    return net


def register_network(db, cidr, source=None):
    if source is None:
        source = NetworkSource.lldp
    _upsert_network(db, cidr, source)


def _read_discovery_overrides(db):
    """Odczytuje nadpisania konfiguracji odkrywania sieci z system_status.
    Zwraca (extra_ranges: list, include_vpn: bool, include_virtual: bool).
    Jesli wpis jest pusty — uzyw wartosci z .env / ustawien domyslnych."""
    try:
        from netdoc.storage.models import SystemStatus

        def _s(key):
            row = db.query(SystemStatus).filter(SystemStatus.key == key).first()
            return row.value if (row and row.value not in (None, "")) else None

        raw_ranges    = _s("network_ranges")
        raw_vpn       = _s("scan_vpn_networks")
        raw_virtual   = _s("scan_virtual_networks")
        raw_laa       = _s("ignore_laa_macs")

        extra_ranges  = [r.strip() for r in raw_ranges.split(",") if r.strip()] if raw_ranges else None
        include_vpn     = (raw_vpn     != "0") if raw_vpn     is not None else None
        include_virtual = (raw_virtual != "0") if raw_virtual is not None else None
        ignore_laa    = (raw_laa != "0")  if raw_laa is not None else None  # domyslnie True
        return extra_ranges, include_vpn, include_virtual, ignore_laa
    except Exception:
        return None, None, None, None


def get_scan_targets(db):
    targets = set()

    # Odczytaj ewentualne nadpisania z DB (ustawione przez panel Admin).
    # None oznacza "nie nadpisano — uzyj .env / ustawien domyslnych".
    db_ranges, db_vpn, db_virtual, _db_laa = _read_discovery_overrides(db)

    # Zakresy reczne: DB ma wyzszy priorytet niz .env gdy ustawione
    manual_ranges = db_ranges if db_ranges is not None else [c for c in settings.network_ranges_list if c]
    for cidr in manual_ranges:
        targets.add(cidr)
        _upsert_network(db, cidr, NetworkSource.manual)

    include_vpn     = db_vpn     if db_vpn     is not None else settings.scan_vpn_networks
    include_virtual = db_virtual if db_virtual is not None else settings.scan_virtual_networks

    # Auto-detect sieci z interfejsow hosta — zawsze, niezaleznie od NETWORK_RANGES.
    # Dzieki temu przelaczenie na inna siec (nowa karta, inna brama) jest wykrywane
    # automatycznie bez edycji .env.
    # Uwaga: skaner dziala na HOSCIE (nie w Dockerze), wiec psutil zwraca prawdziwe interfejsy.
    # Zakresy z NETWORK_RANGES i auto-detected sa ADDYTYWNE (nie wykluczaja sie).
    for cidr in detect_local_networks(
        include_vpn=include_vpn,
        include_virtual=include_virtual,
    ):
        if cidr not in targets:
            targets.add(cidr)
            _upsert_network(db, cidr, NetworkSource.auto)
            logger.info("Auto-detected new network: %s (added to scan targets)", cidr)
    for net in db.query(DiscoveredNetwork).filter(DiscoveredNetwork.is_active == True).all():
        if _is_infrastructure_cidr(net.cidr):
            logger.debug("Pomijam infrastrukturalny zakres z DB: %s", net.cidr)
            continue
        targets.add(net.cidr)
    if not targets:
        logger.error("No networks to scan! Set NETWORK_RANGES in .env or make sure the machine has a private IP address.")
    result = sorted(targets)
    logger.info("Scan targets (%d): %s", len(result), ", ".join(result))
    return result


_PING_PROBE_PORTS = [22, 80, 443, 23, 8080, 8443, 3389, 21, 554, 5000, 10000]
_PING_TCP_TIMEOUT = 1.0


def _tcp_reachable(ip: str) -> bool:
    """Sprawdza osiagalnosc przez TCP na popularnych portach (fallback dla ICMP DROP)."""
    import socket
    for port in _PING_PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=_PING_TCP_TIMEOUT):
                return True
        except OSError:
            pass
    return False


def _tcp_sweep_fallback(network_range: str) -> list:
    """TCP connect fallback gdy nmap jest niedostepny (np. Npcap nie jest jeszcze zaladowany).

    Sprawdza do 5 popularnych portow TCP dla kazdego hosta w podsieci.
    Timeout 0.2s per port — dzieki ThreadPoolExecutor skan /24 trwa ~3-8s.
    Uzywany automatycznie gdy nmap -sn rzuci PortScannerError.
    """
    import ipaddress
    _PROBE_PORTS = [80, 443, 22, 23, 8080]
    _TIMEOUT = 0.2

    def _is_up(ip: str) -> bool:
        for port in _PROBE_PORTS:
            try:
                with _socket.create_connection((ip, port), timeout=_TIMEOUT):
                    return True
            except OSError:
                pass
        return False

    try:
        net = ipaddress.IPv4Network(network_range, strict=False)
    except ValueError:
        return []

    # Sprawdz rozmiar sieci przed budowaniem listy IP (unikamy spiku pamieci dla /8-/16)
    if net.num_addresses > 2050:
        logger.warning(
            "TCP sweep fallback: siec %s zbyt duza (%d adresow) — pomijam.",
            network_range, net.num_addresses
        )
        return []

    all_ips = [str(ip) for ip in net.hosts()]
    if len(all_ips) > 2048:
        logger.warning(
            "TCP sweep fallback: siec %s zbyt duza (%d hostow) — pomijam.",
            network_range, len(all_ips)
        )
        return []

    with ThreadPoolExecutor(max_workers=128) as pool:
        results = list(pool.map(_is_up, all_ips))

    active = [ip for ip, up in zip(all_ips, results) if up]
    logger.info("TCP fallback sweep: %d aktywnych hostow w %s", len(active), network_range)
    return active


def ping_sweep(network_range):
    """Ping sweep przez nmap -sn (ARP/ICMP) + TCP fallback dla hostow z ICMP DROP.

    Hosty blokujace ICMP ale majace otwarte porty TCP (np. Windows z firewallem)
    beda wykryte przez TCP connect na popularnych portach.
    """
    logger.info("Ping sweep: %s", network_range)
    nm = nmap.PortScanner(nmap_search_path=_NMAP_SEARCH_PATH)
    # Uwaga: --min-rate z -sn destabilizuje timer Npcap na Windows (assertion
    # "htn.toclock_running == true") — uzyj -T4 zamiast --min-rate.
    # Przy przejsciowym bledzie Npcap (np. tuz po starcie systemu) ponawia raz.
    for attempt in range(2):
        try:
            nm.scan(hosts=network_range, arguments="-sn -T4")
            break
        except UnicodeDecodeError:
            logger.warning("Ping sweep: nmap output encoding error, pomijam")
            return []
        except nmap.PortScannerError as e:
            if attempt == 0:
                logger.warning(
                    "Ping sweep: nmap error dla %s (%s), ponawiam po 2s...",
                    network_range, e,
                )
                import time as _t; _t.sleep(2)
            else:
                logger.error(
                    "Ping sweep: nmap niedostepny dla %s (%s). Probuje TCP fallback...",
                    network_range, e,
                )
                return _tcp_sweep_fallback(network_range)
    active = [h for h in nm.all_hosts() if nm[h].state() == "up"]
    logger.info("Aktywne hosty (nmap): %d w %s", len(active), network_range)
    return active


def port_scan(hosts, _batch_settings: dict | None = None):
    """Skanuje porty na podanych hostach.

    Tryb klasyczny (domyslny, batch_size=0, concurrency=0):
      Jeden nmap call dla wszystkich hostow naraz — szybkie, jak dotychczas.

    Tryb z partiami i/lub limitem rownoleglosci (batch_size>0 lub concurrency>0):
      Kazdy host skanowany osobno przez _port_scan_one_host_batched().
      Porty dzielone na partie (batch_size portow), miedzy partiami pauza batch_pause_s.
      Maks. concurrency hostow jednoczesnie. Stan zapisywany do pliku — mozliwe wznowienie.
    """
    if not hosts:
        return {}

    nmap_rate, nmap_vi = _read_nmap_settings()

    if _batch_settings is None:
        _batch_settings = _read_batch_scan_settings()

    batch_size     = _batch_settings["batch_size"]
    batch_pause_s  = _batch_settings["batch_pause_s"]
    concurrency    = _batch_settings["concurrency"]
    resume_enabled = _batch_settings["resume_enabled"]

    # ── Tryb klasyczny: jeden nmap dla wszystkich hostow (dotychczasowe zachowanie) ──
    if batch_size == 0 and concurrency == 0:
        logger.info("Port scan: %d hostow (min-rate=%d version-intensity=%d) [tryb klasyczny]",
                    len(hosts), nmap_rate, nmap_vi)
        nm = nmap.PortScanner(nmap_search_path=_NMAP_SEARCH_PATH)
        try:
            nm.scan(hosts=" ".join(hosts),
                    arguments=f"-p {TARGET_PORTS} -sV --version-intensity {nmap_vi} "
                               f"-O --min-rate {nmap_rate}")
        except UnicodeDecodeError as exc:
            logger.warning("Port scan: nmap output encoding error: %s", exc)
            return {}
        except nmap.PortScannerError as exc:
            logger.warning("Port scan: nmap error, pomijam: %s", exc)
            return {}
        results = {}
        for host in nm.all_hosts():
            host_data = {"open_ports": {}, "os": None, "vendor": None}
            if "tcp" in nm[host]:
                for port, info in nm[host]["tcp"].items():
                    if info["state"] == "open":
                        host_data["open_ports"][port] = {
                            "service": info.get("name", ""),
                            "version": info.get("version", ""),
                            "product": info.get("product", ""),
                        }
            if nm[host].get("osmatch"):
                host_data["os"] = nm[host]["osmatch"][0].get("name", "")
            if nm[host].get("vendor"):
                host_data["vendor"] = next(iter(nm[host]["vendor"].values()), None)
            results[host] = host_data
        return results

    # ── Tryb z partiami / limitem rownoleglosci ──────────────────────────────────────
    port_list = [int(p) for p in TARGET_PORTS.split(",")]
    port_batches = _make_port_batches(port_list, batch_size)
    batch_count  = len(port_batches)
    max_workers  = concurrency if concurrency > 0 else len(hosts)

    logger.info(
        "Port scan: %d hostow, %d parti portow (batch_size=%d), "
        "pauza=%.1fs, max_workers=%d%s",
        len(hosts), batch_count, batch_size, batch_pause_s, max_workers,
        " [resume wlaczony]" if resume_enabled else ""
    )

    run_id = _compute_run_id(hosts, batch_size)
    state  = (_load_scan_state(run_id, port_batches)
              if resume_enabled
              else {"run_id": run_id, "port_batches": [list(b) for b in port_batches], "hosts": {}})

    results: dict = {}

    def _scan_one(ip: str):
        return ip, _port_scan_one_host_batched(
            ip, port_batches, batch_pause_s, nmap_rate, nmap_vi, state
        )

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_scan_one, ip): ip for ip in hosts}
        for future in as_completed(futures):
            ip_key = futures[future]
            try:
                ip_res, host_data = future.result()
                results[ip_res] = host_data
            except Exception as exc:
                logger.error("Port scan: nieoczekiwany blad dla %s: %s", ip_key, exc)

    _clear_scan_state()
    return results


# Liczba rownolegych procesow nmap podczas pelnego skanu.
# Kazdy wotek skanuje batch hostow — wiecej = szybciej, ale wieksze obciazenie sieci.
FULL_SCAN_WORKERS = 4
FULL_SCAN_BATCH_SIZE = 6  # hostow per worker


_NMAP_FULL_ARGS_FAST = "-p 1-65535 --min-rate 2000 --max-retries 1 -T4 --host-timeout 5m"
_NMAP_FULL_ARGS_SAFE = "-p 1-65535 --min-rate 500  --max-retries 1 -T3 --host-timeout 10m"


def _full_scan_one_group(hosts: list, port_batches: list, batch_pause_s: float = 3.0,
                         run_id: str | None = None,
                         host_states: dict | None = None) -> dict:
    """Skanuje grupe hostow przez wszystkie partie zakresu portow, potem -sV.

    port_batches: lista stringow nmap, np. ['1-5000', '5001-10000', ...].
    Kolejne partie skanowane sekwencyjnie z pauza batch_pause_s miedzy nimi.
    Po ukonczeniu wszystkich partii wykonuje version detection na otwartych portach.

    Jesli run_id i host_states sa podane, zapisuje stan po kazdej partii
    i pomija juz ukonczone zakresy (wznawianie po przerwie).
    """
    import time as _time

    if host_states is None:
        host_states = {}

    # Przywroc znalezione porty z poprzedniego przebiegu
    found_ports_by_host: dict = {}
    for h in hosts:
        prev = host_states.get(h, {}).get("found_ports", [])
        if prev:
            found_ports_by_host[h] = set(prev)

    total = len(port_batches)

    for i, port_range in enumerate(port_batches):
        # Pomijaj hosty, ktore juz skanowaly ten zakres
        pending = [
            h for h in hosts
            if port_range not in host_states.get(h, {}).get("done_ranges", [])
        ]
        if not pending:
            logger.info("Full scan: port batch %d/%d [%s] — skipping (already completed for all hosts)",
                        i + 1, total, port_range)
            continue

        logger.info(
            "Full scan: %d hosts — port batch %d/%d [%s]",
            len(pending), i + 1, total, port_range,
        )
        nm = nmap.PortScanner(nmap_search_path=_NMAP_SEARCH_PATH)
        try:
            nm.scan(hosts=" ".join(pending),
                    arguments=f"-p {port_range} --min-rate 2000 --max-retries 1 -T4")
        except Exception as exc:
            exc_str = str(exc)
            if "RTTVAR" in exc_str or exc_str.startswith("b'"):
                logger.debug("Full scan partia %s: blad parsowania (%s…) — retry -T3",
                             port_range, exc_str[:60])
                try:
                    nm.scan(hosts=" ".join(pending),
                            arguments=f"-p {port_range} --min-rate 500 --max-retries 1 -T3")
                except Exception as exc2:
                    logger.warning("Full scan partia %s: retry nieudany: %s", port_range, exc2)
                    if i < total - 1:
                        _time.sleep(batch_pause_s)
                    continue
            else:
                logger.warning("Full scan partia %s: blad nmap: %s", port_range, exc)
                if i < total - 1:
                    _time.sleep(batch_pause_s)
                continue

        for host in nm.all_hosts():
            if "tcp" in nm[host]:
                for p, info in nm[host]["tcp"].items():
                    if info["state"] == "open":
                        found_ports_by_host.setdefault(host, set()).add(p)

        # Zapisz stan po kazdej partii (dla kazdego oczekujacego hosta)
        if run_id:
            for h in pending:
                done = list(host_states.get(h, {}).get("done_ranges", [])) + [port_range]
                ports = list(found_ports_by_host.get(h, set()))
                host_states[h] = {"done_ranges": done, "found_ports": ports}
                _save_full_scan_state_host(run_id, h, done, ports)

        if i < total - 1:
            _time.sleep(batch_pause_s)

    # Version detection na wszystkich znalezionych portach
    # Porty drukarek (9100, 515, 631) sa wykluczone z -sV — zapobiega wydrukom smieci
    results: dict = {}
    hosts_with_ports = {h: list(ports) for h, ports in found_ports_by_host.items() if ports}
    if hosts_with_ports:
        all_ports = set(p for ports in hosts_with_ports.values() for p in ports)
        version_ports = all_ports - _PRINTER_PORTS_SKIP_VERSION
        port_str = ",".join(str(p) for p in sorted(version_ports)) if version_ports else ""
        nm2 = nmap.PortScanner(nmap_search_path=_NMAP_SEARCH_PATH)
        scan_ok = False
        if port_str:
            try:
                nm2.scan(hosts=" ".join(hosts_with_ports.keys()),
                         arguments=f"-p {port_str} -sV --min-rate 500")
                scan_ok = True
            except Exception as exc:
                logger.warning("Full scan version detection blad: %s — zachowuję porty z fazy 1", exc)
        if scan_ok:
            for host in nm2.all_hosts():
                host_data: dict = {"open_ports": {}}
                if "tcp" in nm2[host]:
                    for port, info in nm2[host]["tcp"].items():
                        if info["state"] == "open":
                            host_data["open_ports"][port] = {
                                "service": info.get("name", ""),
                                "version": info.get("version", ""),
                                "product": info.get("product", ""),
                            }
                results[host] = host_data
        else:
            # Fallback: zachowaj porty z fazy 1 (bez wersji) — nie kasuj danych przy błędzie -sV
            for host, ports in hosts_with_ports.items():
                results[host] = {"open_ports": {
                    str(p): {"service": "", "version": "", "product": ""} for p in ports
                }}
    return results


def _full_scan_batch(batch_hosts, _retry: bool = False):
    """Skanuje jeden batch hostow: najpierw 1-65535 (szybki), potem -sV na otwartych.

    Jesli nmap zwroci RTTVAR lub inny blad parsowania XML (czesto przy wolnych/opornych
    hostach z --min-rate 2000), ponawia probe z bardziej konserwatywnymi ustawieniami.
    """
    # Etap 1: odkryj otwarte porty
    nm = nmap.PortScanner(nmap_search_path=_NMAP_SEARCH_PATH)
    args = _NMAP_FULL_ARGS_SAFE if _retry else _NMAP_FULL_ARGS_FAST
    try:
        nm.scan(hosts=" ".join(batch_hosts), arguments=args)
    except Exception as exc:
        exc_str = str(exc)
        # RTTVAR lub pusty output (b'\r\n...'): ponow z lagodniejszymi parametrami
        if not _retry and ("RTTVAR" in exc_str or exc_str.startswith("b'")):
            logger.debug("Batch %s: blad parsowania nmap (%s...) — retry z -T3", batch_hosts[:1], exc_str[:60])
            return _full_scan_batch(batch_hosts, _retry=True)
        raise
    open_by_host = {}
    for host in nm.all_hosts():
        if "tcp" in nm[host]:
            open_by_host[host] = [p for p, i in nm[host]["tcp"].items() if i["state"] == "open"]

    # Etap 2: version detection tylko na znalezionych portach
    # Porty drukarek (9100, 515, 631) wykluczone z -sV — zapobiega wydrukom smieci
    results = {}
    hosts_with_ports = {h: ports for h, ports in open_by_host.items() if ports}
    if hosts_with_ports:
        all_ports = set(p for ports in hosts_with_ports.values() for p in ports)
        version_ports = all_ports - _PRINTER_PORTS_SKIP_VERSION
        port_str = ",".join(str(p) for p in sorted(version_ports)) if version_ports else ""
        nm2 = nmap.PortScanner(nmap_search_path=_NMAP_SEARCH_PATH)
        scan_ok = False
        if port_str:
            try:
                nm2.scan(hosts=" ".join(hosts_with_ports), arguments=f"-p {port_str} -sV --min-rate 500")
                scan_ok = True
            except Exception as exc:
                logger.warning("Full scan batch -sV blad: %s — zachowuję porty z fazy 1", exc)
        if scan_ok:
            for host in nm2.all_hosts():
                host_data = {"open_ports": {}}
                if "tcp" in nm2[host]:
                    for port, info in nm2[host]["tcp"].items():
                        if info["state"] == "open":
                            host_data["open_ports"][port] = {
                                "service": info.get("name", ""),
                                "version": info.get("version", ""),
                                "product": info.get("product", ""),
                            }
                results[host] = host_data
        else:
            for host, ports in hosts_with_ports.items():
                results[host] = {"open_ports": {
                    str(p): {"service": "", "version": "", "product": ""} for p in ports
                }}
    return results


def full_port_scan(hosts, workers=FULL_SCAN_WORKERS, batch_size=FULL_SCAN_BATCH_SIZE,
                   progress_callback=None):
    """Pelny skan portow TCP 1-65535 z rownolegloscia po stronie Pythona.

    Hosty dzielone sa na grupy (batch_size hostow), kazda grupa skanowana
    przez osobny watek. Zakres 1-65535 dzielony na partie portow
    wg ustawienia full_scan_port_batch_size z bazy (domyslnie 5000).
    Miedzy partiami portow stosowana pauza scan_batch_pause_s.

    progress_callback(done, total, batch_ips, batch_result) — wywolywane po zakonczeniu
    kazdego batcha hostow. batch_result to dict {ip: host_info} dla tego batcha.
    """
    if not hosts:
        return {}

    settings = _read_batch_scan_settings()
    port_batches   = _make_full_port_range_batches(settings["full_port_batch"])
    batch_pause_s  = settings["batch_pause_s"]
    resume_enabled = settings["resume_enabled"]

    run_id = _compute_full_run_id(hosts, settings["full_port_batch"])

    # Wczytaj stan poprzedniego przebiegu (jesli wznawianie wlaczone)
    host_states: dict = {}
    if resume_enabled:
        host_states = _load_full_scan_state(run_id, hosts)
        done_hosts = [
            h for h in hosts
            if len(host_states.get(h, {}).get("done_ranges", [])) >= len(port_batches)
        ]
        if done_hosts:
            logger.info("Full scan: %d hosts already fully completed — resume will skip them", len(done_hosts))

    batches = [hosts[i:i + batch_size] for i in range(0, len(hosts), batch_size)]
    logger.info(
        "Full port scan: %d hosts in %d groups of max %d (workers=%d) | "
        "port batches: %d x ~%d ports | pause: %.1fs | resume: %s",
        len(hosts), len(batches), batch_size, workers,
        len(port_batches), settings["full_port_batch"] or 65535, batch_pause_s,
        "on" if resume_enabled else "off",
    )

    results = {}
    done_count = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                _full_scan_one_group, batch, port_batches, batch_pause_s,
                run_id if resume_enabled else None,
                {h: host_states[h] for h in batch if h in host_states} if resume_enabled else None,
            ): batch
            for batch in batches
        }
        for future in as_completed(futures):
            batch = futures[future]
            done_count += 1
            batch_result = {}
            try:
                batch_result = future.result()
                results.update(batch_result)
                total_ports = sum(len(v.get("open_ports", {})) for v in batch_result.values())
                logger.info(
                    "Full scan grupa %d/%d gotowa — hosty: %s | "
                    "hosty z otwartymi portami: %d/%d | lacznie otwartych portow: %d",
                    done_count, len(batches),
                    ", ".join(batch),
                    len(batch_result), len(batch),
                    total_ports,
                )
            except Exception as exc:
                logger.warning("Blad grupy %s: %s", batch, exc)
            if progress_callback:
                try:
                    progress_callback(
                        done=done_count, total=len(batches),
                        batch_ips=batch, batch_result=batch_result,
                    )
                except Exception:
                    pass

    logger.info("Full port scan complete: %d hosts with open ports", len(results))
    if resume_enabled:
        _clear_full_scan_state()
    return results


def get_stale_full_scan_ips(db, max_age_days: int) -> list:
    """Zwraca liste IP aktywnych urzadzen bez aktualnego pelnego skanu portow.

    Stale = brak skanu 'nmap_full' lub najnowszy starszy niz max_age_days dni.
    """
    from datetime import datetime, timedelta
    from sqlalchemy import func, or_
    cutoff = datetime.utcnow() - timedelta(days=max_age_days)
    latest_full = (
        db.query(ScanResult.device_id, func.max(ScanResult.scan_time).label("last_full"))
        .filter(ScanResult.scan_type == "nmap_full")
        .group_by(ScanResult.device_id)
        .subquery()
    )
    stale = (
        db.query(Device.ip)
        .outerjoin(latest_full, Device.id == latest_full.c.device_id)
        .filter(
            Device.is_active == True,
            Device.no_full_scan == False,
            or_(latest_full.c.last_full.is_(None), latest_full.c.last_full < cutoff),
        )
        .all()
    )
    return [r.ip for r in stale]


def _persist_scan_batch(db, batch_result: dict) -> int:
    """Zapisuje wyniki jednego batcha full scan do DB natychmiast (checkpoint).

    Zwraca liczbe zapisanych urzadzen.
    """
    if not batch_result:
        return 0
    batch_ips = list(batch_result.keys())
    saved = 0
    for device in db.query(Device).filter(Device.ip.in_(batch_ips)).all():
        host_info = batch_result.get(device.ip)
        if host_info is None:
            # Host byl offline/timeout w trakcie skanu — zachowaj stare dane, zaloguj
            logger.debug("Full scan: %s nie w wynikach nmap (offline/timeout) — stare porty zachowane", device.ip)
            continue
        open_ports = host_info.get("open_ports", {})
        try:
            # Usuń stare wyniki nmap_full przed zapisaniem nowego — dane mają być aktualne
            # synchronize_session="fetch" — SQLAlchemy pobiera IDs i czyści identity map
            db.query(ScanResult).filter(
                ScanResult.device_id == device.id,
                ScanResult.scan_type == "nmap_full",
            ).delete(synchronize_session="fetch")
            db.add(ScanResult(
                device_id=device.id,
                scan_type="nmap_full",
                open_ports={str(p): info for p, info in open_ports.items()},
            ))
            if open_ports:
                _ports_int = {int(p) for p in open_ports.keys()}
                _ports_detail = {int(p): v for p, v in open_ports.items() if isinstance(v, dict)}
                new_type = _guess_device_type(
                    _ports_int, device.os_version, device.vendor, device.mac,
                    hostname=device.hostname, open_ports_detail=_ports_detail,
                )
                if new_type != DeviceType.unknown and new_type != device.device_type:
                    logger.info("Reklasyfikacja po full scan: %s %s -> %s",
                                device.ip, device.device_type.value, new_type.value)
                    device.device_type = new_type
            db.flush()  # wykryj blad per-device przed commitem calego batcha
            saved += 1
        except Exception as exc:
            logger.warning("_persist_scan_batch: blad dla %s: %s — pomijam ten host", device.ip, exc)
            db.rollback()
    try:
        db.commit()
    except Exception as exc:
        logger.error("_persist_scan_batch: commit nieudany: %s — rollback", exc)
        db.rollback()
    return saved


def run_full_scan(db, ips=None, progress_callback=None):
    """Pelen skan portow aktywnych urzadzen z checkpointami per batch.

    ips — opcjonalna lista IP do przeskanowania; None = wszystkie aktywne.
    progress_callback(done, total, batch_ips) — opcjonalny callback postępu.
    Wyniki zapisywane do DB po zakonczeniu kazdego batcha (checkpoint/resume).
    Jesli skan zostanie przerwany, kolejne uruchomienie pominie juz zeskanowane
    urzadzenia (get_stale_full_scan_ips zwroci tylko te bez aktualnego skanu).
    """
    if ips is not None:
        active_ips = list(ips)
    else:
        active_ips = [d.ip for d in db.query(Device).filter(Device.is_active == True).all()]
    if not active_ips:
        logger.info("Full scan: no active devices")
        return 0

    logger.info("Full scan: scanning %d devices: %s", len(active_ips), ", ".join(active_ips))
    saved_total = [0]

    def _on_batch(done, total, batch_ips, batch_result=None):
        if batch_result:
            try:
                count = _persist_scan_batch(db, batch_result)
                saved_total[0] += count
                logger.info("Checkpoint %d/%d: zapisano %d urzadzen", done, total, count)
            except Exception as exc:
                logger.error("_on_batch: blad zapisu checkpointu %d/%d: %s — pomijam batch", done, total, exc)
                try:
                    db.rollback()
                except Exception:
                    pass
        if progress_callback:
            try:
                progress_callback(done=done, total=total, batch_ips=batch_ips)
            except Exception:
                pass

    full_port_scan(active_ips, progress_callback=_on_batch)
    logger.info("Full scan zapisano lacznie: %d urzadzen", saved_total[0])
    return saved_total[0]


# Vendorzy sprzetu sieciowego (router/switch/AP/firewall)
_NETWORK_VENDORS = (
    "ubiquiti", "cisco", "juniper", "mikrotik", "fortinet", "aruba",
    "ruckus", "meraki", "netgear", "zyxel", "tp-link", "tplink",
    "draytek", "edgemax", "unifi", "moxa", "allied telesis",
    "extreme networks", "brocade", "huawei", "cambium", "mimosa",
    "peplink", "cradlepoint",
    # Przemyslowe urzadzenia sieciowe (industrial networking)
    "hirschmann", "westermo", "korenix", "atop technology",
    "red lion", "ewon", "anybus", "prosoft", "spectrum controls",
)

# Wzorce hostname dla sprzetu Ubiquiti (rozroznienie AP/switch/router)
# AP: U6-*, U7-*, UAP-*, U2-*, U5-*
_UBIQUITI_AP_PREFIXES = ("u6-", "u7-", "u5-", "u2-", "uap", "unifi ap")
# Switch: US-*, USW*, US8*, US16*, US24*, US48* (modele bez myslnika np. US860W, USWLite8PoE)
_UBIQUITI_SWITCH_PREFIXES = ("us-", "usw", "unifi switch", "us8", "us16", "us24", "us48")
# Router/gateway: UDM, USG, UDR, UniFi Dream
_UBIQUITI_ROUTER_PREFIXES = ("udm", "usg", "udr", "unifi dream", "unifi gateway")

# Vendorzy serwerow / komputerow
_SERVER_VENDORS = (
    "hewlett packard", "hp inc", "hewlettp", "dell", "ibm", "supermicro",
    "intel", "lenovo", "fujitsu", "oracle",
)

# Producenci kamer IP
_CAMERA_VENDORS = (
    "novus", "dahua", "hikvision", "axis", "hanwha", "vivotek",
    "bosch security", "pelco", "avigilon", "uniview", "tiandy",
    "reolink", "amcrest", "foscam", "lorex", "swann", "zhejiang",
    "surveillance", "cctv",
)

# NAS
_NAS_VENDORS = (
    "synology", "qnap", "western digital", "buffalo technology",
)

# IoT / smart home / industrial / embedded
_IOT_VENDORS = (
    "philips", "google", "amazon", "belkin", "tuya", "shelly",
    "sonoff", "lifx", "nest", "ring", "samsung smart", "ikea", "aqara",
    "camille bauer", "camillebaue", "camilleb",
    "jrc", "jrctokki",
    "siemens", "schneider", "abb ", "beckhoff", "wago",
    "phoenix contact", "advantech", "pepperl", "omron",
    "dexatek",
)

# Producenci falownikow PV i UPS z obsuga SunSpec/Modbus TCP
_INVERTER_VENDORS = (
    "sma solar", "fronius", "solaredge", "sungrow", "goodwe", "growatt",
    "victron", "fimer", "power-one", "abb", "huawei solar", "huawei pv",
    "schneider electric", "xantrex", "outback", "solax", "deye", "saj",
    "ginlong", "sofar", "enphase", "solis", "fronius schweiss",
)

# Drukarki sieciowe
_PRINTER_VENDORS = (
    "canon", "epson", "brother", "lexmark", "xerox",
    "kyocera", "ricoh", "konica", "oki data", "toshiba tec",
)
# Producenci laptopow / komputerow stacjonarnych
_WORKSTATION_VENDORS = (
    "apple",             # Mac (macOS — odrozniamy po OS fingerprint od iPhone)
    "lenovo",            # ThinkPad, IdeaPad, Legion
    "asus",              # VivoBook, ZenBook, ROG
    "acer",              # Aspire, Swift, Nitro
    "msi",               # Laptop gaming
    "razer",             # Razer Blade
    "toshiba",           # Dynabook (dawniej Toshiba)
    "panasonic",         # Toughbook (rugged)
    "getac",             # Getac rugged laptop
    "samsung electr",    # Samsung laptop (Galaxy Book)
    "microsoft",         # Surface Pro/Laptop
    "intel client",      # Intel NUC — "intel" jest już w _SERVER_VENDORS (wyższy priorytet)
)

# Producenci telefonow / tabletow (prawie wylacznie mobile)
_PHONE_VENDORS = (
    "oneplus",           # OnePlus telefony
    "oppo",              # OPPO / OnePlus / Realme (Guangdong OPPO)
    "vivo",              # Vivo (BBK Electronics)
    "realme",            # Realme
    "motorola",          # Motorola / Lenovo Mobile
    "htc",               # HTC
    "blackberry",        # BlackBerry / TCL
    "nothing technology",# Nothing Phone
    "fairphone",         # Fairphone
    "honor",             # Honor (dawniej Huawei Honor)
    "wiko",              # Wiko (popularne w PL)
    "cat comm",          # CAT (Bullitt Group — rugged phone)
    "sonim",             # Sonim rugged phone
    "crosscall",         # Crosscall rugged phone
    "ulefone",           # Ulefone (chiski OEM)
    "doogee",            # Doogee
    "blu products",      # BLU (popularne USA/LA)
)



def _resolve_vendor(vendor, mac):
    """Zwraca vendor_lower: najpierw z pola vendor, potem z manuf OUI lookup."""
    if vendor:
        return vendor.lower()
    if mac:
        mac_v = lookup_vendor_from_mac(mac)
        if mac_v:
            return mac_v.lower()
    return ""


def _get_default_gateways() -> set:
    """Zwraca zbior IP default gateway z tablicy routingu (Windows i Linux)."""
    gateways = set()
    try:
        # Linux / Mac: ip route show default
        r = subprocess.run(["ip", "route", "show", "default"],
                           capture_output=True, text=True, timeout=3)
        for m in re.finditer(r"default via (\d+\.\d+\.\d+\.\d+)", r.stdout):
            gateways.add(m.group(1))
    except Exception:
        pass
    if not gateways:
        try:
            # Windows: route print 0.0.0.0
            r = subprocess.run(["route", "print", "0.0.0.0"],
                               capture_output=True, text=True, timeout=3)
            for m in re.finditer(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", r.stdout):
                gateways.add(m.group(1))
        except Exception:
            pass
    if gateways:
        logger.debug("Wykryte bramy domyslne: %s", gateways)
    return gateways


def _guess_device_type(open_ports, os_name, vendor=None, mac=None, hostname=None,
                       open_ports_detail=None, mdns_services=None):
    """Heurystyczne wykrywanie typu urzadzenia.

    Parametry:
        open_ports:         set/iterable numerow portow (int)
        os_name:            string z OS fingerprint nmap (moze byc None)
        vendor:             nazwa producenta (string, moze byc None)
        mac:                MAC address (string, moze byc None)
        hostname:           hostname (string, moze byc None)
        open_ports_detail:  dict {port_int: {"product": ..., "service": ..., "version": ...}}
                            (opcjonalny — nmap JSON output z enriched info)
        mdns_services:      lista stringow z mdns_scan() np. ["_airprint","_ssh"]
                            (opcjonalny — wskazniki uslug mDNS)

    Kolejnosc priorytetow:
    0. mDNS service hints (airprint/ipp → drukarka, googlecast → iot, afp/raop → macOS)
    1. OS fingerprint nmap lub bannery portow (Cisco IOS, RouterOS, FortiOS, Windows, Linux)
    2. Kamera IP (vendor)
    3. Telefon / tablet (vendor)
    4. Drukarka — port 9100/515/631 lub vendor (przed vendorem HP/Dell!)
    5. NAS (vendor)
    6. Sprzet sieciowy (vendor/OUI) — Ubiquiti rozrozniany po hostname
    7. Falownik PV / SunSpec (port 502 lub vendor)
    8. IoT / industrial / smart home (vendor)
    9. Serwer/PC klasy enterprise (vendor HP/Dell + porty)
    10. Workstation — laptop/PC (vendor workstation lub port Windows bez serwera)
    11. Heurystyka portow bez vendora (NetBIOS/MSRPC → Windows, SSH → Linux)
    """
    mdns_services = mdns_services or []
    # 0. mDNS service hints — silne wskazniki zanim zbadamy porty i vendor
    _mdns_printer = any(s in mdns_services for s in ("_airprint", "_ipp", "_printer"))
    _mdns_mac     = any(s in mdns_services for s in ("_afp", "_afpovertcp", "_raop", "_daap"))
    _mdns_iot     = "_googlecast" in mdns_services or "_nvstream" in mdns_services
    if _mdns_printer:
        return DeviceType.printer
    if _mdns_iot:
        return DeviceType.iot
    os_lower = (os_name or "").lower()
    # Ustal vendor — z pola lub z OUI lookup
    vendor_lower = _resolve_vendor(vendor, mac)

    # Pre-oblicz sygnaly infrastrukturalne (DC i DNS) zanim zajdziemy w logike OS/vendor
    _has_kerberos = 88  in open_ports
    _has_ldap     = 389 in open_ports or 636 in open_ports
    _has_gc       = 3268 in open_ports or 3269 in open_ports  # AD Global Catalog
    _has_smb      = 445 in open_ports
    _has_dns      = 53  in open_ports
    # Domain Controller = Kerberos + (LDAP lub GC) + SMB — minimalne wymaganie AD
    _is_dc = _has_kerberos and (_has_ldap or _has_gc) and _has_smb

    # Wyciagnij dodatkowe sygnaly z bannerow portow (open_ports_detail)
    # Np. product="Microsoft Windows RPC" daje pewnosc Windows nawet bez OS fingerprint
    _banner_hint = ""
    if open_ports_detail:
        _all_products = " ".join(
            (p.get("product") or p.get("service") or "").lower()
            for p in open_ports_detail.values()
            if isinstance(p, dict)
        )
        if "microsoft windows" in _all_products:
            _banner_hint = "windows"
        elif "linux" in _all_products:
            _banner_hint = "linux"
        elif "apple" in _all_products or "macos" in _all_products:
            _banner_hint = "macos"
        elif "jetdirect" in _all_products or "printer" in _all_products:
            _banner_hint = "printer"
        elif "cisco" in _all_products or "ios xe" in _all_products:
            _banner_hint = "cisco"
        elif "active directory" in _all_products or "microsoft-ds" in _all_products or "kerberos" in _all_products:
            _banner_hint = "windows"

    # Polacz OS fingerprint z banner hint (OS fingerprint ma wyzszy priorytet)
    _effective_os = os_lower or _banner_hint

    # 1. OS fingerprint / banner — najpewniejszy sygnal
    if "cisco" in _effective_os or "junos" in _effective_os or "routeros" in _effective_os:
        return DeviceType.router
    if "fortinet" in _effective_os or "fortigate" in _effective_os or "fortios" in _effective_os:
        return DeviceType.firewall
    _is_apple_mobile = (
        ("ios" in _effective_os and any(x in _effective_os for x in ("apple", "iphone", "ipad", "darwin")))
        or "iphone os" in _effective_os
        or "ipad os" in _effective_os
        or "ipod" in _effective_os
    )
    if _is_apple_mobile:
        return DeviceType.phone
    if "android" in _effective_os:
        return DeviceType.phone
    if ("macos" in _effective_os or "mac os" in _effective_os or "mac os x" in _effective_os
            or _mdns_mac):
        # macOS: laptop/workstation (bez serwera) lub serwer z SSH/web
        _has_server_svc = any(p in open_ports for p in (22, 80, 443, 8080))
        return DeviceType.server if _has_server_svc else DeviceType.workstation

    # 1.5 Domain Controller (AD lub Samba) — Kerberos + LDAP/GC + SMB
    # Sprawdzamy PRZED ogolna klasyfikacja Windows/Linux — DC to konkretna rola.
    # Wyjątek: sprzet sieciowy (Cisco AAA, router z LDAP) moze miec te porty bez DC.
    if _is_dc and not any(v in vendor_lower for v in _NETWORK_VENDORS):
        return DeviceType.domain_controller

    _is_windows = ("windows" in _effective_os and not any(v in vendor_lower for v in _NETWORK_VENDORS))
    if _is_windows:
        # Rozroznij Windows Server od Windows stacji roboczej (10/11/7/8/XP)
        _is_win_server = any(v in _effective_os for v in (
            "windows server", "server 2003", "server 2008", "server 2012",
            "server 2016", "server 2019", "server 2022", "server 2025",
        ))
        _is_win_workstation = any(v in _effective_os for v in (
            "windows 10", "windows 11", "windows 7", "windows 8",
            "windows xp", "windows vista", "windows nt",
        ))
        _has_web    = any(p in open_ports for p in (80, 443, 8080, 8443))
        _has_rdp    = 3389 in open_ports
        _has_ssh    = 22 in open_ports
        _has_db     = any(p in open_ports for p in (1433, 3306, 5432, 1521))
        _has_amt    = any(p in open_ports for p in (623, 16992))  # Intel AMT vPro
        _has_hyper_v = 2179 in open_ports                          # Hyper-V vmrdp
        _netbios    = 139 in open_ports or 135 in open_ports
        # Windows Server → zawsze serwer
        if _is_win_server:
            return DeviceType.server
        # Windows workstation (10/11/7/8) → domyslnie workstation.
        # Wyjatki: baza danych lub Hyper-V sugeruja serwer mimo wersji desktopowej.
        # Web/SSH na stacji = IIS dev/WSL/local app — NIE klasyfikujemy jako server.
        if _is_win_workstation:
            if _has_db or _has_hyper_v:
                return DeviceType.server
            return DeviceType.workstation
        # Nieznana wersja Windows — uzyj heurystyki portow
        if _has_web or _has_ssh or _has_db or _has_hyper_v:
            return DeviceType.server
        # RDP + AMT (enterprise management) → workstation klasy biurowej
        if _has_rdp and _has_amt:
            return DeviceType.workstation
        # Same NetBIOS / MSRPC bez dodatkowych uslug → workstation
        if _netbios and not _has_web and not _has_ssh:
            return DeviceType.workstation
        # Windows z RDP ale bez web/SSH → workstation
        if _has_rdp and not _has_web and not _has_ssh:
            return DeviceType.workstation
        return DeviceType.server

    # 2. Kamera IP — port-based detection (przed vendor, bo daje pewność niezależną od OUI)
    #    554/8554 = RTSP: prawie wyłącznie kamery/NVR w sieciach biurowych/przemysłowych
    #    37777/37778 = Dahua proprietary, 34567 = XMEye/generyczne DVR/NVR
    #    Wyjątek: Cisco IOS (router) też ma 554 — ale ten przypadek jest już obsłużony wyżej
    _CAMERA_PORTS_STRONG = {554, 8554, 37777, 37778, 34567}
    # 2a-pre. NAS vendor = pewnik — sprawdź PRZED kamerami (Synology ma Surveillance Station na 554)
    if any(v in vendor_lower for v in _NAS_VENDORS):
        return DeviceType.nas
    _NAS_OS_HINTS_EARLY = ("diskstation", "synology", "dsm ", "qts ", "qnap",
                           "readynas", "freenas", "truenas", "nas4free", "openmediavault")
    if any(v in _effective_os for v in _NAS_OS_HINTS_EARLY):
        return DeviceType.nas

    if any(p in open_ports for p in _CAMERA_PORTS_STRONG):
        # Upewnij się że to nie serwer mediów (Linux z SSH + web = serwer)
        _likely_server = (22 in open_ports and (80 in open_ports or 443 in open_ports)
                          and "linux" in _effective_os)
        if not _likely_server:
            return DeviceType.camera

    # 2b. Kamera IP — vendor
    if any(v in vendor_lower for v in _CAMERA_VENDORS):
        return DeviceType.camera

    # 3. Telefon / tablet — vendor prawie wylacznie mobile
    if any(v in vendor_lower for v in _PHONE_VENDORS):
        return DeviceType.phone
    # iTunes WiFi Sync (62078) — absolutny pewnik iPhone/iPad bez OS fingerprint
    if 62078 in open_ports:
        return DeviceType.phone
    # Hostname wskazuje na iOS/Android gdy brak OS fingerprint
    _hostname_lower = (hostname or "").lower()
    if not _effective_os:
        if any(h in _hostname_lower for h in ("iphone", "ipad", "ipod")):
            return DeviceType.phone
        if any(_hostname_lower.startswith(h) for h in ("android-", "android_", "galaxy-", "galaxy_", "pixel-", "pixel_")):
            return DeviceType.phone
    # Apple vendor bez OS: rozroznij iPhone od Mac po portach
    # MacBook zawsze ma jakies otwarte porty (SSH/SMB/mDNS), iPhone zazwyczaj nie
    if "apple" in vendor_lower and not _effective_os:
        if any(h in _hostname_lower for h in ("iphone", "ipad", "ipod")):
            return DeviceType.phone
        _mac_ports = set(open_ports) - {5353, 5354}  # mDNS nie jest dowodem na Mac
        if not _mac_ports:
            return DeviceType.phone  # brak portow → prawie na pewno iPhone/iPad

    # 4. Drukarka — PRZED sprawdzaniem _SERVER_VENDORS (HP jest serwerem ale tez robi drukarki)
    #    Port 9100 (JetDirect) lub 515 (LPD) lub 631 (IPP) to bardzo silny sygnal drukarki.
    #    SSH (22) NIE dyskwalifikuje drukarki — HP/Xerox/Brother enterprise maja SSH management.
    #    Dyskwalifikuja tylko: Telnet serwer sieciowy (23), SMTP (25), RDP (3389), WinRM (5985).
    _printer_port = any(p in open_ports for p in (9100, 515, 631))
    _server_service = any(p in open_ports for p in (23, 25, 3389, 5985))
    if _printer_port and not _server_service:
        return DeviceType.printer
    # Vendor drukarki (Canon, Epson, Brother, Lexmark, Xerox, Kyocera, Ricoh itd.)
    if any(v in vendor_lower for v in _PRINTER_VENDORS):
        return DeviceType.printer
    # Hint z banneru (JetDirect / AirPrint w nmap product)
    if _banner_hint == "printer":
        return DeviceType.printer

    # 5. NAS — vendor OUI lub OS/SNMP sysDescr (Synology/QNAP nie zawsze maja OUI w bazie)
    if any(v in vendor_lower for v in _NAS_VENDORS):
        return DeviceType.nas
    _NAS_OS_HINTS = ("diskstation", "synology", "dsm ", "qts ", "qnap", "readynas", "freenas", "truenas", "nas4free", "openmediavault")
    if any(v in _effective_os for v in _NAS_OS_HINTS):
        return DeviceType.nas

    # 6. Sprzet sieciowy
    if any(v in vendor_lower for v in _NETWORK_VENDORS):
        if "fortinet" in vendor_lower or "sonicwall" in vendor_lower:
            return DeviceType.firewall
        # Ubiquiti: rozroznienie AP / switch / router po hostname
        if "ubiquiti" in vendor_lower:
            hostname_lower = (hostname or "").lower()
            if any(hostname_lower.startswith(p) for p in _UBIQUITI_AP_PREFIXES):
                return DeviceType.ap
            if any(hostname_lower.startswith(p) for p in _UBIQUITI_SWITCH_PREFIXES):
                return DeviceType.switch
            if any(hostname_lower.startswith(p) for p in _UBIQUITI_ROUTER_PREFIXES):
                return DeviceType.router
            # Ubiquiti bez pasujacego hostname — domyslnie AP (najczestszy typ)
            return DeviceType.ap
        return DeviceType.router

    # 7. Falownik PV / SunSpec vs. PLC/urzadzenia przemyslowe
    #    Port 502 = Modbus TCP — uzywany zarowno przez falowniki PV jak i PLC/sterowniki.
    #    Jesli vendor wskazuje na producenta PLC/IoT (Siemens, Beckhoff, Wago, Omron itd.),
    #    klasyfikujemy jako iot, nie inverter — nawet gdy port 502 jest otwarty.
    _is_pv_vendor  = any(v in vendor_lower for v in _INVERTER_VENDORS)
    _is_iot_vendor = any(v in vendor_lower for v in _IOT_VENDORS)
    if _is_pv_vendor and not _is_iot_vendor:
        return DeviceType.inverter
    if 502 in open_ports and not _is_iot_vendor and not vendor_lower:
        # Modbus bez vendora — prawdopodobnie falownik PV (domyslny przypadek)
        return DeviceType.inverter

    # 8. IoT / industrial / smart home (PLC, liczniki, sterowniki)
    if _is_iot_vendor:
        return DeviceType.iot

    # 9. Serwer/PC klasy enterprise (HP, Dell, Supermicro, IBM itd.)
    if any(v in vendor_lower for v in _SERVER_VENDORS):
        # Serwisow czysto serwerowych (baza danych, mail, WinRM) — zawsze serwer
        _has_server_specific = any(p in open_ports for p in (25, 1433, 3306, 5432, 1521, 5985, 5986))
        if _has_server_specific:
            return DeviceType.server
        # RDP lub NetBIOS (bez mail/db) → workstation klasy enterprise (HP EliteBook, Dell Latitude)
        # Sprawdzamy PRZED web portami bo stacja robocza moze miec IIS/WSL na 80/443
        _has_workstation_hint = 3389 in open_ports or (139 in open_ports and 445 in open_ports)
        if _has_workstation_hint:
            return DeviceType.workstation
        # Web lub SSH bez powyzszych → serwer (HP ProLiant, Dell PowerEdge)
        if 80 in open_ports or 443 in open_ports or 22 in open_ports:
            return DeviceType.server
        # Brak portow a wiemy ze to HP/Dell → server (np. bez skanu portow)
        return DeviceType.server

    # 10. Workstation po vendorze (Apple MacBook, Lenovo ThinkPad, Asus, Acer itd.)
    if any(v in vendor_lower for v in _WORKSTATION_VENDORS):
        _has_server_svc = any(p in open_ports for p in (22, 80, 443, 8080, 8443))
        if _has_server_svc:
            return DeviceType.server
        return DeviceType.workstation

    # 11. Heurystyka portow bez vendora / OS — ostatnia deska ratunku
    # NetBIOS/MSRPC bez linuxa → Windows workstation
    _has_msrpc   = 135 in open_ports
    _has_netbios = 139 in open_ports or 445 in open_ports
    if (_has_msrpc or _has_netbios) and "linux" not in _effective_os:
        _has_server_svc = any(p in open_ports for p in (22, 80, 443, 8080, 1433, 3306, 5432))
        return DeviceType.server if _has_server_svc else DeviceType.workstation

    # mDNS (5353) bez wiadomo co → Apple / IoT
    if 5353 in open_ports and not vendor_lower:
        return DeviceType.unknown  # za mało danych

    # Linux po portach (SSH, web)
    if "linux" in _effective_os:
        if 22 in open_ports and not (80 in open_ports or 443 in open_ports):
            return DeviceType.router
        if (80 in open_ports or 443 in open_ports) and 22 in open_ports:
            return DeviceType.server

    # Serwer DNS (dedykowany lub jako rola na serwerze).
    # Warunek: port 53 + przynajmniej jeden port zarzadczy (SSH/RDP/WinRM/HTTPS).
    # Sam port 53 bez innych sygnalow = relay DNS na routerze (juz zaklasyfikowany wyzej).
    if _has_dns and any(p in open_ports for p in (22, 443, 3389, 5985, 5986)):
        return DeviceType.server

    return DeviceType.unknown


def _hostname_conflict(db, hostname: str, own_ip: str):
    """Zwraca urzadzenie ktore juz ma ten hostname (inny IP) lub None."""
    if not hostname:
        return None
    return (
        db.query(Device)
        .filter(Device.hostname == hostname, Device.ip != own_ip)
        .first()
    )


def upsert_device(db, device_data):
    device = db.query(Device).filter(Device.ip == device_data.ip).first()
    now = datetime.utcnow()
    if device is None:
        # Deduplikacja po MAC: to samo urzadzenie fizyczne moglo zmienic IP
        # (np. laptop przelaczajacy sie miedzy sieciami WiFi).
        # Jesli MAC pasuje do istniejacego rekordu z innym IP → migruj IP zamiast tworzyc duplikat.
        mac_norm = normalize_mac(device_data.mac)
        if mac_norm:
            device_by_mac = (
                db.query(Device)
                .filter(Device.mac == mac_norm, Device.ip != device_data.ip)
                .first()
            )
            if device_by_mac:
                old_ip = device_by_mac.ip
                logger.info(
                    "MAC match: urzadzenie '%s' (%s) zmienilo IP: %s → %s",
                    device_by_mac.hostname or "?", mac_norm, old_ip, device_data.ip,
                )
                db.add(Event(
                    device_id=device_by_mac.id,
                    event_type=EventType.device_appeared,
                    details={"ip": device_data.ip, "old_ip": old_ip, "reason": "zmiana IP (MAC match)"},
                ))
                device_by_mac.ip = device_data.ip
                device_by_mac.last_seen = now
                device_by_mac.is_active = True
                if device_data.hostname and not device_by_mac.hostname:
                    device_by_mac.hostname = device_data.hostname
                if device_data.vendor and not device_by_mac.vendor:
                    device_by_mac.vendor = device_data.vendor
                if device_data.model and not device_by_mac.model:
                    device_by_mac.model = device_data.model
                if device_data.os_version and not device_by_mac.os_version:
                    device_by_mac.os_version = device_data.os_version
                if device_data.site_id and not device_by_mac.site_id:
                    device_by_mac.site_id = device_data.site_id
                db.commit()
                return device_by_mac

        # Sprawdz kolizje hostname przed utworzeniem nowego urzadzenia
        new_hostname = device_data.hostname
        conflict = _hostname_conflict(db, new_hostname, device_data.ip)
        if conflict:
            logger.warning(
                "Hostname collision przy tworzeniu: '%s' juz przypisany do %s — "
                "nowe urzadzenie %s otrzyma pusty hostname",
                new_hostname, conflict.ip, device_data.ip,
            )
            new_hostname = None
        device = Device(
            ip=device_data.ip, hostname=new_hostname,
            mac=normalize_mac(device_data.mac), vendor=device_data.vendor,
            model=device_data.model, os_version=device_data.os_version,
            device_type=device_data.device_type, site_id=device_data.site_id,
            first_seen=now, last_seen=now, is_active=True,
        )
        db.add(device)
        db.flush()
        db.add(Event(device_id=device.id, event_type=EventType.device_appeared,
                     details={"ip": device_data.ip, "hostname": new_hostname}))
        logger.info("Nowe urzadzenie: %s (%s)", device_data.ip, new_hostname)
    else:
        if not device.is_active:
            db.add(Event(device_id=device.id, event_type=EventType.device_appeared,
                         details={"ip": device_data.ip, "reason": "powrot po nieobecnosci"}))
        device.last_seen = now
        device.is_active = True
        if device_data.hostname and device_data.hostname != device.hostname:
            conflict = _hostname_conflict(db, device_data.hostname, device_data.ip)
            if conflict:
                logger.warning(
                    "Hostname collision przy aktualizacji: '%s' juz przypisany do %s — "
                    "pomijam aktualizacje hostname dla %s",
                    device_data.hostname, conflict.ip, device_data.ip,
                )
            else:
                device.hostname = device_data.hostname
        # vendor: aktualizuj tylko gdy urzadzenie nie ma jeszcze vendor
        # lub gdy nowy vendor jest bogatszy w informacje (dluzszy string)
        # Nie nadpisuj "Cisco Systems" oui-generic "Hon Hai Precision Ind. Co.,Ltd."
        if device_data.vendor:
            if not device.vendor:
                device.vendor = device_data.vendor
            elif len(device_data.vendor) > len(device.vendor or ""):
                device.vendor = device_data.vendor
        # os_version: aktualizuj tylko gdy urzadzenie nie ma jeszcze wartosci
        # lub gdy nowa jest bogatsza (dluzszy string — bardziej szczegolowa)
        # Nie nadpisuj szczegolowego SNMP sysDescr generycznym "Linux 4.x" z nmap
        if device_data.os_version:
            if not device.os_version:
                device.os_version = device_data.os_version
            elif len(device_data.os_version) > len(device.os_version):
                device.os_version = device_data.os_version
        if device_data.mac:
            device.mac = normalize_mac(device_data.mac)
        # model ustawiamy tylko jesli nie byl wczesniej znany (nie nadpisujemy dokladniejszego)
        if device_data.model and not device.model:
            device.model = device_data.model
        # device_type: aktualizuj tylko gdy nowy typ jest konkretny (nie unknown)
        # Zapobiega zgubieniu klasyfikacji po skanach bez pelnych danych portow.
        if device_data.device_type != DeviceType.unknown:
            device.device_type = device_data.device_type
        # site_id ustawiamy tylko jesli nie bylo wczesniej ustawione recznie
        if device_data.site_id and not device.site_id:
            device.site_id = device_data.site_id
    db.commit()
    return device


def detect_ip_conflicts(db, arp_map: dict) -> list:
    """Wykrywa konflikty adresow IP — ten sam IP, inny MAC adres niz w DB.

    Porownuje biezaca tablice ARP (ip→mac) z zapisanymi MAC adresami w bazie.
    Konflikt = urządzenie ma inny MAC niz ostatnio widziany → dwa urzadzenia
    walcza o ten sam adres IP (np. statyczny IP zduplikowany recznie).

    Rate-limiting: pomija alarm jesli conflict event dla tego IP byl juz w ciagu 30 min
    (zapobiega spamowi Telegram przy kazdym skanowaniu).

    Zwraca liste dict: [{"ip", "old_mac", "new_mac", "device_id", "hostname"}, ...]
    """
    _INVALID_MACS_NORMALIZED = {"FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"}
    _COOLDOWN_MINUTES = 30
    conflicts = []

    for ip, current_mac in arp_map.items():
        if not current_mac:
            continue
        # Normalizuj przed sprawdzeniem — Windows ARP uzywa kresek (ff-ff-ff-ff-ff-ff)
        _norm_current = normalize_mac(current_mac)
        if not _norm_current or _norm_current.upper() in _INVALID_MACS_NORMALIZED:
            continue
        # Odrzuc smieci — normalize_mac zwraca oryginal gdy nie moze sparsowac
        # (np. "incomplete" z Linux ARP, "192.168.1.1", inne nieprawidlowe stringi)
        if not re.match(r'^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$', _norm_current):
            continue

        device = db.query(Device).filter(Device.ip == ip, Device.is_active == True).first()
        if not device or not device.mac:
            continue  # Nowe urzadzenie lub brak MAC w DB — nie ma z czym porownac

        _norm_db = normalize_mac(device.mac)
        if _norm_db == _norm_current:
            continue  # MAC zgodny — brak konfliktu

        # Rate-limiting: sprawdz czy nie byl juz alarm w ciagu ostatnich 30 min
        _cutoff = datetime.utcnow() - timedelta(minutes=_COOLDOWN_MINUTES)
        _recent = (
            db.query(Event)
            .filter(
                Event.device_id == device.id,
                Event.event_type == EventType.ip_conflict,
                Event.event_time >= _cutoff,
            )
            .first()
        )
        if _recent:
            logger.debug(
                "Konflikt IP %s: pomijam (alarm byl %s temu)",
                ip, datetime.utcnow() - _recent.event_time,
            )
            continue

        conflicts.append({
            "ip": ip,
            "old_mac": _norm_db,
            "new_mac": _norm_current,
            "device_id": device.id,
            "hostname": device.hostname or ip,
        })

        db.add(Event(
            device_id=device.id,
            event_type=EventType.ip_conflict,
            details={"ip": ip, "old_mac": _norm_db, "new_mac": _norm_current},
        ))
        logger.warning(
            "KONFLIKT IP: %s (%s) — DB ma MAC %s, ARP teraz pokazuje %s — "
            "dwa urzadzenia walcza o ten sam adres!",
            ip, device.hostname or "?", _norm_db, _norm_current,
        )

    if conflicts:
        db.commit()
        try:
            from netdoc.notifications.telegram import send_telegram, get_telegram_config
            cfg = get_telegram_config(db)
            if cfg:
                lines = [f"\u26a0\ufe0f <b>NetDoc: {len(conflicts)} konflikt(y) adresow IP!</b>"]
                for c in conflicts[:5]:
                    lines.append(
                        f"\u2022 <b>{c['ip']}</b> ({c['hostname']})\n"
                        f"  Stary MAC: <code>{c['old_mac']}</code>\n"
                        f"  Nowy MAC:  <code>{c['new_mac']}</code>"
                    )
                if len(conflicts) > 5:
                    lines.append(f"...i {len(conflicts) - 5} wiecej")
                send_telegram(cfg["bot_token"], cfg["chat_id"], "\n".join(lines))
        except Exception as exc:
            logger.debug("Telegram alert dla konfliktow IP: %s", exc)

    return conflicts


def mark_missing_devices(db, found_ips, cooldown_minutes: int = 10):
    """Oznacza urzadzenia jako nieaktywne jesli nmap ich nie znalazl.

    Cooldown: jesli ping-worker widzial urzadzenie w ciagu ostatnich cooldown_minutes
    minut (last_seen swiezy), NIE oznaczamy jako nieaktywne — nmap mogl go po prostu
    pominac (ICMP DROP, timing). Urzadzenie zostanie wylaczone dopiero gdy ping-worker
    tez przestanie je widziec (po 5 min bez odpowiedzi TCP/ICMP).
    """
    # Guard: pusta lista found_ips oznaczalaby ze nic nie znaleziono (blad skanu,
    # awaria sieci). SQLAlchemy notin_([]) generuje TRUE -> wszystkie urzadzenia
    # bylby deaktywowane. Zwracamy wczesniej zamiast kasowac cala infrastrukture.
    if not found_ips:
        logger.warning("mark_missing_devices: found_ips jest puste — pomijam deaktywacje")
        return
    threshold = datetime.utcnow() - timedelta(minutes=cooldown_minutes)
    missing = db.query(Device).filter(Device.is_active == True, Device.ip.notin_(found_ips)).all()
    deactivated = 0
    for device in missing:
        if device.last_seen and device.last_seen > threshold:
            logger.debug(
                "Nmap nie widzial %s, ale ping-worker widzial go %ds temu — pomijam",
                device.ip,
                (datetime.utcnow() - device.last_seen).seconds,
            )
            continue
        device.is_active = False
        db.add(Event(device_id=device.id, event_type=EventType.device_disappeared,
                     details={"ip": device.ip, "last_seen": device.last_seen.isoformat() if device.last_seen else None}))
        logger.warning("Urzadzenie niedostepne: %s (%s)", device.ip, device.hostname)
        deactivated += 1
    if deactivated:
        db.commit()


def _get_lab_subnet(db) -> Optional[str]:
    """Zwraca podsiec lab z ustawien systemowych (domyslnie 172.28.0.0/24).

    Uzywana do automatycznego oznaczania urzadzen z podsieci lab jako site_id='lab'.
    """
    try:
        from netdoc.storage.models import SystemStatus
        row = db.query(SystemStatus).filter(SystemStatus.key == "lab_subnet").first()
        if row and row.value:
            return row.value
    except Exception:
        pass
    return "172.28.0.0/24"


def _is_in_subnet(ip: str, cidr: str) -> bool:
    """Sprawdza czy IP nalezy do podsieci CIDR. Zwraca False przy bledzie parsowania."""
    try:
        import ipaddress
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False


def _ensure_lab_monitoring(db) -> int:
    """Gdy lab_monitoring_enabled=1, automatycznie wlacza is_monitored dla urzadzen lab.

    Urzadzenia z site_id='lab' sa zawsze monitorowane gdy lab jest wlaczony,
    niezaleznie od tego czy uzytkownik reczanie przestawil flage is_monitored.
    Zwraca liczbe zaktualizowanych urzadzen.
    """
    from netdoc.storage.models import SystemStatus, Device
    from datetime import datetime
    try:
        row = db.query(SystemStatus).filter(SystemStatus.key == "lab_monitoring_enabled").first()
        if not (row and row.value != "0"):
            return 0
        # Aktywuj monitorowanie dla urzadzen lab ktore go nie maja
        lab_devices = (
            db.query(Device)
            .filter(Device.site_id == "lab", Device.is_monitored == False)
            .all()
        )
        for d in lab_devices:
            d.is_monitored = True
            d.monitor_note = "Auto-monitorowanie: lab jest wlaczony"
            if not d.monitor_since:
                d.monitor_since = datetime.utcnow()
        if lab_devices:
            db.commit()
            logger.info("Lab monitoring: aktywowano monitorowanie dla %d urzadzen lab",
                        len(lab_devices))
        return len(lab_devices)
    except Exception as exc:
        logger.warning("Lab monitoring: blad: %s", exc)
        return 0


def _snmp_save_community(db, device, community: str) -> None:
    """Zapisuje dzialajaca community SNMP do DB (ten sam mechanizm co pipeline).

    Logika:
    - Jesli per-device credential z ta community juz istnieje → aktualizuje last_success_at
    - Jesli global default z ta community istnieje → aktualizuje last_success_at
    - Jesli brak globalnego → tworzy global default
    - Jesli global istnieje ale z inna wartoscia → tworzy per-device
    """
    from datetime import datetime
    try:
        # Sprawdz per-device
        per_dev = (
            db.query(Credential)
            .filter(
                Credential.device_id == device.id,
                Credential.method == CredentialMethod.snmp,
                Credential.username == community,
            )
            .first()
        )
        if per_dev:
            per_dev.last_success_at = datetime.utcnow()
            per_dev.success_count = (per_dev.success_count or 0) + 1
            device.snmp_community = community
            device.snmp_ok_at = datetime.utcnow()
            db.commit()
            return

        # Sprawdz global z ta sama wartoscia
        global_same = (
            db.query(Credential)
            .filter(
                Credential.device_id.is_(None),
                Credential.method == CredentialMethod.snmp,
                Credential.username == community,
            )
            .first()
        )
        if global_same:
            global_same.last_success_at = datetime.utcnow()
            global_same.success_count = (global_same.success_count or 0) + 1
            device.snmp_community = community
            device.snmp_ok_at = datetime.utcnow()
            db.commit()
            return

        # Sprawdz czy jakikolwiek global SNMP istnieje
        global_any = (
            db.query(Credential)
            .filter(
                Credential.device_id.is_(None),
                Credential.method == CredentialMethod.snmp,
            )
            .first()
        )
        if global_any is None:
            cred = Credential(
                device_id=None,
                method=CredentialMethod.snmp,
                username=community,
                notes=f"Auto-discovered by SNMP enrich: {community}",
                priority=50,
                last_success_at=datetime.utcnow(),
            )
            logger.info("SNMP enrich: zapisano nowy global community '%s'", community)
        else:
            cred = Credential(
                device_id=device.id,
                method=CredentialMethod.snmp,
                username=community,
                notes=f"Auto-discovered per-device: {community}",
                priority=10,
                last_success_at=datetime.utcnow(),
            )
            logger.info("SNMP enrich: zapisano per-device community '%s' dla %s",
                        community, device.ip)
        db.add(cred)
        device.snmp_community = community
        device.snmp_ok_at = datetime.utcnow()
        db.commit()
    except Exception as exc:
        logger.debug("_snmp_save_community %s: blad: %s", device.ip, exc)


def snmp_enrich_from_devices(db, devices: list, existing_ips: set) -> dict:
    """Odpytuje routery i switche przez SNMP — odkrywa nowe hosty i podsieci.

    Dla kazdego urzadzenia typu router/switch/unknown z aktywnym SNMP (port 161):
    - Czyta tablice ARP (ipNetToMediaPhysAddress) — IP → MAC dla calosci VLANu
    - Czyta tablice MAC L2 (dot1dTpFdbAddress) — wszystkie MAC na portach switcha
    - Czyta tablice interfejsow (ipAddrTable) — interfejsy z adresami → nowe podsieci
    - Czyta tablice routingu (ipRouteTable) — trasy bezposrednie → nowe podsieci

    Zwraca slownik {ip: {"mac": str, "vendor": str|None}} dla nowo odkrytych hostow.
    Rejestruje nowe podsieci w DiscoveredNetwork (zrodlo: snmp).

    Rate-limiting:
    - Urzadzenia przetwarzane SEKWENCYJNIE (nie rownoleglem) — brak "burst" na siec
    - Miedzy probami community na tym samym urzadzeniu: opoznienie adaptacyjne
      (0.1-0.3s zalezne od dlugosci listy community)
    - Miedzy urzadzeniami: 0.5s pauza (konfigurowalnie przez SNMP_ENRICH_DEVICE_DELAY)
    Przy 1000 switchy i 10k community: proba community jest sekwencyjna per urzadzenie,
    nie wspolbiezna — wyeliminowanie "scanning pattern" wykrywalnego przez IDS.
    """
    # Tylko urzadzenia sieciowe — nie kamery, drukarki, workstations ani niezklasyfikowane.
    # unknown pomijamy: community-worker odkryje SNMP gdy sie urzadzenie sklasyfikuje.
    # Wyjatkiem sa urzadzenia z wczesniej dzialajacym SNMP (snmp_ok_at IS NOT NULL) —
    # te sa dodawane dynamicznie ponizej.
    _SNMP_CANDIDATE_TYPES = {
        DeviceType.router, DeviceType.switch, DeviceType.ap, DeviceType.firewall,
    }
    # Community strings z bazy (metoda snmp, global device_id=None)
    # username = community string; posortowane po priorytecie (nizszy = wazniejszy)
    _SNMP_FALLBACK = ("public", "private")
    try:
        db_comms = [
            c.username for c in
            db.query(Credential)
              .filter(Credential.method == CredentialMethod.snmp)
              .order_by(Credential.priority)
              .all()
            if c.username
        ]
        snmp_communities = tuple(dict.fromkeys(db_comms)) or _SNMP_FALLBACK
    except Exception:
        snmp_communities = _SNMP_FALLBACK
    # Pauza miedzy urzadzeniami — zapobiega "burst" na siec i IDS detection
    # Adaptacyjna: wiecej urzadzen + wiecej community = wieksza pauza
    _n_cands = sum(
        1 for d in devices
        if d.ip and d.is_active and (
            d.device_type in _SNMP_CANDIDATE_TYPES
            or d.snmp_ok_at is not None
            or d.snmp_community is not None
        )
    )
    _n_comms = len(snmp_communities)
    if _n_cands * _n_comms > 1000:
        _device_delay = 1.0       # >1000 prob ogolnie — ostrozniej
    elif _n_cands * _n_comms > 100:
        _device_delay = 0.5
    else:
        _device_delay = 0.0       # mala siec — bez opoznien

    # Opoznienie miedzy probami community dla jednego urzadzenia
    _comm_delay = 0.1 if _n_comms <= 50 else 0.2

    # Odczytaj snmp_debug z DB i ustaw poziom logowania w module snmp_walk
    try:
        from netdoc.storage.models import SystemStatus
        import netdoc.collector.snmp_walk as _sw
        _debug_row = db.query(SystemStatus).filter(SystemStatus.key == "snmp_debug").first()
        _debug_val = int(_debug_row.value) if (_debug_row and _debug_row.value is not None) else 1
        _sw._log_probe = _sw.logger.info if _debug_val else _sw.logger.debug
    except Exception:
        pass

    new_hosts: dict = {}                        # {ip: {"mac": ..., "vendor": ...}}
    new_cidrs: set = set()

    candidates = [
        d for d in devices
        if d.ip and d.is_active and (
            d.device_type in _SNMP_CANDIDATE_TYPES  # znane urzadzenia sieciowe
            or d.snmp_ok_at is not None              # wczesniej odpowiadalo na SNMP
            or d.snmp_community is not None          # ma znana community
        )
    ]

    if not candidates:
        return new_hosts

    logger.info(
        "SNMP enrich: %d kandydatow, %d community, device_delay=%.1fs comm_delay=%.2fs",
        len(candidates), _n_comms, _device_delay, _comm_delay,
    )

    for dev_idx, dev in enumerate(candidates):
        if dev_idx > 0 and _device_delay > 0:
            time.sleep(_device_delay)
        try:
            # Per-device community ma wyzszy priorytet niz globalne
            try:
                dev_comms = [
                    c.username for c in
                    db.query(Credential)
                      .filter(
                          Credential.device_id == dev.id,
                          Credential.method == CredentialMethod.snmp,
                      )
                      .order_by(Credential.priority)
                      .all()
                    if c.username
                ]
                # Per-device + globalne (bez duplikatow)
                effective = tuple(dict.fromkeys(dev_comms + list(snmp_communities)))
            except Exception:
                effective = snmp_communities
            data = snmp_discover_networks(
                dev.ip, communities=effective,
                timeout=2.5, inter_probe_delay=_comm_delay,
            )
        except Exception as exc:
            logger.debug("SNMP enrich %s: blad: %s", dev.ip, exc)
            continue

        # ── Zapisz dzialajaca community do DB (jesli nowa) ───────────────────
        working_comm = data.get("community")
        if working_comm:
            _snmp_save_community(db, dev, working_comm)

        # ── ARP table: IP → MAC ──────────────────────────────────────────────
        for remote_ip, mac in data["arp"].items():
            if not _is_valid_private_ip(remote_ip):
                continue
            if remote_ip in existing_ips:
                # Uzupelniamy MAC jesli brakuje
                if mac and remote_ip not in new_hosts:
                    new_hosts[remote_ip] = {"mac": mac, "vendor": None}
                continue
            entry = new_hosts.setdefault(remote_ip, {"mac": None, "vendor": None})
            if mac and not entry["mac"]:
                entry["mac"] = mac

        # ── MAC table: nowe MAC (bez IP) ─────────────────────────────────────
        # Wpisy z MAC table bez odpowiadajacego IP → trudne do uzycia bez IP.
        # Logujemy tylko liczbowe podsumowanie.
        if data["macs"]:
            logger.debug("SNMP MAC table %s: %d MAC adresow L2", dev.ip, len(data["macs"]))

        # ── Interface IP table → nowe podsieci ───────────────────────────────
        for iface in data["ifaces"]:
            addr = iface.get("ip", "")
            mask = iface.get("mask", "")
            if not _is_valid_private_ip(addr) or not mask:
                continue
            prefix = mask_to_prefix(mask)
            # Pomijaj zbyt szerokie (/8, /12) i loopback podsieci
            if prefix < 16 or prefix > 30:
                continue
            import ipaddress as _ipaddress
            try:
                net = str(_ipaddress.ip_network(f"{addr}/{prefix}", strict=False))
                if net not in new_cidrs:
                    new_cidrs.add(net)
                    _upsert_network(db, net, NetworkSource.auto)
                    logger.info("SNMP ifIP %s: nowa podsiec %s (via %s)", dev.ip, net, addr)
            except Exception:
                pass

        # ── Route table → bezposrednie podsieci ──────────────────────────────
        for route in data["routes"]:
            dest    = route.get("dest", "")
            mask    = route.get("mask", "")
            rtype   = route.get("type", 0)
            # type=3 = direct (podlaczona bezposrednio), typ=2 = remote
            if rtype not in (2, 3):
                continue
            if not _is_valid_private_ip(dest) or not mask:
                continue
            prefix = mask_to_prefix(mask)
            if prefix < 16 or prefix > 30:
                continue
            import ipaddress as _ipaddress
            try:
                net = str(_ipaddress.ip_network(f"{dest}/{prefix}", strict=False))
                if net not in new_cidrs:
                    new_cidrs.add(net)
                    src = NetworkSource.auto if rtype == 3 else NetworkSource.lldp
                    _upsert_network(db, net, src)
                    logger.info(
                        "SNMP route %s: nowa podsiec %s (type=%d via %s)",
                        dev.ip, net, rtype, dest,
                    )
            except Exception:
                pass

    # Uzupelnij vendor z OUI lookup dla nowych hostow
    for remote_ip, entry in new_hosts.items():
        if entry.get("mac") and not entry.get("vendor"):
            entry["vendor"] = lookup_vendor_from_mac(entry["mac"])

    if new_hosts:
        logger.info(
            "SNMP enrich: %d nowych/uzupelnionych hostow, %d nowych podsieci",
            len(new_hosts), len(new_cidrs),
        )
    return new_hosts


def run_discovery(db):
    lab_subnet = _get_lab_subnet(db)
    # Odczytaj ustawienie ignore_laa_macs z DB (domyslnie wlaczone)
    _laa_row = None
    try:
        from netdoc.storage.models import SystemStatus
        _laa_row = db.query(SystemStatus).filter(SystemStatus.key == "ignore_laa_macs").first()
    except Exception:
        pass
    _ignore_laa = (_laa_row.value != "0") if (_laa_row and _laa_row.value not in (None, "")) else True
    ranges = get_scan_targets(db)
    if not ranges:
        return []
    all_hosts = []
    for net_range in ranges:
        all_hosts.extend(ping_sweep(net_range))
    all_hosts = list(dict.fromkeys(all_hosts))

    # Pasywne odkrywanie rownoleglem — SSDP, NBNS, mDNS, WSD jednoczesnie (~4s)
    with ThreadPoolExecutor(max_workers=4) as _passive:
        _f_ssdp = _passive.submit(ssdp_scan)
        _f_nbns = _passive.submit(nbns_scan)
        _f_mdns = _passive.submit(mdns_scan)
        _f_wsd  = _passive.submit(wsd_scan)
        ssdp_meta = _f_ssdp.result()
        nbns_meta = _f_nbns.result()   # {ip: netbios_name}
        mdns_meta = _f_mdns.result()   # {ip: {hostname, services}}
        wsd_meta  = _f_wsd.result()    # {ip: {xaddrs, types}}

    # Hosty APIPA (169.254.x.x) z ARP table — urzadzenia bez DHCP
    apipa_map = apipa_from_arp()       # {ip: mac}

    # Scalaj nowe IP z passive scans (te ktore nmap -sn przeoczyl)
    # APIPA: is_private() zwraca False dla 169.254.x.x — dodaj osobno
    for meta_dict in (ssdp_meta, nbns_meta, mdns_meta, wsd_meta):
        for extra_ip in meta_dict:
            if is_private(extra_ip) and extra_ip not in all_hosts:
                all_hosts.append(extra_ip)
                logger.info("Pasywne discovery: nowy host %s", extra_ip)
    for apipa_ip in apipa_map:
        if apipa_ip not in all_hosts:
            all_hosts.append(apipa_ip)
            logger.info("APIPA discovery: nowy host %s (brak DHCP)", apipa_ip)

    if not all_hosts:
        logger.warning("Discovery: brak aktywnych hostow")
        return []

    # PTR lookup — rownolegly, szybki, dobry dla sieci korporacyjnych
    ptr_map = reverse_dns_lookup(all_hosts)

    # Etap 1: natychmiast wpisz aktywne hosty do bazy (tylko IP) —
    # Grafana zobaczy urzadzenia po ~8s (ping sweep), nie czekajac na port scan.
    arp_map_early = read_arp_table(ignore_laa=_ignore_laa)

    # Wykrywanie konfliktow IP — PRZED upsert_device (ktory zaktualizuje MAC w DB)
    # Porownujemy ARP "teraz" z MAC w DB z poprzedniego skanu.
    detect_ip_conflicts(db, arp_map_early)
    for ip in all_hosts:
        if not is_private(ip) and not ip.startswith("169.254."):
            continue
        # MAC: ARP table > apipa_map (dla 169.254.x.x ktore moga byc tylko w apipa_map)
        mac = arp_map_early.get(ip) or apipa_map.get(ip)
        vendor = lookup_vendor_from_mac(mac) if mac else None
        # Vendor fallback: SSDP SERVER header — fingerprinting, potem raw split
        if not vendor and ip in ssdp_meta:
            srv = ssdp_meta[ip].get("server", "")
            if srv:
                try:
                    from netdoc.collector.fingerprinting import banner_db
                    fp = banner_db.fingerprint_server_header(srv)
                    vendor = fp["vendor"] if fp else None
                except Exception:
                    fp = None
                if not vendor:
                    vendor = srv.split("/")[0].strip()[:64] or None
        # Hostname: NBNS > PTR > mDNS (prio maleje)
        hostname = (nbns_meta.get(ip)
                    or ptr_map.get(ip)
                    or (mdns_meta.get(ip) or {}).get("hostname"))
        # site_id = "lab" dla urzadzen w podsieci laboratoryjnej (np. 172.28.0.0/24)
        site_id = "lab" if _is_in_subnet(ip, lab_subnet) else None
        upsert_device(db, DeviceData(ip=ip, mac=mac, vendor=vendor,
                                     hostname=hostname, site_id=site_id))
    mark_missing_devices(db, all_hosts)
    db.commit()
    logger.info("Szybki commit po ping sweep: %d hostow widocznych w Grafana", len(all_hosts))

    # Etap 2: port scan (wolny — kilka minut)
    scan_data = port_scan(all_hosts)
    devices = []
    for ip in all_hosts:
        if not is_private(ip) and not ip.startswith("169.254."):
            continue
        host_info = scan_data.get(ip, {})
        open_ports = host_info.get("open_ports", {})
        # Vendor z nmap; fallback z SSDP SERVER header gdy nmap nie zidentyfikowal
        _vendor = host_info.get("vendor")
        if not _vendor and ip in ssdp_meta:
            srv = ssdp_meta[ip].get("server", "")
            if srv:
                try:
                    from netdoc.collector.fingerprinting import banner_db
                    fp = banner_db.fingerprint_server_header(srv)
                    _vendor = fp["vendor"] if fp else None
                except Exception:
                    fp = None
                if not _vendor:
                    _vendor = srv.split("/")[0].strip()[:64] or None
        # MAC: ARP table > apipa_map
        _mac = arp_map_early.get(ip) or apipa_map.get(ip)
        # Fallback vendor z OUI gdy nmap/SSDP nie rozpoznaly producenta
        if not _vendor and _mac:
            _vendor = lookup_vendor_from_mac(_mac)
        # Hostname: nmap (rzadko) > NBNS > PTR > mDNS
        _hostname = (host_info.get("hostname")
                     or nbns_meta.get(ip)
                     or ptr_map.get(ip)
                     or (mdns_meta.get(ip) or {}).get("hostname"))
        # mDNS service hints dla _guess_device_type
        _mdns_services = (mdns_meta.get(ip) or {}).get("services", [])
        _site_id = "lab" if _is_in_subnet(ip, lab_subnet) else None
        device_data = DeviceData(
            ip=ip, vendor=_vendor, mac=_mac,
            hostname=_hostname,
            os_version=host_info.get("os"),
            site_id=_site_id,
            device_type=_guess_device_type(
                open_ports, host_info.get("os"), _vendor,
                mac=_mac, hostname=_hostname, mdns_services=_mdns_services,
            ),
            raw=host_info,
        )
        device = upsert_device(db, device_data)
        devices.append(device)
        # Zapisz wyniki portu do ScanResult (potrzebne przez pipeline do _has_open_port)
        db.add(ScanResult(
            device_id=device.id,
            scan_type="nmap",
            open_ports={str(p): info for p, info in open_ports.items()},
        ))
    db.commit()
    # Uzupelnij MAC z ARP table (dostepna bez uprawnien root)
    arp_map = read_arp_table(ignore_laa=_ignore_laa)
    if arp_map:
        reclassify_count = 0
        for device in devices:
            if not device.mac and device.ip in arp_map:
                device.mac = arp_map[device.ip]
            if device.mac and not device.vendor:
                device.vendor = lookup_vendor_from_mac(device.mac)
            # Reklasyfikuj jezeli: (a) typ byl unknown, lub (b) vendor zmienil sie
            # z None na cos konkretnego (np. Ubiquiti — moze zmienic router→ap)
            _needs_reclassify = (
                device.device_type == DeviceType.unknown
                or (device.vendor and device.device_type == DeviceType.router
                    and any(v in device.vendor.lower() for v in ("ubiquiti",)))
            )
            if _needs_reclassify and (device.vendor or device.mac):
                host_info = scan_data.get(device.ip, {})
                open_ports = host_info.get("open_ports", {})
                new_type = _guess_device_type(
                    set(int(p) for p in open_ports.keys()), host_info.get("os"),
                    device.vendor, device.mac, hostname=device.hostname,
                )
                if new_type != DeviceType.unknown:
                    device.device_type = new_type
                    reclassify_count += 1
        db.commit()
        logger.info("MAC z ARP table: %d wpisow, reklasyfikacja: %d urzadzen",
                    len(arp_map), reclassify_count)

    # Reklasyfikuj bramy domyslne jako router (np. Ubiquiti bez rozpoznanego hostname → AP)
    gateways = _get_default_gateways()
    if gateways:
        gw_fixed = 0
        for device in devices:
            if device.ip in gateways and device.device_type not in (
                DeviceType.router, DeviceType.firewall
            ):
                old_type = device.device_type
                device.device_type = DeviceType.router
                gw_fixed += 1
                logger.info("Gateway %s reklasyfikowany: %s -> router", device.ip,
                            old_type.value if old_type else "?")
        if gw_fixed:
            db.commit()

    # ── Enrichment: DC domain name + DNS active check ────────────────────────────
    _dc_devs  = [d for d in devices if d.device_type == DeviceType.domain_controller]
    _dns_devs = [
        d for d in devices
        if d.device_type != DeviceType.domain_controller
        and 53 in {int(p) for p in scan_data.get(d.ip, {}).get("open_ports", {})}
    ]
    _infra_changed = False
    for _dc in _dc_devs:
        if not _dc.os_version:
            _dc_info = ldap_query_rootdse(_dc.ip)
            if _dc_info.get("domain"):
                _dc.os_version = f"Active Directory: {_dc_info['domain']}"
                logger.info("DC: %s — domena AD: %s", _dc.ip, _dc_info["domain"])
                _infra_changed = True
    for _dns_dev in _dns_devs:
        if not _dns_dev.os_version:
            _dns_info = check_dns_responds(_dns_dev.ip)
            if _dns_info.get("responds"):
                _role = "DNS recursive" if _dns_info.get("recursive") else "DNS authoritative"
                _dns_dev.os_version = _role
                logger.info("DNS server: %s — %s (rcode=%d)", _dns_dev.ip, _role,
                            _dns_info.get("rcode", -1))
                _infra_changed = True
    if _infra_changed:
        db.commit()

    # ── SNMP enrich: odpytaj routery/switche przez SNMP ─────────────────────────
    # Odkrywa nowe hosty (z ARP/MAC table) i podsieci (z ifIP/route table)
    # bez DHCP — wystarczy community "public" na routerze.
    snmp_new = snmp_enrich_from_devices(db, devices, set(all_hosts))
    if snmp_new:
        site_id_snmp = "lab" if lab_subnet else None
        for remote_ip, entry in snmp_new.items():
            if remote_ip in set(d.ip for d in devices):
                continue
            _site_id_r = "lab" if _is_in_subnet(remote_ip, lab_subnet) else None
            new_dev = upsert_device(db, DeviceData(
                ip=remote_ip,
                mac=entry.get("mac"),
                vendor=entry.get("vendor"),
                site_id=_site_id_r,
            ))
            devices.append(new_dev)
            all_hosts.append(remote_ip)
        db.commit()
        logger.info("SNMP enrich: dodano %d nowych urzadzen do bazy", len(snmp_new))

    mark_missing_devices(db, all_hosts)
    # Jesli lab jest wlaczony, upewnij sie ze wszystkie urzadzenia lab sa monitorowane
    _ensure_lab_monitoring(db)
    logger.info("Discovery zakonczone: %d urzadzen w %d sieciach", len(devices), len(ranges))
    return devices
