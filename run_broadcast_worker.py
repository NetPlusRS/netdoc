"""run_broadcast_worker.py — NetDoc broadcast/multicast discovery (host-side).

Odkrywa urzadzenia bez credentiali przez:
  - UniFi Discovery (UDP 10001)   — Ubiquiti APs, switche, bramki
  - MikroTik MNDP (UDP 5678)     — RouterOS — identity, model, wersja
  - mDNS / Bonjour (UDP 5353, 224.0.0.251) — Apple, IoT, kamery, drukarki
  - SSDP / UPnP (UDP 1900, 239.255.255.255) — NAS, drukarki, smart home

Dziala na HOSCIE (Windows) — wymaga bezposredniego dostepu L2 do sieci.
Wyniki trafiaja do tabeli Device przez upsert_device() (jak scanner).

Uruchamianie:
    python run_broadcast_worker.py --once        # jeden cykl i wyjscie
    python run_broadcast_worker.py               # petla co 5 min
"""

import logging
import os
import socket
import struct
import sys
import time
import re
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(__file__))

# ---------------------------------------------------------------------------
# Logging — do pliku + stderr
# ---------------------------------------------------------------------------
_LOG_PATH = os.path.join(os.path.dirname(__file__), "logs", "broadcast.log")
os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)

from logging.handlers import RotatingFileHandler
_handlers = [logging.StreamHandler(sys.stderr)]
try:
    _handlers.append(RotatingFileHandler(_LOG_PATH, maxBytes=2 * 1024 * 1024, backupCount=3))
except Exception:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] broadcast: %(message)s",
    handlers=_handlers,
)
logger = logging.getLogger("broadcast_worker")

# ---------------------------------------------------------------------------
# Stale
# ---------------------------------------------------------------------------
UNIFI_PORT  = 10001
MNDP_PORT   = 5678
MDNS_PORT   = 5353
SSDP_PORT   = 1900
MDNS_GROUP  = "224.0.0.251"
SSDP_GROUP  = "239.255.255.255"

RECV_TIMEOUT   = 3.0    # czas nasluchiwania po wyslaniu pakietu
CYCLE_INTERVAL = 300    # sekund miedzy cyklami (5 min)
UPNP_FETCH_MAX = 8      # max URL do HTTP description (throttle)


# ===========================================================================
# UniFi Discovery Protocol (UDP 10001)
# ===========================================================================

def _discover_unifi(bind_ip: str, timeout: float = RECV_TIMEOUT) -> list[dict]:
    """Wysyla UniFi discovery broadcast i parsuje odpowiedzi TLV."""
    results: list[dict] = []
    DISC = b"\x01\x00\x00\x00"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        s.bind((bind_ip, 0))
        s.sendto(DISC, ("255.255.255.255", UNIFI_PORT))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, (src_ip, _) = s.recvfrom(4096)
                if src_ip == bind_ip:
                    continue
                parsed = _parse_unifi_tlv(data, src_ip)
                if parsed:
                    results.append(parsed)
            except socket.timeout:
                break
    except OSError as exc:
        logger.debug("UniFi error: %s", exc)
    finally:
        try: s.close()
        except Exception: pass
    return results


def _parse_unifi_tlv(data: bytes, src_ip: str) -> Optional[dict]:
    """Parsuje UniFi TLV response. Zwraca None jesli brak kluczowych pol."""
    if len(data) < 4:
        return None
    result: dict = {"ip": src_ip, "protocol": "unifi"}
    pos = 4  # pomijamy 4-bajtowy naglowek

    while pos + 3 <= len(data):
        t = data[pos]
        ln = struct.unpack(">H", data[pos + 1:pos + 3])[0]
        v  = data[pos + 3:pos + 3 + ln]
        pos += 3 + ln

        if   t == 0x01:  # MAC w payloadzie z interfejsem (6+6 bajtow: MAC+IP)
            if len(v) == 12:
                result["mac"] = ":".join(f"{b:02X}" for b in v[:6])
        elif t == 0x02:  # MAC (stary format — 6 bajtow)
            if len(v) >= 6:
                result.setdefault("mac", ":".join(f"{b:02X}" for b in v[:6]))
        elif t == 0x0B:  # IP (2 bajty padding + 4 bajty IP)
            if len(v) == 6:
                result["ip"] = ".".join(str(b) for b in v[2:6])
        elif t == 0x15:  # Hostname
            result["hostname"] = v.decode("utf-8", errors="replace").strip("\x00")
        elif t == 0x03:  # Firmware version
            result["firmware"] = v.decode("utf-8", errors="replace").strip("\x00")
        elif t == 0x0C:  # Model (platform)
            result["model"] = v.decode("utf-8", errors="replace").strip("\x00")
        elif t == 0x13:  # Model name (alternative)
            name = v.decode("utf-8", errors="replace").strip("\x00")
            if name:
                result.setdefault("model", name)

    return result if ("mac" in result or "hostname" in result) else None


# ===========================================================================
# MikroTik MNDP — Neighbor Discovery Protocol (UDP 5678)
# ===========================================================================

def _discover_mndp(bind_ip: str, timeout: float = RECV_TIMEOUT) -> list[dict]:
    """Wysyla MNDP broadcast i parsuje odpowiedzi TLV RouterOS."""
    results: list[dict] = []
    DISC = b"\x00\x00\x00\x00"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        s.bind((bind_ip, 0))
        s.sendto(DISC, ("255.255.255.255", MNDP_PORT))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, (src_ip, _) = s.recvfrom(4096)
                if src_ip == bind_ip:
                    continue
                parsed = _parse_mndp_tlv(data, src_ip)
                if parsed:
                    results.append(parsed)
            except socket.timeout:
                break
    except OSError as exc:
        logger.debug("MNDP error: %s", exc)
    finally:
        try: s.close()
        except Exception: pass
    return results


def _parse_mndp_tlv(data: bytes, src_ip: str) -> Optional[dict]:
    """Parsuje MNDP TLV. Typ i dlugosc to big-endian uint16."""
    if len(data) < 4:
        return None
    result: dict = {"ip": src_ip, "protocol": "mndp", "vendor": "MikroTik"}
    pos = 4  # pomijamy 4-bajtowy naglowek

    while pos + 4 <= len(data):
        t  = struct.unpack(">H", data[pos:pos + 2])[0]
        ln = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        v  = data[pos + 4:pos + 4 + ln]
        pos += 4 + ln
        try:
            if   t == 0x0001:  # MAC address
                if len(v) >= 6:
                    result["mac"] = ":".join(f"{b:02X}" for b in v[:6])
            elif t == 0x0005:  # Identity (hostname)
                result["hostname"] = v.decode("utf-8", errors="replace").rstrip("\x00")
            elif t == 0x0007:  # Version (firmware)
                result["firmware"] = v.decode("utf-8", errors="replace").rstrip("\x00")
            elif t == 0x0008:  # Platform (model/board)
                result["model"] = v.decode("utf-8", errors="replace").rstrip("\x00")
            elif t == 0x000E:  # IPv4 address
                if len(v) == 4:
                    result["ip"] = ".".join(str(b) for b in v)
        except Exception:
            pass

    return result if len(result) > 3 else None


# ===========================================================================
# mDNS / Bonjour (multicast 224.0.0.251:5353)
# ===========================================================================

_MDNS_QUERIES = [
    b"_ssh._tcp.local",
    b"_http._tcp.local",
    b"_rtsp._tcp.local",
    b"_printer._tcp.local",
    b"_ipp._tcp.local",
    b"_smb._tcp.local",
    b"_ftp._tcp.local",
    b"_airplay._tcp.local",
    b"_googlecast._tcp.local",
    b"_daap._tcp.local",
]


def _dns_encode(name: bytes) -> bytes:
    encoded = b""
    for label in name.split(b"."):
        encoded += bytes([len(label)]) + label
    return encoded + b"\x00"


def _build_mdns_query(service: bytes) -> bytes:
    header = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    return header + _dns_encode(service) + b"\x00\x0C\x00\x01"  # PTR IN


def _read_dns_name(data: bytes, pos: int) -> tuple[str, int]:
    """Czyta skompresowana nazwe DNS. Zwraca (name, next_pos)."""
    labels = []
    jumped = False
    orig_pos = pos
    jumps = 0
    while pos < len(data) and jumps < 20:
        length = data[pos]
        if length == 0:
            pos += 1
            break
        elif (length & 0xC0) == 0xC0:
            if pos + 1 >= len(data):
                break
            ptr = struct.unpack(">H", data[pos:pos + 2])[0] & 0x3FFF
            if not jumped:
                orig_pos = pos + 2
            jumped = True
            pos = ptr
            jumps += 1
        else:
            pos += 1
            labels.append(data[pos:pos + length].decode("utf-8", errors="replace"))
            pos += length
    return ".".join(labels), (orig_pos if jumped else pos)


def _parse_mdns_response(data: bytes, src_ip: str) -> Optional[dict]:
    """Minimalny parser mDNS — wyciaga hostname i typy uslug."""
    if len(data) < 12:
        return None
    flags = struct.unpack(">H", data[2:4])[0]
    if not (flags & 0x8000):  # nie response
        return None

    qdcount = struct.unpack(">H", data[4:6])[0]
    ancount = struct.unpack(">H", data[6:8])[0]
    arcount = struct.unpack(">H", data[10:12])[0]

    pos = 12
    # Pomijamy pytania
    for _ in range(qdcount):
        try:
            _, pos = _read_dns_name(data, pos)
            pos += 4
        except Exception:
            return None

    hostnames = []
    services  = []

    for _ in range(ancount + arcount):
        if pos >= len(data) - 10:
            break
        try:
            _name, pos = _read_dns_name(data, pos)
            if pos + 10 > len(data):
                break
            rtype = struct.unpack(">H", data[pos:pos + 2])[0]
            pos += 8  # type(2) + class(2) + ttl(4)
            rdlen = struct.unpack(">H", data[pos:pos + 2])[0]
            pos += 2
            rdata = data[pos:pos + rdlen]
            pos += rdlen

            if rtype == 12:   # PTR → instancja uslugi
                target, _ = _read_dns_name(rdata, 0)
                parts = target.split(".")
                # "Nazwa._usluga._tcp.local" — wyciagamy typ i nazwe
                if len(parts) >= 4 and parts[-1] == "local":
                    svc = parts[-3].lstrip("_") if len(parts) >= 3 else ""
                    if svc:
                        services.append(svc)
                    hostnames.append(parts[0])
            elif rtype == 28:  # AAAA — ignoruj, chcemy tylko A
                pass
            elif rtype == 1:   # A record — sprawdz IP
                if rdlen == 4:
                    ip4 = ".".join(str(b) for b in rdata)
                    if ip4 != src_ip and not ip4.startswith("169.254"):
                        src_ip = ip4  # uzywaj IP z A record jesli inny
            elif rtype == 33:  # SRV → hostname hosta
                if len(rdata) >= 6:
                    h, _ = _read_dns_name(rdata, 6)
                    if h and not h.endswith(".local"):
                        hostnames.append(h.split(".")[0])
                    elif h.endswith(".local"):
                        hostnames.append(h.replace(".local", ""))
        except Exception:
            break

    if not services and not hostnames:
        return None

    # Najkrotsza nazwa = prawdopodobnie hostname urzadzenia
    hostname = min(hostnames, key=len) if hostnames else None

    return {
        "ip":       src_ip,
        "protocol": "mdns",
        "hostname": hostname,
        "services": list(set(services)),
    }


def _discover_mdns(bind_ip: str, timeout: float = RECV_TIMEOUT) -> list[dict]:
    """Wysyla zapytania mDNS i zbiera odpowiedzi przez multicast."""
    by_ip: dict[str, dict] = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        mreq = struct.pack("4s4s", socket.inet_aton(MDNS_GROUP), socket.inet_aton(bind_ip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_ip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        s.settimeout(1.0)
        try:
            s.bind(("", MDNS_PORT))
        except OSError:
            # Port 5353 moze byc zajety przez inny proces — wiez do efemerycznego
            s.bind(("", 0))

        for service in _MDNS_QUERIES:
            try:
                s.sendto(_build_mdns_query(service), (MDNS_GROUP, MDNS_PORT))
            except Exception:
                pass

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, (src_ip, _) = s.recvfrom(4096)
                if src_ip == bind_ip:
                    continue
                parsed = _parse_mdns_response(data, src_ip)
                if not parsed:
                    continue
                key = parsed["ip"]
                existing = by_ip.get(key, {})
                merged_svc = list(set(existing.get("services", []) + parsed.get("services", [])))
                by_ip[key] = {
                    "ip":       key,
                    "protocol": "mdns",
                    "hostname": existing.get("hostname") or parsed.get("hostname"),
                    "services": merged_svc,
                }
            except socket.timeout:
                continue
            except Exception:
                pass

        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
        except Exception:
            pass
    except OSError as exc:
        logger.debug("mDNS error: %s", exc)
    finally:
        try: s.close()
        except Exception: pass

    return list(by_ip.values())


# ===========================================================================
# SSDP / UPnP (multicast 239.255.255.255:1900)
# ===========================================================================

_SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.255:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode()


def _fetch_upnp_description(url: str, timeout: float = 3.0) -> dict:
    """Pobiera XML z adresu LOCATION i wyciaga producenta/model."""
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "NetDoc/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            xml = resp.read(32768).decode("utf-8", errors="replace")
        result = {}
        for tag in ("friendlyName", "manufacturer", "modelName", "modelNumber", "serialNumber"):
            m = re.search(rf"<{tag}[^>]*>\s*([^<]+?)\s*</{tag}>", xml, re.IGNORECASE)
            if m:
                result[tag] = m.group(1)
        return result
    except Exception:
        return {}


def _discover_ssdp(bind_ip: str, timeout: float = RECV_TIMEOUT) -> list[dict]:
    """Wysyla SSDP M-SEARCH i zbiera odpowiedzi UPnP."""
    by_ip: dict[str, dict] = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_ip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        s.settimeout(1.0)
        s.bind((bind_ip, 0))
        s.sendto(_SSDP_MSEARCH, (SSDP_GROUP, SSDP_PORT))

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, (src_ip, _) = s.recvfrom(4096)
                if src_ip == bind_ip:
                    continue
                text = data.decode("utf-8", errors="replace")
                if "200 OK" not in text and "NOTIFY" not in text:
                    continue

                entry = by_ip.get(src_ip, {"ip": src_ip, "protocol": "ssdp"})
                loc_m = re.search(r"LOCATION:\s*(\S+)", text, re.IGNORECASE)
                if loc_m:
                    entry.setdefault("location_url", loc_m.group(1))
                srv_m = re.search(r"SERVER:\s*(.+)", text, re.IGNORECASE)
                if srv_m:
                    entry.setdefault("server_header", srv_m.group(1).strip())
                by_ip[src_ip] = entry
            except socket.timeout:
                continue
            except Exception:
                pass
    except OSError as exc:
        logger.debug("SSDP error: %s", exc)
    finally:
        try: s.close()
        except Exception: pass

    # Pobierz opisy UPnP (max UPNP_FETCH_MAX zeby nie zalac sieci)
    fetched = 0
    for entry in by_ip.values():
        url = entry.get("location_url")
        if url and fetched < UPNP_FETCH_MAX:
            desc = _fetch_upnp_description(url)
            if desc:
                entry["friendly_name"] = desc.get("friendlyName")
                entry["vendor"]        = desc.get("manufacturer")
                entry["model"]         = desc.get("modelName") or desc.get("modelNumber")
                entry["serial_number"] = desc.get("serialNumber")
                fetched += 1

    return list(by_ip.values())


# ===========================================================================
# Pomocnicze
# ===========================================================================

def _get_local_ip() -> str:
    """Zwraca glowne IP hosta uzywane dla polaczen wychodzacych."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"


def _services_to_device_type(services: list[str], protocol: str):
    """Proba odgadniecia typu urzadzenia z listy uslug mDNS."""
    from netdoc.storage.models import DeviceType
    if protocol == "unifi":
        return DeviceType.ap
    if protocol == "mndp":
        return DeviceType.router
    svc_set = set(s.lower() for s in services)
    if "printer" in svc_set or "ipp" in svc_set or "pdl-datastream" in svc_set:
        return DeviceType.printer
    if "rtsp" in svc_set or "camera" in svc_set:
        return DeviceType.camera
    return DeviceType.unknown


# ===========================================================================
# Zapis do bazy
# ===========================================================================

def _save_results(db, all_results: list[dict]) -> int:
    """Upsert odkrytych urzadzen do tabeli Device."""
    from netdoc.collector.discovery import upsert_device
    from netdoc.collector.normalizer import DeviceData, normalize_mac

    saved = 0
    for r in all_results:
        ip = r.get("ip")
        if not ip or ip.startswith("127.") or ip.startswith("169.254"):
            continue

        protocol = r.get("protocol", "")
        services = r.get("services", [])

        hostname = r.get("hostname") or r.get("friendly_name") or None
        vendor   = r.get("vendor")
        if not vendor and protocol == "mndp":
            vendor = "MikroTik"
        if not vendor and protocol == "unifi":
            vendor = "Ubiquiti"

        # Uzupelnij vendor z parsowania server_header (np. "Linux/3.x UPnP/1.1 MiniUPnPd")
        if not vendor and r.get("server_header"):
            sh = r["server_header"]
            if "synology" in sh.lower():
                vendor = "Synology"
            elif "qnap" in sh.lower():
                vendor = "QNAP"
            elif "hikvision" in sh.lower():
                vendor = "Hikvision"
            elif "dahua" in sh.lower():
                vendor = "Dahua"

        device_type = _services_to_device_type(services, protocol)

        data = DeviceData(
            ip          = ip,
            mac         = normalize_mac(r.get("mac")),
            hostname    = hostname,
            vendor      = vendor,
            model       = r.get("model"),
            os_version  = r.get("firmware"),
            device_type = device_type,
        )

        # Dodatkowe dane bez dedykowanego pola → asset_notes (tymczasowo)
        extra_parts = []
        services = r.get("services", [])
        if services:
            extra_parts.append("mDNS services: " + ", ".join(sorted(services)))
        if r.get("serial_number"):
            extra_parts.append("Serial: " + r["serial_number"])
        if r.get("server_header") and not vendor:
            extra_parts.append("UPnP server: " + r["server_header"])

        try:
            dev = upsert_device(db, data)
            # Zapisz extra dane do asset_notes jesli pole puste
            if extra_parts and dev and not dev.asset_notes:
                dev.asset_notes = "[broadcast] " + " | ".join(extra_parts)
            db.commit()
            saved += 1
            logger.info(
                "%-6s  %-18s  hostname=%-28s vendor=%-15s model=%s",
                protocol.upper(), ip,
                hostname or "-",
                vendor   or "-",
                r.get("model") or "-",
            )
        except Exception as exc:
            logger.warning("DB save error for %s: %s", ip, exc)
            db.rollback()

    return saved


# ===========================================================================
# Glowny cykl
# ===========================================================================

def _set_status(db, updates: dict) -> None:
    """Zapisuje klucze do tabeli system_status (category=broadcast_worker)."""
    from netdoc.storage.models import SystemStatus
    for key, value in updates.items():
        row = db.query(SystemStatus).filter(SystemStatus.key == key).first()
        if row:
            row.value = str(value)
        else:
            db.add(SystemStatus(key=key, value=str(value), category="broadcast_worker"))
    try:
        db.commit()
    except Exception:
        db.rollback()


def discover_once() -> dict:
    """Jeden pelny cykl broadcast+multicast discovery. Zwraca statystyki."""
    from netdoc.storage.database import SessionLocal

    bind_ip = _get_local_ip()
    logger.info("=== Broadcast discovery — bind_ip=%s ===", bind_ip)

    per_proto: dict[str, list] = {}
    all_results: list[dict] = []

    for name, key, fn in [
        ("UniFi", "broadcast_unifi",  lambda: _discover_unifi(bind_ip)),
        ("MNDP",  "broadcast_mndp",   lambda: _discover_mndp(bind_ip)),
        ("mDNS",  "broadcast_mdns",   lambda: _discover_mdns(bind_ip)),
        ("SSDP",  "broadcast_ssdp",   lambda: _discover_ssdp(bind_ip)),
    ]:
        try:
            found = fn()
            logger.info("%-8s %d device(s)", name, len(found))
            per_proto[key] = found
            all_results.extend(found)
        except Exception as exc:
            logger.warning("%-8s failed: %s", name, exc)
            per_proto[key] = []

    total = len(all_results)
    logger.info("Total discovered: %d", total)

    with SessionLocal() as db:
        saved = _save_results(db, all_results) if all_results else 0
        _set_status(db, {
            "broadcast_last_at":         datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "broadcast_last_discovered": total,
            "broadcast_last_saved":      saved,
            "broadcast_unifi":           len(per_proto.get("broadcast_unifi", [])),
            "broadcast_mndp":            len(per_proto.get("broadcast_mndp", [])),
            "broadcast_mdns":            len(per_proto.get("broadcast_mdns", [])),
            "broadcast_ssdp":            len(per_proto.get("broadcast_ssdp", [])),
        })

    logger.info("Saved/updated in DB: %d", saved)
    return {"discovered": total, "saved": saved, "per_proto": {k: len(v) for k, v in per_proto.items()}}


# ===========================================================================
# Entry point
# ===========================================================================

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="NetDoc broadcast/multicast discovery worker (host-side)"
    )
    parser.add_argument("--once", action="store_true", help="Jeden cykl i wyjscie")
    parser.add_argument(
        "--interval", type=int, default=CYCLE_INTERVAL,
        help=f"Interwal cyklu w sekundach (domyslnie {CYCLE_INTERVAL})",
    )
    args = parser.parse_args()

    from netdoc.storage.database import init_db
    try:
        init_db()
    except Exception as exc:
        logger.warning("init_db: %s — kontynuuje bez migracji", exc)

    if args.once:
        stats = discover_once()
        logger.info("Done: discovered=%d saved=%d", stats["discovered"], stats["saved"])
        return

    logger.info("NetDoc Broadcast Worker start — interval=%ds, bind=%s",
                args.interval, _get_local_ip())
    while True:
        try:
            stats = discover_once()
            logger.info("Cycle done: discovered=%d saved=%d",
                        stats["discovered"], stats["saved"])
        except Exception as exc:
            logger.exception("Cycle error: %s", exc)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
