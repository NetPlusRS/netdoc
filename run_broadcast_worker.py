"""run_broadcast_worker.py — NetDoc broadcast/multicast discovery (host-side).

Architektura: CIAGLY NASLUCH — sockety sa otwarte przez caly czas.
Urzadzenia takie jak UniFi AP, MikroTik, Bonjour, UPnP same wysylaja
ogloszenia gdy pojawiaja sie w sieci — nie trzeba na nie czekac 5 minut.

Watki:
  listener_unifi  — nasluch UDP 10001 (broadcast)
  listener_mndp   — nasluch UDP 5678  (broadcast)
  listener_mdns   — nasluch UDP 5353  (multicast 224.0.0.251)
  listener_ssdp   — nasluch UDP 1900  (multicast 239.255.255.255)
  query_sender    — co QUERY_INTERVAL sekund wysyla aktywne zapytania
  db_writer       — czyta z kolejki, zapisuje do DB (throttle: 1x/5min per IP)

Uruchamianie:
    python run_broadcast_worker.py           # ciagly nasluch (domyslnie)
    python run_broadcast_worker.py --once    # jeden aktywny cykl i wyjscie
"""

import logging
import os
import queue
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(__file__))

# Hide console windows when running as pythonw.exe (no parent console)
if sys.platform == "win32":
    _OrigPopen = subprocess.Popen
    class _NoWindowPopen(_OrigPopen):
        def __init__(self, *args, **kwargs):
            kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)
            super().__init__(*args, **kwargs)
    subprocess.Popen = _NoWindowPopen

# ---------------------------------------------------------------------------
# Logging
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
# RAW packet logging — enabled by presence of broadcast_raw_enabled flag file
# ---------------------------------------------------------------------------
_LOGS_DIR      = os.path.join(os.path.dirname(__file__), "logs")
_RAW_FLAG_FILE = os.path.join(_LOGS_DIR, "broadcast_raw_enabled")
_RAW_LOG_PATH  = os.path.join(_LOGS_DIR, "broadcast_raw.log")
_RAW_MAX_BYTES = 4 * 1024 * 1024   # 4 MB — trim to 1 MB when exceeded
_raw_enabled   = threading.Event()  # set = raw logging on
_raw_lock      = threading.Lock()   # serialise writes


def _check_raw_flag() -> None:
    """Synchronizuje _raw_enabled z plikiem flagi (sprawdzaj co ~10s)."""
    if os.path.exists(_RAW_FLAG_FILE):
        if not _raw_enabled.is_set():
            _raw_enabled.set()
            logger.info("RAW packet logging ENABLED -> %s", _RAW_LOG_PATH)
    else:
        if _raw_enabled.is_set():
            _raw_enabled.clear()
            logger.info("RAW packet logging DISABLED")


def _write_raw(proto: str, src_ip: str, src_port: int, data: bytes) -> None:
    """Zapisuje surowy pakiet do broadcast_raw.log (hex dump + ASCII)."""
    if not _raw_enabled.is_set():
        return
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    header = f"{ts} [{proto:<9}] {src_ip}:{src_port}  {len(data)} bytes\n"
    rows = []
    for i in range(0, min(len(data), 512), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"  {i:04x}: {hex_part:<48}  {asc_part}\n")
    rows.append("\n")
    with _raw_lock:
        try:
            with open(_RAW_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(header + "".join(rows))
            # Trim file when too large — keep last 1 MB
            if os.path.getsize(_RAW_LOG_PATH) > _RAW_MAX_BYTES:
                with open(_RAW_LOG_PATH, "rb") as f:
                    f.seek(-1024 * 1024, 2)
                    tail = f.read()
                with open(_RAW_LOG_PATH, "wb") as f:
                    f.write(tail)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Broadcast stats — in-memory counters per (src_ip, proto)
# Struktura: {src_ip: {"UNIFI": [pkts, bytes], "MDNS": [...], ...}}
# ---------------------------------------------------------------------------
_bcast_stats: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))
_bcast_stats_lock = threading.Lock()
_bcast_stats_start = time.time()   # kiedy zaczelismy liczyc (do "uptime" w API)
_BCAST_STATS_MAX_IPS = 2000

_active_bind_ip: list = ["0.0.0.0"]   # mutable — updated by main() on network change
_rebind_event = threading.Event()      # set → listeners close socket and rebind with new IP


def _record_packet(proto: str, src_ip: str, nbytes: int) -> None:
    """Rejestruje pakiet w licznikach statystyk."""
    with _bcast_stats_lock:
        if src_ip not in _bcast_stats and len(_bcast_stats) >= _BCAST_STATS_MAX_IPS:
            return
        _bcast_stats[src_ip][proto][0] += 1
        _bcast_stats[src_ip][proto][1] += nbytes


def get_broadcast_stats() -> list[dict]:
    """Zwraca liste statystyk posortowana malejaco wg. liczby pakietow."""
    with _bcast_stats_lock:
        rows = []
        for ip, protos in _bcast_stats.items():
            total_pkts  = sum(v[0] for v in protos.values())
            total_bytes = sum(v[1] for v in protos.values())
            proto_detail = {p: {"pkts": v[0], "bytes": v[1]} for p, v in protos.items()}
            rows.append({
                "ip":           ip,
                "total_pkts":   total_pkts,
                "total_bytes":  total_bytes,
                "protocols":    proto_detail,
                "top_proto":    max(protos, key=lambda p: protos[p][0]),
            })
        rows.sort(key=lambda r: r["total_pkts"], reverse=True)
    return rows


# ---------------------------------------------------------------------------
# Stale
# ---------------------------------------------------------------------------
UNIFI_PORT     = 10001
MNDP_PORT      = 5678
MDNS_PORT      = 5353
SSDP_PORT      = 1900
MDNS_GROUP     = "224.0.0.251"
SSDP_GROUP     = "239.255.255.255"

QUERY_INTERVAL = 60      # sekund miedzy aktywnymi zapytaniami discovery
DB_THROTTLE_S  = 300     # min. sekund miedzy zapisami tego samego IP do DB
UPNP_FETCH_MAX = 8       # max HTTP fetchy na cykl zapytan


# ===========================================================================
# Parsery pakietow (wspolne dla nasluch + aktywny skan)
# ===========================================================================

def _parse_unifi_tlv(data: bytes, src_ip: str) -> Optional[dict]:
    if len(data) < 4:
        return None
    result: dict = {"ip": src_ip, "protocol": "unifi"}
    pos = 4
    while pos + 3 <= len(data):
        t  = data[pos]
        ln = struct.unpack(">H", data[pos + 1:pos + 3])[0]
        v  = data[pos + 3:pos + 3 + ln]
        pos += 3 + ln
        if   t == 0x01:
            if len(v) == 12:
                result["mac"] = ":".join(f"{b:02X}" for b in v[:6])
        elif t == 0x02:
            if len(v) >= 6:
                result.setdefault("mac", ":".join(f"{b:02X}" for b in v[:6]))
        elif t == 0x0B:
            if len(v) == 6:
                result["ip"] = ".".join(str(b) for b in v[2:6])
        elif t == 0x15:
            result["hostname"] = v.decode("utf-8", errors="replace").strip("\x00")
        elif t == 0x03:
            result["firmware"] = v.decode("utf-8", errors="replace").strip("\x00")
        elif t == 0x0C:
            result["model"] = v.decode("utf-8", errors="replace").strip("\x00")
        elif t == 0x13:
            result.setdefault("model", v.decode("utf-8", errors="replace").strip("\x00"))
    return result if ("mac" in result or "hostname" in result) else None


def _parse_mndp_tlv(data: bytes, src_ip: str) -> Optional[dict]:
    if len(data) < 4:
        return None
    result: dict = {"ip": src_ip, "protocol": "mndp", "vendor": "MikroTik"}
    pos = 4
    while pos + 4 <= len(data):
        t  = struct.unpack(">H", data[pos:pos + 2])[0]
        ln = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        v  = data[pos + 4:pos + 4 + ln]
        pos += 4 + ln
        try:
            if   t == 0x0001:
                if len(v) >= 6:
                    result["mac"] = ":".join(f"{b:02X}" for b in v[:6])
            elif t == 0x0005:
                result["hostname"] = v.decode("utf-8", errors="replace").rstrip("\x00")
            elif t == 0x0007:
                result["firmware"] = v.decode("utf-8", errors="replace").rstrip("\x00")
            elif t == 0x0008:
                result["model"] = v.decode("utf-8", errors="replace").rstrip("\x00")
            elif t == 0x000E:
                if len(v) == 4:
                    result["ip"] = ".".join(str(b) for b in v)
        except Exception:
            pass
    return result if len(result) > 3 else None


_MDNS_QUERIES = [
    b"_ssh._tcp.local",   b"_http._tcp.local",  b"_rtsp._tcp.local",
    b"_printer._tcp.local", b"_ipp._tcp.local",  b"_smb._tcp.local",
    b"_ftp._tcp.local",   b"_airplay._tcp.local", b"_googlecast._tcp.local",
    b"_daap._tcp.local",
]


def _dns_encode(name: bytes) -> bytes:
    enc = b""
    for label in name.split(b"."):
        enc += bytes([len(label)]) + label
    return enc + b"\x00"


def _build_mdns_query(service: bytes) -> bytes:
    return b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + _dns_encode(service) + b"\x00\x0C\x00\x01"


def _read_dns_name(data: bytes, pos: int) -> tuple[str, int]:
    labels, jumped, orig_pos, jumps = [], False, pos, 0
    while pos < len(data) and jumps < 20:
        length = data[pos]
        if length == 0:
            pos += 1; break
        elif (length & 0xC0) == 0xC0:
            if pos + 1 >= len(data): break
            ptr = struct.unpack(">H", data[pos:pos + 2])[0] & 0x3FFF
            if not jumped: orig_pos = pos + 2
            jumped, pos, jumps = True, ptr, jumps + 1
        else:
            pos += 1
            labels.append(data[pos:pos + length].decode("utf-8", errors="replace"))
            pos += length
    return ".".join(labels), (orig_pos if jumped else pos)


def _parse_mdns_response(data: bytes, src_ip: str) -> Optional[dict]:
    if len(data) < 12: return None
    flags = struct.unpack(">H", data[2:4])[0]
    if not (flags & 0x8000): return None
    qdcount = struct.unpack(">H", data[4:6])[0]
    ancount = struct.unpack(">H", data[6:8])[0]
    arcount = struct.unpack(">H", data[10:12])[0]
    pos = 12
    for _ in range(qdcount):
        try: _, pos = _read_dns_name(data, pos); pos += 4
        except Exception: return None
    hostnames, services = [], []
    for _ in range(ancount + arcount):
        if pos >= len(data) - 10: break
        try:
            _name, pos = _read_dns_name(data, pos)
            if pos + 10 > len(data): break
            rtype = struct.unpack(">H", data[pos:pos + 2])[0]
            pos += 8
            rdlen = struct.unpack(">H", data[pos:pos + 2])[0]
            pos += 2
            rdata = data[pos:pos + rdlen]; pos += rdlen
            if rtype == 12:
                target, _ = _read_dns_name(rdata, 0)
                parts = target.split(".")
                if len(parts) >= 4 and parts[-1] == "local":
                    svc = parts[-3].lstrip("_")
                    if svc: services.append(svc)
                    hostnames.append(parts[0])
            elif rtype == 33:
                if len(rdata) >= 6:
                    h, _ = _read_dns_name(rdata, 6)
                    hostnames.append(h.replace(".local", "").split(".")[0])
            elif rtype == 1:
                if rdlen == 4:
                    ip4 = ".".join(str(b) for b in rdata)
                    if not ip4.startswith("169.254"): src_ip = ip4
        except Exception: break
    if not services and not hostnames: return None
    _MDNS_NOISE = {"ssh", "http", "https", "smb", "ftp", "rdp", "telnet",
                   "tcp", "udp", "sip", "afpovertcp", "rfb", "vnc", "sftp"}
    meaningful = [h for h in hostnames if h.lower() not in _MDNS_NOISE and not h.startswith("_")]
    hostname = max(meaningful, key=len) if meaningful else (max(hostnames, key=len) if hostnames else None)
    return {"ip": src_ip, "protocol": "mdns", "hostname": hostname, "services": list(set(services))}


_SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.255:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 3\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode()


def _fetch_upnp_description(url: str, timeout: float = 3.0) -> dict:
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "NetDoc/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            xml = resp.read(32768).decode("utf-8", errors="replace")
        result = {}
        for tag in ("friendlyName", "manufacturer", "modelName", "modelNumber", "serialNumber"):
            m = re.search(rf"<{tag}[^>]*>\s*([^<]+?)\s*</{tag}>", xml, re.IGNORECASE)
            if m: result[tag] = m.group(1)
        return result
    except Exception:
        return {}


def _parse_ssdp_packet(data: bytes, src_ip: str) -> Optional[dict]:
    text = data.decode("utf-8", errors="replace")
    if "200 OK" not in text and "NOTIFY" not in text:
        return None
    entry: dict = {"ip": src_ip, "protocol": "ssdp"}
    loc_m = re.search(r"LOCATION:\s*(\S+)", text, re.IGNORECASE)
    if loc_m: entry["location_url"] = loc_m.group(1)
    srv_m = re.search(r"SERVER:\s*(.+)", text, re.IGNORECASE)
    if srv_m: entry["server_header"] = srv_m.group(1).strip()
    return entry


# ===========================================================================
# Pomocnicze
# ===========================================================================

def _get_local_ip() -> str:
    # On Windows: prefer explicit-gateway default routes (excludes Docker/WSL On-link routes
    # that may have metric 0 and steal traffic from the real LAN interface).
    if sys.platform == "win32":
        try:
            import re as _re
            r = subprocess.run(["route", "print", "0.0.0.0"],
                               capture_output=True, text=True, timeout=3)
            candidates = []
            for line in r.stdout.splitlines():
                m = _re.search(
                    r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)",
                    line,
                )
                if m:
                    candidates.append((int(m.group(3)), m.group(2)))
            if candidates:
                candidates.sort()
                return candidates[0][1]  # interface IP of lowest-metric real route
        except Exception:
            pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return "0.0.0.0"


def _services_to_device_type(services: list[str], protocol: str):
    from netdoc.storage.models import DeviceType
    if protocol == "unifi": return DeviceType.ap
    if protocol == "mndp":  return DeviceType.router
    s = set(sv.lower() for sv in services)
    if "printer" in s or "ipp" in s: return DeviceType.printer
    if "rtsp" in s or "camera" in s: return DeviceType.camera
    return DeviceType.unknown


def _set_status(db, updates: dict) -> None:
    from netdoc.storage.models import SystemStatus
    for key, value in updates.items():
        row = db.query(SystemStatus).filter(SystemStatus.key == key).first()
        if row:
            row.value = str(value)
        else:
            db.add(SystemStatus(key=key, value=str(value), category="broadcast_worker"))
    try: db.commit()
    except Exception: db.rollback()


# ===========================================================================
# DB writer — throttled, zbiera z kolejki
# ===========================================================================

def _save_one(db, r: dict) -> bool:
    """Zapisuje jedno odkryte urzadzenie. Zwraca True jesli zapisano."""
    from netdoc.collector.discovery import upsert_device
    from netdoc.collector.normalizer import DeviceData, normalize_mac

    ip = r.get("ip")
    if not ip or ip.startswith("127.") or ip.startswith("169.254"):
        return False

    protocol = r.get("protocol", "")
    services = r.get("services", [])
    hostname = r.get("hostname") or r.get("friendly_name") or None
    # Odrzuc UUID-like hostname z mDNS (np. "f742ad63-3442-62de-cf7e-4d728b36398c")
    # — to jest mDNS instance ID, nie uzyteczna nazwa hosta
    if hostname and re.match(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', hostname, re.IGNORECASE
    ):
        hostname = None
    vendor   = r.get("vendor")
    if not vendor and protocol == "mndp":   vendor = "MikroTik"
    if not vendor and protocol == "unifi":  vendor = "Ubiquiti"
    if not vendor:
        sh = (r.get("server_header") or "").lower()
        for kw, vd in (("synology", "Synology"), ("qnap", "QNAP"),
                       ("hikvision", "Hikvision"), ("dahua", "Dahua")):
            if kw in sh: vendor = vd; break

    data = DeviceData(
        ip=ip, mac=normalize_mac(r.get("mac")),
        hostname=hostname, vendor=vendor,
        model=r.get("model"), os_version=r.get("firmware"),
        device_type=_services_to_device_type(services, protocol),
    )
    try:
        dev = upsert_device(db, data)
        # asset_notes — tagged section [broadcast ...] coexists with cred worker tags
        extra_parts = []
        if services:                      extra_parts.append("svc=" + ",".join(sorted(services)))
        if r.get("serial_number"):        extra_parts.append("serial=" + r["serial_number"])
        if r.get("server_header") and not vendor:
            extra_parts.append("upnp=" + r["server_header"][:40])
        if extra_parts and dev:
            note_tag = "[broadcast " + " ".join(extra_parts) + "]"
            current  = dev.asset_notes or ""
            if re.search(r"\[broadcast [^\]]*\]", current):
                dev.asset_notes = re.sub(r"\[broadcast [^\]]*\]", note_tag, current)
            else:
                dev.asset_notes = (current.strip() + "\n" + note_tag).strip()
        db.commit()
        return True
    except Exception as exc:
        logger.warning("DB save error %s: %s", ip, exc)
        db.rollback()
        return False


def db_writer_thread(q: queue.Queue, stop_event: threading.Event) -> None:
    """Czyta z kolejki i zapisuje do DB. Throttle: min DB_THROTTLE_S miedzy zapisami per IP."""
    from netdoc.storage.database import SessionLocal

    last_saved: dict[str, float] = {}   # ip → timestamp ostatniego zapisu
    # Statystyki per protokol do systemu
    proto_counts: dict[str, int] = {"unifi": 0, "mndp": 0, "mdns": 0, "ssdp": 0}
    last_stats_save = time.monotonic()

    db = SessionLocal()
    try:
        while not stop_event.is_set():
            try:
                r = q.get(timeout=1.0)
            except queue.Empty:
                # Co minute zapisz statystyki do systemu
                if time.monotonic() - last_stats_save > 60:
                    try:
                        _set_status(db, {
                            "broadcast_last_at":         datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                            "broadcast_last_discovered": sum(proto_counts.values()),
                            "broadcast_unifi": proto_counts["unifi"],
                            "broadcast_mndp":  proto_counts["mndp"],
                            "broadcast_mdns":  proto_counts["mdns"],
                            "broadcast_ssdp":  proto_counts["ssdp"],
                        })
                    except Exception:
                        try:
                            db.rollback()
                        except Exception:
                            pass
                    last_stats_save = time.monotonic()
                continue

            ip = r.get("ip", "")
            now = time.monotonic()
            if now - last_saved.get(ip, 0) < DB_THROTTLE_S:
                continue  # za czesto — pomijamy

            if _save_one(db, r):
                last_saved[ip] = now
                proto = r.get("protocol", "other")
                proto_counts[proto] = proto_counts.get(proto, 0) + 1
                logger.info("%-6s  %-18s  hostname=%-28s vendor=%-15s model=%s",
                            proto.upper(), ip,
                            r.get("hostname") or "-",
                            r.get("vendor") or "-",
                            r.get("model") or "-")
    finally:
        db.close()


# ===========================================================================
# Watki nasluchujace
# ===========================================================================

def listener_unifi(q: queue.Queue, stop_event: threading.Event) -> None:
    """Ciagly nasluch na UDP 10001 — UniFi APs same wysylaja periodic beacony."""
    s = None
    while not stop_event.is_set():
        if _rebind_event.is_set() and s is not None:
            try: s.close()
            except Exception: pass
            s = None
        try:
            if s is None:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.settimeout(2.0)
                s.bind((_active_bind_ip[0], UNIFI_PORT))
            try:
                data, (src_ip, src_port) = s.recvfrom(4096)
                if src_ip == _active_bind_ip[0]: continue
                _write_raw("UNIFI", src_ip, src_port, data)
                _record_packet("UNIFI", src_ip, len(data))
                parsed = _parse_unifi_tlv(data, src_ip)
                if parsed: q.put(parsed)
            except socket.timeout:
                pass
        except OSError as exc:
            logger.debug("UniFi listener error: %s — restarting socket", exc)
            try: s.close()
            except Exception: pass
            s = None
            time.sleep(5)
    if s:
        try: s.close()
        except Exception: pass


def listener_mndp(q: queue.Queue, stop_event: threading.Event) -> None:
    """Ciagly nasluch na UDP 5678 — MikroTik wysyla MNDP co ~60s."""
    s = None
    while not stop_event.is_set():
        if _rebind_event.is_set() and s is not None:
            try: s.close()
            except Exception: pass
            s = None
        try:
            if s is None:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.settimeout(2.0)
                s.bind(("", MNDP_PORT))
            try:
                data, (src_ip, src_port) = s.recvfrom(4096)
                if src_ip == _active_bind_ip[0]: continue
                _write_raw("MNDP", src_ip, src_port, data)
                _record_packet("MNDP", src_ip, len(data))
                parsed = _parse_mndp_tlv(data, src_ip)
                if parsed: q.put(parsed)
            except socket.timeout:
                pass
        except OSError as exc:
            logger.debug("MNDP listener error: %s — restarting socket", exc)
            try: s.close()
            except Exception: pass
            s = None; time.sleep(5)
    if s:
        try: s.close()
        except Exception: pass


def listener_mdns(q: queue.Queue, stop_event: threading.Event) -> None:
    """Ciagly nasluch mDNS multicast 224.0.0.251:5353."""
    s = None
    mreq = None
    while not stop_event.is_set():
        if _rebind_event.is_set() and s is not None:
            if mreq:
                try: s.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
                except Exception: pass
            try: s.close()
            except Exception: pass
            s = None; mreq = None
        try:
            if s is None:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                mreq = struct.pack("4s4s", socket.inet_aton(MDNS_GROUP), socket.inet_aton(_active_bind_ip[0]))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(_active_bind_ip[0]))
                s.settimeout(2.0)
                try:
                    s.bind(("", MDNS_PORT))
                except OSError:
                    s.bind(("", 0))  # port zajety — ephemeral
            try:
                data, (src_ip, src_port) = s.recvfrom(4096)
                if src_ip == _active_bind_ip[0]: continue
                _write_raw("MDNS", src_ip, src_port, data)
                _record_packet("MDNS", src_ip, len(data))
                parsed = _parse_mdns_response(data, src_ip)
                if parsed: q.put(parsed)
            except socket.timeout:
                pass
        except OSError as exc:
            logger.debug("mDNS listener error: %s — restarting socket", exc)
            if s and mreq:
                try: s.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
                except Exception: pass
            try: s.close()
            except Exception: pass
            s = None; mreq = None; time.sleep(5)
    if s:
        if mreq:
            try: s.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
            except Exception: pass
        try: s.close()
        except Exception: pass


def listener_ssdp(q: queue.Queue, stop_event: threading.Event) -> None:
    """Ciagly nasluch SSDP multicast 239.255.255.255:1900."""
    s = None
    _upnp_pending: dict[str, float] = {}  # url → timestamp (throttle fetchow)
    while not stop_event.is_set():
        if _rebind_event.is_set() and s is not None:
            try: s.close()
            except Exception: pass
            s = None
        try:
            if s is None:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                mreq = struct.pack("4s4s", socket.inet_aton(SSDP_GROUP), socket.inet_aton(_active_bind_ip[0]))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(_active_bind_ip[0]))
                s.settimeout(2.0)
                try: s.bind(("", SSDP_PORT))
                except OSError: s.bind(("", 0))
            try:
                data, (src_ip, src_port) = s.recvfrom(4096)
                if src_ip == _active_bind_ip[0]: continue
                _write_raw("SSDP", src_ip, src_port, data)
                _record_packet("SSDP", src_ip, len(data))
                entry = _parse_ssdp_packet(data, src_ip)
                if not entry: continue
                url = entry.get("location_url")
                now = time.monotonic()
                # Purge stale entries to prevent unbounded growth
                if len(_upnp_pending) > 500:
                    _upnp_pending = {u: t for u, t in _upnp_pending.items()
                                     if now - t < DB_THROTTLE_S * 2}
                # Fetch UPnP description — max 1x/5min per URL
                if url and now - _upnp_pending.get(url, 0) > DB_THROTTLE_S:
                    _upnp_pending[url] = now
                    desc = _fetch_upnp_description(url)
                    if desc:
                        entry["friendly_name"] = desc.get("friendlyName")
                        entry["vendor"]        = desc.get("manufacturer")
                        entry["model"]         = desc.get("modelName") or desc.get("modelNumber")
                        entry["serial_number"] = desc.get("serialNumber")
                q.put(entry)
            except socket.timeout:
                pass
        except OSError as exc:
            logger.debug("SSDP listener error: %s — restarting socket", exc)
            try: s.close()
            except Exception: pass
            s = None; time.sleep(5)
    if s:
        try: s.close()
        except Exception: pass


# ===========================================================================
# Watek aktywnych zapytan
# ===========================================================================

def query_sender(stop_event: threading.Event) -> None:
    """Co QUERY_INTERVAL sekund wysyla aktywne pakiety discovery do wszystkich protokolow.

    Wymagane dla urzadzen ktore NIE wysylaja periodic beaconow (np. niektore SSDP).
    mDNS i UniFi odpowiadaja tez na pasywne ogloszenia — tu tylko aktywne zapytania.
    Czyta aktualny bind IP z _active_bind_ip[0] — aktualizowany przy zmianie sieci.
    """
    def _send_unifi():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.bind((_active_bind_ip[0], 0))
            s.sendto(b"\x01\x00\x00\x00", ("255.255.255.255", UNIFI_PORT))
            s.close()
        except Exception: pass

    def _send_mndp():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.bind((_active_bind_ip[0], 0))
            s.sendto(b"\x00\x00\x00\x00", ("255.255.255.255", MNDP_PORT))
            s.close()
        except Exception: pass

    def _send_mdns():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(_active_bind_ip[0]))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            s.bind((_active_bind_ip[0], 0))
            for svc in _MDNS_QUERIES:
                s.sendto(_build_mdns_query(svc), (MDNS_GROUP, MDNS_PORT))
            s.close()
        except Exception: pass

    def _send_ssdp():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(_active_bind_ip[0]))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
            s.bind((_active_bind_ip[0], 0))
            s.sendto(_SSDP_MSEARCH, (SSDP_GROUP, SSDP_PORT))
            s.close()
        except Exception: pass

    while not stop_event.is_set():
        logger.debug("Active query: UniFi + MNDP + mDNS + SSDP")
        _send_unifi()
        _send_mndp()
        _send_mdns()
        _send_ssdp()
        # Czekaj QUERY_INTERVAL z mozliwoscia przerwania; co 10s sprawdz flage RAW
        for i in range(QUERY_INTERVAL):
            if stop_event.is_set(): return
            if i % 10 == 0:
                _check_raw_flag()
            time.sleep(1)


# ===========================================================================
# Tryb --once (jeden aktywny cykl, bez ciagłego nasluch)
# ===========================================================================

def discover_once() -> dict:
    """Aktywny cykl discovery — wysyla zapytania, czeka na odpowiedzi, zapisuje."""
    from netdoc.storage.database import SessionLocal

    bind_ip = _get_local_ip()
    logger.info("=== Broadcast discovery (once) — bind_ip=%s ===", bind_ip)

    q: queue.Queue = queue.Queue()
    stop = threading.Event()

    _active_bind_ip[0] = bind_ip  # shared with listener threads
    threads = [
        threading.Thread(target=listener_unifi, args=(q, stop), daemon=True),
        threading.Thread(target=listener_mndp,  args=(q, stop), daemon=True),
        threading.Thread(target=listener_mdns,  args=(q, stop), daemon=True),
        threading.Thread(target=listener_ssdp,  args=(q, stop), daemon=True),
    ]
    for t in threads: t.start()

    # Wyslij aktywne zapytania
    time.sleep(0.5)  # sockety potrzebuja chwili na bind
    for fn_name, send_fn in [
        ("UniFi", lambda: _send_broadcast(bind_ip, b"\x01\x00\x00\x00", UNIFI_PORT)),
        ("MNDP",  lambda: _send_broadcast(bind_ip, b"\x00\x00\x00\x00", MNDP_PORT)),
        ("mDNS",  lambda: _send_mdns_queries(bind_ip)),
        ("SSDP",  lambda: _send_ssdp_query(bind_ip)),
    ]:
        try: send_fn()
        except Exception as exc: logger.debug("%s send error: %s", fn_name, exc)

    time.sleep(5)  # zbierz odpowiedzi
    stop.set()
    for t in threads: t.join(timeout=3)

    # Zbierz wyniki z kolejki
    results = []
    while not q.empty():
        try: results.append(q.get_nowait())
        except queue.Empty: break

    # Deduplikuj po IP
    by_ip: dict[str, dict] = {}
    for r in results:
        ip = r.get("ip", "")
        if ip not in by_ip:
            by_ip[ip] = r
        else:
            # Merge services z mDNS
            existing_svc = by_ip[ip].get("services", [])
            new_svc = r.get("services", [])
            by_ip[ip]["services"] = list(set(existing_svc + new_svc))

    proto_counts: dict[str, int] = {}
    for r in by_ip.values():
        proto_counts[r.get("protocol", "?")] = proto_counts.get(r.get("protocol", "?"), 0) + 1
    for p, n in proto_counts.items():
        logger.info("%-8s %d device(s)", p.upper(), n)

    total = len(by_ip)
    logger.info("Total discovered: %d", total)

    saved = 0
    with SessionLocal() as db:
        for r in by_ip.values():
            if _save_one(db, r): saved += 1
        _set_status(db, {
            "broadcast_last_at":         datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "broadcast_last_discovered": total,
            "broadcast_last_saved":      saved,
            "broadcast_unifi": proto_counts.get("unifi", 0),
            "broadcast_mndp":  proto_counts.get("mndp",  0),
            "broadcast_mdns":  proto_counts.get("mdns",  0),
            "broadcast_ssdp":  proto_counts.get("ssdp",  0),
        })

    logger.info("Done: discovered=%d saved=%d", total, saved)
    return {"discovered": total, "saved": saved, "per_proto": proto_counts}


def _send_broadcast(bind_ip: str, pkt: bytes, port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind((bind_ip, 0))
    s.sendto(pkt, ("255.255.255.255", port))
    s.close()


def _send_mdns_queries(bind_ip: str) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_ip))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    s.bind((bind_ip, 0))
    for svc in _MDNS_QUERIES:
        s.sendto(_build_mdns_query(svc), (MDNS_GROUP, MDNS_PORT))
    s.close()


def _send_ssdp_query(bind_ip: str) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_ip))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
    s.bind((bind_ip, 0))
    s.sendto(_SSDP_MSEARCH, (SSDP_GROUP, SSDP_PORT))
    s.close()


# ===========================================================================
# Entry point
# ===========================================================================

def _acquire_broadcast_lock() -> bool:
    """Zapewnia ze tylko jedna instancja broadcast worker dziala na hoscie (PID lock).

    Wzorzec identyczny jak _acquire_scanner_lock() w run_scanner.py — PID file
    + weryfikacja procesu przez psutil. Zwraca False jesli inna instancja dziala.
    """
    pid_path = os.path.join(os.path.dirname(__file__), "broadcast.pid")
    my_pid = os.getpid()

    if os.path.exists(pid_path):
        try:
            with open(pid_path) as _f:
                old_pid = int(_f.read().strip())
            if old_pid != my_pid:
                try:
                    import psutil
                    proc = psutil.Process(old_pid)
                    if proc.is_running():
                        cmdline = " ".join(proc.cmdline()).lower()
                        if "python" in proc.name().lower() and "broadcast_worker" in cmdline:
                            logger.error(
                                "Another broadcast worker instance is already running (PID=%d). Exiting.",
                                old_pid,
                            )
                            return False
                except (ImportError, Exception):
                    pass
                logger.warning("Stale broadcast.pid (PID=%d) — overwriting.", old_pid)
        except (ValueError, OSError):
            pass

    try:
        try:
            os.remove(pid_path)
        except OSError:
            pass
        with open(pid_path, "x") as _f:
            _f.write(str(my_pid))
    except FileExistsError:
        logger.error("Race condition: another broadcast worker grabbed the lock. Exiting.")
        return False
    return True


def _wait_for_postgres(retry_interval: int = 30) -> None:
    """Czeka az PostgreSQL bedzie dostepny, po czym wywoluje init_db().

    Nie odpada do SQLite — broadcast worker wymaga prawdziwej bazy.
    Proba co retry_interval sekund az do skutku (np. Docker jeszcze startuje).
    """
    from netdoc.storage.database import init_db
    from netdoc.config.settings import settings
    import sqlalchemy

    attempt = 0
    while True:
        attempt += 1
        try:
            eng = sqlalchemy.create_engine(
                settings.database_url,
                connect_args={"connect_timeout": 5},
                pool_pre_ping=True,
            )
            with eng.connect() as conn:
                conn.execute(sqlalchemy.text("SELECT 1"))
            eng.dispose()
            init_db()
            logger.info("PostgreSQL ready (%s) — broadcast worker starting", settings.database_url)
            return
        except Exception as exc:
            logger.warning(
                "PostgreSQL not available yet (attempt %d): %s — retrying in %ds",
                attempt, exc, retry_interval,
            )
            time.sleep(retry_interval)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="NetDoc broadcast/multicast discovery (host-side, continuous listener)"
    )
    parser.add_argument("--once", action="store_true",
                        help="Jeden aktywny cykl i wyjscie (tryb diagnostyczny)")
    parser.add_argument("--query-interval", type=int, default=QUERY_INTERVAL,
                        help=f"Interwal aktywnych zapytan w sekundach (domyslnie {QUERY_INTERVAL})")
    args = parser.parse_args()

    if not args.once:
        if not _acquire_broadcast_lock():
            sys.exit(0)

    _wait_for_postgres()

    if args.once:
        stats = discover_once()
        logger.info("Done: %s", stats)
        return

    _pid_path = os.path.join(os.path.dirname(__file__), "broadcast.pid")

    bind_ip = _get_local_ip()
    _active_bind_ip[0] = bind_ip  # shared with listener threads
    logger.info("NetDoc Broadcast Worker start — continuous listener, bind=%s PID=%d",
                bind_ip, os.getpid())
    logger.info("Active query interval: %ds | DB throttle: %ds per IP", args.query_interval, DB_THROTTLE_S)

    pkt_queue: queue.Queue = queue.Queue(maxsize=1000)
    stop_event = threading.Event()

    import signal as _signal
    def _sigterm_handler(signum, frame):
        logger.info("SIGTERM received — shutting down")
        stop_event.set()
    _signal.signal(_signal.SIGTERM, _sigterm_handler)

    threads = [
        threading.Thread(target=listener_unifi,  args=(pkt_queue, stop_event),
                         name="listener-unifi",  daemon=True),
        threading.Thread(target=listener_mndp,   args=(pkt_queue, stop_event),
                         name="listener-mndp",   daemon=True),
        threading.Thread(target=listener_mdns,   args=(pkt_queue, stop_event),
                         name="listener-mdns",   daemon=True),
        threading.Thread(target=listener_ssdp,   args=(pkt_queue, stop_event),
                         name="listener-ssdp",   daemon=True),
        threading.Thread(target=query_sender,    args=(stop_event,),
                         name="query-sender",    daemon=True),
        threading.Thread(target=db_writer_thread, args=(pkt_queue, stop_event),
                         name="db-writer",       daemon=False),  # nie-daemon — czeka na stop
    ]

    for t in threads:
        t.start()
        logger.info("Thread started: %s", t.name)

    _stats_path = os.path.join(_LOGS_DIR, "broadcast_stats.json")
    _last_stats_flush = 0.0
    _ch_prev_totals: dict[str, float] = {}  # ip → last flushed total_pkts

    _SCAN_NOW_FLAG = os.path.join(os.path.dirname(__file__), "scan_now.flag")
    _last_ip_check = 0.0
    _IP_CHECK_INTERVAL = 15  # sekund

    try:
        while True:
            time.sleep(10)
            # Sprawdz czy db-writer zyje
            db_thread = next((t for t in threads if t.name == "db-writer"), None)
            if db_thread and not db_thread.is_alive():
                logger.error("db-writer thread died — restarting")
                new_t = threading.Thread(target=db_writer_thread,
                                         args=(pkt_queue, stop_event), name="db-writer", daemon=False)
                new_t.start()
                threads[threads.index(db_thread)] = new_t
            # Wykryj zmianę interfejsu sieciowego → rebind socketów + scan_now.flag
            now = time.monotonic()
            if now - _last_ip_check >= _IP_CHECK_INTERVAL:
                _last_ip_check = now
                new_ip = _get_local_ip()
                if new_ip != "0.0.0.0" and new_ip != _active_bind_ip[0]:
                    old_ip = _active_bind_ip[0]
                    _active_bind_ip[0] = new_ip
                    logger.info("Network change: %s → %s — rebinding sockets", old_ip, new_ip)
                    logger.info("NetDoc Broadcast Worker rebind — bind=%s PID=%d", new_ip, os.getpid())
                    _rebind_event.set()
                    threading.Timer(5.0, _rebind_event.clear).start()
                    with _bcast_stats_lock:
                        _bcast_stats.clear()
                    _ch_prev_totals.clear()
                    try:
                        with open(_SCAN_NOW_FLAG, "w") as _f:
                            _f.write(datetime.utcnow().isoformat())
                    except Exception as _fe:
                        logger.warning("Cannot create scan_now.flag: %s", _fe)

            # Zapisz statystyki co 30s do logs/broadcast_stats.json + ClickHouse
            if now - _last_stats_flush >= 30:
                _last_stats_flush = now
                stats_rows = get_broadcast_stats()
                try:
                    import json as _json
                    payload = {
                        "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "uptime_s":     int(time.time() - _bcast_stats_start),
                        "rows":         stats_rows,
                    }
                    tmp = _stats_path + ".tmp"
                    with open(tmp, "w", encoding="utf-8") as _f:
                        _json.dump(payload, _f)
                    os.replace(tmp, _stats_path)
                except Exception as _e:
                    logger.debug("stats flush error: %s", _e)
                # Zapisz do ClickHouse — passive_bcast_pkts per device
                # Worker działa na hoście Windows — ClickHouse dostępny przez localhost
                try:
                    import os as _os
                    _os.environ.setdefault("CLICKHOUSE_HOST", "localhost")
                    from netdoc.storage.database import SessionLocal as _SL
                    from netdoc.storage.models import Device as _Dev
                    from netdoc.storage.clickhouse import insert_if_metrics as _insert
                    _now_dt = datetime.utcnow()
                    _ch_rows = []
                    _db2 = _SL()
                    try:
                        for _sr in stats_rows:
                            _ip = _sr["ip"]
                            _total = float(_sr["total_pkts"])
                            _prev  = _ch_prev_totals.get(_ip, _total)
                            _delta = max(0.0, _total - _prev)
                            _ch_prev_totals[_ip] = _total
                            if _delta <= 0:
                                continue
                            _dev = _db2.query(_Dev).filter(_Dev.ip == _ip).first()
                            if _dev:
                                _ch_rows.append((_now_dt, _dev.id, 0, "passive_bcast_pkts", _delta))
                    finally:
                        _db2.close()
                    if _ch_rows:
                        _insert(_ch_rows)
                except Exception as _ce:
                    logger.warning("broadcast ClickHouse flush error: %s", _ce)
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
        stop_event.set()
        for t in threads:
            t.join(timeout=5)
        logger.info("Broadcast worker stopped")
    finally:
        # Clean up PID file on exit
        try:
            if os.path.exists(_pid_path):
                os.remove(_pid_path)
        except Exception:
            pass


if __name__ == "__main__":
    main()
