"""Netdoc Vulnerability Worker.

Sprawdzane podatnosci (bez zewnetrznych skanerow):
  open_telnet, anonymous_ftp, open_ftp, snmp_public, mqtt_noauth,
  redis_noauth, elasticsearch_noauth, docker_api_exposed, http_management,
  ssl_expired, ssl_self_signed, ipmi_exposed, default_credentials
"""
import ftplib, logging, os, socket, ssl, sys, time
from typing import Optional
from sqlalchemy import or_
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import httpx
from prometheus_client import Gauge, start_http_server
from netdoc.storage.database import SessionLocal, init_db
from netdoc.storage.models import (
    Device, DeviceType, Credential, CredentialMethod,
    Event, EventType, Vulnerability, VulnType, VulnSeverity, SystemStatus,
)
from netdoc.config.settings import settings
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [VULN] %(levelname)s %(message)s", stream=sys.stdout)
logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)    # wycisz INFO o kazdym HTTP request
_DEFAULT_INTERVAL = int(os.getenv("VULN_INTERVAL_S",  "120"))
_DEFAULT_WORKERS  = int(os.getenv("VULN_WORKERS",      "16"))
METRICS_PORT      = int(os.getenv("VULN_METRICS_PORT", "8004"))
# Minimum pause between consecutive scans even when a scan overshoots the interval.
# Prevents back-to-back scans with sleep(0) when the system is under load.
_MIN_PAUSE_S = 10
_TCP_TIMEOUT = 3.0
_HTTP_TIMEOUT = 5.0
g_scanned  = Gauge("netdoc_vuln_scanned",    "Urzadzenia przeskanowane")
g_open     = Gauge("netdoc_vuln_open",       "Otwarte podatnosci")
g_new      = Gauge("netdoc_vuln_new_total",  "Nowe podatnosci od startu")
g_resolved = Gauge("netdoc_vuln_resolved",   "Rozwiazane od startu")
g_duration = Gauge("netdoc_vuln_duration_s", "Czas cyklu [s]")
_total_new = 0
_total_resolved = 0
# PERF-06: cache credentials per-cycle, loaded once before thread pool
_global_creds_cache: dict = {}

# ── Filtrowanie skanowania wg typu urządzenia ────────────────────────────────
# Drukarki: TCP connect do portu 9100 (JetDirect) może wysłać losowe bajty
# jako zadanie drukowania. Pomijamy wszystkie sprawdzenia dla drukarek.
_SKIP_VULN_DEVICE_TYPES = frozenset({DeviceType.printer})

# AP/kamera/IoT/telefon: nie uruchamiają baz danych ani serwerowych usług.
# Ograniczamy do sprawdzeń sieciowych (telnet, http, snmp, kamery, firewall).
_LIMITED_VULN_DEVICE_TYPES = frozenset({
    DeviceType.ap, DeviceType.camera, DeviceType.iot,
})

# Sprawdzenia tylko dla serwerów/infrastruktury (pominięte dla AP/kamer/IoT)
_INFRA_CHECKS_NAMES = frozenset({
    "check_mqtt", "check_redis", "check_elasticsearch", "check_docker_api",
    "check_ipmi", "check_mongo", "check_mysql", "check_postgres_weak",
    "check_mssql_weak", "check_vnc_weak", "check_couchdb", "check_memcached",
    "check_influxdb", "check_cassandra", "check_rtsp_weak",
})


def _read_settings() -> tuple:
    """PERF-14: jedna query WHERE key IN (...) zamiast 7 osobnych SELECT."""
    from netdoc.storage.models import SystemStatus
    _KEYS = ("vuln_interval_s", "vuln_workers", "vuln_close_after",
             "vuln_skip_printers", "vuln_limit_ap_iot",
             "vuln_tcp_timeout", "vuln_http_timeout")
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
        return (
            max(10,  _i("vuln_interval_s",    _DEFAULT_INTERVAL)),
            max(1,   _i("vuln_workers",       _DEFAULT_WORKERS)),
            max(1,   _i("vuln_close_after",   3)),
            bool(    _i("vuln_skip_printers", 1)),
            bool(    _i("vuln_limit_ap_iot",  1)),
            max(0.5, _f("vuln_tcp_timeout",   _TCP_TIMEOUT)),
            max(0.5, _f("vuln_http_timeout",  _HTTP_TIMEOUT)),
        )
    except Exception:
        return _DEFAULT_INTERVAL, _DEFAULT_WORKERS, 3, True, True, _TCP_TIMEOUT, _HTTP_TIMEOUT
    finally:
        db.close()


def _tcp_open(ip: str, port: int, timeout: float = _TCP_TIMEOUT) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _tcp_banner(ip: str, port: int, timeout: float = _TCP_TIMEOUT):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(1024).decode("utf-8", errors="replace").strip()
            except Exception:
                return ""
    except OSError:
        return None

def check_telnet(ip: str):
    """Weryfikuje Telnet przez sprawdzenie banneru lub bajtów IAC.

    Wymaga niepustego banneru lub bajtów negocjacji IAC (0xff).
    Port 23 otwarty ale milczący nie jest flagowany — zbyt wiele FP
    na urządzeniach OT/ICS które nie używają Telnetu na tym porcie.
    """
    banner = _tcp_banner(ip, 23)
    if banner is None:
        return None
    # Sprawdź też surowe bajty — IAC (0xff) jako pierwszy bajt wskazuje Telnet
    try:
        with socket.create_connection((ip, 23), timeout=_TCP_TIMEOUT) as s:
            s.settimeout(_TCP_TIMEOUT)
            raw = s.recv(4)
    except OSError:
        raw = b""
    has_iac = raw and raw[0] == 0xFF
    if not banner and not has_iac:
        return None  # port otwarty ale nie odpowiada jako Telnet
    return {
        "vuln_type": VulnType.open_telnet, "severity": VulnSeverity.high,
        "title": "Telnet otwarty (port 23) - plaintext management",
        "port": 23, "evidence": banner[:200] if banner else "IAC negotiation bytes detected",
    }


def check_ftp(ip: str) -> list:
    results = []
    if not _tcp_open(ip, 21):
        return results
    results.append({
        "vuln_type": VulnType.open_ftp, "severity": VulnSeverity.medium,
        "title": "FTP otwarty (port 21) - transfer plaintext",
        "port": 21, "evidence": "port 21 TCP otwarty",
    })
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, 21, timeout=5)
        ftp.login("anonymous", "netdoc@scan.local")
        welcome = ftp.getwelcome()
        ftp.quit()
        results.append({
            "vuln_type": VulnType.anonymous_ftp, "severity": VulnSeverity.high,
            "title": "Anonymous FTP - dostep bez hasla",
            "port": 21, "evidence": (welcome or "login OK")[:200],
        })
    except ftplib.error_perm:
        pass
    except Exception:
        pass
    return results


def check_mqtt(ip: str):
    if not _tcp_open(ip, 1883, timeout=2):
        return None
    try:
        pkt = bytes([0x10,0x10,0x00,0x04,0x4D,0x51,0x54,0x54,
                     0x04,0x02,0x00,0x1E,0x00,0x02,0x6E,0x64])
        with socket.create_connection((ip, 1883), timeout=3) as s:
            s.sendall(pkt)
            s.settimeout(3)
            resp = s.recv(4)
        if len(resp) >= 4 and resp[0] == 0x20 and resp[3] == 0x00:
            return {
                "vuln_type": VulnType.mqtt_noauth, "severity": VulnSeverity.high,
                "title": "MQTT bez autentykacji (port 1883)",
                "port": 1883, "evidence": "CONNACK rc=0",
            }
    except Exception:
        pass
    return None


def check_redis(ip: str):
    if not _tcp_open(ip, 6379, timeout=2):
        return None
    try:
        CRLF = bytes([13, 10])
        ping_cmd = b"*1" + CRLF + b"$4" + CRLF + b"PING" + CRLF
        with socket.create_connection((ip, 6379), timeout=3) as s:
            s.sendall(ping_cmd)
            s.settimeout(3)
            resp = s.recv(64).decode("utf-8", errors="replace")
        if "+PONG" in resp:
            return {
                "vuln_type": VulnType.redis_noauth, "severity": VulnSeverity.critical,
                "title": "Redis bez hasla (port 6379) - pelny dostep",
                "port": 6379, "evidence": resp.strip()[:100],
            }
    except Exception:
        pass
    return None


def check_elasticsearch(ip: str):
    for port in (9200, 9201):
        if not _tcp_open(ip, port, timeout=2):
            continue
        try:
            r = httpx.get(f"http://{ip}:{port}/", timeout=_HTTP_TIMEOUT, verify=False)
            if r.status_code == 200 and "cluster_name" in r.text:
                return {
                    "vuln_type": VulnType.elasticsearch_noauth, "severity": VulnSeverity.high,
                    "title": f"Elasticsearch bez auth (port {port})",
                    "port": port, "evidence": r.text[:200],
                }
        except Exception:
            pass
    return None


def check_docker_api(ip: str):
    if not _tcp_open(ip, 2375, timeout=2):
        return None
    try:
        r = httpx.get(f"http://{ip}:2375/version", timeout=_HTTP_TIMEOUT)
        if r.status_code == 200 and "Version" in r.text:
            return {
                "vuln_type": VulnType.docker_api_exposed, "severity": VulnSeverity.critical,
                "title": "Docker API bez auth (port 2375) - zdalne RCE",
                "port": 2375, "evidence": r.text[:200],
            }
    except Exception:
        pass
    return None

def check_http_management(ip: str, device_type):
    network_types = {DeviceType.router, DeviceType.switch, DeviceType.ap,
                     DeviceType.firewall, DeviceType.camera}
    if device_type not in network_types:
        return None
    for port in (80, 8080):
        if not _tcp_open(ip, port, timeout=2):
            continue
        try:
            r = httpx.get(f"http://{ip}:{port}/", timeout=_HTTP_TIMEOUT,
                          follow_redirects=False, verify=False)
            loc = r.headers.get("location", "")
            if r.status_code in (301, 302):
                # Absolutny redirect na HTTPS — jawne wymuszenie HTTPS
                if "https://" in loc:
                    continue
                # Względny redirect (np. Location: /) — sprawdź czy port 443 jest otwarty
                # Jeśli tak, urządzenie prawdopodobnie wymaga HTTPS (messy redirect setup)
                if not loc.startswith("http") and _tcp_open(ip, 443, timeout=1):
                    continue
            if r.status_code < 400:
                return {
                    "vuln_type": VulnType.http_management, "severity": VulnSeverity.medium,
                    "title": f"HTTP management bez HTTPS (port {port})",
                    "port": port, "evidence": f"HTTP {r.status_code} - brak HTTPS",
                }
        except Exception:
            pass
    return None


def check_ssl(ip: str) -> list:
    results = []
    ctx_noverify = ssl.create_default_context()
    ctx_noverify.check_hostname = False
    ctx_noverify.verify_mode = ssl.CERT_NONE
    ctx_verify = ssl.create_default_context()
    for port in (443, 8443):
        if not _tcp_open(ip, port, timeout=2):
            continue
        self_signed = False
        try:
            with socket.create_connection((ip, port), timeout=3) as sock:
                with ctx_verify.wrap_socket(sock, server_hostname=ip):
                    pass
        except ssl.SSLCertVerificationError as e:
            err = str(e).lower()
            # Hostname mismatch = valid CA cert, tylko inny CN/SAN — nie jest self-signed
            if "hostname" in err or "host name" in err or "doesn't match" in err:
                pass
            else:
                self_signed = True
        except Exception:
            pass
        if self_signed:
            results.append({
                "vuln_type": VulnType.ssl_self_signed, "severity": VulnSeverity.medium,
                "title": f"Certyfikat SSL self-signed (port {port})",
                "port": port, "evidence": "SSLCertVerificationError",
            })
            continue
        try:
            with socket.create_connection((ip, port), timeout=3) as sock:
                with ctx_noverify.wrap_socket(sock) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        key_na = "notAfter"
                        not_after = ssl.cert_time_to_seconds(cert.get(key_na, ""))
                        if not_after < time.time():
                            results.append({
                                "vuln_type": VulnType.ssl_expired, "severity": VulnSeverity.high,
                                "title": f"Certyfikat SSL wygasl (port {port})",
                                "port": port, "evidence": f"notAfter={cert.get(key_na)}",
                            })
        except Exception:
            pass
    return results


def check_ipmi(ip: str):
    """Weryfikuje IPMI przez UDP probe RMCP ASF Ping (port 623/UDP).

    IPMI używa UDP 623, nie TCP. Wysyłamy RMCP Presence Ping i sprawdzamy
    czy odpowiada RMCP Presence Pong (ASF IANA 0x000011be, msg type 0x40).
    """
    # RMCP ASF Presence Ping: version=6, reserved=0, seq=0xff, class=6(ASF),
    # IANA=0x000011be, msg_type=0x80 (Ping), tag=0, reserved=0, data_len=0
    _RMCP_PING = b"\x06\x00\xff\x06\x00\x00\x11\xbe\x80\x00\x00\x00"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.sendto(_RMCP_PING, (ip, 623))
            data, _ = s.recvfrom(256)
    except OSError:
        return None
    # Pong: bajt 8 = 0x40 (ASF Presence Pong)
    if len(data) < 9 or data[8] != 0x40:
        return None
    return {
        "vuln_type": VulnType.ipmi_exposed, "severity": VulnSeverity.high,
        "title": "IPMI/BMC dostepny (port 623/UDP) - zdalny dostep do firmware",
        "port": 623, "evidence": f"RMCP ASF Pong: {data[:12].hex()}",
    }




def check_rdp_exposed(ip: str):
    """Weryfikuje RDP przez TPKT/X.224 handshake — nie flaguje gdy port 3389 używany przez inny serwis."""
    # TPKT + COTP Connection Request + RDP Negotiation Request
    _RDP_CR = (
        b"\x03\x00\x00\x13"           # TPKT v3, length=19
        b"\x0e\xe0\x00\x00\x00\x00\x00"  # COTP CR (0xe0), dst=0, src=0, class=0
        b"\x01\x00\x08\x00\x00\x00\x00\x00"  # RDP NegReq type=1
    )
    try:
        with socket.create_connection((ip, 3389), timeout=3) as s:
            s.settimeout(3)
            s.sendall(_RDP_CR)
            resp = s.recv(19)
    except OSError:
        return None
    # Odpowiedź musi być TPKT (bajt 0 = 0x03) i COTP Connection Confirm (bajt 5 = 0xd0)
    if not resp or resp[0] != 0x03 or len(resp) < 6 or resp[5] != 0xd0:
        return None
    return {
        "vuln_type": VulnType.rdp_exposed, "severity": VulnSeverity.high,
        "title": "RDP dostepny (port 3389) - zdalny pulpit bez VPN",
        "port": 3389, "evidence": f"TPKT/X.224 handshake OK (COTP CC: {resp[:8].hex()})",
    }



def check_vnc(ip: str):
    """VNC bez hasla - sprawdza SecurityType.None (typ 1) w handshake RFB."""
    if not _tcp_open(ip, 5900, timeout=2):
        return None
    try:
        with socket.create_connection((ip, 5900), timeout=3) as s:
            s.settimeout(3)
            banner = s.recv(12)
            if not banner or not banner.startswith(b"RFB "):
                return None
            rfb_str = banner.decode("ascii", errors="replace").strip()
            s.sendall(b"RFB 003.008\n")
            sec_data = s.recv(64)
            if len(sec_data) < 2:
                return None
            n_types = sec_data[0]
            if n_types == 0 or n_types > 20:
                return None
            types = list(sec_data[1:1 + n_types])
            if 1 in types:  # SecurityType.None = 1 (brak hasla)
                return {
                    "vuln_type": VulnType.vnc_noauth, "severity": VulnSeverity.critical,
                    "title": "VNC bez hasla (port 5900) - pelny dostep do pulpitu",
                    "port": 5900, "evidence": f"RFB={rfb_str} sec_types={types}",
                }
    except Exception:
        pass
    return None


def check_mongo(ip: str):
    """MongoDB bez auth - listDatabases bez uwierzytelnienia."""
    if not _tcp_open(ip, 27017, timeout=2):
        return None
    try:
        # BSON: {listDatabases: 1, $db: "admin"} (39 bytes)
        bson_doc = (
            b"\x27\x00\x00\x00"    # doc size = 39
            b"\x10"                 # type int32
            b"listDatabases\x00"   # key
            b"\x01\x00\x00\x00"   # value 1
            b"\x02"                 # type string
            b"$db\x00"              # key
            b"\x06\x00\x00\x00"    # string len
            b"admin\x00"            # value
            b"\x00"                 # end of doc
        )
        # OP_MSG (opCode=2013): flagBits(4) + section kind=0(1) + bson
        import struct as _s
        msg_body = b"\x00\x00\x00\x00" + b"\x00" + bson_doc
        total_len = 16 + len(msg_body)
        header = _s.pack("<iiii", total_len, 1, 0, 2013)
        msg = header + msg_body
        with socket.create_connection((ip, 27017), timeout=3) as s:
            s.sendall(msg)
            s.settimeout(3)
            resp = s.recv(512)
        if len(resp) > 20:
            resp_text = resp.decode("utf-8", errors="replace")
            if ("databases" in resp_text and
                    "not authorized" not in resp_text and
                    "uthentication" not in resp_text):
                return {
                    "vuln_type": VulnType.mongo_noauth, "severity": VulnSeverity.critical,
                    "title": "MongoDB bez auth (port 27017) - dostep do baz bez hasla",
                    "port": 27017, "evidence": resp_text[:200],
                }
    except Exception:
        pass
    return None


def check_rtsp(ip: str, device_type=None):
    """RTSP strumien bez uwierzytelnienia - kamery IP.

    RFC 2326: OPTIONS zawsze zwraca 200 bez auth (listing metod) — to normalne.
    Prawdziwa podatnosc: DESCRIBE zwraca 200 bez auth (dostep do SDP = stream info).
    Sprawdzamy DESCRIBE, nie OPTIONS, aby uniknac false positives.
    """
    if not _tcp_open(ip, 554, timeout=2):
        return None
    try:
        req = (b"DESCRIBE rtsp://" + ip.encode() +
               b"/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: NetDoc/1.0\r\n"
               b"Accept: application/sdp\r\n\r\n")
        with socket.create_connection((ip, 554), timeout=3) as s:
            s.sendall(req)
            s.settimeout(3)
            resp = s.recv(1024).decode("utf-8", errors="replace")
        if "RTSP/1.0" not in resp:
            return None
        # 401/403 = wymaga auth → nie jest podatnosc
        if "401" in resp or "403" in resp:
            return None
        if "200" in resp:
            return {
                "vuln_type": VulnType.rtsp_noauth, "severity": VulnSeverity.high,
                "title": "RTSP kamera bez uwierzytelnienia (port 554)",
                "port": 554,
                "evidence": resp[:200],
                "description": (
                    "Kamera IP udostępnia strumień RTSP bez uwierzytelnienia. "
                    "Każdy w sieci może oglądać transmisję wideo na żywo. "
                    "Zalecane: włączyć Basic/Digest auth w ustawieniach kamery "
                    "lub zablokować port 554 na firewall'u."
                ),
            }
    except Exception:
        pass
    return None


def check_modbus(ip: str):
    """Modbus TCP bez auth - protokol przemyslowy (invertery, PLC, UPS)."""
    if not _tcp_open(ip, 502, timeout=2):
        return None
    try:
        # FC 0x11: Report Server ID
        req = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x11])
        with socket.create_connection((ip, 502), timeout=3) as s:
            s.sendall(req)
            s.settimeout(3)
            resp = s.recv(64)
        # Valid response: transaction ID matches (0x00 0x01) + protocol = 0x00 0x00 + unit = 0x01
        if (len(resp) >= 8 and resp[0] == 0x00 and resp[1] == 0x01 and
                resp[2] == 0x00 and resp[3] == 0x00 and resp[6] == 0x01):
            return {
                "vuln_type": VulnType.modbus_exposed, "severity": VulnSeverity.critical,
                "title": "Modbus TCP bez auth (port 502) - urzadzenie przemyslowe dostepne",
                "port": 502, "evidence": "FC0x11 response: " + resp.hex()[:60],
            }
    except Exception:
        pass
    return None


def check_mysql(ip: str):
    """MySQL bez hasla - proba logowania z pustym haslem (port 3306)."""
    if not _tcp_open(ip, 3306, timeout=2):
        return None
    DEFAULT_USERS = ["root", "admin", "mysql"]
    cached = _global_creds_cache.get(CredentialMethod.mysql)
    if cached is not None:
        users = [u for u, _ in cached if u] or DEFAULT_USERS
    else:
        db = SessionLocal()
        try:
            db_creds = db.query(Credential).filter(
                Credential.method == CredentialMethod.mysql,
                Credential.device_id.is_(None),
            ).order_by(Credential.priority).all()
            users = [cr.username for cr in db_creds if cr.username] or DEFAULT_USERS
        finally:
            db.close()
    try:
        import struct as _s
        for user in users:
            try:
                with socket.create_connection((ip, 3306), timeout=3) as s:
                    s.settimeout(3)
                    greeting = s.recv(512)
                    if not greeting or len(greeting) < 5:
                        break
                    proto = greeting[4]
                    if proto not in (9, 10):
                        break
                    v_start = 5
                    v_end = greeting.find(b"\x00", v_start)
                    if v_end < 0:
                        v_end = min(v_start + 30, len(greeting))
                    version = greeting[v_start:v_end].decode("utf-8", errors="replace")
                    user_b = user.encode("utf-8") + b"\x00"
                    caps = 0x000FA685
                    pkt_body = (
                        _s.pack("<I", caps) +
                        _s.pack("<I", 0x00FFFFFF) +
                        b"!" +
                        b"\x00" * 23 +
                        user_b +
                        b"\x00" +
                        b"\x00"
                    )
                    pkt = _s.pack("<I", len(pkt_body))[:3] + b"" + pkt_body
                    s.sendall(pkt)
                    resp = s.recv(64)
                    if len(resp) >= 5 and resp[4] == 0x00:
                        return {
                            "vuln_type": VulnType.mysql_noauth, "severity": VulnSeverity.critical,
                            "title": f"MySQL bez hasla (port 3306) user={user!r} ver={version}",
                            "port": 3306, "evidence": f"MySQL {version} user={user!r} login bez hasla",
                        }
            except Exception:
                continue
    except Exception:
        pass
    return None
def check_couchdb(ip: str):
    """CouchDB bez uwierzytelnienia - GET /_all_dbs (port 5984)."""
    if not _tcp_open(ip, 5984, timeout=2):
        return None
    try:
        resp = httpx.get(f"http://{ip}:5984/_all_dbs", timeout=_HTTP_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                return {
                    "vuln_type": VulnType.couchdb_noauth, "severity": VulnSeverity.critical,
                    "title": "CouchDB bez uwierzytelnienia (port 5984)",
                    "port": 5984, "evidence": f"_all_dbs: {str(data)[:120]}",
                }
    except Exception:
        pass
    return None


def check_memcached(ip: str):
    """Memcached bez auth - komenda stats (port 11211)."""
    if not _tcp_open(ip, 11211, timeout=2):
        return None
    try:
        with socket.create_connection((ip, 11211), timeout=3) as s:
            s.sendall(b"stats\r\n")
            s.settimeout(3)
            resp = s.recv(512).decode("utf-8", errors="replace")
        if "STAT " in resp:
            return {
                "vuln_type": VulnType.memcached_exposed, "severity": VulnSeverity.high,
                "title": "Memcached bez uwierzytelnienia (port 11211)",
                "port": 11211, "evidence": resp[:200],
            }
    except Exception:
        pass
    return None


def check_influxdb(ip: str):
    """InfluxDB bez auth - GET /api/v2/buckets lub /query (port 8086)."""
    if not _tcp_open(ip, 8086, timeout=2):
        return None
    try:
        resp = httpx.get(f"http://{ip}:8086/api/v2/buckets", timeout=_HTTP_TIMEOUT)
        if resp.status_code == 200:
            return {
                "vuln_type": VulnType.influxdb_noauth, "severity": VulnSeverity.critical,
                "title": "InfluxDB v2 bez uwierzytelnienia (port 8086)",
                "port": 8086, "evidence": resp.text[:150],
            }
        resp2 = httpx.get(f"http://{ip}:8086/query?q=SHOW+DATABASES", timeout=_HTTP_TIMEOUT)
        if resp2.status_code == 200 and "results" in resp2.text:
            return {
                "vuln_type": VulnType.influxdb_noauth, "severity": VulnSeverity.critical,
                "title": "InfluxDB v1 bez uwierzytelnienia (port 8086)",
                "port": 8086, "evidence": resp2.text[:150],
            }
    except Exception:
        pass
    return None


def check_postgres_weak(ip: str):
    """PostgreSQL ze slabymi/domyslnymi poswiadczeniami (port 5432)."""
    if not _tcp_open(ip, 5432, timeout=2):
        return None
    import psycopg2
    DEFAULT_CREDS = [('postgres', 'postgres'), ('postgres', ''), ('postgres', 'password'), ('postgres', 'postgres123'), ('postgres', 'secret'), ('postgres', 'changeme'), ('admin', 'admin'), ('root', 'root')]
    cached = _global_creds_cache.get(CredentialMethod.postgres)
    if cached is not None:
        CREDS = cached or DEFAULT_CREDS
    else:
        db = SessionLocal()
        try:
            db_creds = db.query(Credential).filter(
                Credential.method == CredentialMethod.postgres,
                Credential.device_id.is_(None),
            ).order_by(Credential.priority).all()
            CREDS = [(cr.username or "", cr.password_encrypted or "") for cr in db_creds] or DEFAULT_CREDS
        finally:
            db.close()
    for user, pwd in CREDS:
        try:
            conn = psycopg2.connect(
                host=ip, port=5432, user=user, password=pwd,
                dbname="postgres", connect_timeout=3,
            )
            conn.close()
            return {
                "vuln_type": VulnType.postgres_weak_creds, "severity": VulnSeverity.critical,
                "title": f"PostgreSQL slabe haslo (port 5432) user={user!r}",
                "port": 5432,
                "evidence": f"user={user!r} password={'(brak)' if not pwd else repr(pwd)}",
            }
        except Exception:
            pass
    return None


def check_mssql_weak(ip: str):
    """MSSQL ze slabymi poswiadczeniami - proba logowania sa/blank (port 1433)."""
    if not _tcp_open(ip, 1433, timeout=2):
        return None
    DEFAULT_CREDS = [
        ('sa', ''),           # SQL Express / brak hasla
        ('sa', 'Wapro3000'),  # Wapro ERP (Asseco)
        ('sa', 'sa'), ('sa', 'password'), ('sa', 'Password1'), ('sa', 'P@ssw0rd'),
        ('sa', 'admin'), ('sa', 'admin123'), ('sa', 'Admin123'), ('sa', '1234'),
        ('sa', 'Password123'), ('sa', 'Sa123456'), ('sa', 'Sql123456'),
        ('sa', 'Insert2022'), ('sa', 'Insert2023'),   # Insert GT ERP
        ('sa', 'Optima2022'), ('sa', 'OptimaSA'),     # Comarch Optima
        ('sa', 'Symfonia1'),                           # Sage Symfonia
        ('admin', 'admin'), ('admin', ''),
    ]
    cached = _global_creds_cache.get(CredentialMethod.mssql)
    if cached is not None:
        CREDS = cached or DEFAULT_CREDS
    else:
        db = SessionLocal()
        try:
            db_creds = db.query(Credential).filter(
                Credential.method == CredentialMethod.mssql,
                Credential.device_id.is_(None),
            ).order_by(Credential.priority).all()
            CREDS = [(cr.username or "", cr.password_encrypted or "") for cr in db_creds] or DEFAULT_CREDS
        finally:
            db.close()
    try:
        from impacket.tds import MSSQL
        for user, pwd in CREDS:
            try:
                ms = MSSQL(ip, 1433)
                ms.connect()
                result = ms.login("master", user, pwd, None, None, False)
                ms.disconnect()
                if result:
                    return {
                        "vuln_type": VulnType.mssql_weak_creds, "severity": VulnSeverity.critical,
                        "title": f"MSSQL slabe haslo (port 1433) user={user!r}",
                        "port": 1433,
                        "evidence": f"user={user!r} password={'(brak)' if not pwd else repr(pwd)}",
                    }
            except Exception:
                pass
    except ImportError:
        pass
    return None


def check_vnc_weak(ip: str):
    """VNC ze slabym haslem VncAuth - probuje najpopularniejsze hasla (port 5900)."""
    if not _tcp_open(ip, 5900, timeout=2):
        return None

    def _vnc_des(password: str, challenge: bytes) -> bytes:
        import warnings
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        key = (password.encode("latin-1") + b"\x00" * 8)[:8]
        key_rev = bytes(int(f"{b:08b}"[::-1], 2) for b in key)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            c = Cipher(algorithms.DES(key_rev), modes.ECB())
        enc = c.encryptor()
        return enc.update(challenge) + enc.finalize()

    DEFAULT_PWD = ["password", "1234", "12345", "admin", "vnc", "root",
                   "raspberry", "alpine", "toor", "qwerty", "letmein",
                   "123456", "pass", "secret", "changeme", "test"]
    cached = _global_creds_cache.get(CredentialMethod.vnc)
    if cached is not None:
        WEAK_PWD = [pwd for _, pwd in cached if pwd] or DEFAULT_PWD
    else:
        db = SessionLocal()
        try:
            db_creds = db.query(Credential).filter(
                Credential.method == CredentialMethod.vnc,
                Credential.device_id.is_(None),
            ).order_by(Credential.priority).all()
            WEAK_PWD = [c.password_encrypted for c in db_creds if c.password_encrypted] or DEFAULT_PWD
        finally:
            db.close()
    import struct as _s
    for pwd in WEAK_PWD:
        try:
            with socket.create_connection((ip, 5900), timeout=3) as s:
                s.settimeout(3)
                banner = s.recv(12)
                if not banner or not banner.startswith(b"RFB "):
                    break
                s.sendall(b"RFB 003.008\n")
                sec_data = s.recv(64)
                if not sec_data or sec_data[0] == 0 or sec_data[0] > 20:
                    break
                types = list(sec_data[1:1 + sec_data[0]])
                if 2 not in types:
                    break  # No VncAuth offered
                s.sendall(bytes([2]))
                challenge = s.recv(16)
                if len(challenge) != 16:
                    break
                response = _vnc_des(pwd, challenge)
                s.sendall(response)
                result = s.recv(4)
                if len(result) >= 4 and _s.unpack(">I", result[:4])[0] == 0:
                    return {
                        "vuln_type": VulnType.vnc_weak_creds, "severity": VulnSeverity.critical,
                        "title": f"VNC slabe haslo (port 5900): {pwd!r}",
                        "port": 5900, "evidence": f"SecurityType=VncAuth password={pwd!r} accepted",
                    }
        except Exception:
            continue
    return None


def check_cassandra(ip: str):
    """Apache Cassandra bez uwierzytelnienia - CQL native protocol (port 9042)."""
    if not _tcp_open(ip, 9042, timeout=2):
        return None
    try:
        import struct as _s
        # CQL native protocol v4 STARTUP {CQL_VERSION: "3.0.0"}
        body = (
            b"\x00\x01"       # 1 option
            b"\x00\x0b"       # key len 11
            b"CQL_VERSION"
            b"\x00\x05"       # value len 5
            b"3.0.0"
        )
        header = bytes([0x04, 0x00, 0x00, 0x01, 0x01]) + _s.pack(">I", len(body))
        with socket.create_connection((ip, 9042), timeout=3) as s:
            s.settimeout(3)
            s.sendall(header + body)
            resp = s.recv(64)
        if len(resp) >= 9 and resp[4] == 0x02:  # READY = no auth required
            return {
                "vuln_type": VulnType.cassandra_noauth, "severity": VulnSeverity.critical,
                "title": "Apache Cassandra bez uwierzytelnienia (port 9042)",
                "port": 9042, "evidence": "CQL STARTUP → READY (brak uwierzytelnienia)",
            }
    except Exception:
        pass
    return None



def check_rtsp_weak(ip: str):
    """RTSP kamera ze slabym haslem - probuje najczestsze poswiadczenia kamer IP (port 554)."""
    if not _tcp_open(ip, 554, timeout=2):
        return None
    import base64
    # Sprawdz czy kamera wymaga uwierzytelnienia (oczekujemy 401)
    try:
        req = (b"OPTIONS rtsp://" + ip.encode() + b"/ RTSP/1.0\r\n"
               b"CSeq: 1\r\nUser-Agent: NetDoc/1.0\r\n\r\n")
        with socket.create_connection((ip, 554), timeout=3) as s:
            s.sendall(req)
            s.settimeout(3)
            resp = s.recv(512).decode("utf-8", errors="replace")
        if "RTSP/1.0" not in resp:
            return None
        if "200" in resp:
            return None  # Brak auth - juz wykryte jako rtsp_noauth
        if "401" not in resp:
            return None  # Nie pyta o uwierzytelnienie
    except Exception:
        return None

    DEFAULT_CREDS = [('admin', 'admin'), ('admin', ''), ('admin', '12345'), ('admin', '123456'), ('admin', 'password'), ('admin', '1234'), ('admin', 'admin123'), ('root', 'root'), ('root', ''), ('user', 'user'), ('admin', 'Admin1234'), ('admin', '888888'), ('admin', '666666')]
    cached = _global_creds_cache.get(CredentialMethod.rtsp)
    if cached is not None:
        CREDS = cached or DEFAULT_CREDS
    else:
        db = SessionLocal()
        try:
            db_creds = db.query(Credential).filter(
                Credential.method == CredentialMethod.rtsp,
                Credential.device_id.is_(None),
            ).order_by(Credential.priority).all()
            CREDS = [(cr.username or "", cr.password_encrypted or "") for cr in db_creds] or DEFAULT_CREDS
        finally:
            db.close()
    for user, pwd in CREDS:
        try:
            auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            req = (b"DESCRIBE rtsp://" + ip.encode() + b"/ RTSP/1.0\r\n"
                   b"CSeq: 2\r\nUser-Agent: NetDoc/1.0\r\n"
                   b"Authorization: Basic " + auth.encode() + b"\r\n\r\n")
            with socket.create_connection((ip, 554), timeout=3) as s:
                s.sendall(req)
                s.settimeout(3)
                resp = s.recv(512).decode("utf-8", errors="replace")
            if "RTSP/1.0" in resp and "200" in resp and "401" not in resp:
                return {
                    "vuln_type": VulnType.rtsp_weak_creds, "severity": VulnSeverity.high,
                    "title": f"Kamera RTSP slabe haslo (port 554) user={user!r}",
                    "port": 554,
                    "evidence": f"DESCRIBE Basic auth user={user!r} pwd={'(brak)' if not pwd else '***'} -> 200 OK",
                }
        except Exception:
            continue
    return None


def check_firewall(ip: str, device_type=None):
    """Wykrywa hosty bez firewalla - nadmierna liczba dostepnych portow sieciowych.

    Progi dopasowane do typu urządzenia:
    - serwer/DC: wyższy próg (12/22) — wiele portów to norma
    - pozostałe: próg 10/22
    Serwery i DC pomijane od strony 'zbyt wiele portów = brak firewalla',
    bo zarządzane serwery mogą legalnie eksponować 10+ portów.
    """
    # Serwery i DC legalnie wystawiają wiele portów — ten check daje masowe FP
    if device_type in (DeviceType.server, DeviceType.domain_controller):
        return None

    PROBE_PORTS = [
        21,    # FTP
        23,    # Telnet
        25,    # SMTP
        80,    # HTTP
        110,   # POP3
        135,   # RPC
        139,   # NetBIOS
        143,   # IMAP
        443,   # HTTPS
        445,   # SMB
        1433,  # MSSQL
        1521,  # Oracle
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        5984,  # CouchDB
        6379,  # Redis
        8080,  # HTTP alt
        8443,  # HTTPS alt
        9200,  # Elasticsearch
        27017, # MongoDB
    ]
    open_ports = [p for p in PROBE_PORTS if _tcp_open(ip, p, timeout=0.8)]
    threshold = 10  # 45% z 22 portów
    if len(open_ports) >= threshold:
        return {
            "vuln_type": VulnType.firewall_disabled, "severity": VulnSeverity.high,
            "title": f"Brak/slaby firewall - {len(open_ports)} portow dostepnych sieciowo",
            "port": None,
            "evidence": f"Otwarte porty ({len(open_ports)}/{len(PROBE_PORTS)}): {open_ports}",
        }
    return None

def _verify_cred_network(ip: str, method_name: str, username: str, password: str) -> bool:
    """Re-weryfikuje credential na sieci — zapobiega false positive z bazy.

    Zwraca True tylko gdy credential faktycznie dziala na urzadzeniu.
    Dla metod bez sieciowego testera — zwraca True (trust DB).
    """
    u, p = username or "", password or ""
    try:
        if method_name == "api":
            # Sprawdz HTTP Basic auth — odpowiedz musi byc INNA niz bez credentials
            import httpx
            for port in (80, 443, 8080, 8443):
                try:
                    s = socket.create_connection((ip, port), timeout=2)
                    s.close()
                except OSError:
                    continue
                scheme = "https" if port in (443, 8443) else "http"
                url = f"{scheme}://{ip}:{port}/"
                try:
                    r_no = httpx.get(url, timeout=3, follow_redirects=True, verify=False)
                    r_auth = httpx.get(url, auth=(u, p), timeout=3,
                                       follow_redirects=True, verify=False)
                    if r_auth.status_code not in (200, 201, 204):
                        continue
                    t_auth = r_auth.text.lower()
                    t_no = r_no.text.lower()
                    # Musi zawierac ok-slowo I byc wyraznie INNA niz bez credentials
                    ok_kw = ("logout", "dashboard", "hostname", "system info",
                             "sign out", "configuration", "firmware", "uptime")
                    bad_kw = ("login failed", "invalid", "incorrect", "access denied",
                              "unauthorized", "bad credentials")
                    if not any(w in t_auth for w in ok_kw):
                        continue
                    if any(w in t_auth for w in bad_kw):
                        continue
                    if t_auth == t_no:
                        continue   # identyczna odpowiedz → false positive
                    ratio = (abs(len(t_auth) - len(t_no))
                             / max(len(t_auth), len(t_no), 1))
                    if ratio < 0.05:
                        continue   # prawie identyczna → false positive
                    return True
                except Exception:
                    continue

        elif method_name == "ssh":
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=22, username=u, password=p,
                           timeout=6, allow_agent=False, look_for_keys=False)
            client.close()
            return True

        else:
            # snmp, telnet, rdp, mssql, mysql, postgres — ufamy DB
            return True

    except Exception:
        pass
    return False


def check_default_credentials(ip: str, device_id: int):
    WEAK_U = {"admin","root","user","cisco","ubnt","pi","guest",
              "support","operator","manager","anonymous",""}
    WEAK_P = {"admin","password","12345","1234","cisco","admin123",
              "ubnt","root","pass","default","alpine","raspberry",""}
    db = SessionLocal()
    try:
        cred = (db.query(Credential)
            .filter(Credential.device_id == device_id,
                    Credential.last_success_at.isnot(None))
            .order_by(Credential.last_success_at.desc()).first())
        if not cred:
            return None
        username = (cred.username or "").lower()
        password = (cred.password_encrypted or "").lower()
        if username not in WEAK_U and password not in WEAK_P:
            return None
        meth = cred.method.value
        uname = cred.username
        last_ok = cred.last_success_at
        # Weryfikacja sieciowa — zapobiega false positive z bazy danych
        if not _verify_cred_network(ip, meth, cred.username or "", cred.password_encrypted or ""):
            # DEBUG level — this is an expected negative outcome that fires every scan cycle
            # for the same device; INFO caused log spam for devices with unverifiable creds.
            logger.debug("DEFAULT_CRED %s method=%s user=%r — not confirmed over network → skipping",
                         ip, meth, uname)
            return None
        return {
            "vuln_type": VulnType.default_credentials, "severity": VulnSeverity.critical,
            "title": f"Domyslne credentials: {meth} user={uname!r}",
            "port": None, "evidence": f"method={meth} username={uname!r} last_ok={last_ok} (potwierdzono sieciowo)",
        }
    except Exception:
        pass
    finally:
        db.close()
    return None


def _snmp_udp_responds(ip: str, community: str = "public", timeout: float = 2.0) -> bool:
    """Sprawdza czy urzadzenie odpowiada na SNMP GET sysName przez UDP."""
    import socket
    # Minimal SNMP v2c GET Request dla sysName (1.3.6.1.2.1.1.5.0)
    community_bytes = community.encode()
    com_len = len(community_bytes)
    pdu = (
        b"\x30" + bytes([39 + com_len]) +
        b"\x02\x01\x01" +                         # version: v2c
        b"\x04" + bytes([com_len]) + community_bytes +
        b"\xa0\x1c"                                # GetRequest PDU
        b"\x02\x04\x00\x00\x00\x01"               # request-id
        b"\x02\x01\x00"                            # error-status
        b"\x02\x01\x00"                            # error-index
        b"\x30\x0e\x30\x0c"                        # VarBindList
        b"\x06\x08\x2b\x06\x01\x02\x01\x01\x05\x00"  # OID sysName
        b"\x05\x00"                                # NULL
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pdu, (ip, 161))
        data, _ = s.recvfrom(512)
        return len(data) > 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def check_snmp_public(device_id: int, ip: str = ""):
    """Flaguje urzadzenie tylko jesli SNMP UDP faktycznie odpowiada na community public."""
    # Weryfikacja przez UDP — unikamy false positive z globalnego credentala
    if ip and not _snmp_udp_responds(ip):
        return None
    db = SessionLocal()
    try:
        cred = (db.query(Credential)
            .filter(Credential.method == CredentialMethod.snmp,
                    Credential.username == "public",
                    or_(Credential.device_id == device_id, Credential.device_id.is_(None)))
            .first())
        if cred:
            return {
                "vuln_type": VulnType.snmp_public, "severity": VulnSeverity.medium,
                "title": "SNMP community=public aktywna - brak autentykacji",
                "port": 161, "evidence": f"community=public potwierdzone przez UDP probe na {ip}",
            }
    except Exception:
        pass
    finally:
        db.close()
    return None


def _onvif_get_device_info(ip: str, port: int) -> dict:
    """Próbuje pobrać GetDeviceInformation z ONVIF bez auth (best-effort).

    Nie wszystkie kamery pozwalają na to bez logowania — zwraca pusty dict
    jeśli endpoint wymaga auth lub nie odpowiada.
    """
    import re as _re
    _SOAP = (
        b'<?xml version="1.0"?>'
        b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        b' xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
        b'<s:Body><tds:GetDeviceInformation/></s:Body></s:Envelope>'
    )
    try:
        r = httpx.post(
            f"http://{ip}:{port}/onvif/device_service",
            content=_SOAP,
            headers={"Content-Type": "application/soap+xml; charset=utf-8"},
            timeout=_HTTP_TIMEOUT,
            follow_redirects=False,
        )
        if r.status_code != 200:
            return {}
        body = r.text
        def _tag(name: str) -> Optional[str]:
            m = _re.search(rf'<(?:[^:>]+:)?{name}>([^<]+)<', body)
            return m.group(1).strip() if m else None
        result = {}
        if _tag("Manufacturer"):
            result["vendor"] = _tag("Manufacturer")
        if _tag("Model"):
            result["model"] = _tag("Model")
        if _tag("FirmwareVersion"):
            result["os_version"] = _tag("FirmwareVersion")
        if _tag("SerialNumber"):
            result["serial_number"] = _tag("SerialNumber")
        return result
    except Exception:
        return {}


def check_onvif_noauth(ip: str) -> Optional[dict]:
    """Sprawdza czy kamera/NVR udostępnia ONVIF GetCapabilities bez uwierzytelnienia.

    ONVIF to standard zarządzania kamerami IP (PTZ, strumienie, konfiguracja).
    Dostęp bez auth = pełna kontrola kamery i podgląd strumieni wideo.
    Porty: 80, 8080, 8000 (zależy od producenta).
    """
    _ONVIF_SOAP = (
        b'<?xml version="1.0"?>'
        b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        b' xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
        b'<s:Body><tds:GetCapabilities><tds:Category>All</tds:Category>'
        b'</tds:GetCapabilities></s:Body></s:Envelope>'
    )
    for port in (80, 8080, 8000):
        if not _tcp_open(ip, port):
            continue
        try:
            r = httpx.post(
                f"http://{ip}:{port}/onvif/device_service",
                content=_ONVIF_SOAP,
                headers={"Content-Type": "application/soap+xml; charset=utf-8"},
                timeout=_HTTP_TIMEOUT,
                follow_redirects=False,
            )
            body_lower = r.text.lower()
            # Sprawdz ze odpowiedz zawiera faktyczne dane (GetCapabilitiesResponse)
            # i NIE jest bledem autoryzacji (SOAP Fault z NotAuthorized/Unauthorized)
            has_caps_response = "getcapabilitiesresponse" in body_lower
            has_auth_error = any(w in body_lower for w in (
                "notauthorized", "not authorized", "sendernotauthorized",
                "action not authorized", "authentication required",
            ))
            if r.status_code == 200 and has_caps_response and not has_auth_error:
                # Best-effort: próbuj pobrać dane urządzenia (nie wszystkie kamery pozwalają)
                device_info = _onvif_get_device_info(ip, port)
                return {
                    "vuln_type": VulnType.onvif_noauth, "severity": VulnSeverity.high,
                    "title": f"ONVIF kamera — zarządzanie bez uwierzytelnienia (port {port})",
                    "port": port,
                    "evidence": f"GetCapabilities HTTP 200 bez auth na {ip}:{port}/onvif/device_service",
                    "description": (
                        "Protokół ONVIF dostępny bez logowania. Atakujący może przeglądać "
                        "strumienie wideo, sterować PTZ, zmieniać konfigurację kamery "
                        "i pobierać nagrania bez żadnych uprawnień."
                    ),
                    "enrichment": device_info,  # może być {} jeśli kamera wymaga auth
                }
        except Exception:
            continue
    return None


def check_mjpeg_noauth(ip: str) -> Optional[dict]:
    """Sprawdza czy urządzenie udostępnia strumień MJPEG bez uwierzytelnienia.

    Strumień MJPEG (Motion JPEG) to sekwencja klatek JPEG wysyłana przez HTTP.
    Wiele tanich kamer i kamer IP dla małych biur udostępnia go bez auth.
    Porty: 80, 8080, 4747, 8000, 8888.
    """
    _MJPEG_PATHS = ["/video", "/video.mjpg", "/mjpeg", "/stream",
                    "/?action=stream", "/videostream.cgi", "/cgi-bin/video.mjpg"]
    for port in (80, 8080, 8000, 4747, 8888):
        if not _tcp_open(ip, port):
            continue
        for path in _MJPEG_PATHS:
            try:
                r = httpx.get(
                    f"http://{ip}:{port}{path}",
                    timeout=_HTTP_TIMEOUT,
                    follow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                ct = r.headers.get("content-type", "").lower()
                if r.status_code == 200 and ("multipart" in ct or "mjpeg" in ct):
                    return {
                        "vuln_type": VulnType.mjpeg_noauth, "severity": VulnSeverity.high,
                        "title": f"Strumień MJPEG bez logowania (port {port})",
                        "port": port,
                        "evidence": f"HTTP 200 Content-Type: {ct[:80]} na {ip}:{port}{path}",
                        "description": (
                            "Obraz z kamery jest publicznie dostępny bez uwierzytelnienia. "
                            "Każdy w sieci może oglądać transmisję na żywo."
                        ),
                    }
            except Exception:
                continue
    return None


def check_rtmp_noauth(ip: str) -> Optional[dict]:
    """Sprawdza czy port RTMP (1935) odpowiada na handshake C0+C1.

    RTMP serwer nie wysyła nic jako pierwszy — czeka na C0+C1 od klienta.
    Wysyłamy C0 (wersja RTMP = 0x03) i czekamy na S0+S1+S2 (1537 bajtów).
    Samo otwarte połączenie bez odpowiedzi na C0 jest pomijane (FP).
    """
    if not _tcp_open(ip, 1935):
        return None
    try:
        with socket.create_connection((ip, 1935), timeout=3) as s:
            s.settimeout(3)
            # C0: wersja RTMP (1 bajt) + C1: 1536 bajtów (timestamp + zeros)
            c1 = b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 1528
            s.sendall(b"\x03" + c1)  # C0 + C1
            resp = s.recv(4)          # S0 (1 bajt) + początek S1
    except OSError:
        return None
    # S0 musi być 0x03 (RTMP version 3)
    if not resp or resp[0] != 0x03:
        return None
    return {
        "vuln_type": VulnType.rtmp_exposed, "severity": VulnSeverity.medium,
        "title": "RTMP streaming serwer dostępny (port 1935)",
        "port": 1935,
        "evidence": f"RTMP handshake OK (S0=0x{resp[0]:02x})",
        "description": (
            "Serwer RTMP dostępny w sieci. Może ujawniać prywatne transmisje wideo "
            "(kamery, monitoring, konferencje). Zweryfikuj czy wymaga uwierzytelnienia."
        ),
    }


def check_dahua_dvr_exposed(ip: str) -> Optional[dict]:
    """Sprawdza czy Dahua DVR/NVR/kamera jest dostępna na porcie 37777.

    Port 37777 (Dahua TCP proprietary) to protokół zarządzania rejestratorami
    i kamerami Dahua. Otwarty port = dostęp do zarządzania urządzeniem,
    podglądu i nagrań. Często wykorzystywany w atakach ransomware na NVR.
    """
    if not _tcp_open(ip, 37777):
        return None
    banner = _tcp_banner(ip, 37777, timeout=2.0)
    # Dahua odpowiada binarnie natychmiast po połączeniu
    # Pusta odpowiedź (banner="") = serwis milczy = nie jest Dahua
    if not banner:
        return None
    return {
        "vuln_type": VulnType.dahua_dvr_exposed, "severity": VulnSeverity.high,
        "title": "Dahua DVR/NVR/kamera — port 37777 dostępny",
        "port": 37777,
        "evidence": f"TCP 37777 akceptuje połączenia (Dahua proprietary protocol)",
        "description": (
            "Rejestrator/kamera Dahua nasłuchuje na porcie 37777 (protokół własnościowy). "
            "Dostęp bez właściwego firewall'a umożliwia zarządzanie urządzeniem, "
            "pobieranie nagrań i podgląd kamer na żywo."
        ),
    }


# DISABLED: _xmeye_enumerate_users — dezaktywowane razem z brute-force (2026-03-11)
# Mozna aktywowac w przyszlosci razem z xmeye_bruteforce.
# def _xmeye_enumerate_users(ip, port, usernames, timeout=2.0):
#     """Enumeracja uzytkownikow XMEye przez rozroznienie Ret=203 vs Ret=205."""
#     import hashlib as _h, json as _j, struct as _st
#     def _ret_for_user(user):
#         raw = _h.md5(b"__enum_probe_xyz__").hexdigest().upper()
#         pwd_hash = "".join(raw[i] for i in range(0, 16, 2))
#         data = _j.dumps({"EncryptType": "MD5", "LoginType": "DVRIP-Web",
#                          "PassWord": pwd_hash, "UserName": user}).encode()
#         head = _st.pack("<BBHIIHHI", 0xFF, 0x00, 0, 0, 0, 0, 1000, len(data))
#         try:
#             with socket.create_connection((ip, port), timeout=timeout) as s:
#                 s.sendall(head + data)
#                 resp = s.recv(512)
#             if len(resp) > 20:
#                 payload = resp[20:].decode("utf-8", errors="replace").strip("\x00")
#                 if payload.startswith("{"): return _j.loads(payload).get("Ret", -1)
#         except Exception: pass
#         return -1
#     _BASELINE = _ret_for_user("__nonexistent_user_9xz7__")
#     return [(u, ret) for u in usernames
#             if (ret := _ret_for_user(u)) != 205 and ret != _BASELINE and ret > 0]


def check_xmeye_dvr_exposed(ip: str) -> Optional[dict]:
    """Sprawdza czy generyczny DVR/NVR (XMEye/Sofia) jest dostępny na porcie 34567.

    Port 34567 używany przez rejestratory z chipsetem XMEye/Sofia (Annke, Qvis,
    Raidon, Zmodo i setki marek no-name). Protokół bez szyfrowania,
    podatny na ataki brute-force i znane exploity (CVE-2017-7577).

    Weryfikacja (2026-03-11):
    - Brak lockout po 20+ nieudanych próbach logowania → brute-force możliwy
    - Protokół plaintext → sniffing sieci ujawnia hasła i strumień wideo
    - Unauthenticated commands (CMD 1000/1020) odrzucane przez firmware (Ret=205) →
      urządzenie wymaga logowania, ale brak ochrony przed brute-force
    """
    if not _tcp_open(ip, 34567):
        return None
    banner = _tcp_banner(ip, 34567, timeout=2.0)
    # XMEye/Sofia odpowiada binarnie natychmiast po połączeniu
    # Pusta odpowiedź (banner="") = serwis milczy = nie jest XMEye DVR
    if not banner:
        return None

    # DISABLED: user enumeration + brute-force dezaktywowane (2026-03-11)
    # Aktywowac przez odkomentowanie ponizszych blokow i przywrocenie _xmeye_enumerate_users
    # + _xmeye_login_attempt + xmeye_bruteforce + _XMEYE_CHARSETS.
    #
    # _KNOWN_USERS = ["admin", "root", "user", "guest", "operator", "supervisor", "default"]
    # enumerated = _xmeye_enumerate_users(ip, 34567, _KNOWN_USERS)
    # if enumerated:
    #     logger.warning(f"XMEye user enumeration {ip}: "
    #                    + ", ".join(f"{u}(Ret={r})" for u, r in enumerated))
    # if settings.xmeye_bruteforce_enabled:
    #     for user in ([u for u, _ in enumerated] if enumerated else ["admin"]):
    #         bf_result = xmeye_bruteforce(ip, username=user,
    #                                      max_len=settings.xmeye_bruteforce_max_len,
    #                                      charset=settings.xmeye_bruteforce_charset)
    #         if bf_result: return bf_result

    return {
        "vuln_type": VulnType.xmeye_dvr_exposed, "severity": VulnSeverity.high,
        "title": "XMEye/Sofia DVR — port 34567 dostępny bez ochrony",
        "port": 34567,
        "evidence": "TCP 34567 akceptuje połączenia (XMEye/Sofia DVR protocol, brak lockout konta)",
        "description": (
            "Rejestrator DVR/NVR z chipsetem XMEye/Sofia nasłuchuje na porcie 34567. "
            "Protokół działa bez szyfrowania (plaintext) — dane logowania i strumień wideo "
            "są widoczne w sieci. Brak mechanizmu blokowania konta umożliwia ataki brute-force. "
            "Na starszym firmware: podatność RCE (CVE-2017-7577). "
            "Zalecane: blokada portu 34567 na firewall'u lub VLAN izolujący kamery."
        ),
    }


# DISABLED: XMEye brute-force — dezaktywowane (2026-03-11), zachowane do ewentualnej reaktywacji.
# Wymaga: odkomentowania ponizszych blokow + bloku w check_xmeye_dvr_exposed.
#
# _XMEYE_CHARSETS = {
#     "digits":       "0123456789",
#     "lower":        "abcdefghijklmnopqrstuvwxyz",
#     "lower+digits": "abcdefghijklmnopqrstuvwxyz0123456789",
#     "alnum":        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
# }
#
# def _xmeye_login_attempt(ip, port, username, password, timeout):
#     """Ret=100 → sukces; Ret=203/206 → stan konta (false positive); Ret=205 → bledne haslo."""
#     import hashlib as _h, json as _j, struct as _st
#     raw = _h.md5(password.encode()).hexdigest().upper()
#     pwd_hash = "".join(raw[i] for i in range(0, 16, 2))
#     data = _j.dumps({"EncryptType": "MD5", "LoginType": "DVRIP-Web",
#                      "PassWord": pwd_hash, "UserName": username}).encode()
#     head = _st.pack("<BBHIIHHI", 0xFF, 0x00, 0, 0, 0, 0, 1000, len(data))
#     try:
#         with socket.create_connection((ip, port), timeout=timeout) as s:
#             s.sendall(head + data)
#             resp = s.recv(4096)
#         if len(resp) > 20:
#             payload = resp[20:].decode("utf-8", errors="replace").strip("\x00")
#             if payload.startswith("{"): return _j.loads(payload).get("Ret", 205) == 100
#     except Exception: pass
#     return False
#
# def xmeye_bruteforce(ip, username="admin", port=34567, max_len=4,
#                      charset="digits", timeout_per_attempt=1.5):
#     """Brute-force hasla XMEye/Sofia DVR (port 34567). Tylko Ret=100 = sukces."""
#     import itertools as _it
#     chars = _XMEYE_CHARSETS.get(charset, _XMEYE_CHARSETS["digits"])
#     total = sum(len(chars) ** l for l in range(1, max_len + 1))
#     logger.info(f"XMEye brute-force {ip}:{port} user={username!r} ({total} prob)")
#     for length in range(1, max_len + 1):
#         for combo in _it.product(chars, repeat=length):
#             pwd = "".join(combo)
#             if _xmeye_login_attempt(ip, port, username, pwd, timeout_per_attempt):
#                 logger.warning(f"XMEye brute-force sukces: {ip} user={username!r} pwd={pwd!r}")
#                 return {"vuln_type": VulnType.xmeye_dvr_exposed, "severity": VulnSeverity.critical,
#                         "title": f"XMEye/Sofia DVR — haslo zlamane: user={username!r}", "port": port,
#                         "evidence": f"user={username!r} password={pwd!r} ({length} znaki)"}
#     return None


# Sciezki do sprawdzenia — tylko HEAD/GET bez parametrow restartu
# GET do tych endpointow bez parametrow akcji nie powoduje restartu na zadnym normalnym urzadzeniu.
_REBOOT_PATHS = [
    "/reboot.cgi",           # Netgear, Zyxel, generic router
    "/cgi-bin/reboot.cgi",   # D-Link, generic
    "/cgi-bin/reboot",       # TP-Link, Huawei
    "/admin/reboot",         # Generic admin panel
    "/goform/Reboot",        # Asus/TP-Link (GET bez action= nie restartuje)
    "/setup.cgi",            # Netgear setup (strona, nie akcja)
    "/system/reboot",        # Generic REST API (zwraca JSON error bez auth)
    "/api/system/reboot",    # Ubiquiti/Mikrotik style
]


def check_unauth_reboot(ip: str) -> Optional[dict]:
    """Sprawdza czy endpoint restartu urzadzenia jest dostepny bez uwierzytelnienia.

    Uzywa GET request — pozwala sprawdzic body odpowiedzi (HEAD moze byc mylacy).
    Flaga gdy: endpoint odpowiada 200/204 BEZ naglowka WWW-Authenticate ORAZ
    odpowiedz nie jest strona HTML (logowanie / SPA) ORAZ body nie zawiera
    slow kluczowych oznaczajacych brak uprawnien.

    SPA (np. Ubiquiti UniFi OS) zwraca HTTP 200 + text/html dla kazdej nieznanej
    sciezki — ta heurystyka eliminuje ten typ false positive.
    """
    # Keywords in body indicating access denied / method not supported (not a vulnerability)
    _DENY_BODY = (
        b"unauthorized", b"Unauthorized", b"UNAUTHORIZED",
        b"forbidden", b"Forbidden", b"FORBIDDEN",
        b"permission denied", b"Permission denied", b"PERMISSION DENIED",
        b"access denied", b"Access denied", b"ACCESS DENIED",
        b"not authenticated", b"Not authenticated",
        b"\"error\"", b"'error'",
        # Chinese DVR (Dahua/H264DVR/Sofia) return Ret:136 "Not support GET method"
        # with HTTP 200 text/plain — not a real reboot endpoint, just ignoring the method
        b"Not support", b"not support",
        b"param format error", b"Param format error",
        b"method not allowed", b"Method Not Allowed",
    )

    for port in (80, 8080, 8443, 443):
        if not _tcp_open(ip, port, timeout=2):
            continue
        scheme = "https" if port in (8443, 443) else "http"
        for path in _REBOOT_PATHS:
            try:
                r = httpx.get(
                    f"{scheme}://{ip}:{port}{path}",
                    timeout=3.0,
                    follow_redirects=False,
                    verify=False,
                )
                if r.status_code not in (200, 204):
                    continue
                if "www-authenticate" in r.headers:
                    continue
                # Odpowiedz HTML = strona logowania lub SPA (false positive)
                ct = r.headers.get("content-type", "")
                if "text/html" in ct:
                    continue
                # Body z komunikatem o braku uprawnien = false positive
                body = r.content[:512]
                if any(kw in body for kw in _DENY_BODY):
                    continue
                return {
                    "vuln_type": VulnType.unauth_reboot,
                    "severity": VulnSeverity.critical,
                    "title": f"Endpoint restartu bez uwierzytelnienia: {path}",
                    "port": port,
                    "evidence": (
                        f"GET {scheme}://{ip}:{port}{path} -> {r.status_code} "
                        f"content-type={ct!r} (brak WWW-Authenticate, brak HTML)"
                    ),
                }
            except Exception:
                continue
    return None


def check_tftp(ip: str) -> Optional[dict]:
    """Sprawdza czy serwer TFTP (UDP 69) jest dostepny bez uwierzytelnienia.

    TFTP nie ma mechanizmu uwierzytelniania — kazdy moze czytac i pisac pliki
    jesli serwer jest dostepny. Wysylamy TFTP RRQ (Read Request) dla pliku
    testowego i sprawdzamy odpowiedz.

    Prawidlowy serwer TFTP odpowie:
    - Data packet (opcode=3) jesli plik istnieje
    - Error packet (opcode=5) jesli plik nie istnieje — to TEZ jest dowod,
      ze serwer odpowiada (co oznacza podatnosc na naduzycia).

    Brak odpowiedzi (timeout) = port zamkniety lub filtrowany = nie podatne.
    """
    _TFTP_TIMEOUT = 3.0
    # RRQ: opcode=1, filename="netdoc_probe.txt", mode="octet"
    rrq = b"\x00\x01netdoc_probe.txt\x00octet\x00"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(_TFTP_TIMEOUT)
        sock.sendto(rrq, (ip, 69))
        data, _ = sock.recvfrom(516)
        sock.close()
    except OSError:
        return None

    if len(data) < 2:
        return None

    opcode = (data[0] << 8) | data[1]
    # opcode=3 (DATA): serwer odpowiada danymi pliku
    # opcode=5 (ERROR): serwer istnieje i odpowiada na protokol TFTP
    if opcode not in (3, 5):
        return None

    if opcode == 3:
        evidence = f"TFTP DATA packet ({len(data)} B) — serwer wyslal dane pliku bez auth"
    else:
        err_code = (data[2] << 8) | data[3] if len(data) >= 4 else 0
        err_msg = data[4:].rstrip(b"\x00").decode("utf-8", errors="replace") if len(data) > 4 else ""
        evidence = f"TFTP ERROR packet opcode=5 err={err_code} msg={err_msg!r:.60} — serwer TFTP aktywny"

    return {
        "vuln_type": VulnType.tftp_exposed,
        "severity": VulnSeverity.high,
        "title": "TFTP serwer dostepny bez uwierzytelnienia (UDP 69)",
        "port": 69,
        "evidence": evidence,
    }


def check_cisco_smart_install(ip: str) -> Optional[dict]:
    """Cisco Smart Install (vstack) — TCP 4786 dostępny bez uwierzytelnienia.

    CVE-2018-0171 (CVSS 9.8 CRITICAL): protokół Smart Install działa domyślnie
    na switchach Cisco IOS i IOS-XE bez żadnego uwierzytelnienia. Atakujący może:
    - nadpisać konfigurację startową i running-config urządzenia,
    - skopiować konfigurację (z hasłami) na zewnętrzny serwer TFTP,
    - wymusić reload urządzenia (DoS),
    - załadować zmodyfikowany obraz systemu (pełne przejęcie).

    Port 4786 TCP jest używany wyłącznie przez Cisco Smart Install (vstack).
    Jego obecność oznacza aktywną usługę. Cisco zaleca wyłączenie Smart Install
    komendą 'no vstack' i użycie Cisco DNA Center lub APIC-EM do zarządzania.
    Jeśli Smart Install jest wymagane — ogranicz dostęp ACL tylko do dyrektora.
    """
    if not _tcp_open(ip, 4786, timeout=2):
        return None
    # Probe: minimalna wiadomość vstack HELLO (4 bajty type + padding)
    _PROBE = b'\x00\x00\x00\x01' + b'\x00' * 20
    try:
        with socket.create_connection((ip, 4786), timeout=_TCP_TIMEOUT) as s:
            s.sendall(_PROBE)
            s.settimeout(_TCP_TIMEOUT)
            try:
                data = s.recv(64)
                evidence = f"TCP 4786 open, response {len(data)} B — Smart Install vstack aktywny"
            except socket.timeout:
                evidence = "TCP 4786 open — port Smart Install dostępny (brak odpowiedzi na probe)"
            return {
                "vuln_type": VulnType.cisco_smart_install,
                "severity": VulnSeverity.critical,
                "title": "Cisco Smart Install dostępny bez auth (CVE-2018-0171)",
                "port": 4786,
                "evidence": evidence,
                "description": (
                    "Cisco Smart Install (vstack) działa bez uwierzytelnienia. "
                    "CVE-2018-0171 (CVSS 9.8): atakujący może odczytać/nadpisać konfigurację "
                    "urządzenia (z hasłami), wymusić reload lub załadować złośliwy firmware IOS. "
                    "Fix: 'no vstack' lub ACL ograniczający dostęp do IP dyrektora Smart Install."
                ),
            }
    except Exception:
        return None


def check_cisco_web_exec(ip: str, device_type) -> Optional[dict]:
    """Cisco IOS HTTP Server — dostęp do exec przez URL /level/15/exec/-.

    Cisco IOS HTTP Server udostępnia interfejs CLI przez HTTP na ścieżkach
    /level/1/exec/ do /level/15/exec/ gdzie poziom odpowiada uprawnieniom IOS.
    Poziom 15 = pełne uprawnienia administratora (odpowiednik 'enable mode').

    Zagrożenia:
    - HTTP 200 bez auth: atakujący wykonuje dowolne polecenia IOS bez logowania
      (show running-config, configure terminal, reload — pełne przejęcie urządzenia).
    - HTTP 401 z Cisco realm: interfejs exec istnieje i jest dostępny przez sieć —
      podatny na brute-force i ataki na protokół HTTP Basic Auth (hasło w Base64).

    Cisco zaleca: wyłącz HTTP server ('no ip http server'), używaj HTTPS z ACL
    ('ip http access-class'), lub zarządzaj przez SSH/RESTCONF/NETCONF.
    Interfejs HTTP exec jest przestarzały — nie jest potrzebny w nowoczesnych
    środowiskach.
    """
    network_types = {DeviceType.router, DeviceType.switch, DeviceType.firewall}
    if device_type not in network_types:
        return None
    paths = ["/level/15/exec/-/show/version/CR", "/level/15/exec/-"]
    for port in (80, 8080):
        if not _tcp_open(ip, port, timeout=2):
            continue
        for path in paths:
            try:
                r = httpx.get(
                    f"http://{ip}:{port}{path}",
                    timeout=_HTTP_TIMEOUT,
                    follow_redirects=False,
                    verify=False,
                )
                body_lower = r.text.lower()
                www_auth = r.headers.get("www-authenticate", "").lower()
                # Unauthenticated access — pełne przejęcie
                if r.status_code == 200 and (
                    "cisco" in body_lower or "ios" in body_lower
                    or "router" in body_lower or "switch" in body_lower
                    or "exec" in body_lower
                ):
                    return {
                        "vuln_type": VulnType.cisco_web_exec,
                        "severity": VulnSeverity.critical,
                        "title": "Cisco IOS HTTP exec — pełny dostęp bez uwierzytelnienia",
                        "port": port,
                        "evidence": f"HTTP 200 na {path} — exec interface dostępny bez auth",
                        "description": (
                            "Cisco IOS HTTP Server udostępnia exec CLI na /level/15/exec/- "
                            "bez logowania (poziom 15 = pełny enable). Atakujący może wykonać "
                            "show running-config, configure terminal, reload. "
                            "Fix: 'no ip http server' lub 'ip http access-class'."
                        ),
                    }
                # Auth required but Cisco exec interface exposed — brute-force / HTTP Basic risk
                if r.status_code == 401 and (
                    "level" in www_auth or "cisco" in www_auth
                    or "ios" in www_auth or "exec" in www_auth
                ):
                    return {
                        "vuln_type": VulnType.cisco_web_exec,
                        "severity": VulnSeverity.high,
                        "title": "Cisco IOS HTTP exec dostępny przez sieć (wymagane auth)",
                        "port": port,
                        "evidence": (
                            f"HTTP 401 na {path} — "
                            f"WWW-Auth: {r.headers.get('www-authenticate', '')[:80]}"
                        ),
                        "description": (
                            "Cisco IOS HTTP Server exec interface dostępny z sieci. "
                            "Wymaga auth, ale HTTP Basic Auth przesyła hasło w Base64 — "
                            "podatne na sniffing i brute-force. "
                            "Fix: 'no ip http server', zarządzaj przez SSH/HTTPS."
                        ),
                    }
            except Exception:
                pass
    return None


def _upsert_vuln(db, device_id: int, v: dict) -> tuple:
    now = datetime.utcnow()
    port_val = v.get("port")
    port_filter = (Vulnerability.port.is_(None) if port_val is None
                   else Vulnerability.port == port_val)
    ex = (db.query(Vulnerability)
        .filter(Vulnerability.device_id == device_id,
                Vulnerability.vuln_type == v["vuln_type"],
                port_filter).first())
    if ex:
        ex.last_seen = now
        if not getattr(ex, 'suppressed', False):  # nie wznawiaj zaakceptowanych
            ex.is_open = True
        ex.evidence = v.get("evidence", ex.evidence)
        return ex, False
    rec = Vulnerability(
        device_id=device_id,
        vuln_type=v["vuln_type"], severity=v["severity"], title=v["title"],
        description=v.get("description"), port=v.get("port"), evidence=v.get("evidence"),
    )
    db.add(rec)
    return rec, True


def _close_stale(db, device_id: int, found_keys: set, close_after: int = 3) -> int:
    """Zamyka podatności, które nie zostały wykryte w kolejnych skanach.

    Podatność jest zamykana dopiero gdy skan nie wykryje jej przez ``close_after``
    kolejnych cykli z rzędu (domyślnie 3). Jeden timeout TCP nie zamknie podatności.
    Gdy podatność zostanie ponownie wykryta, licznik consecutive_ok jest zerowany.
    """
    stale = (db.query(Vulnerability)
        .filter(Vulnerability.device_id == device_id, Vulnerability.is_open == True).all())
    closed = 0
    now = datetime.utcnow()
    for v in stale:
        if (v.vuln_type, v.port) not in found_keys:
            if getattr(v, 'suppressed', False):
                continue  # zaakceptowane ryzyko — nie zamykamy
            current = getattr(v, 'consecutive_ok', 0) or 0
            v.consecutive_ok = current + 1
            if v.consecutive_ok >= close_after:
                v.is_open = False
                v.last_seen = now
                closed += 1
        else:
            # Wykryta ponownie — resetuj licznik
            v.consecutive_ok = 0
    return closed


def _scan_device(device_id: int, ip: str, device_type, close_after: int = 3,
                 skip_printers: bool = True, limit_ap_iot: bool = True) -> dict:
    # Drukarki — pomijamy calkowicie gdy opcja wlaczona. TCP connect do portow
    # 9100/515/631 moze spowodowac wydrukowanie losowych znakow.
    if skip_printers and device_type in _SKIP_VULN_DEVICE_TYPES:
        logger.debug("Skipping vuln scan for %s (type: %s)", ip, device_type)
        return {"found": 0, "new": 0, "closed": 0}

    _limited = limit_ap_iot and (device_type in _LIMITED_VULN_DEVICE_TYPES)

    found: list = []
    # Sprawdzenia dla wszystkich typow urzadzen (sieci, HTTP, SNMP, kamery)
    for chk in (
        lambda: check_telnet(ip),
        lambda: check_http_management(ip, device_type),
        lambda: check_rdp_exposed(ip),
        lambda: check_vnc(ip),
        lambda: check_rtsp(ip, device_type),
        lambda: check_modbus(ip),
        lambda: check_firewall(ip, device_type),
        lambda: check_default_credentials(ip, device_id),
        lambda: check_snmp_public(device_id, ip),
        lambda: check_onvif_noauth(ip),
        lambda: check_mjpeg_noauth(ip),
        lambda: check_rtmp_noauth(ip),
        lambda: check_dahua_dvr_exposed(ip),
        lambda: check_xmeye_dvr_exposed(ip),
        lambda: check_unauth_reboot(ip),
        lambda: check_tftp(ip),
        lambda: check_cisco_smart_install(ip),
        lambda: check_cisco_web_exec(ip, device_type),
    ):
        try:
            r = chk()
            if r: found.append(r)
        except Exception as exc:
            logger.debug("check error %s: %s", ip, exc)

    if not _limited:
        # Sprawdzenia infrastrukturalne — tylko dla serwerow/niezidentyfikowanych
        # Pomijane dla AP/kamer/IoT ktore nie uruchamiaja baz danych ani tych uslug
        for chk in (
            lambda: check_mqtt(ip),
            lambda: check_redis(ip),
            lambda: check_elasticsearch(ip),
            lambda: check_docker_api(ip),
            lambda: check_ipmi(ip),
            lambda: check_mongo(ip),
            lambda: check_mysql(ip),
            lambda: check_postgres_weak(ip),
            lambda: check_mssql_weak(ip),
            lambda: check_vnc_weak(ip),
            lambda: check_couchdb(ip),
            lambda: check_memcached(ip),
            lambda: check_influxdb(ip),
            lambda: check_cassandra(ip),
            lambda: check_rtsp_weak(ip),
        ):
            try:
                r = chk()
                if r: found.append(r)
            except Exception as exc:
                logger.debug("check error %s: %s", ip, exc)

    for chk in (lambda: check_ftp(ip), lambda: check_ssl(ip)):
        try:
            found.extend(chk())
        except Exception as exc:
            logger.debug("check list error %s: %s", ip, exc)
    new_count = closed_count = 0
    db = SessionLocal()
    try:
        found_keys = set()
        for v in found:
            rec, is_new = _upsert_vuln(db, device_id, v)
            found_keys.add((v["vuln_type"], v.get("port")))
            if is_new:
                new_count += 1
                db.flush()
                db.add(Event(device_id=device_id,
                    event_type=EventType.vulnerability_detected,
                    details={"vuln_type": v["vuln_type"].value,
                             "severity": v["severity"].value, "title": v["title"]}))
                logger.warning("NOWA PODATNOSC %-18s %-28s %s",
                               ip, v["vuln_type"].value, v["title"])

            # Enrichment z ONVIF — aktualizuj Device gdy mamy dane z GetDeviceInformation
            enrichment = v.get("enrichment")
            if enrichment and v["vuln_type"] == VulnType.onvif_noauth:
                dev = db.query(Device).filter(Device.id == device_id).first()
                if dev:
                    dev.device_type = DeviceType.camera
                    if enrichment.get("vendor") and not dev.vendor:
                        dev.vendor = enrichment["vendor"]
                    if enrichment.get("model") and not dev.model:
                        dev.model = enrichment["model"]
                    if enrichment.get("os_version") and not dev.os_version:
                        dev.os_version = enrichment["os_version"]
                    if enrichment.get("serial_number") and not dev.serial_number:
                        dev.serial_number = enrichment["serial_number"]
                    logger.info("ONVIF enrich %-18s type=camera vendor=%s model=%s serial=%s fw=%s",
                                ip,
                                enrichment.get("vendor", "-"),
                                enrichment.get("model", "-"),
                                enrichment.get("serial_number", "-"),
                                enrichment.get("os_version", "-"))
            elif v["vuln_type"] == VulnType.onvif_noauth:
                # Nawet bez GetDeviceInformation — wiemy że to kamera
                dev = db.query(Device).filter(Device.id == device_id).first()
                if dev and dev.device_type == DeviceType.unknown:
                    dev.device_type = DeviceType.camera
                    logger.info("ONVIF enrich %-18s type=camera (no device info)", ip)

        closed_count = _close_stale(db, device_id, found_keys, close_after)
        if closed_count:
            db.add(Event(device_id=device_id,
                event_type=EventType.vulnerability_resolved,
                details={"resolved_count": closed_count}))
        db.commit()
    except Exception as exc:
        logger.warning("DB error device=%s: %s", device_id, exc)
        db.rollback()
    finally:
        db.close()
    return {"found": len(found), "new": new_count, "closed": closed_count}


def _preload_global_creds(db) -> dict:
    """PERF-06: Wczytaj globalne credentials raz przed pula watkow."""
    _methods = [
        CredentialMethod.mysql, CredentialMethod.postgres, CredentialMethod.mssql,
        CredentialMethod.vnc, CredentialMethod.rtsp,
    ]
    rows = db.query(Credential).filter(
        Credential.device_id.is_(None),
        Credential.method.in_(_methods),
    ).order_by(Credential.method, Credential.priority.desc()).all()
    # WRK-13: inicjalizuj kazda metode jako [] — bez tego brak wpisow w DB
    # powoduje ze check_mysql/check_vnc_weak/etc otwieraja wlasna sesje DB
    # per watek (potencjalnie 1600+ sesji przy 100 urzadzeniach i 16 workerach)
    result: dict = {m: [] for m in _methods}
    for cr in rows:
        result[cr.method].append(
            (cr.username or "", cr.password_encrypted or "")
        )
    return result


def scan_once() -> None:
    global _total_new, _total_resolved, _global_creds_cache
    _, workers, close_after, skip_printers, limit_ap_iot, tcp_timeout, http_timeout = _read_settings()
    global _TCP_TIMEOUT, _HTTP_TIMEOUT
    _TCP_TIMEOUT  = tcp_timeout
    _HTTP_TIMEOUT = http_timeout
    t0 = time.monotonic()
    db = SessionLocal()
    try:
        dev_list = [(d.id, d.ip, d.device_type)
                    for d in db.query(Device).filter(
                        Device.is_active == True,
                        Device.skip_port_scan == False,
                    ).all()]
        _global_creds_cache = _preload_global_creds(db)
    finally:
        db.close()
    if not dev_list:
        logger.info("No active devices"); return
    logger.info("Vuln scan: %d urzadzen, workers=%d close_after=%d skip_printers=%s limit_ap_iot=%s",
                len(dev_list), workers, close_after, skip_printers, limit_ap_iot)
    total_found = new_t = closed_t = 0
    with ThreadPoolExecutor(max_workers=min(workers, len(dev_list))) as pool:
        futures = {
            pool.submit(_scan_device, did, ip, dt, close_after, skip_printers, limit_ap_iot): ip
            for did, ip, dt in dev_list
        }
        for fut in as_completed(futures):
            try:
                r = fut.result()
                total_found += r["found"]; new_t += r["new"]; closed_t += r["closed"]
            except Exception as exc:
                logger.warning("future error: %s", exc)
    _total_new += new_t; _total_resolved += closed_t
    db = SessionLocal()
    try:
        open_count = db.query(Vulnerability).filter(Vulnerability.is_open == True).count()
    finally:
        db.close()
    elapsed = time.monotonic() - t0
    g_scanned.set(len(dev_list)); g_open.set(open_count)
    g_new.set(_total_new); g_resolved.set(_total_resolved); g_duration.set(round(elapsed, 1))
    logger.info("Vuln done: open=%d new=%d closed=%d  %.1fs",
                open_count, new_t, closed_t, elapsed)


def _wait_for_schema(max_retries: int = 12, wait_s: int = 10) -> None:
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
    logger.info("Netdoc Vuln Worker start metrics=:%d default_interval=%ds",
                METRICS_PORT, _DEFAULT_INTERVAL)
    _wait_for_schema()
    init_db()
    start_http_server(METRICS_PORT)
    logger.info("Metrics: http://0.0.0.0:%d/metrics", METRICS_PORT)
    # PERF-02: sleep-until-next-run instead of sleep-after-work.
    # _MIN_PAUSE_S guarantees a short break even when a scan overshoots the
    # configured interval (prevents back-to-back scans with sleep(0)).
    interval = _DEFAULT_INTERVAL
    while True:
        next_run = time.monotonic() + interval
        try:
            db = SessionLocal()
            try:
                _row = db.query(SystemStatus).filter(
                    SystemStatus.key == "vuln_scanning_enabled",
                    SystemStatus.category == "config",
                ).first()
                _enabled = (_row.value if _row else "0") != "0"
            finally:
                db.close()
            if _enabled:
                scan_once()
            else:
                logger.info("Vulnerability scanning disabled (vuln_scanning_enabled=0) — skipping cycle")
        except Exception as exc:
            logger.exception("Unhandled exception in scan_once (vuln): %s", exc)
        interval, *_ = _read_settings()
        time.sleep(max(_MIN_PAUSE_S, next_run - time.monotonic()))


if __name__ == "__main__":
    main()
