"""
config/lab/device/launcher.py

Generic lab device simulator for NetDoc demo lab.
Supported protocols (controlled via env vars):
  HTTP/80, SNMP/161, Modbus/502, Telnet/23, FTP/21,
  RTSP/554, Redis/6379, MQTT/1883, Docker API/2375,
  VNC no-auth/5900, RDP/3389, XMEye/34567, Dahua/37777,
  JetDirect/9100, ONVIF (via HTTP /onvif/device_service)
"""
import base64
import logging
import os
import socket
import threading
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ── Device identity ───────────────────────────────────────────────────────────
DEV_NAME   = os.getenv("DEV_NAME",       "LAB-DEVICE")
SNMP_DESCR = os.getenv("DEV_SNMP_DESCR", "Generic Lab Device v1.0")
SNMP_NAME  = os.getenv("DEV_SNMP_NAME",  "LAB-DEVICE")
SNMP_LOC   = os.getenv("DEV_SNMP_LOC",   "Lab Network")
HTTP_TITLE = os.getenv("DEV_HTTP_TITLE", DEV_NAME)

# ── Feature flags ─────────────────────────────────────────────────────────────
def _flag(key, default="0"):
    return os.getenv(key, default) != "0"

ENABLE_HTTP        = _flag("DEV_ENABLE_HTTP",        "1")
ENABLE_SNMP        = _flag("DEV_ENABLE_SNMP",        "1")
ENABLE_MODBUS      = _flag("DEV_ENABLE_MODBUS")
ENABLE_TELNET      = _flag("DEV_ENABLE_TELNET")
ENABLE_FTP         = _flag("DEV_ENABLE_FTP")
ENABLE_RTSP        = _flag("DEV_ENABLE_RTSP")
RTSP_AUTH          = _flag("DEV_RTSP_AUTH")
RTSP_AUTH_PASS     = os.getenv("DEV_RTSP_AUTH_PASS", "12345")
ENABLE_ONVIF       = _flag("DEV_ENABLE_ONVIF")
ENABLE_REDIS       = _flag("DEV_ENABLE_REDIS")
ENABLE_MQTT        = _flag("DEV_ENABLE_MQTT")
ENABLE_XMEYE       = _flag("DEV_ENABLE_XMEYE")
ENABLE_DAHUA       = _flag("DEV_ENABLE_DAHUA")
ENABLE_RDP         = _flag("DEV_ENABLE_RDP")
ENABLE_VNC_NOAUTH  = _flag("DEV_ENABLE_VNC_NOAUTH")
ENABLE_DOCKER_API  = _flag("DEV_ENABLE_DOCKER_API")
ENABLE_JETDIRECT   = _flag("DEV_ENABLE_JETDIRECT")

TELNET_BANNER = "\r\n" + DEV_NAME + " management console\r\nlogin: "


# ── SNMP (minimal BER encoder, no external deps) ──────────────────────────────
OID_SYSDESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
OID_SYSNAME  = (1, 3, 6, 1, 2, 1, 1, 5, 0)
OID_SYSLOC   = (1, 3, 6, 1, 2, 1, 1, 6, 0)


def _encode_oid(oid):
    first = 40 * oid[0] + oid[1]
    body = [first]
    for n in oid[2:]:
        if n == 0:
            body.append(0)
        else:
            parts = []
            while n:
                parts.append(n & 0x7f)
                n >>= 7
            parts.reverse()
            for i, p in enumerate(parts):
                body.append(p | (0x80 if i < len(parts) - 1 else 0))
    return bytes(body)


def _encode_tlv(tag, value):
    if isinstance(value, str):
        value = value.encode()
    l = len(value)
    if l < 128:
        return bytes([tag, l]) + value
    elif l < 256:
        return bytes([tag, 0x81, l]) + value
    else:
        return bytes([tag, 0x82, l >> 8, l & 0xff]) + value


def _encode_int(n):
    result = []
    while n or not result:
        result.append(n & 0xff)
        n >>= 8
    result.reverse()
    if result[0] & 0x80:
        result.insert(0, 0)
    return _encode_tlv(0x02, bytes(result))


def _build_snmp_response(request, oid_values):
    try:
        idx = 0
        if request[idx] != 0x30:
            return None
        idx += 1
        if request[idx] & 0x80:
            idx += (request[idx] & 0x7f) + 1
        else:
            idx += 1
        if request[idx] != 0x02:
            return None
        ver_len = request[idx + 1]
        version = request[idx + 2]
        idx += 2 + ver_len
        if request[idx] != 0x04:
            return None
        comm_len = request[idx + 1]
        community = request[idx + 2:idx + 2 + comm_len]
        idx += 2 + comm_len
        pdu_tag = request[idx]
        if pdu_tag not in (0xa0, 0xa1):
            return None
        pdu_start = idx + 2
        if request[pdu_start] != 0x02:
            return None
        rid_len = request[pdu_start + 1]
        request_id = request[pdu_start + 2:pdu_start + 2 + rid_len]
        varbinds = b""
        for oid, val in oid_values.items():
            oid_enc = _encode_oid(oid)
            vb = _encode_tlv(0x06, oid_enc) + _encode_tlv(0x04, val)
            varbinds += _encode_tlv(0x30, vb)
        varbind_list = _encode_tlv(0x30, varbinds)
        pdu_body = (_encode_tlv(0x02, request_id) + _encode_int(0) +
                    _encode_int(0) + varbind_list)
        pdu = _encode_tlv(0xa2, pdu_body)
        ver = _encode_tlv(0x02, bytes([version]))
        comm_tlv = _encode_tlv(0x04, community)
        return _encode_tlv(0x30, ver + comm_tlv + pdu)
    except Exception as e:
        logger.debug("SNMP parse error: %s", e)
        return None


def run_snmp():
    oid_values = {
        OID_SYSDESCR: SNMP_DESCR,
        OID_SYSNAME:  SNMP_NAME,
        OID_SYSLOC:   SNMP_LOC,
    }
    for port in (161, 1161):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
            logger.info("SNMP UDP/%d sysName=%s", port, SNMP_NAME)
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    resp = _build_snmp_response(data, oid_values)
                    if resp:
                        sock.sendto(resp, addr)
                except Exception as e:
                    logger.debug("SNMP error: %s", e)
        except Exception as e:
            logger.warning("SNMP UDP/%d unavailable: %s", port, e)
            continue
        break


# ── TCP server helper ─────────────────────────────────────────────────────────
def _tcp_server(port, handler, desc=""):
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(20)
        logger.info("TCP/%d %s", port, desc)
        while True:
            try:
                conn, _ = srv.accept()
                threading.Thread(target=handler, args=(conn,), daemon=True).start()
            except Exception:
                pass
    except Exception as e:
        logger.warning("TCP/%d failed: %s", port, e)


# ── Protocol handlers ─────────────────────────────────────────────────────────
def _h_telnet(conn):
    try:
        conn.sendall(TELNET_BANNER.encode("utf-8", errors="replace"))
        time.sleep(15)
    except Exception:
        pass
    finally:
        conn.close()


def _h_ftp(conn):
    """Anonymous FTP — accepts any username/password."""
    try:
        conn.settimeout(15)
        conn.sendall(b"220 FTP Server ready\r\n")
        while True:
            line = b""
            while not line.endswith(b"\n"):
                ch = conn.recv(1)
                if not ch:
                    return
                line += ch
            cmd = line.decode("utf-8", errors="replace").strip().upper().split(" ")[0]
            if cmd == "USER":
                conn.sendall(b"331 Password required\r\n")
            elif cmd == "PASS":
                conn.sendall(b"230 Login successful\r\n")
            elif cmd in ("QUIT", "BYE"):
                conn.sendall(b"221 Goodbye\r\n")
                return
            elif cmd == "SYST":
                conn.sendall(b"215 UNIX Type: L8\r\n")
            elif cmd == "PWD":
                conn.sendall(b'257 "/" is current directory\r\n')
            elif cmd in ("TYPE", "MODE", "STRU"):
                conn.sendall(b"200 OK\r\n")
            elif cmd == "PASV":
                conn.sendall(b"227 Entering Passive Mode (127,0,0,1,1,1)\r\n")
            elif cmd == "LIST":
                conn.sendall(b"150 Directory listing\r\n425 Can't open data connection\r\n")
            else:
                conn.sendall(b"200 OK\r\n")
    except Exception:
        pass
    finally:
        conn.close()


def _h_rtsp(conn):
    """RTSP server. If RTSP_AUTH=1: requires Basic auth admin/<RTSP_AUTH_PASS>.
    Otherwise: returns 200 to DESCRIBE (no auth needed = rtsp_noauth vulnerability).
    """
    try:
        conn.settimeout(5)
        data = conn.recv(4096).decode("utf-8", errors="replace")
        if not data:
            return
        cseq = "1"
        for line in data.split("\r\n"):
            if line.upper().startswith("CSEQ:"):
                cseq = line.split(":", 1)[1].strip()
                break
        method = data.split(" ")[0] if data else ""

        if method == "DESCRIBE":
            if not RTSP_AUTH:
                resp = (f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                        "Content-Type: application/sdp\r\nContent-Length: 0\r\n\r\n")
                conn.sendall(resp.encode())
            else:
                auth_ok = False
                for line in data.split("\r\n"):
                    if "Authorization: Basic " in line:
                        try:
                            token = line.split("Basic ", 1)[1].strip()
                            decoded = base64.b64decode(token).decode("utf-8", errors="replace")
                            user, pwd = decoded.split(":", 1)
                            if user == "admin" and pwd == RTSP_AUTH_PASS:
                                auth_ok = True
                        except Exception:
                            pass
                if auth_ok:
                    resp = (f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                            "Content-Type: application/sdp\r\nContent-Length: 0\r\n\r\n")
                else:
                    resp = (f"RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\n"
                            "WWW-Authenticate: Basic realm=\"IPCamera\"\r\n\r\n")
                conn.sendall(resp.encode())
        elif method == "OPTIONS":
            if RTSP_AUTH:
                resp = (f"RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\n"
                        "WWW-Authenticate: Basic realm=\"IPCamera\"\r\n\r\n")
            else:
                resp = (f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                        "Public: DESCRIBE, SETUP, PLAY, TEARDOWN\r\n\r\n")
            conn.sendall(resp.encode())
        else:
            conn.sendall(f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n\r\n".encode())
    except Exception:
        pass
    finally:
        conn.close()


def _h_redis(conn):
    """Minimal Redis mock — responds to PING with +PONG (no auth = redis_noauth vulnerability)."""
    try:
        conn.settimeout(30)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            upper = data.upper()
            if b"PING" in upper:
                conn.sendall(b"+PONG\r\n")
            elif b"INFO" in upper:
                info = (b"# Server\r\nredis_version:7.0.11\r\n"
                        b"redis_mode:standalone\r\nos:Linux\r\n")
                conn.sendall(b"$" + str(len(info)).encode() + b"\r\n" + info + b"\r\n")
            else:
                conn.sendall(b"+OK\r\n")
    except Exception:
        pass
    finally:
        conn.close()


def _h_mqtt(conn):
    """Minimal MQTT mock — responds to CONNECT with CONNACK rc=0 (no auth = mqtt_noauth)."""
    try:
        conn.settimeout(30)
        data = conn.recv(256)
        if data and len(data) >= 2 and data[0] == 0x10:
            conn.sendall(bytes([0x20, 0x02, 0x00, 0x00]))  # CONNACK rc=0
            time.sleep(60)
    except Exception:
        pass
    finally:
        conn.close()


def _h_docker_api(conn):
    """Minimal Docker API mock — GET /version returns JSON with Version key."""
    try:
        conn.settimeout(5)
        data = conn.recv(4096).decode("utf-8", errors="replace")
        path = ""
        for line in data.split("\r\n"):
            if line.startswith(("GET ", "POST ")):
                parts = line.split(" ")
                if len(parts) >= 2:
                    path = parts[1]
                break
        if "/version" in path:
            body = ('{"Version":"24.0.5","ApiVersion":"1.43",'
                    '"MinAPIVersion":"1.12","Os":"linux","Arch":"amd64"}')
            status = "200 OK"
        else:
            body = '{"message":"not found"}'
            status = "404 Not Found"
        resp = (f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}")
        conn.sendall(resp.encode())
    except Exception:
        pass
    finally:
        conn.close()


def _h_vnc_noauth(conn):
    """RFB 3.8 with SecurityType.None=1 — VNC without password."""
    try:
        conn.settimeout(10)
        conn.sendall(b"RFB 003.008\n")
        conn.recv(12)                       # client version
        conn.sendall(bytes([0x01, 0x01]))   # 1 type: SecurityType.None=1
        conn.recv(1)                        # client selects type
        conn.sendall(b"\x00\x00\x00\x00")  # SecurityResult = OK
        time.sleep(30)
    except Exception:
        pass
    finally:
        conn.close()


def _h_banner(banner=b""):
    """Return a handler that sends a fixed banner and closes."""
    def handler(conn):
        try:
            if banner:
                conn.sendall(banner)
            time.sleep(2)
        except Exception:
            pass
        finally:
            conn.close()
    return handler


# ── HTTP + ONVIF (Flask) ──────────────────────────────────────────────────────
def run_http():
    import logging as _lg
    _lg.getLogger("werkzeug").setLevel(_lg.WARNING)

    from flask import Flask, Response, request as req

    app = Flask(__name__)
    app.logger.setLevel(_lg.WARNING)

    _html = f"""<!DOCTYPE html>
<html><head><title>{HTTP_TITLE}</title>
<style>
  body{{font-family:sans-serif;background:#f5f5f5;margin:0;padding:40px}}
  .box{{background:#fff;padding:32px;max-width:420px;border-radius:8px;
        box-shadow:0 2px 10px rgba(0,0,0,.12)}}
  h1{{font-size:1.3em;margin:0 0 4px}}
  .sub{{color:#666;font-size:.85em;margin:0 0 20px}}
  input{{width:100%;padding:9px;margin:6px 0;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}}
  button{{width:100%;padding:10px;background:#1a73e8;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:1em}}
  button:hover{{background:#1557b0}}
</style></head>
<body><div class="box">
  <h1>{HTTP_TITLE}</h1>
  <p class="sub">Web Management Interface</p>
  <form method="post" action="/">
    <input name="username" placeholder="Username" autocomplete="off">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Login</button>
  </form>
</div></body></html>"""

    _onvif_caps = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
        '<s:Body>'
        '<tds:GetCapabilitiesResponse>'
        '<tds:Capabilities/>'
        '</tds:GetCapabilitiesResponse>'
        '</s:Body></s:Envelope>'
    )

    @app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
    @app.route("/<path:path>", methods=["GET", "POST"])
    def catch_all(path):
        # ONVIF device service endpoint
        if ENABLE_ONVIF and path == "onvif/device_service":
            body = req.get_data(as_text=True)
            if "GetCapabilities" in body:
                return Response(_onvif_caps,
                                content_type="application/soap+xml; charset=utf-8")
            return Response("", status=400)
        return Response(_html, content_type="text/html; charset=utf-8")

    logger.info("HTTP/80 %s (ONVIF=%s)", HTTP_TITLE, ENABLE_ONVIF)
    app.run(host="0.0.0.0", port=80, threaded=True)


# ── Modbus TCP ────────────────────────────────────────────────────────────────
def run_modbus():
    from pymodbus.server import StartTcpServer
    from pymodbus.datastore import (ModbusSlaveContext, ModbusServerContext,
                                    ModbusSequentialDataBlock)
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0] * 100),
        co=ModbusSequentialDataBlock(0, [0] * 100),
        hr=ModbusSequentialDataBlock(0, list(range(100))),
        ir=ModbusSequentialDataBlock(0, list(range(100))),
    )
    context = ModbusServerContext(slaves=store, single=True)
    logger.info("Modbus TCP/502 %s", DEV_NAME)
    StartTcpServer(context=context, address=("0.0.0.0", 502))


# ── Start all enabled services ────────────────────────────────────────────────
def _start(fn, *args, **kwargs):
    t = threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True)
    t.start()


if ENABLE_SNMP:
    _start(run_snmp)

if ENABLE_TELNET:
    _start(_tcp_server, 23, _h_telnet, "Telnet")

if ENABLE_FTP:
    _start(_tcp_server, 21, _h_ftp, "FTP anon")

if ENABLE_RTSP:
    _start(_tcp_server, 554, _h_rtsp, "RTSP")

if ENABLE_REDIS:
    _start(_tcp_server, 6379, _h_redis, "Redis no-auth")

if ENABLE_MQTT:
    _start(_tcp_server, 1883, _h_mqtt, "MQTT no-auth")

if ENABLE_DOCKER_API:
    _start(_tcp_server, 2375, _h_docker_api, "Docker API")

if ENABLE_VNC_NOAUTH:
    _start(_tcp_server, 5900, _h_vnc_noauth, "VNC no-auth")

if ENABLE_RDP:
    # Minimal RDP TPKT response — TCP open is enough for check_rdp_exposed
    _start(_tcp_server, 3389, _h_banner(b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x00\x00\x00"), "RDP")

if ENABLE_XMEYE:
    # XMEye/Sofia DVR protocol header — must send something so _tcp_banner returns non-None
    _start(_tcp_server, 34567, _h_banner(b"\xff\x00\x00\x00\x00\x00\x00\x00"), "XMEye/34567")

if ENABLE_DAHUA:
    # Dahua proprietary protocol header
    _start(_tcp_server, 37777, _h_banner(b"\xff\x01\x00\x00"), "Dahua/37777")

if ENABLE_JETDIRECT:
    # HP JetDirect — accepts print jobs on port 9100
    _start(_tcp_server, 9100, _h_banner(b"@PJL READY\r\n@PJL INFO STATUS\r\n"), "JetDirect/9100")

if ENABLE_MODBUS:
    _start(run_modbus)

if ENABLE_HTTP:
    run_http()  # blocking — must be last
else:
    while True:
        time.sleep(3600)
