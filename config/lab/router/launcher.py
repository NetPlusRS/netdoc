"""Symulowany MikroTik RB750: SNMP UDP/161 + Telnet /bin/sh."""
import os
import threading
import logging
import socket
import subprocess

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

SNMP_DESCR = os.getenv("ROUTER_SNMP_DESCR", "MikroTik RouterOS 6.49.10 (stable) RB750Gr3")
SNMP_NAME  = os.getenv("ROUTER_SNMP_NAME",  "MikroTik-RB750")
SNMP_LOC   = os.getenv("ROUTER_SNMP_LOC",   "Server Room A / Rack 2")

OID_SYSDESCR = (1,3,6,1,2,1,1,1,0)
OID_SYSNAME  = (1,3,6,1,2,1,1,5,0)
OID_SYSLOC   = (1,3,6,1,2,1,1,6,0)


def encode_oid(oid):
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
                body.append(p | (0x80 if i < len(parts)-1 else 0))
    return bytes(body)


def encode_tlv(tag, value):
    if isinstance(value, str):
        value = value.encode()
    l = len(value)
    if l < 128:
        return bytes([tag, l]) + value
    elif l < 256:
        return bytes([tag, 0x81, l]) + value
    else:
        return bytes([tag, 0x82, l >> 8, l & 0xff]) + value


def encode_int(n):
    result = []
    while n or not result:
        result.append(n & 0xff)
        n >>= 8
    result.reverse()
    if result[0] & 0x80:
        result.insert(0, 0)
    return encode_tlv(0x02, bytes(result))


def build_snmp_response(request, oid_values):
    try:
        idx = 0
        if request[idx] != 0x30: return None
        idx += 1
        if request[idx] & 0x80:
            idx += (request[idx] & 0x7f) + 1
        else:
            idx += 1
        if request[idx] != 0x02: return None
        ver_len = request[idx+1]
        version = request[idx+2]
        idx += 2 + ver_len
        if request[idx] != 0x04: return None
        comm_len = request[idx+1]
        community = request[idx+2:idx+2+comm_len]
        idx += 2 + comm_len
        pdu_tag = request[idx]
        if pdu_tag not in (0xa0, 0xa1): return None
        pdu_start = idx + 2
        if request[pdu_start] != 0x02: return None
        rid_len = request[pdu_start+1]
        request_id = request[pdu_start+2:pdu_start+2+rid_len]
        varbinds = b""
        for oid, val in oid_values.items():
            oid_enc = encode_oid(oid)
            vb = encode_tlv(0x06, oid_enc) + encode_tlv(0x04, val)
            varbinds += encode_tlv(0x30, vb)
        varbind_list = encode_tlv(0x30, varbinds)
        pdu_body = encode_tlv(0x02, request_id) + encode_int(0) + encode_int(0) + varbind_list
        pdu = encode_tlv(0xa2, pdu_body)
        ver = encode_tlv(0x02, bytes([version]))
        comm_tlv = encode_tlv(0x04, community)
        msg = encode_tlv(0x30, ver + comm_tlv + pdu)
        return msg
    except Exception as e:
        logger.debug("SNMP parse error: %s", e)
        return None


def run_snmp():
    OID_VALUES = {
        OID_SYSDESCR: SNMP_DESCR,
        OID_SYSNAME:  SNMP_NAME,
        OID_SYSLOC:   SNMP_LOC,
    }
    for port in (161, 1161):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
            logger.info("SNMP UDP/%d uruchomiony: sysName=%s", port, SNMP_NAME)
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    resp = build_snmp_response(data, OID_VALUES)
                    if resp:
                        sock.sendto(resp, addr)
                except Exception as e:
                    logger.debug("SNMP error: %s", e)
            return
        except Exception as e:
            logger.warning("SNMP port %d niedostepny: %s", port, e)
    logger.error("SNMP calkowicie niedostepny")


def handle_telnet_client(conn, addr):
    """Prosty symulator Telnet — MikroTik banner + brak uwierzytelnienia."""
    try:
        banner = (
            b"\r\n  MMM      MMM       KKK                          TTTTTTTTTTT      KKK\r\n"
            b"  MMMM    MMMM       KKK                          TTTTTTTTTTT      KKK\r\n"
            b"  MMM MMMM MMM  iii  KKK  KKK  rrrrrr   oooooo       TTT      iii  KKK  KKK\r\n"
            b"  MMM  MM  MMM  iii  KKKKK     rr   rr  oo  oo       TTT      iii  KKKKK\r\n"
            b"  MMM      MMM  iii  KKK KKK   rrrrrr   oo  oo       TTT      iii  KKK KKK\r\n"
            b"  MMM      MMM  iii  KKK  KKK  rr  rr   oooooo       TTT      iii  KKK  KKK\r\n"
            b"\r\n"
            b"  MikroTik RouterOS 6.49.10 (c) 1999-2023       http://www.mikrotik.com/\r\n"
            b"\r\n"
            b"[?1h=[admin@MikroTik] > "
        )
        conn.sendall(banner)
        while True:
            data = conn.recv(256)
            if not data:
                break
            cmd = data.strip().decode(errors="ignore")
            if cmd in ("quit", "exit", "logout"):
                conn.sendall(b"\r\nGoodbye\r\n")
                break
            conn.sendall(f"\r\n[admin@MikroTik] > ".encode())
    except Exception:
        pass
    finally:
        conn.close()


def run_telnet():
    """Prosty serwer Telnet TCP/23 symulujacy MikroTik."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", 23))
        srv.listen(5)
        logger.info("Telnet TCP/23 uruchomiony (MikroTik symulator)")
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_telnet_client, args=(conn, addr), daemon=True)
            t.start()
    except Exception as e:
        logger.error("Telnet error: %s", e)


threading.Thread(target=run_snmp, daemon=True).start()
run_telnet()
