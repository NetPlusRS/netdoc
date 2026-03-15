"""Symulowany PLC: Modbus TCP/502 + prosty SNMP UDP/161."""
import os
import threading
import logging
import socket
import struct

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

PLC_NAME   = os.getenv("PLC_NAME",       "PLC-1")
SNMP_DESCR = os.getenv("PLC_SNMP_DESCR", "Generic PLC")
SNMP_NAME  = os.getenv("PLC_SNMP_NAME",  "PLC-1")
SNMP_LOC   = os.getenv("PLC_SNMP_LOC",   "Server Room")

OID_SYSDESCR  = (1,3,6,1,2,1,1,1,0)
OID_SYSNAME   = (1,3,6,1,2,1,1,5,0)
OID_SYSLOC    = (1,3,6,1,2,1,1,6,0)


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
    """Buduje minimalny SNMP v1/v2c GetResponse."""
    try:
        # Parsuj community
        idx = 0
        if request[idx] != 0x30: return None
        idx += 1
        # skip length
        if request[idx] & 0x80:
            idx += (request[idx] & 0x7f) + 1
        else:
            idx += 1
        # version
        if request[idx] != 0x02: return None
        ver_len = request[idx+1]
        version = request[idx+2]
        idx += 2 + ver_len
        # community
        if request[idx] != 0x04: return None
        comm_len = request[idx+1]
        community = request[idx+2:idx+2+comm_len]
        idx += 2 + comm_len
        # PDU type (GetRequest=0xa0, GetNextRequest=0xa1)
        pdu_tag = request[idx]
        if pdu_tag not in (0xa0, 0xa1): return None

        # Znajdz request-id
        pdu_start = idx + 2
        if request[pdu_start] != 0x02: return None
        rid_len = request[pdu_start+1]
        request_id = request[pdu_start+2:pdu_start+2+rid_len]

        # Buduj VarBindList
        varbinds = b""
        for oid, val in oid_values.items():
            oid_enc = encode_oid(oid)
            vb = encode_tlv(0x06, oid_enc) + encode_tlv(0x04, val)
            varbinds += encode_tlv(0x30, vb)
        varbind_list = encode_tlv(0x30, varbinds)

        # response-id, error-status=0, error-index=0
        pdu_body = encode_tlv(0x02, request_id) + encode_int(0) + encode_int(0) + varbind_list
        pdu = encode_tlv(0xa2, pdu_body)

        # SNMP message
        ver = encode_tlv(0x02, bytes([version]))
        comm_tlv = encode_tlv(0x04, community)
        msg = encode_tlv(0x30, ver + comm_tlv + pdu)
        return msg
    except Exception as e:
        logger.debug("SNMP parse error: %s", e)
        return None


def run_snmp():
    """Minimalny SNMP UDP/161 agent (tylko sysDescr/sysName/sysLocation)."""
    OID_VALUES = {
        OID_SYSDESCR: SNMP_DESCR,
        OID_SYSNAME:  SNMP_NAME,
        OID_SYSLOC:   SNMP_LOC,
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 161))
        logger.info("SNMP UDP/161 uruchomiony: sysName=%s", SNMP_NAME)
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                resp = build_snmp_response(data, OID_VALUES)
                if resp:
                    sock.sendto(resp, addr)
            except Exception as e:
                logger.debug("SNMP error: %s", e)
    except Exception as e:
        logger.warning("SNMP nie uruchomiony (brak uprawnien do portu 161): %s", e)
        # Probuj port 1610 (bez uprawnien root)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 1161))
            logger.info("SNMP UDP/1161 (fallback) uruchomiony")
            while True:
                data, addr = sock.recvfrom(4096)
                resp = build_snmp_response(data, OID_VALUES)
                if resp:
                    sock.sendto(resp, addr)
        except Exception as e2:
            logger.error("SNMP calkowicie niedostepny: %s", e2)


def run_modbus():
    from pymodbus.server import StartTcpServer
    from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext, ModbusSequentialDataBlock
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0]*100),
        co=ModbusSequentialDataBlock(0, [0]*100),
        hr=ModbusSequentialDataBlock(0, list(range(100))),
        ir=ModbusSequentialDataBlock(0, list(range(100))),
    )
    context = ModbusServerContext(slaves=store, single=True)
    logger.info("Modbus TCP/502 uruchomiony: %s", PLC_NAME)
    StartTcpServer(context=context, address=("0.0.0.0", 502))


threading.Thread(target=run_snmp, daemon=True).start()
run_modbus()
