"""Pure-Python SNMP GET-NEXT walker — bez pysnmp.

Rozwiazuje problem pysnmp 6.x (nextCmd/walk zwraca pusty dict).
Uzywa raw UDP + BER encoding — zero zewnetrznych zaleznosci.

Odkrywa adresacje sieciowa z tablic zarzadzalnych urzadzen:
  - snmp_arp_table()     — ipNetToMediaPhysAddress (ARP table routera/switcha)
  - snmp_mac_table()     — dot1dTpFdbAddress (bridge MAC forwarding table switcha)
  - snmp_ifip_table()    — ipAddrTable (adresy IP + maski interfejsow)
  - snmp_route_table()   — ipRouteTable (tablice routingu — odkrywa podsieci)

Zastosowanie:
  Router/switch z SNMP "public" community → pelna mapa adresacji bez DHCP.
  MAC table switcha → wszystkie urzadzenia L2 nawet bez pingowania.
"""
import logging
import os as _os
import socket as _socket
import time as _time

logger = logging.getLogger(__name__)

# SNMP_DEBUG=1 → loguj kazda probe community na poziomie INFO (widoczne w logach workera)
# Domyslnie proby sa na DEBUG — nie zasmiecaja logow produkcyjnych
_SNMP_DEBUG = _os.getenv("SNMP_DEBUG", "0") == "1"
_log_probe = logger.info if _SNMP_DEBUG else logger.debug

# ─── BER encoding ─────────────────────────────────────────────────────────────

def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    parts = []
    tmp = n
    while tmp:
        parts.append(tmp & 0xFF)
        tmp >>= 8
    parts.reverse()
    return bytes([0x80 | len(parts)] + parts)


def _enc_oid(oid_str: str) -> bytes:
    """Koduje OID string (np. '1.3.6.1.2.1') do BER."""
    parts = [int(x) for x in oid_str.strip(".").split(".")]
    if len(parts) < 2:
        raise ValueError(f"OID zbyt krotkie: {oid_str}")
    enc = [40 * parts[0] + parts[1]]
    for v in parts[2:]:
        if v == 0:
            enc.append(0)
        else:
            sub = []
            tmp = v
            while tmp:
                sub.append(tmp & 0x7F)
                tmp >>= 7
            sub.reverse()
            for i, b in enumerate(sub):
                enc.append(b | (0x80 if i < len(sub) - 1 else 0))
    body = bytes(enc)
    return b"\x06" + _enc_len(len(body)) + body


def _enc_int(n: int) -> bytes:
    if n == 0:
        return b"\x02\x01\x00"
    enc = []
    tmp = n
    while tmp:
        enc.append(tmp & 0xFF)
        tmp >>= 8
    if enc[-1] & 0x80:
        enc.append(0)
    enc.reverse()
    return b"\x02" + _enc_len(len(enc)) + bytes(enc)


def _enc_str(s: bytes) -> bytes:
    return b"\x04" + _enc_len(len(s)) + s


def _enc_seq(body: bytes, tag: int = 0x30) -> bytes:
    return bytes([tag]) + _enc_len(len(body)) + body


def _build_get_next(community: str, oid_str: str, req_id: int) -> bytes:
    """Buduje pakiet SNMP v1 GET-NEXT."""
    var_bind = _enc_seq(_enc_oid(oid_str) + b"\x05\x00")       # OID + NULL
    pdu = _enc_seq(
        _enc_int(req_id) + _enc_int(0) + _enc_int(0) + _enc_seq(var_bind),
        tag=0xA1,  # GetNextRequest PDU
    )
    msg = _enc_int(0) + _enc_str(community.encode()) + pdu      # v1 + community + PDU
    return _enc_seq(msg)


# ─── BER decoding ─────────────────────────────────────────────────────────────

def _dec_len(data: bytes, off: int):
    """Zwraca (length, new_offset)."""
    b = data[off]; off += 1
    if b < 0x80:
        return b, off
    n = b & 0x7F
    length = 0
    for _ in range(n):
        length = (length << 8) | data[off]; off += 1
    return length, off


def _dec_tlv(data: bytes, off: int):
    """Zwraca (tag, value_bytes, new_offset)."""
    if off >= len(data):
        return None, b"", off
    tag = data[off]; off += 1
    length, off = _dec_len(data, off)
    return tag, data[off:off + length], off + length


def _dec_oid(val_bytes: bytes) -> str:
    """Dekoduje BER OID value (bez tagu i dlugosci) do string."""
    if not val_bytes:
        return ""
    parts = [val_bytes[0] // 40, val_bytes[0] % 40]
    i = 1
    while i < len(val_bytes):
        v = 0
        while i < len(val_bytes):
            b = val_bytes[i]; i += 1
            v = (v << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        parts.append(v)
    return ".".join(str(p) for p in parts)


def _parse_response(resp: bytes):
    """Parsuje odpowiedz SNMP GET-NEXT.

    Zwraca (oid_str, value_bytes, value_tag) lub None gdy blad.
    """
    try:
        _, msg, _ = _dec_tlv(resp, 0)          # outer SEQUENCE
        off = 0
        _, _, off = _dec_tlv(msg, off)          # version
        _, _, off = _dec_tlv(msg, off)          # community
        pdu_tag, pdu, _ = _dec_tlv(msg, off)
        if pdu_tag != 0xA2:                     # GetResponse
            return None
        off = 0
        _, _, off = _dec_tlv(pdu, off)          # request-id
        _, err_val, off = _dec_tlv(pdu, off)    # error-status
        if err_val and err_val[0] != 0:
            return None                         # SNMP error (koniec tabeli itp.)
        _, _, off = _dec_tlv(pdu, off)          # error-index
        _, vbl, _ = _dec_tlv(pdu, off)          # VarBindList
        _, vb, _ = _dec_tlv(vbl, 0)             # first VarBind
        oid_tag, oid_bytes, vb_off = _dec_tlv(vb, 0)
        if oid_tag != 0x06:
            return None
        val_tag, val_bytes, _ = _dec_tlv(vb, vb_off)
        return _dec_oid(oid_bytes), val_bytes, val_tag
    except Exception:
        return None


# ─── Core walker ──────────────────────────────────────────────────────────────

def snmp_walk(
    ip: str,
    base_oid: str,
    community: str = "public",
    timeout: float = 2.0,
    max_iter: int = 500,
) -> list:
    """SNMP GET-NEXT walk drzewa base_oid.

    Zwraca liste (oid_str, value_bytes, value_tag).
    Zatrzymuje sie gdy OID opuszcza poddrzewo lub osiagnieto max_iter.
    Pure Python — zero zewnetrznych zaleznosci, dziala niezaleznie od pysnmp.
    """
    results = []
    current_oid = base_oid
    req_id = 1
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.connect((ip, 161))
    except OSError:
        return results
    try:
        for _ in range(max_iter):
            pdu = _build_get_next(community, current_oid, req_id)
            req_id += 1
            try:
                sock.send(pdu)
                resp = sock.recv(4096)
            except OSError:
                break
            parsed = _parse_response(resp)
            if parsed is None:
                break
            oid_str, val_bytes, val_tag = parsed
            # Zatrzymaj gdy OID opuszcza subtree
            prefix = base_oid + "."
            if oid_str != base_oid and not oid_str.startswith(prefix):
                break
            results.append((oid_str, val_bytes, val_tag))
            current_oid = oid_str
    finally:
        sock.close()
    return results


# ─── High-level discovery functions ───────────────────────────────────────────

def snmp_arp_table(
    ip: str, community: str = "public", timeout: float = 2.0
) -> dict:
    """Czyta tablice ARP urzadzenia przez SNMP (ipNetToMediaPhysAddress).

    OID: 1.3.6.1.2.1.4.22.1.2 — suffix: ifIndex.a.b.c.d → mac
    Zwraca {ip_address: mac_string} dla wszystkich dynamicznych wpisow.

    Router/L3-switch widzial te hosty — mapa obejmuje caly VLAN/kabel,
    nawet urzadzenia bez DHCP ktore tylko wysylaly ruch.
    """
    BASE = "1.3.6.1.2.1.4.22.1.2"
    result = {}
    for oid_str, val_bytes, _ in snmp_walk(ip, BASE, community, timeout):
        suffix = oid_str[len(BASE):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) < 5:
            continue
        remote_ip = ".".join(parts[1:5])          # parts[0]=ifIndex, 1-4=IP octets
        if len(val_bytes) == 6:
            mac = ":".join(f"{b:02x}" for b in val_bytes)
            result[remote_ip] = mac
    if result:
        logger.info("SNMP ARP table %s: %d wpisow IP→MAC", ip, len(result))
    return result


def snmp_mac_table(
    ip: str, community: str = "public", timeout: float = 2.0
) -> list:
    """Czyta tablice forwardingu L2 switcha (dot1dTpFdbAddress).

    OID: 1.3.6.1.2.1.17.4.3.1.1
    Zwraca liste MAC adresow wszystkich urzadzen widocznych na portach switcha.

    Potezniejsze niz ARP: wykrywa rowniez urzadzenia bez IP (drukarki,
    przemyslowe PLC, starsze urzadzenia OT ktore sie nie pinguja).
    """
    BASE = "1.3.6.1.2.1.17.4.3.1.1"
    macs = []
    for oid_str, val_bytes, _ in snmp_walk(ip, BASE, community, timeout):
        if len(val_bytes) == 6:
            mac = ":".join(f"{b:02x}" for b in val_bytes)
            macs.append(mac)
    if macs:
        logger.info("SNMP MAC table %s: %d MAC adresow (L2)", ip, len(macs))
    return macs


def snmp_ifip_table(
    ip: str, community: str = "public", timeout: float = 2.0
) -> list:
    """Czyta tablice adresow IP interfejsow urzadzenia (ipAddrTable).

    Chodzi o adresy skonfigurowane na interfejsach routera/switcha — kazdy
    wpis to (adres_ip, maska_podsieci, indeks_interfejsu).

    OID ipAdEntAddr:    1.3.6.1.2.1.4.20.1.1  — adresy IP (w OID sufiksie)
    OID ipAdEntNetMask: 1.3.6.1.2.1.4.20.1.3  — maski podsieci

    Ujawnia podsieci ktore urzadzenie obs³uguje bez DHCP/DNS.
    Np. router z 5 interfejsami daje 5 podsieci do skanowania.
    """
    BASE_ADDR = "1.3.6.1.2.1.4.20.1.1"
    BASE_MASK = "1.3.6.1.2.1.4.20.1.3"

    # Zbierz adresy (OID suffix = adres IP)
    addrs = []
    for oid_str, val_bytes, val_tag in snmp_walk(ip, BASE_ADDR, community, timeout):
        suffix = oid_str[len(BASE_ADDR):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) == 4:
            try:
                addrs.append(".".join(parts))
            except Exception:
                pass

    # Zbierz maski (OID suffix = adres IP, value = maska)
    masks: dict = {}
    for oid_str, val_bytes, val_tag in snmp_walk(ip, BASE_MASK, community, timeout):
        suffix = oid_str[len(BASE_MASK):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) == 4 and len(val_bytes) == 4:
            addr_key = ".".join(parts)
            mask_str = ".".join(str(b) for b in val_bytes)
            masks[addr_key] = mask_str

    result = []
    for addr in addrs:
        mask = masks.get(addr)
        if mask:
            result.append({"ip": addr, "mask": mask})

    if result:
        logger.info("SNMP ifIP table %s: %d interfejsow z adresem", ip, len(result))
    return result


def snmp_route_table(
    ip: str, community: str = "public", timeout: float = 2.0
) -> list:
    """Czyta tablice routingu urzadzenia (ipRouteTable).

    OID ipRouteDest:    1.3.6.1.2.1.4.21.1.1  — siec docelowa
    OID ipRouteMask:    1.3.6.1.2.1.4.21.1.11 — maska
    OID ipRouteNextHop: 1.3.6.1.2.1.4.21.1.7  — next hop (0.0.0.0 = bezposrednia)
    OID ipRouteType:    1.3.6.1.2.1.4.21.1.8  — typ (3=direct, 4=indirect)

    Zwraca liste {"dest": str, "mask": str, "nexthop": str, "type": int}.
    Trasy direct (type=3) to podsieci bezposrednio podlaczone — idealne do skanowania.
    """
    BASE_DEST    = "1.3.6.1.2.1.4.21.1.1"
    BASE_MASK    = "1.3.6.1.2.1.4.21.1.11"
    BASE_NEXTHOP = "1.3.6.1.2.1.4.21.1.7"
    BASE_TYPE    = "1.3.6.1.2.1.4.21.1.8"

    def _walk_ip_value(base: str) -> dict:
        """Zwraca {suffix_oid: ip_string} dla OID ktorych value to 4-bajtowy IP."""
        out = {}
        for oid_str, val_bytes, _ in snmp_walk(ip, base, community, timeout):
            suffix = oid_str[len(base):].lstrip(".")
            if len(val_bytes) == 4:
                out[suffix] = ".".join(str(b) for b in val_bytes)
        return out

    def _walk_int_value(base: str) -> dict:
        """Zwraca {suffix_oid: int} dla OID ktorych value to integer."""
        out = {}
        for oid_str, val_bytes, _ in snmp_walk(ip, base, community, timeout):
            suffix = oid_str[len(base):].lstrip(".")
            if val_bytes:
                v = 0
                for b in val_bytes:
                    v = (v << 8) | b
                out[suffix] = v
        return out

    dests    = _walk_ip_value(BASE_DEST)
    masks    = _walk_ip_value(BASE_MASK)
    nexthops = _walk_ip_value(BASE_NEXTHOP)
    types    = _walk_int_value(BASE_TYPE)

    result = []
    for suffix, dest in dests.items():
        mask    = masks.get(suffix, "")
        nexthop = nexthops.get(suffix, "")
        rtype   = types.get(suffix, 0)
        result.append({"dest": dest, "mask": mask, "nexthop": nexthop, "type": rtype})

    if result:
        logger.info("SNMP route table %s: %d tras (direct+indirect)", ip, len(result))
    return result


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _is_valid_private_ip(ip_str: str) -> bool:
    """Sprawdza czy string to prywatny unicast IP (RFC 1918)."""
    try:
        parts = [int(x) for x in ip_str.split(".")]
        if len(parts) != 4 or not all(0 <= p <= 255 for p in parts):
            return False
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        return False
    except (ValueError, AttributeError):
        return False


def mask_to_prefix(mask_str: str) -> int:
    """Konwertuje maske podsieci (np. '255.255.255.0') na prefix length (24)."""
    try:
        parts = [int(x) for x in mask_str.split(".")]
        n = sum(bin(b).count("1") for b in parts)
        return n
    except Exception:
        return 24


def snmp_find_community(
    ip: str,
    communities: tuple,
    timeout: float = 1.5,
    inter_probe_delay: float = 0.1,
    max_parallel: int = 3,
) -> str | None:
    """Sprawdza kolejne community strings i zwraca pierwsza ktora dziala.

    Rate-limiting aby nie wyzwolic IDS/lockout na urzadzeniu:
    - inter_probe_delay: pauza miedzy kolejnymi probami jednego IP (domyslnie 100ms)
    - max_parallel: maks rownoleglosc przy wielu urzadzeniach (kontrolowane przez wywolujacego)
    - Dla urzadzen z juz zapamieta community (lista ma 1 element) — zero opoznien.

    Dla duzych list community (>50) automatycznie zwieksza opoznienie
    aby uniknac zaleznosci czasowych wykrywanych przez IDS.
    """
    if not communities:
        return None

    # Adaptacyjny delay: przy duzej liscie community opozniamy bardziej
    # <10 community: 0.1s  |  10-50: 0.2s  |  >50: 0.3s
    if len(communities) > 50:
        delay = max(inter_probe_delay, 0.3)
    elif len(communities) > 10:
        delay = max(inter_probe_delay, 0.2)
    else:
        delay = inter_probe_delay

    for i, comm in enumerate(communities):
        if i > 0:
            _time.sleep(delay)
        _log_probe("SNMP %s: proba community=%r (%d/%d)", ip, comm, i + 1, len(communities))
        rows = snmp_walk(ip, "1.3.6.1.2.1.1.1", comm, timeout=timeout, max_iter=1)
        if rows:
            logger.info("SNMP %s: community=%r OK (proba %d/%d)",
                        ip, comm, i + 1, len(communities))
            return comm
        _log_probe("SNMP %s: community=%r FAIL", ip, comm)

    _log_probe("SNMP %s: zadna z %d community nie dziala", ip, len(communities))
    return None


def snmp_discover_networks(
    ip: str,
    communities: tuple = ("public", "private"),
    timeout: float = 2.0,
    inter_probe_delay: float = 0.1,
) -> dict:
    """Kompletne odkrywanie adresacji przez SNMP z jednego urzadzenia.

    Najpierw szuka dzialajacei community (z rate-limitingiem), potem
    zbiera tablice ARP/MAC/ifIP/routing. Zwraca slownik:
    {
      "arp":       {ip: mac},           # ipNetToMediaPhysAddress
      "macs":      [mac, ...],          # dot1dTpFdbAddress (L2 MAC table)
      "ifaces":    [{"ip", "mask"}, …], # ipAddrTable (interfejsy z adresami)
      "routes":    [{"dest","mask","nexthop","type"}, …],  # ipRouteTable
      "community": str|None,            # community ktora zadziala (do zapisu w DB)
    }

    Rate-limiting: inter_probe_delay (domyslnie 100ms miedzy probami community).
    Dla urzadzen z juz zapamieta community lista ma 1 element → zero delay.
    """
    result: dict = {"arp": {}, "macs": [], "ifaces": [], "routes": [], "community": None}

    comm = snmp_find_community(ip, communities, timeout=1.5,
                               inter_probe_delay=inter_probe_delay)
    if not comm:
        return result

    result["community"] = comm
    result["arp"].update(snmp_arp_table(ip, comm, timeout))
    result["macs"].extend(snmp_mac_table(ip, comm, timeout))
    result["ifaces"].extend(snmp_ifip_table(ip, comm, timeout))
    result["routes"].extend(snmp_route_table(ip, comm, timeout))
    return result
