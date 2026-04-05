"""SNMP L2 data collection — FDB, VLAN membership, STP port state.

Zbiera dane warstwy L2 ze switchy przez SNMP:
  - FDB (dot1dTp) — tablica przekazywania MAC: MAC → bridge port → ifIndex
  - VLAN membership (dot1q) — ktore porty naleza do ktorego VLAN-u
  - STP port state (dot1dStp) — stan Spanning Tree per port

Wszystkie funkcje sa read-only (nie dotykaja bazy danych).
Zapis do DB wykonuje run_snmp_worker.py przez _save_fdb(), _save_vlan_port(), _save_stp_ports().

Uwagi implementacyjne:
  - Cisco IOS wymaga community@vlanId dla per-VLAN FDB — MVP zbiera tylko default bridge instance
  - FDB moze miec do 16 000+ wpisow — max_iter=5000
  - STP: zbieramy bridge-level (nie per-VLAN MSTP instance)
  - Bitstring VLAN membership: n-ty bit = port n (IEEE 802.1Q)
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# OID definicje
# ─────────────────────────────────────────────────────────────────────────────

# Bridge MIB (RFC 1493) — FDB
_OID_FDB_ADDRESS   = "1.3.6.1.2.1.17.4.3.1.1"  # dot1dTpFdbAddress: mac bytes
_OID_FDB_PORT      = "1.3.6.1.2.1.17.4.3.1.2"  # dot1dTpFdbPort: bridge port num
_OID_FDB_STATUS    = "1.3.6.1.2.1.17.4.3.1.3"  # dot1dTpFdbStatus: 3=learned,5=static

# Bridge port → ifIndex mapping
_OID_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"  # dot1dBasePortIfIndex

# Q-BRIDGE MIB (IEEE 802.1Q) — VLAN membership
_OID_VLAN_STATIC_EGRESS = "1.3.6.1.2.1.17.7.1.4.3.1.2"   # dot1qVlanStaticEgressPorts (bitstring)
_OID_VLAN_STATIC_UNTAG  = "1.3.6.1.2.1.17.7.1.4.3.1.4"   # dot1qVlanStaticUntaggedPorts (bitstring)
_OID_VLAN_STATIC_NAME   = "1.3.6.1.2.1.17.7.1.4.3.1.1"   # dot1qVlanStaticName
_OID_PVID               = "1.3.6.1.2.1.17.7.1.4.5.1.1"   # dot1qPvid: PVID per port ifIndex

# STP MIB (RFC 1493) — Spanning Tree
_OID_STP_PORT_STATE     = "1.3.6.1.2.1.17.2.15.1.3"   # dot1dStpPortState: 1-6
_OID_STP_PORT_PATH_COST = "1.3.6.1.2.1.17.2.15.1.7"   # dot1dStpPortPathCost
_OID_STP_PORT_ROLE      = "1.3.6.1.2.1.17.2.15.1.6"   # dot1dStpPortRole (RSTP): 1=disabled,2=root,3=designated,4=alternate,5=backup
_OID_STP_ROOT           = "1.3.6.1.2.1.17.2.5"        # dot1dStpDesignatedRoot (8 bytes)
_OID_STP_ROOT_COST      = "1.3.6.1.2.1.17.2.6"        # dot1dStpRootPathCost

_STP_STATE_NAMES = {
    1: "disabled",
    2: "blocking",
    3: "listening",
    4: "learning",
    5: "forwarding",
    6: "broken",
}

_STP_ROLE_NAMES = {
    1: "disabled",
    2: "root",
    3: "designated",
    4: "alternate",
    5: "backup",
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _oid_suffix_int(full_oid: str, prefix: str) -> Optional[int]:
    """Wyciaga ostatni element OID jako int (np. ifIndex z full OID)."""
    try:
        return int(full_oid.strip(".").rsplit(".", 1)[-1])
    except (ValueError, IndexError):
        return None


def _bytes_to_mac(raw) -> Optional[str]:
    """Konwertuje bajty lub hex string na XX:XX:XX:XX:XX:XX."""
    try:
        if isinstance(raw, (bytes, bytearray)):
            b = raw
        elif isinstance(raw, str):
            # Moze byc OID-style "0.21.105...." lub hex
            parts = raw.split(".")
            if len(parts) == 6 and all(p.isdigit() for p in parts):
                b = bytes(int(p) for p in parts)
            else:
                b = bytes.fromhex(raw.replace(":", "").replace("-", ""))
        else:
            return None
        if len(b) != 6:
            return None
        return ":".join(f"{x:02x}" for x in b)
    except Exception:
        return None


def _parse_bitstring(raw) -> list[int]:
    """Parsuje bitstring IEEE 802.1Q na liste numerow portow (1-based).

    raw: bytes lub string. n-ty bit (MSB first) = port n.
    """
    ports = []
    if isinstance(raw, str):
        # Moze byc hex string bez separatorow lub z separatorami
        try:
            raw = bytes.fromhex(raw.replace(" ", "").replace(":", ""))
        except ValueError:
            return ports
    if not isinstance(raw, (bytes, bytearray)):
        return ports
    for byte_idx, byte_val in enumerate(raw):
        for bit_idx in range(8):
            if byte_val & (0x80 >> bit_idx):
                port_num = byte_idx * 8 + bit_idx + 1
                ports.append(port_num)
    return ports


# ─────────────────────────────────────────────────────────────────────────────
# FDB collection
# ─────────────────────────────────────────────────────────────────────────────

def collect_fdb(ip: str, community: str, timeout: int = 2) -> list[dict]:
    """Zbiera tablice FDB (MAC forwarding table) ze switcha.

    Zwraca liste slownikow:
        mac (str)           — XX:XX:XX:XX:XX:XX
        bridge_port (int)   — numer portu w bridge (dot1dTpFdbPort)
        if_index (int|None) — zmapowany ifIndex (dot1dBasePortIfIndex)
        fdb_status (int)    — 3=learned, 5=static
        vlan_id (None)      — MVP: brak per-VLAN context (Cisco wymaga @vlanId)

    Cisco MVP uwaga: bez community@vlanId zbieramy tylko default bridge instance.
    Pelna implementacja per-VLAN jako rozszerzenie w przyszlosci.
    """
    from netdoc.collector.snmp_walk import snmp_walk

    # Krok 1: Pobierz bridge_port → ifIndex mapping
    port_to_ifindex: dict[int, int] = {}
    try:
        rows = snmp_walk(ip, _OID_BASE_PORT_IFINDEX, community, timeout=timeout, max_iter=512)
        for full_oid, raw_val, _ in rows:
            bp = _oid_suffix_int(full_oid, _OID_BASE_PORT_IFINDEX)
            if bp is not None:
                try:
                    port_to_ifindex[bp] = int(raw_val)
                except (ValueError, TypeError):
                    pass
    except Exception as exc:
        logger.debug("collect_fdb %s: bridge port map error: %s", ip, exc)

    _FDB_MAX_ITER = 16384  # switche enterprise mogą mieć 16000+ wpisów FDB

    # Krok 2: Pobierz FDB — MAC → bridge_port
    mac_to_port: dict[str, int] = {}
    try:
        rows = snmp_walk(ip, _OID_FDB_PORT, community, timeout=timeout, max_iter=_FDB_MAX_ITER)
        if len(rows) >= _FDB_MAX_ITER:
            logger.warning("collect_fdb %s: FDB walk truncated at %d — switch może mieć więcej wpisów", ip, _FDB_MAX_ITER)
        for full_oid, raw_val, _ in rows:
            try:
                # Suffix OID to bajty MAC: 1.3.6.1.2.1.17.4.3.1.2.0.21.105.X.X.X
                suffix = full_oid.strip().split(_OID_FDB_PORT.rstrip(".") + ".")[-1]
                parts  = suffix.strip(".").split(".")
                if len(parts) == 6:
                    mac = ":".join(f"{int(p):02x}" for p in parts)
                    mac_to_port[mac] = int(raw_val)
            except Exception:
                pass
    except Exception as exc:
        logger.debug("collect_fdb %s: FDB port walk error: %s", ip, exc)

    # Krok 3: Pobierz status wpisow
    mac_to_status: dict[str, int] = {}
    try:
        rows = snmp_walk(ip, _OID_FDB_STATUS, community, timeout=timeout, max_iter=_FDB_MAX_ITER)
        for full_oid, raw_val, _ in rows:
            try:
                suffix = full_oid.strip().split(_OID_FDB_STATUS.rstrip(".") + ".")[-1]
                parts  = suffix.strip(".").split(".")
                if len(parts) == 6:
                    mac = ":".join(f"{int(p):02x}" for p in parts)
                    mac_to_status[mac] = int(raw_val)
            except Exception:
                pass
    except Exception as exc:
        logger.debug("collect_fdb %s: FDB status walk error: %s", ip, exc)

    # Złożenie wyniku
    result = []
    for mac, bridge_port in mac_to_port.items():
        if_index = port_to_ifindex.get(bridge_port)
        status   = mac_to_status.get(mac, 3)  # default: learned
        # Filtruj broadcast i multicast MAC
        first_octet = int(mac.split(":")[0], 16) if mac else 0
        if first_octet & 0x01:
            continue
        result.append({
            "mac":         mac,
            "bridge_port": bridge_port,
            "if_index":    if_index,
            "fdb_status":  status,
            "vlan_id":     None,
        })

    logger.debug("collect_fdb %s: %d entries (bridge port map: %d)", ip, len(result), len(port_to_ifindex))
    return result


# ─────────────────────────────────────────────────────────────────────────────
# VLAN membership collection
# ─────────────────────────────────────────────────────────────────────────────

def collect_vlan_port(ip: str, community: str, timeout: int = 2) -> list[dict]:
    """Zbiera przynaleznosc portow do VLAN-ow ze switcha (dot1q MIB).

    Zwraca liste slownikow:
        vlan_id (int)       — numer VLAN (1-4094)
        vlan_name (str|None) — nazwa VLAN
        if_index (int)      — ifIndex portu
        port_mode (str)     — 'access' (untagged) lub 'trunk' (tagged)
        is_pvid (bool)      — True jezeli to PVID portu

    Metoda: egress ports bitstring → lista portow w VLAN.
    Untagged bitstring sluzy do rozroznienia access/trunk.
    """
    from netdoc.collector.snmp_walk import snmp_walk

    # Pobierz nazwy VLAN-ow
    vlan_names: dict[int, str] = {}
    try:
        rows = snmp_walk(ip, _OID_VLAN_STATIC_NAME, community, timeout=timeout, max_iter=512)
        for full_oid, raw_val, _ in rows:
            vlan_id = _oid_suffix_int(full_oid, _OID_VLAN_STATIC_NAME)
            if vlan_id is not None:
                try:
                    name = raw_val.decode("utf-8", errors="replace").strip() if isinstance(raw_val, bytes) else str(raw_val).strip()
                    vlan_names[vlan_id] = name
                except Exception:
                    pass
    except Exception as exc:
        logger.debug("collect_vlan_port %s: vlan names error: %s", ip, exc)

    # Pobierz egress ports per VLAN
    vlan_egress: dict[int, list[int]] = {}
    try:
        rows = snmp_walk(ip, _OID_VLAN_STATIC_EGRESS, community, timeout=timeout, max_iter=512)
        for full_oid, raw_val, _ in rows:
            vlan_id = _oid_suffix_int(full_oid, _OID_VLAN_STATIC_EGRESS)
            if vlan_id is not None:
                vlan_egress[vlan_id] = _parse_bitstring(raw_val)
    except Exception as exc:
        logger.debug("collect_vlan_port %s: egress walk error: %s", ip, exc)

    # Pobierz untagged ports per VLAN
    vlan_untagged: dict[int, set[int]] = {}
    try:
        rows = snmp_walk(ip, _OID_VLAN_STATIC_UNTAG, community, timeout=timeout, max_iter=512)
        for full_oid, raw_val, _ in rows:
            vlan_id = _oid_suffix_int(full_oid, _OID_VLAN_STATIC_UNTAG)
            if vlan_id is not None:
                vlan_untagged[vlan_id] = set(_parse_bitstring(raw_val))
    except Exception as exc:
        logger.debug("collect_vlan_port %s: untagged walk error: %s", ip, exc)

    # Pobierz PVID per ifIndex
    pvid_map: dict[int, int] = {}  # ifIndex → vlan_id
    try:
        rows = snmp_walk(ip, _OID_PVID, community, timeout=timeout, max_iter=512)
        for full_oid, raw_val, _ in rows:
            if_index = _oid_suffix_int(full_oid, _OID_PVID)
            if if_index is not None:
                try:
                    pvid_map[if_index] = int(raw_val)
                except (ValueError, TypeError):
                    pass
    except Exception as exc:
        logger.debug("collect_vlan_port %s: pvid walk error: %s", ip, exc)

    # Mapowanie bridge port (1-based z bitstring) → ifIndex
    # Uwaga: w Q-BRIDGE bitstring indeksy sa bridge ports, nie ifIndex
    # Potrzebujemy mapowania bridge_port → ifIndex
    port_to_ifindex: dict[int, int] = {}
    try:
        from netdoc.collector.snmp_walk import snmp_walk as _walk
        rows = _walk(ip, _OID_BASE_PORT_IFINDEX, community, timeout=timeout, max_iter=512)
        for full_oid, raw_val, _ in rows:
            bp = _oid_suffix_int(full_oid, _OID_BASE_PORT_IFINDEX)
            if bp is not None:
                try:
                    port_to_ifindex[bp] = int(raw_val)
                except (ValueError, TypeError):
                    pass
    except Exception as exc:
        logger.debug("collect_vlan_port %s: port-ifindex map error: %s", ip, exc)

    # Złożenie wyniku
    result = []
    for vlan_id, bridge_ports in vlan_egress.items():
        if vlan_id < 1 or vlan_id > 4094:
            continue
        untagged_ports = vlan_untagged.get(vlan_id, set())
        vlan_name = vlan_names.get(vlan_id)
        for bp in bridge_ports:
            if_index = port_to_ifindex.get(bp)
            if if_index is None:
                continue
            is_untagged = bp in untagged_ports
            port_mode   = "access" if is_untagged else "trunk"
            is_pvid     = pvid_map.get(if_index) == vlan_id
            result.append({
                "vlan_id":   vlan_id,
                "vlan_name": vlan_name,
                "if_index":  if_index,
                "port_mode": port_mode,
                "is_pvid":   is_pvid,
            })

    logger.debug("collect_vlan_port %s: %d vlan-port entries (vlans: %d)", ip, len(result), len(vlan_egress))
    return result


# ─────────────────────────────────────────────────────────────────────────────
# STP collection
# ─────────────────────────────────────────────────────────────────────────────

def collect_stp_ports(ip: str, community: str, timeout: int = 2) -> tuple[list[dict], Optional[str], Optional[int]]:
    """Zbiera stan STP per port ze switcha.

    Zwraca tuple:
        ports (list[dict]): lista portow z polami:
            stp_port_num (int)   — dot1dStpPort
            if_index (int|None)  — zmapowany ifIndex
            stp_state (int)      — 1=disabled..5=forwarding
            stp_role (str|None)  — 'root'|'designated'|'alternate'|'backup' (RSTP)
            path_cost (int|None) — dot1dStpPortPathCost
        root_mac (str|None): MAC root bridge (dot1dStpDesignatedRoot)
        root_cost (int|None): koszt sciezki do root (dot1dStpRootPathCost)
    """
    from netdoc.collector.snmp_walk import snmp_walk

    # Bridge port → ifIndex mapping
    port_to_ifindex: dict[int, int] = {}
    try:
        rows = snmp_walk(ip, _OID_BASE_PORT_IFINDEX, community, timeout=timeout, max_iter=512)
        for full_oid, raw_val, _ in rows:
            bp = _oid_suffix_int(full_oid, _OID_BASE_PORT_IFINDEX)
            if bp is not None:
                try:
                    port_to_ifindex[bp] = int(raw_val)
                except (ValueError, TypeError):
                    pass
    except Exception as exc:
        logger.debug("collect_stp_ports %s: port-ifindex map error: %s", ip, exc)

    # STP port state
    port_state: dict[int, int] = {}
    try:
        rows = snmp_walk(ip, _OID_STP_PORT_STATE, community, timeout=timeout, max_iter=256)
        for full_oid, raw_val, _ in rows:
            bp = _oid_suffix_int(full_oid, _OID_STP_PORT_STATE)
            if bp is not None:
                try:
                    port_state[bp] = int(raw_val)
                except (ValueError, TypeError):
                    pass
    except Exception as exc:
        logger.debug("collect_stp_ports %s: port state error: %s", ip, exc)

    # STP port path cost
    port_cost: dict[int, int] = {}
    try:
        rows = snmp_walk(ip, _OID_STP_PORT_PATH_COST, community, timeout=timeout, max_iter=256)
        for full_oid, raw_val, _ in rows:
            bp = _oid_suffix_int(full_oid, _OID_STP_PORT_PATH_COST)
            if bp is not None:
                try:
                    port_cost[bp] = int(raw_val)
                except (ValueError, TypeError):
                    pass
    except Exception as exc:
        logger.debug("collect_stp_ports %s: port cost error: %s", ip, exc)

    # STP port role (RSTP)
    port_role: dict[int, str] = {}
    try:
        rows = snmp_walk(ip, _OID_STP_PORT_ROLE, community, timeout=timeout, max_iter=256)
        for full_oid, raw_val, _ in rows:
            bp = _oid_suffix_int(full_oid, _OID_STP_PORT_ROLE)
            if bp is not None:
                try:
                    role_int = int(raw_val)
                    port_role[bp] = _STP_ROLE_NAMES.get(role_int, str(role_int))
                except (ValueError, TypeError):
                    pass
    except Exception as exc:
        logger.debug("collect_stp_ports %s: port role error: %s", ip, exc)

    # Root bridge info (GET — nie walk)
    root_mac: Optional[str]  = None
    root_cost: Optional[int] = None
    try:
        from netdoc.collector.drivers.snmp import _snmp_get
        raw_root = _snmp_get(ip, community, _OID_STP_ROOT + ".0", timeout=timeout)
        if raw_root is not None:
            # dot1dStpDesignatedRoot = Bridge ID (8 bajty): 2B priorytet + 6B MAC.
            # _bytes_to_mac oczekuje dokladnie 6 bajtow — pomijamy 2 bajty priorytetu.
            if isinstance(raw_root, (bytes, bytearray)) and len(raw_root) == 8:
                root_mac = _bytes_to_mac(raw_root[2:])
            elif isinstance(raw_root, str):
                parts = raw_root.split(".")
                if len(parts) == 8 and all(p.isdigit() for p in parts):
                    root_mac = _bytes_to_mac(bytes(int(p) for p in parts[2:]))
                else:
                    root_mac = _bytes_to_mac(raw_root)
            else:
                root_mac = _bytes_to_mac(raw_root)
    except Exception as exc:
        logger.debug("collect_stp_ports %s: root mac error: %s", ip, exc)
    try:
        from netdoc.collector.drivers.snmp import _snmp_get
        raw_cost = _snmp_get(ip, community, _OID_STP_ROOT_COST + ".0", timeout=timeout)
        if raw_cost is not None:
            root_cost = int(raw_cost)
    except Exception as exc:
        logger.debug("collect_stp_ports %s: root cost error: %s", ip, exc)

    # Zlozenie portow
    all_ports = set(port_state.keys()) | set(port_cost.keys()) | set(port_role.keys())
    ports = []
    for bp in sorted(all_ports):
        state = port_state.get(bp)
        if state == 1:  # disabled — pomijamy (nie jest uzyteczny)
            continue
        ports.append({
            "stp_port_num": bp,
            "if_index":     port_to_ifindex.get(bp),
            "stp_state":    state,
            "stp_role":     port_role.get(bp),
            "path_cost":    port_cost.get(bp),
        })

    logger.debug("collect_stp_ports %s: %d ports, root_mac=%s", ip, len(ports), root_mac)
    return ports, root_mac, root_cost
