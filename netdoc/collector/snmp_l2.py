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
# Static VLAN table (standard, dziala na wiekszosci urzadzen)
_OID_VLAN_STATIC_EGRESS = "1.3.6.1.2.1.17.7.1.4.3.1.2"   # dot1qVlanStaticEgressPorts (bitstring)
_OID_VLAN_STATIC_UNTAG  = "1.3.6.1.2.1.17.7.1.4.3.1.4"   # dot1qVlanStaticUntaggedPorts (bitstring)
_OID_VLAN_STATIC_NAME   = "1.3.6.1.2.1.17.7.1.4.3.1.1"   # dot1qVlanStaticName
# Current VLAN table (fallback — Cisco SG300, HP, inne ktore nie maja static table)
# Index: <TimeMark>.<VlanIndex> — ostatni element = VLAN ID
_OID_VLAN_CURR_EGRESS   = "1.3.6.1.2.1.17.7.1.4.2.1.3"   # dot1qVlanCurrentEgressPorts (bitstring)
_OID_VLAN_CURR_UNTAG    = "1.3.6.1.2.1.17.7.1.4.2.1.4"   # dot1qVlanCurrentUntaggedPorts (bitstring)
# Per-port VLAN assignment (dziala niezaleznie od bitstring VLAN tables)
_OID_PVID               = "1.3.6.1.2.1.17.7.1.4.5.1.1"   # dot1qPvid: access VLAN per bridge port
# Cisco IOS — ciscoVlanMembership MIB (dostepny bez community@vlanId)
_OID_CISCO_VM_VLAN      = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"  # vmVlan: access VLAN per ifIndex
_OID_CISCO_VTP_NAME     = "1.3.6.1.4.1.9.9.46.1.3.1.1.4.1" # vtpVlanName per VLAN (domain 1)

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


def _int_from_raw(raw) -> Optional[int]:
    """Konwertuje surową wartość SNMP (bytes lub str) na int.

    snmp_walk zwraca bytes z BER — int(bytes) rzuca TypeError.
    Używamy big-endian decode, tak jak _int_val w snmp_sensors.py.
    """
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        return int.from_bytes(raw, "big") if raw else 0
    try:
        return int(raw)
    except (ValueError, TypeError):
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
                    port_to_ifindex[bp] = _int_from_raw(raw_val)
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
                    mac_to_port[mac] = _int_from_raw(raw_val)
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
                    mac_to_status[mac] = _int_from_raw(raw_val)
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

    Strategia (3-etapowa):
    1. dot1qVlanStaticTable — standard, dziala na Juniper, HP ProCurve, Extreme
    2. dot1qVlanCurrentTable — fallback dla urzadzen bez static table (Cisco SG300, Ubiquiti)
    3. PVID per bridge port — ostateczny fallback: znamy tylko access VLAN per port
       Cisco IOS (2960X, 3750) wymaga community@vlanId dla pelnego dot1q — PVID jest
       dostepne bez tego i daje minimalnie uzyteczne dane (access VLAN per port).
    """
    from netdoc.collector.snmp_walk import snmp_walk

    def _walk_safe(oid, max_iter=512):
        try:
            return list(snmp_walk(ip, oid, community, timeout=timeout, max_iter=max_iter))
        except Exception as exc:
            logger.debug("collect_vlan_port %s walk %s: %s", ip, oid, exc)
            return []

    # ── Mapowanie bridge port → ifIndex (potrzebne dla bitstring i PVID) ──────
    port_to_ifindex: dict[int, int] = {}
    for full_oid, raw_val, _ in _walk_safe(_OID_BASE_PORT_IFINDEX):
        bp = _oid_suffix_int(full_oid, _OID_BASE_PORT_IFINDEX)
        if bp is not None:
            v = _int_from_raw(raw_val)
            if v:
                port_to_ifindex[bp] = v

    # ── PVID per bridge port (dot1qPvid) — zawsze zbieramy, niezaleznie od metody
    pvid_by_bp: dict[int, int] = {}   # bridgePort → vlan_id
    for full_oid, raw_val, _ in _walk_safe(_OID_PVID):
        bp = _oid_suffix_int(full_oid, _OID_PVID)
        if bp is not None:
            v = _int_from_raw(raw_val)
            if v and 1 <= v <= 4094:
                pvid_by_bp[bp] = v

    # ── VLAN nazwy (static table — nie ma w current table) ────────────────────
    vlan_names: dict[int, str] = {}
    for full_oid, raw_val, _ in _walk_safe(_OID_VLAN_STATIC_NAME):
        vlan_id = _oid_suffix_int(full_oid, _OID_VLAN_STATIC_NAME)
        if vlan_id is not None:
            try:
                name = raw_val.decode("utf-8", errors="replace").strip() if isinstance(raw_val, (bytes, bytearray)) else str(raw_val).strip()
                if name:
                    vlan_names[vlan_id] = name
            except Exception:
                pass

    # ── Strategia 1: dot1qVlanStaticEgressPorts (bitstring per VLAN) ──────────
    vlan_egress:   dict[int, list[int]] = {}
    vlan_untagged: dict[int, set[int]]  = {}

    for full_oid, raw_val, _ in _walk_safe(_OID_VLAN_STATIC_EGRESS):
        vlan_id = _oid_suffix_int(full_oid, _OID_VLAN_STATIC_EGRESS)
        if vlan_id is not None:
            vlan_egress[vlan_id] = _parse_bitstring(raw_val)

    for full_oid, raw_val, _ in _walk_safe(_OID_VLAN_STATIC_UNTAG):
        vlan_id = _oid_suffix_int(full_oid, _OID_VLAN_STATIC_UNTAG)
        if vlan_id is not None:
            vlan_untagged[vlan_id] = set(_parse_bitstring(raw_val))

    # ── Strategia 2: dot1qVlanCurrentEgressPorts (jesli static puste) ─────────
    if not vlan_egress:
        for full_oid, raw_val, _ in _walk_safe(_OID_VLAN_CURR_EGRESS):
            # Index: <TimeMark>.<VlanIndex> — ostatni element = VLAN ID
            vlan_id = _oid_suffix_int(full_oid, _OID_VLAN_CURR_EGRESS)
            if vlan_id is not None and 1 <= vlan_id <= 4094:
                vlan_egress[vlan_id] = _parse_bitstring(raw_val)
        for full_oid, raw_val, _ in _walk_safe(_OID_VLAN_CURR_UNTAG):
            vlan_id = _oid_suffix_int(full_oid, _OID_VLAN_CURR_UNTAG)
            if vlan_id is not None and 1 <= vlan_id <= 4094:
                vlan_untagged[vlan_id] = set(_parse_bitstring(raw_val))
        if vlan_egress:
            logger.debug("collect_vlan_port %s: uzywam dot1qVlanCurrentTable (static puste)", ip)

    # ── Zlozenie wyniku z bitstring (strategia 1 lub 2) ───────────────────────
    result = []
    seen: set[tuple] = set()  # (vlan_id, if_index) — deduplikacja

    if vlan_egress:
        for vlan_id, bridge_ports in vlan_egress.items():
            if vlan_id < 1 or vlan_id > 4094:
                continue
            untagged_set = vlan_untagged.get(vlan_id, set())
            vlan_name = vlan_names.get(vlan_id)
            for bp in bridge_ports:
                if_index = port_to_ifindex.get(bp)
                if if_index is None:
                    continue
                key = (vlan_id, if_index)
                if key in seen:
                    continue
                seen.add(key)
                is_untagged = bp in untagged_set
                port_mode   = "access" if is_untagged else "trunk"
                is_pvid     = pvid_by_bp.get(bp) == vlan_id
                result.append({
                    "vlan_id":   vlan_id,
                    "vlan_name": vlan_name,
                    "if_index":  if_index,
                    "port_mode": port_mode,
                    "is_pvid":   is_pvid,
                })

    # ── Strategia 3 (fallback): PVID per port — gdy bitstring nie dal danych ──
    # Daje tylko access VLAN per port, bez trunk VLAN membership.
    # Cisco IOS bez community@vlanId najczesciej laduje tutaj.
    if not result and pvid_by_bp:
        logger.debug("collect_vlan_port %s: fallback do PVID-only (brak danych z bitstring)", ip)
        for bp, vlan_id in pvid_by_bp.items():
            if_index = port_to_ifindex.get(bp)
            if if_index is None:
                continue
            key = (vlan_id, if_index)
            if key in seen:
                continue
            seen.add(key)
            result.append({
                "vlan_id":   vlan_id,
                "vlan_name": vlan_names.get(vlan_id),
                "if_index":  if_index,
                "port_mode": "access",
                "is_pvid":   True,
            })

    # ── Strategia 4 (Cisco IOS): ciscoVlanMembership MIB — vmVlan per ifIndex ─
    # Dostepny na Cisco IOS bez community@vlanId. Dziala gdy Q-BRIDGE MIB jest zablokowane.
    # Probujemy zawsze jesli wciaz nie mamy danych.
    if not result:
        cisco_vlan_by_if: dict[int, int] = {}  # ifIndex → vlan_id
        for full_oid, raw_val, _ in _walk_safe(_OID_CISCO_VM_VLAN, max_iter=300):
            if_idx = _oid_suffix_int(full_oid, _OID_CISCO_VM_VLAN)
            if if_idx is not None:
                v = _int_from_raw(raw_val)
                if v and 1 <= v <= 4094:
                    cisco_vlan_by_if[if_idx] = v

        if cisco_vlan_by_if:
            # Pobierz nazwy VLAN z VTP (jesli dostepne)
            for full_oid, raw_val, _ in _walk_safe(_OID_CISCO_VTP_NAME, max_iter=512):
                vlan_id = _oid_suffix_int(full_oid, _OID_CISCO_VTP_NAME)
                if vlan_id is not None and vlan_id not in vlan_names:
                    try:
                        name = raw_val.decode("utf-8", errors="replace").strip() if isinstance(raw_val, (bytes, bytearray)) else str(raw_val).strip()
                        if name:
                            vlan_names[vlan_id] = name
                    except Exception:
                        pass

            logger.debug("collect_vlan_port %s: uzywam ciscoVlanMembership MIB (%d porty)", ip, len(cisco_vlan_by_if))
            for if_idx, vlan_id in cisco_vlan_by_if.items():
                key = (vlan_id, if_idx)
                if key in seen:
                    continue
                seen.add(key)
                result.append({
                    "vlan_id":   vlan_id,
                    "vlan_name": vlan_names.get(vlan_id),
                    "if_index":  if_idx,
                    "port_mode": "access",
                    "is_pvid":   True,
                })

    method = ("bitstring" if vlan_egress else
              ("pvid" if pvid_by_bp and any(r["is_pvid"] for r in result) else
               ("cisco_vm" if result else "none")))
    logger.debug("collect_vlan_port %s: %d vlan-port entries (vlans: %d, method: %s)",
                 ip, len(result), len({r["vlan_id"] for r in result}), method)
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
                    port_to_ifindex[bp] = _int_from_raw(raw_val)
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
                    port_state[bp] = _int_from_raw(raw_val)
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
                    port_cost[bp] = _int_from_raw(raw_val)
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
                    role_int = _int_from_raw(raw_val)
                    # Wartości 1-5 = valid enum; większe = OCTET STRING (Bridge ID) — ignoruj
                    if role_int is not None and 1 <= role_int <= 5:
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


# ─────────────────────────────────────────────────────────────────────────────
# Cisco VTP MIB — tryb portu (trunk/access) i dane trunk
# ─────────────────────────────────────────────────────────────────────────────

# CISCO-VTP-MIB (1.3.6.1.4.1.9.9.46.1.6.1.1.*)
_OID_TRUNK_ENCAP          = "1.3.6.1.4.1.9.9.46.1.6.1.1.3"   # vlanTrunkPortEncapsulationType
_OID_TRUNK_VLANS_ENABLED  = "1.3.6.1.4.1.9.9.46.1.6.1.1.4"   # vlanTrunkPortVlansEnabled (bitstring 128B)
_OID_TRUNK_NATIVE_VLAN    = "1.3.6.1.4.1.9.9.46.1.6.1.1.5"   # vlanTrunkPortNativeVlan
_OID_TRUNK_STATUS         = "1.3.6.1.4.1.9.9.46.1.6.1.1.13"  # vlanTrunkPortDynamicStatus

_TRUNK_ENCAP_NAMES = {1: "none", 2: "isl", 3: "isl", 4: "dot1q", 5: "negotiate"}
# vlanTrunkPortDynamicStatus: 1=trunking, 2=notTrunking, 3=negotiating, 4=dot1q, 5=other
_TRUNK_STATUS_TRUNKING = 1


def collect_trunk_info(ip: str, community: str, timeout: int = 2) -> dict[int, dict]:
    """Zbiera tryb portu trunk/access z Cisco VTP MIB.

    Dostępne tylko na urządzeniach Cisco z CISCO-VTP-MIB.
    Zwraca {if_index: {'port_mode', 'native_vlan', 'trunk_encap', 'trunk_vlans'}}

    port_mode:   'trunk'  — port jest trunk (aktywnie trunking)
                 'access' — port nie jest trunk
    native_vlan: VLAN ID native (trunk) lub None
    trunk_encap: 'dot1q' | 'isl' | 'none' | None
    trunk_vlans: liczba VLANów dozwolonych na trunk (z bitstringa 128B)
    """
    from netdoc.collector.snmp_walk import snmp_walk

    encap:       dict[int, str] = {}
    native:      dict[int, int] = {}
    status:      dict[int, int] = {}
    vlans_bits:  dict[int, bytes] = {}

    def _walk_int(oid: str, dest: dict) -> None:
        try:
            rows = snmp_walk(ip, oid, community, timeout=timeout, max_iter=256)
            for full_oid, raw_val, _ in rows:
                ifidx = _oid_suffix_int(full_oid, oid)
                if ifidx is not None:
                    v = _int_from_raw(raw_val)
                    if v is not None:
                        dest[ifidx] = v
        except Exception as exc:
            logger.debug("collect_trunk_info %s %s: %s", ip, oid, exc)

    _walk_int(_OID_TRUNK_NATIVE_VLAN, native)
    _walk_int(_OID_TRUNK_STATUS,      status)

    # Encap — zwraca int, mapujemy na string
    try:
        rows = snmp_walk(ip, _OID_TRUNK_ENCAP, community, timeout=timeout, max_iter=256)
        for full_oid, raw_val, _ in rows:
            ifidx = _oid_suffix_int(full_oid, _OID_TRUNK_ENCAP)
            if ifidx is not None:
                v = _int_from_raw(raw_val)
                if v is not None:
                    encap[ifidx] = _TRUNK_ENCAP_NAMES.get(v, "none")
    except Exception as exc:
        logger.debug("collect_trunk_info %s encap: %s", ip, exc)

    # Allowed VLANs bitstring (128 bajtów = 1024 bity = VLAN 1-1024)
    try:
        rows = snmp_walk(ip, _OID_TRUNK_VLANS_ENABLED, community, timeout=timeout, max_iter=256)
        for full_oid, raw_val, _ in rows:
            ifidx = _oid_suffix_int(full_oid, _OID_TRUNK_VLANS_ENABLED)
            if ifidx is not None and isinstance(raw_val, (bytes, bytearray)):
                vlans_bits[ifidx] = bytes(raw_val)
    except Exception as exc:
        logger.debug("collect_trunk_info %s vlans: %s", ip, exc)

    if not status:
        # Urządzenie nie obsługuje VTP MIB
        logger.debug("collect_trunk_info %s: no VTP MIB data", ip)
        return {}

    result: dict[int, dict] = {}
    for ifidx in status:
        is_trunk   = (status[ifidx] == _TRUNK_STATUS_TRUNKING)
        enc        = encap.get(ifidx)
        nat        = native.get(ifidx)
        bits       = vlans_bits.get(ifidx, b"")
        vlan_count = bin(int.from_bytes(bits, "big")).count("1") if bits else None

        result[ifidx] = {
            "port_mode":   "trunk" if is_trunk else "access",
            "native_vlan": nat if is_trunk else None,
            "trunk_encap": enc if is_trunk else None,
            "trunk_vlans": vlan_count if is_trunk else None,
        }

    logger.debug("collect_trunk_info %s: %d ports (%d trunk)",
                 ip, len(result), sum(1 for v in result.values() if v["port_mode"] == "trunk"))
    return result
