"""Netdoc SNMP Worker — szybki poller SNMP dla urzadzen ze ZNANA community (co 300s).

Odpowiedzialnosc:
  - Odpytuje sysName/sysDescr/sysLocation dla urzadzen z ustawiona snmp_community
  - Aktualizuje hostname, os_version, location jesli puste
  - Odswierza snmp_ok_at przy kazdym udanym pollu

NIE wykonuje autodiscovery community — to robi community-worker (run_community_worker.py).
Eksportuje metryki Prometheus na porcie 8002.
"""
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

from prometheus_client import Gauge, start_http_server

from netdoc.storage.database import SessionLocal, init_db
from netdoc.storage.models import Device, Credential, CredentialMethod, DeviceType, DeviceFieldHistory, InterfaceHistory, DeviceSensor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SNMP-W] %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)
logging.getLogger("asyncio").setLevel(logging.CRITICAL)  # pysnmp pending tasks noise

_DEFAULT_SNMP_INTERVAL = int(os.getenv("SNMP_INTERVAL", "300"))
_DEFAULT_SNMP_WORKERS  = int(os.getenv("SNMP_WORKERS", "32"))  # PERF-12: 10→32 (limit 1600 vs 500 urz.)
METRICS_PORT  = int(os.getenv("SNMP_METRICS_PORT", "8002"))

g_polled   = Gauge("netdoc_snmp_polled",    "Urzadzenia przeskanowane w ostatnim cyklu")
g_success  = Gauge("netdoc_snmp_success",   "Urzadzenia z dzialajacym SNMP")
g_failed   = Gauge("netdoc_snmp_failed",    "Urzadzenia bez odpowiedzi SNMP")
g_new_cred = Gauge("netdoc_snmp_new_creds", "Nowe credentiale odkryte w ostatnim cyklu")
g_duration = Gauge("netdoc_snmp_duration_s","Czas trwania ostatniego cyklu [s]")



# ---------------------------------------------------------------------------
# LLDP enrichment przez SNMP walk (lldpRemTable)
# ---------------------------------------------------------------------------
# OID prefix: 1.0.8802.1.1.2.1.4.1.1 (lldpRemEntry)
#  .4  lldpRemChassisIdSubtype
#  .5  lldpRemChassisId
#  .6  lldpRemPortIdSubtype
#  .7  lldpRemPortId
#  .8  lldpRemPortDesc
#  .9  lldpRemSysName
#  .10 lldpRemSysDesc
_LLDP_REM_TABLE = "1.0.8802.1.1.2.1.4.1.1"


def _enrich_lldp(ip: str, community: str, timeout: int = 2) -> list[dict]:
    """Odpytuje switche o tabele sasiadow LLDP (lldpRemTable).

    Zwraca liste slownikow z danymi sasiadow: ip, hostname, model, firmware.
    Urzadzenia bez LLDP zwracaja pusta liste.
    """
    from netdoc.collector.snmp_walk import snmp_walk
    from netdoc.collector.normalizer import normalize_mac

    rows: dict[str, dict] = {}  # klucz: (localPort, remIdx)

    try:
        for oid_str, raw_val, _tag in snmp_walk(
            ip, _LLDP_REM_TABLE, community=community, timeout=timeout, max_iter=300
        ):
            # OID format: 1.0.8802.1.1.2.1.4.1.1.<field>.<timeMark>.<localPort>.<remIdx>
            suffix = oid_str[len(_LLDP_REM_TABLE):].lstrip(".")
            parts = suffix.split(".")
            if len(parts) < 4:
                continue
            field_id   = int(parts[0])
            local_port = parts[2]
            rem_idx    = parts[3]
            key = (local_port, rem_idx)

            if isinstance(raw_val, (bytes, bytearray)):
                try:
                    val = raw_val.decode("utf-8", errors="replace").strip()
                except Exception:
                    val = raw_val.hex()
            else:
                val = str(raw_val).strip() if raw_val is not None else ""

            entry = rows.setdefault(key, {"local_port": local_port})

            if   field_id == 4:   # lldpRemChassisIdSubtype
                try:
                    sub = int.from_bytes(raw_val, "big") if isinstance(raw_val, (bytes, bytearray)) else int(raw_val)
                    entry["chassis_subtype"] = sub
                except (TypeError, ValueError):
                    pass
            elif field_id == 5:   # lldpRemChassisId
                # Subtype 4 = MAC address (6 binary bytes)
                # Subtype 5 = network address, subtype 7 = locally assigned (text string)
                if isinstance(raw_val, (bytes, bytearray)) and len(raw_val) == 6:
                    mac = normalize_mac("".join(f"{b:02x}" for b in raw_val))
                    if mac:
                        entry["mac"] = mac
                    else:
                        entry.setdefault("chassis_id", val)
                else:
                    entry.setdefault("chassis_id", val)
            elif field_id == 7:   # lldpRemPortId — moze byc MAC (subtype 3) lub ifName (subtype 5)
                if isinstance(raw_val, (bytes, bytearray)) and len(raw_val) == 6:
                    mac = normalize_mac("".join(f"{b:02x}" for b in raw_val))
                    if mac:
                        entry.setdefault("mac", mac)
                else:
                    entry["remote_port"] = val
            elif field_id == 8:   # lldpRemPortDesc
                entry.setdefault("remote_port", val)
            elif field_id == 9:   # lldpRemSysName
                entry["hostname"] = val
            elif field_id == 10:  # lldpRemSysDesc (sysDescr sasiada = firmware/model)
                entry["sys_desc"] = val

    except Exception as exc:
        logger.debug("LLDP walk %s: %s", ip, exc)
        return []

    return [v for v in rows.values() if v.get("hostname") or v.get("mac")]


def _save_lldp_neighbors(db, src_device_id: int, src_ip: str, neighbors: list[dict], proto: str = "LLDP") -> int:
    """Upsertuje sasiadow LLDP/CDP/EDP jako Device w bazie i tworzy TopologyLink.

    Zwraca liczbe zapisanych/zaktualizowanych sasiadi.
    """
    from netdoc.collector.discovery import upsert_device
    from netdoc.collector.normalizer import DeviceData, normalize_mac
    from netdoc.storage.models import TopologyLink, TopologyProtocol, Interface

    proto_enum = {
        "LLDP": TopologyProtocol.lldp,
        "CDP":  TopologyProtocol.cdp,
        "EDP":  TopologyProtocol.lldp,  # EDP (Extreme) — nie ma osobnego enum, traktuj jak LLDP
    }.get(proto, TopologyProtocol.lldp)

    saved = 0
    for n in neighbors:
        ip = n.get("chassis_id")  # moze byc IP jako chassis ID
        mac_raw = n.get("mac")
        hostname = n.get("hostname", "").strip()
        local_port_idx = n.get("local_port")    # ifIndex z CDP/LLDP (string)
        remote_port    = n.get("remote_port")

        # Znajdz lub stworz urzadzenie sasiada
        remote_device = None

        if ip and _is_ip(str(ip)):
            # Mamy IP — upsert przez IP
            os_ver = (n.get("sys_desc") or n.get("software") or "")[:120] or None
            vendor_hint = n.get("platform") or None
            data = DeviceData(
                ip         = str(ip),
                mac        = normalize_mac(mac_raw),
                hostname   = hostname or None,
                os_version = os_ver,
                vendor     = vendor_hint,
            )
            try:
                remote_device = upsert_device(db, data)
                db.commit()
                logger.info("%s neighbor: %-18s hostname=%-28s via %s port=%s",
                            proto, ip, hostname or "-", src_ip, local_port_idx or "?")
            except Exception as exc:
                logger.debug("LLDP upsert error %s: %s", ip, exc)
                db.rollback()
        else:
            # Brak IP — szukaj po MAC lub hostname w bazie
            mac_norm = normalize_mac(mac_raw) if mac_raw else None
            if mac_norm:
                remote_device = db.query(Device).filter(Device.mac == mac_norm).first()
            if remote_device is None and hostname:
                remote_device = db.query(Device).filter(Device.hostname == hostname).first()
            if remote_device is not None:
                # Uzupelnij dane jesli puste
                changed = False
                sys_desc = n.get("sys_desc", "")
                if sys_desc and not remote_device.os_version:
                    remote_device.os_version = sys_desc[:120]
                    changed = True
                if mac_norm and not remote_device.mac:
                    remote_device.mac = mac_norm
                    changed = True
                if changed:
                    try:
                        db.commit()
                    except Exception:
                        db.rollback()

        if remote_device is None:
            continue  # nie znaleziono sasiada — pominij

        # Rozwiaz lokalny port (ifIndex → Interface.id)
        src_iface_id = None
        if local_port_idx:
            try:
                src_iface = (
                    db.query(Interface)
                    .filter(Interface.device_id == src_device_id,
                            Interface.if_index == int(local_port_idx))
                    .first()
                )
                if src_iface:
                    src_iface_id = src_iface.id
            except (ValueError, TypeError):
                pass

        # Upsert TopologyLink — jeden link na pare (src, dst, src_port)
        existing_link = (
            db.query(TopologyLink)
            .filter(
                TopologyLink.src_device_id == src_device_id,
                TopologyLink.dst_device_id == remote_device.id,
            )
            .first()
        )
        try:
            if existing_link:
                existing_link.last_seen = datetime.utcnow()
                if src_iface_id and not existing_link.src_interface_id:
                    existing_link.src_interface_id = src_iface_id
            else:
                db.add(TopologyLink(
                    src_device_id    = src_device_id,
                    dst_device_id    = remote_device.id,
                    src_interface_id = src_iface_id,
                    protocol         = proto_enum,
                ))
                saved += 1
                logger.info("%s link: %s → %s (via port %s)",
                            proto, src_ip, remote_device.ip or remote_device.hostname,
                            local_port_idx or "?")
            db.commit()
        except Exception as exc:
            logger.debug("TopologyLink save error %s→%s: %s", src_device_id, remote_device.id, exc)
            db.rollback()

    return saved


def _is_ip(s: str) -> bool:
    """Prosta walidacja IPv4."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _is_infrastructure_ip(ip: str) -> bool:
    """Zwraca True dla zakresów które nie są urządzeniami sieciowymi użytkownika:
    - 172.16.0.0/12  — Docker bridge / overlay networks (172.16–172.31)
    - 100.64.0.0/10  — CGNAT / Tailscale / VPN tunnel IPs (100.64–100.127)
    - 127.0.0.0/8    — loopback
    - 169.254.0.0/16 — link-local
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return False
    if a == 127:
        return True  # loopback
    if a == 169 and b == 254:
        return True  # link-local
    if a == 172 and 16 <= b <= 31:
        return True  # Docker bridge 172.16–172.31
    if a == 100 and 64 <= b <= 127:
        return True  # CGNAT/Tailscale/VPN 100.64–100.127
    return False


# ---------------------------------------------------------------------------
# CDP enrichment — Cisco Discovery Protocol via SNMP (ciscocdpMIB)
# ---------------------------------------------------------------------------
# OID prefix: 1.3.6.1.4.1.9.9.23.1.2.1.1 (cdpCacheEntry)
# Index: .<field>.<ifIndex>.<devIndex>
#  .3  cdpCacheAddressType  (1=IPv4)
#  .4  cdpCacheAddress      (4 bytes IPv4)
#  .5  cdpCacheVersion      (software version string)
#  .6  cdpCacheDeviceId     (hostname)
#  .7  cdpCacheDevicePort   (remote port)
#  .8  cdpCachePlatform     (model/platform)
_CDP_CACHE_TABLE = "1.3.6.1.4.1.9.9.23.1.2.1.1"


def _enrich_cdp(ip: str, community: str, timeout: int = 2) -> list[dict]:
    """Odpytuje urzadzenie Cisco o tablice sasiadow CDP (cdpCacheTable).

    Zwraca liste slownikow z polami ip/hostname/platform/software/local_port/remote_port.
    Urzadzenia bez CDP lub nie-Cisco zwracaja pusta liste.
    """
    from netdoc.collector.snmp_walk import snmp_walk

    rows: dict[tuple, dict] = {}  # klucz: (ifIndex, devIndex)

    try:
        for oid_str, raw_val, _tag in snmp_walk(
            ip, _CDP_CACHE_TABLE, community=community, timeout=timeout, max_iter=500
        ):
            suffix = oid_str[len(_CDP_CACHE_TABLE):].lstrip(".")
            parts = suffix.split(".")
            if len(parts) < 3:
                continue
            field_id  = int(parts[0])
            if_idx    = parts[1]
            dev_idx   = parts[2]
            key = (if_idx, dev_idx)

            if isinstance(raw_val, (bytes, bytearray)):
                val_str = raw_val.decode("utf-8", errors="replace").strip()
            else:
                val_str = str(raw_val).strip() if raw_val is not None else ""

            entry = rows.setdefault(key, {"local_port": if_idx})

            if field_id == 3:   # cdpCacheAddressType
                entry["addr_type"] = int(raw_val) if isinstance(raw_val, int) else (
                    int.from_bytes(raw_val, "big") if isinstance(raw_val, (bytes, bytearray)) else 1
                )
            elif field_id == 4:  # cdpCacheAddress
                if isinstance(raw_val, (bytes, bytearray)) and len(raw_val) == 4:
                    entry["ip"] = ".".join(str(b) for b in raw_val)
                elif _is_ip(val_str):
                    entry["ip"] = val_str
            elif field_id == 5:  # cdpCacheVersion
                entry["software"] = val_str[:120]
            elif field_id == 6:  # cdpCacheDeviceId
                # Cisco często dodaje domenę do hostname: "switch01.domain.com"
                entry["hostname"] = val_str.split(".")[0] if "." in val_str else val_str
            elif field_id == 7:  # cdpCacheDevicePort
                entry["remote_port"] = val_str
            elif field_id == 8:  # cdpCachePlatform
                entry["platform"] = val_str

    except Exception as exc:
        logger.debug("CDP walk %s: %s", ip, exc)
        return []

    return [v for v in rows.values() if v.get("hostname") or v.get("ip")]


# ---------------------------------------------------------------------------
# EDP enrichment — Extreme Discovery Protocol via SNMP (extremeware-mib)
# ---------------------------------------------------------------------------
# OID prefix: 1.3.6.1.4.1.1991.1.14.7.1.1 (extremeEdpNeighborEntry)
#  .2  extremeEdpNeighborIpAddress
#  .3  extremeEdpNeighborSysName
#  .4  extremeEdpNeighborSoftwareVersion
#  .5  extremeEdpNeighborPortIfIndex
_EDP_NEIGHBOR_TABLE = "1.3.6.1.4.1.1991.1.14.7.1.1"


def _enrich_edp(ip: str, community: str, timeout: int = 2) -> list[dict]:
    """Odpytuje urzadzenie Extreme Networks o tablice sasiadow EDP.

    Zwraca liste slownikow z polami ip/hostname/software/local_port.
    Nie-Extreme urzadzenia zwracaja pusta liste.
    """
    from netdoc.collector.snmp_walk import snmp_walk

    rows: dict[str, dict] = {}

    try:
        for oid_str, raw_val, _tag in snmp_walk(
            ip, _EDP_NEIGHBOR_TABLE, community=community, timeout=timeout, max_iter=200
        ):
            suffix = oid_str[len(_EDP_NEIGHBOR_TABLE):].lstrip(".")
            parts = suffix.split(".")
            if len(parts) < 2:
                continue
            field_id = int(parts[0])
            idx      = parts[1]

            if isinstance(raw_val, (bytes, bytearray)):
                val_str = raw_val.decode("utf-8", errors="replace").strip()
            else:
                val_str = str(raw_val).strip() if raw_val is not None else ""

            entry = rows.setdefault(idx, {})

            if field_id == 2:  # extremeEdpNeighborIpAddress
                if isinstance(raw_val, (bytes, bytearray)) and len(raw_val) == 4:
                    entry["ip"] = ".".join(str(b) for b in raw_val)
                elif _is_ip(val_str):
                    entry["ip"] = val_str
            elif field_id == 3:  # extremeEdpNeighborSysName
                entry["hostname"] = val_str
            elif field_id == 4:  # extremeEdpNeighborSoftwareVersion
                entry["software"] = val_str[:120]
            elif field_id == 5:  # extremeEdpNeighborPortIfIndex
                entry["local_port"] = val_str

    except Exception as exc:
        logger.debug("EDP walk %s: %s", ip, exc)
        return []

    return [v for v in rows.values() if v.get("hostname") or v.get("ip")]


# ---------------------------------------------------------------------------
# sysUpTime + Entity MIB enrichment — dodawane w trakcie normalnego pollu
# ---------------------------------------------------------------------------
OID_SYSUPTIME        = "1.3.6.1.2.1.1.3.0"
# entPhysicalEntry (chassis = index 1):
OID_ENT_DESCR        = "1.3.6.1.2.1.47.1.1.1.1.2.1"   # entPhysicalDescr
OID_ENT_MODEL        = "1.3.6.1.2.1.47.1.1.1.1.13.1"  # entPhysicalModelName
OID_ENT_FIRMWARE     = "1.3.6.1.2.1.47.1.1.1.1.9.1"   # entPhysicalFirmwareRev
OID_ENT_SOFTWARE     = "1.3.6.1.2.1.47.1.1.1.1.10.1"  # entPhysicalSoftwareRev
OID_ENT_SERIAL       = "1.3.6.1.2.1.47.1.1.1.1.11.1"  # entPhysicalSerialNum
OID_ENT_HW_REV       = "1.3.6.1.2.1.47.1.1.1.1.8.1"   # entPhysicalHardwareRev
# UCD-SNMP MIB — hardware facts (nie runtime)
OID_MEM_TOTAL_REAL   = "1.3.6.1.4.1.2021.4.5.0"        # memTotalReal — całkowita RAM w KB


def _timeticks_to_str(ticks) -> str:
    """Zamienia TimeTicks (setne sekundy) na czytelny string, np. '3d 14h 22m'."""
    try:
        total_s = int(ticks) // 100
    except (TypeError, ValueError):
        return str(ticks)
    days, rem = divmod(total_s, 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    if days:
        return f"{days}d {hours}h {mins}m"
    if hours:
        return f"{hours}h {mins}m"
    return f"{mins}m"


def _update_asset_notes_tag(notes: str | None, tag: str, value: str) -> str:
    """Zastepuje sekcje [tag ...] w asset_notes lub dodaje na koncu."""
    import re
    pattern = rf"\[{re.escape(tag)}[^\]]*\]"
    new_tag = f"[{tag} {value}]"
    if notes and re.search(pattern, notes):
        return re.sub(pattern, new_tag, notes)
    return (notes + "\n" + new_tag) if notes else new_tag


_UBNT_AP_PFX     = ("u6-", "u7-", "u5-", "u2-", "uap", "unifi ap")
_UBNT_SWITCH_PFX = ("us-", "usw", "us8", "us16", "us24", "us48", "unifi switch")
_UBNT_ROUTER_PFX = ("udm", "usg", "udr", "unifi dream", "unifi gateway")
_NAS_OS_HINTS    = ("diskstation", "synology", "dsm ", "qts ", "qnap",
                    "readynas", "freenas", "truenas", "nas4free", "openmediavault")

# Cisco — słowa kluczowe w modelu/sysDescr identyfikujące switch vs router
_CISCO_SWITCH_KEYWORDS = (
    "catalyst", "ws-c", "c9300", "c9200", "c9100", "c9500", "c9600",
    "c3750", "c3850", "c3560", "c2960", "c2950", "me-3", "ie-", "sg-",
    "nexus", "nx-os",
)
_CISCO_ROUTER_KEYWORDS = (
    "isr", "asr", "csr", "c8000", "c1000", "c1100", "c1900", "c2900",
    "c3900", "c4000", "c7200", "c7600", "ncs", "crs",
)


def _reclassify_from_snmp(device) -> None:
    """Re-klasyfikuje urządzenie na podstawie danych SNMP (hostname, vendor, os_version).

    Koryguje błędne typy nadane przez discovery gdy SNMP dostarcza dokładniejszych danych.
    Cisco: switch/router/firewall/ap po profilu SNMP + modelu/sysDescr.
    Ubiquiti: AP/switch/router po hostname. NAS: Synology/QNAP po vendor lub os_version.
    Zapis do device.device_type jeśli się zmieni.
    """
    from netdoc.storage.models import DeviceType as DT
    hn  = (device.hostname  or "").lower()
    vn  = (device.vendor    or "").lower()
    osv = (device.os_version or "").lower()
    mdl = (device.model     or "").lower()

    # NAS — vendor lub sysDescr wskazuje jednoznacznie
    if any(k in vn for k in ("synology", "qnap", "western digital", "buffalo")):
        if device.device_type != DT.nas:
            device.device_type = DT.nas
        return
    if any(k in osv for k in _NAS_OS_HINTS):
        if device.device_type != DT.nas:
            device.device_type = DT.nas
        return

    # Cisco — reklasyfikacja na podstawie profilu SNMP i słów kluczowych w modelu/sysDescr
    # Discovery zawsze zwraca router dla "cisco" w OS fingerprint — korygujemy po SNMP.
    if any(k in vn for k in ("cisco",)) or any(k in osv for k in ("cisco ios", "cisco nx", "cisco asa", "cisco adaptive")):
        _cisco_hint = osv + " " + mdl
        try:
            from netdoc.collector.snmp_profiles import detect_vendor_profile
            _profile = detect_vendor_profile(
                getattr(device, "snmp_sys_object_id", None), osv
            )
        except Exception:
            _profile = "generic"

        # Firewall — ASA ma priorytet
        if _profile == "cisco_asa" or "adaptive security" in _cisco_hint or " asa" in _cisco_hint:
            new_type = DT.firewall
        # WLC / Access Point controller
        elif _profile == "cisco_wlc" or "wireless lan controller" in _cisco_hint or "aireos" in _cisco_hint:
            new_type = DT.ap
        # IOS-XR = backbone router (brak L2)
        elif _profile == "cisco_ios_xr" or "ios-xr" in _cisco_hint or "ios xr" in _cisco_hint:
            new_type = DT.router
        # Switch — po słowach kluczowych w modelu/sysDescr lub profilu z L2 (FDB/VLAN)
        elif any(k in _cisco_hint for k in _CISCO_SWITCH_KEYWORDS):
            new_type = DT.switch
        # Router — po słowach kluczowych
        elif any(k in _cisco_hint for k in _CISCO_ROUTER_KEYWORDS):
            new_type = DT.router
        # Fallback: profil z FDB → switch; pozostałe → router
        elif _profile in ("cisco_ios", "cisco_ios_xe", "cisco_nxos"):
            new_type = DT.switch
        else:
            return  # nie zmieniaj — za mało danych

        if device.device_type != new_type:
            logger.info("Reclassify Cisco %s: %s → %s (profile=%s model=%r)",
                        device.ip,
                        device.device_type.value if device.device_type else "?",
                        new_type.value, _profile, device.model)
            device.device_type = new_type
        return

    # Ubiquiti — tylko gdy vendor = ubiquiti (nie nadpisuj innych)
    if "ubiquiti" not in vn and "ubnt" not in vn:
        return
    if any(hn.startswith(p) for p in _UBNT_ROUTER_PFX):
        new_type = DT.router
    elif any(hn.startswith(p) for p in _UBNT_SWITCH_PFX):
        new_type = DT.switch
    elif any(hn.startswith(p) for p in _UBNT_AP_PFX):
        new_type = DT.ap
    else:
        return  # nieznany Ubiquiti — nie zmieniaj
    if device.device_type != new_type:
        logger.info("Reclassify %s: %s → %s (snmp hostname %r)",
                    device.ip, device.device_type.value if device.device_type else "?",
                    new_type.value, device.hostname)
        device.device_type = new_type


def _poll_device(device_id: int, ip: str, community: str,
                 hostname: str | None, os_version: str | None, location: str | None,
                 snmp_timeout: int = 2) -> dict:
    """Odpytuje urzadzenie ze ZNANA community — bez autodiscovery.
    PERF-03: dane device przekazane bezposrednio (nie re-query per watek).
    Otwiera DB tylko do zapisu wyniku, nie do odczytu device.
    """
    from netdoc.collector.drivers.snmp import _snmp_get, OID_SYSNAME, OID_SYSDESCR, OID_SYSLOCATION, OID_SYSCONTACT

    result = {"device_id": device_id, "success": False, "community": None}
    if not community:
        return result  # scan_once() filtruje community=None, ale na wszelki wypadek
    try:
        sysname = _snmp_get(ip, community, OID_SYSNAME, timeout=snmp_timeout)
    except Exception as exc:
        logger.debug("SNMP get error %s: %s", ip, exc)
        return result  # wyjątek sieci — nie dotykamy DB, community pozostaje nienaruszone

    db = SessionLocal()
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return result

        if not sysname:
            # Nie czysc community przy jednorazowym bladzie — urzadzenie moglo byc chwilowo zajete.
            # Czysc dopiero gdy nie odpowiadalo przez >30 minut (zabezpieczenie przed flappingiem).
            stale_limit = datetime.utcnow() - timedelta(minutes=30)
            if device.snmp_ok_at and device.snmp_ok_at > stale_limit:
                logger.debug("Community '****' no response for %s — skipping (ok_at recent)", ip)
                return result
            logger.info("Community '****' no longer responds for %s — clearing", ip)
            device.snmp_community = None
            device.snmp_ok_at     = None
            db.commit()
            return result

        result["success"]   = True
        result["community"] = community

        sysdescr  = _snmp_get(ip, community, OID_SYSDESCR,    timeout=snmp_timeout)
        sysloc    = _snmp_get(ip, community, OID_SYSLOCATION,  timeout=snmp_timeout)
        uptime    = _snmp_get(ip, community, OID_SYSUPTIME,    timeout=snmp_timeout)
        contact   = _snmp_get(ip, community, OID_SYSCONTACT,   timeout=snmp_timeout)
        sysobject = _snmp_get(ip, community, "1.3.6.1.2.1.1.2.0", timeout=snmp_timeout)  # sysObjectID

        # Change detection + update: SNMP is authoritative over nmap fingerprinting.
        # Always update fields with SNMP values so nmap guesses don't persist.
        # History logged only when the value actually changes (old != new).
        _new_vals = {
            "hostname":    sysname,
            "os_version":  sysdescr[:120] if sysdescr else None,
            "location":    sysloc,
            "sys_contact": contact.strip()[:255] if contact and contact.strip() else None,
        }
        for _field, _new in _new_vals.items():
            if not _new:
                continue
            _old = getattr(device, _field)
            if _old is not None and _old != _new:
                # Hostname: pomiń zapis historii gdy różnica to tylko wielkość liter
                # (NBNS zwraca UPPERCASE, SNMP sysName zwraca prawidłowy case)
                if _field == "hostname" and (_old or "").lower() == (_new or "").lower():
                    pass  # tylko case — nie generuj historii, ale zaktualizuj
                else:
                    db.add(DeviceFieldHistory(
                        device_id=device_id,
                        field_name=_field,
                        old_value=str(_old),
                        new_value=str(_new),
                        source="snmp",
                    ))
                    logger.info("Field change %s [%s]: %r -> %r", ip, _field, _old, _new)
            # Always write SNMP value (overrides nmap OS fingerprint)
            setattr(device, _field, _new)

        # sysObjectID — zapisuj do vendor detection + wyznacz profil vendora
        if sysobject:
            oid_str = str(sysobject).strip().lstrip(".")
            if oid_str and oid_str != device.snmp_sys_object_id:
                device.snmp_sys_object_id = oid_str[:100]
                # Aktualizuj vendor jesli nieznany lub auto-wykryty
                try:
                    from netdoc.collector.snmp_profiles import detect_vendor_profile, VENDOR_PROFILES
                    profile_name = detect_vendor_profile(oid_str, sysdescr or "")
                    profile = VENDOR_PROFILES.get(profile_name, {})
                    display = profile.get("display_name")
                    if display and (not device.vendor or device.vendor == "Unknown"):
                        device.vendor = display
                except Exception:
                    pass

        # sysUpTime — zapisuj do dedykowanej kolumny; wyczyść stary tag z asset_notes
        if uptime is not None:
            device.snmp_uptime = _timeticks_to_str(uptime)
            if device.asset_notes:
                import re as _re
                device.asset_notes = _re.sub(r'\[uptime [^\]]*\]\n?', '', device.asset_notes).strip() or None

        # Entity MIB — model, firmware, serial, hardware rev (chassis index 1)
        # Pobieramy zawsze — nadpisujemy tylko gdy nowe dane są niepuste i różne
        try:
            ent_serial   = _snmp_get(ip, community, OID_ENT_SERIAL,   timeout=snmp_timeout)
            ent_model    = _snmp_get(ip, community, OID_ENT_MODEL,     timeout=snmp_timeout)
            ent_firmware = _snmp_get(ip, community, OID_ENT_FIRMWARE,  timeout=snmp_timeout)
            ent_software = _snmp_get(ip, community, OID_ENT_SOFTWARE,  timeout=snmp_timeout)
            ent_hw_rev   = _snmp_get(ip, community, OID_ENT_HW_REV,   timeout=snmp_timeout)

            def _clean(v) -> str | None:
                s = str(v).strip() if v is not None else ""
                return s[:255] if s and s not in ("0", "..", "Not Specified", "N/A", "") else None

            # Serial
            s = _clean(ent_serial)
            if s and s != device.serial_number:
                if device.serial_number:
                    logger.info("Serial update %-18s: %r → %r", ip, device.serial_number, s)
                device.serial_number = s

            # Model — sklejamy model + hw_rev jeśli oba są
            raw_model = _clean(ent_model)
            hw_rev    = _clean(ent_hw_rev)
            new_model = raw_model
            if raw_model and hw_rev and hw_rev not in raw_model:
                new_model = f"{raw_model} (hw {hw_rev})"
            if new_model and new_model != device.model:
                if device.model:
                    db.add(DeviceFieldHistory(device_id=device_id, field_name="model",
                                             old_value=device.model, new_value=new_model, source="snmp"))
                device.model = new_model
                logger.info("Model    %-18s: %s", ip, new_model)

            # Firmware/software — zapisujemy do os_version jeśli bardziej szczegółowy niż sysDescr
            # Preferujemy entPhysicalSoftwareRev > entPhysicalFirmwareRev
            fw = _clean(ent_software) or _clean(ent_firmware)
            if fw:
                current = device.os_version or ""
                if fw not in current:
                    new_os = f"{current} | fw:{fw}" if current else fw
                    new_os = new_os[:120]
                    if new_os != device.os_version:
                        db.add(DeviceFieldHistory(device_id=device_id, field_name="os_version",
                                                 old_value=device.os_version, new_value=new_os, source="snmp"))
                        device.os_version = new_os
                        logger.info("Firmware %-18s: %s", ip, fw)
        except Exception:
            pass  # brak Entity MIB — normalne dla prostych urzadzen

        # UCD-SNMP — RAM (hardware fact, nie runtime)
        try:
            mem_raw = _snmp_get(ip, community, OID_MEM_TOTAL_REAL, timeout=snmp_timeout)
            if mem_raw is not None:
                mem_kb = int(mem_raw)
                if mem_kb > 0:
                    device.ram_total_mb = mem_kb // 1024
        except Exception:
            pass  # brak UCD-SNMP MIB — normalne dla switchów, drukarek

        device.snmp_ok_at = datetime.utcnow()

        # Re-klasyfikacja gdy SNMP nadpisał hostname i typ może być błędny
        # Dotyczy głównie Ubiquiti: AP vs Switch vs Router po hostname
        _reclassify_from_snmp(device)

        # Zaktualizuj last_success_at na credentialu jesli istnieje
        existing = (
            db.query(Credential)
            .filter(Credential.device_id == device_id, Credential.method == CredentialMethod.snmp)
            .first()
        ) or (
            db.query(Credential)
            .filter(Credential.device_id.is_(None), Credential.method == CredentialMethod.snmp,
                    Credential.username == community)
            .first()
        )
        if existing:
            existing.last_success_at = datetime.utcnow()
            existing.success_count   = (existing.success_count or 0) + 1

        db.commit()  # jeden atomowy commit: device + credential razem

    except Exception as exc:
        logger.warning("SNMP poll error device_id=%s: %s", device_id, exc)
        db.rollback()
    finally:
        db.close()
    return result



# ---------------------------------------------------------------------------
# ARP table walk — odkrywa urzadzenia w innych VLAN-ach przez routery/L3 switche
# ---------------------------------------------------------------------------
# OID prefix: 1.3.6.1.2.1.3.1.1 (ipNetToMediaEntry, RFC 1213)
# Index: .<field>.<ifIndex>.<a>.<b>.<c>.<d>  gdzie a.b.c.d = IP
#  .2  ipNetToMediaPhysAddress  (MAC — 6 bytes)
#  .3  ipNetToMediaNetAddress   (IP — w OID suffix)
#  .4  ipNetToMediaType         (1=other, 2=invalid, 3=dynamic, 4=static)
_ARP_TABLE_OID = "1.3.6.1.2.1.3.1.1"


def _enrich_arp(ip: str, community: str, timeout: int = 2) -> list[dict]:
    """Czyta ARP table urzadzenia L3 (router / L3 switch) przez SNMP walk.

    Zwraca liste slownikow {ip, mac, arp_type} dla wpisow dynamic/static.
    Urzadzenia bez routingu zwracaja pusta liste.
    """
    from netdoc.collector.snmp_walk import snmp_walk
    from netdoc.collector.normalizer import normalize_mac

    rows: dict[str, dict] = {}  # klucz: neighbor_ip

    try:
        for oid_str, raw_val, _tag in snmp_walk(
            ip, _ARP_TABLE_OID, community=community, timeout=timeout, max_iter=2000
        ):
            suffix = oid_str[len(_ARP_TABLE_OID):].lstrip(".")
            parts = suffix.split(".")
            # .<field>.<ifIndex>.<a>.<b>.<c>.<d>
            if len(parts) < 6:
                continue
            field_id = int(parts[0])
            # IP pochodzi z ostatnich 4 oktetow OID (bez ifIndex)
            neighbor_ip = ".".join(parts[-4:])
            if not _is_ip(neighbor_ip):
                continue

            entry = rows.setdefault(neighbor_ip, {"ip": neighbor_ip})

            if field_id == 2:  # ipNetToMediaPhysAddress
                if isinstance(raw_val, (bytes, bytearray)) and len(raw_val) == 6:
                    mac = normalize_mac("".join(f"{b:02x}" for b in raw_val))
                    if mac:
                        entry["mac"] = mac
            elif field_id == 4:  # ipNetToMediaType: 2=invalid
                try:
                    arp_type = int(raw_val)
                    entry["arp_type"] = arp_type
                except (TypeError, ValueError):
                    pass

    except Exception as exc:
        logger.debug("ARP walk %s: %s", ip, exc)
        return []

    # Odfiltruj wpisy invalid (type=2) i multicast/broadcast MAC
    # oraz zakresy infrastrukturalne: Docker bridge (172.16-31.x), CGNAT/VPN (100.64-127.x), loopback
    result = []
    for v in rows.values():
        if v.get("arp_type") == 2:
            continue  # invalid entry
        mac = v.get("mac", "").upper()
        if mac and (mac.startswith("FF:FF") or mac.startswith("01:")):
            continue  # broadcast/multicast
        if not v.get("mac"):
            continue  # potrzebujemy MAC żeby nie śmiecić w DB
        # Skip Docker/overlay/CGNAT/VPN ranges
        ip_str = v.get("ip", "")
        if _is_infrastructure_ip(ip_str):
            continue
        result.append(v)
    return result


# ---------------------------------------------------------------------------
# Interface walk — zbiera ifDescr, ifOperStatus, ifAdminStatus, ifSpeed z ifTable
# oraz ifAlias i ifHighSpeed z ifXTable, ifPhysAddress (MAC), ifMauType (duplex)
# ---------------------------------------------------------------------------
_IF_TABLE_OID     = "1.3.6.1.2.1.2.2.1"    # ifEntry (IF-MIB)
_IF_DESCR_ID      = 2    # ifDescr
_IF_PHYSADDR_ID   = 6    # ifPhysAddress (MAC — 6 bytes)
_IF_ADMINSTATUS_ID= 7    # ifAdminStatus: 1=up, 2=down, 3=testing
_IF_OPERSTATUS_ID = 8    # ifOperStatus:  1=up, 2=down, 3=testing, ...
_IF_SPEED_ID      = 5    # ifSpeed (bps, max 4Gbps — powyżej trzeba ifHighSpeed)
_IFX_TABLE_OID    = "1.3.6.1.2.1.31.1.1.1" # ifXEntry (IF-MIB extensions)
_IFX_HIGHSPEED_ID = 15   # ifHighSpeed (Mbps)
_IFX_ALIAS_ID     = 18   # ifAlias (human description, np. "Uplink serwer")
# dot3 MIB — duplex status
_DOT3_STATS_OID   = "1.3.6.1.2.1.10.7.2.1" # dot3StatsEntry
_DOT3_DUPLEX_ID   = 19   # dot3StatsDuplexStatus: 1=unknown, 2=half, 3=full


def _decode_str(raw_val) -> str:
    if isinstance(raw_val, (bytes, bytearray)):
        return raw_val.decode("utf-8", errors="replace").strip()
    return str(raw_val).strip()


def _enrich_interfaces(ip: str, community: str, timeout: int = 2) -> list[dict]:
    """Czyta ifTable + ifXTable przez SNMP walk.

    Zwraca listę dict z kluczami:
      if_index, name, alias, admin_status, oper_status, speed_mbps
    Ignoruje loopback i interfejsy wirtualne (lo, sit0, ip6tnl0...).
    """
    from netdoc.collector.snmp_walk import snmp_walk

    _SKIP_NAMES = {"lo", "loopback", "sit0", "ip6tnl0", "ip6_vti0", "ip_vti0",
                   "erspan0", "ifb0", "ifb1", "ovs-system"}

    ifaces: dict[str, dict] = {}  # klucz: ifIndex (str)

    def _walk_table(base_oid: str) -> None:
        try:
            for oid_str, raw_val, _tag in snmp_walk(
                ip, base_oid, community=community, timeout=timeout, max_iter=2000
            ):
                suffix = oid_str[len(base_oid):].lstrip(".")
                parts = suffix.split(".", 1)
                if len(parts) < 2:
                    continue
                try:
                    field_id = int(parts[0])
                    if_index = parts[1]
                except ValueError:
                    continue
                entry = ifaces.setdefault(if_index, {"if_index": if_index})

                if base_oid == _IF_TABLE_OID:
                    if field_id == _IF_DESCR_ID:
                        entry["name"] = _decode_str(raw_val)
                    elif field_id == _IF_PHYSADDR_ID:
                        if isinstance(raw_val, (bytes, bytearray)) and len(raw_val) == 6:
                            entry["mac"] = ":".join(f"{b:02x}" for b in raw_val)
                    elif field_id == _IF_ADMINSTATUS_ID:
                        try:
                            v = int.from_bytes(raw_val, "big") if isinstance(raw_val, (bytes, bytearray)) else int(raw_val)
                            entry["admin_status"] = v == 1
                        except (TypeError, ValueError):
                            pass
                    elif field_id == _IF_OPERSTATUS_ID:
                        try:
                            v = int.from_bytes(raw_val, "big") if isinstance(raw_val, (bytes, bytearray)) else int(raw_val)
                            entry["oper_status"] = v == 1
                        except (TypeError, ValueError):
                            pass
                    elif field_id == _IF_SPEED_ID:
                        try:
                            v = int.from_bytes(raw_val, "big") if isinstance(raw_val, (bytes, bytearray)) else int(raw_val)
                            # ifSpeed w bps — konwertuj do Mbps (0 = nieznane, max 4Gbps)
                            entry["speed_mbps_low"] = v // 1_000_000 if v else 0
                        except (TypeError, ValueError):
                            pass
                elif base_oid == _IFX_TABLE_OID:
                    if field_id == _IFX_HIGHSPEED_ID:
                        try:
                            v = int.from_bytes(raw_val, "big") if isinstance(raw_val, (bytes, bytearray)) else int(raw_val)
                            entry["speed_mbps"] = v
                        except (TypeError, ValueError):
                            pass
                    elif field_id == _IFX_ALIAS_ID:
                        alias = _decode_str(raw_val)
                        if alias:
                            entry["alias"] = alias
                else:  # dot3StatsEntry
                    if field_id == _DOT3_DUPLEX_ID:
                        try:
                            v = int.from_bytes(raw_val, "big") if isinstance(raw_val, (bytes, bytearray)) else int(raw_val)
                            entry["duplex"] = {2: "half", 3: "full"}.get(v)
                        except (TypeError, ValueError):
                            pass
        except Exception as exc:
            logger.debug("IF walk %s %s: %s", ip, base_oid, exc)

    _walk_table(_IF_TABLE_OID)
    _walk_table(_IFX_TABLE_OID)
    _walk_table(_DOT3_STATS_OID)

    # IP per interface — ipAddrTable (RFC 1213)
    # OID: 1.3.6.1.2.1.4.20.1.2.<ip_addr> → ifIndex
    _IP_ADDR_IFINDEX = "1.3.6.1.2.1.4.20.1.2"
    ifindex_to_ip: dict[str, str] = {}
    try:
        for oid_str, raw_val, _tag in snmp_walk(
            ip, _IP_ADDR_IFINDEX, community=community, timeout=timeout, max_iter=200
        ):
            # suffix = ostatni element = IP adres (w OID: 192.168.5.1 → .192.168.5.1)
            suffix = oid_str[len(_IP_ADDR_IFINDEX):].lstrip(".")
            ip_addr = suffix  # np. "192.168.5.1"
            try:
                if_idx_val = int.from_bytes(raw_val, "big") if isinstance(raw_val, (bytes, bytearray)) else int(raw_val)
                if if_idx_val > 0:
                    ifindex_to_ip[str(if_idx_val)] = ip_addr
            except (TypeError, ValueError):
                pass
    except Exception as exc:
        logger.debug("IP addr walk %s: %s", ip, exc)

    result = []
    for v in ifaces.values():
        name = v.get("name", "")
        if not name or name.lower() in _SKIP_NAMES:
            continue
        spd = v.get("speed_mbps") or v.get("speed_mbps_low") or None
        if spd == 0:
            spd = None
        if_idx_str = v["if_index"]
        result.append({
            "if_index":     int(if_idx_str) if if_idx_str.isdigit() else None,
            "name":         name,
            "alias":        v.get("alias"),
            "mac":          v.get("mac"),
            "ip":           ifindex_to_ip.get(if_idx_str),
            "admin_status": v.get("admin_status"),
            "oper_status":  v.get("oper_status"),
            "speed_mbps":   spd,
            "duplex":       v.get("duplex"),
        })
    return result


def _save_interface_history(db, device_id: int, ifaces: list[dict]) -> int:
    """Porównuje stan interfejsów z ostatnim wpisem w historii i zapisuje zmiany.

    Model InterfaceHistory:
      event_type: "discovered" | "up" | "down" | "speed_change"
      old_speed:  prędkość w Mbps (Integer 32-bit), None przy "discovered"/"up"/"down"
      new_speed:  prędkość w Mbps (Integer 32-bit), None przy "up"/"down"
    Zwraca liczbę zapisanych wpisów.
    """
    saved = 0
    for iface in ifaces:
        name    = iface["name"]
        new_st  = iface.get("oper_status")   # 1=up, 2=down, inne=unknown
        new_spd = iface.get("speed_mbps")

        # Ostatni wpis per interfejs = aktualny znany stan
        last = (
            db.query(InterfaceHistory)
            .filter(InterfaceHistory.device_id == device_id,
                    InterfaceHistory.interface_name == name)
            .order_by(InterfaceHistory.changed_at.desc())
            .first()
        )

        if last is None:
            # Pierwsze wykrycie — zapisz stan bazowy
            db.add(InterfaceHistory(
                device_id=device_id, interface_name=name,
                event_type="discovered", old_speed=None, new_speed=new_spd,
            ))
            saved += 1
            continue

        # Odczytaj ostatni znany stan
        last_status = "up" if last.event_type == "up" else (
                      "down" if last.event_type == "down" else None)
        last_spd    = last.new_speed  # new_speed = prędkość przy speed_change/discovered

        # Sprawdź zmianę statusu operacyjnego
        curr_status = "up" if new_st == 1 else ("down" if new_st == 2 else None)
        if curr_status and curr_status != last_status and last_status is not None:
            db.add(InterfaceHistory(
                device_id=device_id, interface_name=name,
                event_type=curr_status, old_speed=None, new_speed=None,
            ))
            saved += 1

        # Sprawdź zmianę prędkości
        if new_spd is not None and last_spd is not None and new_spd != last_spd:
            db.add(InterfaceHistory(
                device_id=device_id, interface_name=name,
                event_type="speed_change", old_speed=last_spd, new_speed=new_spd,
            ))
            saved += 1

    if saved:
        try:
            db.commit()
        except Exception as exc:
            logger.warning("interface_history commit error device_id=%s: %s", device_id, exc)
            db.rollback()
    return saved


def _save_arp_devices(db, src_ip: str, entries: list[dict]) -> int:
    """Upsertuje urzadzenia z ARP table do DB. Zwraca liczbe nowych/zaktualizowanych."""
    from netdoc.collector.discovery import upsert_device
    from netdoc.collector.normalizer import DeviceData

    saved = 0
    for e in entries:
        neighbor_ip = e["ip"]
        if neighbor_ip == src_ip:
            continue
        data = DeviceData(ip=neighbor_ip, mac=e.get("mac"))
        try:
            upsert_device(db, data)
            saved += 1
        except Exception as exc:
            logger.debug("ARP save error %s: %s", neighbor_ip, exc)
            db.rollback()
    if saved:
        try:
            db.commit()
        except Exception as exc:
            logger.debug("ARP bulk commit error: %s", exc)
            db.rollback()
    return saved


def _save_sensors(db, device_id: int, sensors: list[dict]) -> int:
    """Upsertuje sensory do device_sensors (ON CONFLICT DO UPDATE).

    Każdy sensor to dict z kluczami: name, value, unit, raw_str, source.
    Zwraca liczbę zapisanych/zaktualizowanych sensorów.
    """
    if not sensors:
        return 0
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from netdoc.storage.database import engine

    rows = [
        {
            "device_id":   device_id,
            "sensor_name": s["name"],
            "value":       s.get("value"),
            "unit":        s.get("unit"),
            "raw_str":     s.get("raw_str"),
            "source":      s.get("source"),
            "polled_at":   datetime.utcnow(),
        }
        for s in sensors if s.get("name")
    ]
    if not rows:
        return 0
    try:
        # Upsert nowych wartości
        stmt = pg_insert(DeviceSensor.__table__).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_sensor_dev_name",
            set_={
                "value":     stmt.excluded.value,
                "unit":      stmt.excluded.unit,
                "raw_str":   stmt.excluded.raw_str,
                "source":    stmt.excluded.source,
                "polled_at": stmt.excluded.polled_at,
            },
        )
        db.execute(stmt)
        # Usuń sensory których już nie zwraca poll (stare/nieobecne) — zapobiega zaleganiu śmieci
        current_names = [r["sensor_name"] for r in rows]
        db.query(DeviceSensor).filter(
            DeviceSensor.device_id == device_id,
            DeviceSensor.sensor_name.notin_(current_names),
        ).delete(synchronize_session=False)
        db.commit()
        return len(rows)
    except Exception as exc:
        logger.warning("sensor save error device_id=%s: %s", device_id, exc)
        db.rollback()
        return 0


def _save_interfaces(db, device_id: int, ifaces: list[dict]) -> int:
    """Upsertuje bieżący stan interfejsów do tabeli interfaces (ON CONFLICT DO UPDATE).

    Klucz unikatowości: (device_id, if_index).
    Interfejsy nieobecne w nowym pollu są usuwane (stale cleanup).
    Zwraca liczbę wierszy zapisanych/zaktualizowanych.
    """
    if not ifaces:
        return 0
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from netdoc.storage.models import Interface

    now = datetime.utcnow()
    rows = []
    for iface in ifaces:
        if_index = iface.get("if_index")
        if if_index is None:
            continue  # bez if_index nie możemy upsertować (brak klucza UNIQUE)
        rows.append({
            "device_id":    device_id,
            "if_index":     if_index,
            "name":         iface.get("name", ""),
            "alias":        iface.get("alias"),
            "mac":          iface.get("mac"),
            "ip":           iface.get("ip"),
            "admin_status": iface.get("admin_status"),
            "oper_status":  iface.get("oper_status"),
            "speed":        iface.get("speed_mbps"),
            "duplex":       iface.get("duplex"),
            "polled_at":    now,
        })
    if not rows:
        return 0
    try:
        stmt = pg_insert(Interface.__table__).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_iface_dev_ifindex",
            set_={
                "name":         stmt.excluded.name,
                "alias":        stmt.excluded.alias,
                "mac":          stmt.excluded.mac,
                "ip":           stmt.excluded.ip,
                "admin_status": stmt.excluded.admin_status,
                "oper_status":  stmt.excluded.oper_status,
                "speed":        stmt.excluded.speed,
                "duplex":       stmt.excluded.duplex,
                "polled_at":    stmt.excluded.polled_at,
            },
        )
        db.execute(stmt)
        # Usuń interfejsy nieobecne w bieżącym pollu (zniknęły z urządzenia)
        current_indices = [r["if_index"] for r in rows]
        db.query(Interface).filter(
            Interface.device_id == device_id,
            Interface.if_index.isnot(None),
            Interface.if_index.notin_(current_indices),
        ).delete(synchronize_session=False)
        db.commit()
        return len(rows)
    except Exception as exc:
        logger.warning("interface save error device_id=%s: %s", device_id, exc)
        db.rollback()
        return 0


def _collect_ubnt_wireless(ip: str, community: str, timeout: int = 2) -> dict:
    """Pobiera dane WiFi z AP Ubiquiti UniFi przez SNMP (ubntUnifiVapTable).

    Zwraca dict:
        vaps  — lista dict per SSID/BSSID:
                  bssid, ssid, ifname, radio_band, sta_count, tx_bytes, rx_bytes
        total_clients — łączna liczba klientów
    """
    from netdoc.collector.snmp_walk import snmp_walk

    _VAP_OID = "1.3.6.1.4.1.41112.1.6.1.2.1"

    def _iv(v) -> int:
        if isinstance(v, (bytes, bytearray)):
            return int.from_bytes(v, "big") if v else 0
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0

    def _sv(v) -> str:
        if isinstance(v, (bytes, bytearray)):
            return v.decode("utf-8", errors="replace").strip()
        return str(v).strip()

    def _mac(v) -> str:
        """Formatuje surowe 6 bajtów jako XX:XX:XX:XX:XX:XX."""
        if isinstance(v, (bytes, bytearray)) and len(v) == 6:
            return ":".join(f"{b:02X}" for b in v)
        s = _sv(v)
        if len(s) == 17 and s.count(":") == 5:
            return s.upper()
        return s  # fallback — zostaw jak jest

    # Indeks: .field.vapIdx (prosty int) — każde pole w osobnym wierszu
    # field 2 = bssid (6 bajtów MAC — może być taki sam dla wielu SSIDów na tym samym radiu)
    # field 6 = ssid (nazwa sieci)
    # field 7 = ifname (wifi0ap1, wifi0ap2... — unikalny per VAP)
    # field 8 = sta_count (klienci)
    # field 9 = radio_band (ng=2.4GHz, na=5GHz)
    # field 10 = tx_bytes (Counter32)
    # field 13 = rx_bytes (Counter32)
    _VAP_FIELDS = {"2": "bssid", "6": "ssid", "7": "ifname", "8": "sta_count",
                   "9": "radio_band", "10": "tx_bytes", "13": "rx_bytes"}

    by_idx: dict[str, dict] = {}
    try:
        rows = snmp_walk(ip, _VAP_OID, community=community, timeout=timeout, max_iter=1000)
        for oid, raw_val, _tag in rows:
            sub = oid[len(_VAP_OID):].lstrip(".")
            parts = sub.split(".")
            if len(parts) != 2:
                continue
            field, vidx = parts
            if field not in _VAP_FIELDS:
                continue
            entry = by_idx.setdefault(vidx, {})
            fname = _VAP_FIELDS[field]
            if fname == "bssid":
                entry[fname] = _mac(raw_val)
            elif fname in ("ssid", "ifname", "radio_band"):
                entry[fname] = _sv(raw_val)
            else:
                entry[fname] = _iv(raw_val)
    except Exception as exc:
        logger.debug("UBNT VAP walk %s: %s", ip, exc)
        return {"vaps": [], "total_clients": 0}

    vaps = []
    for vidx, e in sorted(by_idx.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0):
        ifname = e.get("ifname", "")
        ssid   = e.get("ssid", "")
        if not ifname or not ssid:
            continue
        vaps.append({
            "bssid":      e.get("bssid"),
            "ssid":       ssid,
            "ifname":     ifname,
            "radio_band": e.get("radio_band"),
            "sta_count":  e.get("sta_count", 0),
            "tx_bytes":   e.get("tx_bytes", 0) or None,
            "rx_bytes":   e.get("rx_bytes", 0) or None,
        })

    total_clients = sum(v["sta_count"] for v in vaps)
    return {"vaps": vaps, "total_clients": total_clients}


def _save_vap_data(db, device_id: int, vaps: list[dict]) -> int:
    """Upsertuje dane VAP (SSID/klienci) do tabeli device_vap."""
    if not vaps:
        return 0
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from netdoc.storage.models import DeviceVap

    now = datetime.utcnow()
    rows = [
        {
            "device_id":  device_id,
            "bssid":      v.get("bssid"),
            "ssid":       v.get("ssid"),
            "ifname":     v["ifname"],
            "radio_band": v.get("radio_band"),
            "sta_count":  v.get("sta_count"),
            "tx_bytes":   v.get("tx_bytes"),
            "rx_bytes":   v.get("rx_bytes"),
            "polled_at":  now,
        }
        for v in vaps if v.get("ifname")
    ]
    if not rows:
        return 0
    try:
        stmt = pg_insert(DeviceVap.__table__).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_vap_device_ifname",
            set_={
                "bssid":      stmt.excluded.bssid,
                "ssid":       stmt.excluded.ssid,
                "radio_band": stmt.excluded.radio_band,
                "sta_count":  stmt.excluded.sta_count,
                "tx_bytes":   stmt.excluded.tx_bytes,
                "rx_bytes":   stmt.excluded.rx_bytes,
                "polled_at":  stmt.excluded.polled_at,
            },
        )
        db.execute(stmt)
        # Usuń VAP które zniknęły z AP (np. SSID wyłączony)
        current_ifnames = [r["ifname"] for r in rows]
        db.query(DeviceVap).filter(
            DeviceVap.device_id == device_id,
            DeviceVap.ifname.notin_(current_ifnames),
        ).delete(synchronize_session=False)
        db.commit()
        return len(rows)
    except Exception as exc:
        logger.warning("VAP save error device_id=%s: %s", device_id, exc)
        db.rollback()
        return 0


def _save_fdb(db, device_id: int, entries: list[dict]) -> int:
    """Upsertuje tablice FDB switcha (MAC-port mapping) do device_fdb.

    Klucz unikatowosci: (device_id, mac). Stare wpisy (> 2 cykle) usuwane.
    Zwraca liczbe wierszy zapisanych.
    """
    if not entries:
        return 0
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from netdoc.storage.models import DeviceFdbEntry

    # Uzupelnij interface_name z tabeli interfaces jesli mamy if_index
    from netdoc.storage.models import Interface as _Iface
    ifindex_to_name: dict[int, str] = {}
    all_indices = [e["if_index"] for e in entries if e.get("if_index")]
    if all_indices:
        ifaces = db.query(_Iface.if_index, _Iface.name).filter(
            _Iface.device_id == device_id,
            _Iface.if_index.in_(all_indices),
        ).all()
        ifindex_to_name = {row.if_index: row.name for row in ifaces}

    now = datetime.utcnow()
    rows = []
    for e in entries:
        rows.append({
            "device_id":      device_id,
            "mac":            e["mac"],
            "bridge_port":    e["bridge_port"],
            "if_index":       e.get("if_index"),
            "interface_name": ifindex_to_name.get(e.get("if_index")),
            "vlan_id":        e.get("vlan_id"),
            "fdb_status":     e.get("fdb_status", 3),
            "polled_at":      now,
        })
    if not rows:
        return 0
    try:
        stmt = pg_insert(DeviceFdbEntry.__table__).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_fdb_dev_mac",
            set_={
                "bridge_port":    stmt.excluded.bridge_port,
                "if_index":       stmt.excluded.if_index,
                "interface_name": stmt.excluded.interface_name,
                "vlan_id":        stmt.excluded.vlan_id,
                "fdb_status":     stmt.excluded.fdb_status,
                "polled_at":      stmt.excluded.polled_at,
            },
        )
        db.execute(stmt)
        # Usun stale wpisy (niewidziane przez > 2 cykle ~30 min)
        from datetime import timedelta
        stale_cutoff = now - timedelta(minutes=30)
        db.query(DeviceFdbEntry).filter(
            DeviceFdbEntry.device_id == device_id,
            DeviceFdbEntry.polled_at < stale_cutoff,
        ).delete(synchronize_session=False)
        db.commit()
        return len(rows)
    except Exception as exc:
        logger.warning("_save_fdb device_id=%s: %s", device_id, exc)
        db.rollback()
        return 0


def _save_vlan_port(db, device_id: int, entries: list[dict]) -> int:
    """Upsertuje przynaleznosc portow do VLAN-ow do device_vlan_port.

    Klucz unikatowosci: (device_id, vlan_id, if_index).
    Zwraca liczbe wierszy zapisanych.
    """
    if not entries:
        return 0
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from netdoc.storage.models import DeviceVlanPort

    now = datetime.utcnow()
    rows = [
        {
            "device_id":  device_id,
            "vlan_id":    e["vlan_id"],
            "vlan_name":  e.get("vlan_name"),
            "if_index":   e["if_index"],
            "port_mode":  e.get("port_mode"),
            "is_pvid":    bool(e.get("is_pvid", False)),
            "polled_at":  now,
        }
        for e in entries
        if e.get("vlan_id") and e.get("if_index")
    ]
    if not rows:
        return 0
    try:
        stmt = pg_insert(DeviceVlanPort.__table__).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_vlan_port",
            set_={
                "vlan_name": stmt.excluded.vlan_name,
                "port_mode": stmt.excluded.port_mode,
                "is_pvid":   stmt.excluded.is_pvid,
                "polled_at": stmt.excluded.polled_at,
            },
        )
        db.execute(stmt)
        # Usun VLAN-porty ktore znikly (batch DELETE)
        current_pairs = [(r["vlan_id"], r["if_index"]) for r in rows]
        from sqlalchemy import tuple_ as sa_tuple
        db.query(DeviceVlanPort).filter(
            DeviceVlanPort.device_id == device_id,
            ~sa_tuple(DeviceVlanPort.vlan_id, DeviceVlanPort.if_index).in_(current_pairs),
        ).delete(synchronize_session=False)
        db.commit()
        return len(rows)
    except Exception as exc:
        logger.warning("_save_vlan_port device_id=%s: %s", device_id, exc)
        db.rollback()
        return 0


def _save_stp_ports(db, device_id: int, ports: list[dict],
                    root_mac: str | None, root_cost: int | None) -> int:
    """Upsertuje stan STP portow + root bridge info.

    Klucz unikatowosci: (device_id, stp_port_num).
    Aktualizuje device.stp_root_mac i device.stp_root_cost.
    Zwraca liczbe wierszy zapisanych.
    """
    if not ports and root_mac is None:
        return 0
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from netdoc.storage.models import DeviceStpPort

    now = datetime.utcnow()

    # Aktualizuj root bridge info w device
    if root_mac is not None or root_cost is not None:
        dev = db.query(Device).filter_by(id=device_id).first()
        if dev:
            if root_mac  is not None: dev.stp_root_mac  = root_mac
            if root_cost is not None: dev.stp_root_cost = root_cost

    if not ports:
        try:
            db.commit()
        except Exception as exc:
            logger.warning("_save_stp_ports device_id=%s commit: %s", device_id, exc)
            db.rollback()
        return 0

    rows = [
        {
            "device_id":    device_id,
            "stp_port_num": p["stp_port_num"],
            "if_index":     p.get("if_index"),
            "stp_state":    p.get("stp_state"),
            "stp_role":     p.get("stp_role"),
            "path_cost":    p.get("path_cost"),
            "polled_at":    now,
        }
        for p in ports
        if p.get("stp_port_num") is not None
    ]
    if not rows:
        return 0
    try:
        stmt = pg_insert(DeviceStpPort.__table__).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_stp_dev_port",
            set_={
                "if_index":   stmt.excluded.if_index,
                "stp_state":  stmt.excluded.stp_state,
                "stp_role":   stmt.excluded.stp_role,
                "path_cost":  stmt.excluded.path_cost,
                "polled_at":  stmt.excluded.polled_at,
            },
        )
        db.execute(stmt)
        db.commit()
        return len(rows)
    except Exception as exc:
        logger.warning("_save_stp_ports device_id=%s: %s", device_id, exc)
        db.rollback()
        return 0


def _save_trunk_info(db, device_id: int, trunk_data: dict) -> int:
    """Zapisuje tryb portu (access/trunk) i dane trunk do tabeli interfaces.

    trunk_data: {if_index: {'port_mode', 'native_vlan', 'trunk_encap', 'trunk_vlans'}}
    Aktualizuje istniejące wiersze interfaces przez UPDATE (nie insert — interfejs musi istnieć).
    Zwraca liczbę zaktualizowanych wierszy.
    """
    if not trunk_data:
        return 0
    from netdoc.storage.models import Interface

    updated = 0
    try:
        for if_index, info in trunk_data.items():
            rows = db.query(Interface).filter_by(device_id=device_id, if_index=if_index).all()
            for iface in rows:
                iface.port_mode   = info.get("port_mode")
                iface.native_vlan = info.get("native_vlan")
                iface.trunk_encap = info.get("trunk_encap")
                iface.trunk_vlans = info.get("trunk_vlans")
                updated += 1
        db.commit()
    except Exception as exc:
        logger.warning("_save_trunk_info device_id=%s: %s", device_id, exc)
        db.rollback()
    return updated


_DEFAULT_SNMP_TIMEOUT = int(os.getenv("SNMP_TIMEOUT_S", "2"))


def _read_snmp_settings() -> tuple:
    """Czyta ustawienia z system_status (zmiana skutkuje w nastepnym cyklu).
    PERF-14: jedna query WHERE key IN (...) zamiast 4 osobnych SELECT.
    """
    from netdoc.storage.models import SystemStatus
    _KEYS = ("snmp_interval_s", "snmp_workers", "snmp_timeout_s", "snmp_community_delay_s")
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
        return (max(10, _i("snmp_interval_s",        _DEFAULT_SNMP_INTERVAL)),
                max(1,  _i("snmp_workers",           _DEFAULT_SNMP_WORKERS)),
                max(1,  _i("snmp_timeout_s",         _DEFAULT_SNMP_TIMEOUT)),
                max(0,  _i("snmp_community_delay_s", 3)))
    except Exception:
        return _DEFAULT_SNMP_INTERVAL, _DEFAULT_SNMP_WORKERS, _DEFAULT_SNMP_TIMEOUT, 3
    finally:
        db.close()


def scan_once() -> None:
    interval, workers, snmp_timeout, _unused_delay = _read_snmp_settings()
    t0 = time.monotonic()
    db = SessionLocal()
    try:
        # Tylko urzadzenia ze znana community — autodiscovery robi community-worker
        devices = (
            db.query(Device)
            .filter(Device.is_active == True, Device.snmp_community.isnot(None))
            .all()
        )
    finally:
        db.close()

    if not devices:
        logger.info("No devices with known community — nothing to poll")
        g_polled.set(0); g_success.set(0); g_failed.set(0); g_duration.set(0)
        return

    # Paszport cache — jeden lookup per device na cały cykl
    try:
        from netdoc.collector.passport_loader import (
            find_passport as _fp,
            passport_allows_arp as _passport_allows_arp,
            passport_allows_cpu as _passport_allows_cpu,
            passport_allows_ram as _passport_allows_ram,
            passport_sensor_method as _passport_sensor_method,
            passport_sensor_oids as _passport_sensor_oids,
            passport_extra_oids as _passport_extra_oids,
        )
        _device_passports: dict = {
            d.id: _fp(d.vendor, d.model, d.os_version)
            for d in devices
        }
        _device_extra_oids: dict = {
            d.id: _passport_extra_oids(_device_passports.get(d.id))
            for d in devices
        }
        _n_matched = sum(1 for p in _device_passports.values() if p is not None)
        logger.info("Passport match: %d/%d devices", _n_matched, len(devices))
    except ImportError:
        _device_passports = {}
        _device_extra_oids = {}
        def _passport_allows_arp(p): return None  # type: ignore[misc]
        def _passport_allows_cpu(p): return None  # type: ignore[misc]
        def _passport_allows_ram(p): return None  # type: ignore[misc]
        def _passport_sensor_method(p): return None  # type: ignore[misc]
        def _passport_sensor_oids(p): return {}  # type: ignore[misc]
        def _passport_extra_oids(p): return {}  # type: ignore[misc]

    logger.info("SNMP poll: %d devices with known community | workers=%d", len(devices), workers)

    polled = success = failed = 0
    with ThreadPoolExecutor(max_workers=min(workers, len(devices))) as pool:
        # PERF-03: przekazujemy dane device bezposrednio — eliminuje N re-query per watek
        futures = {
            pool.submit(
                _poll_device, d.id, d.ip, d.snmp_community,
                d.hostname, d.os_version, d.location, snmp_timeout
            ): d.id
            for d in devices
        }
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception as exc:
                logger.error("SNMP poll thread error: %s", exc)
                polled += 1
                failed += 1
                continue
            polled += 1
            if res["success"]:
                success += 1
            else:
                failed += 1

    elapsed = time.monotonic() - t0
    g_polled.set(polled); g_success.set(success)
    g_failed.set(failed); g_new_cred.set(0); g_duration.set(round(elapsed, 1))
    logger.info("SNMP poll done: %d ok / %d failed  %.1fs", success, failed, elapsed)

    # Neighbor enrichment (LLDP / CDP / EDP) — dla urzadzen ze SNMP pytamy o sasiadow
    neighbor_total = 0
    neighbor_devices = [d for d in devices if d.snmp_community]
    if neighbor_devices:
        logger.info("Neighbor enrichment: checking %d devices (LLDP/CDP/EDP)", len(neighbor_devices))
        db_neigh = SessionLocal()
        try:
            for d in neighbor_devices:
                # LLDP — standard (HP, Juniper, Cisco, Extreme...)
                lldp_nb = _enrich_lldp(d.ip, d.snmp_community, timeout=snmp_timeout)
                if lldp_nb:
                    n = _save_lldp_neighbors(db_neigh, d.id, d.ip, lldp_nb, "LLDP")
                    neighbor_total += n
                    if n:
                        logger.info("LLDP %-18s: %d neighbor(s)", d.ip, n)

                # CDP — Cisco proprietary
                cdp_nb = _enrich_cdp(d.ip, d.snmp_community, timeout=snmp_timeout)
                if cdp_nb:
                    n = _save_lldp_neighbors(db_neigh, d.id, d.ip, cdp_nb, "CDP")
                    neighbor_total += n
                    if n:
                        logger.info("CDP  %-18s: %d neighbor(s)", d.ip, n)

                # EDP — Extreme Networks
                edp_nb = _enrich_edp(d.ip, d.snmp_community, timeout=snmp_timeout)
                if edp_nb:
                    n = _save_lldp_neighbors(db_neigh, d.id, d.ip, edp_nb, "EDP")
                    neighbor_total += n
                    if n:
                        logger.info("EDP  %-18s: %d neighbor(s)", d.ip, n)

        except Exception as exc:
            logger.warning("Neighbor enrichment error: %s", exc)
        finally:
            db_neigh.close()
        if neighbor_total:
            logger.info("Neighbor total updated: %d", neighbor_total)

    # ARP table walk — routery i L3 switche ujawniaja urzadzenia w innych VLAN-ach
    # Paszport (snmp_collection.arp.enabled) ma priorytet; fallback: device_type heuristic
    _L3_TYPES = {DeviceType.router, DeviceType.switch, DeviceType.firewall, DeviceType.unknown}
    arp_candidates = []
    for _d in devices:
        if not _d.snmp_community:
            continue
        _arp_flag = _passport_allows_arp(_device_passports.get(_d.id))
        if _arp_flag is True:
            arp_candidates.append(_d)
        elif _arp_flag is None and _d.device_type in _L3_TYPES:
            arp_candidates.append(_d)
        # _arp_flag == False → jawnie wyłączone w paszporcie, pomiń
    if arp_candidates:
        logger.info("ARP walk: checking %d L3 devices for ARP table", len(arp_candidates))
        arp_total = 0
        db_arp = SessionLocal()
        try:
            for d in arp_candidates:
                arp_entries = _enrich_arp(d.ip, d.snmp_community, timeout=snmp_timeout)
                if arp_entries:
                    n = _save_arp_devices(db_arp, d.ip, arp_entries)
                    arp_total += n
                    logger.info("ARP  %-18s: %d entries, %d new/updated", d.ip, len(arp_entries), n)
        except Exception as exc:
            logger.warning("ARP walk error: %s", exc)
        finally:
            db_arp.close()
        if arp_total:
            logger.info("ARP total new/updated devices: %d", arp_total)

    # Interface walk — zbiera ifTable+ifXTable, upsertuje stan i zapisuje zdarzenia
    if_changed = 0
    if_saved   = 0
    db_if = SessionLocal()
    try:
        for d in devices:
            ifaces = _enrich_interfaces(d.ip, d.snmp_community, timeout=snmp_timeout)
            if ifaces:
                # Bieżący stan interfejsów (upsert do interfaces)
                n_saved = _save_interfaces(db_if, d.id, ifaces)
                if_saved += n_saved
                logger.info("IF   %-18s: %d port(s)", d.ip, len(ifaces))
                # Historia zmian (up/down/speed_change)
                # speed_mbps: Mbps (kolumna Integer 32-bit, max 2G — nie przekraczamy)
                old_fmt = [
                    {
                        "name":        i["name"],
                        "oper_status": 1 if i.get("oper_status") else 2,
                        "speed_mbps":  i.get("speed_mbps") or 0,
                    }
                    for i in ifaces
                ]
                n_hist = _save_interface_history(db_if, d.id, old_fmt)
                if n_hist:
                    if_changed += n_hist
    except Exception as exc:
        logger.warning("Interface walk error: %s", exc)
    finally:
        db_if.close()
    if if_saved:
        logger.info("Interface upserts total: %d", if_saved)
    if if_changed:
        logger.info("Interface history total: %d new entries", if_changed)

    # Sensor poll — temperature, CPU, RAM, voltage, fans (per device type/vendor)
    sensor_total = 0
    db_sens = SessionLocal()
    try:
        from netdoc.collector.snmp_sensors import poll_sensors
        for d in devices:
            vendor_hint = (d.vendor or "").lower()
            os_hint     = (d.os_version or "").lower()
            _pp = _device_passports.get(d.id)
            _s_method = _passport_sensor_method(_pp)
            _s_oids   = _passport_sensor_oids(_pp)
            try:
                sensors = poll_sensors(
                    str(d.ip), d.snmp_community,
                    vendor_hint=vendor_hint,
                    os_hint=os_hint,
                    timeout=snmp_timeout,
                    sensor_method=_s_method,
                    sensor_oids=_s_oids,
                )
            except Exception as exc:
                logger.debug("Sensor poll %s: %s", d.ip, exc)
                continue
            if sensors:
                n = _save_sensors(db_sens, d.id, sensors)
                sensor_total += n
                logger.info("Sensors %-18s: %d values", d.ip, len(sensors))
    except ImportError:
        logger.debug("snmp_sensors module not available — skipping sensor poll")
    except Exception as exc:
        logger.warning("Sensor poll error: %s", exc)
    finally:
        db_sens.close()
    if sensor_total:
        logger.info("Sensor upserts total: %d", sensor_total)

    # WiFi VAP data — Ubiquiti UniFi APs (ubntUnifiVapTable)
    ap_candidates = [d for d in devices if d.snmp_community and d.device_type == DeviceType.ap]
    if ap_candidates:
        vap_total = 0
        db_vap = SessionLocal()
        try:
            for d in ap_candidates:
                try:
                    result = _collect_ubnt_wireless(str(d.ip), d.snmp_community, timeout=snmp_timeout)
                    vaps = result["vaps"]
                    if vaps:
                        n = _save_vap_data(db_vap, d.id, vaps)
                        vap_total += n
                        logger.info("WiFi %-18s: %d VAP(s), %d clients total",
                                    d.ip, len(vaps), result["total_clients"])
                        # Zapisz total_clients jako sensor (widoczny na karcie urządzenia)
                        _save_sensors(db_vap, d.id, [{
                            "name":   "wifi_clients_total",
                            "value":  float(result["total_clients"]),
                            "unit":   "clients",
                            "source": "ubnt_vap",
                        }])
                except Exception as exc:
                    logger.debug("WiFi VAP %s: %s", d.ip, exc)
        except Exception as exc:
            logger.warning("WiFi VAP collection error: %s", exc)
        finally:
            db_vap.close()

    # L2 data — FDB, VLAN, STP (tylko switche; co 15 minut — nie co 5 min)
    _L2_TYPES = {DeviceType.switch}
    _L2_INTERVAL = 900  # 15 minut
    _l2_last_run_key = "_l2_last_run"
    import time as _time_mod
    _l2_now = _time_mod.monotonic()
    if not hasattr(scan_once, "_l2_last"):
        scan_once._l2_last = 0.0  # type: ignore[attr-defined]
    if _l2_now - scan_once._l2_last >= _L2_INTERVAL:  # type: ignore[attr-defined]
        # BUG-WRK1: _l2_last ustawiany NA KOŃCU (nie na początku) — błąd w kolekcji
        # nie blokuje kolejnej próby na 15 min, tylko do następnego 5-min cyklu.
        from netdoc.collector.snmp_profiles import get_profile
        l2_candidates = [d for d in devices if d.snmp_community and d.device_type in _L2_TYPES]
        if l2_candidates:
            logger.info("L2 collection: %d switches (FDB/VLAN/STP)", len(l2_candidates))
            db_l2 = SessionLocal()
            try:
                import threading as _threading
                from netdoc.collector.snmp_l2 import collect_fdb, collect_vlan_port, collect_stp_ports, collect_trunk_info
                _L2_PER_DEVICE_TIMEOUT = 60  # BUG-WRK2: daemon thread — zabezpiecza przed zawieszonym walkiem

                def _collect_l2_device(d_arg, prof_arg, ip_arg, comm_arg):
                    if prof_arg.get("fdb_supported", True):
                        try:
                            fdb = collect_fdb(ip_arg, comm_arg, snmp_timeout)
                            if fdb:
                                n = _save_fdb(db_l2, d_arg.id, fdb)
                                logger.info("FDB  %-18s: %d entries", ip_arg, n)
                        except Exception as exc:
                            logger.debug("FDB %s: %s", ip_arg, exc)
                    if prof_arg.get("vlan_supported", True):
                        try:
                            vlan_ports = collect_vlan_port(ip_arg, comm_arg, snmp_timeout)
                            if vlan_ports:
                                n = _save_vlan_port(db_l2, d_arg.id, vlan_ports)
                                logger.info("VLAN %-18s: %d vlan-port entries", ip_arg, n)
                        except Exception as exc:
                            logger.debug("VLAN %s: %s", ip_arg, exc)
                    if prof_arg.get("stp_supported", True):
                        try:
                            stp_ports, root_mac, root_cost = collect_stp_ports(ip_arg, comm_arg, snmp_timeout)
                            if stp_ports or root_mac:
                                n = _save_stp_ports(db_l2, d_arg.id, stp_ports, root_mac, root_cost)
                                logger.info("STP  %-18s: %d ports, root=%s", ip_arg, n, root_mac or "-")
                        except Exception as exc:
                            logger.debug("STP %s: %s", ip_arg, exc)
                    # Cisco trunk port mode (VTP MIB) — access/trunk, native VLAN, encap, allowed VLANs
                    try:
                        trunk_data = collect_trunk_info(ip_arg, comm_arg, snmp_timeout)
                        if trunk_data:
                            n = _save_trunk_info(db_l2, d_arg.id, trunk_data)
                            trunk_count = sum(1 for v in trunk_data.values() if v["port_mode"] == "trunk")
                            logger.info("TRNK %-18s: %d ports (%d trunk)", ip_arg, n, trunk_count)
                    except Exception as exc:
                        logger.debug("TRUNK %s: %s", ip_arg, exc)

                for d in l2_candidates:
                    _prof = get_profile(d.snmp_sys_object_id, d.os_version)
                    _ip = str(d.ip)
                    _comm = d.snmp_community
                    _t = _threading.Thread(
                        target=_collect_l2_device, args=(d, _prof, _ip, _comm), daemon=True
                    )
                    _t.start()
                    _t.join(timeout=_L2_PER_DEVICE_TIMEOUT)
                    if _t.is_alive():
                        logger.warning("L2 collection %s: timeout after %ds — skipping", _ip, _L2_PER_DEVICE_TIMEOUT)
                scan_once._l2_last = _l2_now  # type: ignore[attr-defined]
            except Exception as exc:
                logger.warning("L2 collection error: %s", exc)
            finally:
                db_l2.close()

    # Interface metrics → ClickHouse (in/out octets HC, errors, discards)
    # BUG-WRK3: _ensure_metrics_table() wywoływana tu (nie tylko w main()) — ponawia po restarcie CH.
    # PERF-1: metryki zbierane równolegle przez ThreadPoolExecutor zamiast sekwencyjnie.
    try:
        from netdoc.storage.clickhouse import insert_if_metrics, _ensure_metrics_table
        from datetime import datetime as _dt
        _ensure_metrics_table()
        now_ts = _dt.now()  # lokalny czas — ClickHouse (Europe/Warsaw) interpretuje naive datetime jako localtime
        metrics_batch: list[tuple] = []
        snmp_devs = [d for d in devices if d.snmp_community]

        def _collect_one(dev):
            return _collect_if_metrics(str(dev.ip), dev.snmp_community, snmp_timeout), dev.id

        with ThreadPoolExecutor(max_workers=min(32, len(snmp_devs) or 1)) as _pool:
            futures = {_pool.submit(_collect_one, d): d for d in snmp_devs}
            for fut in as_completed(futures):
                try:
                    raw, dev_id = fut.result()
                    for if_index, metric_name, value in raw:
                        metrics_batch.append((now_ts, dev_id, if_index, metric_name, value))
                except Exception as exc:
                    logger.debug("IF metrics collect error: %s", exc)
        if metrics_batch:
            insert_if_metrics(metrics_batch)
            logger.info("IF metrics: %d data points -> ClickHouse", len(metrics_batch))
    except Exception as exc:
        logger.warning("IF metrics collection error: %s", exc)

    # ── Resource metrics (CPU/mem) → ClickHouse ──────────────────────────────
    # Zbierane co każdy cykl SNMP workera via HOST-RESOURCES-MIB (if_index=0)
    # Passport: pomijamy urządzenia gdzie obie flagi cpu i ram jawnie wyłączone
    _res_devs = []
    for _d in devices:
        _pp = _device_passports.get(_d.id)
        if _passport_allows_cpu(_pp) is False and _passport_allows_ram(_pp) is False:
            continue  # paszport jawnie wyklucza CPU i RAM dla tego modelu
        _res_devs.append(_d)
    if len(_res_devs) < len(devices):
        logger.debug("Resource metrics: skipping %d devices (passport cpu+ram=false)",
                     len(devices) - len(_res_devs))
    _collect_resource_metrics(_res_devs, snmp_timeout, device_extra_oids=_device_extra_oids)

    # ── Alert computation ─────────────────────────────────────────────────────
    # Uruchamiane co 30 min (nie co każdy cykl) — porównuje trendy błędów i CPU/mem z progami
    _DIAG_INTERVAL = 1800  # 30 minut
    if not hasattr(scan_once, "_diag_last"):
        scan_once._diag_last = 0.0  # type: ignore[attr-defined]
    _diag_now = time.monotonic()
    if _diag_now - scan_once._diag_last >= _DIAG_INTERVAL:  # type: ignore[attr-defined]
        try:
            _compute_alerts(devices)
            scan_once._diag_last = _diag_now  # type: ignore[attr-defined]
        except Exception as exc:
            logger.warning("Alert computation error: %s", exc)

    # ── Network Tier Analysis ──────────────────────────────────────────────────
    # Uruchamiane co 1h — analiza roli L2/L3 urządzeń na podstawie LLDP, FDB, portów, STP
    _TIER_INTERVAL = 3600  # 1 godzina
    if not hasattr(scan_once, "_tier_last"):
        scan_once._tier_last = 0.0  # type: ignore[attr-defined]
    if time.monotonic() - scan_once._tier_last >= _TIER_INTERVAL:  # type: ignore[attr-defined]
        try:
            from netdoc.analyzer.tier import analyze_all_devices as _analyze_tiers
            _tier_db = SessionLocal()
            try:
                _n = _analyze_tiers(_tier_db)
                logger.info("Network tier analysis: %d devices analyzed", _n)
            finally:
                _tier_db.close()
            scan_once._tier_last = time.monotonic()  # type: ignore[attr-defined]
        except Exception as exc:
            logger.warning("Network tier analysis error: %s", exc)


def _collect_resource_metrics(
    devices, snmp_timeout: int, device_extra_oids: dict | None = None
) -> None:
    """Zbiera CPU i pamięć ze wszystkich urządzeń i zapisuje do ClickHouse (if_index=0).

    device_extra_oids: {device_id: {"cpu_5min": oid, "ram_free": oid, "ram_used": oid}}
    Gdy obecne, używa vendor-specific OIDów zamiast HOST-RESOURCES-MIB.
    """
    from netdoc.storage.models import SystemStatus
    db_cfg = SessionLocal()
    try:
        r = db_cfg.query(SystemStatus).filter(
            SystemStatus.key == "diag_enabled", SystemStatus.category == "config"
        ).first()
        if r and r.value == "0":
            return
    except Exception:
        pass
    finally:
        db_cfg.close()

    from netdoc.collector.snmp_l2 import collect_host_resources
    from netdoc.storage.clickhouse import insert_if_metrics
    from datetime import datetime as _dt

    snmp_devs = [d for d in devices if d.snmp_community]
    if not snmp_devs:
        return

    batch: list[tuple] = []
    now_ts = _dt.now()

    def _collect_res(dev):
        extra = (device_extra_oids or {}).get(dev.id, {})
        return collect_host_resources(
            str(dev.ip), dev.snmp_community, snmp_timeout,
            cpu_oid=extra.get("cpu_5min"),
            ram_free_oid=extra.get("ram_free"),
            ram_used_oid=extra.get("ram_used"),
        ), dev.id

    with ThreadPoolExecutor(max_workers=min(16, len(snmp_devs))) as pool:
        futures = {pool.submit(_collect_res, d): d for d in snmp_devs}
        for fut in as_completed(futures):
            try:
                data, dev_id = fut.result()
                if data.get("cpu_percent") is not None:
                    batch.append((now_ts, dev_id, 0, "cpu_percent", data["cpu_percent"]))
                if data.get("mem_used_pct") is not None:
                    batch.append((now_ts, dev_id, 0, "mem_used_pct", data["mem_used_pct"]))
            except Exception as exc:
                logger.debug("Resource metrics collect error: %s", exc)

    if batch:
        try:
            insert_if_metrics(batch)
            logger.info("Resource metrics: %d points (CPU/mem) -> ClickHouse", len(batch))
        except Exception as exc:
            logger.warning("Resource metrics insert error: %s", exc)


def _compute_alerts(devices) -> None:
    """Oblicza alerty diagnostyczne (błędy portów, CPU, RAM) i zapisuje do PostgreSQL.

    Porównuje:
      - Błędy portów: łącznie last 24h vs. baseline [7d temu ±24h] → trend% i próg absolutny
      - CPU/mem: ostatni odczyt vs. próg
    Upsertuje wiersze do device_port_alerts (unikalne per device+if_index+alert_type).
    """
    from netdoc.storage.models import SystemStatus, DevicePortAlert
    from netdoc.storage.clickhouse import query_error_totals, query_resource_history
    from datetime import datetime as _dt

    db_cfg = SessionLocal()
    try:
        cfg_rows = db_cfg.query(SystemStatus).filter(
            SystemStatus.key.in_([
                "diag_enabled", "diag_error_warn_per_hour", "diag_error_critical_per_hour",
                "diag_error_trend_pct", "diag_error_trend_days",
                "diag_cpu_warn_pct", "diag_cpu_critical_pct",
                "diag_mem_warn_pct", "diag_mem_critical_pct",
            ]),
            SystemStatus.category == "config",
        ).all()
        cfg = {r.key: r.value for r in cfg_rows}
    finally:
        db_cfg.close()

    if cfg.get("diag_enabled", "1") == "0":
        return

    def _f(key, default):
        try:
            return float(cfg.get(key, default))
        except (ValueError, TypeError):
            return float(default)

    err_warn    = _f("diag_error_warn_per_hour",     10)
    err_crit    = _f("diag_error_critical_per_hour", 100)
    trend_pct   = _f("diag_error_trend_pct",         50)
    trend_days  = int(_f("diag_error_trend_days",     7))
    cpu_warn    = _f("diag_cpu_warn_pct",             80)
    cpu_crit    = _f("diag_cpu_critical_pct",         95)
    mem_warn    = _f("diag_mem_warn_pct",             80)
    mem_crit    = _f("diag_mem_critical_pct",         90)

    now = _dt.utcnow()

    snmp_devs = [d for d in devices if d.snmp_community]
    logger.info("Alert computation: %d devices", len(snmp_devs))
    if not snmp_devs:
        return

    dev_ids = [d.id for d in snmp_devs]

    # Bulk load: interfejsy, sensory, istniejące alerty — JEDNA sesja zamiast 3×N
    from netdoc.storage.models import DevicePortAlert, Interface, DeviceSensor as _DevSensor
    db_bulk = SessionLocal()
    try:
        all_ifaces = (
            db_bulk.query(Interface.device_id, Interface.if_index, Interface.name)
            .filter(Interface.device_id.in_(dev_ids), Interface.if_index.isnot(None))
            .all()
        )
        iface_map: dict[int, dict[int, str]] = {}
        for row in all_ifaces:
            iface_map.setdefault(row.device_id, {})[row.if_index] = row.name or ""

        all_sensors = (
            db_bulk.query(_DevSensor.device_id, _DevSensor.sensor_name, _DevSensor.value)
            .filter(_DevSensor.device_id.in_(dev_ids), _DevSensor.value.isnot(None))
            .all()
        )
        sensor_map: dict[int, dict[str, float]] = {}
        for row in all_sensors:
            if row.sensor_name:
                sensor_map.setdefault(row.device_id, {})[row.sensor_name] = float(row.value)

        all_existing = (
            db_bulk.query(DevicePortAlert)
            .filter(DevicePortAlert.device_id.in_(dev_ids))
            .all()
        )
        alert_map: dict[int, list] = {}
        for a in all_existing:
            alert_map.setdefault(a.device_id, []).append(a)
    finally:
        db_bulk.close()

    # Oblicz alerty (czyste funkcje, bez sesji DB)
    device_alerts: dict[int, list[dict]] = {}
    for dev in snmp_devs:
        try:
            device_alerts[dev.id] = _compute_device_alerts(
                dev, now,
                iface_map.get(dev.id, {}),
                sensor_map.get(dev.id, {}),
                err_warn, err_crit, trend_pct, trend_days,
                cpu_warn, cpu_crit, mem_warn, mem_crit,
                query_error_totals, query_resource_history,
            )
        except Exception as exc:
            logger.debug("Alert computation device %s: %s", dev.ip, exc)

    # Zapisz do DB w jednej sesji — zamiast 3 sesji per urządzenie
    db_a = SessionLocal()
    try:
        for dev in snmp_devs:
            dev_id = dev.id
            alerts_to_upsert = device_alerts.get(dev_id, [])
            existing_alerts = alert_map.get(dev_id, [])
            iface_names_dev = iface_map.get(dev_id, {})

            if not alerts_to_upsert:
                for a in existing_alerts:
                    if a.acknowledged_at is None:
                        db_a.delete(a)
                continue

            existing_by_key = {(a.if_index, a.alert_type): a for a in existing_alerts}
            active_combos = {(a["if_index"], a["alert_type"]) for a in alerts_to_upsert}

            for a in alerts_to_upsert:
                key = (a["if_index"], a["alert_type"])
                existing = existing_by_key.get(key)
                if existing:
                    existing.severity       = a["severity"]
                    existing.value_current  = a["value_current"]
                    existing.value_baseline = a["value_baseline"]
                    existing.trend_pct      = a["trend_pct"]
                    existing.last_seen      = now
                else:
                    db_a.add(DevicePortAlert(
                        device_id      = dev_id,
                        if_index       = a["if_index"],
                        interface_name = iface_names_dev.get(a["if_index"]),
                        alert_type     = a["alert_type"],
                        severity       = a["severity"],
                        value_current  = a["value_current"],
                        value_baseline = a["value_baseline"],
                        trend_pct      = a["trend_pct"],
                        first_seen     = now,
                        last_seen      = now,
                    ))

            for existing in existing_alerts:
                if (existing.if_index, existing.alert_type) not in active_combos:
                    if existing.acknowledged_at is None:
                        db_a.delete(existing)

        db_a.commit()
    except Exception as exc:
        db_a.rollback()
        logger.warning("Alert batch upsert: %s", exc)
    finally:
        db_a.close()


def _compute_device_alerts(
    dev, now,
    iface_names: dict,   # {if_index: name} — załadowane bulk w _compute_alerts
    sensors: dict,       # {sensor_name: value} — załadowane bulk w _compute_alerts
    err_warn, err_crit, trend_pct_thresh, trend_days,
    cpu_warn, cpu_crit, mem_warn, mem_crit,
    query_error_totals, query_resource_history,
) -> list[dict]:
    """Oblicza alerty dla jednego urządzenia. Nie otwiera sesji DB — tylko obliczenia."""
    from netdoc.storage.models import DevicePortAlert, Interface

    alerts_to_upsert: list[dict] = []

    _NOISY_IFACE_PREFIXES = ("vwiresta", "vwire", "mon", "wifi1ap", "wifi0ap", "wifi1", "wifi0")

    # ── Błędy portów ─────────────────────────────────────────────────────────
    try:
        recent  = query_error_totals(dev.id, hours=24)
        baseline = query_error_totals(dev.id, hours=trend_days * 24 + 24)

        _iface_names = iface_names  # przekazane z zewnątrz (bulk)

        for if_index, recent_errors in recent.items():
            iface_name = _iface_names.get(if_index, "")

            # Pomiń znane strukturalnie głośne interfejsy (mesh backhaul, VAP monitor)
            if any(iface_name.startswith(p) for p in _NOISY_IFACE_PREFIXES):
                continue

            rate_per_h = recent_errors / 24.0

            severity = None
            if rate_per_h >= err_crit:
                severity = "critical"
            elif rate_per_h >= err_warn:
                severity = "warning"

            base_total = baseline.get(if_index, 0.0) - recent_errors
            base_rate  = max(0.0, base_total) / (trend_days * 24)
            trend = None
            if base_rate > 0:
                trend = round((rate_per_h - base_rate) / base_rate * 100, 1)
                # Trend alert tylko gdy wartość bezwzględna jest istotna (≥ 10% progu warning).
                # Zapobiega fałszywym alarmom gdy 2→4 błędy/h daje "+100% trend".
                if severity is None and trend >= trend_pct_thresh and rate_per_h >= err_warn * 0.1:
                    severity = "warning"

            if severity:
                alerts_to_upsert.append({
                    "if_index":      if_index,
                    "alert_type":    "error_rate" if rate_per_h >= err_warn else "error_trend",
                    "severity":      severity,
                    "value_current": round(rate_per_h, 2),
                    "value_baseline": round(base_rate, 2),
                    "trend_pct":     trend,
                })
    except Exception as exc:
        logger.debug("Error trend computation dev %s: %s", dev.ip, exc)

    # ── CPU i pamięć ─────────────────────────────────────────────────────────
    try:
        resource_hist = query_resource_history(dev.id, hours=1, step_minutes=5)
        if resource_hist:
            last = resource_hist[-1]
            cpu = last.get("cpu_percent")
            mem = last.get("mem_used_pct")

            if cpu is not None:
                if cpu >= cpu_crit:
                    alerts_to_upsert.append({"if_index": 0, "alert_type": "cpu_high",
                        "severity": "critical", "value_current": cpu, "value_baseline": None, "trend_pct": None})
                elif cpu >= cpu_warn:
                    alerts_to_upsert.append({"if_index": 0, "alert_type": "cpu_high",
                        "severity": "warning", "value_current": cpu, "value_baseline": None, "trend_pct": None})

            if mem is not None:
                if mem >= mem_crit:
                    alerts_to_upsert.append({"if_index": 0, "alert_type": "mem_high",
                        "severity": "critical", "value_current": mem, "value_baseline": None, "trend_pct": None})
                elif mem >= mem_warn:
                    alerts_to_upsert.append({"if_index": 0, "alert_type": "mem_high",
                        "severity": "warning", "value_current": mem, "value_baseline": None, "trend_pct": None})
    except Exception as exc:
        logger.debug("CPU/mem alert dev %s: %s", dev.ip, exc)

    # ── Sensory: dyski, RAID, temp ───────────────────────────────────────────
    try:
        _sensors = sensors  # przekazane z zewnątrz (bulk)

        # RAID/Storage pool free% — krytyczne <5%, warning <15%
        for sname, sval in _sensors.items():
            if "free_pct" in sname:
                if sval < 5:
                    alerts_to_upsert.append({"if_index": 0, "alert_type": f"sensor_{sname}",
                        "severity": "critical", "value_current": sval,
                        "value_baseline": None, "trend_pct": None})
                elif sval < 15:
                    alerts_to_upsert.append({"if_index": 0, "alert_type": f"sensor_{sname}",
                        "severity": "warning", "value_current": sval,
                        "value_baseline": None, "trend_pct": None})

        # Disk health != 1 (Synology: 2=Warning, 3=Critical, 4=Failing)
        for sname, sval in _sensors.items():
            if sname.endswith("_health") and "disk" in sname:
                if sval >= 3:
                    alerts_to_upsert.append({"if_index": 0, "alert_type": f"sensor_{sname}",
                        "severity": "critical", "value_current": sval,
                        "value_baseline": None, "trend_pct": None})
                elif sval >= 2:
                    alerts_to_upsert.append({"if_index": 0, "alert_type": f"sensor_{sname}",
                        "severity": "warning", "value_current": sval,
                        "value_baseline": None, "trend_pct": None})

        # Cisco IOS: HOST-RESOURCES-MIB mem_used_pct (~87%) is a false positive —
        # Cisco pre-allocates pool memory at boot, so it always looks high.
        # Replace ClickHouse-based mem_high alert with CISCO-PROCESS-MIB data.
        if "mem_total_mb" in _sensors and "mem_io_used_pct" in _sensors:
            # Remove any ClickHouse-based mem_high alert
            alerts_to_upsert = [a for a in alerts_to_upsert if a["alert_type"] != "mem_high"]
            # Alert on I/O pool usage (mem_io_used_pct) — packet drop risk when high
            _io_pct = _sensors["mem_io_used_pct"]
            if _io_pct >= mem_crit:
                alerts_to_upsert.append({"if_index": 0, "alert_type": "mem_high",
                    "severity": "critical", "value_current": _io_pct, "value_baseline": None, "trend_pct": None})
            elif _io_pct >= mem_warn:
                alerts_to_upsert.append({"if_index": 0, "alert_type": "mem_high",
                    "severity": "warning", "value_current": _io_pct, "value_baseline": None, "trend_pct": None})

        # RAID status != 1 (Synology: 11=Degrade, 12=Crashed)
        for sname, sval in _sensors.items():
            if sname.endswith("_status") and "raid" in sname:
                if sval >= 11:
                    alerts_to_upsert.append({"if_index": 0, "alert_type": f"sensor_{sname}",
                        "severity": "critical", "value_current": sval,
                        "value_baseline": None, "trend_pct": None})
                elif sval > 1:
                    alerts_to_upsert.append({"if_index": 0, "alert_type": f"sensor_{sname}",
                        "severity": "warning", "value_current": sval,
                        "value_baseline": None, "trend_pct": None})

        # Bad sectors > 0
        for sname, sval in _sensors.items():
            if "bad_sector" in sname and sval > 0:
                severity = "critical" if sval >= 50 else "warning"
                alerts_to_upsert.append({"if_index": 0, "alert_type": f"sensor_{sname}",
                    "severity": severity, "value_current": sval,
                    "value_baseline": None, "trend_pct": None})

        # Temp: warn >60C, critical >75C
        for sname, sval in _sensors.items():
            if "temp" in sname and sval is not None:
                if sval >= 75:
                    alerts_to_upsert.append({"if_index": 0, "alert_type": f"sensor_{sname}",
                        "severity": "critical", "value_current": sval,
                        "value_baseline": None, "trend_pct": None})
                elif sval >= 60:
                    alerts_to_upsert.append({"if_index": 0, "alert_type": f"sensor_{sname}",
                        "severity": "warning", "value_current": sval,
                        "value_baseline": None, "trend_pct": None})

    except Exception as exc:
        logger.debug("Sensor alert computation dev %s: %s", dev.ip, exc)

    return alerts_to_upsert


def _collect_if_metrics(ip: str, community: str, timeout: int = 2) -> list[tuple]:
    """Zbiera metryki interfejsow (64-bit HC gdy dostepne, fallback na 32-bit).

    Zwraca liste krotek: (if_index: int, metric_name: str, value: float)

    OID-y:
      ifHCInOctets  (1.3.6.1.2.1.31.1.1.1.6)  — 64-bit bajty wchodzace
      ifHCOutOctets (1.3.6.1.2.1.31.1.1.1.10) — 64-bit bajty wychodzace
      ifInOctets    (1.3.6.1.2.1.2.2.1.10)    — 32-bit fallback wchodzace
      ifOutOctets   (1.3.6.1.2.1.2.2.1.16)    — 32-bit fallback wychodzace
      ifInErrors    (1.3.6.1.2.1.2.2.1.14)    — bledy wchodzace
      ifOutErrors   (1.3.6.1.2.1.2.2.1.20)    — bledy wychodzace
      ifInDiscards  (1.3.6.1.2.1.2.2.1.13)    — odrzucone wchodzace
      ifOutDiscards (1.3.6.1.2.1.2.2.1.19)    — odrzucone wychodzace
    """
    from netdoc.collector.snmp_walk import snmp_walk

    _OID_GROUPS = [
        # (oid_prefix, metric_name, is_hc)
        ("1.3.6.1.2.1.31.1.1.1.6",  "in_octets_hc",  True),
        ("1.3.6.1.2.1.31.1.1.1.10", "out_octets_hc", True),
        ("1.3.6.1.2.1.2.2.1.10",    "in_octets",     False),
        ("1.3.6.1.2.1.2.2.1.16",    "out_octets",    False),
        ("1.3.6.1.2.1.2.2.1.14",    "in_errors",     False),
        ("1.3.6.1.2.1.2.2.1.20",    "out_errors",    False),
        ("1.3.6.1.2.1.2.2.1.13",    "in_discards",   False),
        ("1.3.6.1.2.1.2.2.1.19",    "out_discards",  False),
    ]

    # Zbieramy ktore if_index maja HC (by pominac 32-bit duplikaty gdy HC dostepne)
    hc_indices: set = set()
    results: list[tuple] = []

    for oid_prefix, metric_name, is_hc in _OID_GROUPS:
        try:
            rows = snmp_walk(ip, oid_prefix, community, timeout=timeout, max_iter=512)
            for full_oid, raw_val, _ in rows:
                try:
                    # ifIndex jest ostatnim elementem OID: 1.3.6.1.2.1.2.2.1.10.5 → 5
                    if_index = int(full_oid.rstrip(".").rsplit(".", 1)[-1])
                    # raw_val to bytes z BER — dekoduj big-endian (Counter32/64/Gauge32)
                    if isinstance(raw_val, (bytes, bytearray)):
                        int_v = int.from_bytes(raw_val, "big") if raw_val else 0
                    else:
                        int_v = int(raw_val)
                    value = float(int_v)
                except (ValueError, TypeError, IndexError):
                    continue
                if is_hc:
                    hc_indices.add(if_index)
                results.append((if_index, metric_name, value))
        except Exception as exc:
            logger.debug("_collect_if_metrics %s %s: %s", ip, metric_name, exc)

    # Filtruj 32-bit octets gdy HC dostepne dla danego if_index
    # (unikamy duplikatu tego samego pomiaru w dwoch metrykach)
    filtered = []
    skip_32bit = {"in_octets", "out_octets"}
    for if_index, metric_name, value in results:
        if metric_name in skip_32bit and if_index in hc_indices:
            continue
        filtered.append((if_index, metric_name, value))

    return filtered


def _wait_for_schema(max_retries: int = 12, wait_s: int = 10) -> None:
    """Czeka az tabela devices bedzie dostepna (race condition przy swiezej bazie)."""
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
    logger.info("Netdoc SNMP Worker — default_interval=%ds workers=%d metrics=:%d",
                _DEFAULT_SNMP_INTERVAL, _DEFAULT_SNMP_WORKERS, METRICS_PORT)
    _wait_for_schema()
    init_db()
    try:
        from netdoc.storage.clickhouse import _ensure_metrics_table
        _ensure_metrics_table()
    except Exception as exc:
        logger.warning("ClickHouse metrics table init failed: %s — metryki IF beda pomijane", exc)
    start_http_server(METRICS_PORT)
    logger.info("Metrics: http://0.0.0.0:%d/metrics", METRICS_PORT)
    # PERF-02: sleep-until-next-run zamiast sleep-after-work
    interval = _DEFAULT_SNMP_INTERVAL
    while True:
        next_run = time.monotonic() + interval
        try:
            scan_once()
        except Exception as exc:
            logger.exception("Unhandled exception in scan_once: %s", exc)
        interval, *_ = _read_snmp_settings()
        time.sleep(max(0.0, next_run - time.monotonic()))


if __name__ == "__main__":
    main()
