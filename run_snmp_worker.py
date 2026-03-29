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
from datetime import datetime

from prometheus_client import Gauge, start_http_server

from netdoc.storage.database import SessionLocal, init_db
from netdoc.storage.models import Device, Credential, CredentialMethod, DeviceType, DeviceFieldHistory, InterfaceHistory

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

            if   field_id == 5:   # lldpRemChassisId — moze byc MAC
                if len(raw_val) == 6 if isinstance(raw_val, (bytes, bytearray)) else False:
                    mac = normalize_mac("".join(f"{b:02x}" for b in raw_val))
                    if mac:
                        entry["mac"] = mac
                else:
                    entry.setdefault("chassis_id", val)
            elif field_id == 9:   # lldpRemSysName
                entry["hostname"] = val
            elif field_id == 10:  # lldpRemSysDesc (sysDescr sasiada = firmware/model)
                entry["sys_desc"] = val
            elif field_id == 7:   # lldpRemPortId
                entry["remote_port"] = val
            elif field_id == 8:   # lldpRemPortDesc
                entry.setdefault("remote_port_desc", val)

    except Exception as exc:
        logger.debug("LLDP walk %s: %s", ip, exc)
        return []

    return [v for v in rows.values() if v.get("hostname") or v.get("mac")]


def _save_lldp_neighbors(db, src_device_id: int, src_ip: str, neighbors: list[dict], proto: str = "LLDP") -> int:
    """Upsertuje sasiadow LLDP jako Device w bazie. Zwraca liczbe zapisanych."""
    from netdoc.collector.discovery import upsert_device
    from netdoc.collector.normalizer import DeviceData, normalize_mac

    saved = 0
    for n in neighbors:
        ip = n.get("chassis_id")  # moze byc IP jako chassis ID
        hostname = n.get("hostname", "").strip()

        # Jesli chassis_id nie wyglada jak IP — szukamy urzadzenia po hostname
        if not ip or not _is_ip(ip):
            # Sprobuj znalezc po hostname
            if hostname:
                existing = db.query(Device).filter(Device.hostname == hostname).first()
                if existing:
                    # Uzupelnij dane jesli puste
                    changed = False
                    sys_desc = n.get("sys_desc", "")
                    if sys_desc and not existing.os_version:
                        existing.os_version = sys_desc[:120]
                        changed = True
                    if n.get("mac") and not existing.mac:
                        existing.mac = normalize_mac(n["mac"])
                        changed = True
                    if changed:
                        db.commit()
                        saved += 1
            continue  # nie mamy IP → nie mozemy zrobic upsert

        # CDP uses "software"+"platform", LLDP uses "sys_desc", EDP uses "software"
        os_ver = (n.get("sys_desc") or n.get("software") or "")[:120] or None
        vendor_hint = n.get("platform") or None  # CDP platform e.g. "cisco WS-C3750X-48P"
        data = DeviceData(
            ip         = ip,
            mac        = normalize_mac(n.get("mac")),
            hostname   = hostname or None,
            os_version = os_ver,
            vendor     = vendor_hint,
        )
        try:
            upsert_device(db, data)
            db.commit()
            saved += 1
            logger.info("%s neighbor: %-18s hostname=%-28s via %s port=%s",
                        proto, ip, hostname or "-", src_ip, n.get("local_port", "?"))
        except Exception as exc:
            logger.debug("LLDP save error %s: %s", ip, exc)
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

            entry = rows.setdefault(key, {"local_port_idx": if_idx})

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
# sysUpTime + Entity MIB serial enrichment — dodawane w trakcie normalnego pollu
# ---------------------------------------------------------------------------
OID_SYSUPTIME   = "1.3.6.1.2.1.1.3.0"
OID_ENT_SERIAL  = "1.3.6.1.2.1.47.1.1.1.1.11.1"  # entPhysicalSerialNum chassis


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
            # Community przestalo dzialac — wyczysc, community-worker znajdzie nowe
            logger.info("Community '%s' no longer responds for %s — clearing", community, ip)
            device.snmp_community = None
            device.snmp_ok_at     = None
            db.commit()
            return result

        result["success"]   = True
        result["community"] = community

        sysdescr = _snmp_get(ip, community, OID_SYSDESCR,   timeout=snmp_timeout)
        sysloc   = _snmp_get(ip, community, OID_SYSLOCATION, timeout=snmp_timeout)
        uptime   = _snmp_get(ip, community, OID_SYSUPTIME,   timeout=snmp_timeout)
        contact  = _snmp_get(ip, community, OID_SYSCONTACT,  timeout=snmp_timeout)

        # Zmiana detekcja: porównaj bieżące wartości z nowym odczytem SNMP.
        # Historia logowana gdy pole już było ustawione (old != None) i SNMP zwraca inną wartość.
        # Samo update'owanie pola "tylko gdy puste" — zachowane dla compat z manualną edycją.
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
                db.add(DeviceFieldHistory(
                    device_id=device_id,
                    field_name=_field,
                    old_value=str(_old),
                    new_value=str(_new),
                    source="snmp",
                ))
                logger.info("Field change %s [%s]: %r → %r", ip, _field, _old, _new)

        if sysname  and not device.hostname:   device.hostname   = sysname
        if sysdescr and not device.os_version: device.os_version = sysdescr[:120]
        if sysloc   and not device.location:   device.location   = sysloc
        if contact and contact.strip() and not device.sys_contact: device.sys_contact = contact.strip()[:255]

        # sysUpTime — zapisuj do dedykowanej kolumny; wyczyść stary tag z asset_notes
        if uptime is not None:
            device.snmp_uptime = _timeticks_to_str(uptime)
            if device.asset_notes:
                import re as _re
                device.asset_notes = _re.sub(r'\[uptime [^\]]*\]\n?', '', device.asset_notes).strip() or None

        # Serial number (Entity MIB) — uzupelnij raz jesli puste
        if not device.serial_number:
            try:
                serial = _snmp_get(ip, community, OID_ENT_SERIAL, timeout=snmp_timeout)
                if serial and str(serial).strip() not in ("", "0", ".."):
                    device.serial_number = str(serial).strip()[:255]
                    logger.info("Serial %-18s: %s", ip, device.serial_number)
            except Exception:
                pass  # brak Entity MIB — normalne dla prostych urzadzen

        device.snmp_ok_at = datetime.utcnow()

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
    result = []
    for v in rows.values():
        if v.get("arp_type") == 2:
            continue  # invalid entry
        mac = v.get("mac", "").upper()
        if mac and (mac.startswith("FF:FF") or mac.startswith("01:")):
            continue  # broadcast/multicast
        if v.get("mac"):  # potrzebujemy MAC żeby nie śmiecić w DB
            result.append(v)
    return result


# ---------------------------------------------------------------------------
# Interface walk — zbiera ifDescr, ifOperStatus, ifSpeed z ifTable
# ---------------------------------------------------------------------------
_IF_TABLE_OID    = "1.3.6.1.2.1.2.2.1"   # ifEntry
_IF_DESCR_ID     = 2   # ifDescr
_IF_OPERSTATUS_ID= 8   # ifOperStatus: 1=up, 2=down, 3=testing, ...
_IF_SPEED_ID     = 5   # ifSpeed (bps)


def _enrich_interfaces(ip: str, community: str, timeout: int = 2) -> list[dict]:
    """Czyta ifTable przez SNMP walk — zwraca listę {name, oper_status, speed_bps}.

    Ignoruje loopback (lo) i interfejsy bez nazwy.
    """
    from netdoc.collector.snmp_walk import snmp_walk

    ifaces: dict[str, dict] = {}  # klucz: ifIndex (str)
    try:
        for oid_str, raw_val, _tag in snmp_walk(
            ip, _IF_TABLE_OID, community=community, timeout=timeout, max_iter=1000
        ):
            suffix = oid_str[len(_IF_TABLE_OID):].lstrip(".")
            parts = suffix.split(".", 1)
            if len(parts) < 2:
                continue
            try:
                field_id = int(parts[0])
                if_index = parts[1]
            except ValueError:
                continue
            entry = ifaces.setdefault(if_index, {"index": if_index})
            if field_id == _IF_DESCR_ID:
                try:
                    entry["name"] = (
                        raw_val.decode("utf-8", errors="replace")
                        if isinstance(raw_val, (bytes, bytearray))
                        else str(raw_val)
                    ).strip()
                except Exception:
                    pass
            elif field_id == _IF_OPERSTATUS_ID:
                try:
                    entry["oper_status"] = int(raw_val)
                except (TypeError, ValueError):
                    pass
            elif field_id == _IF_SPEED_ID:
                try:
                    entry["speed_bps"] = int(raw_val)
                except (TypeError, ValueError):
                    pass
    except Exception as exc:
        logger.debug("IF walk %s: %s", ip, exc)
        return []

    result = []
    for v in ifaces.values():
        name = v.get("name", "")
        if not name or name.lower() in ("lo", "loopback"):
            continue
        result.append({
            "name":        name,
            "oper_status": v.get("oper_status"),
            "speed_bps":   v.get("speed_bps"),
        })
    return result


def _save_interface_history(db, device_id: int, ifaces: list[dict]) -> int:
    """Porównuje stan interfejsów z ostatnim wpisem w historii i zapisuje zmiany.

    Model InterfaceHistory:
      event_type: "discovered" | "up" | "down" | "speed_change"
      old_speed:  poprzednia prędkość (bps), None przy "discovered"/"up"/"down"
      new_speed:  nowa prędkość (bps), None przy "up"/"down"
    Zwraca liczbę zapisanych wpisów.
    """
    saved = 0
    for iface in ifaces:
        name    = iface["name"]
        new_st  = iface.get("oper_status")   # 1=up, 2=down, inne=unknown
        new_spd = iface.get("speed_bps")

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
        # Pomijamy IP samego urzadzenia ktore pytamy
        if neighbor_ip == src_ip:
            continue
        data = DeviceData(ip=neighbor_ip, mac=e.get("mac"))
        try:
            upsert_device(db, data)
            db.commit()
            saved += 1
        except Exception as exc:
            logger.debug("ARP save error %s: %s", neighbor_ip, exc)
            db.rollback()
    return saved


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
        g_polled.set(0); g_success.set(0); g_failed.set(0)
        return

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
    # Uruchamiamy tylko dla urzadzen ktore wyglądają na routing (router/switch/firewall/unknown)
    _L3_TYPES = {DeviceType.router, DeviceType.switch, DeviceType.firewall, DeviceType.unknown}
    arp_candidates = [d for d in devices if d.snmp_community and d.device_type in _L3_TYPES]
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

    # Interface walk — zbiera ifTable i zapisuje zmiany do interface_history
    if_changed = 0
    db_if = SessionLocal()
    try:
        for d in devices:
            ifaces = _enrich_interfaces(d.ip, d.snmp_community, timeout=snmp_timeout)
            if ifaces:
                n = _save_interface_history(db_if, d.id, ifaces)
                if n:
                    if_changed += n
                    logger.info("IF   %-18s: %d interface change(s)", d.ip, n)
    except Exception as exc:
        logger.warning("Interface walk error: %s", exc)
    finally:
        db_if.close()
    if if_changed:
        logger.info("Interface history total: %d new entries", if_changed)


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
