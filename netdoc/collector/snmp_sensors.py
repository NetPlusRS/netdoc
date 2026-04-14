"""netdoc.collector.snmp_sensors — SNMP sensor polling.

Reads environmental & performance sensors from network devices using SNMP.
No vendor MIB files required — uses pure OID trees with known structures.

Coverage layers (tried in order for every device):
  1. ENTITY-SENSOR-MIB  (RFC 3433)  — standard, works on Cisco/HP/Juniper/Aruba/Extreme
  2. HOST-RESOURCES-MIB (RFC 2790)  — CPU load, RAM, storage on Linux/Windows/BSD SNMP agents
  3. UCD-SNMP-MIB       (Net-SNMP)  — detailed CPU/memory on Linux with net-snmp
  4. IF-MIB extended                — per-interface error/discard counters
  5. Vendor-specific OIDs           — keyed by detected vendor string:
       Cisco   (CISCO-ENVMON + CISCO-PROCESS)
       MikroTik
       Ubiquiti / UniFi
       HP / ProCurve / Aruba
       Juniper
       Huawei
       Fortinet FortiGate
       pfSense / OPNsense (via Net-SNMP)
       Synology NAS
       QNAP NAS
       APC / Schneider UPS
       Eaton UPS
       Linux generic (via ucdavis)

Each source returns a list of dicts:
  {"name": str, "value": float|None, "unit": str, "raw": str, "source": str}

The worker calls poll_sensors(ip, community, vendor_hint, timeout) which
tries all applicable sources and merges results — deduplicated by name.
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ─── helpers ──────────────────────────────────────────────────────────────────

def _walk(ip: str, base_oid: str, community: str, timeout: float, max_iter: int = 500):
    from netdoc.collector.snmp_walk import snmp_walk
    return snmp_walk(ip, base_oid, community=community, timeout=timeout, max_iter=max_iter)


def _get(ip: str, oid: str, community: str, timeout: float):
    """Single SNMP GET dla konkretnego OID (skalara lub wiersza tabeli).

    Używa prawdziwego GET (nie GETNEXT/walk) żeby uderzyć dokładnie w podany OID.
    Fallback na GETNEXT gdy GET nie zadziała (stare urządzenia / MIB subtree).
    """
    try:
        from netdoc.collector.drivers.snmp import _snmp_get
        val = _snmp_get(ip, community, oid, timeout=int(timeout))
        if val is not None:
            return val, None
    except Exception:
        pass
    # Fallback: GETNEXT z weryfikacją OID
    from netdoc.collector.snmp_walk import snmp_walk
    rows = snmp_walk(ip, oid, community=community, timeout=timeout, max_iter=1)
    if rows:
        ret_oid, val, tag = rows[0]
        if ret_oid == oid or ret_oid.startswith(oid + "."):
            return val, tag
    return None, None


def _int_val(raw) -> Optional[int]:
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        if not raw:
            return None
        v = 0
        for b in raw:
            v = (v << 8) | b
        return v
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _str_val(raw) -> str:
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        return raw.decode("utf-8", errors="replace").strip()
    return str(raw).strip()


def _sensor(name: str, value, unit: str, source: str, raw: str = "") -> dict:
    try:
        fval = float(value)
    except (TypeError, ValueError):
        fval = None
    return {"name": name, "value": fval, "unit": unit, "source": source,
            "raw": raw or (str(value) if value is not None else "")}


# ─── 1. ENTITY-SENSOR-MIB (RFC 3433) ─────────────────────────────────────────
# entPhySensorTable: 1.3.6.1.2.1.99.1.1
#  .1  entPhySensorType      (1=other,2=unknown,3=voltsAC,4=voltsDC,5=amperes,
#                             6=watts,7=hertz,8=celsius,9=percentRH,10=rpm,
#                             11=cmm,12=truthvalue,13=specialEnum,14=dBm)
#  .2  entPhySensorScale     (-24=yocto..0=units..24=yotta; common: -3=milli,0=units,3=kilo)
#  .3  entPhySensorPrecision (decimal places)
#  .4  entPhySensorValue     (integer, scaled by scale/precision)
#  .5  entPhySensorOperStatus (1=ok,2=unavailable,3=nonoperational)
#
# entPhysicalName: 1.3.6.1.2.1.47.1.1.1.1.7  — human name per index
# entPhysicalDescr: 1.3.6.1.2.1.47.1.1.1.1.2

_ENT_SENSOR_TABLE   = "1.3.6.1.2.1.99.1.1"
_ENT_PHYS_NAME      = "1.3.6.1.2.1.47.1.1.1.1.7"
_ENT_PHYS_DESCR     = "1.3.6.1.2.1.47.1.1.1.1.2"

_ENT_TYPE_UNIT = {
    3: "V",     # voltsAC
    4: "V",     # voltsDC
    5: "A",     # amperes
    6: "W",     # watts
    7: "Hz",    # hertz
    8: "°C",    # celsius
    9: "%",     # percentRH
    10: "rpm",  # rpm
    11: "m³/min",
    14: "dBm",
}

_ENT_SCALE_EXP = {
    -24: -24, -21: -21, -18: -18, -15: -15, -12: -12, -9: -9,
    -6: -6, -3: -3, 0: 0, 3: 3, 6: 6, 9: 9,
}


def _entity_sensor_mib(ip: str, community: str, timeout: float) -> list[dict]:
    """Reads ENTITY-SENSOR-MIB — most complete standard-based sensor source."""
    results = []

    # Collect sensor table: type, scale, precision, value, status per index
    sensors: dict[str, dict] = {}
    for oid_str, raw_val, _tag in _walk(ip, _ENT_SENSOR_TABLE, community, timeout, max_iter=2000):
        suffix = oid_str[len(_ENT_SENSOR_TABLE):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) < 2:
            continue
        field = int(parts[0])
        idx   = ".".join(parts[1:])
        entry = sensors.setdefault(idx, {})
        iv = _int_val(raw_val)
        if field == 1:   entry["type"]      = iv
        elif field == 2: entry["scale"]     = iv
        elif field == 3: entry["precision"] = iv
        elif field == 4: entry["value"]     = iv
        elif field == 5: entry["status"]    = iv

    if not sensors:
        return results

    # Collect physical names for sensor indices
    names: dict[str, str] = {}
    for oid_str, raw_val, _tag in _walk(ip, _ENT_PHYS_NAME, community, timeout, max_iter=2000):
        idx = oid_str[len(_ENT_PHYS_NAME):].lstrip(".")
        names[idx] = _str_val(raw_val)

    descrs: dict[str, str] = {}
    for oid_str, raw_val, _tag in _walk(ip, _ENT_PHYS_DESCR, community, timeout, max_iter=2000):
        idx = oid_str[len(_ENT_PHYS_DESCR):].lstrip(".")
        descrs[idx] = _str_val(raw_val)

    type_counter: dict[int, int] = {}
    for idx, s in sensors.items():
        stype  = s.get("type", 0) or 0
        scale  = s.get("scale", 0) or 0
        prec   = s.get("precision", 0) or 0
        raw_v  = s.get("value")
        status = s.get("status", 1) or 1
        if status != 1 or raw_v is None:
            continue
        unit = _ENT_TYPE_UNIT.get(stype, "")
        if not unit:
            continue  # skip unknown/boolean/enum sensor types

        # Scale: value * 10^(scale_exp - precision)
        exp = _ENT_SCALE_EXP.get(scale, 0) - (prec or 0)
        try:
            fval = raw_v * (10 ** exp)
        except Exception:
            fval = float(raw_v)

        # Build sensor name from physical entity name/description
        phys_name = names.get(idx) or descrs.get(idx) or ""
        phys_name = phys_name.strip()

        type_counter[stype] = type_counter.get(stype, 0) + 1
        n = type_counter[stype]
        type_label = {3: "voltage_ac", 4: "voltage_dc", 5: "current",
                      6: "power", 7: "freq", 8: "temp", 9: "humidity",
                      10: "fan", 11: "airflow", 14: "optical_power"}.get(stype, f"sensor{stype}")

        # Use physical name if meaningful, otherwise numbered
        if phys_name and len(phys_name) > 1:
            # Sanitize: lowercase, spaces→underscore, strip special
            clean = phys_name.lower().replace(" ", "_").replace("/", "_")
            clean = "".join(c for c in clean if c.isalnum() or c == "_")
            name = f"{type_label}_{clean}" if not clean.startswith(type_label[:4]) else clean
        else:
            name = f"{type_label}_{n}" if n > 1 else type_label

        results.append(_sensor(name, fval, unit, "entity_sensor", str(raw_v)))

    return results


# ─── 2. HOST-RESOURCES-MIB (RFC 2790) ─────────────────────────────────────────
# hrProcessorLoad: 1.3.6.1.2.1.25.3.3.1.2  — CPU load % per processor
# hrStorageTable:  1.3.6.1.2.1.25.2.3.1    — storage: RAM, disks
#   .2  hrStorageType
#   .4  hrStorageAllocationUnits  (bytes per block)
#   .5  hrStorageSize             (total blocks)
#   .6  hrStorageUsed             (used blocks)
# hrStorageTypes:
#   1.3.6.1.2.1.25.2.1.2 = RAM
#   1.3.6.1.2.1.25.2.1.3 = Virtual memory
#   1.3.6.1.2.1.25.2.1.4 = Fixed disk
#   1.3.6.1.2.1.25.2.1.10 = FlashMemory

_HR_CPU_LOAD    = "1.3.6.1.2.1.25.3.3.1.2"
_HR_STORAGE     = "1.3.6.1.2.1.25.2.3.1"
_HR_RAM_TYPE    = "1.3.6.1.2.1.25.2.1.2"
_HR_VMEM_TYPE   = "1.3.6.1.2.1.25.2.1.3"
_HR_DISK_TYPE   = "1.3.6.1.2.1.25.2.1.4"
_HR_FLASH_TYPE  = "1.3.6.1.2.1.25.2.1.10"


def _host_resources_mib(ip: str, community: str, timeout: float) -> list[dict]:
    """Reads HOST-RESOURCES-MIB — CPU load and memory/storage usage."""
    results = []

    # CPU load — average across all cores
    cpu_vals = []
    for oid_str, raw_val, _tag in _walk(ip, _HR_CPU_LOAD, community, timeout, max_iter=64):
        v = _int_val(raw_val)
        if v is not None and 0 <= v <= 100:
            cpu_vals.append(v)
    if cpu_vals:
        avg_cpu = sum(cpu_vals) / len(cpu_vals)
        results.append(_sensor("cpu_load", round(avg_cpu, 1), "%", "host_resources"))
        if len(cpu_vals) > 1:
            for i, v in enumerate(cpu_vals, 1):
                results.append(_sensor(f"cpu{i}_load", v, "%", "host_resources"))

    # Storage table
    storage: dict[str, dict] = {}
    for oid_str, raw_val, _tag in _walk(ip, _HR_STORAGE, community, timeout, max_iter=500):
        suffix = oid_str[len(_HR_STORAGE):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) < 2:
            continue
        field = int(parts[0])
        idx   = parts[1]
        entry = storage.setdefault(idx, {})
        if field == 2:   entry["type"]  = _str_val(raw_val)
        elif field == 4: entry["alloc"] = _int_val(raw_val)
        elif field == 5: entry["total"] = _int_val(raw_val)
        elif field == 6: entry["used"]  = _int_val(raw_val)

    ram_n = disk_n = flash_n = 0
    for idx, s in storage.items():
        stype = s.get("type", "")
        alloc = s.get("alloc") or 0
        total = s.get("total") or 0
        used  = s.get("used")
        if not alloc or not total or used is None:
            continue
        total_bytes = total * alloc
        used_bytes  = used  * alloc
        pct = round(used_bytes / total_bytes * 100, 1) if total_bytes else 0

        if _HR_RAM_TYPE in stype or "ram" in stype.lower():
            ram_n += 1
            sfx = f"_{ram_n}" if ram_n > 1 else ""
            results.append(_sensor(f"ram_used_pct{sfx}", pct, "%", "host_resources"))
            results.append(_sensor(f"ram_used_mb{sfx}", round(used_bytes / 1048576, 1), "MB", "host_resources"))
            results.append(_sensor(f"ram_total_mb{sfx}", round(total_bytes / 1048576, 1), "MB", "host_resources"))
        elif _HR_DISK_TYPE in stype or "fixeddisk" in stype.lower():
            disk_n += 1
            sfx = f"_{disk_n}" if disk_n > 1 else ""
            results.append(_sensor(f"disk_used_pct{sfx}", pct, "%", "host_resources"))
            results.append(_sensor(f"disk_used_gb{sfx}", round(used_bytes / 1073741824, 2), "GB", "host_resources"))
            results.append(_sensor(f"disk_total_gb{sfx}", round(total_bytes / 1073741824, 2), "GB", "host_resources"))
        elif _HR_FLASH_TYPE in stype or "flash" in stype.lower():
            flash_n += 1
            sfx = f"_{flash_n}" if flash_n > 1 else ""
            results.append(_sensor(f"flash_used_pct{sfx}", pct, "%", "host_resources"))

    return results


# ─── 3. UCD-SNMP / Net-SNMP (Linux agents) ───────────────────────────────────
# memTotalReal:  1.3.6.1.4.1.2021.4.5.0
# memAvailReal:  1.3.6.1.4.1.2021.4.6.0
# laLoad (1min): 1.3.6.1.4.1.2021.10.1.3.1
# laLoad (5min): 1.3.6.1.4.1.2021.10.1.3.2
# ssCpuUser:     1.3.6.1.4.1.2021.11.9.0
# ssCpuSystem:   1.3.6.1.4.1.2021.11.10.0
# ssCpuIdle:     1.3.6.1.4.1.2021.11.11.0

_UCD_BASE = "1.3.6.1.4.1.2021"


def _ucd_snmp_mib(ip: str, community: str, timeout: float) -> list[dict]:
    """Reads UCD-SNMP MIB (Net-SNMP on Linux) — load avg, CPU breakdown, RAM."""
    results = []
    oids = {
        "1.3.6.1.4.1.2021.4.5.0":   ("ram_total_kb", "KB"),
        "1.3.6.1.4.1.2021.4.6.0":   ("ram_avail_kb", "KB"),
        "1.3.6.1.4.1.2021.10.1.3.1":("load_avg_1m", ""),
        "1.3.6.1.4.1.2021.10.1.3.2":("load_avg_5m", ""),
        "1.3.6.1.4.1.2021.11.9.0":  ("cpu_user_pct", "%"),
        "1.3.6.1.4.1.2021.11.10.0": ("cpu_system_pct", "%"),
        "1.3.6.1.4.1.2021.11.11.0": ("cpu_idle_pct", "%"),
    }
    for oid, (name, unit) in oids.items():
        val, tag = _get(ip, oid, community, timeout)
        if val is None:
            continue
        sv = _str_val(val)
        try:
            fval = float(sv)
        except ValueError:
            continue
        # load_avg strings come as "0.25" etc
        results.append(_sensor(name, fval, unit, "ucd_snmp", sv))

    # Compute RAM used% if we got total + avail
    total = next((r["value"] for r in results if r["name"] == "ram_total_kb"), None)
    avail = next((r["value"] for r in results if r["name"] == "ram_avail_kb"), None)
    if total and avail and total > 0:
        used_pct = round((total - avail) / total * 100, 1)
        results.append(_sensor("ram_used_pct", used_pct, "%", "ucd_snmp"))

    return results


# ─── 4. Cisco ENVMON + PROCESS MIBs ──────────────────────────────────────────
# CISCO-ENVMON-MIB:
#   ciscoEnvMonTemperatureTable: 1.3.6.1.4.1.9.9.13.1.3.1
#     .3  ciscoEnvMonTemperatureStatusValue  (°C)
#     .6  ciscoEnvMonTemperatureState (1=normal,2=warning,3=critical,4=shutdown,5=notPresent,6=notFunctioning)
#   ciscoEnvMonVoltageTable: 1.3.6.1.4.1.9.9.13.1.2.1
#     .3  ciscoEnvMonVoltageStatusValue (mV)
#   ciscoEnvMonFanTable: 1.3.6.1.4.1.9.9.13.1.4.1
#     .3  ciscoEnvMonFanState
#   ciscoEnvMonSupplyTable: 1.3.6.1.4.1.9.9.13.1.5.1
#     .3  ciscoEnvMonSupplyState
#
# CISCO-PROCESS-MIB:
#   cpmCPUTotalTable: 1.3.6.1.4.1.9.9.109.1.1.1.1
#     .6  cpmCPUTotal5minRev (%)
#     .8  cpmCPUMemoryUsed   (KB)
#     .9  cpmCPUMemoryFree   (KB)

_CISCO_TEMP    = "1.3.6.1.4.1.9.9.13.1.3.1"
_CISCO_VOLT    = "1.3.6.1.4.1.9.9.13.1.2.1"
_CISCO_FAN     = "1.3.6.1.4.1.9.9.13.1.4.1"
_CISCO_SUPPLY  = "1.3.6.1.4.1.9.9.13.1.5.1"
_CISCO_CPU     = "1.3.6.1.4.1.9.9.109.1.1.1.1"
# CISCO-MEMORY-POOL-MIB: ciscoMemoryPoolTable (bardziej niezawodne niż cpmCPUMemory)
# .2 = ciscoMemoryPoolName (string)
# .5 = ciscoMemoryPoolUsed (bytes, Gauge32)
# .6 = ciscoMemoryPoolFree (bytes, Gauge32)
_CISCO_MEM_POOL = "1.3.6.1.4.1.9.9.48.1.1.1"
# CISCO-FLASH-MIB: ciscoFlashPartitionTable
# .4.deviceIdx.partIdx = ciscoFlashPartitionSize (KB)
# .5.deviceIdx.partIdx = ciscoFlashPartitionSizeFree (KB)
# .11.deviceIdx.partIdx = ciscoFlashPartitionName (string)
_CISCO_FLASH_PART = "1.3.6.1.4.1.9.9.10.1.1.3.1"


def _cisco_envmon(ip: str, community: str, timeout: float) -> list[dict]:
    results = []

    # Temperature
    temps: dict[str, dict] = {}
    for oid_str, raw_val, _tag in _walk(ip, _CISCO_TEMP, community, timeout, max_iter=200):
        suffix = oid_str[len(_CISCO_TEMP):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) < 2:
            continue
        field, idx = int(parts[0]), parts[1]
        entry = temps.setdefault(idx, {})
        if field == 2:   entry["descr"] = _str_val(raw_val)
        elif field == 3: entry["value"] = _int_val(raw_val)
        elif field == 6: entry["state"] = _int_val(raw_val)

    for i, (idx, t) in enumerate(temps.items(), 1):
        v = t.get("value")
        state = t.get("state", 1) or 1
        if v is not None and state != 5:  # 5=notPresent
            descr = t.get("descr") or f"temp_{i}"
            clean = descr.lower().replace(" ", "_").replace("/", "_")
            clean = "".join(c for c in clean if c.isalnum() or c == "_")
            results.append(_sensor(f"temp_{clean}" if not clean.startswith("temp") else clean,
                                   v, "°C", "cisco_envmon"))

    # Voltage (mV → V)
    volts: dict[str, dict] = {}
    for oid_str, raw_val, _tag in _walk(ip, _CISCO_VOLT, community, timeout, max_iter=100):
        suffix = oid_str[len(_CISCO_VOLT):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) < 2: continue
        field, idx = int(parts[0]), parts[1]
        entry = volts.setdefault(idx, {})
        if field == 2:   entry["descr"] = _str_val(raw_val)
        elif field == 3: entry["value"] = _int_val(raw_val)

    for i, (idx, v) in enumerate(volts.items(), 1):
        mv = v.get("value")
        if mv is not None:
            descr = v.get("descr") or f"volt_{i}"
            clean = "".join(c for c in descr.lower().replace(" ", "_") if c.isalnum() or c == "_")
            results.append(_sensor(f"voltage_{clean}", round(mv / 1000, 3), "V", "cisco_envmon"))

    # Fan state (1=normal, 2=warning, 3=critical, 4=shutdown, 5=notPresent, 6=notFunctioning)
    fans: dict[str, dict] = {}
    for oid_str, raw_val, _tag in _walk(ip, _CISCO_FAN, community, timeout, max_iter=100):
        suffix = oid_str[len(_CISCO_FAN):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) < 2: continue
        field, idx = int(parts[0]), parts[1]
        entry = fans.setdefault(idx, {})
        if field == 2:   entry["descr"] = _str_val(raw_val)
        elif field == 3: entry["state"] = _int_val(raw_val)

    for i, (idx, f) in enumerate(fans.items(), 1):
        state = f.get("state", 1) or 1
        if state not in (1, 5):  # skip "notPresent"
            descr = f.get("descr") or f"fan_{i}"
            clean = "".join(c for c in descr.lower().replace(" ", "_") if c.isalnum() or c == "_")
            # 1=ok(1.0), 2=warning(0.5), 3/4/6=critical(0.0)
            ok_val = 1.0 if state == 1 else (0.5 if state == 2 else 0.0)
            results.append(_sensor(f"fan_{clean}_ok" if not clean.startswith("fan") else f"{clean}_ok",
                                   ok_val, "", "cisco_envmon",
                                   raw={1:"normal",2:"warning",3:"critical",4:"shutdown",6:"notFunctioning"}.get(state,str(state))))

    # CPU (5-min average) — tylko pole 6 (cpmCPUTotal5minRev), bez pól pamięci
    # Pola 8/9 (cpmCPUMemoryUsed/Free) są na wielu urządzeniach Cisco niedostępne
    # lub zwracają błędne wartości — pamięć zbieramy z ciscoMemoryPoolTable.
    cpu: dict[str, dict] = {}
    for oid_str, raw_val, _tag in _walk(ip, _CISCO_CPU, community, timeout, max_iter=100):
        suffix = oid_str[len(_CISCO_CPU):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) < 2: continue
        field, idx = int(parts[0]), parts[1]
        entry = cpu.setdefault(idx, {})
        if field == 6: entry["cpu5m"] = _int_val(raw_val)

    for i, (idx, c) in enumerate(cpu.items(), 1):
        sfx = f"_{i}" if i > 1 else ""
        if c.get("cpu5m") is not None:
            results.append(_sensor(f"cpu_load_5m{sfx}", c["cpu5m"], "%", "cisco_process"))

    # RAM — CISCO-MEMORY-POOL-MIB (ciscoMemoryPoolTable)
    # Indeks: 1=Processor, 2=I/O, pozostałe pomijamy
    # Pool "Processor" to główna pamięć systemu IOS
    mem_pools: dict[str, dict] = {}
    for oid_str, raw_val, _tag in _walk(ip, _CISCO_MEM_POOL, community, timeout, max_iter=200):
        suffix = oid_str[len(_CISCO_MEM_POOL):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) < 2: continue
        field, idx = int(parts[0]), parts[1]
        entry = mem_pools.setdefault(idx, {})
        if field == 2:   entry["name"] = _str_val(raw_val)
        elif field == 5: entry["used"] = _int_val(raw_val)   # bytes
        elif field == 6: entry["free"] = _int_val(raw_val)   # bytes

    for idx, pool in mem_pools.items():
        name = pool.get("name", "")
        used = pool.get("used")
        free = pool.get("free")
        if used is None or free is None or (used + free) <= 0:
            continue
        total = used + free
        pct = round(used / total * 100, 1)
        if name.lower() in ("processor", ""):
            # Główna pamięć — bez sufiksu (wyświetlana jako główna)
            results.append(_sensor("mem_used_pct", pct, "%", "cisco_process"))
            results.append(_sensor("mem_used_mb", round(used / 1048576, 1), "MB", "cisco_process"))
            results.append(_sensor("mem_total_mb", round(total / 1048576, 1), "MB", "cisco_process"))
        elif name.lower() in ("i/o", "io"):
            results.append(_sensor("mem_io_used_pct", pct, "%", "cisco_process"))

    # Flash — CISCO-FLASH-MIB ciscoFlashPartitionTable
    # OID: _CISCO_FLASH_PART.field.deviceIdx.partIdx
    flash_parts: dict[str, dict] = {}
    for oid_str, raw_val, _tag in _walk(ip, _CISCO_FLASH_PART, community, timeout, max_iter=100):
        suffix = oid_str[len(_CISCO_FLASH_PART):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) < 3: continue
        field = int(parts[0])
        key = f"{parts[1]}.{parts[2]}"  # deviceIdx.partIdx
        entry = flash_parts.setdefault(key, {})
        if field == 4:   entry["size_kb"]  = _int_val(raw_val)   # KB
        elif field == 5: entry["free_kb"]  = _int_val(raw_val)   # KB
        elif field == 11: entry["name"]    = _str_val(raw_val)

    for i, (key, fp) in enumerate(flash_parts.items(), 1):
        size_kb = fp.get("size_kb")
        free_kb = fp.get("free_kb")
        if size_kb is None or size_kb <= 0:
            continue
        used_kb = size_kb - (free_kb or 0)
        pct = round(used_kb / size_kb * 100, 1) if size_kb > 0 else 0
        sfx = f"_{i}" if i > 1 else ""
        results.append(_sensor(f"flash_used_pct{sfx}", pct, "%", "cisco_flash"))
        results.append(_sensor(f"flash_total_mb{sfx}", round(size_kb / 1024, 1), "MB", "cisco_flash"))

    return results


# ─── 5. MikroTik ─────────────────────────────────────────────────────────────
# MIKROTIK-MIB: 1.3.6.1.4.1.14988.1.1
#   .3.10   mtxrHlTemperature      (°C × 10)
#   .3.11   mtxrHlProcessorTemperature (°C × 10)
#   .3.100  mtxrHlCpuTemperature   (°C × 10, newer models)
#   .7.4    mtxrCPULoad (%)
#   .6.1    mtxrHlFreeMemory (bytes)
#   .6.2    mtxrHlTotalMemory (bytes)
#   .6.3    mtxrHlFreeHddSpace (bytes)
#   .6.5    mtxrHlVoltage (V × 10)
#   .6.6    mtxrHlActiveFan (rpm)
#   .6.9    mtxrHlBoardTemp (°C × 10)

_MTIK_BASE = "1.3.6.1.4.1.14988.1.1"


def _mikrotik(ip: str, community: str, timeout: float) -> list[dict]:
    results = []
    oids = {
        "1.3.6.1.4.1.14988.1.1.3.10":  ("temp_cpu",      10, "°C"),
        "1.3.6.1.4.1.14988.1.1.3.11":  ("temp_processor",10, "°C"),
        "1.3.6.1.4.1.14988.1.1.3.100": ("temp_cpu2",     10, "°C"),
        "1.3.6.1.4.1.14988.1.1.7.4":   ("cpu_load",      1,  "%"),
        "1.3.6.1.4.1.14988.1.1.6.1":   ("ram_free",      1,  "B"),
        "1.3.6.1.4.1.14988.1.1.6.2":   ("ram_total",     1,  "B"),
        "1.3.6.1.4.1.14988.1.1.6.3":   ("hdd_free",      1,  "B"),
        "1.3.6.1.4.1.14988.1.1.6.5":   ("voltage",       10, "V"),
        "1.3.6.1.4.1.14988.1.1.6.6":   ("fan_rpm",       1,  "rpm"),
        "1.3.6.1.4.1.14988.1.1.6.9":   ("temp_board",    10, "°C"),
    }
    raw_vals = {}
    for oid, (name, divisor, unit) in oids.items():
        val, tag = _get(ip, oid, community, timeout)
        if val is None:
            continue
        iv = _int_val(val)
        if iv is None:
            continue
        fval = round(iv / divisor, 2) if divisor != 1 else iv
        results.append(_sensor(name, fval, unit, "mikrotik"))
        raw_vals[name] = fval

    # RAM used %
    rt = raw_vals.get("ram_total")
    rf = raw_vals.get("ram_free")
    if rt and rf and rt > 0:
        results.append(_sensor("ram_used_pct", round((rt - rf) / rt * 100, 1), "%", "mikrotik"))

    return results


# ─── 6. Ubiquiti / UniFi ─────────────────────────────────────────────────────
#
# Layer A — UniFi AP sysinfo (1.3.6.1.4.1.41112.1.6.1.2.1)
#   .3  unifiApSystemCpuLoad    (%)
#   .4  unifiApSystemMemUsed    (KB)
#   .5  unifiApSystemMemTotal   (KB)
#
# Layer B — UBNT-AirOS generic scalars (1.3.6.1.4.1.41112.1.7.8)
#   .3  ubntHostCpuLoad         (0–65535 → /655.35 = %)
#   .4  ubntHostTemperature     (°C, integer)
#
# Layer C — lmsensors MIB (1.3.6.1.4.1.2021.13.16)  — UDM/UDMP Linux net-snmp
#   lmTempSensorsTable  .2.1.{2,3}.idx  name / value (millidegrees °C → /1000)
#   lmFanSensorsTable   .3.1.{2,3}.idx  name / value (RPM)
#   lmMiscSensorsTable  .5.1.{2,3}.idx  name / value (mV*1000 → /1000 = V for voltage)
#
# Layer D — EdgeSwitch / EdgeRouter (1.3.6.1.4.1.4413.1.1.43.1)
#   Fan table     .6.1.{2,3,4}.idx  descr / state (2=ok) / speed RPM
#   Temp table    .8.1.{3,4,5}.idx  descr / state / value °C
#
# Layer E — AirMAX / AirFiber wireless (1.3.6.1.4.1.41112.1.4.5.1)
#   .3  signal dBm  .5  noise dBm  .6  tx_capacity %  .7  rx_capacity %

_UBNT_AP_SYSINFO  = "1.3.6.1.4.1.41112.1.6.1.2.1"
_UBNT_HOST        = "1.3.6.1.4.1.41112.1.7.8"
_UBNT_WIRELESS    = "1.3.6.1.4.1.41112.1.4.5.1"
_LMSENSORS_TEMP   = "1.3.6.1.4.1.2021.13.16.2.1"
_LMSENSORS_FAN    = "1.3.6.1.4.1.2021.13.16.3.1"
_LMSENSORS_MISC   = "1.3.6.1.4.1.2021.13.16.5.1"
_EDGE_FAN_TABLE   = "1.3.6.1.4.1.4413.1.1.43.1.6.1"
_EDGE_TEMP_TABLE  = "1.3.6.1.4.1.4413.1.1.43.1.8.1"


def _lmsensors_table(ip: str, base_oid: str, community: str, timeout: float,
                     value_scale: float, unit: str, source: str) -> list[dict]:
    """Reads an lmsensors-style table: field .2 = name, field .3 = value."""
    names: dict[str, str]   = {}
    values: dict[str, int]  = {}
    for oid_str, raw_val, _ in _walk(ip, base_oid, community, timeout, max_iter=200):
        suffix = oid_str[len(base_oid):].lstrip(".")
        parts = suffix.split(".", 1)
        if len(parts) < 2:
            continue
        field, idx = parts[0], parts[1]
        if field == "2":
            names[idx] = _str_val(raw_val)
        elif field == "3":
            iv = _int_val(raw_val)
            if iv is not None:
                values[idx] = iv
    results = []
    for idx, name in names.items():
        if idx not in values:
            continue
        val = values[idx] * value_scale
        results.append(_sensor(name, round(val, 2) if value_scale != 1 else val, unit, source))
    return results


def _ubiquiti(ip: str, community: str, timeout: float) -> list[dict]:
    results: list[dict] = []
    seen: set[str] = set()

    def _add(s: dict) -> None:
        if s["name"] not in seen:
            seen.add(s["name"])
            results.append(s)

    # ── Layer A: UniFi AP sysinfo ────────────────────────────────────────────
    ap_raw: dict[str, int] = {}
    for oid, field in [
        ("1.3.6.1.4.1.41112.1.6.1.2.1.3", "cpu_load"),
        ("1.3.6.1.4.1.41112.1.6.1.2.1.4", "ram_used_kb"),
        ("1.3.6.1.4.1.41112.1.6.1.2.1.5", "ram_total_kb"),
    ]:
        val, _ = _get(ip, oid, community, timeout)
        iv = _int_val(val)
        if iv is not None:
            ap_raw[field] = iv
    if "cpu_load" in ap_raw:
        _add(_sensor("cpu_load", ap_raw["cpu_load"], "%", "ubiquiti-ap"))
    ru, rt = ap_raw.get("ram_used_kb"), ap_raw.get("ram_total_kb")
    if ru is not None and rt and rt > 0:
        _add(_sensor("ram_used_pct", round(ru / rt * 100, 1), "%", "ubiquiti-ap"))

    # ── Layer B: ubntHost scalars (airOS, all models) ────────────────────────
    cpu_val, _ = _get(ip, f"{_UBNT_HOST}.3", community, timeout)
    if cpu_val is not None:
        iv = _int_val(cpu_val)
        if iv is not None:
            # scale 0–65535 → %
            _add(_sensor("cpu_load", round(iv / 655.35, 1), "%", "ubiquiti-airos"))
    temp_val, _ = _get(ip, f"{_UBNT_HOST}.4", community, timeout)
    if temp_val is not None:
        iv = _int_val(temp_val)
        if iv is not None and 0 < iv < 200:
            _add(_sensor("temperature", float(iv), "°C", "ubiquiti-airos"))

    # ── Layer C: lmsensors MIB (UDM/UDMP running net-snmp on Linux) ─────────
    for s in _lmsensors_table(ip, _LMSENSORS_TEMP, community, timeout,
                               value_scale=0.001, unit="°C", source="lmsensors"):
        _add(s)
    for s in _lmsensors_table(ip, _LMSENSORS_FAN, community, timeout,
                               value_scale=1, unit="rpm", source="lmsensors"):
        _add(s)
    # lmMisc: voltage in mV*1000 → divide by 1000 to get V; filter out non-voltage by name
    for s in _lmsensors_table(ip, _LMSENSORS_MISC, community, timeout,
                               value_scale=0.001, unit="V", source="lmsensors"):
        n = s["name"].lower()
        if any(k in n for k in ("volt", "vin", "vout", "vcore", "3v", "5v", "12v", "+v")):
            _add(s)

    # ── Layer D: EdgeSwitch / EdgeRouter fan + temp tables ───────────────────
    edge_fans: dict[str, dict] = {}
    for oid_str, raw_val, _ in _walk(ip, _EDGE_FAN_TABLE, community, timeout, max_iter=100):
        suffix = oid_str[len(_EDGE_FAN_TABLE):].lstrip(".")
        parts = suffix.split(".", 1)
        if len(parts) < 2:
            continue
        field, idx = parts[0], parts[1]
        entry = edge_fans.setdefault(idx, {})
        if field == "2":
            entry["descr"] = _str_val(raw_val)
        elif field == "3":
            entry["state"] = _int_val(raw_val)   # 2 = operational
        elif field == "4":
            entry["rpm"]   = _int_val(raw_val)
    for idx, f in edge_fans.items():
        if f.get("state") == 2 and f.get("rpm") is not None:
            name = f.get("descr") or f"fan_{idx}"
            _add(_sensor(name, float(f["rpm"]), "rpm", "edge"))

    edge_temps: dict[str, dict] = {}
    for oid_str, raw_val, _ in _walk(ip, _EDGE_TEMP_TABLE, community, timeout, max_iter=100):
        suffix = oid_str[len(_EDGE_TEMP_TABLE):].lstrip(".")
        parts = suffix.split(".", 1)
        if len(parts) < 2:
            continue
        field, idx = parts[0], parts[1]
        entry = edge_temps.setdefault(idx, {})
        if field == "3":
            entry["descr"] = _str_val(raw_val)
        elif field == "4":
            entry["state"] = _int_val(raw_val)
        elif field == "5":
            entry["temp"]  = _int_val(raw_val)
    for idx, t in edge_temps.items():
        if t.get("temp") is not None and t.get("state") in (None, 2, 4):  # 4=good on some models
            name = t.get("descr") or f"temperature_{idx}"
            _add(_sensor(name, float(t["temp"]), "°C", "edge"))

    # ── Layer E: AirMAX / AirFiber wireless (per radio) ─────────────────────
    wireless: dict[str, dict] = {}
    for oid_str, raw_val, _ in _walk(ip, _UBNT_WIRELESS, community, timeout, max_iter=100):
        suffix = oid_str[len(_UBNT_WIRELESS):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) < 2:
            continue
        field, idx = int(parts[0]), parts[1]
        entry = wireless.setdefault(idx, {})
        iv = _int_val(raw_val)
        if   field == 3: entry["signal"]  = iv
        elif field == 5: entry["noise"]   = iv
        elif field == 6: entry["tx_cap"]  = iv

    for i, (idx, w) in enumerate(wireless.items(), 1):
        sfx = f"_{i}" if i > 1 else ""
        if w.get("signal") is not None:
            _add(_sensor(f"wireless_signal{sfx}", w["signal"], "dBm", "ubiquiti"))
        if w.get("noise") is not None:
            _add(_sensor(f"wireless_noise{sfx}", w["noise"], "dBm", "ubiquiti"))
        if w.get("tx_cap") is not None:
            _add(_sensor(f"wireless_tx_capacity{sfx}", w["tx_cap"], "%", "ubiquiti"))

    return results


# ─── 7. HP / ProCurve / Aruba ─────────────────────────────────────────────────
# hp-unix-mib / hp-icf-chassis:
#  hpicfSensorTable: 1.3.6.1.4.1.11.2.14.11.5.1.9.1
#    .1  hpicfSensorIndex
#    .2  hpicfSensorObjectId
#    .3  hpicfSensorNumber
#    .4  hpicfSensorDescr
#    .5  hpicfSensorCode (1=unknown,2=bad,3=warning,4=good,5=notPresent,6=notInitialized)
#    .7  hpicfSensorStatus (same as Code)
#  HPE iLO temperature: 1.3.6.1.4.1.232.6.2.6.8 (cpqHeThermalDegCelsius)
#    .1.3  value in °C per sensor

_HP_SENSOR_TABLE = "1.3.6.1.4.1.11.2.14.11.5.1.9.1"
_HPE_ILO_TEMP    = "1.3.6.1.4.1.232.6.2.6.8.1.4"  # cpqHeThermalDegCelsius


def _hp_aruba(ip: str, community: str, timeout: float) -> list[dict]:
    results = []

    sensors: dict[str, dict] = {}
    for oid_str, raw_val, _tag in _walk(ip, _HP_SENSOR_TABLE, community, timeout, max_iter=200):
        suffix = oid_str[len(_HP_SENSOR_TABLE):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) < 2: continue
        field, idx = int(parts[0]), parts[1]
        entry = sensors.setdefault(idx, {})
        if field == 4:   entry["descr"]  = _str_val(raw_val)
        elif field == 5: entry["code"]   = _int_val(raw_val)

    for i, (idx, s) in enumerate(sensors.items(), 1):
        code = s.get("code", 1) or 1
        descr = s.get("descr") or f"sensor_{i}"
        if code == 5:  # notPresent
            continue
        clean = "".join(c for c in descr.lower().replace(" ", "_") if c.isalnum() or c == "_")
        ok = 1.0 if code == 4 else (0.5 if code == 3 else 0.0)
        status_str = {1:"unknown",2:"bad",3:"warning",4:"good",5:"notPresent",6:"notInitialized"}.get(code,str(code))
        results.append(_sensor(f"hp_sensor_{clean}_ok", ok, "", "hp_aruba", status_str))

    # iLO temperature (servers)
    for oid_str, raw_val, _tag in _walk(ip, _HPE_ILO_TEMP, community, timeout, max_iter=100):
        idx = oid_str[len(_HPE_ILO_TEMP):].lstrip(".")
        iv = _int_val(raw_val)
        if iv is not None and iv > 0:
            results.append(_sensor(f"ilo_temp_{idx}", iv, "°C", "hp_ilo"))

    return results


# ─── 8. Juniper ───────────────────────────────────────────────────────────────
# JUNIPER-MIB: 1.3.6.1.4.1.2636.3
#  jnxOperatingTable: 1.3.6.1.4.1.2636.3.1.13.1
#    .5  jnxOperatingTemp   (°C)
#    .6  jnxOperatingCPU    (%)
#    .7  jnxOperatingBuffer (% used)
#    .8  jnxOperatingHeap   (% used)
#    .11 jnxOperatingDescr

_JNX_OPER_TABLE = "1.3.6.1.4.1.2636.3.1.13.1"


def _juniper(ip: str, community: str, timeout: float) -> list[dict]:
    results = []
    entries: dict[str, dict] = {}
    for oid_str, raw_val, _tag in _walk(ip, _JNX_OPER_TABLE, community, timeout, max_iter=500):
        suffix = oid_str[len(_JNX_OPER_TABLE):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) < 2: continue
        field, idx = int(parts[0]), ".".join(parts[1:])
        entry = entries.setdefault(idx, {})
        if field == 5:   entry["temp"]   = _int_val(raw_val)
        elif field == 6: entry["cpu"]    = _int_val(raw_val)
        elif field == 7: entry["buffer"] = _int_val(raw_val)
        elif field == 8: entry["heap"]   = _int_val(raw_val)
        elif field == 11:entry["descr"]  = _str_val(raw_val)

    for i, (idx, e) in enumerate(entries.items(), 1):
        descr = e.get("descr") or f"slot_{i}"
        clean = "".join(c for c in descr.lower().replace(" ", "_") if c.isalnum() or c == "_")[:20]
        sfx = f"_{clean}" if clean else f"_{i}"
        if e.get("temp") is not None and e["temp"] > 0:
            results.append(_sensor(f"temp{sfx}", e["temp"], "°C", "juniper"))
        if e.get("cpu") is not None:
            results.append(_sensor(f"cpu_load{sfx}", e["cpu"], "%", "juniper"))
        if e.get("buffer") is not None:
            results.append(_sensor(f"buffer_used{sfx}", e["buffer"], "%", "juniper"))

    return results


# ─── 9. Huawei ────────────────────────────────────────────────────────────────
# HUAWEI-MIB: 1.3.6.1.4.1.2011.5.25
#  hwEntityTempTable: 1.3.6.1.4.1.2011.5.25.31.1.1.1.1
#    .11  hwEntityTemperature (°C)
#  hwCPUTable: 1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5  cpuUsage (%)
#  hwMemTable: 1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7  memUsage (%)

_HW_ENT_TABLE = "1.3.6.1.4.1.2011.5.25.31.1.1.1.1"


def _huawei(ip: str, community: str, timeout: float) -> list[dict]:
    results = []
    entries: dict[str, dict] = {}
    for oid_str, raw_val, _tag in _walk(ip, _HW_ENT_TABLE, community, timeout, max_iter=500):
        suffix = oid_str[len(_HW_ENT_TABLE):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) < 2: continue
        field, idx = int(parts[0]), parts[1]
        entry = entries.setdefault(idx, {})
        if field == 5:   entry["cpu"]  = _int_val(raw_val)
        elif field == 7: entry["mem"]  = _int_val(raw_val)
        elif field == 11:entry["temp"] = _int_val(raw_val)

    for i, (idx, e) in enumerate(entries.items(), 1):
        sfx = f"_{i}" if i > 1 else ""
        if e.get("temp") is not None and e["temp"] > 0:
            results.append(_sensor(f"temp{sfx}", e["temp"], "°C", "huawei"))
        if e.get("cpu") is not None:
            results.append(_sensor(f"cpu_load{sfx}", e["cpu"], "%", "huawei"))
        if e.get("mem") is not None:
            results.append(_sensor(f"mem_used_pct{sfx}", e["mem"], "%", "huawei"))

    return results


# ─── 10. Fortinet FortiGate ───────────────────────────────────────────────────
# FORTINET-FORTIGATE-MIB: 1.3.6.1.4.1.12356.101
#  fgSysCpuUsage:    1.3.6.1.4.1.12356.101.4.1.3.0  (%)
#  fgSysMemUsage:    1.3.6.1.4.1.12356.101.4.1.4.0  (%)
#  fgSysMemCapacity: 1.3.6.1.4.1.12356.101.4.1.5.0  (KB)
#  fgSysDiskUsage:   1.3.6.1.4.1.12356.101.4.1.6.0  (MB)
#  fgSysDiskCapacity:1.3.6.1.4.1.12356.101.4.1.7.0  (MB)
#  fgProcessorTable: 1.3.6.1.4.1.12356.101.4.4.1     per-core CPU

_FG_BASE = "1.3.6.1.4.1.12356.101.4.1"


def _fortinet(ip: str, community: str, timeout: float) -> list[dict]:
    results = []
    oids = {
        "1.3.6.1.4.1.12356.101.4.1.3.0": ("cpu_load",       1, "%"),
        "1.3.6.1.4.1.12356.101.4.1.4.0": ("mem_used_pct",   1, "%"),
        "1.3.6.1.4.1.12356.101.4.1.5.0": ("mem_total_kb",   1, "KB"),
        "1.3.6.1.4.1.12356.101.4.1.6.0": ("disk_used_mb",   1, "MB"),
        "1.3.6.1.4.1.12356.101.4.1.7.0": ("disk_total_mb",  1, "MB"),
    }
    for oid, (name, div, unit) in oids.items():
        val, _ = _get(ip, oid, community, timeout)
        if val is None: continue
        iv = _int_val(val)
        if iv is None: continue
        results.append(_sensor(name, iv, unit, "fortinet"))

    return results


# ─── 11. Synology NAS ─────────────────────────────────────────────────────────
# SYNOLOGY-SYSTEM-MIB: 1.3.6.1.4.1.6574
#  synoSystem.systemStatus:   1.3.6.1.4.1.6574.1.1.0
#  synoSystem.temperature:    1.3.6.1.4.1.6574.1.2.0   (°C)
#  synoSystem.powerStatus:    1.3.6.1.4.1.6574.1.4.0
#  synoCpuInfo.cpuUsage:      1.3.6.1.4.1.6574.1.5.1.0 (%)
#  synoMemory.swaplessFreeMemory: 1.3.6.1.4.1.6574.1.5.4.0 (KB)
#  synoMemory.totalPhysicalMemory: 1.3.6.1.4.1.6574.1.5.5.0 (KB)
#  SYNOLOGY-DISK-MIB diskTable: 1.3.6.1.4.1.6574.2.1.1
#    .13 diskTemperature (°C)
#    .2  diskID (string name)
#  SYNOLOGY-RAID-MIB raidTable: 1.3.6.1.4.1.6574.3.1.1
#    .3  raidStatus (1=normal,2=repairing,3=migrating,4=expanding,5=deleting,6=creating,
#                   7=RaidSyncing,8=RaidParityChecking,9=RaidAssembling,10=Canceling,
#                   11=Degrade,12=Crashed)

_SYNO_BASE = "1.3.6.1.4.1.6574"


def _synology(ip: str, community: str, timeout: float) -> list[dict]:
    results = []
    oids = {
        "1.3.6.1.4.1.6574.1.2.0":   ("temp_system", 1, "°C"),
        "1.3.6.1.4.1.6574.1.5.1.0": ("cpu_load",    1, "%"),
        "1.3.6.1.4.1.6574.1.5.4.0": ("ram_free_kb", 1, "KB"),
        "1.3.6.1.4.1.6574.1.5.5.0": ("ram_total_kb",1, "KB"),
    }
    raw_vals = {}
    for oid, (name, div, unit) in oids.items():
        val, _ = _get(ip, oid, community, timeout)
        if val is None: continue
        iv = _int_val(val)
        if iv is None: continue
        results.append(_sensor(name, iv, unit, "synology"))
        raw_vals[name] = iv

    rf = raw_vals.get("ram_free_kb")
    rt = raw_vals.get("ram_total_kb")
    if rf is not None and rt and rt > 0:
        results.append(_sensor("ram_used_pct", round((rt - rf) / rt * 100, 1), "%", "synology"))

    # Disk temperatures
    disk_names: dict[str, str] = {}
    disk_temps: dict[str, int] = {}
    for oid_str, raw_val, _tag in _walk(ip, "1.3.6.1.4.1.6574.2.1.1", community, timeout, max_iter=200):
        suffix = oid_str[len("1.3.6.1.4.1.6574.2.1.1"):].lstrip(".")
        parts = suffix.split(".")
        if len(parts) < 2: continue
        field, idx = int(parts[0]), parts[1]
        if field == 2:   disk_names[idx] = _str_val(raw_val)
        elif field == 13:
            iv = _int_val(raw_val)
            if iv is not None: disk_temps[idx] = iv

    for idx, temp in disk_temps.items():
        dname = disk_names.get(idx) or f"disk_{idx}"
        clean = "".join(c for c in dname.lower().replace(" ", "_") if c.isalnum() or c == "_")
        results.append(_sensor(f"temp_{clean}", temp, "°C", "synology"))

    return results


# ─── 12. APC / Schneider UPS ─────────────────────────────────────────────────
# PowerNet-MIB: 1.3.6.1.4.1.318.1.1.1
#  upsBasicBatteryStatus:      .2.1.2.0  (1=unknown,2=batteryNormal,3=batteryLow,4=batteryInFaultCondition)
#  upsAdvBatteryCapacity:      .2.2.1.0  (% remaining)
#  upsAdvBatteryTemperature:   .2.2.2.0  (°C)
#  upsAdvBatteryRunTimeRemaining: .2.2.3.0 (timeticks/100=seconds)
#  upsAdvInputLineVoltage:     .3.2.1.0  (V)
#  upsAdvInputFrequency:       .3.2.4.0  (Hz × 10)
#  upsAdvOutputVoltage:        .4.2.1.0  (V)
#  upsAdvOutputLoad:           .4.2.3.0  (%)
#  upsAdvOutputCurrent:        .4.2.4.0  (A)

_APC_BASE = "1.3.6.1.4.1.318.1.1.1"


def _apc_ups(ip: str, community: str, timeout: float) -> list[dict]:
    results = []
    oids = {
        "1.3.6.1.4.1.318.1.1.1.2.2.1.0": ("battery_charge_pct",   1,   "%"),
        "1.3.6.1.4.1.318.1.1.1.2.2.2.0": ("battery_temp",         1,   "°C"),
        "1.3.6.1.4.1.318.1.1.1.2.2.3.0": ("battery_runtime_s",    100, "s"),
        "1.3.6.1.4.1.318.1.1.1.3.2.1.0": ("input_voltage",        1,   "V"),
        "1.3.6.1.4.1.318.1.1.1.3.2.4.0": ("input_freq",           10,  "Hz"),
        "1.3.6.1.4.1.318.1.1.1.4.2.1.0": ("output_voltage",       1,   "V"),
        "1.3.6.1.4.1.318.1.1.1.4.2.3.0": ("output_load_pct",      1,   "%"),
        "1.3.6.1.4.1.318.1.1.1.4.2.4.0": ("output_current",       1,   "A"),
    }
    for oid, (name, div, unit) in oids.items():
        val, _ = _get(ip, oid, community, timeout)
        if val is None: continue
        iv = _int_val(val)
        if iv is None: continue
        fval = round(iv / div, 2) if div != 1 else iv
        results.append(_sensor(name, fval, unit, "apc_ups"))

    return results


# ─── 13. Eaton UPS ────────────────────────────────────────────────────────────
# XUPS-MIB: 1.3.6.1.4.1.534.1
#  xupsOutputLoad:         .4.1.0  (%)
#  xupsOutputVoltage:      .4.4.1.2.1  (V)
#  xupsBatteryAbsStateOfCharge: .2.4.0  (%)
#  xupsBatteryTemperature: .2.7.0  (°C)
#  xupsInputVoltage:       .3.4.1.2.1  (V)
#  xupsEnvAmbientTemp:     .10.1.0  (°C)

_EATON_BASE = "1.3.6.1.4.1.534.1"


def _eaton_ups(ip: str, community: str, timeout: float) -> list[dict]:
    results = []
    oids = {
        "1.3.6.1.4.1.534.1.4.1.0": ("output_load_pct",     1, "%"),
        "1.3.6.1.4.1.534.1.2.4.0": ("battery_charge_pct",  1, "%"),
        "1.3.6.1.4.1.534.1.2.7.0": ("battery_temp",        1, "°C"),
        "1.3.6.1.4.1.534.1.10.1.0":("temp_ambient",        1, "°C"),
    }
    for oid, (name, div, unit) in oids.items():
        val, _ = _get(ip, oid, community, timeout)
        if val is None: continue
        iv = _int_val(val)
        if iv is None: continue
        results.append(_sensor(name, iv, unit, "eaton_ups"))

    return results


# ─── VENDOR DISPATCH TABLE ────────────────────────────────────────────────────

# Maps vendor keyword (lowercase) → list of vendor-specific poll functions.
# Multiple keywords can map to the same function.
_VENDOR_FUNCS = [
    (["cisco", "ios", "catalyst", "nexus", "asr", "isr", "c9"],  _cisco_envmon),
    (["mikrotik", "routerboard", "chr"],                          _mikrotik),
    (["ubiquiti", "unifi", "ubnt", "edgeos", "edgeswitch"],       _ubiquiti),
    (["hewlett", "hp ", "hpe", "procurve", "aruba"],              _hp_aruba),
    (["juniper", "junos", "srx", "ex ", "mx ", "qfx"],           _juniper),
    (["huawei", "vrp"],                                           _huawei),
    (["fortinet", "fortigate"],                                   _fortinet),
    (["synology"],                                                _synology),
    (["apc", "schneider", "powerware"],                           _apc_ups),
    (["eaton"],                                                   _eaton_ups),
]

# Vendor keywords that indicate Linux-based OS (Net-SNMP available)
_LINUX_HINTS = ["linux", "ubuntu", "debian", "centos", "fedora", "raspbian",
                "openwrt", "ddwrt", "pfsense", "opnsense", "proxmox", "freebsd",
                "synology", "qnap", "omv", "truenas"]


# ─── CISCO-ENVMON-MIB ────────────────────────────────────────────────────────
# Temperatura chassis, stan wentylatorów i zasilaczy na urządzeniach Cisco IOS.
# Stany: 1=normal, 2=warning, 3=critical, 4=shutdown, 5=notPresent, 6=notFunctioning
_CISCO_ENVMON_STATE_STR = {1: "normal", 2: "warning", 3: "critical",
                           4: "shutdown", 5: "notPresent", 6: "notFunctioning"}


def _cisco_envmon_mib(
    ip: str, community: str, timeout: float, oids: Optional[dict] = None
) -> list[dict]:
    """Zbiera temperaturę, stan wentylatorów i zasilaczy z CISCO-ENVMON-MIB.

    oids (z passport sensors.oids):
      temp      — ciscoEnvMonTemperatureStatusValue (°C)
      fan_state — ciscoEnvMonFanState (1=normal)
      psu_state — ciscoEnvMonSupplyState (1=normal)
    """
    _default_oids = {
        "temp":      "1.3.6.1.4.1.9.9.13.1.3.1.3.1",
        "fan_state": "1.3.6.1.4.1.9.9.13.1.4.1.3.1",
        "psu_state": "1.3.6.1.4.1.9.9.13.1.5.1.3.1",
    }
    merged = {**_default_oids, **(oids or {})}

    results: list[dict] = []

    def _get_int_oid(key: str) -> Optional[int]:
        oid = merged.get(key)
        if not oid:
            return None
        val, _tag = _get(ip, oid, community, timeout)
        return _int_val(val)

    # Temperatura chassis (°C)
    temp = _get_int_oid("temp")
    if temp is not None and -40 <= temp <= 150:
        results.append(_sensor("temperature_celsius", float(temp), "°C", "cisco_envmon",
                               str(temp)))

    # Stan wentylatora (1=normal → OK, inne = problem)
    fan = _get_int_oid("fan_state")
    if fan is not None:
        fan_str = _CISCO_ENVMON_STATE_STR.get(fan, str(fan))
        # Wartość numeryczna: 1 (normal) i 5 (notPresent) traktujemy jako OK
        fan_val = 1.0 if fan in (1, 5) else 0.0
        results.append(_sensor("fan_ok", fan_val, "", "cisco_envmon", fan_str))

    # Stan zasilacza (1=normal)
    psu = _get_int_oid("psu_state")
    if psu is not None:
        psu_str = _CISCO_ENVMON_STATE_STR.get(psu, str(psu))
        psu_val = 1.0 if psu in (1, 5) else 0.0
        results.append(_sensor("psu_ok", psu_val, "", "cisco_envmon", psu_str))

    return results


# ─── Ubiquiti UniFi — radio stats + client RSSI ───────────────────────────────
# ubntRadioTable (1.3.6.1.4.1.41112.1.6.1.4.1):
#   .5 = ubntRadioFreq (MHz)  .6 = ubntRadioTxPower (dBm)
#   .7 = ubntRadioNoise (dBm, negative)  .8 = ubntRadioChannel
# ubntStaTable (1.3.6.1.4.1.41112.1.6.1.1.1):
#   .11 = ubntStaRssi (dBm, unsigned — wymaga korekty na ujemne)
_UBNT_RADIO_OID = "1.3.6.1.4.1.41112.1.6.1.4.1"
_UBNT_STA_OID   = "1.3.6.1.4.1.41112.1.6.1.1.1"


def _ubnt_radio_sta(ip: str, community: str, timeout: float) -> list[dict]:
    """Zbiera statystyki radia i klientów WiFi z UniFi MIB.

    Zwraca sensory:
      noise_floor_db_[band]   — floor szumu per radio (dBm)
      tx_power_dbm_[band]     — moc nadawania per radio (dBm)
      wifi_rssi_avg_db        — średni RSSI wszystkich klientów (dBm)
      wifi_rssi_min_db        — najsłabszy klient (dBm) — kluczowe dla troubleshootingu
    """
    results: list[dict] = []

    def _band_label(freq_mhz: int) -> str:
        if freq_mhz < 3000:
            return "2g"
        if freq_mhz < 6000:
            return "5g"
        return "6g"

    # ── Radio stats ───────────────────────────────────────────────────────────
    radios: dict[str, dict] = {}  # idx → {freq, tx_power, noise, channel}
    try:
        _RADIO_FIELDS = {"5": "freq", "6": "tx_power", "7": "noise", "8": "channel"}
        for full_oid, raw_val, _ in _walk(ip, _UBNT_RADIO_OID, community, timeout):
            suffix = full_oid[len(_UBNT_RADIO_OID):].lstrip(".")
            parts = suffix.split(".", 1)
            if len(parts) != 2:
                continue
            field, idx = parts[0], parts[1]
            if field not in _RADIO_FIELDS:
                continue
            v = _int_val(raw_val)
            if v is None:
                continue
            radios.setdefault(idx, {})[_RADIO_FIELDS[field]] = v
    except Exception as exc:
        logger.debug("ubnt_radio %s radio table: %s", ip, exc)

    for idx, r in radios.items():
        freq = r.get("freq", 0)
        if freq < 2000:
            continue  # nie wyglada na radiowa czestotliwosc
        band = _band_label(freq)
        noise = r.get("noise")
        if noise is not None:
            # noise moze byc przechowywany jako unsigned (np. 65436 = -100 dBm w uint8)
            if noise > 200:
                noise = noise - 256
            if -120 <= noise <= -20:
                results.append(_sensor(f"noise_floor_db_{band}", float(noise), "dBm",
                                       "ubnt_radio", str(noise)))
        tx = r.get("tx_power")
        if tx is not None and 0 < tx <= 40:
            results.append(_sensor(f"tx_power_dbm_{band}", float(tx), "dBm",
                                   "ubnt_radio", str(tx)))

    # ── Client RSSI ───────────────────────────────────────────────────────────
    rssi_values: list[int] = []
    try:
        _STA_RSSI_FIELD = "11"
        for full_oid, raw_val, _ in _walk(ip, _UBNT_STA_OID, community, timeout, max_iter=500):
            suffix = full_oid[len(_UBNT_STA_OID):].lstrip(".")
            if not suffix.startswith(_STA_RSSI_FIELD + "."):
                continue
            v = _int_val(raw_val)
            if v is None:
                continue
            # RSSI w UniFi zwracany jako unsigned — konwertuj na dBm
            if v > 200:
                v = v - 256
            if -120 <= v <= -10:  # sensowny zakres RSSI
                rssi_values.append(v)
    except Exception as exc:
        logger.debug("ubnt_radio %s sta table: %s", ip, exc)

    if rssi_values:
        avg = round(sum(rssi_values) / len(rssi_values), 1)
        results.append(_sensor("wifi_rssi_avg_db", float(avg), "dBm",
                               "ubnt_radio", f"{len(rssi_values)} clients"))
        results.append(_sensor("wifi_rssi_min_db", float(min(rssi_values)), "dBm",
                               "ubnt_radio", str(min(rssi_values))))

    return results


# ─── Printer-MIB (RFC 3805) ───────────────────────────────────────────────────
# Obsługuje drukarki z community public — zbiera stan tonera, bębna i licznik stron.
# OID domyślne (prnMarkerSupplies index 1 = toner, index 2 = bęben):
_PRINTER_MIB_DEFAULTS = {
    "toner_level": "1.3.6.1.2.1.43.11.1.1.9.1.1",   # prnMarkerSuppliesLevel (toner)
    "toner_max":   "1.3.6.1.2.1.43.11.1.1.8.1.1",   # prnMarkerSuppliesMaxCapacity
    "drum_level":  "1.3.6.1.2.1.43.11.1.1.9.1.2",   # supplies index 2 (bęben, opcjonalny)
    "drum_max":    "1.3.6.1.2.1.43.11.1.1.8.1.2",
    "page_count":  "1.3.6.1.2.1.43.10.2.1.4.1.1",   # prtMarkerLifeCount
}


def _printer_mib(
    ip: str, community: str, timeout: float, oids: Optional[dict] = None
) -> list[dict]:
    """Zbiera dane z Printer-MIB (RFC 3805) — toner, bęben, licznik stron.

    Zwraca listę sensorów:
      toner_pct   — poziom tonera w %
      drum_pct    — poziom bębna w % (jeśli dostępny)
      page_count  — łączna liczba wydrukowanych stron
    """
    merged = dict(_PRINTER_MIB_DEFAULTS)
    if oids:
        merged.update(oids)

    results: list[dict] = []

    def _get_int(oid_key: str) -> Optional[int]:
        oid = merged.get(oid_key)
        if not oid:
            return None
        val, _tag = _get(ip, oid, community, timeout)
        return _int_val(val)

    # Toner — procent (level/max * 100)
    toner_level = _get_int("toner_level")
    toner_max   = _get_int("toner_max")
    if toner_level is not None and toner_max and toner_max > 0:
        pct = round(toner_level / toner_max * 100, 1)
        results.append(_sensor("toner_pct", pct, "%", "printer_mib",
                                f"{toner_level}/{toner_max}"))
    elif toner_level is not None and toner_level >= 0:
        # Niektóre drukarki zwracają bezpośrednio procent (max=100)
        results.append(_sensor("toner_pct", float(toner_level), "%", "printer_mib",
                                str(toner_level)))

    # Bęben — opcjonalny, taki sam schemat
    drum_level = _get_int("drum_level")
    drum_max   = _get_int("drum_max")
    if drum_level is not None and drum_max and drum_max > 0:
        pct = round(drum_level / drum_max * 100, 1)
        results.append(_sensor("drum_pct", pct, "%", "printer_mib",
                                f"{drum_level}/{drum_max}"))

    # Licznik stron — zwracany jako surowa liczba
    page_count = _get_int("page_count")
    if page_count is not None and page_count >= 0:
        results.append(_sensor("page_count", float(page_count), "pages", "printer_mib",
                                str(page_count)))

    return results


def _synology_mib(ip: str, community: str, timeout: float) -> list[dict]:
    """SYNOLOGY-DISK-MIB + SYNOLOGY-RAID-MIB — dyski, RAID, temperatura per dysk.

    OIDs:
      1.3.6.1.4.1.6574.2.1.1.{field}.{disk_idx}  — disk table
      1.3.6.1.4.1.6574.3.1.1.{field}.{raid_idx}  — RAID table

    diskHealthStatus: 1=Normal, 2=Warning, 3=Critical, 4=Failing
    raidStatus:       1=Normal, 2+=problem (11=Degrade, 12=Crashed)
    """
    results: list[dict] = []

    def _g(oid: str) -> Optional[str]:
        """GET single OID via _get() helper (uses real SNMP GET)."""
        val, _tag = _get(ip, oid, community, timeout)
        return val if val not in (None, "") else None

    # ── Disk table ──────────────────────────────────────────────────────────
    for disk_idx in range(1, 9):
        disk_id = _g(f"1.3.6.1.4.1.6574.2.1.1.2.{disk_idx}")
        if not disk_id:
            continue  # empty slot — skip, don't stop (slots can have gaps)

        suffix = f"_{disk_idx}"

        temp = _g(f"1.3.6.1.4.1.6574.2.1.1.6.{disk_idx}")
        if temp is not None:
            try:
                tv = float(temp)
                if 5 <= tv <= 80:
                    results.append(_sensor(f"disk{suffix}_temp_c", tv, "C", "synology_disk",
                                           f"disk={disk_id} temp={temp}"))
            except (ValueError, TypeError):
                pass

        health = _g(f"1.3.6.1.4.1.6574.2.1.1.13.{disk_idx}")
        if health is not None:
            try:
                hv = int(health)
                results.append(_sensor(f"disk{suffix}_health", float(hv), "", "synology_disk",
                                       f"disk={disk_id} health={hv}(1=Normal,2=Warn,3=Crit)"))
            except (ValueError, TypeError):
                pass

        bad = _g(f"1.3.6.1.4.1.6574.2.1.1.11.{disk_idx}")
        if bad is not None:
            try:
                bv = int(bad)
                if bv >= 0:  # -1 = not available (HDDs without SMART counter)
                    results.append(_sensor(f"disk{suffix}_bad_sectors", float(bv), "sectors",
                                           "synology_disk", f"disk={disk_id} bad={bv}"))
            except (ValueError, TypeError):
                pass

    # ── RAID/Volume table ───────────────────────────────────────────────────
    for raid_idx in range(1, 9):
        raid_name = _g(f"1.3.6.1.4.1.6574.3.1.1.2.{raid_idx}")
        if not raid_name:
            continue  # empty/missing RAID slot — skip, don't stop

        suffix = f"_{raid_idx}"

        raid_status = _g(f"1.3.6.1.4.1.6574.3.1.1.3.{raid_idx}")
        if raid_status is not None:
            try:
                sv = int(raid_status)
                results.append(_sensor(f"raid{suffix}_status", float(sv), "", "synology_raid",
                                       f"pool={raid_name} status={sv}(1=Normal,11=Degrade,12=Crash)"))
            except (ValueError, TypeError):
                pass

        free_raw = _g(f"1.3.6.1.4.1.6574.3.1.1.4.{raid_idx}")
        total_raw = _g(f"1.3.6.1.4.1.6574.3.1.1.5.{raid_idx}")
        if free_raw is not None and total_raw is not None:
            try:
                free_b = int(free_raw)
                total_b = int(total_raw)
                if total_b > 0:
                    free_pct = round(free_b / total_b * 100, 1)
                    results.append(_sensor(f"raid{suffix}_free_pct", free_pct, "%",
                                           "synology_raid",
                                           f"pool={raid_name} free={free_b/(1024**3):.1f}GB/{total_b/(1024**3):.1f}GB"))
            except (ValueError, TypeError):
                pass

    return results


# ─── MAIN ENTRY POINT ─────────────────────────────────────────────────────────

def poll_sensors(
    ip: str,
    community: str,
    vendor_hint: str = "",
    os_hint: str = "",
    timeout: float = 3.0,
    sensor_method: Optional[str] = None,
    sensor_oids: Optional[dict] = None,
) -> list[dict]:
    """Poll applicable sensor sources for a device.

    Args:
        ip:            Device IP
        community:     SNMP community string
        vendor_hint:   device.vendor or device.os_version (used to pick vendor-specific OIDs)
        os_hint:       device.os_version (additional hint for Linux/Net-SNMP detection)
        timeout:       SNMP timeout per individual GET/walk
        sensor_method: Passport-specified method: "printer_mib" | None (= default auto-detect)
        sensor_oids:   OID overrides from passport (used by e.g. printer_mib method)

    Returns:
        List of sensor dicts: {name, value, unit, source, raw}
        Deduplicated by name — first result wins (standard sources have priority).
    """
    results: list[dict] = []
    seen_names: set[str] = set()
    hint = (vendor_hint + " " + os_hint).lower()

    def _add(sensors: list[dict]) -> None:
        for s in sensors:
            n = s["name"]
            if n not in seen_names and s.get("value") is not None:
                seen_names.add(n)
                results.append(s)

    # Passport-driven dispatch — when sensor_method specified, use only that method
    if sensor_method == "printer_mib":
        try:
            _add(_printer_mib(ip, community, timeout, oids=sensor_oids))
        except Exception as e:
            logger.debug("printer_mib %s: %s", ip, e)
        return _sanitize_sensors(results)

    if sensor_method == "cisco_envmon":
        # _cisco_envmon = full Cisco collector: CPU (CISCO-PROCESS-MIB) +
        # RAM (CISCO-MEMORY-POOL-MIB) + temp/fan/PSU (CISCO-ENVMON-MIB)
        try:
            _add(_cisco_envmon(ip, community, timeout))
        except Exception as e:
            logger.debug("cisco_envmon %s: %s", ip, e)
        return _sanitize_sensors(results)

    if sensor_method == "ubnt_radio":
        try:
            _add(_ubnt_radio_sta(ip, community, timeout))
        except Exception as e:
            logger.debug("ubnt_radio %s: %s", ip, e)
        return _sanitize_sensors(results)

    if sensor_method == "synology_mib":
        try:
            _add(_synology_mib(ip, community, timeout))
        except Exception as e:
            logger.debug("synology_mib %s: %s", ip, e)
        # Also collect standard sensors (CPU/RAM/temp via HOST-RESOURCES + UCD)
        try:
            _add(_host_resources_mib(ip, community, timeout))
        except Exception:
            pass
        try:
            _add(_ucd_snmp_mib(ip, community, timeout))
        except Exception:
            pass
        try:
            _add(_synology(ip, community, timeout))
        except Exception:
            pass
        return _sanitize_sensors(results)

    # Layer 1: ENTITY-SENSOR-MIB — RFC standard, try always
    try:
        _add(_entity_sensor_mib(ip, community, timeout))
    except Exception as e:
        logger.debug("entity_sensor %s: %s", ip, e)

    # Layer 2: HOST-RESOURCES-MIB — try always (works on Linux, Windows, many network OS)
    try:
        _add(_host_resources_mib(ip, community, timeout))
    except Exception as e:
        logger.debug("host_resources %s: %s", ip, e)

    # Layer 3: UCD/Net-SNMP — only for Linux-based devices
    if any(k in hint for k in _LINUX_HINTS):
        try:
            _add(_ucd_snmp_mib(ip, community, timeout))
        except Exception as e:
            logger.debug("ucd_snmp %s: %s", ip, e)

    # Layer 4: vendor-specific
    matched_funcs = set()
    for keywords, func in _VENDOR_FUNCS:
        if any(k in hint for k in keywords):
            if func not in matched_funcs:
                matched_funcs.add(func)
                try:
                    _add(func(ip, community, timeout))
                except Exception as e:
                    logger.debug("%s vendor sensor %s: %s", func.__name__, ip, e)

    # If no vendor matched at all AND no standard sensors found — try all vendor funcs
    # (handles unrecognized vendors that still respond to e.g. CISCO-ENVMON)
    if not matched_funcs and not results:
        logger.debug("No vendor match for %s (%r) — trying all vendor probes", ip, vendor_hint[:40])
        for keywords, func in _VENDOR_FUNCS:
            if func not in matched_funcs:
                matched_funcs.add(func)
                try:
                    new = [s for s in func(ip, community, timeout)
                           if s["name"] not in seen_names and s.get("value") is not None]
                    if new:
                        for s in new:
                            seen_names.add(s["name"])
                        results.extend(new)
                        break  # stop at first vendor that returns data
                except Exception:
                    pass

    results = _sanitize_sensors(results)

    if results:
        logger.debug("Sensors %s: %d values from %s",
                     ip, len(results),
                     ", ".join(sorted({r["source"] for r in results})))
    return results


def _sanitize_sensors(sensors: list[dict]) -> list[dict]:
    """Czyści listę sensorów:
    - Usuwa surowe KB (ram_total_kb, ram_used_kb) — tylko ram_used_pct ma sens
    - Usuwa ram_used_pct poza zakresem 0-100 (błędne OIDy Ubiquiti AP)
    - Usuwa temp = 0°C (nieobecny/nieaktywny sensor, nie realna temperatura)
    - Usuwa fan = 0 rpm (nieaktywny wentylator — zaśmieca kartę)
    - Deduplikuje case-insensitive (temp-CPU vs temp-cpu → zostaje pierwsza)
    """
    keep: list[dict] = []
    seen_lower: set[str] = set()

    for s in sensors:
        name  = s.get("name", "")
        value = s.get("value")
        unit  = s.get("unit", "")
        nl    = name.lower()

        # Odrzuć surowe wartości KB — zbędne gdy mamy %
        if nl in ("ram_total_kb", "ram_used_kb", "ram_free_kb"):
            continue

        # ram_used_pct musi być w sensownym zakresie
        if nl == "ram_used_pct" and (value is None or not (0 <= value <= 100)):
            continue

        # Temperatura 0–1°C = nieobecny/niedostępny sensor (wartość sentinel)
        # Żaden działający komponent nie ma temperatury 0 lub 1°C
        if unit == "°C" and value is not None and value <= 1.0:
            continue

        # Wentylator 0 rpm = nieaktywny / nieobecny
        if unit == "rpm" and value is not None and value == 0:
            continue

        # Deduplikacja case-insensitive — zostaje pierwsza (wyższy priorytet źródła)
        if nl in seen_lower:
            continue
        seen_lower.add(nl)

        keep.append(s)

    return keep
