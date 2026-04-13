"""netdoc.collector.passport_loader — ładuje paszporty YAML urządzeń i dopasowuje do Device.

Paszport opisuje PER MODEL co i jak zbierać przez SNMP. Jest to prescriptive —
mówi workerowi CO kolekcjonować, nie tylko dokumentuje co działa.

Schemat snmp_collection w paszporcie:
  snmp_collection:
    interfaces:
      hc_counters: bool      # użyj ifHCInOctets (64-bit) zamiast ifInOctets (32-bit)
    cpu:
      enabled: bool          # czy zbierać CPU
      method: str            # host_resources (domyślnie) | cisco_process
    ram:
      enabled: bool          # czy zbierać RAM
      method: str            # host_resources (domyślnie) | ucd_snmp
    arp:
      enabled: bool          # czy chodzić po ARP table (ipNetToMediaTable)
    sensors:
      enabled: bool          # czy zbierać sensory specyficzne dla modelu
      method: str            # printer_mib | entity_sensor | ubnt_wireless | host_resources
      oids: dict             # opcjonalne OID override (używane przez printer_mib)

Brak wpisu w paszporcie = fallback do obecnego zachowania workera (próbuj wszystko).
"""
import os
import glob
import logging
from functools import lru_cache
from typing import Optional

logger = logging.getLogger(__name__)

# Katalog z paszportami — dwa poziomy wyżej od tego pliku (netdoc/collector/ → /)
_PASSPORT_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "device_passports")
)


@lru_cache(maxsize=1)
def _load_all_passports() -> list[dict]:
    """Wczytuje wszystkie pliki YAML z device_passports/. Cache per proces."""
    try:
        import yaml
    except ImportError:
        logger.warning("PyYAML nie zainstalowany — paszporty niedostępne")
        return []

    passports: list[dict] = []
    pattern = os.path.join(_PASSPORT_DIR, "*.yaml")
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if data and isinstance(data, dict):
                data["_source"] = os.path.basename(path)
                passports.append(data)
        except Exception as exc:
            logger.warning("Passport load error %s: %s", path, exc)

    logger.info("Loaded %d device passports from %s", len(passports), _PASSPORT_DIR)
    return passports


def find_passport(
    vendor: Optional[str],
    model: Optional[str],
    os_version: Optional[str],
) -> Optional[dict]:
    """Dopasowuje urządzenie do paszportu na podstawie vendor/model/os_version.

    Logika dopasowania:
      vendor_ok: match_vendors jest puste (bez ograniczenia) LUB vendor pasuje do jednego z wpisów
      content_ok: model pasuje do match_models LUB os_version pasuje do match_os

    Zwraca pierwszy pasujący paszport lub None.
    """
    v = (vendor or "").strip().lower()
    m = (model or "").strip().lower()
    o = (os_version or "").strip().lower()

    if not (v or m or o):
        return None

    for passport in _load_all_passports():
        match_vendors = [x.lower() for x in (passport.get("match_vendors") or [])]
        match_models  = [x.lower() for x in (passport.get("match_models") or [])]
        match_os      = [x.lower() for x in (passport.get("match_os") or [])]

        # Vendor: pusta lista = bez ograniczenia (pasuje każdy vendor)
        if match_vendors:
            vendor_ok = v and any(
                mv in v or v in mv for mv in match_vendors
            )
        else:
            vendor_ok = True

        if not vendor_ok:
            continue

        # Dopasowanie treści — model lub os_version musi pasować
        model_ok = bool(m and match_models and any(mm in m for mm in match_models))
        os_ok    = bool(o and match_os and any(mo in o for mo in match_os))

        if model_ok or os_ok:
            return passport

    return None


def get_snmp_collection(passport: Optional[dict]) -> dict:
    """Zwraca sekcję snmp_collection z paszportu, lub {} gdy brak paszportu."""
    if not passport:
        return {}
    return passport.get("snmp_collection") or {}


def passport_allows_arp(passport: Optional[dict]) -> Optional[bool]:
    """Zwraca True/False jeśli paszport jawnie określa arp.enabled, None gdy brak wpisu."""
    col = get_snmp_collection(passport)
    arp = col.get("arp")
    if arp is None:
        return None
    return bool(arp.get("enabled", True))


def passport_allows_cpu(passport: Optional[dict]) -> Optional[bool]:
    """Zwraca True/False jeśli paszport jawnie określa cpu.enabled, None gdy brak wpisu."""
    col = get_snmp_collection(passport)
    cpu = col.get("cpu")
    if cpu is None:
        return None
    return bool(cpu.get("enabled", True))


def passport_allows_ram(passport: Optional[dict]) -> Optional[bool]:
    """Zwraca True/False jeśli paszport jawnie określa ram.enabled, None gdy brak wpisu."""
    col = get_snmp_collection(passport)
    ram = col.get("ram")
    if ram is None:
        return None
    return bool(ram.get("enabled", True))


def passport_sensor_method(passport: Optional[dict]) -> Optional[str]:
    """Zwraca sensors.method z paszportu lub None gdy brak wpisu."""
    col = get_snmp_collection(passport)
    sensors = col.get("sensors")
    if not sensors or not sensors.get("enabled", True):
        return None
    return sensors.get("method")


def passport_sensor_oids(passport: Optional[dict]) -> dict:
    """Zwraca sensors.oids z paszportu lub {} gdy brak."""
    col = get_snmp_collection(passport)
    sensors = col.get("sensors") or {}
    return sensors.get("oids") or {}


def passport_extra_oids(passport: Optional[dict]) -> dict:
    """Zwraca extra_oids z snmp_collection — OIDy dla CPU i RAM (ClickHouse path)."""
    col = get_snmp_collection(passport)
    return col.get("extra_oids") or {}


def reload_passports() -> None:
    """Czyści cache i przeładowuje paszporty (użyteczne w testach)."""
    _load_all_passports.cache_clear()
