"""Inferuje capabilities urządzenia z danych już zebranych w DB.

Używane gdy brak ręcznego paszportu YAML (device_passports/*.yaml).
Zero dodatkowych zapytań DB — korzysta z coverage sets przekazanych z app.py.

Wynik ma taki sam kształt jak 'capabilities' z YAML paszportu, plus:
  _inferred: True   — flaga: dane wyliczone, nie przetestowane manualnie
"""
from __future__ import annotations

# Typy urządzeń dla których FDB (Q-BRIDGE MAC table) jest sensowny
_FDB_TYPES = {"switch"}

# Typy urządzeń dla których LLDP/CDP jest sensowny
_LLDP_TYPES = {"switch", "router", "firewall", "ap"}

# Typy urządzeń dla których SSH jest typowy
_SSH_TYPES = {"switch", "router", "firewall", "server", "nas", "domain_controller", "unknown"}

# Typy urządzeń dla których syslog jest typowy
_SYSLOG_TYPES = {"switch", "router", "firewall", "ap", "nas", "camera"}


def infer_capabilities_bulk(
    devices,
    cov_ssh_ids:    set,
    cov_fdb_ids:    set,
    cov_lldp_ids:   set,
    cov_syslog_ids: set,
) -> dict[int, dict]:
    """Batch inference capabilities dla listy urządzeń.

    Args:
        devices:        lista obiektów Device (ORM) lub słowników z kluczami id, device_type
        cov_ssh_ids:    zestaw device_id z potwierdzoną sesją SSH
        cov_fdb_ids:    zestaw device_id z danymi FDB (48h)
        cov_lldp_ids:   zestaw device_id widocznych w topology_links
        cov_syslog_ids: zestaw device_id z logami syslog (24h)

    Returns:
        {device_id: capabilities_dict}  — tylko dla urządzeń bez YAML paszportu
    """
    result: dict[int, dict] = {}

    for dev in devices:
        if isinstance(dev, dict):
            did  = dev.get("id")
            dtype = dev.get("device_type") or "unknown"
        else:
            did  = dev.id
            dtype = (dev.device_type.value if dev.device_type else None) or "unknown"

        if did is None:
            continue

        # Czy dane faktycznie zebrane (aktywność wyższa prio niż typ urządzenia)
        has_fdb    = did in cov_fdb_ids
        has_lldp   = did in cov_lldp_ids
        has_ssh    = did in cov_ssh_ids
        has_syslog = did in cov_syslog_ids

        # Relevance z typu urządzenia (fallback gdy brak danych)
        fdb_rel    = dtype in _FDB_TYPES    or has_fdb
        lldp_rel   = dtype in _LLDP_TYPES   or has_lldp
        ssh_rel    = dtype in _SSH_TYPES    or has_ssh
        syslog_rel = dtype in _SYSLOG_TYPES or has_syslog

        result[did] = {
            # Capabilities SNMP — snmp_ok sprawdzany osobno przez snmp_ok_at
            "snmp_fdb":   fdb_rel,
            "snmp_vlan":  fdb_rel,      # zwykle razem z FDB
            "snmp_stp":   dtype in {"switch"},
            # Protokoły
            "lldp_snmp":  lldp_rel,
            "lldp_ssh":   lldp_rel,
            "cdp":        lldp_rel,
            "ssh":        ssh_rel,
            "syslog":     syslog_rel,
            # Flaga: wyliczone, nie przetestowane
            "_inferred":  True,
        }

    return result
