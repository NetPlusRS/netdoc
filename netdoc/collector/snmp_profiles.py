"""Vendor profiles dla SNMP — OID i mozliwosci per producent.

Uzycie:
    from netdoc.collector.snmp_profiles import detect_vendor_profile, VENDOR_PROFILES

    profile_name = detect_vendor_profile(device.snmp_sys_object_id, device.os_version)
    profile = VENDOR_PROFILES[profile_name]
    if profile.get("fdb_supported", True):
        ...

Jak dodac nowego vendora:
  1. Dodaj wpis do VENDOR_PROFILES z kluczem = nazwa (snake_case)
  2. Ustaw sysObjectID_prefix (lista OID prefiksow) i/lub sysdescr_regex
  3. Ustaw flagi mozliwosci: fdb_supported, vlan_supported, stp_supported, metrics_hc_supported
  4. Dodaj vendor-specific extra_oids jezeli potrzebne (zbierane przez snmp_sensors.py)

Rozszerzanie:
  Flagi sa celowo liberalne (domyslnie True) — proba zawsze, blad = debug log.
  Ustaw False tylko gdy wiadomo ze OID nie istnieje (np. firewall bez L2).
"""
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Vendor profiles
# ─────────────────────────────────────────────────────────────────────────────

VENDOR_PROFILES: dict[str, dict] = {

    # ── Cisco ─────────────────────────────────────────────────────────────────
    "cisco_ios": {
        "display_name": "Cisco IOS",
        "sysObjectID_prefix": ["1.3.6.1.4.1.9.1.", "1.3.6.1.4.1.9.6."],
        "sysdescr_regex": r"cisco ios(?!-xe|-xr|-nx)",
        "fdb_supported": True,
        "fdb_vlan_community": True,   # wymaga community@vlanId dla per-VLAN FDB — MVP: default only
        "vlan_supported": True,
        "stp_supported": True,
        "metrics_hc_supported": True,
        "extra_oids": {
            "cpu_5min": "1.3.6.1.4.1.9.2.1.58.0",      # oldCiscoAvgBusy5
            "cpu_5min_new": "1.3.6.1.4.1.9.9.109.1.1.1.1.6.1",  # cpmCPUTotal5minRev
        },
    },
    "cisco_ios_xe": {
        "display_name": "Cisco IOS XE",
        "sysObjectID_prefix": ["1.3.6.1.4.1.9.1."],
        "sysdescr_regex": r"cisco ios.?xe|ios-xe",
        "fdb_supported": True,
        "fdb_vlan_community": True,
        "vlan_supported": True,
        "stp_supported": True,
        "metrics_hc_supported": True,
        "extra_oids": {
            "cpu_5min": "1.3.6.1.4.1.9.9.109.1.1.1.1.6.1",
        },
    },
    "cisco_ios_xr": {
        "display_name": "Cisco IOS XR",
        "sysObjectID_prefix": ["1.3.6.1.4.1.9.1."],
        "sysdescr_regex": r"cisco ios.?xr|ios-xr",
        "fdb_supported": False,   # router — brak L2 FDB
        "vlan_supported": False,
        "stp_supported": False,
        "metrics_hc_supported": True,
    },
    "cisco_nxos": {
        "display_name": "Cisco NX-OS",
        "sysObjectID_prefix": ["1.3.6.1.4.1.9.12."],
        "sysdescr_regex": r"cisco nx-?os|nexus",
        "fdb_supported": True,
        "vlan_supported": True,
        "stp_supported": True,
        "metrics_hc_supported": True,
        "extra_oids": {
            "cpu_5min": "1.3.6.1.4.1.9.9.109.1.1.1.1.6.1",
        },
    },
    "cisco_asa": {
        "display_name": "Cisco ASA",
        "sysObjectID_prefix": ["1.3.6.1.4.1.9.1.745.", "1.3.6.1.4.1.9.1.1."],
        "sysdescr_regex": r"cisco adaptive security|cisco asa",
        "fdb_supported": False,   # firewall — brak bridge FDB
        "vlan_supported": False,
        "stp_supported": False,
        "metrics_hc_supported": True,
    },
    "cisco_wlc": {
        "display_name": "Cisco WLC",
        "sysObjectID_prefix": ["1.3.6.1.4.1.9.1."],
        "sysdescr_regex": r"cisco wireless lan controller|cisco wlc|aireos",
        "fdb_supported": False,
        "vlan_supported": False,
        "stp_supported": False,
        "metrics_hc_supported": True,
    },

    # ── Juniper ───────────────────────────────────────────────────────────────
    "juniper": {
        "display_name": "Juniper JunOS",
        "sysObjectID_prefix": ["1.3.6.1.4.1.2636."],
        "sysdescr_regex": r"junos|juniper",
        "fdb_supported": True,
        "vlan_supported": True,
        "stp_supported": True,
        "metrics_hc_supported": True,
        "extra_oids": {
            "cpu_util": "1.3.6.1.4.1.2636.3.1.13.1.6.9.1.0.0",  # jnxOperatingCPU (.6)
            "mem_util": "1.3.6.1.4.1.2636.3.1.13.1.7.9.1.0.0",  # jnxOperatingBuffer (.7)
            "temp":     "1.3.6.1.4.1.2636.3.1.13.1.5.9.1.0.0",  # jnxOperatingTemp (.5)
        },
    },

    # ── MikroTik ──────────────────────────────────────────────────────────────
    "mikrotik": {
        "display_name": "MikroTik RouterOS",
        "sysObjectID_prefix": ["1.3.6.1.4.1.14988."],
        "sysdescr_regex": r"routeros|mikrotik",
        "fdb_supported": True,
        "vlan_supported": True,
        "stp_supported": True,
        "metrics_hc_supported": True,
        "extra_oids": {
            "cpu_load":    "1.3.6.1.4.1.14988.1.1.7.4",    # mtxrCPULoad (0-100%)
            "temp_cpu":    "1.3.6.1.4.1.14988.1.1.3.11",  # mtxrHlCpuTemperature
            "temp_board":  "1.3.6.1.4.1.14988.1.1.3.10",  # mtxrHlBoardTemperature
            "voltage":     "1.3.6.1.4.1.14988.1.1.3.8",   # mtxrHlVoltage
            "mem_total":   "1.3.6.1.4.1.14988.1.1.3.16",  # mtxrTotalMemory
            "mem_used":    "1.3.6.1.4.1.14988.1.1.3.17",  # mtxrUsedMemory
        },
    },

    # ── Ubiquiti ──────────────────────────────────────────────────────────────
    "ubiquiti_unifi": {
        "display_name": "Ubiquiti UniFi",
        "sysObjectID_prefix": ["1.3.6.1.4.1.41112.1.6."],
        "sysdescr_regex": r"unifi",
        "fdb_supported": True,
        "vlan_supported": True,
        "stp_supported": False,  # AP — typowo brak STP
        "metrics_hc_supported": False,  # stare AP nie maja HC
        "extra_oids": {
            "cpu_load":    "1.3.6.1.4.1.41112.1.6.1.2.1.3.1",   # unifiApSystemCpuLoad
            "mem_used":    "1.3.6.1.4.1.41112.1.6.1.2.1.4.1",   # unifiApSystemMemUsed
            "mem_total":   "1.3.6.1.4.1.41112.1.6.1.2.1.5.1",   # unifiApSystemMemTotal
        },
    },
    "ubiquiti_airos": {
        "display_name": "Ubiquiti AirOS",
        "sysObjectID_prefix": ["1.3.6.1.4.1.41112.1."],
        "sysdescr_regex": r"airos|airmax|ubnt",
        "fdb_supported": False,
        "vlan_supported": False,
        "stp_supported": False,
        "metrics_hc_supported": False,
        "extra_oids": {
            "cpu_load":   "1.3.6.1.4.1.41112.1.7.8.3",
            "temp":       "1.3.6.1.4.1.41112.1.7.8.4",
            "signal":     "1.3.6.1.4.1.41112.1.4.5.1.6.1",
            "noise":      "1.3.6.1.4.1.41112.1.4.5.1.5.1",
        },
    },

    # ── HP / Aruba ────────────────────────────────────────────────────────────
    "hp_procurve": {
        "display_name": "HP ProCurve / Aruba",
        "sysObjectID_prefix": ["1.3.6.1.4.1.11.2.3.7.", "1.3.6.1.4.1.25506."],
        "sysdescr_regex": r"procurve|hp switch|aruba|comware",
        "fdb_supported": True,
        "vlan_supported": True,
        "stp_supported": True,
        "metrics_hc_supported": True,
        "extra_oids": {
            "cpu_util": "1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.6.1",  # hpSwitchCpuStatValue (field=6, index=1)
        },
    },

    # ── Huawei ────────────────────────────────────────────────────────────────
    "huawei": {
        "display_name": "Huawei VRP",
        "sysObjectID_prefix": ["1.3.6.1.4.1.2011."],
        "sysdescr_regex": r"huawei|vrp|quidway",
        "fdb_supported": True,
        "vlan_supported": True,
        "stp_supported": True,
        "metrics_hc_supported": True,
        "extra_oids": {
            "cpu_avg":  "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5.0",  # hwEntityCpuUsage
            "mem_util": "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7.0",  # hwEntityMemUsage
            "temp":     "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11.0", # hwEntityTemperature
        },
    },

    # ── Fortinet ──────────────────────────────────────────────────────────────
    "fortinet": {
        "display_name": "Fortinet FortiGate",
        "sysObjectID_prefix": ["1.3.6.1.4.1.12356."],
        "sysdescr_regex": r"fortinet|fortigate|fortios",
        "fdb_supported": False,   # firewall — brak bridge FDB
        "vlan_supported": False,
        "stp_supported": False,
        "metrics_hc_supported": True,
        "extra_oids": {
            "cpu_util":  "1.3.6.1.4.1.12356.101.4.1.3.0",  # fgSysCpuUsage
            "mem_util":  "1.3.6.1.4.1.12356.101.4.1.4.0",  # fgSysMemUsage
            "sessions":  "1.3.6.1.4.1.12356.101.4.1.8.0",  # fgSysSesCount
        },
    },

    # ── Palo Alto ─────────────────────────────────────────────────────────────
    "paloalto": {
        "display_name": "Palo Alto PAN-OS",
        "sysObjectID_prefix": ["1.3.6.1.4.1.25461."],
        "sysdescr_regex": r"palo alto|pan-os|panos",
        "fdb_supported": False,
        "vlan_supported": False,
        "stp_supported": False,
        "metrics_hc_supported": True,
        "extra_oids": {
            "cpu_mgmt":    "1.3.6.1.4.1.25461.2.1.2.1.16.0",  # panSysCpuMgmtUtil
            "cpu_data":    "1.3.6.1.4.1.25461.2.1.2.1.17.0",  # panSysCpuDataUtil
            "sessions":    "1.3.6.1.4.1.25461.2.1.2.1.19.0",  # panSysActiveSessions
        },
    },

    # ── pfSense / OPNsense (FreeBSD) ──────────────────────────────────────────
    "pfsense": {
        "display_name": "pfSense / OPNsense",
        "sysObjectID_prefix": ["1.3.6.1.4.1.12325."],
        "sysdescr_regex": r"pfsense|opnsense|freebsd",
        "fdb_supported": False,
        "vlan_supported": False,
        "stp_supported": False,
        "metrics_hc_supported": True,
    },

    # ── Linux (ogolny) ────────────────────────────────────────────────────────
    "linux": {
        "display_name": "Linux",
        "sysObjectID_prefix": ["1.3.6.1.4.1.8072."],   # NET-SNMP
        "sysdescr_regex": r"linux",
        "fdb_supported": False,   # serwery Linux typowo brak bridge FDB
        "vlan_supported": False,
        "stp_supported": False,
        "metrics_hc_supported": True,
    },

    # ── Windows (ogolny) ──────────────────────────────────────────────────────
    "windows": {
        "display_name": "Windows SNMP",
        "sysObjectID_prefix": ["1.3.6.1.4.1.311."],
        "sysdescr_regex": r"windows|microsoft",
        "fdb_supported": False,
        "vlan_supported": False,
        "stp_supported": False,
        "metrics_hc_supported": True,
    },

    # ── Synology NAS ──────────────────────────────────────────────────────────
    "synology": {
        "display_name": "Synology DSM",
        "sysObjectID_prefix": [],
        "sysdescr_regex": r"synology|dsm",
        "fdb_supported": False,
        "vlan_supported": False,
        "stp_supported": False,
        "metrics_hc_supported": False,
        "extra_oids": {
            "cpu_util":    "1.3.6.1.4.1.6574.1.4.1.0",  # synoSystemCpuUtilization
            "mem_total":   "1.3.6.1.4.1.6574.1.4.2.0",  # synoSystemMemTotal
            "mem_avail":   "1.3.6.1.4.1.6574.1.4.3.0",  # synoSystemMemAvail
            "temp_system": "1.3.6.1.4.1.6574.1.2.0",    # synoSystemTemperature
        },
    },

    # ── QNAP NAS ──────────────────────────────────────────────────────────────
    "qnap": {
        "display_name": "QNAP QTS",
        "sysObjectID_prefix": [],
        "sysdescr_regex": r"qnap|qts",
        "fdb_supported": False,
        "vlan_supported": False,
        "stp_supported": False,
        "metrics_hc_supported": False,
    },

    # ── APC UPS ───────────────────────────────────────────────────────────────
    "apc_ups": {
        "display_name": "APC UPS",
        "sysObjectID_prefix": ["1.3.6.1.4.1.318."],
        "sysdescr_regex": r"apc|american power conversion",
        "fdb_supported": False,
        "vlan_supported": False,
        "stp_supported": False,
        "metrics_hc_supported": False,
        "extra_oids": {
            "battery_status":    "1.3.6.1.4.1.318.1.1.1.2.2.4.0",   # upsAdvBatteryReplaceIndicator
            "battery_capacity":  "1.3.6.1.4.1.318.1.1.1.2.2.1.0",   # upsAdvBatteryCapacity
            "battery_temp":      "1.3.6.1.4.1.318.1.1.1.2.2.2.0",   # upsAdvBatteryTemperature
            "output_load":       "1.3.6.1.4.1.318.1.1.1.4.2.3.0",   # upsAdvOutputLoad
            "output_voltage":    "1.3.6.1.4.1.318.1.1.1.4.2.1.0",   # upsAdvOutputVoltage
        },
    },

    # ── D-Link ────────────────────────────────────────────────────────────────
    "dlink": {
        "display_name": "D-Link",
        "sysObjectID_prefix": ["1.3.6.1.4.1.171."],
        "sysdescr_regex": r"d-link|dlink",
        "fdb_supported": True,
        "vlan_supported": True,
        "stp_supported": True,
        "metrics_hc_supported": False,
    },

    # ── TP-Link ───────────────────────────────────────────────────────────────
    "tplink": {
        "display_name": "TP-Link",
        "sysObjectID_prefix": ["1.3.6.1.4.1.11863."],
        "sysdescr_regex": r"tp-link|tplink",
        "fdb_supported": True,
        "vlan_supported": True,
        "stp_supported": True,
        "metrics_hc_supported": False,
    },

    # ── Extreme Networks ──────────────────────────────────────────────────────
    "extreme": {
        "display_name": "Extreme Networks",
        "sysObjectID_prefix": ["1.3.6.1.4.1.1916.", "1.3.6.1.4.1.1991."],
        "sysdescr_regex": r"extreme|exos",
        "fdb_supported": True,
        "vlan_supported": True,
        "stp_supported": True,
        "metrics_hc_supported": True,
    },

    # ── Fallback — generic (nieznany vendor) ──────────────────────────────────
    "generic": {
        "display_name": "Generic / Unknown",
        "sysObjectID_prefix": [],
        "sysdescr_regex": None,
        "fdb_supported": True,    # probujemy zawsze — debug log jezeli brak MIB
        "vlan_supported": True,
        "stp_supported": True,
        "metrics_hc_supported": True,
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Wykrywanie vendora
# ─────────────────────────────────────────────────────────────────────────────

def detect_vendor_profile(
    sys_object_id: Optional[str],
    sys_descr: Optional[str],
) -> str:
    """Wykrywa vendor profile na podstawie sysObjectID i sysDescr.

    Kolejnosc priorytetow:
      1. sysObjectID prefix match (dokladna, deterministyczna)
      2. sysDescr regex match (fallback gdy OID nieznany)
      3. 'generic' jezeli nic nie pasuje

    Zwraca klucz profilu z VENDOR_PROFILES.
    """
    oid  = (sys_object_id or "").strip().lstrip(".")
    desc = (sys_descr or "").lower()

    # Krok 1: sysObjectID prefix match (deterministyczna metoda)
    # Po dopasowaniu OID, sprawdz czy sysDescr nie wskazuje bardziej specyficznego profilu
    # w tej samej rodzinie (np. Cisco IOS-XE vs Cisco IOS — oba maja ten sam OID prefix).
    for profile_name, profile in VENDOR_PROFILES.items():
        if profile_name == "generic":
            continue
        for prefix in profile.get("sysObjectID_prefix", []):
            if oid.startswith(prefix.lstrip(".")):
                # Refinement: sprawdz czy sysDescr wskazuje inny profil w tej rodzinie
                if desc:
                    for refine_name, refine_profile in VENDOR_PROFILES.items():
                        if refine_name in ("generic", profile_name):
                            continue
                        refine_pattern = refine_profile.get("sysdescr_regex")
                        if refine_pattern and re.search(refine_pattern, desc, re.IGNORECASE):
                            logger.debug(
                                "vendor_profile: %s (OID=%s, refined by sysDescr)", refine_name, profile_name
                            )
                            return refine_name
                logger.debug("vendor_profile: %s (via OID %s)", profile_name, oid[:30])
                return profile_name

    # Krok 2: sysDescr regex fallback (gdy OID nieznany)
    for profile_name, profile in VENDOR_PROFILES.items():
        if profile_name == "generic":
            continue
        pattern = profile.get("sysdescr_regex")
        if pattern and re.search(pattern, desc, re.IGNORECASE):
            logger.debug("vendor_profile: %s (via sysDescr)", profile_name)
            return profile_name

    logger.debug("vendor_profile: generic (oid=%s, descr_prefix=%s)", oid[:20], desc[:30])
    return "generic"


def get_profile(sys_object_id: Optional[str], sys_descr: Optional[str]) -> dict:
    """Skrot: detect + zwroc slownik profilu."""
    name = detect_vendor_profile(sys_object_id, sys_descr)
    return VENDOR_PROFILES.get(name, VENDOR_PROFILES["generic"])
