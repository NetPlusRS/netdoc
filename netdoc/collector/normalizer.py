"""Normalizuje dane z roznych vendorow do wspolnego formatu DeviceData."""
from dataclasses import dataclass, field
from typing import Optional, List
from netdoc.storage.models import DeviceType


@dataclass
class InterfaceData:
    name: str
    mac: Optional[str] = None
    ip: Optional[str] = None
    speed: Optional[int] = None          # Mbps
    duplex: Optional[str] = None
    admin_status: bool = True
    oper_status: bool = False
    description: Optional[str] = None


@dataclass
class NeighborData:
    """Sasiad odkryty przez LLDP/CDP."""
    local_interface: str
    remote_ip: Optional[str] = None
    remote_hostname: Optional[str] = None
    remote_interface: Optional[str] = None
    protocol: str = "lldp"


@dataclass
class DeviceData:
    """Znormalizowane dane urzadzenia — wspolny format niezalezny od vendora."""
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    os_version: Optional[str] = None
    device_type: DeviceType = DeviceType.unknown
    site_id: Optional[str] = None
    location: Optional[str] = None
    interfaces: List[InterfaceData] = field(default_factory=list)
    neighbors: List[NeighborData] = field(default_factory=list)
    raw: dict = field(default_factory=dict)   # oryginalne dane z drivera


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Normalizuje MAC do formatu XX:XX:XX:XX:XX:XX.

    Obslugiwe formaty:
      - AA:BB:CC:DD:EE:FF  (standardowy z dwukropkami)
      - AA-BB-CC-DD-EE-FF  (Windows)
      - AABBCCDDEEFF       (bez separatorow)
      - aabb.ccdd.eeff     (Cisco dot notation)
    """
    if not mac:
        return None
    upper = mac.upper().strip()
    # Cisco dot notation: xxxx.xxxx.xxxx -> 3 grupy po 4 znaki
    dot_parts = upper.split(".")
    if len(dot_parts) == 3 and all(len(p) == 4 for p in dot_parts):
        hex_str = "".join(dot_parts)
        return ":".join(hex_str[i:i+2] for i in range(0, 12, 2))
    cleaned = upper.replace("-", ":").replace(".", ":")
    parts = cleaned.split(":")
    if len(parts) == 1 and len(cleaned) == 12:
        # format bez separatorow np. AABBCCDDEEFF
        parts = [cleaned[i:i+2] for i in range(0, 12, 2)]
    if len(parts) != 6:
        return mac  # zwroc oryginal jesli nie mozna znormalizowac
    return ":".join(p.zfill(2) for p in parts)
