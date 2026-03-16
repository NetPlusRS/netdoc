"""Generic SNMP driver — SNMP v2c GET, pysnmp 6.x.

Uwagi:
  - Tylko SNMP GET (sysName, sysDescr, sysLocation) — walk przez snmp_walk.py (pure-Python).
  - Fail-fast: jesli sysName nie odpowiada, pomijamy dalsze OID.
  - Timeout: 2 sekundy, bez retry.
"""
import asyncio
import logging
import threading
from typing import Optional, List

from pysnmp.hlapi.asyncio import (
    getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity,
)

from netdoc.collector.drivers.base import BaseDriver
from netdoc.collector.normalizer import DeviceData, InterfaceData, NeighborData
from netdoc.storage.models import Credential

logger = logging.getLogger(__name__)
# pysnmp 6.x zostawia pending asyncio tasks — suppress ERROR-level noise
logging.getLogger("asyncio").setLevel(logging.CRITICAL)

OID_SYSNAME     = "1.3.6.1.2.1.1.5.0"
OID_SYSDESCR    = "1.3.6.1.2.1.1.1.0"
OID_SYSLOCATION = "1.3.6.1.2.1.1.6.0"
OID_SYSOID      = "1.3.6.1.2.1.1.2.0"   # sysObjectID → identyfikacja producenta/modelu
OID_SYSCONTACT  = "1.3.6.1.2.1.1.4.0"   # sysContact  → osoba kontaktowa / opis

# OID-y dla walk (zostawione jako stale dla przyszlych wersji pysnmp)
OID_IFDESCR        = "1.3.6.1.2.1.2.2.1.2"
OID_IFOPERSTATUS   = "1.3.6.1.2.1.2.2.1.8"
OID_IFADMINSTATUS  = "1.3.6.1.2.1.2.2.1.7"
OID_IFSPEED        = "1.3.6.1.2.1.2.2.1.5"
OID_LLDP_REM_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"


async def _async_get(ip: str, community: str, oid: str, timeout: int = 2) -> Optional[str]:
    """Pojedyncze zapytanie SNMP GET z hard timeout."""
    try:
        coro = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),  # v2c
            UdpTransportTarget((ip, 161), timeout=timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        # asyncio.wait_for jako pierwsza warstwa — NIE gwarantuje anulowania w pysnmp 6.x.
        # Prawdziwy timeout zapewnia daemon thread z t.join(timeout) w _snmp_get() powyżej.
        error_indication, error_status, _, var_binds = await asyncio.wait_for(
            coro, timeout=timeout + 1
        )
    except (asyncio.TimeoutError, Exception):
        return None
    if error_indication or error_status:
        return None
    return str(var_binds[0][1]) if var_binds else None


def _snmp_get(ip: str, community: str, oid: str, timeout: int = 2) -> Optional[str]:
    """Synchroniczny wrapper dla SNMP GET z absolutnym timeoutem.

    Uzywa daemon thread — gwarantuje powrot nawet jesli pysnmp blokuje run_until_complete.
    """
    result: list = [None]

    def _run() -> None:
        try:
            loop = asyncio.new_event_loop()
            try:
                result[0] = loop.run_until_complete(_async_get(ip, community, oid, timeout))
            finally:
                loop.close()
        except Exception:
            pass

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=timeout + 2)   # hard wall-clock timeout; thread moze zostac jako daemon
    return result[0]


def _snmp_walk(ip: str, community: str, oid: str, timeout: int = 2) -> dict:
    """Walk SNMP — uzywaj snmp_walk.py (pure-Python), nie pysnmp."""
    return {}


class SNMPDriver(BaseDriver):
    """Pobiera dane przez SNMP v2c — hostname, opis, lokalizacja, vendor (sysObjectID)."""

    name = "snmp"

    def __init__(self, ip: str, credential=None, community: str = "public"):
        super().__init__(ip, credential)
        self.community = community

    def collect(self) -> DeviceData:
        try:
            # Fail-fast: jesli sysName nie odpowiada — nie probuj dalej
            hostname = _snmp_get(self.ip, self.community, OID_SYSNAME)
            if not hostname:
                return DeviceData(ip=self.ip)

            sys_descr = _snmp_get(self.ip, self.community, OID_SYSDESCR)
            location  = _snmp_get(self.ip, self.community, OID_SYSLOCATION)
            sys_oid   = _snmp_get(self.ip, self.community, OID_SYSOID)
            contact   = _snmp_get(self.ip, self.community, OID_SYSCONTACT)

            # sysObjectID → vendor (enterprise OID lookup)
            vendor = None
            if sys_oid:
                try:
                    from netdoc.collector.oid_lookup import oid_db
                    vendor = oid_db.lookup_vendor(sys_oid)
                    if vendor:
                        logger.debug("SNMP OID vendor: %s -> %s (%s)", self.ip, vendor, sys_oid)
                except Exception:
                    pass

            return DeviceData(
                ip=self.ip,
                hostname=hostname,
                vendor=vendor,
                location=location,
                os_version=sys_descr,
                interfaces=[],
                neighbors=[],
                raw={"sysObjectID": sys_oid, "sysContact": contact} if sys_oid else {},
            )
        except Exception as e:
            logger.error("SNMP error dla %s: %s", self.ip, e)
            return DeviceData(ip=self.ip)

    def _collect_interfaces(self) -> List[InterfaceData]:
        """Nie uzywane w tej wersji — walk SNMP niestabilny z pysnmp-lextudio 6.x."""
        return []

    def _collect_lldp_neighbors(self) -> List[NeighborData]:
        """Nie uzywane w tej wersji."""
        return []
