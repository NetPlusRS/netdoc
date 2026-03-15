"""Driver dla urzadzen Cisco (IOS, IOS-XE, NX-OS) przez SSH + netmiko."""
import logging
import re
from typing import Optional, List

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

from netdoc.collector.drivers.base import BaseDriver
from netdoc.collector.normalizer import DeviceData, InterfaceData, NeighborData, normalize_mac
from netdoc.storage.models import DeviceType, Credential

logger = logging.getLogger(__name__)

# Mapowanie platform netmiko
PLATFORM_MAP = {
    "ios": "cisco_ios",
    "ios-xe": "cisco_xe",
    "nx-os": "cisco_nxos",
    "asa": "cisco_asa",
}


class CiscoDriver(BaseDriver):
    """
    Laczy sie do urzadzenia Cisco przez SSH.
    Parsuje output CLI przy uzyciu ntc-templates.
    """

    name = "cisco"

    def __init__(self, ip: str, credential: Optional[Credential] = None, platform: str = "ios"):
        super().__init__(ip, credential)
        self.platform = PLATFORM_MAP.get(platform, "cisco_ios")

    def _connect(self):
        return ConnectHandler(
            device_type=self.platform,
            host=self.ip,
            username=self._get_username() or "",
            password=self._get_password() or "",
            timeout=15,
            session_log=None,
        )

    def collect(self) -> DeviceData:
        try:
            with self._connect() as conn:
                return self._gather(conn)
        except NetmikoAuthenticationException:
            logger.error("Cisco: blad autentykacji %s", self.ip)
        except NetmikoTimeoutException:
            logger.error("Cisco: timeout %s", self.ip)
        except Exception as e:
            logger.error("Cisco: blad polaczenia %s: %s", self.ip, e)
        return DeviceData(ip=self.ip)

    def _gather(self, conn) -> DeviceData:
        version_output = conn.send_command("show version", use_textfsm=True)
        interfaces_output = conn.send_command("show interfaces", use_textfsm=True)
        lldp_output = conn.send_command("show lldp neighbors detail", use_textfsm=True)

        hostname = conn.base_prompt
        vendor = "Cisco"
        model = None
        os_version = None

        if isinstance(version_output, list) and version_output:
            v = version_output[0]
            model = v.get("hardware", [None])[0] if v.get("hardware") else None
            os_version = v.get("version")

        interfaces = self._parse_interfaces(interfaces_output)
        neighbors = self._parse_lldp_neighbors(lldp_output)

        return DeviceData(
            ip=self.ip,
            hostname=hostname,
            vendor=vendor,
            model=model,
            os_version=os_version,
            device_type=DeviceType.router,
            interfaces=interfaces,
            neighbors=neighbors,
        )

    def _parse_interfaces(self, output) -> List[InterfaceData]:
        if not isinstance(output, list):
            return []
        result = []
        for iface in output:
            result.append(InterfaceData(
                name=iface.get("interface", ""),
                ip=iface.get("ip_address") or None,
                admin_status=iface.get("link_status", "").lower() != "administratively down",
                oper_status=iface.get("protocol_status", "").lower() == "up",
                description=iface.get("description") or None,
            ))
        return result

    def _parse_lldp_neighbors(self, output) -> List[NeighborData]:
        if not isinstance(output, list):
            return []
        result = []
        for neighbor in output:
            result.append(NeighborData(
                local_interface=neighbor.get("local_interface", ""),
                remote_hostname=neighbor.get("neighbor", ""),
                remote_ip=neighbor.get("management_ip") or None,
                remote_interface=neighbor.get("neighbor_interface", ""),
                protocol="lldp",
            ))
        return result
