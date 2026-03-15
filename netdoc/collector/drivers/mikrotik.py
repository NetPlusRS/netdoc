"""Driver dla MikroTik RouterOS przez SSH (netmiko)."""
import logging
import re
from typing import Optional, List

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

from netdoc.collector.drivers.base import BaseDriver
from netdoc.collector.normalizer import DeviceData, InterfaceData, NeighborData, normalize_mac
from netdoc.storage.models import DeviceType, Credential

logger = logging.getLogger(__name__)


class MikrotikDriver(BaseDriver):
    """
    Laczy sie z MikroTik RouterOS przez SSH.
    Parsuje output komend /interface print oraz /ip neighbor print.
    """

    name = "mikrotik"

    def collect(self) -> DeviceData:
        try:
            with ConnectHandler(
                device_type="mikrotik_routeros",
                host=self.ip,
                username=self._get_username() or "admin",
                password=self._get_password() or "",
                timeout=15,
            ) as conn:
                return self._gather(conn)
        except NetmikoAuthenticationException:
            logger.error("MikroTik: blad autentykacji %s", self.ip)
        except NetmikoTimeoutException:
            logger.error("MikroTik: timeout %s", self.ip)
        except Exception as e:
            logger.error("MikroTik: blad %s: %s", self.ip, e)
        return DeviceData(ip=self.ip)

    def _gather(self, conn) -> DeviceData:
        identity = conn.send_command("/system identity print")
        resource = conn.send_command("/system resource print")
        interfaces_raw = conn.send_command("/interface print detail")
        neighbors_raw = conn.send_command("/ip neighbor print detail")

        hostname = self._parse_value(identity, "name")
        model = self._parse_value(resource, "board-name")
        os_version = self._parse_value(resource, "version")

        interfaces = self._parse_interfaces(interfaces_raw)
        neighbors = self._parse_neighbors(neighbors_raw)

        return DeviceData(
            ip=self.ip,
            hostname=hostname,
            vendor="MikroTik",
            model=model,
            os_version=os_version,
            device_type=DeviceType.router,
            interfaces=interfaces,
            neighbors=neighbors,
        )

    @staticmethod
    def _parse_value(text: str, key: str) -> Optional[str]:
        """Parsuje wartosc z outputu MikroTik w formacie 'key: value'."""
        match = re.search(rf"{re.escape(key)}:\s*(.+)", text)
        return match.group(1).strip() if match else None

    def _parse_interfaces(self, text: str) -> List[InterfaceData]:
        interfaces = []
        blocks = re.split(r"\n\s*\d+\s+", text)
        for block in blocks[1:]:
            name_match = re.search(r'name="([^"]+)"', block)
            mac_match = re.search(r'mac-address=([\da-fA-F:]+)', block)
            running = "running" in block.lower()
            disabled = "disabled" in block.lower()
            if name_match:
                interfaces.append(InterfaceData(
                    name=name_match.group(1),
                    mac=normalize_mac(mac_match.group(1)) if mac_match else None,
                    oper_status=running,
                    admin_status=not disabled,
                ))
        return interfaces

    def _parse_neighbors(self, text: str) -> List[NeighborData]:
        neighbors = []
        blocks = re.split(r"\n\s*\d+\s+", text)
        for block in blocks[1:]:
            iface_match = re.search(r'interface=([\w/]+)', block)
            ip_match = re.search(r'address=([\d.]+)', block)
            identity_match = re.search(r'identity="([^"]+)"', block)
            if iface_match:
                neighbors.append(NeighborData(
                    local_interface=iface_match.group(1),
                    remote_ip=ip_match.group(1) if ip_match else None,
                    remote_hostname=identity_match.group(1) if identity_match else None,
                    protocol="lldp",
                ))
        return neighbors
