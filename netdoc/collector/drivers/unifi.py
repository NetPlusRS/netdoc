"""Driver dla UniFi Cloud API (api.ui.com)."""
import logging
from typing import Optional, List
import requests
from requests.exceptions import RequestException

from netdoc.collector.drivers.base import BaseDriver
from netdoc.collector.normalizer import DeviceData, InterfaceData, normalize_mac
from netdoc.config.settings import settings
from netdoc.storage.models import DeviceType, Credential

logger = logging.getLogger(__name__)


DEVICE_TYPE_MAP = {
    "usg": DeviceType.router,
    "ugw": DeviceType.router,
    "udm": DeviceType.router,
    "usw": DeviceType.switch,
    "uap": DeviceType.ap,
}


class UnifiDriver(BaseDriver):
    """
    Pobiera dane z UniFi Cloud API.
    Obsluguje: UDM, USG, UniFi AP, UniFi Switch.
    """

    name = "unifi"

    def __init__(self, ip: str, credential: Optional[Credential] = None, site: str = "default"):
        super().__init__(ip, credential)
        self.site = site
        self._session: Optional[requests.Session] = None
        self._base_url = settings.unifi_host

    def _login(self) -> requests.Session:
        session = requests.Session()
        session.verify = False  # UniFi czesto ma self-signed cert
        username = self._get_username() or settings.unifi_username
        password = self._get_password() or settings.unifi_password
        resp = session.post(
            f"{self._base_url}/api/auth/login",
            json={"username": username, "password": password},
            timeout=10,
        )
        resp.raise_for_status()
        return session

    def _get_devices(self, session: requests.Session) -> List[dict]:
        resp = session.get(
            f"{self._base_url}/proxy/network/api/s/{self.site}/stat/device",
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json().get("data", [])

    def collect(self) -> DeviceData:
        """Pobiera dane urzadzenia przez UniFi API."""
        try:
            session = self._login()
            devices = self._get_devices(session)
            # Znajdz urzadzenie po IP
            target = next((d for d in devices if d.get("ip") == self.ip), None)
            if not target:
                logger.warning("UniFi: brak urzadzenia %s w API", self.ip)
                return DeviceData(ip=self.ip)

            return self._parse_device(target)
        except RequestException as e:
            logger.error("UniFi API error dla %s: %s", self.ip, e)
            return DeviceData(ip=self.ip)

    def _parse_device(self, data: dict) -> DeviceData:
        model = data.get("model", "").lower()
        dtype = DeviceType.unknown
        for prefix, dtype_val in DEVICE_TYPE_MAP.items():
            if model.startswith(prefix):
                dtype = dtype_val
                break

        interfaces = []
        for port in data.get("port_table", []):
            interfaces.append(InterfaceData(
                name=port.get("name", f"port{port.get('port_idx', '')}"),
                speed=port.get("speed"),
                oper_status=port.get("up", False),
                admin_status=not port.get("disabled", False),
            ))

        return DeviceData(
            ip=self.ip,
            hostname=data.get("name") or data.get("hostname"),
            mac=normalize_mac(data.get("mac")),
            vendor="Ubiquiti",
            model=data.get("model"),
            os_version=data.get("version"),
            device_type=dtype,
            interfaces=interfaces,
            raw=data,
        )
