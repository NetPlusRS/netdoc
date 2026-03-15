"""Abstrakcyjna klasa bazowa dla wszystkich driverow."""
from abc import ABC, abstractmethod
from typing import Optional
from netdoc.collector.normalizer import DeviceData
from netdoc.storage.models import Credential


class BaseDriver(ABC):
    """
    Kazdy driver musi implementowac metode collect().
    Driver otrzymuje adres IP i opcjonalne credentials,
    zwraca znormalizowany DeviceData.
    """

    name: str = "base"

    def __init__(self, ip: str, credential: Optional[Credential] = None):
        self.ip = ip
        self.credential = credential

    @abstractmethod
    def collect(self) -> DeviceData:
        """Zbiera dane z urzadzenia i zwraca znormalizowany DeviceData."""
        ...

    def _get_username(self) -> Optional[str]:
        return self.credential.username if self.credential else None

    def _get_password(self) -> Optional[str]:
        if not self.credential or not self.credential.password_encrypted:
            return None
        from netdoc.config.credentials import decrypt
        return decrypt(self.credential.password_encrypted)

    def _get_api_key(self) -> Optional[str]:
        if not self.credential or not self.credential.api_key_encrypted:
            return None
        from netdoc.config.credentials import decrypt
        return decrypt(self.credential.api_key_encrypted)
