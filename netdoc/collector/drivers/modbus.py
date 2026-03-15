"""
Modbus TCP + SunSpec driver — odczytuje dane identyfikacyjne z falownikow PV i UPS.

SunSpec Common Block (Model 1) lezy pod adresem bazowym 40001 (offset 40000):
  40001-40002: SunSpec ID = 0x53756e53 ("SunS") — walidacja
  40003:       Model ID = 1 (Common Block)
  40004:       Block length (zwykle 65)
  40005-40020: Manufacturer  (32 znaki UTF-8 = 16 rejestrow)
  40021-40036: Model         (32 znaki = 16 rejestrow)
  40037-40044: Options       (16 znakow = 8 rejestrow)
  40045-40052: SW Version    (16 znakow = 8 rejestrow)
  40053-40068: Serial Number (32 znaki = 16 rejestrow)
  40069:       Device Address (1 rejestr)

Wspierani producenci: SMA, Fronius, SolarEdge, Sungrow, GoodWe, Growatt,
                      Victron, ABB/FIMER, Huawei PV, Schneider, Eaton.
"""
import logging
from typing import Optional

from netdoc.collector.drivers.base import BaseDriver
from netdoc.collector.normalizer import DeviceData

logger = logging.getLogger(__name__)

SUNSPEC_BASE_ADDRESS = 40000      # rejestr 40001 = adres Modbus 40000
SUNSPEC_ID = 0x53756e53           # "SunS"
COMMON_BLOCK_LENGTH = 69          # rejestry 40001..40069
MODBUS_PORT = 502
TIMEOUT = 3

# Import opcjonalny — pymodbus musi byc zainstalowany
try:
    try:
        from pymodbus.client import ModbusTcpClient
    except ImportError:
        from pymodbus.client.sync import ModbusTcpClient  # pymodbus 2.x
except ImportError:
    ModbusTcpClient = None  # type: ignore


def _regs_to_string(registers: list) -> str:
    """Zamienia liste 16-bitowych rejestrow na string UTF-8 (big-endian)."""
    raw = bytearray()
    for reg in registers:
        raw.append((reg >> 8) & 0xFF)
        raw.append(reg & 0xFF)
    return raw.rstrip(bytes([0])).decode("utf-8", errors="replace").strip()


def _read_sunspec(ip: str, port: int = MODBUS_PORT, unit_id: int = 1) -> Optional[dict]:
    """
    Laczy sie do falownika przez Modbus TCP i czyta SunSpec Common Block.
    Zwraca slownik z kluczami: manufacturer, model, options, version, serial.
    Zwraca None jesli brak odpowiedzi lub nie jest to urzadzenie SunSpec.
    """
    if ModbusTcpClient is None:
        logger.warning("pymodbus nie jest zainstalowany — dodaj pymodbus do requirements.txt")
        return None
    try:
        client = ModbusTcpClient(ip, port=port, timeout=TIMEOUT)
        if not client.connect():
            return None

        try:
            result = client.read_holding_registers(
                address=SUNSPEC_BASE_ADDRESS,
                count=COMMON_BLOCK_LENGTH,
                slave=unit_id,
            )
            if result.isError():
                return None

            regs = result.registers
            if len(regs) < COMMON_BLOCK_LENGTH:
                return None

            sunspec_id = (regs[0] << 16) | regs[1]
            if sunspec_id != SUNSPEC_ID:
                logger.debug("Modbus %s: brak SunSpec ID (got 0x%08X)", ip, sunspec_id)
                return None

            return {
                "manufacturer": _regs_to_string(regs[4:20]),
                "model":        _regs_to_string(regs[20:36]),
                "options":      _regs_to_string(regs[36:44]),
                "version":      _regs_to_string(regs[44:52]),
                "serial":       _regs_to_string(regs[52:68]),
                "device_address": regs[68] if len(regs) > 68 else 1,
            }
        finally:
            client.close()

    except Exception as exc:
        logger.debug("Modbus %s: blad polaczenia: %s", ip, exc)
        return None


class ModbusDriver(BaseDriver):
    """Driver Modbus TCP/SunSpec dla falownikow PV i kompatybilnych urz."""

    name = "modbus_sunspec"

    def collect(self) -> DeviceData:
        logger.debug("%s: Modbus SunSpec probe...", self.ip)
        data = _read_sunspec(self.ip)
        if not data:
            return DeviceData(ip=self.ip)

        manufacturer = data.get("manufacturer") or ""
        model = data.get("model") or ""
        version = data.get("version") or ""
        serial = data.get("serial") or ""

        hostname = f"{manufacturer.split()[0]}-{serial}".strip("-") if serial else None

        logger.info(
            "%s: SunSpec OK — %s %s ver:%s sn:%s",
            self.ip, manufacturer, model, version, serial,
        )
        return DeviceData(
            ip=self.ip,
            hostname=hostname,
            vendor=manufacturer or None,
            model=model or None,
            os_version=version or None,
        )
