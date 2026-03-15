"""Testy Modbus TCP / SunSpec driver."""
from unittest.mock import patch, MagicMock
import pytest

from netdoc.collector.drivers.modbus import _regs_to_string, _read_sunspec, ModbusDriver
from netdoc.storage.models import Device, DeviceType

_NULL = bytes([0])


def _str_to_regs(text: str, count: int) -> list:
    """Koduje string do listy count rejestrow Modbus (big-endian, null-padded)."""
    raw = text.encode("utf-8").ljust(count * 2, _NULL)
    return [(raw[i] << 8) | raw[i + 1] for i in range(0, count * 2, 2)]


def _make_sunspec_regs(manufacturer="SMA", model="SB5000", version="3.20", serial="SN99") -> list:
    """Buduje 69-elementowa liste rejestrow zgodna z SunSpec Common Block."""
    sun_id = [0x5375, 0x6e53]  # "SunS"
    header = [1, 65]           # model_id=1, block_len=65
    regs = (sun_id + header
            + _str_to_regs(manufacturer, 16)
            + _str_to_regs(model, 16)
            + _str_to_regs("", 8)
            + _str_to_regs(version, 8)
            + _str_to_regs(serial, 16)
            + [1])
    assert len(regs) == 69
    return regs


def test_regs_to_string_basic():
    """_regs_to_string dekoduje rejestry Modbus do stringa."""
    # "ABC" = 0x41 0x42 0x43 0x00 ...
    regs = [0x4142, 0x4300]
    assert _regs_to_string(regs) == "ABC"


def test_regs_to_string_strips_trailing_nulls():
    """Null bajty na koncu sa usuwane."""
    regs = [0x534d, 0x4100, 0x0000]
    assert _regs_to_string(regs) == "SMA"


def test_read_sunspec_returns_none_on_connection_failure():
    """Brak polaczenia (connect=False) zwraca None."""
    mock_client = MagicMock()
    mock_client.connect.return_value = False
    with patch("netdoc.collector.drivers.modbus.ModbusTcpClient", return_value=mock_client):
        result = _read_sunspec("10.0.0.1")
    assert result is None


def test_read_sunspec_returns_none_on_wrong_id():
    """Zly SunSpec ID zwraca None."""
    mock_client = MagicMock()
    mock_client.connect.return_value = True
    mock_result = MagicMock()
    mock_result.isError.return_value = False
    mock_result.registers = [0x0000, 0x0001] + [0] * 67
    mock_client.read_holding_registers.return_value = mock_result
    with patch("netdoc.collector.drivers.modbus.ModbusTcpClient", return_value=mock_client):
        result = _read_sunspec("10.0.0.1")
    assert result is None


def test_read_sunspec_parses_common_block():
    """Poprawny SunSpec block jest parsowany do slownika."""
    regs = _make_sunspec_regs(manufacturer="SMA", model="SB5000", version="3.20", serial="SN99")
    mock_client = MagicMock()
    mock_client.connect.return_value = True
    mock_result = MagicMock()
    mock_result.isError.return_value = False
    mock_result.registers = regs
    mock_client.read_holding_registers.return_value = mock_result
    with patch("netdoc.collector.drivers.modbus.ModbusTcpClient", return_value=mock_client):
        result = _read_sunspec("10.0.0.1")
    assert result is not None
    assert result["manufacturer"] == "SMA"
    assert result["model"] == "SB5000"
    assert result["version"] == "3.20"
    assert result["serial"] == "SN99"


def test_modbus_driver_collect_returns_device_data():
    """ModbusDriver.collect() zwraca DeviceData z danymi producenta."""
    regs = _make_sunspec_regs(manufacturer="Fronius", model="Primo 8.2", version="1.14", serial="FR987")
    mock_client = MagicMock()
    mock_client.connect.return_value = True
    mock_result = MagicMock()
    mock_result.isError.return_value = False
    mock_result.registers = regs
    mock_client.read_holding_registers.return_value = mock_result
    with patch("netdoc.collector.drivers.modbus.ModbusTcpClient", return_value=mock_client):
        driver = ModbusDriver(ip="10.0.0.2")
        data = driver.collect()
    assert data.vendor == "Fronius"
    assert data.model == "Primo 8.2"
    assert data.os_version == "1.14"
    assert "FR987" in (data.hostname or "")


def test_modbus_driver_collect_returns_empty_on_no_response():
    """Brak odpowiedzi z falownika zwraca pusty DeviceData."""
    mock_client = MagicMock()
    mock_client.connect.return_value = False
    with patch("netdoc.collector.drivers.modbus.ModbusTcpClient", return_value=mock_client):
        driver = ModbusDriver(ip="10.0.0.3")
        data = driver.collect()
    assert data.hostname is None
    assert data.vendor is None


def test_modbus_driver_in_pipeline_when_port_502_open(db):
    """_pick_drivers dodaje ModbusDriver gdy port 502 jest otwarty."""
    from datetime import datetime
    from netdoc.storage.models import ScanResult
    from netdoc.collector.pipeline import _pick_drivers
    from netdoc.collector.drivers.modbus import ModbusDriver

    device = Device(ip="10.5.0.1", device_type=DeviceType.unknown, is_active=True)
    db.add(device); db.commit(); db.refresh(device)

    db.add(ScanResult(
        device_id=device.id,
        scan_time=datetime.utcnow(),
        scan_type="nmap",
        open_ports={"502": {"service": "modbus"}},
    ))
    db.commit()

    with patch("netdoc.collector.pipeline._try_snmp_communities", return_value=None):
        drivers = _pick_drivers(db, device)

    assert any(isinstance(d, ModbusDriver) for d in drivers)
