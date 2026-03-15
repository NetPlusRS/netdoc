"""Testy modulu normalizacji danych."""
import pytest
from netdoc.collector.normalizer import normalize_mac, DeviceData, InterfaceData
from netdoc.storage.models import DeviceType


@pytest.mark.parametrize("raw, expected", [
    ("AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF"),
    ("aa-bb-cc-dd-ee-ff", "AA:BB:CC:DD:EE:FF"),
    ("AABBCCDDEEFF", "AA:BB:CC:DD:EE:FF"),
    ("aabb.ccdd.eeff", "AA:BB:CC:DD:EE:FF"),
    (None, None),
    ("invalid", "invalid"),  # zwrot oryginalu gdy nie mozna sparsowac
])
def test_normalize_mac(raw, expected):
    assert normalize_mac(raw) == expected


def test_device_data_defaults():
    d = DeviceData(ip="10.0.0.1")
    assert d.device_type == DeviceType.unknown
    assert d.interfaces == []
    assert d.neighbors == []
    assert d.raw == {}


def test_device_data_with_interfaces():
    iface = InterfaceData(name="eth0", ip="10.0.0.1", speed=1000, oper_status=True)
    d = DeviceData(ip="10.0.0.1", interfaces=[iface])
    assert len(d.interfaces) == 1
    assert d.interfaces[0].speed == 1000
