"""Testy dla netdoc_pro.passport.generate.collect_device_data.

Sprawdza: data_gaps, hw_summary, filtrowanie interfejsow, prywatnosc danych.
Nie wymaga Pro licence — tylko importuje funkcje bezposrednio.
"""
import pytest
from datetime import datetime, timedelta
from netdoc.storage.models import (
    Device, DeviceType, Interface, DeviceSensor, Credential, CredentialMethod,
)
from netdoc_pro.passport.generate import collect_device_data


# ─── helpers ──────────────────────────────────────────────────────────────────

def _device(db, device_type=DeviceType.switch, snmp_ok_at=None,
            serial=None, vendor="Cisco", model="C2960X"):
    d = Device(
        ip="10.0.0.1",
        device_type=device_type,
        is_active=True,
        vendor=vendor,
        model=model,
        serial_number=serial,
        snmp_ok_at=snmp_ok_at,
    )
    db.add(d)
    db.commit()
    db.refresh(d)
    return d


def _iface(db, device_id, name, if_index, oper_status=True):
    i = Interface(device_id=device_id, name=name, if_index=if_index,
                  oper_status=oper_status, admin_status=True)
    db.add(i)
    db.commit()


def _sensor(db, device_id, name, value, unit="%"):
    s = DeviceSensor(device_id=device_id, sensor_name=name, value=value, unit=unit)
    db.add(s)
    db.commit()


def _ssh_success_cred(db, device_id):
    """Dodaje per-device SSH credential z last_success_at (SSH jest potwierdzone)."""
    c = Credential(
        device_id=device_id,
        method=CredentialMethod.ssh,
        username="admin",
        last_success_at=datetime.utcnow(),
    )
    db.add(c)
    db.commit()


# ─── nieistniejace urzadzenie ─────────────────────────────────────────────────

def test_collect_raises_for_unknown_device(db):
    with pytest.raises(ValueError, match="not found"):
        collect_device_data(db, device_id=99999)


# ─── prywatnosc: ip i hostname nie w snapshot ─────────────────────────────────

def test_collect_does_not_expose_ip_or_hostname(db):
    dev = _device(db)
    snap, _ = collect_device_data(db, dev.id)
    assert "ip" not in snap
    assert "hostname" not in snap


# ─── brak SNMP → data_gap warning ────────────────────────────────────────────

def test_collect_gap_no_snmp(db):
    dev = _device(db, snmp_ok_at=None)
    snap, _ = collect_device_data(db, dev.id)
    fields = [g["field"] for g in snap["data_gaps"]]
    assert "SNMP" in fields
    snmp_gap = next(g for g in snap["data_gaps"] if g["field"] == "SNMP")
    assert snmp_gap["severity"] == "warning"


def test_collect_no_snmp_gap_when_snmp_ok_recent(db):
    dev = _device(db, snmp_ok_at=datetime.utcnow() - timedelta(hours=1))
    snap, _ = collect_device_data(db, dev.id)
    fields = [g["field"] for g in snap["data_gaps"]]
    assert "SNMP" not in fields


def test_collect_snmp_old_shows_info_gap(db):
    dev = _device(db, snmp_ok_at=datetime.utcnow() - timedelta(days=10))
    snap, _ = collect_device_data(db, dev.id)
    fields = [g["field"] for g in snap["data_gaps"]]
    assert "SNMP" in fields
    snmp_gap = next(g for g in snap["data_gaps"] if g["field"] == "SNMP")
    assert snmp_gap["severity"] == "info"


# ─── brak interfejsow → data_gap warning ─────────────────────────────────────

def test_collect_gap_no_interfaces(db):
    dev = _device(db)
    snap, _ = collect_device_data(db, dev.id)
    fields = [g["field"] for g in snap["data_gaps"]]
    assert "Interfaces" in fields


def test_collect_no_iface_gap_when_interfaces_exist(db):
    dev = _device(db, snmp_ok_at=datetime.utcnow())
    _iface(db, dev.id, "GigabitEthernet0/1", if_index=1)
    snap, _ = collect_device_data(db, dev.id)
    fields = [g["field"] for g in snap["data_gaps"]]
    assert "Interfaces" not in fields


# ─── brak sensorow → data_gap warning ────────────────────────────────────────

def test_collect_gap_no_sensors(db):
    dev = _device(db)
    snap, _ = collect_device_data(db, dev.id)
    fields = [g["field"] for g in snap["data_gaps"]]
    assert "Sensors" in fields


def test_collect_no_sensor_gap_when_sensors_exist(db):
    dev = _device(db, snmp_ok_at=datetime.utcnow())
    _sensor(db, dev.id, "cpu_load", 15.0, "%")
    snap, _ = collect_device_data(db, dev.id)
    fields = [g["field"] for g in snap["data_gaps"]]
    assert "Sensors" not in fields


# ─── SSH gap: tylko dla urzadzen z relevant device_type ──────────────────────

def test_collect_ssh_gap_for_switch_without_ssh(db):
    dev = _device(db, device_type=DeviceType.switch)
    snap, _ = collect_device_data(db, dev.id)
    fields = [g["field"] for g in snap["data_gaps"]]
    assert "SSH" in fields


def test_collect_no_ssh_gap_for_camera(db):
    dev = _device(db, device_type=DeviceType.camera)
    snap, _ = collect_device_data(db, dev.id)
    fields = [g["field"] for g in snap["data_gaps"]]
    assert "SSH" not in fields


def test_collect_no_ssh_gap_when_ssh_confirmed(db):
    dev = _device(db, device_type=DeviceType.switch)
    _ssh_success_cred(db, dev.id)
    snap, _ = collect_device_data(db, dev.id)
    fields = [g["field"] for g in snap["data_gaps"]]
    assert "SSH" not in fields


# ─── hw_summary: RAM z sensorow ──────────────────────────────────────────────

def test_hw_ram_from_sensor_ram_total_mb(db):
    dev = _device(db)
    _sensor(db, dev.id, "ram_total_mb", 512.0, "MB")
    snap, _ = collect_device_data(db, dev.id)
    assert snap["hw"]["ram_total_mb"] == 512


def test_hw_ram_from_sensor_mem_total_mb_cisco(db):
    """Cisco: sensor mem_total_mb (nie ram_total_mb)."""
    dev = _device(db)
    _sensor(db, dev.id, "mem_total_mb", 256.0, "MB")
    snap, _ = collect_device_data(db, dev.id)
    assert snap["hw"]["ram_total_mb"] == 256


def test_hw_ram_prefers_ram_total_mb_over_mem_total_mb(db):
    dev = _device(db)
    _sensor(db, dev.id, "ram_total_mb", 1024.0, "MB")
    _sensor(db, dev.id, "mem_total_mb",  512.0, "MB")
    snap, _ = collect_device_data(db, dev.id)
    assert snap["hw"]["ram_total_mb"] == 1024


def test_hw_ram_gap_when_no_ram_sensor(db):
    dev = _device(db)
    snap, _ = collect_device_data(db, dev.id)
    assert snap["hw"]["ram_total_mb"] is None
    fields = [g["field"] for g in snap["data_gaps"]]
    assert "RAM" in fields


# ─── hw_summary: CPU ─────────────────────────────────────────────────────────

def test_hw_cpu_load_from_sensor(db):
    dev = _device(db)
    _sensor(db, dev.id, "cpu_load", 42.0, "%")
    snap, _ = collect_device_data(db, dev.id)
    assert snap["hw"]["cpu_load"] == 42.0


def test_hw_cpu_load_prefers_cisco_5m(db):
    dev = _device(db)
    _sensor(db, dev.id, "cpu_load",    10.0, "%")
    _sensor(db, dev.id, "cpu_load_5m", 25.0, "%")
    snap, _ = collect_device_data(db, dev.id)
    assert snap["hw"]["cpu_load"] == 25.0


# ─── hw_summary: disk ─────────────────────────────────────────────────────────

def test_hw_disk_from_sensor_disk_total_gb(db):
    dev = _device(db)
    _sensor(db, dev.id, "disk_total_gb", 120.0, "GB")
    snap, _ = collect_device_data(db, dev.id)
    assert snap["hw"]["disk_total_gb"] == 120.0


def test_hw_disk_fortinet_fallback_only_when_no_gb_sensor(db):
    """disk_total_mb (Fortinet) uzywany tylko gdy brak disk_total_gb."""
    dev = _device(db)
    _sensor(db, dev.id, "disk_total_mb", 10240.0, "MB")   # 10 GB
    snap, _ = collect_device_data(db, dev.id)
    assert snap["hw"]["disk_total_gb"] == pytest.approx(10.0, abs=0.1)


def test_hw_disk_prefers_gb_over_mb_fortinet(db):
    dev = _device(db)
    _sensor(db, dev.id, "disk_total_gb", 50.0,    "GB")
    _sensor(db, dev.id, "disk_total_mb", 20480.0, "MB")  # 20 GB — nie powinno nadpisac
    snap, _ = collect_device_data(db, dev.id)
    assert snap["hw"]["disk_total_gb"] == 50.0


# ─── filtrowanie wirtualnych interfejsow ─────────────────────────────────────

def test_collect_filters_virtual_interfaces(db):
    dev = _device(db)
    _iface(db, dev.id, "GigabitEthernet0/1", if_index=1)   # fizyczny — zostaje
    _iface(db, dev.id, "lo",                 if_index=2)   # loopback — filtrowany
    _iface(db, dev.id, "docker0",            if_index=3)   # docker — filtrowany
    _iface(db, dev.id, "tun0",               if_index=4)   # VPN — filtrowany
    _iface(db, dev.id, "bond0",              if_index=5)   # bond — filtrowany
    _iface(db, dev.id, "eth0.30",            if_index=6)   # subinterface — filtrowany
    snap, _ = collect_device_data(db, dev.id)
    iface_names = [i["name"] for i in snap["interfaces"]]
    assert iface_names == ["GigabitEthernet0/1"]


# ─── statystyki portow ────────────────────────────────────────────────────────

def test_collect_port_stats(db):
    dev = _device(db)
    _iface(db, dev.id, "Gi0/1", if_index=1, oper_status=True)
    _iface(db, dev.id, "Gi0/2", if_index=2, oper_status=True)
    _iface(db, dev.id, "Gi0/3", if_index=3, oper_status=False)
    snap, _ = collect_device_data(db, dev.id)
    assert snap["ports_total"] == 3
    assert snap["ports_up"]    == 2
    assert snap["ports_down"]  == 1


# ─── brak serial → data_gap ───────────────────────────────────────────────────

def test_collect_gap_no_serial(db):
    dev = _device(db, serial=None)
    snap, _ = collect_device_data(db, dev.id)
    fields = [g["field"] for g in snap["data_gaps"]]
    assert "Serial" in fields


def test_collect_no_serial_gap_when_serial_present(db):
    dev = _device(db, serial="FOC12345678")
    snap, _ = collect_device_data(db, dev.id)
    fields = [g["field"] for g in snap["data_gaps"]]
    assert "Serial" not in fields
