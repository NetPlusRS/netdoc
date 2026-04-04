"""API endpoints dla danych historycznych metryk interfejsow i danych L2.

Endpointy:
    GET /api/devices/{id}/if-metrics         — historia metryki interfejsu z ClickHouse
    GET /api/devices/{id}/if-metrics/rates   — biezace predkosci in/out per interfejs
    GET /api/devices/{id}/fdb                — tablica MAC-port (FDB)
    GET /api/devices/{id}/vlan-ports         — przynaleznosc portow do VLAN-ow
    GET /api/devices/{id}/stp                — stan STP + root bridge
"""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from netdoc.storage.database import get_db
from netdoc.storage.models import Device, DeviceFdbEntry, DeviceVlanPort, DeviceStpPort, Interface

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/devices", tags=["metrics-l2"])


def _get_device_or_404(device_id: int, db: Session) -> Device:
    dev = db.query(Device).filter_by(id=device_id).first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    return dev


# ─────────────────────────────────────────────────────────────────────────────
# Interface metrics (ClickHouse)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/{device_id}/if-metrics")
def get_if_metrics_history(
    device_id: int,
    if_index: int = Query(..., description="ifIndex interfejsu"),
    metric: str = Query(
        "in_octets_hc",
        description="Nazwa metryki: in_octets_hc, out_octets_hc, in_octets, out_octets, in_errors, out_errors, in_discards, out_discards",
    ),
    hours: int = Query(24, ge=1, le=720, description="Zakres czasu wstecz w godzinach"),
    step_minutes: int = Query(5, ge=1, le=60, description="Granularnosc agregacji w minutach"),
    db: Session = Depends(get_db),
):
    """Historia metryki interfejsu z ClickHouse — dane do wykresow.

    Zwraca liste punktow: {bucket (datetime), avg_value, max_value}
    Wartosci dla licznikow octets: bajty/s (pochodna licznika / krok czasu).
    GUI mnozy przez 8 aby uzyskac bps. Dla in_errors/out_errors: delty/s.
    """
    _get_device_or_404(device_id, db)

    # Pobierz nazwe interfejsu (jezeli dostepna)
    iface = db.query(Interface).filter_by(device_id=device_id, if_index=if_index).first()
    interface_name = iface.name if iface else None

    try:
        from netdoc.storage.clickhouse import query_if_metrics_history
        buckets = query_if_metrics_history(device_id, if_index, metric, hours, step_minutes)
    except Exception as exc:
        logger.warning("get_if_metrics_history device=%d: %s", device_id, exc)
        buckets = []

    return {
        "device_id":      device_id,
        "if_index":       if_index,
        "interface_name": interface_name,
        "metric":         metric,
        "hours":          hours,
        "step_minutes":   step_minutes,
        "buckets":        buckets,
    }


@router.get("/{device_id}/if-metrics/rates")
def get_if_current_rates(
    device_id: int,
    since_minutes: int = Query(10, ge=1, le=60, description="Okno do obliczenia aktualnej predkosci"),
    db: Session = Depends(get_db),
):
    """Biezace predkosci in/out (bps) per interfejs — dane do tabeli podsumowania.

    Zwraca liste interfejsow z polami:
        if_index, interface_name, in_bps, out_bps, in_errors, out_errors, in_discards, out_discards
    """
    _get_device_or_404(device_id, db)

    # Pobierz mapowanie if_index → interface_name
    ifaces = db.query(Interface.if_index, Interface.name).filter_by(device_id=device_id).all()
    ifname_map = {row.if_index: row.name for row in ifaces if row.if_index}

    try:
        from netdoc.storage.clickhouse import query_if_current_rates
        rates = query_if_current_rates(device_id, since_minutes)
    except Exception as exc:
        logger.warning("get_if_current_rates device=%d: %s", device_id, exc)
        rates = []

    for r in rates:
        r["interface_name"] = ifname_map.get(r["if_index"])

    return {
        "device_id":     device_id,
        "since_minutes": since_minutes,
        "interfaces":    rates,
    }


# ─────────────────────────────────────────────────────────────────────────────
# FDB — MAC-port forwarding table
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/{device_id}/fdb")
def get_fdb(
    device_id: int,
    mac: Optional[str] = Query(None, description="Filtruj po fragmentach MAC (case-insensitive)"),
    if_index: Optional[int] = Query(None, description="Filtruj po ifIndex portu"),
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    """Tablica przekazywania MAC (FDB) switcha — mapowanie MAC → port fizyczny.

    Pozwala znalezc na ktorym porcie switcha znajduje sie dane urzadzenie.
    fdb_status: 3=learned (dynamiczny), 5=static (konfigurowany recznie)
    """
    _get_device_or_404(device_id, db)

    q = db.query(DeviceFdbEntry).filter_by(device_id=device_id)
    if mac:
        q = q.filter(DeviceFdbEntry.mac.ilike(f"%{mac.replace(':', '').lower()}%"))
    if if_index is not None:
        q = q.filter(DeviceFdbEntry.if_index == if_index)

    total = q.count()
    entries = q.order_by(DeviceFdbEntry.bridge_port, DeviceFdbEntry.mac).limit(limit).all()

    return {
        "device_id": device_id,
        "total":     total,
        "limit":     limit,
        "entries": [
            {
                "mac":            e.mac,
                "bridge_port":    e.bridge_port,
                "if_index":       e.if_index,
                "interface_name": e.interface_name,
                "vlan_id":        e.vlan_id,
                "fdb_status":     e.fdb_status,
                "polled_at":      e.polled_at.isoformat() if e.polled_at else None,
            }
            for e in entries
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# VLAN membership
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/{device_id}/vlan-ports")
def get_vlan_ports(
    device_id: int,
    vlan_id: Optional[int] = Query(None, description="Filtruj po numerze VLAN"),
    db: Session = Depends(get_db),
):
    """Przynaleznosc portow do VLAN-ow — ktore porty sa w jakim VLAN-ie.

    port_mode: 'access' (untagged) lub 'trunk' (tagged)
    is_pvid: True jezeli to natywny/domyslny VLAN portu
    """
    _get_device_or_404(device_id, db)

    q = db.query(DeviceVlanPort).filter_by(device_id=device_id)
    if vlan_id is not None:
        q = q.filter(DeviceVlanPort.vlan_id == vlan_id)

    entries = q.order_by(DeviceVlanPort.vlan_id, DeviceVlanPort.if_index).all()

    # Zgrupuj per VLAN
    vlans: dict[int, dict] = {}
    for e in entries:
        if e.vlan_id not in vlans:
            vlans[e.vlan_id] = {
                "vlan_id":   e.vlan_id,
                "vlan_name": e.vlan_name,
                "ports":     [],
            }
        vlans[e.vlan_id]["ports"].append({
            "if_index":  e.if_index,
            "port_mode": e.port_mode,
            "is_pvid":   e.is_pvid,
        })

    return {
        "device_id": device_id,
        "vlans":     list(vlans.values()),
        "total_entries": len(entries),
    }


# ─────────────────────────────────────────────────────────────────────────────
# STP — Spanning Tree Protocol
# ─────────────────────────────────────────────────────────────────────────────

_STP_STATE_LABELS = {
    1: "disabled",
    2: "blocking",
    3: "listening",
    4: "learning",
    5: "forwarding",
    6: "broken",
}

@router.get("/{device_id}/stp")
def get_stp(
    device_id: int,
    db: Session = Depends(get_db),
):
    """Stan STP (Spanning Tree Protocol) — root bridge + stan portow.

    stp_state: 2=blocking (orange), 5=forwarding (green), 1=disabled (gray)
    stp_role: root, designated, alternate, backup
    """
    dev = _get_device_or_404(device_id, db)

    ports = db.query(DeviceStpPort).filter_by(device_id=device_id).order_by(
        DeviceStpPort.stp_port_num
    ).all()

    # Pobierz nazwy interfejsow
    if_indices = [p.if_index for p in ports if p.if_index]
    ifname_map: dict[int, str] = {}
    if if_indices:
        ifaces = db.query(Interface.if_index, Interface.name).filter(
            Interface.device_id == device_id,
            Interface.if_index.in_(if_indices),
        ).all()
        ifname_map = {row.if_index: row.name for row in ifaces}

    return {
        "device_id":    device_id,
        "root_mac":     dev.stp_root_mac,
        "root_cost":    dev.stp_root_cost,
        "is_root":      dev.mac == dev.stp_root_mac if (dev.mac and dev.stp_root_mac) else None,
        "ports": [
            {
                "stp_port_num":  p.stp_port_num,
                "if_index":      p.if_index,
                "interface_name": ifname_map.get(p.if_index) if p.if_index else None,
                "stp_state":     p.stp_state,
                "stp_state_label": _STP_STATE_LABELS.get(p.stp_state, str(p.stp_state)),
                "stp_role":      p.stp_role,
                "path_cost":     p.path_cost,
                "polled_at":     p.polled_at.isoformat() if p.polled_at else None,
            }
            for p in ports
        ],
    }
