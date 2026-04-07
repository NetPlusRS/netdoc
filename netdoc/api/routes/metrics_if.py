"""API endpoints dla danych historycznych metryk interfejsow i danych L2.

Endpointy:
    GET /api/devices/{id}/if-metrics         — historia metryki interfejsu z ClickHouse
    GET /api/devices/{id}/if-metrics/rates   — biezace predkosci in/out per interfejs
    GET /api/devices/{id}/port-summary       — zestawienie portow (tryb, VLAN, STP, sasiad, predkosc)
    GET /api/devices/{id}/fdb                — tablica MAC-port (FDB)
    GET /api/devices/{id}/vlan-ports         — przynaleznosc portow do VLAN-ow
    GET /api/devices/{id}/stp                — stan STP + root bridge
    GET /api/devices/{id}/alerts             — aktywne alerty diagnostyczne dla urządzenia
    GET /api/devices/{id}/resource-history   — historia CPU/mem z ClickHouse
    POST /api/devices/{id}/alerts/{alert_id}/ack — potwierdzenie alertu
    GET /api/alerts                          — wszystkie aktywne alerty (sieciowe)
"""
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from netdoc.storage.database import get_db
from netdoc.storage.models import Device, DeviceFdbEntry, DeviceVlanPort, DeviceStpPort, Interface, TopologyLink, DevicePortAlert

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/devices", tags=["metrics-l2"])
alerts_router = APIRouter(prefix="/api/alerts", tags=["diagnostics"])


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
    _ALLOWED_METRICS = {
        "in_octets_hc", "out_octets_hc", "in_octets", "out_octets",
        "in_errors", "out_errors", "in_discards", "out_discards",
    }
    if metric not in _ALLOWED_METRICS:
        raise HTTPException(status_code=400, detail=f"Niedozwolona metryka. Dozwolone: {', '.join(sorted(_ALLOWED_METRICS))}")
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
# Port Summary — zestawienie portów do oceny sieci
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/{device_id}/port-summary")
def get_port_summary(device_id: int, db: Session = Depends(get_db)):
    """Zestawienie wszystkich portów urządzenia do oceny architektury sieci.

    Łączy dane z tabel: interfaces, device_vlan_port, device_stp_port, topology_links.
    Każdy port zawiera:
      - name, alias, speed_mbps, duplex, admin_up, oper_up
      - port_mode (access/trunk/routed), native_vlan, trunk_encap, trunk_vlans
      - stp_role, stp_state
      - neighbor_ip, neighbor_hostname, neighbor_port (LLDP/CDP)
      - vlan_id (dla access), access_vlans (lista dla trunk)
    Użyteczne do planowania migracji do collapsed core / 3-tier.
    """
    _get_device_or_404(device_id, db)

    # Interfejsy
    ifaces = (
        db.query(Interface)
        .filter_by(device_id=device_id)
        .order_by(Interface.if_index)
        .all()
    )

    # VLAN-port: {if_index → [{'vlan_id', 'port_mode', 'is_pvid'}]}
    vlan_rows = db.query(DeviceVlanPort).filter_by(device_id=device_id).all()
    vlan_by_ifidx: dict[int, list[dict]] = {}
    for vr in vlan_rows:
        vlan_by_ifidx.setdefault(vr.if_index, []).append({
            "vlan_id":   vr.vlan_id,
            "vlan_name": vr.vlan_name,
            "port_mode": vr.port_mode,
            "is_pvid":   vr.is_pvid,
        })

    # STP: {if_index → {'role', 'state', 'path_cost'}}
    stp_rows = db.query(DeviceStpPort).filter_by(device_id=device_id).all()
    stp_by_ifidx: dict[int, dict] = {}
    for sr in stp_rows:
        if sr.if_index is not None:
            stp_by_ifidx[sr.if_index] = {
                "stp_role":  sr.stp_role,
                "stp_state": sr.stp_state,
                "path_cost": sr.path_cost,
            }

    # Topology links — sąsiedzi (LLDP/CDP)
    # src_device = ten device → dst = sąsiad; lub odwrotnie
    links_src = (
        db.query(TopologyLink)
        .filter(TopologyLink.src_device_id == device_id)
        .all()
    )
    links_dst = (
        db.query(TopologyLink)
        .filter(TopologyLink.dst_device_id == device_id)
        .all()
    )

    # neighbor: {interface_id → {'neighbor_ip', 'neighbor_hostname', 'neighbor_port', 'protocol'}}
    neighbor_by_iface_id: dict[int, dict] = {}

    for lnk in links_src:
        # src = nasz interfejs, dst = sąsiad
        if lnk.src_interface_id is None:
            continue
        nb_dev = db.query(Device).filter_by(id=lnk.dst_device_id).first()
        nb_iface = db.query(Interface).filter_by(id=lnk.dst_interface_id).first() if lnk.dst_interface_id else None
        neighbor_by_iface_id[lnk.src_interface_id] = {
            "neighbor_ip":       str(nb_dev.ip) if nb_dev else None,
            "neighbor_hostname": nb_dev.hostname or (str(nb_dev.ip) if nb_dev else None),
            "neighbor_port":     nb_iface.name if nb_iface else None,
            "neighbor_alias":    nb_iface.alias if nb_iface else None,
            "protocol":          lnk.protocol.value if lnk.protocol else None,
        }

    for lnk in links_dst:
        # dst = nasz interfejs, src = sąsiad
        if lnk.dst_interface_id is None:
            continue
        if lnk.dst_interface_id in neighbor_by_iface_id:
            continue  # już mamy
        nb_dev = db.query(Device).filter_by(id=lnk.src_device_id).first()
        nb_iface = db.query(Interface).filter_by(id=lnk.src_interface_id).first() if lnk.src_interface_id else None
        neighbor_by_iface_id[lnk.dst_interface_id] = {
            "neighbor_ip":       str(nb_dev.ip) if nb_dev else None,
            "neighbor_hostname": nb_dev.hostname or (str(nb_dev.ip) if nb_dev else None),
            "neighbor_port":     nb_iface.name if nb_iface else None,
            "neighbor_alias":    nb_iface.alias if nb_iface else None,
            "protocol":          lnk.protocol.value if lnk.protocol else None,
        }

    _STP_STATE_LABELS = {
        1: "disabled", 2: "blocking", 3: "listening",
        4: "learning", 5: "forwarding", 6: "broken",
    }

    ports = []
    for iface in ifaces:
        vlans = vlan_by_ifidx.get(iface.if_index, [])
        stp   = stp_by_ifidx.get(iface.if_index, {})
        nb    = neighbor_by_iface_id.get(iface.id, {})

        # Tryb portu: priorytet danych z Cisco VTP MIB (iface.port_mode),
        # fallback do device_vlan_port (access/trunk z bitstringa)
        port_mode = iface.port_mode
        if not port_mode and vlans:
            modes = {v["port_mode"] for v in vlans if v["port_mode"]}
            if "trunk" in modes:
                port_mode = "trunk"
            elif "access" in modes:
                port_mode = "access"

        # VLAN info
        pvid_entry = next((v for v in vlans if v["is_pvid"]), None)
        native_vlan = iface.native_vlan or (pvid_entry["vlan_id"] if pvid_entry else None)
        access_vlans = sorted({v["vlan_id"] for v in vlans}) if vlans else []

        ports.append({
            "if_index":       iface.if_index,
            "name":           iface.name,
            "alias":          iface.alias,
            "mac":            iface.mac,
            "ip":             iface.ip,
            "speed_mbps":     iface.speed,
            "duplex":         iface.duplex,
            "admin_up":       iface.admin_status,
            "oper_up":        iface.oper_status,
            # Tryb portu
            "port_mode":      port_mode,
            "native_vlan":    native_vlan,
            "trunk_encap":    iface.trunk_encap,
            "trunk_vlans":    iface.trunk_vlans,
            "access_vlans":   access_vlans,
            # STP
            "stp_role":       stp.get("stp_role"),
            "stp_state":      _STP_STATE_LABELS.get(stp.get("stp_state"), None),
            "stp_path_cost":  stp.get("path_cost"),
            # Sąsiad LLDP/CDP
            "neighbor_ip":        nb.get("neighbor_ip"),
            "neighbor_hostname":  nb.get("neighbor_hostname"),
            "neighbor_port":      nb.get("neighbor_port"),
            "neighbor_alias":     nb.get("neighbor_alias"),
            "neighbor_protocol":  nb.get("protocol"),
        })

    return {"device_id": device_id, "ports": ports}


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
        mac_safe = mac.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        q = q.filter(DeviceFdbEntry.mac.ilike(f"%{mac_safe}%", escape="\\"))
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
        if e.vlan_id is None:
            continue
        if e.vlan_id not in vlans:
            vlans[e.vlan_id] = {
                "vlan_id":   e.vlan_id,
                "vlan_name": e.vlan_name,
                "ports":     [],
                "polled_at": e.polled_at.isoformat() if e.polled_at else None,
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
        "is_root":      (dev.mac.lower() == dev.stp_root_mac.lower()) if (dev.mac and dev.stp_root_mac) else None,
        "ports": [
            {
                "stp_port_num":  p.stp_port_num,
                "if_index":      p.if_index,
                "interface_name": ifname_map.get(p.if_index) if p.if_index else None,
                "stp_state":     p.stp_state,
                "stp_state_label": _STP_STATE_LABELS.get(p.stp_state) if p.stp_state is not None else None,
                "stp_role":      p.stp_role,
                "path_cost":     p.path_cost,
                "polled_at":     p.polled_at.isoformat() if p.polled_at else None,
            }
            for p in ports
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Diagnostics — alerty per urządzenie
# ─────────────────────────────────────────────────────────────────────────────

def _alert_to_dict(a: DevicePortAlert, device_name: str | None = None) -> dict:
    return {
        "id":              a.id,
        "device_id":       a.device_id,
        "device_name":     device_name,
        "if_index":        a.if_index,
        "interface_name":  a.interface_name,
        "alert_type":      a.alert_type,
        "severity":        a.severity,
        "value_current":   a.value_current,
        "value_baseline":  a.value_baseline,
        "trend_pct":       a.trend_pct,
        "first_seen":      a.first_seen.isoformat() if a.first_seen else None,
        "last_seen":       a.last_seen.isoformat()  if a.last_seen  else None,
        "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
    }


@router.get("/{device_id}/diag-alerts")
def get_device_diag_alerts(device_id: int, db: Session = Depends(get_db)):
    """Zwraca aktywne alerty diagnostyczne dla urządzenia."""
    _get_device_or_404(device_id, db)
    alerts = (
        db.query(DevicePortAlert)
        .filter(DevicePortAlert.device_id == device_id)
        .order_by(DevicePortAlert.severity.desc(), DevicePortAlert.last_seen.desc())
        .all()
    )
    return {"device_id": device_id, "alerts": [_alert_to_dict(a) for a in alerts]}


@router.get("/{device_id}/resource-history")
def get_resource_history(
    device_id: int,
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
):
    """Zwraca historię CPU i pamięci RAM z ClickHouse."""
    _get_device_or_404(device_id, db)
    step = 5 if hours <= 6 else (10 if hours <= 24 else (30 if hours <= 72 else 60))
    try:
        from netdoc.storage.clickhouse import query_resource_history
        data = query_resource_history(device_id, hours=hours, step_minutes=step)
    except Exception as exc:
        logger.warning("resource-history %d: %s", device_id, exc)
        data = []
    return {"device_id": device_id, "hours": hours, "step_minutes": step, "data": data}


@router.post("/{device_id}/diag-alerts/{alert_id}/ack")
def acknowledge_alert(device_id: int, alert_id: int, db: Session = Depends(get_db)):
    """Potwierdza (wycisza) alert — ustawia acknowledged_at = now."""
    _get_device_or_404(device_id, db)
    alert = db.query(DevicePortAlert).filter_by(id=alert_id, device_id=device_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged_at = datetime.utcnow()
    db.commit()
    return {"status": "ok", "alert_id": alert_id}


# ─────────────────────────────────────────────────────────────────────────────
# Sieciowe alerty — wszystkie urządzenia
# ─────────────────────────────────────────────────────────────────────────────

@alerts_router.get("")
def get_all_alerts(
    severity: Optional[str] = Query(None, description="warning|critical"),
    acknowledged: bool = Query(False, description="Pokaż potwierdzone"),
    db: Session = Depends(get_db),
):
    """Wszystkie aktywne alerty diagnostyczne w sieci."""
    q = db.query(DevicePortAlert, Device.hostname, Device.ip).join(
        Device, DevicePortAlert.device_id == Device.id
    )
    if severity:
        q = q.filter(DevicePortAlert.severity == severity)
    if not acknowledged:
        q = q.filter(DevicePortAlert.acknowledged_at.is_(None))
    q = q.order_by(DevicePortAlert.severity.desc(), DevicePortAlert.last_seen.desc())

    rows = q.all()
    return {
        "total": len(rows),
        "alerts": [
            _alert_to_dict(alert, device_name=hostname or str(ip))
            for alert, hostname, ip in rows
        ],
    }
