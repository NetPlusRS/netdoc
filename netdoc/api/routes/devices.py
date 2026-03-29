"""CRUD endpoints dla urzadzen."""
from typing import List, Optional
from datetime import datetime, date as pydate
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from netdoc.storage.database import get_db
from netdoc.storage.models import Device, DeviceType
from netdoc.notifications.telegram import FLAG_COLORS

router = APIRouter(prefix="/api/devices", tags=["devices"])


# --- Schematy Pydantic ---

class DeviceOut(BaseModel):
    id: int
    ip: str
    hostname: Optional[str]
    mac: Optional[str]
    vendor: Optional[str]
    model: Optional[str]
    os_version: Optional[str]
    device_type: DeviceType
    site_id: Optional[str]
    location: Optional[str]
    is_active: bool
    first_seen: datetime
    last_seen: datetime
    warranty_end: Optional[datetime] = None
    is_trusted: bool = False
    trust_note: Optional[str] = None
    trust_category: Optional[str] = None
    trusted_at: Optional[datetime] = None
    flag_color: Optional[str] = None
    is_monitored: bool = False
    monitor_note: Optional[str] = None
    monitor_since: Optional[datetime] = None
    # Inwentaryzacja / dane urządzenia
    serial_number: Optional[str] = None
    asset_tag: Optional[str] = None
    responsible_person: Optional[str] = None
    asset_notes: Optional[str] = None
    sys_contact: Optional[str] = None
    ip_type: str = "unknown"
    snmp_community: Optional[str] = None
    snmp_ok_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    location: Optional[str] = None
    site_id: Optional[str] = None
    device_type: Optional[DeviceType] = None
    # Inwentaryzacja / dane urządzenia
    serial_number: Optional[str] = None
    asset_tag: Optional[str] = None
    responsible_person: Optional[str] = None
    asset_notes: Optional[str] = None
    sys_contact: Optional[str] = None


class TrustUpdate(BaseModel):
    trusted: bool
    note: Optional[str] = None
    category: Optional[str] = None  # infrastructure / endpoint / iot / guest / other


class FlagUpdate(BaseModel):
    color: Optional[str] = None  # None = usun flage; dozwolone: red/orange/yellow/green/blue/purple

    @field_validator("color")
    @classmethod
    def validate_color(cls, v):
        if v is not None and v not in FLAG_COLORS:
            raise ValueError(f"Niedozwolony kolor flagi. Dozwolone: {', '.join(FLAG_COLORS)}")
        return v


class MonitorUpdate(BaseModel):
    monitored: bool
    note: Optional[str] = None  # opis co jest monitorowane


IP_TYPES = ("static", "dhcp", "unknown")

class IpTypeUpdate(BaseModel):
    ip_type: str

    @field_validator("ip_type")
    @classmethod
    def validate_ip_type(cls, v):
        if v not in IP_TYPES:
            raise ValueError(f"Niedozwolony typ IP. Dozwolone: {', '.join(IP_TYPES)}")
        return v


# --- Endpointy ---

@router.get("/", response_model=List[DeviceOut])
def list_devices(
    active_only: bool = Query(default=False, description="Tylko aktywne urzadzenia"),
    device_type: Optional[DeviceType] = Query(default=None),
    db: Session = Depends(get_db),
):
    """Zwraca liste urzadzen z opcjonalnym filtrowaniem."""
    q = db.query(Device)
    if active_only:
        q = q.filter(Device.is_active == True)
    if device_type:
        q = q.filter(Device.device_type == device_type)
    return q.order_by(Device.ip).all()


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(device_id: int, db: Session = Depends(get_db)):
    """Zwraca szczegoly urzadzenia."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Urzadzenie nie znalezione")
    return device


@router.patch("/{device_id}", response_model=DeviceOut)
def update_device(device_id: int, payload: DeviceUpdate, db: Session = Depends(get_db)):
    """Aktualizuje edytowalne pola urzadzenia (hostname, location, itp.)."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Urzadzenie nie znalezione")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(device, field, value)
    db.commit()
    db.refresh(device)
    return device


@router.delete("/scan-results", status_code=200)
def clear_bulk_scan_results(
    device_ids: Optional[str] = Query(None, description="Przecinkowa lista device_id; brak = wszystkie"),
    scan_type: Optional[str] = Query(None, description="Typ skanu: nmap, nmap_full lub None = wszystkie"),
    db: Session = Depends(get_db),
):
    """Usuwa wyniki skanowania portow dla wielu urzadzen naraz.

    device_ids=1,2,3  → tylko te urzadzenia
    brak device_ids   → wszystkie urzadzenia
    scan_type         → filtr po typie skanu
    """
    from netdoc.storage.models import ScanResult
    q = db.query(ScanResult)
    if device_ids:
        try:
            ids = [int(x.strip()) for x in device_ids.split(",") if x.strip()]
        except ValueError:
            raise HTTPException(status_code=400, detail="Nieprawidlowy format device_ids")
        q = q.filter(ScanResult.device_id.in_(ids))
    if scan_type:
        q = q.filter(ScanResult.scan_type == scan_type)
    deleted = q.delete(synchronize_session=False)
    db.commit()
    return {"deleted": deleted}


@router.delete("/{device_id}", status_code=204)
def delete_device(
    device_id: int,
    force: bool = False,
    db: Session = Depends(get_db),
):
    """Usuwa urzadzenie z bazy.

    Domyslnie nie pozwala usunac aktywnego urzadzenia (force=False).
    Przy force=true usuwa rowniez aktywne — urzadzenie zostanie ponownie
    odkryte przy nastepnym skanie jesli nadal jest w sieci.
    """
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Urzadzenie nie znalezione")
    if device.is_active and not force:
        raise HTTPException(
            status_code=409,
            detail="Urzadzenie jest aktywne. Uzyj force=true aby usunac.",
        )
    db.delete(device)
    db.commit()


@router.patch("/{device_id}/trust", response_model=DeviceOut)
def set_device_trust(device_id: int, payload: TrustUpdate, db: Session = Depends(get_db)):
    """Ustawia lub usuwa status zaufanego urzadzenia."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Urzadzenie nie znalezione")
    device.is_trusted = payload.trusted
    if payload.trusted:
        device.trust_note = payload.note
        device.trust_category = payload.category
        device.trusted_at = datetime.utcnow()
    else:
        device.trust_note = None
        device.trust_category = None
        device.trusted_at = None
    db.commit()
    db.refresh(device)
    return device


@router.patch("/{device_id}/flag", response_model=DeviceOut)
def set_device_flag(device_id: int, payload: FlagUpdate, db: Session = Depends(get_db)):
    """Ustawia lub usuwa kolorowa flage urzadzenia.

    color: red | orange | yellow | green | blue | purple | null (brak flagi)
    """
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Urzadzenie nie znalezione")
    device.flag_color = payload.color
    db.commit()
    db.refresh(device)
    return device


@router.patch("/{device_id}/monitor", response_model=DeviceOut)
def set_device_monitor(device_id: int, payload: MonitorUpdate, db: Session = Depends(get_db)):
    """Wlacza lub wylacza monitorowanie dostepnosci urzadzenia.

    Gdy is_monitored=True i urzadzenie stanie sie niedostepne,
    wyslany zostanie alert przez skonfigurowane kanaly (np. Telegram).
    """
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Urzadzenie nie znalezione")
    device.is_monitored = payload.monitored
    if payload.monitored:
        device.monitor_note = payload.note
        device.monitor_since = datetime.utcnow()
    else:
        device.monitor_note = None
        device.monitor_since = None
    db.commit()
    db.refresh(device)
    return device


@router.patch("/{device_id}/ip-type", response_model=DeviceOut)
def set_ip_type(device_id: int, payload: IpTypeUpdate, db: Session = Depends(get_db)):
    """Ustawia typ adresacji IP urzadzenia (static/dhcp/unknown)."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Urzadzenie nie znalezione")
    device.ip_type = payload.ip_type
    db.commit()
    db.refresh(device)
    return device


@router.post("/{device_id}/reclassify", response_model=DeviceOut)
def reclassify_device(device_id: int, db: Session = Depends(get_db)):
    """Ponownie klasyfikuje typ urzadzenia na podstawie dostepnych danych.

    Uzywa otwartych portow z ostatniego skanu, vendora i hostname.
    """
    from netdoc.storage.models import ScanResult
    from netdoc.collector.discovery import _guess_device_type
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Urzadzenie nie znalezione")
    # Pobierz porty z ostatniego skanu
    latest_scan = (
        db.query(ScanResult)
        .filter(ScanResult.device_id == device_id)
        .order_by(ScanResult.scan_time.desc())
        .first()
    )
    open_ports: set = set()
    open_ports_detail: dict = {}
    if latest_scan and latest_scan.open_ports:
        try:
            open_ports = {int(p) for p in latest_scan.open_ports.keys()}
            open_ports_detail = {int(p): v for p, v in latest_scan.open_ports.items()
                                 if isinstance(v, dict)}
        except (ValueError, TypeError):
            pass
    new_type = _guess_device_type(
        open_ports, device.os_version, device.vendor, device.mac,
        hostname=device.hostname, open_ports_detail=open_ports_detail,
    )
    device.device_type = new_type
    db.commit()
    db.refresh(device)
    return device


@router.delete("/{device_id}/scan-results", status_code=200)
def clear_device_scan_results(
    device_id: int,
    scan_type: Optional[str] = Query(None, description="Typ skanu do usuniecia: nmap, nmap_full lub None = wszystkie"),
    db: Session = Depends(get_db),
):
    """Usuwa wyniki skanowania portow dla danego urzadzenia.

    scan_type=nmap_full  → tylko pelny skan 1-65535
    scan_type=nmap       → tylko szybki skan
    brak parametru       → oba typy
    """
    from netdoc.storage.models import ScanResult
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Urzadzenie nie znalezione")
    q = db.query(ScanResult).filter(ScanResult.device_id == device_id)
    if scan_type:
        q = q.filter(ScanResult.scan_type == scan_type)
    deleted = q.delete(synchronize_session=False)
    db.commit()
    return {"deleted": deleted, "device_id": device_id}


@router.get("/{device_id}/alerts")
def get_device_alerts(device_id: int, db: Session = Depends(get_db)):
    """Zwraca historie alertow monitorowania dla urzadzenia."""
    from netdoc.storage.models import MonitoringAlert
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Urzadzenie nie znalezione")
    alerts = (
        db.query(MonitoringAlert)
        .filter(MonitoringAlert.device_id == device_id)
        .order_by(MonitoringAlert.sent_at.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "id": a.id,
            "alert_type": a.alert_type,
            "message": a.message,
            "channel": a.channel,
            "delivered": a.delivered,
            "sent_at": a.sent_at.isoformat() if a.sent_at else None,
        }
        for a in alerts
    ]
