"""Endpoint do zarzadzania credentials (SNMP community, SSH, API keys)."""
import json as _json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime

from netdoc.storage.database import get_db
from netdoc.storage.models import Credential, CredentialMethod, Device, SystemStatus, ScanResult

router = APIRouter(prefix="/api/credentials", tags=["credentials"])


class CredentialIn(BaseModel):
    device_id: Optional[int] = None       # None = global default
    method: CredentialMethod
    username: Optional[str] = None        # SNMP: community string; SSH: login
    password: Optional[str] = None        # SSH password (przechowywana jawnie na razie)
    priority: int = 100
    notes: Optional[str] = None


class CredentialOut(BaseModel):
    model_config = {"from_attributes": True}

    id: int
    device_id: Optional[int]
    device_ip: Optional[str]
    method: str
    username: Optional[str]
    priority: int
    notes: Optional[str]
    last_success_at: Optional[datetime]


@router.get("/", response_model=List[CredentialOut])
def list_credentials(db: Session = Depends(get_db)):
    """Lista wszystkich credentials. Hasla nie sa zwracane."""
    rows = db.query(Credential).order_by(Credential.method, Credential.priority).all()
    # Build device_id → ip map in one query to avoid N+1
    device_ids = {r.device_id for r in rows if r.device_id}
    ip_map: dict = {}
    if device_ids:
        for dev in db.query(Device).filter(Device.id.in_(device_ids)).all():
            ip_map[dev.id] = dev.ip
    result = []
    for r in rows:
        result.append(CredentialOut(
            id=r.id, device_id=r.device_id, device_ip=ip_map.get(r.device_id),
            method=r.method.value, username=r.username,
            priority=r.priority, notes=r.notes,
            last_success_at=r.last_success_at,
        ))
    return result


@router.post("/", response_model=CredentialOut, status_code=201)
def create_credential(body: CredentialIn, db: Session = Depends(get_db)):
    """Dodaj credential. Dla SNMP: username = community string."""
    if body.device_id:
        dev = db.query(Device).filter(Device.id == body.device_id).first()
        if not dev:
            raise HTTPException(404, f"Device {body.device_id} nie istnieje")
    cred = Credential(
        device_id=body.device_id,
        method=body.method,
        username=body.username,
        password_encrypted=body.password,
        priority=body.priority,
        notes=body.notes,
    )
    db.add(cred)
    try:
        db.commit()
        db.refresh(cred)
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Credential już istnieje (duplikat)")
    ip = None
    if cred.device_id:
        dev = db.query(Device).filter(Device.id == cred.device_id).first()
        ip = dev.ip if dev else None
    return CredentialOut(
        id=cred.id, device_id=cred.device_id, device_ip=ip,
        method=cred.method.value, username=cred.username,
        priority=cred.priority, notes=cred.notes,
        last_success_at=cred.last_success_at,
    )


@router.put("/{cred_id}", response_model=CredentialOut)
def update_credential(cred_id: int, body: CredentialIn, db: Session = Depends(get_db)):
    """Zaktualizuj credential."""
    cred = db.query(Credential).filter(Credential.id == cred_id).first()
    if not cred:
        raise HTTPException(404, f"Credential {cred_id} nie istnieje")
    cred.username = body.username
    if body.password is not None:
        cred.password_encrypted = body.password
    cred.priority = body.priority
    cred.notes = body.notes
    db.commit()
    db.refresh(cred)
    ip = None
    if cred.device_id:
        dev = db.query(Device).filter(Device.id == cred.device_id).first()
        ip = dev.ip if dev else None
    return CredentialOut(
        id=cred.id, device_id=cred.device_id, device_ip=ip,
        method=cred.method.value, username=cred.username,
        priority=cred.priority, notes=cred.notes,
        last_success_at=cred.last_success_at,
    )


@router.delete("/bulk/all", status_code=200)
def bulk_delete_credentials(
    method: Optional[str] = None,
    include_device: bool = False,
    db: Session = Depends(get_db),
):
    """Bulk delete credentials. method=None -> wszystkie typy. include_device=True -> rowniez per-device."""
    q = db.query(Credential)
    if not include_device:
        q = q.filter(Credential.device_id.is_(None))
    if method:
        valid = {m.value for m in CredentialMethod}
        if method not in valid:
            raise HTTPException(400, f"Unknown method: {method}")
        q = q.filter(Credential.method == CredentialMethod(method))
    count = q.delete(synchronize_session=False)
    db.commit()
    return {"deleted": count}


@router.delete("/{cred_id}", status_code=204)
def delete_credential(cred_id: int, db: Session = Depends(get_db)):
    """Usun credential."""
    cred = db.query(Credential).filter(Credential.id == cred_id).first()
    if not cred:
        raise HTTPException(404, f"Credential {cred_id} nie istnieje")
    db.delete(cred)
    db.commit()


@router.get("/cred-scan-stats")
def cred_scan_stats(db: Session = Depends(get_db)):
    """Statystyki skanowania credentiali per urzadzenie i per credential globalny.

    Zwraca:
    - devices: lista aktywnych urzadzen z tried/total/queue per protokol, last_attempt_at
    - cred_totals: globalne liczby par per metoda (ssh/api/rdp)
    - last_cycle_at: kiedy ostatni cykl sie zaczynal
    - interval_s: aktualny interwal cyklu [s]
    - global_cred_usage: per globalny credential (id) -> liczba urzadzen z sukcesem
    """
    # 1. Globalne liczniki par per metoda
    def _count_global(method):
        return db.query(func.count(Credential.id)).filter(
            Credential.device_id.is_(None), Credential.method == method
        ).scalar() or 0

    cred_totals = {
        "ssh": _count_global(CredentialMethod.ssh),
        "api": _count_global(CredentialMethod.api),
        "rdp": _count_global(CredentialMethod.rdp),
        "ftp": _count_global(CredentialMethod.ssh),  # FTP uzywa tych samych par co SSH
    }

    # 2. Wszystkie tried_* keys z SystemStatus (jeden SELECT)
    tried_rows = db.query(SystemStatus).filter(
        SystemStatus.key.like("tried_%")
    ).all()
    tried_by_device = {}  # device_id -> {"ssh": set, "api": set, ..., "_at": str}
    for row in tried_rows:
        try:
            dev_id = int(row.key.split("_", 1)[1])
        except (ValueError, IndexError):
            continue
        try:
            raw = _json.loads(row.value or "{}")
        except Exception:
            raw = {}
        tried_by_device[dev_id] = raw

    # 3. Status cyklu
    def _ss(key):
        r = db.query(SystemStatus).filter(SystemStatus.key == key).first()
        return r.value if r else None

    last_cycle_at = _ss("cred_last_cycle_at")
    interval_s    = int(_ss("cred_interval_s_current") or _ss("cred_interval_s") or 60)

    # 4a. Latest scan_result per device — one query, used for port availability flags
    _SSH_PORTS = {22, 2222, 22222}
    _WEB_PORTS = {80, 8080, 8008, 443, 8443, 8888, 5000, 3000, 4000, 9090, 7070, 7443}
    _RDP_PORTS = {3389}
    _FTP_PORTS = {21}

    latest_sq = (
        db.query(ScanResult.device_id, func.max(ScanResult.scan_time).label("last"))
        .group_by(ScanResult.device_id)
        .subquery()
    )
    latest_scans = db.query(ScanResult).join(
        latest_sq,
        (ScanResult.device_id == latest_sq.c.device_id) &
        (ScanResult.scan_time  == latest_sq.c.last),
    ).all()
    # device_id -> set of open port numbers (int)
    open_ports_by_device: dict[int, set] = {}
    for sr in latest_scans:
        if sr.open_ports:
            try:
                open_ports_by_device[sr.device_id] = {int(p) for p in sr.open_ports.keys()}
            except (ValueError, TypeError):
                pass

    # 4b. Lista aktywnych urzadzen z tried stats
    devices = db.query(Device).filter(Device.is_active == True).all()
    dev_stats = []
    for d in devices:
        tried = tried_by_device.get(d.id, {})
        def _tried_count(key):
            v = tried.get(key)
            return len(v) if isinstance(v, list) else 0

        ports = open_ports_by_device.get(d.id, set())
        has_ssh = bool(ports & _SSH_PORTS)
        has_web = bool(ports & _WEB_PORTS)
        has_rdp = bool(ports & _RDP_PORTS)
        has_ftp = bool(ports & _FTP_PORTS)

        dev_stats.append({
            "device_id":     d.id,
            "ip":            d.ip,
            "hostname":      d.hostname or "",
            "ssh_total":     cred_totals["ssh"] if has_ssh else 0,
            "ssh_tried":     _tried_count("ssh"),
            "api_total":     cred_totals["api"] if has_web else 0,
            "api_tried":     _tried_count("api"),
            "rdp_total":     cred_totals["rdp"] if has_rdp else 0,
            "rdp_tried":     _tried_count("rdp"),
            "ftp_tried":     _tried_count("ftp"),
            "has_ssh":       has_ssh,
            "has_web":       has_web,
            "has_rdp":       has_rdp,
            "has_ftp":       has_ftp,
            "last_attempt_at": tried.get("_at"),
            "last_cred_ok_at": d.last_credential_ok_at.isoformat() if d.last_credential_ok_at else None,
        })

    # 5. Per globalny credential — ile urzadzen ma z nim sukces
    #    Liczymy device-specific creds (device_id != None) posortowane po username+password
    dev_creds = db.query(Credential).filter(
        Credential.device_id.isnot(None),
        Credential.last_success_at.isnot(None),
    ).all()
    # Mapowanie (method, user, pass) -> count urzadzen
    from collections import Counter
    _usage: Counter = Counter()
    for c in dev_creds:
        _usage[(c.method, c.username or "", c.password_encrypted or "")] += 1

    # Global creds z usage count
    global_creds = db.query(Credential).filter(Credential.device_id.is_(None)).all()
    global_cred_usage = {}
    for c in global_creds:
        key = (c.method, c.username or "", c.password_encrypted or "")
        global_cred_usage[c.id] = _usage.get(key, 0)

    return {
        "devices":           dev_stats,
        "cred_totals":       cred_totals,
        "last_cycle_at":     last_cycle_at,
        "interval_s":        interval_s,
        "global_cred_usage": global_cred_usage,
    }


@router.get("/snmp-fallback-list")
def snmp_fallback_list(db: Session = Depends(get_db)):
    """Lista community stringow probowanych podczas autodiscovery.

    Zwraca global SNMP credentials z DB (posortowane po priorytecie).
    Jesli baza pusta — fallback do hardcoded listy.
    """
    from netdoc.collector.pipeline import SNMP_COMMUNITY_FALLBACK
    db_communities = [
        c.username for c in
        db.query(Credential)
          .filter(Credential.device_id.is_(None), Credential.method == CredentialMethod.snmp)
          .order_by(Credential.priority)
          .all()
        if c.username
    ]
    communities = db_communities if db_communities else SNMP_COMMUNITY_FALLBACK
    return {"communities": communities, "count": len(communities), "source": "db" if db_communities else "builtin"}
