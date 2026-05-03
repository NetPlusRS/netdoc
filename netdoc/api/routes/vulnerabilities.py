"""API endpoints dla podatnosci bezpieczenstwa."""
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from netdoc.storage.database import get_db
from netdoc.storage.models import Vulnerability, VulnType, VulnSeverity

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


class VulnOut(BaseModel):
    id: int
    device_id: int
    vuln_type: str
    severity: str
    title: str
    description: Optional[str] = None
    port: Optional[int] = None
    evidence: Optional[str] = None
    first_seen: datetime
    model_config = {"from_attributes": True}

    last_seen: datetime
    is_open: bool
    suppressed: bool = False
    consecutive_ok: int = 0


class VulnSummary(BaseModel):
    total_open: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    by_type: dict


@router.get("/", response_model=List[VulnOut])
def list_vulnerabilities(
    is_open: Optional[bool] = Query(None, description="Filter by open/closed"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    device_id: Optional[int] = Query(None, description="Filter by device"),
    vuln_type: Optional[str] = Query(None, description="Filter by type"),
    limit: int = Query(200, le=1000),
    db: Session = Depends(get_db),
):
    """Lista podatnosci z opcjonalnym filtrowaniem."""
    q = db.query(Vulnerability)
    if is_open is not None:
        q = q.filter(Vulnerability.is_open == is_open)
    if severity:
        try:
            q = q.filter(Vulnerability.severity == VulnSeverity(severity))
        except ValueError:
            pass
    if device_id:
        q = q.filter(Vulnerability.device_id == device_id)
    if vuln_type:
        try:
            q = q.filter(Vulnerability.vuln_type == VulnType(vuln_type))
        except ValueError:
            pass
    return q.order_by(Vulnerability.last_seen.desc()).limit(limit).all()


@router.get("/summary", response_model=VulnSummary)
def vulnerability_summary(db: Session = Depends(get_db)):
    """Podsumowanie otwartych podatnosci wg severity."""
    rows = (
        db.query(Vulnerability.severity, Vulnerability.vuln_type, func.count(Vulnerability.id))
        .filter(Vulnerability.is_open.is_(True))
        .group_by(Vulnerability.severity, Vulnerability.vuln_type)
        .all()
    )
    counts: dict = {s.value: 0 for s in VulnSeverity}
    by_type: dict = {}
    total = 0
    for severity, vuln_type, cnt in rows:
        counts[severity.value] = counts.get(severity.value, 0) + cnt
        by_type[vuln_type.value] = by_type.get(vuln_type.value, 0) + cnt
        total += cnt
    return VulnSummary(
        total_open=total,
        critical=counts.get("critical", 0),
        high=counts.get("high", 0),
        medium=counts.get("medium", 0),
        low=counts.get("low", 0),
        info=counts.get("info", 0),
        by_type=by_type,
    )


@router.patch("/{vuln_id}/suppress", response_model=VulnOut)
def suppress_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    """Akceptacja ryzyka — skaner nie bedzie wznawal tej podatnosci."""
    from fastapi import HTTPException
    v = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(404, "Podatnosc nie znaleziona")
    v.suppressed = True
    v.is_open = False
    v.last_seen = datetime.utcnow()
    db.commit()
    db.refresh(v)
    return v


@router.patch("/{vuln_id}/unsuppress", response_model=VulnOut)
def unsuppress_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    """Cofniecie akceptacji ryzyka — podatnosc wraca do aktywnych przy nastepnym skanie."""
    from fastapi import HTTPException
    v = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(404, "Podatnosc nie znaleziona")
    v.suppressed = False
    v.is_open = True
    v.last_seen = datetime.utcnow()
    db.commit()
    db.refresh(v)
    return v


@router.patch("/unsuppress-all")
def unsuppress_all_vulnerabilities(db: Session = Depends(get_db)):
    """Cofniecie akceptacji ryzyka dla wszystkich wyciszonych podatnosci."""
    try:
        count = (
            db.query(Vulnerability)
            .filter(Vulnerability.suppressed.is_(True))
            .update(
                {"suppressed": False, "is_open": True, "last_seen": datetime.utcnow()},
                synchronize_session=False,
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {"unsuppressed": count}


@router.patch("/{vuln_id}/close", response_model=VulnOut)
def close_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    """Reczne zamkniecie podatnosci (np. po naprawie)."""
    from fastapi import HTTPException
    v = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(404, "Podatnosc nie znaleziona")
    v.is_open = False
    v.last_seen = datetime.utcnow()
    db.commit()
    db.refresh(v)
    return v
