"""API endpoints dla podatnosci bezpieczenstwa."""
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
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
    open_vulns = db.query(Vulnerability).filter(Vulnerability.is_open == True).all()
    by_type: dict = {}
    counts = {s.value: 0 for s in VulnSeverity}
    for v in open_vulns:
        counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
        by_type[v.vuln_type.value] = by_type.get(v.vuln_type.value, 0) + 1
    return VulnSummary(
        total_open=len(open_vulns),
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
    suppressed = db.query(Vulnerability).filter(Vulnerability.suppressed == True).all()
    count = len(suppressed)
    for v in suppressed:
        v.suppressed = False
        v.is_open = True
        v.last_seen = datetime.utcnow()
    db.commit()
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
