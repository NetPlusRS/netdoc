"""Endpoints dla topologii sieci."""
from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from netdoc.storage.database import get_db
from netdoc.storage.models import TopologyLink, Device, TopologyProtocol

router = APIRouter(prefix="/api/topology", tags=["topology"])


class NodeOut(BaseModel):
    id: int
    ip: str
    hostname: Optional[str]
    vendor: Optional[str]
    device_type: str
    is_active: bool

    model_config = {"from_attributes": True}


class LinkOut(BaseModel):
    id: int
    src_device_id: int
    src_device_ip: Optional[str]
    src_device_hostname: Optional[str]
    dst_device_id: int
    dst_device_ip: Optional[str]
    dst_device_hostname: Optional[str]
    protocol: TopologyProtocol
    confidence: str
    last_seen: datetime

    model_config = {"from_attributes": False}


class TopologyGraphOut(BaseModel):
    nodes: List[NodeOut]
    links: List[LinkOut]


def _link_out(link: TopologyLink) -> LinkOut:
    return LinkOut(
        id=link.id,
        src_device_id=link.src_device_id,
        src_device_ip=link.src_device.ip if link.src_device else None,
        src_device_hostname=link.src_device.hostname if link.src_device else None,
        dst_device_id=link.dst_device_id,
        dst_device_ip=link.dst_device.ip if link.dst_device else None,
        dst_device_hostname=link.dst_device.hostname if link.dst_device else None,
        protocol=link.protocol,
        confidence=link.confidence.value if hasattr(link.confidence, "value") else str(link.confidence),
        last_seen=link.last_seen,
    )


@router.get("/", response_model=TopologyGraphOut)
def get_topology(
    active_only: bool = True,
    db: Session = Depends(get_db),
):
    """Zwraca pelny graf topologii sieci. Format kompatybilny z D3.js / vis.js."""
    q = db.query(Device)
    if active_only:
        q = q.filter(Device.is_active == True)
    nodes = q.all()

    device_ids = {d.id for d in nodes}
    links = (
        db.query(TopologyLink)
        .filter(
            TopologyLink.src_device_id.in_(device_ids),
            TopologyLink.dst_device_id.in_(device_ids),
        )
        .all()
    )

    return TopologyGraphOut(nodes=nodes, links=[_link_out(l) for l in links])


@router.get("/links", response_model=List[LinkOut])
def list_links(db: Session = Depends(get_db)):
    """Zwraca wszystkie polaczenia topologiczne."""
    return [_link_out(l) for l in db.query(TopologyLink).all()]
