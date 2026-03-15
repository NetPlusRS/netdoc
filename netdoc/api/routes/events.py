"""Endpoint dla historii zdarzen."""
from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from netdoc.storage.database import get_db
from netdoc.storage.models import Event, EventType

router = APIRouter(prefix="/api/events", tags=["events"])


class EventOut(BaseModel):
    id: int
    device_id: Optional[int]
    event_time: datetime
    event_type: EventType
    details: Optional[dict]

    model_config = {"from_attributes": True}


@router.get("/", response_model=List[EventOut])
def list_events(
    device_id: Optional[int] = Query(default=None),
    event_type: Optional[EventType] = Query(default=None),
    limit: int = Query(default=100, le=1000),
    db: Session = Depends(get_db),
):
    """Zwraca liste zdarzen (posortowanych od najnowszych)."""
    q = db.query(Event)
    if device_id:
        q = q.filter(Event.device_id == device_id)
    if event_type:
        q = q.filter(Event.event_type == event_type)
    return q.order_by(Event.event_time.desc()).limit(limit).all()
