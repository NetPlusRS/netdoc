"""Syslog endpoints — odpytuje ClickHouse (netdoc_logs.syslog)."""
import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/syslog", tags=["syslog"])

_SEVERITY_NAMES = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}


def _enrich(row: dict[str, Any]) -> dict[str, Any]:
    """Dodaje severity_name i serializuje datetime."""
    row = dict(row)
    sev = row.get("severity")
    row["severity_name"] = _SEVERITY_NAMES.get(sev, "UNKNOWN")
    # clickhouse-connect zwraca datetime jako Python datetime — serialize to ISO string
    ts = row.get("timestamp")
    if ts is not None and hasattr(ts, "isoformat"):
        row["timestamp"] = ts.isoformat()
    return row


@router.get("")
def get_syslog(
    device_id: Optional[int] = Query(default=None, description="Filtruj po device_id"),
    src_ip:    Optional[str] = Query(default=None, description="Filtruj po IP źródłowym"),
    severity:  Optional[int] = Query(default=None, ge=0, le=7, description="Max poziom (0=EMERG,7=DEBUG)"),
    program:   Optional[str] = Query(default=None, description="Filtruj po nazwie programu"),
    hours:     int           = Query(default=24,   ge=1, le=720, description="Zakres czasu wstecz (godziny)"),
    limit:     int           = Query(default=200,  ge=1, le=1000, description="Max wierszy"),
):
    """Zwraca logi syslog z ClickHouse z opcjonalnymi filtrami."""
    try:
        from netdoc.storage.clickhouse import query_syslog
        rows = query_syslog(
            device_id=device_id,
            src_ip=src_ip,
            severity_max=severity,
            program=program,
            since_hours=hours,
            limit=limit,
        )
    except Exception as exc:
        logger.warning("ClickHouse query failed: %s", exc)
        raise HTTPException(status_code=503, detail=f"ClickHouse niedostępny: {exc}") from exc

    return {"logs": [_enrich(r) for r in rows], "count": len(rows)}


@router.get("/devices/{device_id}")
def get_device_syslog(
    device_id: int,
    severity:  Optional[int] = Query(default=None, ge=0, le=7),
    program:   Optional[str] = Query(default=None),
    hours:     int           = Query(default=24, ge=1, le=720),
    limit:     int           = Query(default=200, ge=1, le=1000),
):
    """Logi syslog dla konkretnego urządzenia (po device_id z PostgreSQL)."""
    try:
        from netdoc.storage.clickhouse import query_syslog
        rows = query_syslog(
            device_id=device_id,
            severity_max=severity,
            program=program,
            since_hours=hours,
            limit=limit,
        )
    except Exception as exc:
        logger.warning("ClickHouse query device %s failed: %s", device_id, exc)
        raise HTTPException(status_code=503, detail=f"ClickHouse niedostępny: {exc}") from exc

    return {"device_id": device_id, "logs": [_enrich(r) for r in rows], "count": len(rows)}
