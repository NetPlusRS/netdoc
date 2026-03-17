"""ClickHouse client — singleton dla zapytań do netdoc_logs.

Używa clickhouse-connect (HTTP/8123) — nie wymaga dodatkowej konfiguracji sieci,
łączy się przez ten sam port co Grafana i Vector.

Lazy init: połączenie nawiązywane przy pierwszym zapytaniu.
"""
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client
    try:
        import clickhouse_connect
        host     = os.getenv("CLICKHOUSE_HOST", "netdoc-clickhouse")
        port     = int(os.getenv("CLICKHOUSE_HTTP_PORT", "8123"))
        user     = os.getenv("CLICKHOUSE_USER", "netdoc")
        password = os.getenv("CLICKHOUSE_PASSWORD", "netdoc")
        _client = clickhouse_connect.get_client(
            host=host,
            port=port,
            username=user,
            password=password,
            database="netdoc_logs",
            connect_timeout=5,
            send_receive_timeout=30,
        )
        logger.info("ClickHouse: połączono z %s:%s", host, port)
    except Exception as exc:
        logger.warning("ClickHouse niedostępny: %s", exc)
        raise
    return _client


def query_syslog(
    device_id: int | None = None,
    src_ip: str | None = None,
    severity_max: int | None = None,
    program: str | None = None,
    since_hours: int = 24,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Zwraca logi syslog z ClickHouse.

    Parametry:
        device_id    — filtruj po device_id (0 = nieznane)
        src_ip       — filtruj po IP źródłowym (alternatywa dla device_id)
        severity_max — maksymalny poziom (0=EMERG, 7=DEBUG); np. 3 = ERROR i poważniejsze
        program      — filtruj po nazwie procesu (LIKE %program%)
        since_hours  — zakres czasu wstecz (domyślnie 24h)
        limit        — max wierszy w odpowiedzi (max 1000)
    """
    limit = min(limit, 1000)
    since_hours = max(1, min(since_hours, 24 * 30))

    where = ["timestamp >= now() - INTERVAL {since_hours:UInt32} HOUR"]
    params: dict[str, Any] = {"since_hours": since_hours, "limit": limit}

    if device_id is not None:
        where.append("device_id = {device_id:UInt32}")
        params["device_id"] = device_id
    if src_ip:
        where.append("src_ip = {src_ip:String}")
        params["src_ip"] = src_ip
    if severity_max is not None:
        where.append("severity <= {severity_max:UInt8}")
        params["severity_max"] = severity_max
    if program:
        where.append("program ILIKE {program:String}")
        params["program"] = f"%{program}%"

    sql = (
        "SELECT timestamp, src_ip, device_id, hostname, facility, severity, program, message"
        " FROM netdoc_logs.syslog"
        " WHERE " + " AND ".join(where) +
        " ORDER BY timestamp DESC"
        " LIMIT {limit:UInt32}"
    )

    client = _get_client()
    result = client.query(sql, parameters=params)

    cols = result.column_names
    return [dict(zip(cols, row)) for row in result.result_rows]


def count_syslog_by_severity(device_id: int, since_hours: int = 24) -> dict[int, int]:
    """Zlicza logi per severity dla jednego urządzenia (do badge'ów w UI)."""
    sql = (
        "SELECT severity, count() AS cnt"
        " FROM netdoc_logs.syslog"
        " WHERE device_id = {device_id:UInt32}"
        "   AND timestamp >= now() - INTERVAL {since_hours:UInt32} HOUR"
        " GROUP BY severity"
        " ORDER BY severity"
    )
    try:
        result = _get_client().query(sql, parameters={"device_id": device_id, "since_hours": since_hours})
        return {row[0]: row[1] for row in result.result_rows}
    except Exception as exc:
        logger.warning("count_syslog_by_severity failed: %s", exc)
        return {}
