"""Testy syslog API + klienta ClickHouse.

ClickHouse nie jest dostępny w środowisku testowym (brak kontenera),
dlatego _get_client jest mockowany. Testy weryfikują:
  - logikę budowania zapytań SQL (klauzule WHERE, parametry)
  - poprawność odpowiedzi HTTP endpointów (via conftest client)
  - serializację datetime i severity_name w _enrich()
  - obsługę błędów (503 gdy ClickHouse niedostępny)
"""
import datetime
from unittest.mock import MagicMock, patch

import pytest

from netdoc.api.routes.syslog import _enrich


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_mock_client(rows=None, column_names=None):
    """Zwraca (mock_client, mock_result) gotowe do użycia w patch."""
    cols = column_names or [
        "timestamp", "src_ip", "device_id", "hostname",
        "facility", "severity", "program", "message",
    ]
    mock_result = MagicMock()
    mock_result.column_names = cols
    mock_result.result_rows = rows or []
    mock_client = MagicMock()
    mock_client.query.return_value = mock_result
    return mock_client


# ─── _enrich() ────────────────────────────────────────────────────────────────

def test_enrich_adds_severity_name_error():
    row = {"timestamp": datetime.datetime(2026, 3, 17, 12, 0, 0), "severity": 3}
    assert _enrich(row)["severity_name"] == "ERROR"


def test_enrich_adds_severity_name_warning():
    row = {"timestamp": datetime.datetime(2026, 3, 17, 12, 0, 0), "severity": 4}
    assert _enrich(row)["severity_name"] == "WARNING"


def test_enrich_adds_severity_name_info():
    row = {"timestamp": datetime.datetime(2026, 3, 17, 12, 0, 0), "severity": 6}
    assert _enrich(row)["severity_name"] == "INFO"


def test_enrich_serializes_datetime_to_iso():
    row = {"timestamp": datetime.datetime(2026, 3, 17, 12, 34, 56), "severity": 6}
    assert _enrich(row)["timestamp"] == "2026-03-17T12:34:56"


def test_enrich_unknown_severity():
    row = {"timestamp": datetime.datetime(2026, 3, 17, 12, 0, 0), "severity": 99}
    assert _enrich(row)["severity_name"] == "UNKNOWN"


# ─── /api/syslog — via conftest client fixture ────────────────────────────────

@patch("netdoc.storage.clickhouse._get_client")
def test_get_syslog_returns_logs(mock_get_client, client):
    mock_get_client.return_value = _make_mock_client(rows=[
        (datetime.datetime(2026, 3, 17, 12, 0, 0), "192.168.1.1", 5, "sw-01", 3, 3, "SYS", "Link down"),
    ])
    resp = client.get("/api/syslog")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 1
    assert data["logs"][0]["severity_name"] == "ERROR"
    assert data["logs"][0]["src_ip"] == "192.168.1.1"


@patch("netdoc.storage.clickhouse._get_client")
def test_get_syslog_filters_by_device_id(mock_get_client, client):
    mc = _make_mock_client()
    mock_get_client.return_value = mc

    resp = client.get("/api/syslog?device_id=42&hours=6&limit=50")
    assert resp.status_code == 200

    params = mc.query.call_args[1]["parameters"]
    assert params.get("device_id") == 42
    assert params.get("since_hours") == 6
    assert params.get("limit") == 50


@patch("netdoc.storage.clickhouse._get_client")
def test_get_syslog_filters_by_severity(mock_get_client, client):
    mc = _make_mock_client()
    mock_get_client.return_value = mc

    resp = client.get("/api/syslog?severity=3")
    assert resp.status_code == 200
    params = mc.query.call_args[1]["parameters"]
    assert params.get("severity_max") == 3


def test_get_syslog_limit_validation(client):
    # limit powyżej 1000 — walidacja FastAPI (le=1000)
    resp = client.get("/api/syslog?limit=9999")
    assert resp.status_code == 422


@patch("netdoc.storage.clickhouse._get_client")
def test_get_syslog_returns_503_when_clickhouse_down(mock_get_client, client):
    mock_get_client.side_effect = ConnectionError("ClickHouse niedostępny")
    resp = client.get("/api/syslog")
    assert resp.status_code == 503


# ─── /api/syslog/devices/{id} ─────────────────────────────────────────────────

@patch("netdoc.storage.clickhouse._get_client")
def test_get_device_syslog_passes_device_id(mock_get_client, client):
    mc = _make_mock_client(rows=[
        (datetime.datetime(2026, 3, 17, 10, 0, 0), "10.0.0.1", 7, "router-01", 3, 4, "BGP", "Neighbor down"),
    ])
    mock_get_client.return_value = mc

    resp = client.get("/api/syslog/devices/7")
    assert resp.status_code == 200
    data = resp.json()
    assert data["device_id"] == 7
    assert data["count"] == 1
    assert data["logs"][0]["severity_name"] == "WARNING"
    params = mc.query.call_args[1]["parameters"]
    assert params.get("device_id") == 7


# ─── query_syslog — SQL building ──────────────────────────────────────────────

@patch("netdoc.storage.clickhouse._get_client")
def test_query_syslog_no_filters_uses_only_time_where(mock_get_client):
    mc = _make_mock_client()
    mock_get_client.return_value = mc

    from netdoc.storage.clickhouse import query_syslog
    query_syslog(since_hours=12, limit=100)

    sql    = mc.query.call_args[0][0]
    params = mc.query.call_args[1]["parameters"]
    # device_id istnieje w SELECT; sprawdzamy że NIE ma go w WHERE
    where_part = sql[sql.index("WHERE"):]
    assert "device_id" not in where_part
    assert "src_ip"    not in where_part
    assert "severity"  not in where_part
    assert params["since_hours"] == 12
    assert params["limit"] == 100


@patch("netdoc.storage.clickhouse._get_client")
def test_query_syslog_program_filter_uses_ilike(mock_get_client):
    mc = _make_mock_client()
    mock_get_client.return_value = mc

    from netdoc.storage.clickhouse import query_syslog
    query_syslog(program="bgp", since_hours=24)

    sql    = mc.query.call_args[0][0]
    params = mc.query.call_args[1]["parameters"]
    assert "ILIKE" in sql
    assert params["program"] == "%bgp%"


@patch("netdoc.storage.clickhouse._get_client")
def test_query_syslog_limit_capped_at_1000(mock_get_client):
    mc = _make_mock_client()
    mock_get_client.return_value = mc

    from netdoc.storage.clickhouse import query_syslog
    query_syslog(limit=99999)

    params = mc.query.call_args[1]["parameters"]
    assert params["limit"] == 1000
