"""Regression tests for SecurityEvent model, store_security_event(), and related
Flask/FastAPI endpoints.

Coverage:
  - SecurityEvent SQLAlchemy model (create / query)
  - store_security_event() in netdoc.integrations.wazuh
  - GET /api/devices/<id>/security-events  (Flask)
  - GET /api/devices/<id>/wazuh-alerts     (Flask — no file → empty list)
  - GET /api/wazuh/alerts                  (Flask — no file → available=False)
  - GET /api/wazuh/agents                  (Flask — Wazuh disabled → empty)
  - wazuh_alerts._level_to_severity()
  - wazuh_alerts._parse_alerts_json()      (temp file with fixture data)
"""
import json
import os
import tempfile
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from netdoc.storage.models import Device, DeviceType, SecurityEvent


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_device(db, ip="10.0.1.1"):
    d = Device(ip=ip, device_type=DeviceType.unknown, is_active=True)
    db.add(d)
    db.commit()
    db.refresh(d)
    return d


def _make_sec_event(db, device_id, event_type="new_device", severity="info",
                    ip="10.0.1.1", description="test event", details=None):
    ev = SecurityEvent(
        device_id=device_id,
        event_type=event_type,
        severity=severity,
        ip=ip,
        description=description,
        details=details or {},
        ts=datetime.utcnow(),
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev


# ─── SecurityEvent model ──────────────────────────────────────────────────────

def test_security_event_create(db):
    dev = _make_device(db)
    ev = _make_sec_event(db, dev.id)
    assert ev.id is not None
    assert ev.event_type == "new_device"
    assert ev.severity == "info"
    assert ev.device_id == dev.id


def test_security_event_cascade_delete(db):
    dev = _make_device(db)
    _make_sec_event(db, dev.id)
    assert db.query(SecurityEvent).count() == 1
    db.delete(dev)
    db.commit()
    assert db.query(SecurityEvent).count() == 0


def test_security_event_device_id_nullable(db):
    """device_id may be NULL (event before device is committed)."""
    ev = SecurityEvent(
        device_id=None, event_type="new_device", severity="info",
        ip="1.2.3.4", description="orphan", details={}, ts=datetime.utcnow(),
    )
    db.add(ev)
    db.commit()
    assert ev.id is not None


def test_security_event_details_stored(db):
    dev = _make_device(db)
    payload = {"vuln_type": "open_telnet", "port": 23}
    ev = _make_sec_event(db, dev.id, details=payload)
    fetched = db.query(SecurityEvent).filter_by(id=ev.id).first()
    assert fetched.details == payload


# ─── store_security_event() ───────────────────────────────────────────────────

def test_store_security_event_creates_row(db):
    from netdoc.integrations.wazuh import store_security_event
    dev = _make_device(db)
    store_security_event(db, dev.id, "new_device", "10.0.1.1",
                         description="New device discovered: 10.0.1.1")
    db.flush()
    ev = db.query(SecurityEvent).filter_by(device_id=dev.id).first()
    assert ev is not None
    assert ev.event_type == "new_device"
    assert ev.severity == "info"   # mapped from event_type


def test_store_security_event_vuln_severity(db):
    from netdoc.integrations.wazuh import store_security_event
    dev = _make_device(db)
    store_security_event(db, dev.id, "new_vuln", "10.0.1.1",
                         description="Vulnerability: open_telnet",
                         severity="critical")
    db.flush()
    ev = db.query(SecurityEvent).filter_by(device_id=dev.id).first()
    assert ev.severity == "critical"


def test_store_security_event_default_severity_from_map(db):
    from netdoc.integrations.wazuh import store_security_event
    dev = _make_device(db)
    store_security_event(db, dev.id, "ip_conflict", "10.0.1.1",
                         description="IP conflict")
    db.flush()
    ev = db.query(SecurityEvent).filter_by(device_id=dev.id).first()
    assert ev.severity == "warning"   # _SEVERITY_MAP["ip_conflict"]


def test_store_security_event_does_not_raise_on_db_error(db):
    """store_security_event must not propagate exceptions (defensive)."""
    from netdoc.integrations.wazuh import store_security_event
    bad_db = MagicMock()
    bad_db.add.side_effect = RuntimeError("boom")
    # Should not raise
    store_security_event(bad_db, None, "new_device", "1.2.3.4",
                         description="test")


def test_store_security_event_savepoint_does_not_rollback_caller(db):
    """Savepoint failure must NOT roll back the caller's transaction."""
    from netdoc.integrations.wazuh import store_security_event
    # begin_nested returns a savepoint context manager; simulate it raising on __enter__
    bad_db = MagicMock()
    bad_nested = MagicMock()
    bad_nested.__enter__ = MagicMock(side_effect=Exception("savepoint failed"))
    bad_nested.__exit__ = MagicMock(return_value=False)
    bad_db.begin_nested.return_value = bad_nested
    # Must not raise and must NOT call db.rollback()
    store_security_event(bad_db, None, "new_device", "1.2.3.4", description="test")
    bad_db.rollback.assert_not_called()


def test_security_event_no_duplicate_relationship():
    """SecurityEvent must have exactly one 'device' relationship (no SAWarning)."""
    from netdoc.storage.models import SecurityEvent
    mapper = SecurityEvent.__mapper__
    rel_names = [r.key for r in mapper.relationships]
    assert rel_names.count("device") == 1


# ─── Flask endpoint: /api/devices/<id>/security-events ───────────────────────

def _build_flask_app(db_session):
    """Create Flask test app with SessionLocal patched to return db_session."""
    from netdoc.web.app import create_app
    flask_app = create_app()
    flask_app.config["TESTING"] = True

    # Patch SessionLocal so Flask routes use the SQLite test session
    import netdoc.web.app as _web
    original_sl = _web.SessionLocal

    class _FakeSession:
        def __init__(self):
            self._s = db_session

        def __enter__(self):
            return self._s

        def __exit__(self, *a):
            pass

        def query(self, *a, **kw):
            return self._s.query(*a, **kw)

        def close(self):
            pass

    _web.SessionLocal = _FakeSession
    yield flask_app
    _web.SessionLocal = original_sl


@pytest.fixture()
def flask_client(db):
    import netdoc.web.app as _web
    from netdoc.web.app import create_app

    original_sl = _web.SessionLocal

    class _FixedSession:
        def __init__(self):
            pass

        def query(self, *a, **kw):
            return db.query(*a, **kw)

        def add(self, obj):
            return db.add(obj)

        def commit(self):
            return db.commit()

        def close(self):
            pass

    _web.SessionLocal = _FixedSession

    flask_app = create_app()
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c

    _web.SessionLocal = original_sl


def test_security_events_endpoint_empty(flask_client, db):
    dev = _make_device(db)
    r = flask_client.get(f"/api/devices/{dev.id}/security-events")
    assert r.status_code == 200
    data = r.get_json()
    assert data["events"] == []
    assert data["device_id"] == dev.id


def test_security_events_endpoint_returns_events(flask_client, db):
    dev = _make_device(db)
    _make_sec_event(db, dev.id, event_type="new_vuln", severity="warning",
                    description="Vuln: open_telnet")
    r = flask_client.get(f"/api/devices/{dev.id}/security-events")
    assert r.status_code == 200
    events = r.get_json()["events"]
    assert len(events) == 1
    assert events[0]["event_type"] == "new_vuln"
    assert events[0]["severity"] == "warning"
    assert "open_telnet" in events[0]["description"]


def test_security_events_endpoint_device_not_found(flask_client):
    r = flask_client.get("/api/devices/99999/security-events")
    assert r.status_code == 404


def test_security_events_endpoint_limit(flask_client, db):
    dev = _make_device(db)
    for i in range(5):
        _make_sec_event(db, dev.id, description=f"event {i}")
    r = flask_client.get(f"/api/devices/{dev.id}/security-events?limit=3")
    assert r.status_code == 200
    assert len(r.get_json()["events"]) == 3


# ─── Flask endpoint: /api/devices/<id>/wazuh-alerts (no alerts file) ─────────

def test_wazuh_device_alerts_no_file(flask_client, db):
    """Returns empty list with available=False when alerts.json not mounted."""
    dev = _make_device(db)
    with patch("netdoc.integrations.wazuh_alerts.alerts_file_available", return_value=False):
        r = flask_client.get(f"/api/devices/{dev.id}/wazuh-alerts")
    assert r.status_code == 200
    data = r.get_json()
    assert data["alerts"] == []
    assert data["available"] is False


def test_wazuh_device_alerts_device_not_found(flask_client):
    r = flask_client.get("/api/devices/99999/wazuh-alerts")
    assert r.status_code == 404


# ─── Flask endpoint: /api/wazuh/alerts ───────────────────────────────────────

def test_wazuh_global_alerts_no_file(flask_client):
    with patch("netdoc.integrations.wazuh_alerts.alerts_file_available", return_value=False):
        r = flask_client.get("/api/wazuh/alerts")
    assert r.status_code == 200
    data = r.get_json()
    assert data["available"] is False
    assert data["alerts"] == []


def test_wazuh_global_alerts_invalid_params_no_500(flask_client):
    """Bad query params must return 200 with defaults, not HTTP 500."""
    with patch("netdoc.integrations.wazuh_alerts.alerts_file_available", return_value=False):
        r = flask_client.get("/api/wazuh/alerts?hours=abc&limit=xyz")
    assert r.status_code == 200


def test_security_events_endpoint_invalid_limit_no_500(flask_client, db):
    dev = _make_device(db)
    r = flask_client.get(f"/api/devices/{dev.id}/security-events?limit=notanint")
    assert r.status_code == 200


def test_wazuh_global_alerts_with_file(flask_client, tmp_path):
    """Parses alerts from a real temp alerts.json."""
    alert_line = json.dumps({
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "rule": {"id": "550", "level": 7, "description": "Integrity check", "groups": ["ossec"]},
        "agent": {"id": "000", "name": "test-host", "ip": "10.0.1.1"},
        "data": {"srcip": "10.0.1.1"},
        "location": "syscheck",
        "full_log": "test log line",
    })
    alerts_file = tmp_path / "alerts.json"
    alerts_file.write_text(alert_line + "\n")

    with patch("netdoc.integrations.wazuh_alerts.ALERTS_JSON_PATH", str(alerts_file)):
        with patch("netdoc.integrations.wazuh_alerts.alerts_file_available", return_value=True):
            r = flask_client.get("/api/wazuh/alerts?hours=24")

    assert r.status_code == 200
    data = r.get_json()
    assert data["available"] is True
    assert len(data["alerts"]) == 1
    assert data["alerts"][0]["rule_id"] == "550"
    assert data["alerts"][0]["severity"] == "warning"   # level 7


# ─── Flask endpoint: /api/wazuh/agents ───────────────────────────────────────

def test_wazuh_agents_disabled(flask_client, db):
    """Returns available=False when Wazuh is not enabled."""
    with patch("netdoc.integrations.wazuh_alerts.get_wazuh_api_config", return_value=None):
        r = flask_client.get("/api/wazuh/agents")
    assert r.status_code == 200
    data = r.get_json()
    assert data["available"] is False
    assert data["agents"] == []


def test_wazuh_agents_api_error(flask_client, db):
    """Returns empty agents list on API error (graceful degradation)."""
    cfg = {"url": "https://test:55000", "user": "u", "password": "p"}
    with patch("netdoc.integrations.wazuh_alerts.get_wazuh_api_config", return_value=cfg):
        with patch("netdoc.integrations.wazuh_alerts.get_agents", return_value=[]):
            r = flask_client.get("/api/wazuh/agents")
    assert r.status_code == 200
    assert r.get_json()["agents"] == []


def test_wazuh_agents_db_error_returns_json_not_500(flask_client, db):
    """DB error reading Wazuh config must return JSON 200, not HTML 500 (BUG-API-2)."""
    with patch("netdoc.integrations.wazuh_alerts.get_wazuh_api_config",
               side_effect=Exception("DB gone")):
        r = flask_client.get("/api/wazuh/agents")
    assert r.status_code == 200
    data = r.get_json()
    assert data is not None, "response must be JSON, not HTML"
    assert data["available"] is False
    assert data["agents"] == []
    assert "count" in data


def test_wazuh_agents_disabled_has_count_field(flask_client, db):
    """available=False response includes count field for consistent structure (BUG-API-3)."""
    with patch("netdoc.integrations.wazuh_alerts.get_wazuh_api_config", return_value=None):
        r = flask_client.get("/api/wazuh/agents")
    data = r.get_json()
    assert "count" in data
    assert data["count"] == 0


def test_wazuh_global_alerts_no_file_has_count_and_since_hours(flask_client):
    """available=False response has count and since_hours fields (BUG-API-3)."""
    with patch("netdoc.integrations.wazuh_alerts.alerts_file_available", return_value=False):
        r = flask_client.get("/api/wazuh/alerts?hours=48")
    data = r.get_json()
    assert "count" in data
    assert data["count"] == 0
    assert "since_hours" in data
    assert data["since_hours"] == 48


def test_wazuh_device_alerts_no_file_has_consistent_fields(flask_client, db):
    """Device wazuh-alerts available=False response has ip, count, since_hours (BUG-API-3)."""
    dev = _make_device(db)
    with patch("netdoc.integrations.wazuh_alerts.alerts_file_available", return_value=False):
        r = flask_client.get(f"/api/devices/{dev.id}/wazuh-alerts?hours=48")
    data = r.get_json()
    assert data["available"] is False
    assert "count" in data and data["count"] == 0
    assert "since_hours" in data and data["since_hours"] == 48
    assert "ip" in data


# ─── wazuh_alerts._level_to_severity() ───────────────────────────────────────

def test_level_to_severity():
    from netdoc.integrations.wazuh_alerts import _level_to_severity
    assert _level_to_severity(0) == "info"
    assert _level_to_severity(6) == "info"
    assert _level_to_severity(7) == "warning"
    assert _level_to_severity(11) == "warning"
    assert _level_to_severity(12) == "critical"
    assert _level_to_severity(15) == "critical"


# ─── wazuh_alerts._parse_alerts_json() ───────────────────────────────────────

def _write_alerts(path, alerts):
    with open(path, "w") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")


def test_parse_alerts_returns_all(tmp_path):
    from netdoc.integrations.wazuh_alerts import _parse_alerts_json
    now = datetime.utcnow()
    alerts_file = tmp_path / "alerts.json"
    _write_alerts(str(alerts_file), [
        {
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "rule": {"id": "100", "level": 3, "description": "Low alert", "groups": []},
            "agent": {"id": "001", "name": "host-a", "ip": "192.168.1.10"},
            "data": {},
            "location": "syscheck",
            "full_log": "log line 1",
        },
        {
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "rule": {"id": "200", "level": 12, "description": "Critical alert", "groups": []},
            "agent": {"id": "002", "name": "host-b", "ip": "192.168.1.20"},
            "data": {"srcip": "10.0.0.1"},
            "location": "ossec",
            "full_log": "log line 2",
        },
    ])
    with patch("netdoc.integrations.wazuh_alerts.ALERTS_JSON_PATH", str(alerts_file)):
        results = _parse_alerts_json(since_hours=24)
    assert len(results) == 2


def test_parse_alerts_ip_filter(tmp_path):
    from netdoc.integrations.wazuh_alerts import _parse_alerts_json
    now = datetime.utcnow()
    alerts_file = tmp_path / "alerts.json"
    _write_alerts(str(alerts_file), [
        {
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "rule": {"id": "100", "level": 3, "description": "A", "groups": []},
            "agent": {"id": "001", "name": "host-a", "ip": "192.168.1.10"},
            "data": {"srcip": "192.168.1.10"},
            "location": "syscheck", "full_log": "",
        },
        {
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "rule": {"id": "200", "level": 5, "description": "B", "groups": []},
            "agent": {"id": "002", "name": "host-b", "ip": "192.168.1.20"},
            "data": {},
            "location": "ossec", "full_log": "",
        },
    ])
    with patch("netdoc.integrations.wazuh_alerts.ALERTS_JSON_PATH", str(alerts_file)):
        results = _parse_alerts_json(ip_filter="192.168.1.10", since_hours=24)
    assert len(results) == 1
    assert results[0]["agent_ip"] == "192.168.1.10"


def test_parse_alerts_time_filter(tmp_path):
    from netdoc.integrations.wazuh_alerts import _parse_alerts_json
    old_ts  = (datetime.utcnow() - timedelta(hours=50)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    new_ts  = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
    alerts_file = tmp_path / "alerts.json"
    _write_alerts(str(alerts_file), [
        {"timestamp": old_ts,  "rule": {"id": "1", "level": 3, "description": "old", "groups": []},
         "agent": {"id": "0", "name": "h", "ip": "1.1.1.1"}, "data": {}, "location": "", "full_log": ""},
        {"timestamp": new_ts,  "rule": {"id": "2", "level": 5, "description": "new", "groups": []},
         "agent": {"id": "0", "name": "h", "ip": "1.1.1.1"}, "data": {}, "location": "", "full_log": ""},
    ])
    with patch("netdoc.integrations.wazuh_alerts.ALERTS_JSON_PATH", str(alerts_file)):
        results = _parse_alerts_json(since_hours=24)
    assert len(results) == 1
    assert results[0]["rule_id"] == "2"


def test_parse_alerts_missing_file():
    from netdoc.integrations.wazuh_alerts import _parse_alerts_json
    with patch("netdoc.integrations.wazuh_alerts.ALERTS_JSON_PATH", "/nonexistent/path/alerts.json"):
        results = _parse_alerts_json()
    assert results == []


def test_parse_alerts_skips_entries_without_timestamp(tmp_path):
    """Alerts with missing/unparseable timestamp are skipped (not added to results)."""
    from netdoc.integrations.wazuh_alerts import _parse_alerts_json
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
    alerts_file = tmp_path / "alerts.json"
    _write_alerts(str(alerts_file), [
        {"timestamp": "",   "rule": {"id": "1", "level": 3, "description": "no-ts", "groups": []},
         "agent": {"id": "0", "name": "h", "ip": "1.1.1.1"}, "data": {}, "location": "", "full_log": ""},
        {"timestamp": now,  "rule": {"id": "2", "level": 5, "description": "valid", "groups": []},
         "agent": {"id": "0", "name": "h", "ip": "1.1.1.1"}, "data": {}, "location": "", "full_log": ""},
    ])
    with patch("netdoc.integrations.wazuh_alerts.ALERTS_JSON_PATH", str(alerts_file)):
        results = _parse_alerts_json(since_hours=24)
    assert len(results) == 1
    assert results[0]["rule_id"] == "2"


def test_parse_alerts_handles_timezone_aware_timestamps(tmp_path):
    """Timestamps with UTC offset are compared correctly against cutoff (BUG-L1)."""
    from netdoc.integrations.wazuh_alerts import _parse_alerts_json
    # A timestamp 1 hour ago but expressed in +02:00 (would be 1h in future in naive local)
    now_utc = datetime.utcnow()
    recent_utc = now_utc - timedelta(minutes=30)
    # Express as UTC+2: add 2 hours to the clock face but keep same moment
    ts_aware = recent_utc.strftime("%Y-%m-%dT") + \
               (recent_utc + timedelta(hours=2)).strftime("%H:%M:%S") + "+02:00"
    alerts_file = tmp_path / "alerts.json"
    _write_alerts(str(alerts_file), [
        {"timestamp": ts_aware, "rule": {"id": "99", "level": 5, "description": "tz-test", "groups": []},
         "agent": {"id": "0", "name": "h", "ip": "1.1.1.1"}, "data": {}, "location": "", "full_log": ""},
    ])
    with patch("netdoc.integrations.wazuh_alerts.ALERTS_JSON_PATH", str(alerts_file)):
        results = _parse_alerts_json(since_hours=24)
    # Alert is 30 min ago — must appear in 24h window
    assert len(results) == 1
    assert results[0]["rule_id"] == "99"


def test_parse_alerts_time_filter_skips_old_entries(tmp_path):
    """Entries older than cutoff are skipped; newer entries are returned."""
    from netdoc.integrations.wazuh_alerts import _parse_alerts_json
    old_ts = (datetime.utcnow() - timedelta(hours=50)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    new_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
    alerts_file = tmp_path / "alerts.json"
    _write_alerts(str(alerts_file), [
        {"timestamp": old_ts, "rule": {"id": "1", "level": 3, "description": "old", "groups": []},
         "agent": {"id": "0", "name": "h", "ip": "1.1.1.1"}, "data": {}, "location": "", "full_log": ""},
        {"timestamp": new_ts, "rule": {"id": "2", "level": 5, "description": "new", "groups": []},
         "agent": {"id": "0", "name": "h", "ip": "1.1.1.1"}, "data": {}, "location": "", "full_log": ""},
    ])
    with patch("netdoc.integrations.wazuh_alerts.ALERTS_JSON_PATH", str(alerts_file)):
        results = _parse_alerts_json(since_hours=24)
    assert len(results) == 1
    assert results[0]["rule_id"] == "2"


def test_parse_alerts_out_of_order_timestamps(tmp_path):
    """Out-of-order old timestamp mid-file does not drop newer entries after it (BUG-API-5 fix)."""
    from netdoc.integrations.wazuh_alerts import _parse_alerts_json
    old_ts  = (datetime.utcnow() - timedelta(hours=50)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    new_ts1 = (datetime.utcnow() - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    new_ts2 = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
    alerts_file = tmp_path / "alerts.json"
    # File order: new1, old (out-of-order), new2
    # reversed() sees: new2, old, new1 — old must NOT stop iteration
    _write_alerts(str(alerts_file), [
        {"timestamp": new_ts1, "rule": {"id": "1", "level": 3, "description": "new1", "groups": []},
         "agent": {"id": "0", "name": "h", "ip": "1.1.1.1"}, "data": {}, "location": "", "full_log": ""},
        {"timestamp": old_ts, "rule": {"id": "2", "level": 3, "description": "old-ooo", "groups": []},
         "agent": {"id": "0", "name": "h", "ip": "1.1.1.1"}, "data": {}, "location": "", "full_log": ""},
        {"timestamp": new_ts2, "rule": {"id": "3", "level": 5, "description": "new2", "groups": []},
         "agent": {"id": "0", "name": "h", "ip": "1.1.1.1"}, "data": {}, "location": "", "full_log": ""},
    ])
    with patch("netdoc.integrations.wazuh_alerts.ALERTS_JSON_PATH", str(alerts_file)):
        results = _parse_alerts_json(since_hours=24)
    ids = {r["rule_id"] for r in results}
    assert "1" in ids, "new_ts1 entry must not be skipped due to out-of-order old entry"
    assert "3" in ids, "new_ts2 entry must be returned"
    assert "2" not in ids, "old entry must be filtered out"


def test_parse_alerts_limit(tmp_path):
    from netdoc.integrations.wazuh_alerts import _parse_alerts_json
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
    alerts_file = tmp_path / "alerts.json"
    alerts = [
        {"timestamp": now, "rule": {"id": str(i), "level": 3, "description": f"A{i}", "groups": []},
         "agent": {"id": "0", "name": "h", "ip": "1.1.1.1"}, "data": {}, "location": "", "full_log": ""}
        for i in range(10)
    ]
    _write_alerts(str(alerts_file), alerts)
    with patch("netdoc.integrations.wazuh_alerts.ALERTS_JSON_PATH", str(alerts_file)):
        results = _parse_alerts_json(since_hours=24, limit=3)
    assert len(results) == 3


def test_parse_alerts_invalid_json_lines(tmp_path):
    """Malformed lines are silently skipped."""
    from netdoc.integrations.wazuh_alerts import _parse_alerts_json
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
    alerts_file = tmp_path / "alerts.json"
    with open(str(alerts_file), "w") as f:
        f.write("not-json\n")
        f.write("{incomplete\n")
        f.write(json.dumps({
            "timestamp": now,
            "rule": {"id": "99", "level": 5, "description": "valid", "groups": []},
            "agent": {"id": "0", "name": "h", "ip": "1.1.1.1"},
            "data": {}, "location": "", "full_log": "",
        }) + "\n")
    with patch("netdoc.integrations.wazuh_alerts.ALERTS_JSON_PATH", str(alerts_file)):
        results = _parse_alerts_json(since_hours=24)
    assert len(results) == 1
    assert results[0]["rule_id"] == "99"


# ─── alerts_file_available() ─────────────────────────────────────────────────

def test_alerts_file_available_false():
    from netdoc.integrations.wazuh_alerts import alerts_file_available
    with patch("netdoc.integrations.wazuh_alerts.ALERTS_JSON_PATH", "/no/such/file"):
        assert alerts_file_available() is False


def test_alerts_file_available_true(tmp_path):
    from netdoc.integrations.wazuh_alerts import alerts_file_available
    f = tmp_path / "alerts.json"
    f.write_text("")
    with patch("netdoc.integrations.wazuh_alerts.ALERTS_JSON_PATH", str(f)):
        assert alerts_file_available() is True
