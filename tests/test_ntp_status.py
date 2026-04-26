"""Regression tests for NTP drift detection endpoints.

Covers:
- GET /api/ntp-status            (batch for all devices)
- GET /api/devices/<id>/ntp-status  (single device)
- get_ntp_drift_batch()          (ClickHouse query function)
- _check_ntp_drift_alerts()      (alert generation in scanner)
"""
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_app():
    from netdoc.web.app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app


def _mock_db_with_threshold(threshold="30"):
    db = MagicMock()
    db.__enter__ = lambda s: s
    db.__exit__ = MagicMock(return_value=False)
    row = MagicMock()
    row.value = threshold
    db.query.return_value.filter_by.return_value.first.return_value = row
    return db


# ---------------------------------------------------------------------------
# get_ntp_drift_batch — unit tests
# ---------------------------------------------------------------------------

class TestGetNtpDriftBatch:
    def test_returns_dict_keyed_by_device_id(self):
        from netdoc.storage.clickhouse import get_ntp_drift_batch
        ch = MagicMock()
        ch.query.return_value.result_rows = [(1, 5.0, 10), (2, 120.0, 50)]
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            result = get_ntp_drift_batch()
        assert 1 in result
        assert 2 in result
        assert result[1]["offset_seconds"] == 5.0
        assert result[2]["samples"] == 50

    def test_empty_result_on_clickhouse_error(self):
        from netdoc.storage.clickhouse import get_ntp_drift_batch
        ch = MagicMock()
        ch.query.side_effect = RuntimeError("connection refused")
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            result = get_ntp_drift_batch()
        assert result == {}

    def test_passes_since_hours_to_query(self):
        from netdoc.storage.clickhouse import get_ntp_drift_batch
        ch = MagicMock()
        ch.query.return_value.result_rows = []
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            get_ntp_drift_batch(since_hours=6)
        call_kwargs = ch.query.call_args[1]
        assert call_kwargs["parameters"]["since_hours"] == 6


# ---------------------------------------------------------------------------
# GET /api/ntp-status — batch endpoint
# ---------------------------------------------------------------------------

class TestNtpStatusEndpoint:
    def test_returns_200_with_device_data(self):
        app = _make_app()
        ch = MagicMock()
        ch.query.return_value.result_rows = [(42, 10.0, 5)]
        db = _mock_db_with_threshold("30")
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            with patch("netdoc.web.app.SessionLocal", return_value=db):
                with app.test_client() as c:
                    resp = c.get("/api/ntp-status")
        assert resp.status_code == 200
        data = resp.get_json()
        # JSON keys are always strings
        assert "42" in data
        assert data["42"]["offset_seconds"] == 10.0
        assert data["42"]["status"] == "ok"

    def test_status_warn_when_above_threshold(self):
        app = _make_app()
        ch = MagicMock()
        ch.query.return_value.result_rows = [(7, 90.0, 20)]
        db = _mock_db_with_threshold("30")
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            with patch("netdoc.web.app.SessionLocal", return_value=db):
                with app.test_client() as c:
                    resp = c.get("/api/ntp-status")
        data = resp.get_json()
        assert data["7"]["status"] == "warn"

    def test_threshold_from_db_is_used(self):
        app = _make_app()
        ch = MagicMock()
        ch.query.return_value.result_rows = [(1, 45.0, 10)]
        db = _mock_db_with_threshold("60")
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            with patch("netdoc.web.app.SessionLocal", return_value=db):
                with app.test_client() as c:
                    resp = c.get("/api/ntp-status")
        data = resp.get_json()
        # 45s < 60s threshold → ok
        assert data["1"]["status"] == "ok"
        assert data["1"]["threshold"] == 60

    def test_clickhouse_error_returns_empty_dict(self):
        """When ClickHouse is unavailable get_ntp_drift_batch returns {} — endpoint still 200."""
        app = _make_app()
        ch = MagicMock()
        ch.query.side_effect = RuntimeError("timeout")
        db = _mock_db_with_threshold("30")
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            with patch("netdoc.web.app.SessionLocal", return_value=db):
                with app.test_client() as c:
                    resp = c.get("/api/ntp-status")
        assert resp.status_code == 200
        assert resp.get_json() == {}

    def test_empty_clickhouse_returns_empty_dict(self):
        app = _make_app()
        ch = MagicMock()
        ch.query.return_value.result_rows = []
        db = _mock_db_with_threshold("30")
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            with patch("netdoc.web.app.SessionLocal", return_value=db):
                with app.test_client() as c:
                    resp = c.get("/api/ntp-status")
        assert resp.status_code == 200
        assert resp.get_json() == {}


# ---------------------------------------------------------------------------
# GET /api/devices/<id>/ntp-status — single device endpoint
# ---------------------------------------------------------------------------

class TestDeviceNtpStatusEndpoint:
    def test_unknown_when_no_syslog(self):
        app = _make_app()
        ch = MagicMock()
        ch.query.return_value.result_rows = []  # no data for any device
        db = _mock_db_with_threshold("30")
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            with patch("netdoc.web.app.SessionLocal", return_value=db):
                with app.test_client() as c:
                    resp = c.get("/api/devices/99/ntp-status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "unknown"
        assert data["offset_seconds"] is None

    def test_ok_status_below_threshold(self):
        app = _make_app()
        ch = MagicMock()
        ch.query.return_value.result_rows = [(5, 8.0, 3)]
        db = _mock_db_with_threshold("30")
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            with patch("netdoc.web.app.SessionLocal", return_value=db):
                with app.test_client() as c:
                    resp = c.get("/api/devices/5/ntp-status")
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["offset_seconds"] == 8.0

    def test_warn_status_above_threshold(self):
        app = _make_app()
        ch = MagicMock()
        ch.query.return_value.result_rows = [(3, 120.0, 15)]
        db = _mock_db_with_threshold("30")
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            with patch("netdoc.web.app.SessionLocal", return_value=db):
                with app.test_client() as c:
                    resp = c.get("/api/devices/3/ntp-status")
        data = resp.get_json()
        assert data["status"] == "warn"


# ---------------------------------------------------------------------------
# _check_ntp_drift_alerts — alert generation
# ---------------------------------------------------------------------------

class TestCheckNtpDriftAlerts:
    def _call(self, drift_map, enabled="1", threshold="30", recent_alert=None):
        """Call _check_ntp_drift_alerts with mocked dependencies."""
        from run_scanner import _check_ntp_drift_alerts

        db = MagicMock()

        def _query_side(model_cls):
            q = MagicMock()
            from netdoc.storage.models import SystemStatus, SecurityEvent, Device
            if model_cls is SystemStatus:
                def _filter_by(**kwargs):
                    fq = MagicMock()
                    key = kwargs.get("key", "")
                    if key == "ntp_alert_enabled":
                        r = MagicMock(); r.value = enabled
                    elif key == "ntp_alert_threshold":
                        r = MagicMock(); r.value = threshold
                    else:
                        r = None
                    fq.first.return_value = r
                    return fq
                q.filter_by.side_effect = _filter_by
            elif model_cls is SecurityEvent:
                fq = MagicMock()
                fq.filter.return_value.first.return_value = recent_alert
                q.filter.return_value = fq.filter.return_value
            elif model_cls is Device:
                dev = MagicMock(); dev.ip = "10.0.0.1"
                q.filter_by.return_value.first.return_value = dev
            return q

        db.query.side_effect = _query_side

        ch = MagicMock()
        ch.query.return_value.result_rows = [
            (device_id, offset, samples)
            for device_id, (offset, samples) in drift_map.items()
        ]

        stored = []

        def _store(db_, **kwargs):
            stored.append(kwargs)

        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            with patch("netdoc.integrations.wazuh.store_security_event", side_effect=_store):
                _check_ntp_drift_alerts(db)

        return stored

    def test_no_alert_when_disabled(self):
        stored = self._call({1: (120.0, 10)}, enabled="0")
        assert stored == []

    def test_no_alert_below_threshold(self):
        stored = self._call({1: (10.0, 5)}, threshold="30")
        assert stored == []

    def test_alert_created_above_threshold(self):
        stored = self._call({1: (90.0, 20)}, threshold="30")
        assert len(stored) == 1
        assert stored[0]["event_type"] == "ntp_drift"
        assert stored[0]["severity"] == "warning"

    def test_critical_severity_for_large_drift(self):
        # >30*10 = >300s drift → critical
        stored = self._call({1: (400.0, 10)}, threshold="30")
        assert len(stored) == 1
        assert stored[0]["severity"] == "critical"

    def test_deduplication_skips_if_recent_alert(self):
        from netdoc.storage.models import SecurityEvent
        recent = MagicMock(spec=SecurityEvent)
        stored = self._call({1: (120.0, 5)}, recent_alert=recent)
        assert stored == []

    def test_alert_contains_offset_in_description(self):
        stored = self._call({1: (75.0, 8)}, threshold="30")
        assert "75s" in stored[0]["description"] or "75" in stored[0]["description"]
