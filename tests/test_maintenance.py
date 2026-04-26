"""
Regression tests for maintenance (clear history) endpoints.

Covers:
- POST /maintenance/clear-broadcast  (ClickHouse TRUNCATE device_metrics + device_ping)
- POST /maintenance/clear-syslog     (ClickHouse TRUNCATE syslog)
- POST /maintenance/clear-devices    (PostgreSQL TRUNCATE devices CASCADE)
- POST /maintenance/clear-networks   (PostgreSQL TRUNCATE discovered_networks CASCADE)
- POST /devices/<id>/delete          (individual device delete via API proxy)
- POST /networks/<id>/delete         (per-network delete with optional device cascade)
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


def _mock_db_session(count_value=5):
    """Return a mock SQLAlchemy session whose execute().scalar() returns count_value."""
    db = MagicMock()
    db.__enter__ = lambda s: s
    db.__exit__ = MagicMock(return_value=False)
    execute_result = MagicMock()
    execute_result.scalar.return_value = count_value
    db.execute.return_value = execute_result
    return db


def _mock_ch_client():
    """Return a mock ClickHouse client."""
    ch = MagicMock()
    return ch


# ---------------------------------------------------------------------------
# clear-broadcast
# ---------------------------------------------------------------------------

class TestClearBroadcast:
    def test_returns_ok_true(self):
        app = _make_app()
        ch = _mock_ch_client()
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            with app.test_client() as c:
                resp = c.post("/maintenance/clear-broadcast")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert "cleared" in data["message"].lower() or "broadcast" in data["message"].lower()

    def test_truncates_device_metrics_and_ping(self):
        app = _make_app()
        ch = _mock_ch_client()
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            with app.test_client() as c:
                c.post("/maintenance/clear-broadcast")
        calls = [str(call) for call in ch.command.call_args_list]
        assert any("device_metrics" in c for c in calls)
        assert any("device_ping" in c for c in calls)

    def test_clickhouse_error_returns_500(self):
        app = _make_app()
        ch = _mock_ch_client()
        ch.command.side_effect = RuntimeError("connection refused")
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            with app.test_client() as c:
                resp = c.post("/maintenance/clear-broadcast")
        assert resp.status_code == 500
        data = resp.get_json()
        assert data["ok"] is False
        assert "connection refused" in data["message"]


# ---------------------------------------------------------------------------
# clear-syslog
# ---------------------------------------------------------------------------

class TestClearSyslog:
    def test_returns_ok_true(self):
        app = _make_app()
        ch = _mock_ch_client()
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            with app.test_client() as c:
                resp = c.post("/maintenance/clear-syslog")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True

    def test_truncates_syslog_table(self):
        app = _make_app()
        ch = _mock_ch_client()
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            with app.test_client() as c:
                c.post("/maintenance/clear-syslog")
        calls = [str(call) for call in ch.command.call_args_list]
        assert any("syslog" in c for c in calls)

    def test_clickhouse_error_returns_500(self):
        app = _make_app()
        ch = _mock_ch_client()
        ch.command.side_effect = RuntimeError("timeout")
        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            with app.test_client() as c:
                resp = c.post("/maintenance/clear-syslog")
        assert resp.status_code == 500
        data = resp.get_json()
        assert data["ok"] is False


# ---------------------------------------------------------------------------
# clear-devices
# ---------------------------------------------------------------------------

class TestClearDevices:
    def test_returns_ok_true_with_count(self):
        app = _make_app()
        db = _mock_db_session(count_value=42)
        with patch("netdoc.web.app.SessionLocal", return_value=db):
            with app.test_client() as c:
                resp = c.post("/maintenance/clear-devices")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert "42" in data["message"]

    def test_executes_truncate_cascade(self):
        app = _make_app()
        db = _mock_db_session(count_value=10)
        with patch("netdoc.web.app.SessionLocal", return_value=db):
            with app.test_client() as c:
                c.post("/maintenance/clear-devices")
        # call.args[0] is the sqlalchemy text() object; str() returns the SQL string
        sql_calls = [str(call.args[0]) for call in db.execute.call_args_list]
        assert any("TRUNCATE" in s.upper() and "devices" in s.lower() for s in sql_calls)
        assert any("CASCADE" in s.upper() for s in sql_calls)

    def test_commits_transaction(self):
        app = _make_app()
        db = _mock_db_session(count_value=3)
        with patch("netdoc.web.app.SessionLocal", return_value=db):
            with app.test_client() as c:
                c.post("/maintenance/clear-devices")
        db.commit.assert_called_once()

    def test_db_error_returns_500_and_rollback(self):
        app = _make_app()
        db = MagicMock()
        db.__enter__ = lambda s: s
        db.__exit__ = MagicMock(return_value=False)
        db.execute.side_effect = RuntimeError("db error")
        with patch("netdoc.web.app.SessionLocal", return_value=db):
            with app.test_client() as c:
                resp = c.post("/maintenance/clear-devices")
        assert resp.status_code == 500
        data = resp.get_json()
        assert data["ok"] is False
        db.rollback.assert_called_once()

    def test_zero_devices_still_returns_ok(self):
        app = _make_app()
        db = _mock_db_session(count_value=0)
        with patch("netdoc.web.app.SessionLocal", return_value=db):
            with app.test_client() as c:
                resp = c.post("/maintenance/clear-devices")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert "0" in data["message"]


# ---------------------------------------------------------------------------
# clear-networks
# ---------------------------------------------------------------------------

class TestClearNetworks:
    def test_returns_ok_true_with_count(self):
        app = _make_app()
        db = _mock_db_session(count_value=9)
        with patch("netdoc.web.app.SessionLocal", return_value=db):
            with app.test_client() as c:
                resp = c.post("/maintenance/clear-networks")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert "9" in data["message"]

    def test_executes_truncate_discovered_networks(self):
        app = _make_app()
        db = _mock_db_session(count_value=5)
        with patch("netdoc.web.app.SessionLocal", return_value=db):
            with app.test_client() as c:
                c.post("/maintenance/clear-networks")
        sql_calls = [str(call.args[0]) for call in db.execute.call_args_list]
        assert any("discovered_networks" in s for s in sql_calls)

    def test_commits_transaction(self):
        app = _make_app()
        db = _mock_db_session(count_value=3)
        with patch("netdoc.web.app.SessionLocal", return_value=db):
            with app.test_client() as c:
                c.post("/maintenance/clear-networks")
        db.commit.assert_called_once()

    def test_db_error_returns_500_and_rollback(self):
        app = _make_app()
        db = MagicMock()
        db.__enter__ = lambda s: s
        db.__exit__ = MagicMock(return_value=False)
        db.execute.side_effect = RuntimeError("db error")
        with patch("netdoc.web.app.SessionLocal", return_value=db):
            with app.test_client() as c:
                resp = c.post("/maintenance/clear-networks")
        assert resp.status_code == 500
        data = resp.get_json()
        assert data["ok"] is False
        db.rollback.assert_called_once()


# ---------------------------------------------------------------------------
# Individual device delete  POST /devices/<id>/delete
# ---------------------------------------------------------------------------

class TestDeviceDelete:
    def _make_requests_mock(self, status=204):
        mr = MagicMock()
        resp = MagicMock()
        resp.status_code = status
        resp.content = b""
        resp.raise_for_status = MagicMock()
        mr.delete.return_value = resp
        return mr

    def test_redirects_after_success(self):
        app = _make_app()
        mr = self._make_requests_mock(204)
        ms = MagicMock()
        ms.__enter__ = lambda s: s
        ms.__exit__ = MagicMock(return_value=False)
        ms.query.return_value.filter_by.return_value.first.return_value = MagicMock(key="scanner_job", value="idle", category="config")

        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests", mr):
                with app.test_client() as c:
                    resp = c.post("/devices/1/delete")
        # Flask redirects to /devices after delete
        assert resp.status_code == 302
        assert "/devices" in resp.headers.get("Location", "")

    def test_calls_api_delete_with_force(self):
        app = _make_app()
        mr = self._make_requests_mock(204)
        ms = MagicMock()
        ms.__enter__ = lambda s: s
        ms.__exit__ = MagicMock(return_value=False)
        ms.query.return_value.filter_by.return_value.first.return_value = MagicMock(key="scanner_job", value="idle", category="config")

        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests", mr):
                with app.test_client() as c:
                    c.post("/devices/42/delete")
        # Verify a DELETE request was made with device id 42 and force=true
        mr.delete.assert_called_once()
        call_url = mr.delete.call_args[0][0]
        assert "42" in call_url
        assert "force=true" in call_url

    def test_api_error_still_redirects(self):
        """Even when API returns error, Flask redirects (with flash message)."""
        app = _make_app()
        mr = self._make_requests_mock(500)
        resp_mock = mr.delete.return_value
        resp_mock.status_code = 500
        resp_mock.content = b'{"detail":"not found"}'
        resp_mock.raise_for_status.side_effect = Exception("500")
        resp_mock.json.return_value = {"detail": "not found"}

        ms = MagicMock()
        ms.__enter__ = lambda s: s
        ms.__exit__ = MagicMock(return_value=False)
        ms.query.return_value.filter_by.return_value.first.return_value = MagicMock(key="scanner_job", value="idle", category="config")

        with patch("netdoc.web.app.SessionLocal", return_value=ms):
            with patch("netdoc.web.app.requests", mr):
                with app.test_client() as c:
                    resp = c.post("/devices/99/delete")
        assert resp.status_code == 302


# ---------------------------------------------------------------------------
# Per-network delete  POST /networks/<id>/delete
# ---------------------------------------------------------------------------

class TestNetworkDelete:
    def _make_db_with_network(self, net_id=1, cidr="192.168.1.0/24", devices=None):
        from netdoc.storage.models import DiscoveredNetwork, Device
        net = MagicMock(spec=DiscoveredNetwork)
        net.id = net_id
        net.cidr = cidr
        db = MagicMock()
        db.__enter__ = lambda s: s
        db.__exit__ = MagicMock(return_value=False)

        def _query_side_effect(model):
            q = MagicMock()
            if model is DiscoveredNetwork:
                q.filter_by.return_value.first.return_value = net
            elif model is Device:
                # _delete_devices_in_cidr calls db.query(Device).all()
                q.all.return_value = devices or []
            else:
                q.filter_by.return_value.first.return_value = None
                q.all.return_value = []
            return q

        db.query.side_effect = _query_side_effect
        return db, net

    def test_delete_network_without_devices_redirects(self):
        app = _make_app()
        db, net = self._make_db_with_network()
        with patch("netdoc.web.app.SessionLocal", return_value=db):
            with app.test_client() as c:
                resp = c.post("/networks/1/delete", data={})
        assert resp.status_code == 302
        assert "/networks" in resp.headers.get("Location", "")
        # Without delete_devices param, network is deleted but no device deletion
        db.delete.assert_called_once_with(net)

    def test_delete_network_with_devices_calls_cascade(self):
        """With delete_devices=1, devices inside the CIDR should be deleted via db.delete()."""
        app = _make_app()
        # Create mock devices inside 10.0.0.0/24
        d1 = MagicMock()
        d1.ip = "10.0.0.1"
        d2 = MagicMock()
        d2.ip = "10.0.0.200"
        d_outside = MagicMock()
        d_outside.ip = "192.168.99.1"  # outside the CIDR — should not be deleted
        db, net = self._make_db_with_network(cidr="10.0.0.0/24", devices=[d1, d2, d_outside])
        with patch("netdoc.web.app.SessionLocal", return_value=db):
            with app.test_client() as c:
                resp = c.post("/networks/1/delete", data={"delete_devices": "1"})
        assert resp.status_code == 302
        # db.delete called for d1, d2, and the network itself (3 times total)
        assert db.delete.call_count == 3

    def test_delete_nonexistent_network_redirects(self):
        app = _make_app()
        db, _ = self._make_db_with_network()
        # Override: network not found
        db.query.return_value.filter_by.return_value.first.return_value = None
        # Reset side_effect so the override takes effect
        db.query.side_effect = None
        db.query.return_value.filter_by.return_value.first.return_value = None
        with patch("netdoc.web.app.SessionLocal", return_value=db):
            with app.test_client() as c:
                resp = c.post("/networks/9999/delete", data={})
        assert resp.status_code == 302
        db.delete.assert_not_called()

    def test_db_error_still_redirects(self):
        app = _make_app()
        db, net = self._make_db_with_network()
        db.delete.side_effect = RuntimeError("FK violation")
        with patch("netdoc.web.app.SessionLocal", return_value=db):
            with app.test_client() as c:
                resp = c.post("/networks/1/delete", data={})
        assert resp.status_code == 302
        db.rollback.assert_called_once()
