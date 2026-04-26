"""Regression tests for err-disabled port detection.

Covers:
- _check_err_disabled(): SNMP-based detection (Cisco OID + admin/oper fallback)
- _check_syslog_err_disabled(): syslog pattern detection (SecurityEvent)
"""
import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_iface_row(device_id, if_index, name, alias=None, admin=True, oper=False):
    row = MagicMock()
    row.device_id   = device_id
    row.if_index    = if_index
    row.name        = name
    row.alias       = alias
    row.admin_status = admin
    row.oper_status  = oper
    return row


def _make_device(dev_id, ip="10.0.0.1", community="public", vendor="Cisco", os_version=""):
    d = MagicMock()
    d.id            = dev_id
    d.ip            = ip
    d.snmp_community = community
    d.vendor        = vendor
    d.os_version    = os_version
    return d


# ---------------------------------------------------------------------------
# _check_err_disabled — SNMP-based
# ---------------------------------------------------------------------------

class TestCheckErrDisabled:
    def _run(self, devices, suspect_rows, snmp_get_return=None,
             existing_alerts=None, commit_raises=False):
        from run_snmp_worker import _check_err_disabled

        db = MagicMock()
        db.__enter__ = lambda s: s
        db.__exit__ = MagicMock(return_value=False)

        from netdoc.storage.models import Interface, DevicePortAlert

        def _query_side(model_cls):
            q = MagicMock()
            if model_cls is Interface:
                fq = MagicMock()
                fq.filter.return_value.all.return_value = suspect_rows
                q.filter.return_value = fq.filter.return_value
            elif model_cls is DevicePortAlert:
                fq = MagicMock()
                fq.filter.return_value.all.return_value = existing_alerts or []
                q.filter.return_value = fq.filter.return_value
            return q

        db.query.side_effect = _query_side

        if commit_raises:
            db.commit.side_effect = RuntimeError("db error")

        added = []
        db.add.side_effect = lambda obj: added.append(obj)

        deleted = []
        db.delete.side_effect = lambda obj: deleted.append(obj)

        with patch("run_snmp_worker.SessionLocal", return_value=db):
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=snmp_get_return):
                _check_err_disabled(devices, snmp_timeout=1)

        return added, deleted, db

    def test_no_devices_with_snmp_returns_early(self):
        d = _make_device(1)
        d.snmp_community = None
        added, deleted, db = self._run([d], [])
        db.query.assert_not_called()

    def test_cisco_errDisabled_creates_alert(self):
        dev = _make_device(1, vendor="Cisco Systems", os_version="Cisco IOS 15.2")
        row = _make_iface_row(1, 38, "GigabitEthernet1/0/38")
        # cieIfOperStatusCause = 42 (bpduGuard) → err-disabled
        added, deleted, _ = self._run([dev], [row], snmp_get_return="42")
        assert len(added) == 1
        assert added[0].alert_type == "err_disabled"
        assert added[0].severity == "critical"
        assert added[0].if_index == 38

    def test_cisco_cause_1_no_alert(self):
        """cause=1 (connected) — port is actually up, no alert."""
        dev = _make_device(1, vendor="Cisco", os_version="Cisco IOS")
        row = _make_iface_row(1, 5, "Gi1/0/5")
        added, _, _ = self._run([dev], [row], snmp_get_return="1")
        assert added == []

    def test_cisco_cause_2_no_alert(self):
        """cause=2 (notConnect) — just no cable, not err-disabled."""
        dev = _make_device(1, vendor="Cisco", os_version="Cisco IOS")
        row = _make_iface_row(1, 10, "Gi1/0/10")
        added, _, _ = self._run([dev], [row], snmp_get_return="2")
        assert added == []

    def test_non_cisco_with_alias_creates_alert(self):
        """Non-Cisco: admin-up oper-down with alias → alert (labelled port)."""
        dev = _make_device(1, vendor="HP", os_version="ProCurve")
        row = _make_iface_row(1, 3, "1/0/3", alias="Camera NVR uplink")
        added, _, _ = self._run([dev], [row], snmp_get_return=None)
        assert len(added) == 1
        assert added[0].alert_type == "err_disabled"

    def test_non_cisco_without_alias_no_alert(self):
        """Non-Cisco: admin-up oper-down with no alias → ignore (probably empty port)."""
        dev = _make_device(1, vendor="HP", os_version="ProCurve")
        row = _make_iface_row(1, 7, "1/0/7", alias=None)
        added, _, _ = self._run([dev], [row], snmp_get_return=None)
        assert added == []

    def test_existing_alert_updated_not_duplicated(self):
        from netdoc.storage.models import DevicePortAlert
        dev = _make_device(1, vendor="Cisco", os_version="Cisco IOS")
        row = _make_iface_row(1, 38, "Gi1/0/38")
        existing = MagicMock(spec=DevicePortAlert)
        existing.device_id   = 1
        existing.if_index    = 38
        existing.alert_type  = "err_disabled"
        existing.acknowledged_at = None
        added, _, db = self._run([dev], [row], snmp_get_return="42", existing_alerts=[existing])
        # Should NOT add a new row — only update existing
        assert added == []
        assert existing.last_seen is not None

    def test_recovered_port_alert_removed(self):
        """If alert exists but port is now oper-up → delete the alert."""
        from netdoc.storage.models import DevicePortAlert
        dev = _make_device(1, vendor="Cisco", os_version="Cisco IOS")
        # No suspect rows (port is back up)
        existing = MagicMock(spec=DevicePortAlert)
        existing.device_id   = 1
        existing.if_index    = 38
        existing.alert_type  = "err_disabled"
        existing.acknowledged_at = None
        added, deleted, _ = self._run([dev], [], snmp_get_return=None, existing_alerts=[existing])
        assert added == []
        assert existing in deleted

    def test_db_error_does_not_crash(self):
        dev = _make_device(1, vendor="Cisco", os_version="Cisco IOS")
        row = _make_iface_row(1, 5, "Gi1/0/5")
        # Should not raise even if commit fails
        added, _, _ = self._run([dev], [row], snmp_get_return="42", commit_raises=True)


# ---------------------------------------------------------------------------
# _check_syslog_err_disabled — syslog pattern detection
# ---------------------------------------------------------------------------

class TestCheckSyslogErrDisabled:
    def _run(self, syslog_rows, recent_event=None, diag_enabled="1"):
        from run_scanner import _check_syslog_err_disabled
        from netdoc.storage.models import Device, SecurityEvent, SystemStatus

        db = MagicMock()

        def _query_side(model_cls):
            q = MagicMock()
            if model_cls is SystemStatus:
                r = MagicMock(); r.value = diag_enabled
                q.filter_by.return_value.first.return_value = r
            elif model_cls is SecurityEvent:
                fq = MagicMock()
                fq.filter.return_value.first.return_value = recent_event
                q.filter.return_value = fq.filter.return_value
            elif model_cls is Device:
                dev = MagicMock(); dev.ip = "10.0.0.1"
                q.filter_by.return_value.first.return_value = dev
            return q

        db.query.side_effect = _query_side

        ch = MagicMock()
        ch.query.return_value.result_rows = syslog_rows

        stored = []

        def _store(db_, **kwargs):
            stored.append(kwargs)

        with patch("netdoc.storage.clickhouse._get_client", return_value=ch):
            with patch("netdoc.integrations.wazuh.store_security_event", side_effect=_store):
                _check_syslog_err_disabled(db)

        return stored

    def test_errdisable_in_syslog_creates_security_event(self):
        rows = [(5, "10.0.0.5", "%PM-4-ERR_DISABLE: bpduguard error on Gi1/0/38", datetime.utcnow())]
        stored = self._run(rows)
        assert len(stored) == 1
        assert stored[0]["event_type"] == "err_disabled_syslog"
        assert stored[0]["severity"] == "critical"

    def test_deduplication_skips_recent_event(self):
        rows = [(5, "10.0.0.5", "%PM-4-ERR_DISABLE: bpduguard error", datetime.utcnow())]
        recent = MagicMock()
        stored = self._run(rows, recent_event=recent)
        assert stored == []

    def test_disabled_when_diag_disabled(self):
        rows = [(5, "10.0.0.5", "%ERR_DISABLE: port-security", datetime.utcnow())]
        stored = self._run(rows, diag_enabled="0")
        assert stored == []

    def test_no_rows_no_events(self):
        stored = self._run([])
        assert stored == []

    def test_multiple_devices_one_event_each(self):
        now = datetime.utcnow()
        rows = [
            (1, "10.0.0.1", "%PM-4-ERR_DISABLE: bpduGuard error on Gi1/0/1", now),
            (2, "10.0.0.2", "err-disable state: port-security violation on Fa0/2", now),
        ]
        stored = self._run(rows)
        assert len(stored) == 2
        device_ids = {s["device_id"] for s in stored}
        assert device_ids == {1, 2}
