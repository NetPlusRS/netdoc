"""Regression tests for broadcast traffic feature.

Covers all areas that had bugs and were fixed:
  - run_broadcast_worker: _record_packet (BCW-04 cap), get_broadcast_stats,
      _get_local_ip (Docker NIC exclusion), ClickHouse delta logic (BCW-01)
  - netdoc/api/routes/metrics_if: broadcast-summary and broadcast-history endpoints
  - netdoc/storage/clickhouse: query_broadcast_top_devices, query_broadcast_history
"""
import sys
import types
import socket
from datetime import datetime
from unittest.mock import MagicMock, patch
import pytest

# ── stub prometheus before importing worker ──────────────────────────────────
prom_stub = types.ModuleType("prometheus_client")
prom_stub.Gauge = lambda *a, **kw: MagicMock()
prom_stub.start_http_server = lambda *a, **kw: None
sys.modules.setdefault("prometheus_client", prom_stub)

import run_broadcast_worker as bw
from netdoc.storage.models import Device, DeviceType


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def _clear_bcast_stats():
    """Reset module-level _bcast_stats between tests."""
    bw._bcast_stats.clear()
    yield
    bw._bcast_stats.clear()


def _add_device(db, ip: str, hostname: str = None) -> Device:
    d = Device(ip=ip, hostname=hostname, device_type=DeviceType.router, is_active=True)
    db.add(d)
    db.commit()
    db.refresh(d)
    return d


def _make_ch_client(snmp_rows=None, passive_rows=None):
    """Mock ClickHouse client that distinguishes SNMP vs passive queries by SQL content."""
    client = MagicMock()

    def _side_effect(sql, parameters=None):
        result = MagicMock()
        if "passive_bcast_pkts" in sql and "sum(value)" in sql:
            result.result_rows = passive_rows or []
        else:
            result.result_rows = snmp_rows or []
        return result

    client.query.side_effect = _side_effect
    return client


# ═══════════════════════════════════════════════════════════════════════════════
# _record_packet + get_broadcast_stats
# ═══════════════════════════════════════════════════════════════════════════════

class TestRecordPacket:
    def test_records_pkts_and_bytes(self):
        bw._record_packet("UNIFI", "10.0.0.1", 512)
        assert bw._bcast_stats["10.0.0.1"]["UNIFI"] == [1, 512]

    def test_accumulates_multiple_calls(self):
        bw._record_packet("MDNS", "10.0.0.2", 100)
        bw._record_packet("MDNS", "10.0.0.2", 200)
        assert bw._bcast_stats["10.0.0.2"]["MDNS"] == [2, 300]

    def test_multiple_protos_same_ip(self):
        bw._record_packet("UNIFI", "10.0.0.3", 64)
        bw._record_packet("MDNS",  "10.0.0.3", 128)
        assert bw._bcast_stats["10.0.0.3"]["UNIFI"][0] == 1
        assert bw._bcast_stats["10.0.0.3"]["MDNS"][0] == 1

    def test_cap_rejects_new_ips_at_limit(self):
        """New IPs are silently dropped once _BCAST_STATS_MAX_IPS is reached."""
        bw._bcast_stats.clear()
        for i in range(bw._BCAST_STATS_MAX_IPS):
            bw._record_packet("MDNS", f"10.{i // 256}.{i % 256}.1", 1)
        assert len(bw._bcast_stats) == bw._BCAST_STATS_MAX_IPS
        bw._record_packet("MDNS", "99.99.99.99", 100)
        assert "99.99.99.99" not in bw._bcast_stats

    def test_existing_ip_still_counted_at_cap(self):
        """Already-tracked IPs keep accumulating even when the cap is full."""
        bw._record_packet("UNIFI", "10.0.0.1", 10)
        for i in range(bw._BCAST_STATS_MAX_IPS - 1):
            bw._record_packet("MDNS", f"10.1.{i // 256}.{i % 256}", 1)
        bw._record_packet("UNIFI", "10.0.0.1", 20)
        assert bw._bcast_stats["10.0.0.1"]["UNIFI"] == [2, 30]


class TestGetBroadcastStats:
    def test_empty_returns_empty_list(self):
        assert bw.get_broadcast_stats() == []

    def test_sorted_by_total_pkts_descending(self):
        bw._record_packet("MDNS",  "10.0.0.1", 10)     # 1 pkt
        bw._record_packet("UNIFI", "10.0.0.2", 5)
        bw._record_packet("UNIFI", "10.0.0.2", 5)      # 2 pkts
        rows = bw.get_broadcast_stats()
        assert rows[0]["ip"] == "10.0.0.2"
        assert rows[1]["ip"] == "10.0.0.1"

    def test_total_pkts_and_bytes(self):
        bw._record_packet("UNIFI", "10.0.0.1", 100)
        bw._record_packet("MDNS",  "10.0.0.1", 200)
        row = bw.get_broadcast_stats()[0]
        assert row["total_pkts"] == 2
        assert row["total_bytes"] == 300

    def test_top_proto_by_packet_count(self):
        bw._record_packet("MDNS",  "10.0.0.1", 1)     # 1 pkt
        bw._record_packet("UNIFI", "10.0.0.1", 999)
        bw._record_packet("UNIFI", "10.0.0.1", 999)   # 2 pkts
        row = bw.get_broadcast_stats()[0]
        assert row["top_proto"] == "UNIFI"

    def test_proto_detail_structure(self):
        bw._record_packet("SSDP", "10.0.0.5", 64)
        row = bw.get_broadcast_stats()[0]
        assert "SSDP" in row["protocols"]
        assert row["protocols"]["SSDP"] == {"pkts": 1, "bytes": 64}

    def test_snapshot_independent_of_later_writes(self):
        """get_broadcast_stats() returns a snapshot, not a live view."""
        bw._record_packet("MDNS", "10.0.0.1", 100)
        snap = bw.get_broadcast_stats()
        bw._record_packet("MDNS", "10.0.0.1", 100)
        assert snap[0]["total_pkts"] == 1


# ═══════════════════════════════════════════════════════════════════════════════
# _get_local_ip — Windows routing table parsing (Docker NIC exclusion)
# ═══════════════════════════════════════════════════════════════════════════════

_ROUTE_DOCKER_WINS = """\
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         On-link       192.168.4.2      0
          0.0.0.0          0.0.0.0      192.168.5.1    192.168.5.191     35
"""

_ROUTE_LAN_ONLY = """\
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1      10.0.0.50     20
"""

_ROUTE_MULTI_GW = """\
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1      10.0.0.50     20
          0.0.0.0          0.0.0.0      10.10.0.1         10.0.0.51    100
"""


class TestGetLocalIp:
    def _mock_route(self, output: str):
        r = MagicMock()
        r.stdout = output
        return r

    def test_windows_ignores_onlink_metric0_docker_nic(self):
        """Docker On-link metric=0 must lose to LAN gateway route metric=35."""
        with patch("sys.platform", "win32"), \
             patch("run_broadcast_worker.subprocess.run",
                   return_value=self._mock_route(_ROUTE_DOCKER_WINS)):
            ip = bw._get_local_ip()
        assert ip == "192.168.5.191"

    def test_windows_single_real_gateway(self):
        with patch("sys.platform", "win32"), \
             patch("run_broadcast_worker.subprocess.run",
                   return_value=self._mock_route(_ROUTE_LAN_ONLY)):
            ip = bw._get_local_ip()
        assert ip == "10.0.0.50"

    def test_windows_picks_lowest_metric_among_real_gateways(self):
        with patch("sys.platform", "win32"), \
             patch("run_broadcast_worker.subprocess.run",
                   return_value=self._mock_route(_ROUTE_MULTI_GW)):
            ip = bw._get_local_ip()
        assert ip == "10.0.0.50"   # metric 20 beats metric 100

    def test_windows_falls_back_to_socket_on_route_error(self):
        """subprocess.run raises → falls through to socket.connect."""
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("192.168.1.100", 0)
        with patch("sys.platform", "win32"), \
             patch("run_broadcast_worker.subprocess.run", side_effect=OSError), \
             patch("socket.socket", return_value=mock_sock):
            ip = bw._get_local_ip()
        assert ip == "192.168.1.100"

    def test_non_windows_uses_socket_directly(self):
        """On Linux/Mac the route table is never consulted."""
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("172.16.0.5", 0)
        with patch("sys.platform", "linux"), \
             patch("socket.socket", return_value=mock_sock):
            ip = bw._get_local_ip()
        assert ip == "172.16.0.5"

    def test_returns_0000_when_all_methods_fail(self):
        with patch("sys.platform", "linux"), \
             patch("socket.socket", side_effect=OSError):
            ip = bw._get_local_ip()
        assert ip == "0.0.0.0"


# ═══════════════════════════════════════════════════════════════════════════════
# ClickHouse delta logic (BCW-01)
# Tests the invariant: worker writes 30-second deltas, NOT cumulative totals.
# ═══════════════════════════════════════════════════════════════════════════════

class TestClickHouseDeltaLogic:
    """Replicate the delta calculation from the main() stats-flush section."""

    @staticmethod
    def _run_flush(prev_totals: dict, stats_rows: list) -> tuple[dict, list]:
        written = []
        for sr in stats_rows:
            ip    = sr["ip"]
            total = float(sr["total_pkts"])
            prev  = prev_totals.get(ip, total)
            delta = max(0.0, total - prev)
            prev_totals[ip] = total
            if delta <= 0:
                continue
            written.append((ip, delta))
        return prev_totals, written

    def test_first_flush_writes_nothing(self):
        """First cycle: prev defaults to current total → delta=0 → nothing written."""
        prev, written = self._run_flush({}, [{"ip": "10.0.0.1", "total_pkts": 500}])
        assert written == []
        assert prev["10.0.0.1"] == 500.0

    def test_second_flush_writes_actual_delta(self):
        prev = {"10.0.0.1": 500.0}
        _, written = self._run_flush(prev, [{"ip": "10.0.0.1", "total_pkts": 550}])
        assert written == [("10.0.0.1", 50.0)]

    def test_counter_reset_clamped_to_zero(self):
        """Worker restart drops total → delta is negative → clamped to 0, nothing written."""
        prev = {"10.0.0.1": 1000.0}
        _, written = self._run_flush(prev, [{"ip": "10.0.0.1", "total_pkts": 10}])
        assert written == []

    def test_multiple_ips_are_independent(self):
        prev = {"10.0.0.1": 100.0}
        rows = [
            {"ip": "10.0.0.1", "total_pkts": 120},   # known → delta 20
            {"ip": "10.0.0.2", "total_pkts": 50},     # new   → delta 0 (first flush)
        ]
        _, written = self._run_flush(prev, rows)
        written_ips = [ip for ip, _ in written]
        assert "10.0.0.1" in written_ips
        assert "10.0.0.2" not in written_ips

    def test_prev_totals_saved_even_on_zero_delta(self):
        """Skipped-first-cycle IPs are saved so the next cycle gives correct delta."""
        prev, _ = self._run_flush({}, [{"ip": "10.0.0.1", "total_pkts": 100}])
        _, written = self._run_flush(prev, [{"ip": "10.0.0.1", "total_pkts": 130}])
        assert written == [("10.0.0.1", 30.0)]  # not 130.0

    def test_zero_traffic_ip_produces_no_rows(self):
        """An IP whose total doesn't grow produces no ClickHouse row."""
        prev = {"10.0.0.1": 200.0}
        _, written = self._run_flush(prev, [{"ip": "10.0.0.1", "total_pkts": 200}])
        assert written == []


# ═══════════════════════════════════════════════════════════════════════════════
# query_broadcast_top_devices — unit (mocked ClickHouse)
# ═══════════════════════════════════════════════════════════════════════════════

class TestQueryBroadcastTopDevices:
    def _call(self, snmp_rows=None, passive_rows=None, since_hours=24, limit=10):
        from netdoc.storage.clickhouse import query_broadcast_top_devices
        client = _make_ch_client(snmp_rows, passive_rows)
        with patch("netdoc.storage.clickhouse._get_client", return_value=client):
            return query_broadcast_top_devices(since_hours=since_hours, limit=limit)

    def test_returns_empty_on_no_data(self):
        assert self._call() == []

    def test_bcast_plus_mcast_as_total_in(self):
        rows = self._call(snmp_rows=[
            (7, "in_bcast_pkts", 1000.0),
            (7, "in_mcast_pkts",  200.0),
        ])
        assert rows[0]["total_in"] == 1200.0

    def test_nucast_fallback_when_bcast_mcast_zero(self):
        """Older devices only report in_nucast_pkts (combined bcast+mcast)."""
        rows = self._call(snmp_rows=[(7, "in_nucast_pkts", 5000.0)])
        assert rows[0]["total_in"] == 5000.0

    def test_bcast_preferred_nucast_not_double_counted(self):
        """When in_bcast_pkts > 0, in_nucast_pkts must NOT be added to total_in."""
        rows = self._call(snmp_rows=[
            (7, "in_bcast_pkts",  500.0),
            (7, "in_nucast_pkts", 800.0),
        ])
        assert rows[0]["total_in"] == 500.0   # not 1300

    def test_passive_pkts_added_to_total_in(self):
        rows = self._call(
            snmp_rows=[(7, "in_bcast_pkts", 100.0)],
            passive_rows=[(7, 50.0)],
        )
        assert rows[0]["total_in"] == 150.0
        assert rows[0]["passive_pkts"] == 50.0

    def test_passive_only_device_appears_in_results(self):
        rows = self._call(passive_rows=[(42, 200.0)])
        assert len(rows) == 1
        assert rows[0]["device_id"] == 42
        assert rows[0]["passive_pkts"] == 200.0
        assert rows[0]["total_in"] == 200.0

    def test_sorted_by_total_in_descending(self):
        rows = self._call(snmp_rows=[
            (1, "in_bcast_pkts", 100.0),
            (2, "in_bcast_pkts", 500.0),
            (3, "in_bcast_pkts", 300.0),
        ])
        assert [r["device_id"] for r in rows] == [2, 3, 1]

    def test_limit_applied(self):
        snmp = [(i, "in_bcast_pkts", float(i)) for i in range(1, 21)]
        assert len(self._call(snmp_rows=snmp, limit=5)) == 5

    def test_all_output_fields_present(self):
        rows = self._call(snmp_rows=[(1, "in_bcast_pkts", 10.0)])
        expected = {"device_id", "in_bcast", "out_bcast", "in_mcast", "out_mcast",
                    "in_nucast", "out_nucast", "passive_pkts", "total_in"}
        assert expected.issubset(rows[0].keys())

    def test_ch_query_exception_returns_empty(self):
        """Query execution failure (e.g. ClickHouse unreachable) returns empty list."""
        from netdoc.storage.clickhouse import query_broadcast_top_devices
        mock_client = MagicMock()
        mock_client.query.side_effect = Exception("connection refused")
        with patch("netdoc.storage.clickhouse._get_client", return_value=mock_client):
            assert query_broadcast_top_devices() == []


# ═══════════════════════════════════════════════════════════════════════════════
# query_broadcast_history — unit (mocked ClickHouse)
# SNMP rows: (bucket, metric, prev_max, cur_max, step)
# Passive rows: (bucket, rate)  where rate = sum(value)/step_f (already divided)
# ═══════════════════════════════════════════════════════════════════════════════

class TestQueryBroadcastHistory:
    def _call(self, snmp_rows=None, passive_rows=None, device_id=1, hours=24, step=5):
        from netdoc.storage.clickhouse import query_broadcast_history
        client = _make_ch_client(snmp_rows, passive_rows)
        with patch("netdoc.storage.clickhouse._get_client", return_value=client):
            return query_broadcast_history(device_id, since_hours=hours, step_minutes=step)

    def test_empty_when_no_data(self):
        assert self._call() == []

    def test_snmp_rate_computed_as_delta_over_step(self):
        bucket = datetime(2026, 4, 21, 12, 0, 0)
        # rate = (cur_max - prev_max) / step = (400 - 100) / 300 = 1.0
        rows = self._call(snmp_rows=[(bucket, "in_bcast_pkts", 100.0, 400.0, 300.0)])
        assert rows[0]["in_bcast_rate"] == pytest.approx(1.0)

    def test_counter_reset_yields_zero_rate(self):
        """cur_max < prev_max → counter wrapped/reset → rate=0."""
        bucket = datetime(2026, 4, 21, 12, 0, 0)
        rows = self._call(snmp_rows=[(bucket, "in_bcast_pkts", 500.0, 100.0, 300.0)])
        assert rows[0]["in_bcast_rate"] == 0.0

    def test_first_bucket_prev_negative_yields_zero_rate(self):
        """lagInFrame returns -1 for the first bucket (no preceding row)."""
        bucket = datetime(2026, 4, 21, 12, 0, 0)
        rows = self._call(snmp_rows=[(bucket, "in_bcast_pkts", -1.0, 900.0, 300.0)])
        assert rows[0]["in_bcast_rate"] == 0.0

    def test_passive_rate_taken_from_sum_already_divided(self):
        """passive_rate comes from SQL sum(value)/step_f — passed through as-is."""
        bucket = datetime(2026, 4, 21, 12, 0, 0)
        rows = self._call(passive_rows=[(bucket, 0.5)])
        assert rows[0]["passive_rate"] == pytest.approx(0.5)

    def test_output_has_all_seven_rate_fields(self):
        """All 7 rate fields must be present — including out_nucast_rate added in CH-11."""
        bucket = datetime(2026, 4, 21, 12, 0, 0)
        rows = self._call(snmp_rows=[(bucket, "in_bcast_pkts", 0.0, 300.0, 300.0)])
        expected = {
            "bucket", "in_bcast_rate", "out_bcast_rate",
            "in_mcast_rate", "out_mcast_rate",
            "in_nucast_rate", "out_nucast_rate", "passive_rate",
        }
        assert expected == set(rows[0].keys())

    def test_buckets_sorted_chronologically(self):
        b1 = datetime(2026, 4, 21, 10, 0, 0)
        b2 = datetime(2026, 4, 21, 12, 0, 0)
        b3 = datetime(2026, 4, 21, 11, 0, 0)
        snmp_rows = [
            (b1, "in_bcast_pkts", 0.0, 100.0, 300.0),
            (b2, "in_bcast_pkts", 0.0, 300.0, 300.0),
            (b3, "in_bcast_pkts", 0.0, 200.0, 300.0),
        ]
        rows = self._call(snmp_rows=snmp_rows)
        keys = [r["bucket"] for r in rows]
        assert keys == sorted(keys)

    def test_snmp_and_passive_buckets_merged(self):
        """A bucket present in both queries gets all fields populated."""
        bucket = datetime(2026, 4, 21, 12, 0, 0)
        rows = self._call(
            snmp_rows=[(bucket, "in_bcast_pkts", 0.0, 600.0, 300.0)],
            passive_rows=[(bucket, 0.25)],
        )
        assert len(rows) == 1
        assert rows[0]["in_bcast_rate"] == pytest.approx(2.0)
        assert rows[0]["passive_rate"] == pytest.approx(0.25)

    def test_ch_exception_returns_empty(self):
        from netdoc.storage.clickhouse import query_broadcast_history
        with patch("netdoc.storage.clickhouse._get_client", side_effect=Exception("ch down")):
            assert query_broadcast_history(1) == []


# ═══════════════════════════════════════════════════════════════════════════════
# API: GET /api/metrics/broadcast-summary
# ═══════════════════════════════════════════════════════════════════════════════

class TestBroadcastSummaryAPI:
    def _ch_row(self, device_id, total_in=100.0, **kw):
        return {
            "device_id": device_id,
            "in_bcast": kw.get("in_bcast", 0.0),
            "out_bcast": kw.get("out_bcast", 0.0),
            "in_mcast": kw.get("in_mcast", 0.0),
            "out_mcast": kw.get("out_mcast", 0.0),
            "in_nucast": kw.get("in_nucast", 0.0),
            "out_nucast": kw.get("out_nucast", 0.0),
            "passive_pkts": kw.get("passive_pkts", 0.0),
            "total_in": total_in,
        }

    def test_returns_200_with_envelope_when_no_data(self, client):
        with patch("netdoc.storage.clickhouse.query_broadcast_top_devices", return_value=[]):
            resp = client.get("/api/metrics/broadcast-summary")
        assert resp.status_code == 200
        body = resp.json()
        assert body["devices"] == []
        assert "since_hours" in body
        assert "threshold" in body

    def test_returns_ip_and_hostname_from_db(self, client, db):
        dev = _add_device(db, "192.168.1.1", "my-router")
        with patch("netdoc.storage.clickhouse.query_broadcast_top_devices",
                   return_value=[self._ch_row(dev.id, total_in=1000.0)]):
            resp = client.get("/api/metrics/broadcast-summary")
        d = resp.json()["devices"][0]
        assert d["ip"] == "192.168.1.1"
        assert d["hostname"] == "my-router"

    def test_is_spammer_false_when_threshold_zero(self, client, db):
        dev = _add_device(db, "10.0.0.1")
        with patch("netdoc.storage.clickhouse.query_broadcast_top_devices",
                   return_value=[self._ch_row(dev.id, total_in=999_999.0)]):
            resp = client.get("/api/metrics/broadcast-summary?threshold=0")
        assert resp.json()["devices"][0]["is_spammer"] is False

    def test_is_spammer_true_when_total_above_threshold(self, client, db):
        dev = _add_device(db, "10.0.0.1")
        with patch("netdoc.storage.clickhouse.query_broadcast_top_devices",
                   return_value=[self._ch_row(dev.id, total_in=5001.0)]):
            resp = client.get("/api/metrics/broadcast-summary?threshold=5000")
        assert resp.json()["devices"][0]["is_spammer"] is True

    def test_is_spammer_false_at_exactly_threshold(self, client, db):
        """Threshold comparison is strict (>), so equal value is not spam."""
        dev = _add_device(db, "10.0.0.1")
        with patch("netdoc.storage.clickhouse.query_broadcast_top_devices",
                   return_value=[self._ch_row(dev.id, total_in=5000.0)]):
            resp = client.get("/api/metrics/broadcast-summary?threshold=5000")
        assert resp.json()["devices"][0]["is_spammer"] is False

    def test_device_missing_from_db_gets_null_ip(self, client):
        with patch("netdoc.storage.clickhouse.query_broadcast_top_devices",
                   return_value=[self._ch_row(9999, total_in=42.0)]):
            resp = client.get("/api/metrics/broadcast-summary")
        d = resp.json()["devices"][0]
        assert d["ip"] is None
        assert d["hostname"] is None

    def test_ch_error_returns_empty_device_list(self, client):
        with patch("netdoc.storage.clickhouse.query_broadcast_top_devices",
                   side_effect=Exception("ch down")):
            resp = client.get("/api/metrics/broadcast-summary")
        assert resp.status_code == 200
        assert resp.json()["devices"] == []

    def test_since_hours_echoed_in_response(self, client):
        with patch("netdoc.storage.clickhouse.query_broadcast_top_devices", return_value=[]):
            resp = client.get("/api/metrics/broadcast-summary?since_hours=6")
        assert resp.json()["since_hours"] == 6

    def test_threshold_echoed_in_response(self, client):
        with patch("netdoc.storage.clickhouse.query_broadcast_top_devices", return_value=[]):
            resp = client.get("/api/metrics/broadcast-summary?threshold=1000")
        assert resp.json()["threshold"] == 1000.0


# ═══════════════════════════════════════════════════════════════════════════════
# API: GET /api/devices/{id}/broadcast-history
# ═══════════════════════════════════════════════════════════════════════════════

_FULL_BUCKET = {
    "bucket": "2026-04-21T12:00:00",
    "in_bcast_rate": 1.5, "out_bcast_rate": 0.5,
    "in_mcast_rate": 0.2, "out_mcast_rate": 0.1,
    "in_nucast_rate": 0.0, "out_nucast_rate": 0.3,
    "passive_rate": 0.05,
}


class TestBroadcastHistoryAPI:
    def test_404_for_missing_device(self, client):
        resp = client.get("/api/devices/9999/broadcast-history")
        assert resp.status_code == 404

    def test_200_with_empty_buckets_when_no_ch_data(self, client, db):
        dev = _add_device(db, "10.0.0.1")
        with patch("netdoc.storage.clickhouse.query_broadcast_history", return_value=[]):
            resp = client.get(f"/api/devices/{dev.id}/broadcast-history")
        assert resp.status_code == 200
        body = resp.json()
        assert body["buckets"] == []
        assert body["device_id"] == dev.id

    def test_returns_all_seven_rate_fields_per_bucket(self, client, db):
        dev = _add_device(db, "10.0.0.1")
        with patch("netdoc.storage.clickhouse.query_broadcast_history",
                   return_value=[_FULL_BUCKET]):
            resp = client.get(f"/api/devices/{dev.id}/broadcast-history")
        b = resp.json()["buckets"][0]
        assert b["in_bcast_rate"] == 1.5
        assert b["out_bcast_rate"] == 0.5
        assert b["out_nucast_rate"] == 0.3  # CH-11 field
        assert b["passive_rate"] == 0.05

    def test_hours_and_step_minutes_echoed(self, client, db):
        dev = _add_device(db, "10.0.0.1")
        with patch("netdoc.storage.clickhouse.query_broadcast_history", return_value=[]):
            resp = client.get(
                f"/api/devices/{dev.id}/broadcast-history?hours=6&step_minutes=10"
            )
        body = resp.json()
        assert body["hours"] == 6
        assert body["step_minutes"] == 10

    def test_ch_error_returns_empty_buckets(self, client, db):
        dev = _add_device(db, "10.0.0.1")
        with patch("netdoc.storage.clickhouse.query_broadcast_history",
                   side_effect=Exception("ch down")):
            resp = client.get(f"/api/devices/{dev.id}/broadcast-history")
        assert resp.status_code == 200
        assert resp.json()["buckets"] == []
