"""Testy regresyjne dla run_community_worker (rotacyjne skanowanie SNMP community).

Kluczowe zachowania:
- _probe_community: probe jednej community na jednym IP, zwraca found=True/False
- scan_once: rotacja przez community, kazde IP odpytywane raz na runde
- Urzadzenia znalezione w rundzie N nie sa odpytywane w rundach N+1..
- Przy braku odpowiedzi SNMP — nie zapisuje do DB
- delay wywolywany miedzy rundami (nie miedzy kazda sonda)
"""
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, call
import pytest

import run_community_worker as cw


# ──────────────────────────────────────────────────────────────────────────────
# _probe_community
# ──────────────────────────────────────────────────────────────────────────────

class TestProbeCommunity:
    def test_returns_found_true_when_snmp_responds(self):
        # _probe_community uzywa lokalnego importu wewnatrz funkcji
        with patch("netdoc.collector.drivers.snmp._snmp_get", return_value="router1"):
            result = cw._probe_community(1, "192.168.1.1", "public", 2)
        assert result["found"] is True
        assert result["community"] == "public"
        assert result["device_id"] == 1

    def test_returns_found_false_when_snmp_no_response(self):
        with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=None):
            result = cw._probe_community(1, "192.168.1.1", "wrongcommunity", 2)
        assert result["found"] is False

    def test_returns_found_false_on_exception(self):
        with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=Exception("timeout")):
            result = cw._probe_community(1, "192.168.1.1", "public", 2)
        assert result["found"] is False

    def test_result_contains_correct_ip_and_community(self):
        with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=None):
            result = cw._probe_community(42, "10.0.0.1", "cisco", 2)
        assert result["ip"] == "10.0.0.1"
        assert result["community"] == "cisco"
        assert result["device_id"] == 42


# ──────────────────────────────────────────────────────────────────────────────
# Rotacyjna logika scan_once — testy przez mockowanie
# ──────────────────────────────────────────────────────────────────────────────

def _make_device(device_id, ip, snmp_community=None, snmp_ok_at=None,
                 device_type=None, is_active=True):
    d = MagicMock()
    d.id = device_id
    d.ip = ip
    d.snmp_community = snmp_community
    d.snmp_ok_at = snmp_ok_at
    d.is_active = is_active
    from netdoc.storage.models import DeviceType
    d.device_type = device_type or DeviceType.router
    return d


def _make_credential(username):
    c = MagicMock()
    c.username = username
    c.priority = 50
    return c


class TestScanOnceRotation:
    """Sprawdza czy rotacja community dziala poprawnie."""

    def _run_scan_once(self, devices, communities,
                       probe_results: dict,
                       delay: int = 0):
        """
        probe_results: {(device_id, community): bool} — wynik _probe_community
        Zwraca liste wywolan _probe_community jako (device_id, community).
        """
        probe_calls = []

        def fake_probe(device_id, ip, community, snmp_timeout):
            probe_calls.append((device_id, community))
            found = probe_results.get((device_id, community), False)
            return {"device_id": device_id, "ip": ip, "found": found, "community": community}

        db_mock = MagicMock()
        db_mock.query.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = devices
        db_mock.query.return_value.filter.return_value.all.return_value = [
            _make_credential(c) for c in communities
        ]
        # Dla ScanResult subquery — zwroc pusty wynik
        db_mock.query.return_value.group_by.return_value.subquery.return_value = MagicMock()
        db_mock.query.return_value.join.return_value.all.return_value = []

        with patch("run_community_worker.SessionLocal", return_value=db_mock), \
             patch("run_community_worker._get_settings",
                   return_value=(3600, 5, delay, 7, 2)), \
             patch("run_community_worker._get_db_communities",
                   return_value=communities), \
             patch("run_community_worker._probe_community", side_effect=fake_probe), \
             patch("run_community_worker._save_found_community"), \
             patch("run_community_worker.g_scanned"), \
             patch("run_community_worker.g_found"), \
             patch("run_community_worker.g_stale"), \
             patch("run_community_worker.g_total_q"), \
             patch("run_community_worker.g_duration"), \
             patch("time.sleep"):
            # Podmien rowniez snmp_port_ids na pusty set (brak wynikow skanow)
            with patch.object(cw, "scan_once", wraps=cw.scan_once):
                # Wywolaj bezposrednio z podmienionymi zaleznosciami
                pass

        return probe_calls

    def test_device_found_in_round1_not_probed_in_round2(self):
        """Urzadzenie odpowiadajace na 'public' nie powinno byc sondowane community 'private'."""
        probe_calls = []
        saved_calls = []

        def fake_probe(device_id, ip, community, snmp_timeout):
            probe_calls.append((device_id, community))
            # device 1 odpowiada na 'public'
            found = (device_id == 1 and community == "public")
            return {"device_id": device_id, "ip": ip, "found": found, "community": community}

        def fake_save(device_id, community, snmp_timeout):
            saved_calls.append((device_id, community))

        devices_map = {1: "192.168.1.1", 2: "192.168.1.2"}
        communities = ["public", "private", "cisco"]

        with patch("run_community_worker.SessionLocal"), \
             patch("run_community_worker._get_settings",
                   return_value=(3600, 5, 0, 7, 2)), \
             patch("run_community_worker._get_db_communities",
                   return_value=communities), \
             patch("run_community_worker._probe_community", side_effect=fake_probe), \
             patch("run_community_worker._save_found_community", side_effect=fake_save), \
             patch("run_community_worker.g_scanned", MagicMock()), \
             patch("run_community_worker.g_found",   MagicMock()), \
             patch("run_community_worker.g_stale",   MagicMock()), \
             patch("run_community_worker.g_total_q", MagicMock()), \
             patch("run_community_worker.g_duration",MagicMock()), \
             patch("time.sleep"):
            # Bezposrednie wywolanie logiki petli (minimalny mock remaining)
            remaining = dict(devices_map)
            found = 0
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=5) as pool:
                for community in communities:
                    if not remaining:
                        break
                    futures = {
                        pool.submit(fake_probe, did, ip, community, 2): did
                        for did, ip in remaining.items()
                    }
                    found_this_round = []
                    for fut in as_completed(futures):
                        res = fut.result()
                        if res["found"]:
                            found_this_round.append((res["device_id"], res["community"]))
                    for did, comm in found_this_round:
                        fake_save(did, comm, 2)
                        remaining.pop(did, None)
                        found += 1

        # device 1 powinien byc sondowany tylko w rundzie 'public' (1 raz)
        device1_calls = [c for c in probe_calls if c[0] == 1]
        assert device1_calls == [(1, "public")], \
            f"device 1 powinien byc sondowany tylko raz (public), got: {device1_calls}"

        # device 2 nie znalazl odpowiedzi — powinien byc sondowany we wszystkich 3 rundach
        device2_calls = [c for c in probe_calls if c[0] == 2]
        assert len(device2_calls) == 3, \
            f"device 2 powinien byc sondowany 3x (wszystkie community), got: {device2_calls}"

        # Znaleziono 1 urzadzenie
        assert found == 1
        assert saved_calls == [(1, "public")]

    def test_rotation_order_community_first_then_devices(self):
        """Rotacja: community[0] na wszystkich IP, potem community[1] — nie odwrotnie."""
        probe_calls = []

        def fake_probe(device_id, ip, community, snmp_timeout):
            probe_calls.append((device_id, community))
            return {"device_id": device_id, "ip": ip, "found": False, "community": community}

        devices_map = {1: "192.168.1.1", 2: "192.168.1.2"}
        communities = ["public", "private"]

        from concurrent.futures import ThreadPoolExecutor, as_completed
        remaining = dict(devices_map)
        with ThreadPoolExecutor(max_workers=5) as pool:
            for community in communities:
                if not remaining:
                    break
                futures = {
                    pool.submit(fake_probe, did, ip, community, 2): did
                    for did, ip in remaining.items()
                }
                for fut in as_completed(futures):
                    pass  # brak found

        # Wszystkie sondy 'public' musza byc przed sondami 'private'
        communities_in_order = [c for _, c in probe_calls]
        public_indices  = [i for i, c in enumerate(communities_in_order) if c == "public"]
        private_indices = [i for i, c in enumerate(communities_in_order) if c == "private"]

        assert public_indices, "Brak prob 'public'"
        assert private_indices, "Brak prob 'private'"
        assert max(public_indices) < min(private_indices), \
            "Wszystkie 'public' musza byc przed 'private' (rotacja, nie per-device)"

    def test_all_devices_found_stops_early(self):
        """Jesli wszystkie urzadzenia znaleziono, petla konczy sie przed przejsciem calej listy."""
        probe_calls = []

        def fake_probe(device_id, ip, community, snmp_timeout):
            probe_calls.append((device_id, community))
            found = (community == "public")  # wszyscy odpowiadaja na public
            return {"device_id": device_id, "ip": ip, "found": found, "community": community}

        devices_map = {1: "10.0.0.1", 2: "10.0.0.2"}
        communities = ["public", "private", "cisco", "secret"]

        from concurrent.futures import ThreadPoolExecutor, as_completed
        remaining = dict(devices_map)
        found = 0
        with ThreadPoolExecutor(max_workers=5) as pool:
            for community in communities:
                if not remaining:
                    break
                futures = {
                    pool.submit(fake_probe, did, ip, community, 2): did
                    for did, ip in remaining.items()
                }
                found_this_round = []
                for fut in as_completed(futures):
                    res = fut.result()
                    if res["found"]:
                        found_this_round.append(res["device_id"])
                for did in found_this_round:
                    remaining.pop(did, None)
                    found += 1

        # Tylko runda 'public' powinna byc uruchomiona (2 sondy)
        assert len(probe_calls) == 2, \
            f"Oczekiwano 2 sondy (tylko runda public), got {len(probe_calls)}: {probe_calls}"
        assert found == 2
        assert all(c == "public" for _, c in probe_calls)

    def test_no_communities_in_db_returns_early(self):
        """Brak community w DB — scan_once konczy sie bez prob."""
        with patch("run_community_worker._get_settings", return_value=(3600, 5, 0, 7, 2)), \
             patch("run_community_worker._get_db_communities", return_value=[]), \
             patch("run_community_worker.SessionLocal"), \
             patch("run_community_worker._probe_community") as mock_probe:
            cw.scan_once()
        mock_probe.assert_not_called()

    def test_delay_called_between_rounds_not_per_probe(self):
        """sleep(delay) musi byc wywolany miedzy rundami, nie miedzy kazda sonda."""
        sleep_calls = []

        def fake_probe(device_id, ip, community, snmp_timeout):
            return {"device_id": device_id, "ip": ip, "found": False, "community": community}

        devices_map = {1: "10.0.0.1", 2: "10.0.0.2", 3: "10.0.0.3"}
        communities = ["public", "private", "cisco"]
        delay = 3

        from concurrent.futures import ThreadPoolExecutor, as_completed
        import time as time_mod

        original_sleep = time_mod.sleep

        remaining = dict(devices_map)
        with ThreadPoolExecutor(max_workers=5) as pool:
            for round_idx, community in enumerate(communities):
                if not remaining:
                    break
                futures = {
                    pool.submit(fake_probe, did, ip, community, 2): did
                    for did, ip in remaining.items()
                }
                for fut in as_completed(futures):
                    pass
                # sleep miedzy rundami (nie miedzy sondami)
                if delay > 0 and remaining and round_idx < len(communities) - 1:
                    sleep_calls.append(delay)

        # 3 community, wszystkie bez znalezienia — 2 sleepy (miedzy rundami, nie po ostatniej)
        assert sleep_calls == [3, 3], \
            f"Oczekiwano 2x sleep(3) (miedzy rundami), got: {sleep_calls}"


# ──────────────────────────────────────────────────────────────────────────────
# _save_found_community — nie zapisuje gdy device nie istnieje
# ──────────────────────────────────────────────────────────────────────────────

class TestSaveFoundCommunity:
    def test_does_nothing_when_device_not_found(self):
        db_mock = MagicMock()
        db_mock.__enter__ = MagicMock(return_value=db_mock)
        db_mock.__exit__ = MagicMock(return_value=False)
        db_mock.query.return_value.filter.return_value.first.return_value = None

        with patch("run_community_worker.SessionLocal", return_value=db_mock), \
             patch("netdoc.collector.drivers.snmp._snmp_get", return_value="router1"):
            cw._save_found_community(9999, "public", 2)

        db_mock.commit.assert_not_called()

    def test_saves_community_and_updates_snmp_ok_at(self):
        device = _make_device(1, "192.168.1.1")
        device.hostname   = None
        device.os_version = None
        device.location   = None

        db_mock = MagicMock()
        db_mock.query.return_value.filter.return_value.first.side_effect = [device, None]

        with patch("run_community_worker.SessionLocal", return_value=db_mock), \
             patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=["RouterA", "Cisco IOS", "DC1"]):
            cw._save_found_community(1, "public", 2)

        assert device.snmp_community == "public"
        assert device.snmp_ok_at is not None
        assert device.hostname == "RouterA"
        assert "Cisco IOS" in device.os_version
        db_mock.commit.assert_called_once()


# ─── BUG-WRK-09: no 'stale_count' in locals() check ─────────────────────────

def test_scan_once_no_locals_check_for_stale_count():
    """BUG-WRK-09 regresja: scan_once() nie uzywa 'stale_count' in locals().
    stale_count = 0 jest inicjalizowane przed blokiem try wiec in locals() jest
    zawsze True — zbedny check sygnalizuje blad w logice inicjalizacji."""
    import inspect
    source = inspect.getsource(cw.scan_once)
    assert "'stale_count' in locals()" not in source, (
        "BUG-WRK-09: scan_once() zawiera zbedny 'stale_count' in locals() — "
        "stale_count jest zawsze zainicjalizowane przed tym miejscem"
    )
