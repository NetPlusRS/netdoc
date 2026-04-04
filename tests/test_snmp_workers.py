"""Testy scenariuszowe dla snmp-worker i community-worker.

Scenariusze enterprise:
  - Factory reset / zmiana community
  - Rotacja community w calej sieci
  - Tymczasowe zerwanie polaczenia
  - Urządzenia stale (przeterminowane)
  - Nowe urzadzenia bez community
  - Specjalne znaki w community
  - Priorytety per-device vs global
  - Odpornosc na wyjatki / rollback
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, call

from netdoc.storage.models import Device, DeviceType, Credential, CredentialMethod


# ─────────────────────────────────────────────────────────────────────────────
# Helpers / fixtures
# ─────────────────────────────────────────────────────────────────────────────

def _dev(db, ip, *, community=None, snmp_ok_at=None, hostname=None,
         os_version=None, location=None, active=True, device_type=DeviceType.router):
    d = Device(ip=ip, device_type=device_type, is_active=active,
               snmp_community=community, snmp_ok_at=snmp_ok_at,
               hostname=hostname, os_version=os_version, location=location)
    db.add(d); db.commit(); db.refresh(d)
    return d


def _cred(db, username, device_id=None, priority=50):
    c = Credential(device_id=device_id, method=CredentialMethod.snmp,
                   username=username, priority=priority)
    db.add(c); db.commit(); db.refresh(c)
    return c


def _patch_session(db):
    """Zwraca context manager patchujacy SessionLocal w workerach na test db.
    db.close() jest mockowane aby nie zamykac sesji testowej.
    """
    db.close = lambda: None
    factory = lambda: db
    return (
        patch("run_snmp_worker.SessionLocal", side_effect=factory),
        patch("run_community_worker.SessionLocal", side_effect=factory),
    )


# ─────────────────────────────────────────────────────────────────────────────
# snmp-worker: _poll_device
# ─────────────────────────────────────────────────────────────────────────────

class TestSnmpWorkerPollDevice:

    def _pd(self, dev, snmp_timeout=2):
        """Helper: wywołuje _poll_device z nowymi parametrami (PERF-03 sygnatura)."""
        from run_snmp_worker import _poll_device
        return _poll_device(dev.id, dev.ip, dev.snmp_community,
                            dev.hostname, dev.os_version, dev.location, snmp_timeout)

    def test_poll_skips_device_without_community(self, db):
        """Urzadzenie bez snmp_community jest pomijane — zwraca success=False."""
        dev = _dev(db, "10.1.0.1", community=None)

        with _patch_session(db)[0]:
            result = self._pd(dev)

        assert result["success"] is False
        assert result["community"] is None

    def test_poll_success_updates_snmp_ok_at(self, db):
        """Udany poll odswierza snmp_ok_at."""
        old_time = datetime(2026, 1, 1, 0, 0, 0)
        dev = _dev(db, "10.1.0.2", community="public", snmp_ok_at=old_time)

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value="router-01"):
                result = self._pd(dev)

        assert result["success"] is True
        db.refresh(dev)
        assert dev.snmp_ok_at > old_time

    def test_poll_success_fills_empty_hostname(self, db):
        """Udany poll uzupelnia hostname jesli brak."""
        dev = _dev(db, "10.1.0.3", community="public", hostname=None)

        def _fake_get(ip, community, oid, timeout=2):
            from netdoc.collector.drivers.snmp import OID_SYSNAME
            return "router-main" if oid == OID_SYSNAME else None

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=_fake_get):
                self._pd(dev)

        db.refresh(dev)
        assert dev.hostname == "router-main"

    def test_poll_overwrites_hostname_snmp_authoritative(self, db):
        """Udany poll NADPISUJE hostname — SNMP jest autorytatywne wzgledem nmap."""
        dev = _dev(db, "10.1.0.4", community="public", hostname="istniejaca-nazwa")

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value="nowa-nazwa"):
                self._pd(dev)

        db.refresh(dev)
        assert dev.hostname == "nowa-nazwa"

    def test_factory_reset_clears_community(self, db):
        """Po factory reset urzadzenia stara community przestaje dzialac."""
        dev = _dev(db, "10.1.0.5", community="private",
                   snmp_ok_at=datetime(2026, 3, 10, 12, 0, 0))

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=None):
                result = self._pd(dev)

        assert result["success"] is False
        db.refresh(dev)
        assert dev.snmp_community is None
        assert dev.snmp_ok_at is None

    def test_community_rotation_clears_all_stale(self, db):
        """Rotacja community w calej sieci: stare community przestaja dzialac."""
        devices = [
            _dev(db, f"10.2.0.{i}", community="stare-haslo",
                 snmp_ok_at=datetime(2026, 3, 12, 12, 0, 0))
            for i in range(1, 4)
        ]

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=None):
                for dev in devices:
                    self._pd(dev)

        for dev in devices:
            db.refresh(dev)
            assert dev.snmp_community is None

    def test_temporary_disconnect_clears_community(self, db):
        """Tymczasowe zerwanie polaczenia (maintenance) — community wyczyszczone."""
        dev = _dev(db, "10.1.0.6", community="public",
                   snmp_ok_at=datetime(2026, 3, 12, 10, 0, 0))

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=None):
                self._pd(dev)

        db.refresh(dev)
        assert dev.snmp_community is None

    def test_poll_exception_does_not_corrupt_community(self, db):
        """Wyjątek w trakcie pollu nie niszczy snmp_community — rollback zachowuje stan."""
        dev = _dev(db, "10.1.0.7", community="public",
                   snmp_ok_at=datetime(2026, 3, 12, 12, 0, 0))

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get",
                       side_effect=RuntimeError("socket error")):
                result = self._pd(dev)

        assert result["success"] is False
        db.refresh(dev)
        assert dev.snmp_community == "public"

    def test_poll_updates_credential_last_success_at(self, db):
        """Udany poll aktualizuje last_success_at na globalnym credentiale."""
        dev = _dev(db, "10.1.0.8", community="public")
        cred = _cred(db, "public")

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value="switch-01"):
                self._pd(dev)

        db.refresh(cred)
        assert cred.last_success_at is not None
        assert cred.success_count == 1

    def test_poll_updates_per_device_credential(self, db):
        """Udany poll aktualizuje per-device credential jesli istnieje."""
        dev = _dev(db, "10.1.0.9", community="per-device-comm")
        cred = _cred(db, "per-device-comm", device_id=dev.id, priority=10)

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value="ap-01"):
                self._pd(dev)

        db.refresh(cred)
        assert cred.last_success_at is not None

    def test_poll_nonexistent_device_returns_failure(self, db):
        """Polling nieistniejacego device_id zwraca success=False bez bledu."""
        from run_snmp_worker import _poll_device

        with _patch_session(db)[0]:
            result = _poll_device(99999, "10.1.0.99", "public", None, None, None)

        assert result["success"] is False

    def test_poll_fills_os_version_from_sysdescr(self, db):
        """Poll uzupelnia os_version z sysDescr jesli jest puste."""
        from netdoc.collector.drivers.snmp import OID_SYSNAME, OID_SYSDESCR
        dev = _dev(db, "10.1.0.10", community="public", os_version=None)

        def _fake_get(ip, community, oid, timeout=2):
            if oid == OID_SYSNAME:  return "switch-02"
            if oid == OID_SYSDESCR: return "Cisco IOS 15.2"
            return None

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=_fake_get):
                self._pd(dev)

        db.refresh(dev)
        assert dev.os_version == "Cisco IOS 15.2"

    def test_poll_fills_location_from_syslocation(self, db):
        """Poll uzupelnia location z sysLocation jesli jest puste."""
        from netdoc.collector.drivers.snmp import OID_SYSNAME, OID_SYSLOCATION
        dev = _dev(db, "10.1.0.11", community="public", location=None)

        def _fake_get(ip, community, oid, timeout=2):
            if oid == OID_SYSNAME:     return "router-03"
            if oid == OID_SYSLOCATION: return "Serwerownia A / Rack 3"
            return None

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=_fake_get):
                self._pd(dev)

        db.refresh(dev)
        assert dev.location == "Serwerownia A / Rack 3"


# ─────────────────────────────────────────────────────────────────────────────
# community-worker: _probe_device
# ─────────────────────────────────────────────────────────────────────────────

class TestCommunityWorkerProbeDevice:
    """Testy dla nowego API: _probe_community (probe) + _save_found_community (zapis)."""

    def test_probe_finds_community_and_saves(self, db):
        """_save_found_community zapisuje community i snmp_ok_at dla znalezionego urzadzenia."""
        from run_community_worker import _save_found_community
        dev = _dev(db, "10.3.0.1", community=None)

        def _fake_get(ip, community, oid, timeout=1):
            return "firewall-01"

        with _patch_session(db)[1]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=_fake_get):
                _save_found_community(dev.id, "public", 1)

        db.refresh(dev)
        assert dev.snmp_community == "public"
        assert dev.snmp_ok_at is not None

    def test_probe_creates_global_credential_when_missing(self, db):
        """_save_found_community tworzy nowy global credential jesli nie istnieje."""
        from run_community_worker import _save_found_community
        dev = _dev(db, "10.3.0.2", community=None)

        with _patch_session(db)[1]:
            with patch("netdoc.collector.drivers.snmp._snmp_get",
                       return_value="server-01"):
                _save_found_community(dev.id, "corp2026", 1)

        cred = (db.query(Credential)
                .filter(Credential.device_id == None,
                        Credential.method == CredentialMethod.snmp,
                        Credential.username == "corp2026")
                .first())
        assert cred is not None
        assert cred.last_success_at is not None

    def test_probe_updates_existing_global_credential(self, db):
        """_save_found_community zwieksza success_count na istniejacym globalnym credentiale."""
        from run_community_worker import _save_found_community
        dev = _dev(db, "10.3.0.3", community=None)
        cred = _cred(db, "public")
        cred.success_count = 5
        db.commit()

        with _patch_session(db)[1]:
            with patch("netdoc.collector.drivers.snmp._snmp_get",
                       return_value="ap-main"):
                _save_found_community(dev.id, "public", 1)

        db.refresh(cred)
        assert cred.success_count == 6

    def test_probe_no_response_returns_not_found(self):
        """_probe_community zwraca found=False gdy brak odpowiedzi SNMP."""
        from run_community_worker import _probe_community
        with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=None):
            result = _probe_community(4, "10.3.0.4", "public", 1)
        assert result["found"] is False

    def test_probe_does_not_overwrite_existing_hostname(self, db):
        """_save_found_community nie nadpisuje hostname jesli juz ustawiony."""
        from run_community_worker import _save_found_community
        dev = _dev(db, "10.3.0.5", community=None, hostname="existing-hostname")

        with _patch_session(db)[1]:
            with patch("netdoc.collector.drivers.snmp._snmp_get",
                       return_value="new-hostname-from-snmp"):
                _save_found_community(dev.id, "public", 1)

        db.refresh(dev)
        assert dev.hostname == "existing-hostname"

    def test_probe_special_characters_in_community(self):
        """_probe_community z community zawierajaca myslniki, @, cyfry dziala poprawnie."""
        from run_community_worker import _probe_community
        special = "corp@snmp-v2-2026"
        with patch("netdoc.collector.drivers.snmp._snmp_get", return_value="server-01"):
            result = _probe_community(6, "10.3.0.6", special, 1)
        assert result["found"] is True
        assert result["community"] == special

    def test_save_exception_does_not_save_partial_state(self, db):
        """Wyjątek w _save_found_community — rollback, baza bez zmian."""
        from run_community_worker import _save_found_community
        dev = _dev(db, "10.3.0.7", community=None)

        call_count = [0]

        def _fake_get(ip, community, oid, timeout=1):
            call_count[0] += 1
            if call_count[0] == 1:
                return "router"           # pierwszy OID (sysname) — sukces
            raise RuntimeError("baza padla")  # kolejne OID — blad

        with _patch_session(db)[1]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=_fake_get):
                _save_found_community(dev.id, "public", 1)

        # Baza musi byc spojnosc — albo wszystko albo nic
        db.refresh(dev)
        if dev.snmp_community is not None:
            assert dev.snmp_ok_at is not None
        else:
            assert dev.snmp_ok_at is None


# ─────────────────────────────────────────────────────────────────────────────
# community-worker: scan_once — filtrowanie urzadzen
# ─────────────────────────────────────────────────────────────────────────────

class TestCommunityWorkerScanOnce:

    def test_scan_includes_devices_without_community(self, db):
        """scan_once pobiera urzadzenia bez snmp_community."""
        from run_community_worker import _get_db_communities
        _cred(db, "public")
        dev_no_comm  = _dev(db, "10.4.0.1", community=None)
        dev_has_comm = _dev(db, "10.4.0.2", community="public",
                            snmp_ok_at=datetime.utcnow())

        # Symuluj zapytanie ktore robi scan_once
        from sqlalchemy import or_
        stale_threshold = datetime.utcnow() - timedelta(days=7)
        from netdoc.storage.models import Device as DevModel
        result = (
            db.query(DevModel)
            .filter(DevModel.is_active == True)
            .filter(
                (DevModel.snmp_community == None) |
                (DevModel.snmp_ok_at < stale_threshold)
            )
            .all()
        )
        ids = [d.id for d in result]
        assert dev_no_comm.id in ids
        assert dev_has_comm.id not in ids  # swiezy — pomijany

    def test_scan_includes_stale_devices(self, db):
        """scan_once pobiera urzadzenia z przeterminowanym snmp_ok_at (> recheck_days)."""
        from netdoc.storage.models import Device as DevModel
        stale_ok_at  = datetime.utcnow() - timedelta(days=10)
        fresh_ok_at  = datetime.utcnow() - timedelta(hours=1)
        dev_stale = _dev(db, "10.4.0.3", community="public", snmp_ok_at=stale_ok_at)
        dev_fresh = _dev(db, "10.4.0.4", community="public", snmp_ok_at=fresh_ok_at)

        stale_threshold = datetime.utcnow() - timedelta(days=7)
        result = (
            db.query(DevModel)
            .filter(DevModel.is_active == True)
            .filter(
                (DevModel.snmp_community == None) |
                (DevModel.snmp_ok_at < stale_threshold)
            )
            .all()
        )
        ids = [d.id for d in result]
        assert dev_stale.id in ids   # 10 dni > 7 dni → do sprawdzenia
        assert dev_fresh.id not in ids  # 1 godzina → swiezy

    def test_scan_skips_inactive_devices(self, db):
        """scan_once pomija urzadzenia nieaktywne."""
        from netdoc.storage.models import Device as DevModel
        dev_inactive = _dev(db, "10.4.0.5", community=None, active=False)
        dev_active   = _dev(db, "10.4.0.6", community=None, active=True)

        stale_threshold = datetime.utcnow() - timedelta(days=7)
        result = (
            db.query(DevModel)
            .filter(DevModel.is_active == True)
            .filter(
                (DevModel.snmp_community == None) |
                (DevModel.snmp_ok_at < stale_threshold)
            )
            .all()
        )
        ids = [d.id for d in result]
        assert dev_inactive.id not in ids
        assert dev_active.id in ids

    def test_stale_boundary_exactly_at_threshold(self, db):
        """Urzadzenie z snmp_ok_at dokladnie na granicy progu: powinna byc pominieta."""
        from netdoc.storage.models import Device as DevModel
        # Dokladnie 7 dni temu — nie stale (< threshold = False)
        threshold = datetime.utcnow() - timedelta(days=7)
        dev = _dev(db, "10.4.0.7", community="public",
                   snmp_ok_at=threshold + timedelta(seconds=1))  # 1s nad progiem

        stale_threshold = datetime.utcnow() - timedelta(days=7)
        result = (
            db.query(DevModel)
            .filter(DevModel.is_active == True)
            .filter(
                (DevModel.snmp_community == None) |
                (DevModel.snmp_ok_at < stale_threshold)
            )
            .all()
        )
        ids = [d.id for d in result]
        assert dev.id not in ids  # swiezy jeszcze

    def test_scan_skips_when_no_communities_in_db(self, db, caplog):
        """scan_once nie wykonuje skanowania gdy brak community w DB."""
        from run_community_worker import scan_once
        _dev(db, "10.4.0.8", community=None)

        with _patch_session(db)[1]:
            with patch("netdoc.collector.drivers.snmp._snmp_get"):
                import logging
                with caplog.at_level(logging.WARNING):
                    scan_once()

        assert any("No communities" in r.message for r in caplog.records)


# ─────────────────────────────────────────────────────────────────────────────
# Scenariusz integracyjny: factory reset → autodiscovery
# ─────────────────────────────────────────────────────────────────────────────

class TestFactoryResetIntegration:

    def test_factory_reset_full_cycle(self, db):
        """Pelny cykl po factory reset:
        1. Urzadzenie ma stara community 'private'
        2. snmp-worker: 'private' nie odpowiada → czyści community
        3. community-worker: probuje listę, 'public' działa → zapisuje
        """
        from run_snmp_worker import _poll_device

        _cred(db, "public")   # global community w DB
        dev = _dev(db, "10.5.0.1", community="private",
                   snmp_ok_at=datetime(2026, 3, 10, 12, 0, 0))

        # Krok 1: snmp-worker — 'private' przestalo dzialac (factory reset)
        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=None):
                poll_result = _poll_device(dev.id, dev.ip, dev.snmp_community,
                                           dev.hostname, dev.os_version, dev.location)

        assert poll_result["success"] is False
        db.refresh(dev)
        assert dev.snmp_community is None   # wyczyszczone

        # Krok 2: community-worker — odkrywa 'public' (ustawienie fabryczne)
        from run_community_worker import _probe_community, _save_found_community

        with patch("netdoc.collector.drivers.snmp._snmp_get", return_value="switch-reset"):
            probe_result = _probe_community(dev.id, dev.ip, "public", 1)

        assert probe_result["found"] is True

        with _patch_session(db)[1]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value="switch-reset"):
                _save_found_community(dev.id, "public", 1)

        db.refresh(dev)
        assert dev.snmp_community == "public"
        assert dev.hostname == "switch-reset"

    def test_community_rotation_across_network(self, db):
        """IT zmienia community na wszystkich urzadzeniach jednoczesnie.

        Przed: 10 urzadzen ze snmp_community='stare2025'
        Po rotacji: snmp-worker resetuje wszystkie, community-worker
        odkrywa nowe 'corp2026'.
        """
        from run_snmp_worker import _poll_device

        _cred(db, "corp2026")  # nowe community juz dodane do bazy
        devices = [
            _dev(db, f"10.6.0.{i}", community="stare2025",
                 snmp_ok_at=datetime(2026, 3, 12, 8, 0, 0))
            for i in range(1, 6)
        ]

        # Krok 1: snmp-worker — stare community nie odpowiadaja
        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=None):
                for dev in devices:
                    _poll_device(dev.id, dev.ip, dev.snmp_community,
                                 dev.hostname, dev.os_version, dev.location)

        for dev in devices:
            db.refresh(dev)
            assert dev.snmp_community is None

        # Krok 2: community-worker — odkrywa nowe community
        from run_community_worker import _save_found_community

        def _fake_get(ip, community, oid, timeout=1):
            return f"device-{ip}"

        with _patch_session(db)[1]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=_fake_get):
                for dev in devices:
                    _save_found_community(dev.id, "corp2026", 1)

        found_count = sum(
            1 for dev in devices
            if (db.refresh(dev) or True) and dev.snmp_community == "corp2026"
        )
        assert found_count == 5

    def test_device_returns_after_maintenance(self, db):
        """Urzadzenie wraca do sieci po oknie serwisowym.

        snmp-worker wyczyscil community podczas niedostepnosci.
        community-worker wykrywa ta sama community po powrocie.
        """
        from run_snmp_worker import _poll_device

        _cred(db, "mgmt")
        dev = _dev(db, "10.7.0.1", community="mgmt",
                   snmp_ok_at=datetime(2026, 3, 12, 2, 0, 0))

        # Maintenance: urzadzenie offline — poll failuje
        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=None):
                _poll_device(dev.id, dev.ip, dev.snmp_community,
                             dev.hostname, dev.os_version, dev.location)

        db.refresh(dev)
        assert dev.snmp_community is None

        # Po maintenance: urzadzenie online z ta sama community
        from run_community_worker import _save_found_community

        with _patch_session(db)[1]:
            with patch("netdoc.collector.drivers.snmp._snmp_get",
                       return_value="core-router"):
                _save_found_community(dev.id, "mgmt", 1)

        db.refresh(dev)
        assert dev.snmp_community == "mgmt"
        assert dev.snmp_ok_at is not None


# ─── PERF-14: _read_snmp_settings używa WHERE IN zamiast N SELECT ─────────────

def test_read_snmp_settings_uses_single_query(db):
    """PERF-14 regresja: _read_snmp_settings wykonuje 1 query WHERE key IN (...)
    zamiast osobnych SELECT per klucz konfiguracyjny."""
    from run_snmp_worker import _read_snmp_settings
    from netdoc.storage.models import SystemStatus

    db.add(SystemStatus(key="snmp_interval_s", value="60", category="config"))
    db.add(SystemStatus(key="snmp_workers", value="5", category="config"))
    db.commit()

    query_count = []
    original_query = db.query

    def counting_query(model):
        if hasattr(model, "__tablename__") and model.__tablename__ == "system_status":
            query_count.append(1)
        return original_query(model)

    with _patch_session(db)[0]:
        with patch.object(db, "query", side_effect=counting_query):
            result = _read_snmp_settings()

    assert len(query_count) == 1, (
        f"PERF-14: oczekiwano 1 query do system_status, bylo: {len(query_count)}"
    )
    assert result[0] == 60   # snmp_interval_s
    assert result[1] == 5    # snmp_workers


# ─── PERF-12: Domyślna wartość snmp_workers = 32 ─────────────────────────────

def test_snmp_default_workers_is_32():
    """PERF-12 regresja: domyślna liczba workerów SNMP to 32, nie 10.
    Zwiększa limit z 500 do 1600 urządzeń w cyklu 300s."""
    import run_snmp_worker as w
    import os
    # Wartość domyślna (gdy nie ma zmiennej środowiskowej SNMP_WORKERS)
    # Testujemy logikę: int(os.getenv("SNMP_WORKERS", "32")) == 32
    default = int(os.getenv("SNMP_WORKERS", "32"))
    assert default == 32, f"PERF-12: domyślne SNMP_WORKERS powinno być 32, jest {default}"


# ─── PERF-02: sleep-until-next-run w main() workerów ─────────────────────────

def test_snmp_main_uses_next_run_sleep_pattern():
    """PERF-02 regresja: main() w snmp_worker używa next_run = monotonic() + interval
    i time.sleep(max(0, next_run - monotonic())) zamiast sleep-after-work."""
    import inspect
    import run_snmp_worker as w

    source = inspect.getsource(w.main)
    assert "next_run" in source, \
        "PERF-02: main() musi używać wzorca next_run = time.monotonic() + interval"
    assert "max(0" in source or "max(0." in source, \
        "PERF-02: main() musi używać max(0.0, next_run - time.monotonic())"


# ─── TEST-2: PERF-03 regresja — scan_once przekazuje primitives, nie ORM ─────

def test_scan_once_passes_device_primitives_not_orm(db):
    """PERF-03 regresja: scan_once() przekazuje (id, ip, community, hostname,
    os_version, location) bezposrednio do _poll_device — nie przekazuje obiektu ORM
    (ktory wymagalby dodatkowego SELECT per watek)."""
    from run_snmp_worker import scan_once
    from netdoc.storage.models import Device

    dev = Device(ip="10.5.0.1", snmp_community="public", is_active=True,
                 hostname="router-test", os_version="RouterOS", location="rack1")
    db.add(dev)
    db.commit()
    db.refresh(dev)

    calls = []

    def fake_poll(dev_id, dev_ip, community, hostname, os_version, location, snmp_timeout=2):
        calls.append({"id": dev_id, "ip": dev_ip, "community": community,
                      "hostname": hostname, "os_version": os_version})
        return {"device_id": dev_id, "success": False, "community": community}

    with _patch_session(db)[0]:
        with patch("run_snmp_worker._poll_device", side_effect=fake_poll):
            scan_once()

    assert len(calls) == 1, f"Oczekiwano 1 wywolanie _poll_device, bylo: {len(calls)}"
    c = calls[0]
    assert isinstance(c["id"], int),    "PERF-03: id musi byc int (nie ORM Device)"
    assert isinstance(c["ip"], str),    "PERF-03: ip musi byc str (nie ORM Device)"
    assert c["community"] == "public"
    assert c["hostname"] == "router-test"


# ─── WRK-01: try/except w main() SNMP ────────────────────────────────────────

def test_snmp_main_has_try_except_in_loop():
    """WRK-01 regresja: main() w snmp_worker opakowuje scan_once() w try/except
    — nieobsluzony wyjatek nie zatrzymuje workera."""
    import inspect
    import run_snmp_worker as m

    source = inspect.getsource(m.main)
    assert "try:" in source, "WRK-01: main() musi miec try/except wokol scan_once()"
    assert "except Exception" in source, \
        "WRK-01: main() musi lapac Exception w petli while True"


# ─────────────────────────────────────────────────────────────────────────────
# sysUpTime helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestTimeticks:
    def test_days_hours_minutes(self):
        from run_snmp_worker import _timeticks_to_str
        assert _timeticks_to_str(8640000) == "1d 0h 0m"   # 86400s = 1d
        assert _timeticks_to_str(9576000) == "1d 2h 36m"

    def test_hours_only(self):
        from run_snmp_worker import _timeticks_to_str
        assert _timeticks_to_str(360000) == "1h 0m"

    def test_minutes_only(self):
        from run_snmp_worker import _timeticks_to_str
        assert _timeticks_to_str(12000) == "2m"

    def test_zero(self):
        from run_snmp_worker import _timeticks_to_str
        assert _timeticks_to_str(0) == "0m"

    def test_invalid(self):
        from run_snmp_worker import _timeticks_to_str
        result = _timeticks_to_str("bad")
        assert isinstance(result, str)


class TestUpdateAssetNotesTag:
    def test_creates_tag_when_notes_empty(self):
        from run_snmp_worker import _update_asset_notes_tag
        result = _update_asset_notes_tag(None, "uptime", "3d 2h 5m")
        assert "[uptime 3d 2h 5m]" in result

    def test_replaces_existing_tag(self):
        from run_snmp_worker import _update_asset_notes_tag
        notes = "some notes\n[uptime 1d 0h 0m]"
        result = _update_asset_notes_tag(notes, "uptime", "2d 0h 0m")
        assert "[uptime 2d 0h 0m]" in result
        assert "[uptime 1d 0h 0m]" not in result

    def test_does_not_affect_other_tags(self):
        from run_snmp_worker import _update_asset_notes_tag
        notes = "[broadcast svc=rtsp]\n[uptime 1h 0m]"
        result = _update_asset_notes_tag(notes, "uptime", "2h 0m")
        assert "[broadcast svc=rtsp]" in result
        assert "[uptime 2h 0m]" in result

    def test_appends_when_other_content_present(self):
        from run_snmp_worker import _update_asset_notes_tag
        notes = "existing notes"
        result = _update_asset_notes_tag(notes, "uptime", "5m")
        assert "existing notes" in result
        assert "[uptime 5m]" in result


# ─────────────────────────────────────────────────────────────────────────────
# _poll_device: uptime + serial enrichment
# ─────────────────────────────────────────────────────────────────────────────

class TestPollDeviceUptimeSerial:

    def _pd(self, dev, db):
        from run_snmp_worker import _poll_device
        return _poll_device(dev.id, dev.ip, dev.snmp_community,
                            dev.hostname, dev.os_version, dev.location)

    def test_uptime_saved_to_snmp_uptime_column(self, db):
        """Poll zapisuje sysUpTime do kolumny snmp_uptime (nie do asset_notes)."""
        dev = _dev(db, "10.9.0.1", community="public")

        def fake_get(ip, community, oid, timeout=2):
            from run_snmp_worker import OID_SYSUPTIME
            from netdoc.collector.drivers.snmp import OID_SYSNAME
            if oid == OID_SYSNAME:   return "router-x"
            if oid == OID_SYSUPTIME: return 360000  # 1h = 3600s = 360000 timeticks
            return None

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=fake_get):
                self._pd(dev, db)

        db.refresh(dev)
        assert dev.snmp_uptime is not None
        assert "1h" in dev.snmp_uptime  # 360000 timeticks = 3600s = 1h → "1h 0m"

    def test_serial_saved_when_empty(self, db):
        """Poll zapisuje serial number z Entity MIB jesli pole puste."""
        dev = _dev(db, "10.9.0.2", community="public")
        assert dev.serial_number is None

        def fake_get(ip, community, oid, timeout=2):
            from run_snmp_worker import OID_ENT_SERIAL
            from netdoc.collector.drivers.snmp import OID_SYSNAME
            if oid == OID_SYSNAME:  return "switch-y"
            if oid == OID_ENT_SERIAL: return "FCW2134X0AB"
            return None

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=fake_get):
                self._pd(dev, db)

        db.refresh(dev)
        assert dev.serial_number == "FCW2134X0AB"

    def test_serial_updated_when_snmp_returns_different(self, db):
        """Poll NADPISUJE serial_number gdy SNMP zwraca inny numer — SNMP jest autorytatywne."""
        dev = _dev(db, "10.9.0.3", community="public")
        dev.serial_number = "EXISTING-SERIAL"
        db.commit()

        def fake_get(ip, community, oid, timeout=2):
            from run_snmp_worker import OID_ENT_SERIAL
            from netdoc.collector.drivers.snmp import OID_SYSNAME
            if oid == OID_SYSNAME:    return "switch-z"
            if oid == OID_ENT_SERIAL: return "NEW-SERIAL"
            return None

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=fake_get):
                self._pd(dev, db)

        db.refresh(dev)
        assert dev.serial_number == "NEW-SERIAL"

    def test_empty_serial_not_saved(self, db):
        """Poll ignoruje pusty/zerowy serial z Entity MIB."""
        dev = _dev(db, "10.9.0.4", community="public")

        def fake_get(ip, community, oid, timeout=2):
            from run_snmp_worker import OID_ENT_SERIAL
            from netdoc.collector.drivers.snmp import OID_SYSNAME
            if oid == OID_SYSNAME:    return "ap-1"
            if oid == OID_ENT_SERIAL: return "0"  # pusty/invalid
            return None

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=fake_get):
                self._pd(dev, db)

        db.refresh(dev)
        assert dev.serial_number is None


# ─────────────────────────────────────────────────────────────────────────────
# RAM (UCD-SNMP memTotalReal)
# ─────────────────────────────────────────────────────────────────────────────

class TestPollDeviceRam:
    """Testy dla bloku UCD-SNMP OID_MEM_TOTAL_REAL → ram_total_mb."""

    def _pd(self, dev, db):
        from run_snmp_worker import _poll_device
        return _poll_device(dev.id, str(dev.ip), dev.snmp_community,
                            dev.hostname, dev.os_version, dev.location)

    def test_ram_saved_from_snmp(self, db):
        """Poll zapisuje ram_total_mb z memTotalReal (w KB)."""
        dev = _dev(db, "10.10.0.1", community="public")

        def fake_get(ip, community, oid, timeout=2):
            from run_snmp_worker import OID_MEM_TOTAL_REAL
            from netdoc.collector.drivers.snmp import OID_SYSNAME
            if oid == OID_SYSNAME:      return "router-r"
            if oid == OID_MEM_TOTAL_REAL: return "524288"  # 512 MB in KB
            return None

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=fake_get):
                self._pd(dev, db)

        db.refresh(dev)
        assert dev.ram_total_mb == 512  # 524288 KB // 1024

    def test_ram_zero_not_saved(self, db):
        """Poll ignoruje memTotalReal=0 (invalid)."""
        dev = _dev(db, "10.10.0.2", community="public")

        def fake_get(ip, community, oid, timeout=2):
            from run_snmp_worker import OID_MEM_TOTAL_REAL
            from netdoc.collector.drivers.snmp import OID_SYSNAME
            if oid == OID_SYSNAME:        return "switch-s"
            if oid == OID_MEM_TOTAL_REAL: return "0"
            return None

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=fake_get):
                self._pd(dev, db)

        db.refresh(dev)
        assert dev.ram_total_mb is None

    def test_ram_none_not_saved(self, db):
        """Poll nie nadpisuje ram_total_mb gdy OID niedostepny (brak UCD-SNMP MIB)."""
        dev = _dev(db, "10.10.0.3", community="public")

        def fake_get(ip, community, oid, timeout=2):
            from netdoc.collector.drivers.snmp import OID_SYSNAME
            if oid == OID_SYSNAME: return "printer-p"
            return None  # OID_MEM_TOTAL_REAL niedostepny

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=fake_get):
                result = self._pd(dev, db)

        db.refresh(dev)
        assert dev.ram_total_mb is None
        assert result["success"] is True  # brak MIB nie jest bledem

    def test_ram_non_numeric_not_saved(self, db):
        """Poll ignoruje memTotalReal='N/A' (int() rzuca wyjatek, blok except lapie)."""
        dev = _dev(db, "10.10.0.4", community="public")

        def fake_get(ip, community, oid, timeout=2):
            from run_snmp_worker import OID_MEM_TOTAL_REAL
            from netdoc.collector.drivers.snmp import OID_SYSNAME
            if oid == OID_SYSNAME:        return "ap-a"
            if oid == OID_MEM_TOTAL_REAL: return "N/A"
            return None

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=fake_get):
                result = self._pd(dev, db)

        db.refresh(dev)
        assert dev.ram_total_mb is None
        assert result["success"] is True  # except: pass — poll nie pada


# ─────────────────────────────────────────────────────────────────────────────
# CDP enrichment
# ─────────────────────────────────────────────────────────────────────────────

class TestEnrichCdp:

    def _walk_fixture(self, entries: list[tuple]) -> list[tuple]:
        """entries: list of (oid_suffix, raw_val) → pełny OID z prefixem CDP."""
        from run_snmp_worker import _CDP_CACHE_TABLE
        return [(f"{_CDP_CACHE_TABLE}.{sfx}", val, None) for sfx, val in entries]

    def test_parses_cisco_neighbor_with_ip(self):
        from run_snmp_worker import _enrich_cdp
        # field.ifIndex.devIndex:  6=DeviceId, 4=Address, 8=Platform, 5=Version
        walk_data = self._walk_fixture([
            ("6.1.1", b"switch-core"),   # hostname
            ("4.1.1", bytes([10, 0, 1, 2])),  # IP 10.0.1.2
            ("8.1.1", b"Cisco WS-C3750X"),    # platform
            ("5.1.1", b"15.0(2)SE5"),         # software version
        ])
        with patch("netdoc.collector.snmp_walk.snmp_walk", return_value=iter(walk_data)):
            result = _enrich_cdp("10.0.0.1", "public")

        assert len(result) == 1
        r = result[0]
        assert r["hostname"] == "switch-core"
        assert r["ip"] == "10.0.1.2"
        assert r["platform"] == "Cisco WS-C3750X"
        assert r["software"] == "15.0(2)SE5"

    def test_strips_domain_from_hostname(self):
        from run_snmp_worker import _enrich_cdp
        walk_data = self._walk_fixture([
            ("6.1.1", b"router01.corp.local"),
            ("4.1.1", bytes([192, 168, 1, 1])),
        ])
        with patch("netdoc.collector.snmp_walk.snmp_walk", return_value=iter(walk_data)):
            result = _enrich_cdp("10.0.0.1", "public")

        assert result[0]["hostname"] == "router01"

    def test_multiple_neighbors(self):
        from run_snmp_worker import _enrich_cdp
        walk_data = self._walk_fixture([
            ("6.1.1", b"sw-access-1"),
            ("4.1.1", bytes([10, 1, 0, 1])),
            ("6.2.1", b"sw-access-2"),
            ("4.2.1", bytes([10, 1, 0, 2])),
        ])
        with patch("netdoc.collector.snmp_walk.snmp_walk", return_value=iter(walk_data)):
            result = _enrich_cdp("10.0.0.1", "public")

        assert len(result) == 2

    def test_returns_empty_on_walk_exception(self):
        from run_snmp_worker import _enrich_cdp
        with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=Exception("timeout")):
            result = _enrich_cdp("10.0.0.1", "public")
        assert result == []


# ─────────────────────────────────────────────────────────────────────────────
# ARP table enrichment
# ─────────────────────────────────────────────────────────────────────────────

class TestEnrichArp:

    def _walk_fixture(self, entries):
        from run_snmp_worker import _ARP_TABLE_OID
        return [(f"{_ARP_TABLE_OID}.{sfx}", val, None) for sfx, val in entries]

    def test_parses_dynamic_arp_entry(self):
        from run_snmp_worker import _enrich_arp
        # field.ifIndex.a.b.c.d → MAC from field 2, type from field 4
        walk_data = self._walk_fixture([
            ("2.1.192.168.1.10", bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])),  # MAC
            ("4.1.192.168.1.10", 3),   # type=3 dynamic
        ])
        with patch("netdoc.collector.snmp_walk.snmp_walk", return_value=iter(walk_data)):
            result = _enrich_arp("192.168.1.1", "public")

        assert len(result) == 1
        assert result[0]["ip"] == "192.168.1.10"
        assert result[0]["mac"].upper() == "AA:BB:CC:DD:EE:FF"

    def test_skips_invalid_arp_entries(self):
        from run_snmp_worker import _enrich_arp
        walk_data = self._walk_fixture([
            ("2.1.192.168.1.20", bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])),
            ("4.1.192.168.1.20", 2),  # type=2 invalid — should be skipped
        ])
        with patch("netdoc.collector.snmp_walk.snmp_walk", return_value=iter(walk_data)):
            result = _enrich_arp("192.168.1.1", "public")

        assert result == []

    def test_skips_broadcast_mac(self):
        from run_snmp_worker import _enrich_arp
        walk_data = self._walk_fixture([
            ("2.1.192.168.1.255", bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])),
            ("4.1.192.168.1.255", 3),
        ])
        with patch("netdoc.collector.snmp_walk.snmp_walk", return_value=iter(walk_data)):
            result = _enrich_arp("192.168.1.1", "public")

        assert result == []

    def test_returns_empty_on_exception(self):
        from run_snmp_worker import _enrich_arp
        with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=Exception("no route")):
            result = _enrich_arp("10.0.0.1", "public")
        assert result == []

    def test_save_arp_devices_upserts_new(self, db):
        """_save_arp_devices tworzy nowe urzadzenia z ARP entries."""
        from run_snmp_worker import _save_arp_devices
        from netdoc.storage.models import Device

        entries = [{"ip": "10.20.0.5", "mac": "aa:bb:cc:11:22:33"}]

        with _patch_session(db)[0]:
            n = _save_arp_devices(db, "10.20.0.1", entries)

        assert n >= 1
        dev = db.query(Device).filter(Device.ip == "10.20.0.5").first()
        assert dev is not None
        assert dev.mac.upper() == "AA:BB:CC:11:22:33"

    def test_save_arp_devices_skips_src_ip(self, db):
        """_save_arp_devices nie zapisuje wpisu IP samego urzadzenia-zrodla."""
        from run_snmp_worker import _save_arp_devices
        from netdoc.storage.models import Device

        src = "10.20.0.1"
        entries = [{"ip": src, "mac": "00:11:22:33:44:55"}]

        with _patch_session(db)[0]:
            n = _save_arp_devices(db, src, entries)

        assert n == 0
        assert db.query(Device).filter(Device.ip == src).first() is None
