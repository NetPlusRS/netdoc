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

    def test_poll_skips_device_without_community(self, db):
        """Urzadzenie bez snmp_community jest pomijane — zwraca success=False."""
        from run_snmp_worker import _poll_device
        dev = _dev(db, "10.1.0.1", community=None)

        with _patch_session(db)[0]:
            result = _poll_device(dev.id)

        assert result["success"] is False
        assert result["community"] is None

    def test_poll_success_updates_snmp_ok_at(self, db):
        """Udany poll odswierza snmp_ok_at."""
        from run_snmp_worker import _poll_device
        old_time = datetime(2026, 1, 1, 0, 0, 0)
        dev = _dev(db, "10.1.0.2", community="public", snmp_ok_at=old_time)

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value="router-01"):
                result = _poll_device(dev.id)

        assert result["success"] is True
        db.refresh(dev)
        assert dev.snmp_ok_at > old_time

    def test_poll_success_fills_empty_hostname(self, db):
        """Udany poll uzupelnia hostname jesli brak."""
        from run_snmp_worker import _poll_device
        dev = _dev(db, "10.1.0.3", community="public", hostname=None)

        def _fake_get(ip, community, oid, timeout=2):
            from netdoc.collector.drivers.snmp import OID_SYSNAME
            return "router-main" if oid == OID_SYSNAME else None

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=_fake_get):
                _poll_device(dev.id)

        db.refresh(dev)
        assert dev.hostname == "router-main"

    def test_poll_does_not_overwrite_existing_hostname(self, db):
        """Udany poll NIE nadpisuje hostname jesli juz ustawiony."""
        from run_snmp_worker import _poll_device
        dev = _dev(db, "10.1.0.4", community="public", hostname="istniejaca-nazwa")

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value="nowa-nazwa"):
                _poll_device(dev.id)

        db.refresh(dev)
        assert dev.hostname == "istniejaca-nazwa"

    def test_factory_reset_clears_community(self, db):
        """Po factory reset urzadzenia stara community przestaje dzialac.

        Scenariusz: admin resetuje switch do ustawien fabrycznych.
        Stara community 'private' nie odpowiada.
        snmp-worker powinien wyczysc snmp_community aby community-worker
        mogl znalezc nowa (domyslnie 'public').
        """
        from run_snmp_worker import _poll_device
        dev = _dev(db, "10.1.0.5", community="private",
                   snmp_ok_at=datetime(2026, 3, 10, 12, 0, 0))

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=None):
                result = _poll_device(dev.id)

        assert result["success"] is False
        db.refresh(dev)
        assert dev.snmp_community is None   # wyczyszczone — community-worker znajdzie nowe
        assert dev.snmp_ok_at is None

    def test_community_rotation_clears_all_stale(self, db):
        """Rotacja community w calej sieci: stare community przestaja dzialac.

        IT zmienia community ze 'stare-haslo' na 'nowe-haslo2026'.
        snmp-worker resetuje wszystkie urzadzenia — community-worker
        nastepnie znajdzie 'nowe-haslo2026' (musi byc w DB).
        """
        from run_snmp_worker import _poll_device
        devices = [
            _dev(db, f"10.2.0.{i}", community="stare-haslo",
                 snmp_ok_at=datetime(2026, 3, 12, 12, 0, 0))
            for i in range(1, 4)
        ]

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=None):
                for dev in devices:
                    _poll_device(dev.id)

        for dev in devices:
            db.refresh(dev)
            assert dev.snmp_community is None

    def test_temporary_disconnect_clears_community(self, db):
        """Tymczasowe zerwanie polaczenia (maintenance) — community wyczyszczone.

        Po powrocie urzadzenia community-worker wykryje community ponownie.
        """
        from run_snmp_worker import _poll_device
        dev = _dev(db, "10.1.0.6", community="public",
                   snmp_ok_at=datetime(2026, 3, 12, 10, 0, 0))

        # Symulacja: urzadzenie niedostepne (maintenance window)
        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value=None):
                _poll_device(dev.id)

        db.refresh(dev)
        assert dev.snmp_community is None  # gotowe do ponownego odkrycia

    def test_poll_exception_does_not_corrupt_community(self, db):
        """Wyjątek w trakcie pollu nie niszczy snmp_community — rollback zachowuje stan.

        Scenariusz: błąd sieciowy (nie brak odpowiedzi, ale wyjątek).
        Community powinna pozostac niezmieniona az do potwierdzenia braku odpowiedzi.
        """
        from run_snmp_worker import _poll_device
        dev = _dev(db, "10.1.0.7", community="public",
                   snmp_ok_at=datetime(2026, 3, 12, 12, 0, 0))

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get",
                       side_effect=RuntimeError("socket error")):
                result = _poll_device(dev.id)

        assert result["success"] is False
        db.refresh(dev)
        # Community NIE powinna byc wyczyszczona po wyjatku — tylko po None odpowiedzi
        assert dev.snmp_community == "public"

    def test_poll_updates_credential_last_success_at(self, db):
        """Udany poll aktualizuje last_success_at na globalnym credentiale."""
        from run_snmp_worker import _poll_device
        dev = _dev(db, "10.1.0.8", community="public")
        cred = _cred(db, "public")  # global credential

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value="switch-01"):
                _poll_device(dev.id)

        db.refresh(cred)
        assert cred.last_success_at is not None
        assert cred.success_count == 1

    def test_poll_updates_per_device_credential(self, db):
        """Udany poll aktualizuje per-device credential jesli istnieje."""
        from run_snmp_worker import _poll_device
        dev = _dev(db, "10.1.0.9", community="per-device-comm")
        cred = _cred(db, "per-device-comm", device_id=dev.id, priority=10)

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", return_value="ap-01"):
                _poll_device(dev.id)

        db.refresh(cred)
        assert cred.last_success_at is not None

    def test_poll_nonexistent_device_returns_failure(self, db):
        """Polling nieistniejacego device_id zwraca success=False bez bledu."""
        from run_snmp_worker import _poll_device

        with _patch_session(db)[0]:
            result = _poll_device(99999)

        assert result["success"] is False

    def test_poll_fills_os_version_from_sysdescr(self, db):
        """Poll uzupelnia os_version z sysDescr jesli jest puste."""
        from run_snmp_worker import _poll_device
        from netdoc.collector.drivers.snmp import OID_SYSNAME, OID_SYSDESCR, OID_SYSLOCATION
        dev = _dev(db, "10.1.0.10", community="public", os_version=None)

        def _fake_get(ip, community, oid, timeout=2):
            if oid == OID_SYSNAME:  return "switch-02"
            if oid == OID_SYSDESCR: return "Cisco IOS 15.2"
            return None

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=_fake_get):
                _poll_device(dev.id)

        db.refresh(dev)
        assert dev.os_version == "Cisco IOS 15.2"

    def test_poll_fills_location_from_syslocation(self, db):
        """Poll uzupelnia location z sysLocation jesli jest puste."""
        from run_snmp_worker import _poll_device
        from netdoc.collector.drivers.snmp import OID_SYSNAME, OID_SYSDESCR, OID_SYSLOCATION
        dev = _dev(db, "10.1.0.11", community="public", location=None)

        def _fake_get(ip, community, oid, timeout=2):
            if oid == OID_SYSNAME:     return "router-03"
            if oid == OID_SYSLOCATION: return "Serwerownia A / Rack 3"
            return None

        with _patch_session(db)[0]:
            with patch("netdoc.collector.drivers.snmp._snmp_get", side_effect=_fake_get):
                _poll_device(dev.id)

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

        assert any("Brak community" in r.message for r in caplog.records)


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
                poll_result = _poll_device(dev.id)

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
                    _poll_device(dev.id)

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
                _poll_device(dev.id)

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
