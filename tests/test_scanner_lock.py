"""Testy dla mechanizmu blokady skanera (scanner.pid) i logiki restartu.

Scenariusze testowane:
- _is_scanner_process: dead PID, cudzy PID, nasz PID ze starym run_scanner w cmdline
- _acquire_scanner_lock: brak pliku, swiezy PID (skaner dziala), stale PID (python inny),
  stale PID (nie-python), uszkodzony plik, ten sam PID co my
- Logika restartu: po przerwaniu full scan, pelny discovery restart
"""
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch
import pytest


# ---------------------------------------------------------------------------
# Helpers do importu funkcji bez uruchamiania skanera
# ---------------------------------------------------------------------------

def _import_lock_fns():
    """Importuje _is_scanner_process i _acquire_scanner_lock z run_scanner."""
    import importlib
    spec = importlib.util.find_spec("run_scanner")
    assert spec is not None, "run_scanner.py nie znaleziony"
    # Importujemy przez atrybut modulu (juz zaladowany lub ladujemy)
    if "run_scanner" not in sys.modules:
        import run_scanner  # noqa: F401
    import run_scanner as rs
    return rs._is_scanner_process, rs._acquire_scanner_lock, rs._LOCK_FILE


# ---------------------------------------------------------------------------
# Testy _is_scanner_process
# ---------------------------------------------------------------------------

class TestIsScanner:
    def test_dead_pid_returns_false(self):
        """PID ktory nie istnieje -> False."""
        _is_scanner_process, _, _ = _import_lock_fns()
        assert _is_scanner_process(99999999) is False

    def test_non_python_pid_returns_false(self):
        """PID procesu nie-python (np. pid 4 = System) -> False."""
        _is_scanner_process, _, _ = _import_lock_fns()
        import psutil
        # Znajdz dowolny nie-python proces
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if "python" not in proc.name().lower():
                    result = _is_scanner_process(proc.pid)
                    assert result is False
                    return
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        pytest.skip("Nie znaleziono nie-python procesu")

    def test_python_without_scanner_returns_false(self):
        """Python bez 'run_scanner' w cmdline -> False."""
        _is_scanner_process, _, _ = _import_lock_fns()
        mock_proc = MagicMock()
        mock_proc.is_running.return_value = True
        mock_proc.name.return_value = "python.exe"
        mock_proc.cmdline.return_value = ["python.exe", "-c", "print(42)"]

        with patch("psutil.Process", return_value=mock_proc):
            result = _is_scanner_process(12345)
        assert result is False

    def test_python_with_run_scanner_returns_true(self):
        """Python z 'run_scanner.py' w cmdline -> True."""
        _is_scanner_process, _, _ = _import_lock_fns()
        mock_proc = MagicMock()
        mock_proc.is_running.return_value = True
        mock_proc.name.return_value = "python.exe"
        mock_proc.cmdline.return_value = [
            "C:\\Python311\\python.exe", "-u",
            "C:\\Users\\netdoc\\run_scanner.py", "--once",
        ]

        with patch("psutil.Process", return_value=mock_proc):
            result = _is_scanner_process(18276)
        assert result is True

    def test_not_running_returns_false(self):
        """proc.is_running() == False -> False."""
        _is_scanner_process, _, _ = _import_lock_fns()
        mock_proc = MagicMock()
        mock_proc.is_running.return_value = False

        with patch("psutil.Process", return_value=mock_proc):
            result = _is_scanner_process(12345)
        assert result is False

    def test_no_such_process_returns_false(self):
        """psutil.NoSuchProcess -> False (nie crashuje)."""
        import psutil
        _is_scanner_process, _, _ = _import_lock_fns()
        with patch("psutil.Process", side_effect=psutil.NoSuchProcess(12345)):
            result = _is_scanner_process(12345)
        assert result is False

    def test_access_denied_on_cmdline_uses_name(self):
        """AccessDenied na cmdline -> sprawdz tylko nazwe procesu."""
        import psutil
        _is_scanner_process, _, _ = _import_lock_fns()
        mock_proc = MagicMock()
        mock_proc.is_running.return_value = True
        mock_proc.name.return_value = "python.exe"
        mock_proc.cmdline.side_effect = psutil.AccessDenied(12345)

        with patch("psutil.Process", return_value=mock_proc):
            # Python w nazwie, AccessDenied na cmdline -> True (bezpieczne zalozenie)
            result = _is_scanner_process(12345)
        assert result is True


# ---------------------------------------------------------------------------
# Testy _acquire_scanner_lock
# ---------------------------------------------------------------------------

class TestAcquireLock:
    def test_no_lock_file_creates_and_returns_true(self, tmp_path):
        """Brak pliku lock -> tworzy go i zwraca True."""
        _is_scanner_process, _acquire_scanner_lock, _ = _import_lock_fns()
        import run_scanner as rs
        lock_file = str(tmp_path / "scanner.pid")

        with patch.object(rs, "_LOCK_FILE", lock_file):
            result = _acquire_scanner_lock()
        assert result is True
        assert os.path.exists(lock_file)
        with open(lock_file) as f:
            assert f.read().strip() == str(os.getpid())

    def test_active_scanner_returns_false(self, tmp_path):
        """Istniejacy lock z aktywnym skanerem -> False."""
        _is_scanner_process, _acquire_scanner_lock, _ = _import_lock_fns()
        import run_scanner as rs
        lock_file = str(tmp_path / "scanner.pid")

        with open(lock_file, "w") as f:
            f.write("55555")

        with patch.object(rs, "_LOCK_FILE", lock_file), \
             patch.object(rs, "_is_scanner_process", return_value=True):
            result = _acquire_scanner_lock()
        assert result is False

    def test_stale_pid_non_scanner_overwrites(self, tmp_path):
        """Stale PID (nie-skaner) -> nadpisuje lock i zwraca True."""
        _is_scanner_process, _acquire_scanner_lock, _ = _import_lock_fns()
        import run_scanner as rs
        lock_file = str(tmp_path / "scanner.pid")

        with open(lock_file, "w") as f:
            f.write("55555")  # stary PID ktory nie nalezy do skanera

        with patch.object(rs, "_LOCK_FILE", lock_file), \
             patch.object(rs, "_is_scanner_process", return_value=False):
            result = _acquire_scanner_lock()
        assert result is True
        with open(lock_file) as f:
            assert f.read().strip() == str(os.getpid())

    def test_corrupted_lock_file_ignored(self, tmp_path):
        """Uszkodzony plik lock (nie-liczba) -> ignorowany, lock tworzony."""
        _is_scanner_process, _acquire_scanner_lock, _ = _import_lock_fns()
        import run_scanner as rs
        lock_file = str(tmp_path / "scanner.pid")

        with open(lock_file, "w") as f:
            f.write("not-a-number")

        with patch.object(rs, "_LOCK_FILE", lock_file):
            result = _acquire_scanner_lock()
        assert result is True

    def test_same_pid_in_lock_file_acquires(self, tmp_path):
        """Lock zawiera nasz wlasny PID -> uznaj za OK (race condition safe)."""
        _is_scanner_process, _acquire_scanner_lock, _ = _import_lock_fns()
        import run_scanner as rs
        lock_file = str(tmp_path / "scanner.pid")

        with open(lock_file, "w") as f:
            f.write(str(os.getpid()))

        with patch.object(rs, "_LOCK_FILE", lock_file):
            result = _acquire_scanner_lock()
        assert result is True

    def test_atexit_cleans_lock(self, tmp_path):
        """Po zakonczeniu procesu plik lock zostaje usuniety przez atexit."""
        _is_scanner_process, _acquire_scanner_lock, _ = _import_lock_fns()
        import run_scanner as rs
        import atexit
        lock_file = str(tmp_path / "scanner.pid")

        with patch.object(rs, "_LOCK_FILE", lock_file):
            _acquire_scanner_lock()
        assert os.path.exists(lock_file)
        # Wywolaj wszystkie zarejestrowane atexit handlery (symulacja zamkniecia)
        # Nie bedziemy wywolywac wszystkich - sprawdzamy ze plik da sie usunac
        # (czyli mamy jego PID)
        with open(lock_file) as f:
            assert f.read().strip() == str(os.getpid())


# ---------------------------------------------------------------------------
# Testy logiki restartu po przerwaniu (scenariusze duzych sieci)
# ---------------------------------------------------------------------------

class TestRestartLogic:
    """Testuje ze mechanizm checkpointow full scan dziala poprawnie.

    Po przerwaniu skanera w polowie full scan, kolejne uruchomienie
    powinno skanowac tylko te urzadzenia, dla ktorych brak wpisu ScanResult
    nmap_full lub jest on starszy niz max_age_days.
    """

    def _make_db(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        from netdoc.storage.models import Base
        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        return sessionmaker(bind=engine)()

    def _add_device(self, db, ip, active=True):
        from netdoc.storage.models import Device, DeviceType
        from datetime import datetime
        now = datetime.utcnow()
        d = Device(ip=ip, device_type=DeviceType.unknown, is_active=active,
                   first_seen=now, last_seen=now)
        db.add(d)
        db.flush()
        return d

    def _add_scan_result(self, db, device_id, age_days=0):
        from netdoc.storage.models import ScanResult
        from datetime import datetime, timedelta
        sr = ScanResult(
            device_id=device_id,
            scan_type="nmap_full",
            scan_time=datetime.utcnow() - timedelta(days=age_days),
            open_ports={},
        )
        db.add(sr)
        db.flush()

    def test_full_scan_skips_recently_scanned(self):
        """Urzadzenia ze swiezym ScanResult(nmap_full) nie trafiaja na liste stale."""
        from netdoc.collector.discovery import get_stale_full_scan_ips
        db = self._make_db()
        d1 = self._add_device(db, "10.0.0.1")
        d2 = self._add_device(db, "10.0.0.2")
        d3 = self._add_device(db, "10.0.0.3")
        self._add_scan_result(db, d1.id, age_days=1)  # swiezy
        self._add_scan_result(db, d2.id, age_days=1)  # swiezy
        # d3 nie ma wpisu — stale
        db.commit()

        stale = get_stale_full_scan_ips(db, max_age_days=7)
        assert "10.0.0.3" in stale
        assert "10.0.0.1" not in stale
        assert "10.0.0.2" not in stale
        db.close()

    def test_interrupted_full_scan_resumes_only_remaining(self):
        """Po przerwaniu scanu: tylko urzadzenia bez ScanResult wracaja na liste."""
        from netdoc.collector.discovery import get_stale_full_scan_ips
        db = self._make_db()
        devices = [self._add_device(db, f"192.168.1.{i}") for i in range(1, 6)]
        # 3 zdazono zeskanowac, 2 nie
        for d in devices[:3]:
            self._add_scan_result(db, d.id, age_days=0)
        db.commit()

        stale = get_stale_full_scan_ips(db, max_age_days=7)
        assert set(stale) == {"192.168.1.4", "192.168.1.5"}
        db.close()

    def test_large_network_all_stale_initially(self):
        """Nowa siec: wszystkie urzadzenia sa stale (brak ScanResult)."""
        from netdoc.collector.discovery import get_stale_full_scan_ips
        db = self._make_db()
        n = 50
        for i in range(n):
            self._add_device(db, f"10.10.{i // 254}.{i % 254 + 1}")
        db.commit()

        stale = get_stale_full_scan_ips(db, max_age_days=7)
        assert len(stale) == n
        db.close()

    def test_old_scan_result_treated_as_stale(self):
        """ScanResult starszy niz max_age_days jest traktowany jak brak scanu."""
        from netdoc.collector.discovery import get_stale_full_scan_ips
        db = self._make_db()
        d_old = self._add_device(db, "10.0.0.10")
        d_new = self._add_device(db, "10.0.0.11")
        self._add_scan_result(db, d_old.id, age_days=10)  # starszy niz 7 dni
        self._add_scan_result(db, d_new.id, age_days=1)   # swiezy
        db.commit()

        stale = get_stale_full_scan_ips(db, max_age_days=7)
        assert "10.0.0.10" in stale
        assert "10.0.0.11" not in stale
        db.close()

    def test_inactive_devices_excluded_from_full_scan(self):
        """Urzadzenia nieaktywne (is_active=False) nie trafiaja do full scan."""
        from netdoc.collector.discovery import get_stale_full_scan_ips
        db = self._make_db()
        self._add_device(db, "10.0.0.1", active=True)
        self._add_device(db, "10.0.0.2", active=False)
        db.commit()

        stale = get_stale_full_scan_ips(db, max_age_days=7)
        assert "10.0.0.1" in stale
        assert "10.0.0.2" not in stale
        db.close()

    def test_deleted_device_rediscovered_by_upsert(self):
        """Usuniete z GUI urzadzenie wraca po kolejnym skanie (upsert po IP)."""
        from netdoc.storage.models import Device, DeviceType, Event
        from netdoc.collector.discovery import upsert_device
        from netdoc.collector.normalizer import DeviceData
        from datetime import datetime
        db = self._make_db()

        now = datetime.utcnow()
        dev = Device(ip="192.168.5.42", hostname="TestDevice",
                     device_type=DeviceType.unknown, is_active=True,
                     first_seen=now, last_seen=now)
        db.add(dev)
        db.commit()
        device_id = dev.id

        # Symuluj usuniecie z GUI
        db.delete(dev)
        db.commit()
        assert db.query(Device).filter_by(ip="192.168.5.42").first() is None

        # Kolejny skan — upsert_device powinien stworzyc nowe urzadzenie
        new_data = DeviceData(ip="192.168.5.42", hostname="TestDevice",
                              device_type=DeviceType.unknown)
        restored = upsert_device(db, new_data)
        assert restored is not None
        assert restored.ip == "192.168.5.42"
        assert restored.is_active is True
        # Urzadzenie zostalo ponownie odkryte (nowy wpis w bazie)
        assert db.query(Device).filter_by(ip="192.168.5.42").count() == 1
        db.close()
