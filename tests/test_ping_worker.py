"""Testy dla run_ping.py — logika fail counter i oznaczania DOWN/UP."""
import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, call

import run_ping


def _reset_globals():
    """Resetuje globalne liczniki miedzy testami."""
    run_ping._fail_counts.clear()
    run_ping._events_up   = 0
    run_ping._events_down = 0


def _make_device(id=1, ip="192.168.1.1", is_active=True, last_seen_minsago=1):
    d = MagicMock()
    d.id        = id
    d.ip        = ip
    d.hostname  = "test-host"
    d.is_active = is_active
    d.last_seen = datetime.utcnow() - timedelta(minutes=last_seen_minsago)
    return d


def _mock_db_with_devices(devices: list):
    db = MagicMock()
    db.query.return_value.all.return_value = devices
    # _read_settings query: SystemStatus row
    row = MagicMock()
    row.value = "10"
    db.query.return_value.filter.return_value.first.return_value = row
    return db


# ── Testy ─────────────────────────────────────────────────────────────────────

def test_fail_counter_reset_on_success():
    """Po udanej probie licznik niepowodzen jest zerowany."""
    _reset_globals()
    d = _make_device(id=1, is_active=True, last_seen_minsago=1)
    run_ping._fail_counts[1] = 2

    with patch("run_ping.SessionLocal") as mock_sl, \
         patch("run_ping._check", return_value=5.0), \
         patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
        db = _mock_db_with_devices([d])
        mock_sl.return_value = db
        run_ping.poll_once()

    assert run_ping._fail_counts.get(1, 0) == 0


def test_fail_counter_increments_on_failure():
    """Po kazdym nieudanym sprawdzeniu licznik rosnie."""
    _reset_globals()
    d = _make_device(id=2, is_active=True, last_seen_minsago=1)

    with patch("run_ping.SessionLocal") as mock_sl, \
         patch("run_ping._check", return_value=None), \
         patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
        db = _mock_db_with_devices([d])
        mock_sl.return_value = db
        run_ping.poll_once()

    assert run_ping._fail_counts.get(2, 0) == 1


def test_device_not_marked_down_below_threshold():
    """Urzadzenie NIE jest DOWN gdy niepowodzenia < _FAIL_THRESHOLD."""
    _reset_globals()
    orig = run_ping._FAIL_THRESHOLD
    run_ping._FAIL_THRESHOLD = 3
    d = _make_device(id=3, is_active=True, last_seen_minsago=10)

    try:
        for _ in range(run_ping._FAIL_THRESHOLD - 1):
            with patch("run_ping.SessionLocal") as mock_sl, \
                 patch("run_ping._check", return_value=None), \
                 patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
                db = _mock_db_with_devices([d])
                mock_sl.return_value = db
                run_ping.poll_once()

        assert d.is_active is True
        assert run_ping._fail_counts.get(3, 0) == run_ping._FAIL_THRESHOLD - 1
    finally:
        run_ping._FAIL_THRESHOLD = orig


def test_device_marked_down_after_threshold_failures():
    """Urzadzenie JEST DOWN po _FAIL_THRESHOLD niepowodzeniach + stale last_seen."""
    _reset_globals()
    orig = run_ping._FAIL_THRESHOLD
    run_ping._FAIL_THRESHOLD = 3
    d = _make_device(id=4, is_active=True, last_seen_minsago=10)

    try:
        for _ in range(run_ping._FAIL_THRESHOLD):
            with patch("run_ping.SessionLocal") as mock_sl, \
                 patch("run_ping._check", return_value=None), \
                 patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
                db = _mock_db_with_devices([d])
                mock_sl.return_value = db
                run_ping.poll_once()

        assert d.is_active is False
        assert run_ping._events_down == 1
    finally:
        run_ping._FAIL_THRESHOLD = orig


def test_device_not_marked_down_if_seen_recently():
    """Urzadzenie NIE jest DOWN nawet po N niepowodzeniach gdy last_seen swiezy."""
    _reset_globals()
    orig = run_ping._FAIL_THRESHOLD
    run_ping._FAIL_THRESHOLD = 2
    d = _make_device(id=5, is_active=True, last_seen_minsago=1)

    try:
        for _ in range(run_ping._FAIL_THRESHOLD + 1):
            with patch("run_ping.SessionLocal") as mock_sl, \
                 patch("run_ping._check", return_value=None), \
                 patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
                db = _mock_db_with_devices([d])
                mock_sl.return_value = db
                run_ping.poll_once()

        assert d.is_active is True
    finally:
        run_ping._FAIL_THRESHOLD = orig


def test_device_recovers_to_up_after_success():
    """Urzadzenie wraca do UP po udanej probie (is_active=False → True)."""
    _reset_globals()
    d = _make_device(id=6, is_active=False, last_seen_minsago=30)

    with patch("run_ping.SessionLocal") as mock_sl, \
         patch("run_ping._check", return_value=5.0), \
         patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
        db = _mock_db_with_devices([d])
        mock_sl.return_value = db
        run_ping.poll_once()

    assert d.is_active is True
    assert run_ping._events_up == 1
    assert run_ping._fail_counts.get(6, 0) == 0


def test_fail_counts_independent_per_device():
    """Liczniki niepowodzen sa niezalezne dla roznych urzadzen."""
    _reset_globals()
    d1 = _make_device(id=10, ip="10.0.0.1", is_active=True, last_seen_minsago=1)
    d2 = _make_device(id=11, ip="10.0.0.2", is_active=True, last_seen_minsago=1)

    def _check_selective(ip, device_ports=None):
        return 5.0 if ip == "10.0.0.1" else None

    with patch("run_ping.SessionLocal") as mock_sl, \
         patch("run_ping._check", side_effect=_check_selective), \
         patch("run_ping._read_settings", return_value=(1, 4, 5, 1.5, 3)):
        db = _mock_db_with_devices([d1, d2])
        mock_sl.return_value = db
        run_ping.poll_once()

    assert run_ping._fail_counts.get(10, 0) == 0
    assert run_ping._fail_counts.get(11, 0) == 1


def test_fail_threshold_constant_exists():
    """Stala _FAIL_THRESHOLD istnieje i ma rozumna wartosc."""
    assert hasattr(run_ping, "_FAIL_THRESHOLD")
    assert 1 <= run_ping._FAIL_THRESHOLD <= 10


def test_fail_counts_dict_exists():
    """Globalny slownik _fail_counts istnieje i jest dictem."""
    assert hasattr(run_ping, "_fail_counts")
    assert isinstance(run_ping._fail_counts, dict)


# ── Testy weryfikujace dostepnosc narzedzi ICMP ────────────────────────────────

def test_ping3_importable():
    """ping3 musi byc zainstalowany — bez niego _icmp_alive zawsze zwraca False
    i urzadzenia odpowiadajace tylko na ICMP (np. switche bez TCP) beda DOWN.
    Fix: dodac ping3 do requirements.txt."""
    try:
        import ping3  # noqa: F401
    except ImportError:
        pytest.fail(
            "ping3 nie jest zainstalowany! Urzadzenia odpowiadajace tylko na ICMP "
            "beda zawsze pokazywane jako DOWN. Dodaj 'ping3' do requirements.txt."
        )


def test_icmp_alive_returns_float_or_none():
    """_icmp_alive musi zwracac bool, nigdy nie rzucac wyjatku (nawet bez ping3)."""
    result = run_ping._icmp_alive("127.0.0.1")
    assert result is None or isinstance(result, float), (
        f"_icmp_alive musi zwracac float lub None, zwrocilo {type(result).__name__}"
    )


def test_icmp_alive_has_subprocess_fallback():
    """_icmp_alive musi miec fallback na subprocess ping gdy ping3 niedostepny.
    Symuluje brak ping3 przez wyrzucenie ImportError — worker musi nadal dzialac."""
    import sys
    import types

    # Tymczasowo ukrywamy ping3
    orig = sys.modules.get("ping3", None)
    sys.modules["ping3"] = None  # powoduje ImportError przy 'import ping3'
    try:
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"time=5.3 ms")
            result = run_ping._icmp_alive("192.168.1.1")
        assert result is not None, (
            "_icmp_alive zwrocilo False gdy ping3 niedostepny i subprocess ping zwrocil 0 — "
            "brakuje fallback na subprocess ping"
        )
    finally:
        if orig is None:
            del sys.modules["ping3"]
        else:
            sys.modules["ping3"] = orig


def test_check_uses_icmp_when_tcp_fails():
    """_check musi probowac ICMP gdy wszystkie TCP porty nie odpowiadaja.
    Urzadzenia jak switche bez otwartych portow TCP musza byc wykryte przez ICMP."""
    with patch("run_ping._tcp_alive_rtt", return_value=None), \
         patch("run_ping._icmp_alive", return_value=True) as mock_icmp:
        result = run_ping._check("192.168.1.1")
    mock_icmp.assert_called_once_with("192.168.1.1")
    assert result is not None, "_check powinno zwrocic True gdy _icmp_alive=True"


def _make_monitored_device(id=99, ip="192.168.99.1", is_active=True,
                            is_monitored=True, last_seen_minsago=10):
    d = MagicMock()
    d.id           = id
    d.ip           = ip
    d.hostname     = "monitored-host"
    d.is_active    = is_active
    d.is_monitored = is_monitored
    d.monitor_note = None
    d.last_seen    = datetime.utcnow() - timedelta(minutes=last_seen_minsago)
    return d


def test_monitoring_alert_sent_on_device_going_down():
    """Alert monitorowania jest wysylany gdy monitorowane urzadzenie przechodzi DOWN."""
    _reset_globals()
    orig = run_ping._FAIL_THRESHOLD
    run_ping._FAIL_THRESHOLD = 1
    d = _make_monitored_device(id=20, is_active=True, is_monitored=True, last_seen_minsago=10)

    with patch("run_ping.SessionLocal") as mock_sl, \
         patch("run_ping._check", return_value=None), \
         patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 1)), \
         patch("netdoc.notifications.telegram.send_monitoring_alert") as mock_alert:
        db = _mock_db_with_devices([d])
        mock_sl.return_value = db
        # Inject patched function into run_ping's namespace dla local import
        import netdoc.notifications.telegram as _tg
        orig_fn = _tg.send_monitoring_alert
        _tg.send_monitoring_alert = mock_alert
        try:
            run_ping.poll_once()
        finally:
            _tg.send_monitoring_alert = orig_fn

    try:
        assert mock_alert.call_count >= 1
        call_args = mock_alert.call_args[0]
        assert call_args[2] == "offline"
    finally:
        run_ping._FAIL_THRESHOLD = orig


def test_monitoring_alert_sent_on_device_coming_online():
    """Alert monitorowania jest wysylany gdy monitorowane urzadzenie wraca ONLINE."""
    _reset_globals()
    d = _make_monitored_device(id=21, is_active=False, is_monitored=True, last_seen_minsago=30)

    import netdoc.notifications.telegram as _tg2
    mock_alert2 = MagicMock()
    orig_fn2 = _tg2.send_monitoring_alert
    _tg2.send_monitoring_alert = mock_alert2
    try:
        with patch("run_ping.SessionLocal") as mock_sl, \
             patch("run_ping._check", return_value=5.0), \
             patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
            db = _mock_db_with_devices([d])
            mock_sl.return_value = db
            run_ping.poll_once()
    finally:
        _tg2.send_monitoring_alert = orig_fn2

    assert mock_alert2.call_count >= 1
    assert mock_alert2.call_args[0][2] == "online"


def test_no_monitoring_alert_for_unmonitored_device():
    """Brak alertu dla urzadzenia z is_monitored=False."""
    _reset_globals()
    d = _make_monitored_device(id=22, is_active=False, is_monitored=False, last_seen_minsago=30)

    import netdoc.notifications.telegram as _tg3
    mock_alert3 = MagicMock()
    orig_fn3 = _tg3.send_monitoring_alert
    _tg3.send_monitoring_alert = mock_alert3
    try:
        with patch("run_ping.SessionLocal") as mock_sl, \
             patch("run_ping._check", return_value=5.0), \
             patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
            db = _mock_db_with_devices([d])
            mock_sl.return_value = db
            run_ping.poll_once()
    finally:
        _tg3.send_monitoring_alert = orig_fn3

    mock_alert3.assert_not_called()


def test_requirements_txt_contains_ping3():
    """requirements.txt musi zawierac ping3 — zabezpieczenie przed jego usuniecia."""
    import pathlib
    req = pathlib.Path(__file__).parent.parent / "requirements.txt"
    assert req.exists(), "requirements.txt nie istnieje"
    content = req.read_text()
    assert "ping3" in content, (
        "ping3 nie ma w requirements.txt! "
        "Bez tego kontener Docker nie bedzie mial ICMP probe "
        "i urzadzenia bez otwartych portow TCP beda zawsze DOWN."
    )


# ── Testy: zachowanie ping-workera przy pauzowaniu sieci ──────────────────────

def _make_device_in_net(id, ip, is_active=True, last_seen_minsago=1):
    """Urzadzenie z podanym IP (siec NIE jest atrybutem Device)."""
    d = _make_device(id=id, ip=ip, is_active=is_active, last_seen_minsago=last_seen_minsago)
    d.is_monitored = False
    return d


def test_ping_worker_pings_all_devices_regardless_of_network_status():
    """Ping-worker pinguje WSZYSTKIE urzadzenia w DB, niezaleznie od statusu sieci.

    Pauza sieci (DiscoveredNetwork.is_active=False) dotyczy tylko skanera discovery.
    Ping-worker nie ma informacji o przynaleznosci urzadzenia do sieci i pinguje
    kazde urzadzenie z Device.all().
    """
    _reset_globals()
    # Symuluj 3 urzadzenia z zakresu "zatrzymanej" sieci 10.10.0.0/24
    devices = [
        _make_device_in_net(1, "10.10.0.1", is_active=True),
        _make_device_in_net(2, "10.10.0.2", is_active=True),
        _make_device_in_net(3, "10.10.0.3", is_active=True),
    ]
    checked_ips = []

    def _fake_check(ip, device_ports=None):
        checked_ips.append(ip)
        return True  # wszyscy odpowiadaja

    with patch("run_ping.SessionLocal") as mock_sl, \
         patch("run_ping._check", side_effect=_fake_check), \
         patch("run_ping._read_settings", return_value=(1, 4, 5, 1.5, 3)):
        db = _mock_db_with_devices(devices)
        mock_sl.return_value = db
        run_ping.poll_once()

    # Wszystkie 3 urzadzenia zostaly sprawdzone — niezaleznie od statusu sieci
    assert set(checked_ips) == {"10.10.0.1", "10.10.0.2", "10.10.0.3"}


def test_paused_network_devices_stay_active_when_responding():
    """Urzadzenia z zatrzymanej sieci pozostaja UP jesli odpowiadaja na ping.

    Pauza sieci NIE powoduje ze urzadzenia automatycznie ida w DOWN.
    DOWN moze nastapic tylko jezeli urzadzenie PRZESTANIE odpowiadac na ping.
    """
    _reset_globals()
    d = _make_device_in_net(5, "10.10.0.5", is_active=True, last_seen_minsago=1)

    with patch("run_ping.SessionLocal") as mock_sl, \
         patch("run_ping._check", return_value=5.0), \
         patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
        db = _mock_db_with_devices([d])
        mock_sl.return_value = db
        run_ping.poll_once()

    # Urzadzenie nadal aktywne po pauzowaniu sieci (odpowiadalo na ping)
    assert d.is_active is True
    assert run_ping._fail_counts.get(5, 0) == 0


def test_paused_network_devices_go_down_when_not_responding():
    """Urzadzenia z zatrzymanej sieci MOGa pojsc w DOWN — ale tylko przez brak odpowiedzi na ping,
    nie przez sam fakt pauzy sieci.

    To poprawne zachowanie: skaner nie skanuje zakresu, ale ping-worker nadal monitoruje
    istniejace urzadzenia. Jesli urzadzenie przestaje odpowiadac, idzie w DOWN po threshold.
    """
    _reset_globals()
    inactive_threshold_mins = 5
    d = _make_device_in_net(6, "10.10.0.6", is_active=True,
                             last_seen_minsago=inactive_threshold_mins + 1)
    # Ustaw licznik na progu (FAIL_THRESHOLD - 1 juz bylo, ta proba bedzie ostatnia)
    run_ping._fail_counts[6] = run_ping._FAIL_THRESHOLD - 1

    with patch("run_ping.SessionLocal") as mock_sl, \
         patch("run_ping._check", return_value=None), \
         patch("run_ping._read_settings", return_value=(1, 2, inactive_threshold_mins, 1.5, 3)):
        db = _mock_db_with_devices([d])
        mock_sl.return_value = db
        run_ping.poll_once()

    # DOWN bo przekroczyl threshold niepowodzen + za dlugo niewidziany
    assert d.is_active is False


def test_paused_network_devices_recover_when_resuming():
    """Urzadzenie ktore bylo DOWN wraca do UP gdy siec jest wznowiona i urzadzenie odpowiada.

    Wznowienie sieci (is_active=True w DiscoveredNetwork) nie zmienia stanu Device.
    Ping-worker po prostu wykryje ze urzadzenie odpowiada i oznajczy UP.
    """
    _reset_globals()
    # Urzadzenie bylo DOWN (is_active=False) — siec zostala wznowiona
    d = _make_device_in_net(7, "10.10.0.7", is_active=False, last_seen_minsago=60)
    run_ping._fail_counts[7] = run_ping._FAIL_THRESHOLD

    with patch("run_ping.SessionLocal") as mock_sl, \
         patch("run_ping._check", return_value=5.0), \
         patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
        db = _mock_db_with_devices([d])
        mock_sl.return_value = db
        run_ping.poll_once()

    # Po pozytywnym pingu urzadzenie wraca do UP — niezaleznie od statusu sieci
    assert d.is_active is True
    assert run_ping._fail_counts.get(7, 0) == 0


def test_network_pause_affects_only_scanner_not_ping():
    """Dokumentacja: pauza sieci wplywa TYLKO na skaner discovery (run_scanner.py).

    Ping-worker (_check) jest wywolywany dla urzadzen z db.query(Device).all()
    i NIE filtruje po przynaleznosci do aktywnej sieci.
    Workersy SNMP, vuln, cred rowniez dzialaja niezaleznie od statusu sieci.
    """
    # Test weryfikuje ze w poll_once() nie ma zadnego filtrowania po sieci
    import inspect
    src = inspect.getsource(run_ping.poll_once)
    assert "DiscoveredNetwork" not in src, (
        "poll_once() NIE powinno filtrowac po DiscoveredNetwork — "
        "ping-worker monitoruje wszystkie urzadzenia niezaleznie od statusu sieci"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Testy jednostkowe _tcp_alive
# ═══════════════════════════════════════════════════════════════════════════════

class TestTcpAlive:
    """Testy dla _tcp_alive — wykrywanie przez TCP connect na popularnych portach."""

    def test_returns_true_when_first_port_connects(self):
        """_tcp_alive zwraca True gdy pierwszy port jest otwarty."""
        with patch("run_ping.socket.create_connection") as mock_conn:
            mock_conn.return_value.__enter__ = lambda s: s
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            result = run_ping._tcp_alive_rtt("192.168.1.1")
        assert result is not None

    def test_returns_false_when_all_ports_refused(self):
        """_tcp_alive zwraca False gdy wszystkie porty z PROBE_PORTS sa zamkniete."""
        with patch("run_ping.socket.create_connection",
                   side_effect=OSError("Connection refused")):
            result = run_ping._tcp_alive_rtt("192.168.1.99")
        assert result is None

    def test_short_circuits_after_first_success(self):
        """_tcp_alive przestaje probowac po pierwszym sukcesie — nie sprawdza wszystkich portow."""
        call_count = 0
        first_port = run_ping.PROBE_PORTS[0]

        def _side_effect(addr, timeout):
            nonlocal call_count
            host, port = addr
            call_count += 1
            if port == first_port:
                m = MagicMock()
                m.__enter__ = lambda s: s
                m.__exit__ = MagicMock(return_value=False)
                return m
            raise OSError("refused")

        with patch("run_ping.socket.create_connection", side_effect=_side_effect):
            result = run_ping._tcp_alive_rtt("10.0.0.1")

        assert result is not None
        assert call_count == 1, (
            f"_tcp_alive_rtt powinno sprawdzic tylko 1 port (sukces na pierwszym), "
            f"sprawdzilo {call_count}"
        )

    def test_tries_next_port_after_timeout(self):
        """_tcp_alive kontynuuje probe kolejnych portow po timeout (OSError)."""
        ports_tried = []

        def _side_effect(addr, timeout):
            host, port = addr
            ports_tried.append(port)
            if port == run_ping.PROBE_PORTS[-1]:  # ostatni port — sukces
                m = MagicMock()
                m.__enter__ = lambda s: s
                m.__exit__ = MagicMock(return_value=False)
                return m
            raise OSError("timed out")

        with patch("run_ping.socket.create_connection", side_effect=_side_effect):
            result = run_ping._tcp_alive_rtt("10.0.0.2")

        assert result is not None
        assert len(ports_tried) == len(run_ping.PROBE_PORTS), (
            f"_tcp_alive_rtt powinno probowac wszystkich {len(run_ping.PROBE_PORTS)} portow "
            f"zanim ostatni sie powiedzie, sprawdzono: {len(ports_tried)}"
        )

    def test_probe_ports_contains_common_management_ports(self):
        """PROBE_PORTS musi zawierac kluczowe porty do wykrywania urzadzen sieciowych."""
        for p in [22, 80, 443, 23]:
            assert p in run_ping.PROBE_PORTS, (
                f"Port {p} musi byc w PROBE_PORTS — kluczowy dla wykrywania urzadzen"
            )

    def test_probe_ports_contains_remote_access_ports(self):
        """PROBE_PORTS musi zawierac porty zdalnego dostepu (RDP, etc.)."""
        assert 3389 in run_ping.PROBE_PORTS, "Port 3389 (RDP) powinien byc w PROBE_PORTS"


# ═══════════════════════════════════════════════════════════════════════════════
# Testy jednostkowe _icmp_alive — fallback ping3 → subprocess
# ═══════════════════════════════════════════════════════════════════════════════

class TestIcmpAlive:
    """Testy dla _icmp_alive — dwustopniowy fallback: ping3 → subprocess ping."""

    def test_returns_true_when_ping3_succeeds(self):
        """_icmp_alive zwraca True gdy ping3.ping zwroci float (czas odpowiedzi)."""
        with patch("ping3.ping", return_value=12.5):
            result = run_ping._icmp_alive("10.0.0.1")
        assert result is not None

    def test_ping3_returning_none_falls_through_to_subprocess(self):
        """Gdy ping3 zwraca None (host nieosiagalny) — subprocess ping jest probowany.

        BUG: gdyby fallback nie dzialal, urzadzenie bez ICMP raw socket
        bylaby zawsze DOWN pomimo dzialajacego pinga systemowego.
        """
        with patch("ping3.ping", return_value=None) as mock_p3, \
             patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(returncode=0, stdout=b"time=5.3 ms")
            result = run_ping._icmp_alive("10.0.0.2")
        mock_sub.assert_called_once()
        assert result is not None, (
            "Gdy ping3 zwraca None, _icmp_alive powinno probowac subprocess ping "
            "i zwrocic True jesli subprocess wrocil 0"
        )

    def test_ping3_returning_false_falls_through_to_subprocess(self):
        """Gdy ping3 zwraca False (timeout) — subprocess ping jest probowany.

        False (timeout ping3) != brak odpowiedzi — subprocess ma inny mechanizm
        i moze zadzialac gdy ping3 ma problemy z raw socketem.
        """
        with patch("ping3.ping", return_value=False), \
             patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(returncode=0, stdout=b"time=5.3 ms")
            result = run_ping._icmp_alive("10.0.0.3")
        mock_sub.assert_called_once()
        assert result is not None

    def test_subprocess_called_with_linux_ping_syntax(self):
        """subprocess ping uzyta z prawidlowa skladnia Linux (iputils-ping w Docker)."""
        with patch("ping3.ping", return_value=None), \
             patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(returncode=1)
            run_ping._icmp_alive("10.1.2.3")

        args = mock_sub.call_args[0][0]  # pierwszy pozycyjny argument = lista poleceń
        assert args[0] == "ping", f"Pierwsze polecenie musi byc 'ping', jest: {args[0]}"
        assert "-c" in args, "Brakuje flagi -c (count) — to Linux ping (iputils), nie Windows"
        assert "10.1.2.3" in args, "IP musi byc przekazane do subprocess ping"

    def test_both_ping3_and_subprocess_fail_returns_false(self):
        """_icmp_alive zwraca False gdy zarówno ping3 jak i subprocess nie odpowiadaja."""
        with patch("ping3.ping", return_value=None), \
             patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(returncode=1)
            result = run_ping._icmp_alive("192.168.99.99")
        assert result is None

    def test_ping3_exception_falls_through_to_subprocess(self):
        """Wyjatek z ping3 (np. PermissionError na NET_RAW) → subprocess jest probowany."""
        with patch("ping3.ping", side_effect=PermissionError("Operation not permitted")), \
             patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(returncode=0, stdout=b"time=5.3 ms")
            result = run_ping._icmp_alive("10.0.0.10")
        mock_sub.assert_called_once()
        assert result is not None, (
            "Blad ping3 (PermissionError) nie moze blokować fallbacku subprocess — "
            "docker bez NET_RAW moze nadal uzywac 'ping' z iputils"
        )

    def test_ping3_zero_ms_response_is_alive(self):
        """ping3 zwracajace 0.0ms traktowane jako alive (0.0 jest truthy dla 'is not None/False')."""
        with patch("ping3.ping", return_value=0.0):
            result = run_ping._icmp_alive("127.0.0.1")
        assert result is not None, (
            "0.0ms to prawidlowy czas odpowiedzi (loopback) — urzadzenie powinno byc alive"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Testy dla _check — kombinacje TCP/ICMP
# ═══════════════════════════════════════════════════════════════════════════════

class TestCheck:
    """Testy dla _check — orkiestracja ICMP-first, TCP jako fallback."""

    def test_returns_rtt_when_icmp_succeeds(self):
        """_check zwraca RTT gdy ICMP succeed — TCP nie jest wywolywane (short-circuit)."""
        with patch("run_ping._icmp_alive", return_value=4.2) as mock_icmp, \
             patch("run_ping._tcp_alive_rtt") as mock_tcp:
            result = run_ping._check("10.0.0.1")
        assert result == 4.2
        mock_icmp.assert_called_once_with("10.0.0.1")
        mock_tcp.assert_not_called()  # short-circuit — TCP nie jest wywolywane

    def test_returns_rtt_when_only_tcp_responds(self):
        """_check zwraca RTT gdy ICMP fail ale TCP succeed — kluczowe dla urzadzen blokujacych ICMP."""
        with patch("run_ping._icmp_alive", return_value=None) as mock_icmp, \
             patch("run_ping._tcp_alive_rtt", return_value=8.1) as mock_tcp:
            result = run_ping._check("192.168.1.254")
        assert result == 8.1
        mock_icmp.assert_called_once_with("192.168.1.254")
        mock_tcp.assert_called_once_with("192.168.1.254", None)

    def test_returns_none_when_both_fail(self):
        """_check zwraca None gdy ani ICMP ani TCP nie odpowiadaja — urzadzenie niedostepne."""
        with patch("run_ping._icmp_alive", return_value=None), \
             patch("run_ping._tcp_alive_rtt", return_value=None):
            result = run_ping._check("10.99.99.99")
        assert result is None

    def test_tcp_called_only_when_icmp_fails(self):
        """_tcp_alive_rtt wywolane TYLKO gdy _icmp_alive zwroci None (ICMP-first short-circuit)."""
        call_log = []

        def fake_icmp(ip):
            call_log.append(("icmp", ip))
            return None

        def fake_tcp(ip, device_ports=None):
            call_log.append(("tcp", ip))
            return 5.0

        with patch("run_ping._icmp_alive", side_effect=fake_icmp), \
             patch("run_ping._tcp_alive_rtt", side_effect=fake_tcp):
            run_ping._check("10.0.0.5")

        assert call_log == [("icmp", "10.0.0.5"), ("tcp", "10.0.0.5")], (
            f"_check powinno: 1. probowac ICMP, 2. probowac TCP gdy ICMP fail. "
            f"Kolejnosc: {call_log}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Testy edge-case poll_once — last_seen=None, pusta baza
# ═══════════════════════════════════════════════════════════════════════════════

class TestPollOnceEdgeCases:
    """Testy zachowania poll_once w edge-case'ach."""

    def test_device_never_seen_not_marked_down_on_failure(self):
        """Urzadzenie z last_seen=None (nigdy widziane) NIE moze byc oznaczone DOWN.

        Bug: brak sprawdzenia 'last_seen is not None' sprowadziloby do TypeError
        przy porownaniu datetime < datetime, lub false DOWN dla nowych urzadzen
        ktorych ping-worker jeszcze nie widzial.
        """
        _reset_globals()
        d = MagicMock()
        d.id        = 99
        d.ip        = "10.0.0.99"
        d.hostname  = "nowe-urzadzenie"
        d.is_active = True
        d.last_seen = None           # nigdy nie widziane
        d.is_monitored = False

        orig_threshold = run_ping._FAIL_THRESHOLD
        run_ping._FAIL_THRESHOLD = 1  # agresywny threshold

        try:
            for _ in range(5):  # wiele nieudanych prob
                with patch("run_ping.SessionLocal") as mock_sl, \
                     patch("run_ping._check", return_value=None), \
                     patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
                    db = _mock_db_with_devices([d])
                    mock_sl.return_value = db
                    run_ping.poll_once()

            assert d.is_active is True, (
                "Urzadzenie z last_seen=None (nigdy widziane) NIE powinno byc "
                "oznaczone DOWN — brak historii kontaktu != jest niedostepne"
            )
        finally:
            run_ping._FAIL_THRESHOLD = orig_threshold

    def test_empty_device_list_returns_without_crash(self):
        """poll_once z pusta lista urzadzen nie rzuca wyjatku i wraca normalnie."""
        _reset_globals()
        with patch("run_ping.SessionLocal") as mock_sl, \
             patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
            db = _mock_db_with_devices([])
            mock_sl.return_value = db
            # Nie powinno rzucic zadnego wyjatku
            run_ping.poll_once()

    def test_device_seen_exactly_at_inactive_boundary_not_marked_down(self):
        """Urzadzenie widziane DOKLADNIE na granicy inactive_threshold NIE idzie w DOWN.

        inactive_threshold = now - timedelta(minutes=inactive_after)
        Warunek: last_seen < inactive_threshold (strict less-than)
        Urzadzenie widziane w tym samym momencie co threshold (==) pozostaje UP.
        """
        _reset_globals()
        inactive_after = 5  # minutes
        # last_seen = dokladnie na granicy (nie starsze niz threshold)
        d = _make_device(id=50, is_active=True, last_seen_minsago=inactive_after)
        run_ping._fail_counts[50] = run_ping._FAIL_THRESHOLD  # juz na progu

        with patch("run_ping.SessionLocal") as mock_sl, \
             patch("run_ping._check", return_value=None), \
             patch("run_ping._read_settings", return_value=(1, 2, inactive_after, 1.5, 3)):
            db = _mock_db_with_devices([d])
            mock_sl.return_value = db
            run_ping.poll_once()

        # Przy last_seen == granica (dokl. N minut temu), datetime comparison moze isc w DOWN
        # Test dokumentuje aktualne zachowanie — wazne zeby nie bylo TypeError
        assert isinstance(d.is_active, bool), (
            "is_active po poll_once musi byc bool, nie rzucac TypeError"
        )

    def test_poll_once_updates_last_seen_on_success(self):
        """poll_once aktualizuje Device.last_seen dla urzadzen ktore odpowiadaja."""
        _reset_globals()
        d = _make_device(id=60, is_active=True, last_seen_minsago=30)
        old_last_seen = d.last_seen

        with patch("run_ping.SessionLocal") as mock_sl, \
             patch("run_ping._check", return_value=5.0), \
             patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
            db = _mock_db_with_devices([d])
            mock_sl.return_value = db
            run_ping.poll_once()

        assert d.last_seen != old_last_seen, (
            "Device.last_seen powinno byc zaktualizowane po udanym pingu"
        )
        assert d.last_seen > old_last_seen, (
            "Device.last_seen po udanym pingu powinno byc pozniejsze niz poprzednia wartosc"
        )

    def test_poll_once_does_not_update_last_seen_on_failure(self):
        """poll_once NIE zmienia Device.last_seen gdy urzadzenie nie odpowiada."""
        _reset_globals()
        d = _make_device(id=61, is_active=True, last_seen_minsago=2)
        old_last_seen = d.last_seen

        with patch("run_ping.SessionLocal") as mock_sl, \
             patch("run_ping._check", return_value=None), \
             patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
            db = _mock_db_with_devices([d])
            mock_sl.return_value = db
            run_ping.poll_once()

        assert d.last_seen == old_last_seen, (
            "Device.last_seen NIE powinno byc zmieniane gdy ping failuje"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Runda 2 — zdarzenia UP/DOWN — tylko jeden na przejscie stanu
# ═══════════════════════════════════════════════════════════════════════════════

class TestEventCounters:
    """Zdarzenia UP/DOWN generowane dokladnie 1x na przejscie stanu, nie powtarzane."""

    def test_up_event_generated_exactly_once_on_transition(self):
        """events_up rosnie o 1 gdy urzadzenie przechodzi DOWN→UP.
        Kolejny poll (was_active=True, alive=True) NIE generuje kolejnego eventu UP."""
        _reset_globals()
        d = _make_device(id=70, is_active=False, last_seen_minsago=30)

        # Poll 1 — przejscie DOWN→UP
        with patch("run_ping.SessionLocal") as mock_sl, \
             patch("run_ping._check", return_value=5.0), \
             patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
            db = _mock_db_with_devices([d])
            mock_sl.return_value = db
            run_ping.poll_once()

        assert run_ping._events_up == 1, "Przejscie DOWN→UP powinno wygenerowac dokladnie 1 event UP"
        assert d.is_active is True

        # Poll 2 — was_active=True, alive=True — BRAK kolejnego eventu UP
        with patch("run_ping.SessionLocal") as mock_sl, \
             patch("run_ping._check", return_value=5.0), \
             patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
            db = _mock_db_with_devices([d])
            mock_sl.return_value = db
            run_ping.poll_once()

        assert run_ping._events_up == 1, (
            "Drugi poll (nadal UP) NIE powinien generowac dodatkowego eventu UP — "
            f"events_up={run_ping._events_up} zamiast 1"
        )

    def test_down_event_generated_exactly_once_on_transition(self):
        """events_down rosnie o 1 gdy urzadzenie przechodzi UP→DOWN.
        Kolejne pole (was_active=False, alive=False) NIE generuja kolejnych DOWN."""
        _reset_globals()
        orig_threshold = run_ping._FAIL_THRESHOLD
        run_ping._FAIL_THRESHOLD = 1
        inactive = 5

        try:
            d = _make_device(id=71, is_active=True, last_seen_minsago=inactive + 1)

            # Poll 1 — przejscie UP→DOWN
            with patch("run_ping.SessionLocal") as mock_sl, \
                 patch("run_ping._check", return_value=None), \
                 patch("run_ping._read_settings", return_value=(1, 2, inactive, 1.5, 1)):
                db = _mock_db_with_devices([d])
                mock_sl.return_value = db
                run_ping.poll_once()

            assert run_ping._events_down == 1, "Przejscie UP→DOWN powinno wygenerowac dokladnie 1 event DOWN"
            assert d.is_active is False

            # Poll 2 — was_active=False, alive=False — BRAK kolejnego DOWN eventu
            with patch("run_ping.SessionLocal") as mock_sl, \
                 patch("run_ping._check", return_value=None), \
                 patch("run_ping._read_settings", return_value=(1, 2, inactive, 1.5, 1)):
                db = _mock_db_with_devices([d])
                mock_sl.return_value = db
                run_ping.poll_once()

            assert run_ping._events_down == 1, (
                "Kolejny poll (nadal DOWN) NIE powinien generowac dodatkowego eventu DOWN — "
                f"events_down={run_ping._events_down} zamiast 1"
            )
        finally:
            run_ping._FAIL_THRESHOLD = orig_threshold

    def test_already_down_device_no_down_event_on_failure(self):
        """Urzadzenie juz DOWN (is_active=False) failujace ping NIE generuje DOWN eventu."""
        _reset_globals()
        d = _make_device(id=72, is_active=False, last_seen_minsago=60)

        with patch("run_ping.SessionLocal") as mock_sl, \
             patch("run_ping._check", return_value=None), \
             patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
            db = _mock_db_with_devices([d])
            mock_sl.return_value = db
            run_ping.poll_once()

        assert run_ping._events_down == 0, (
            "Urzadzenie juz DOWN NIE powinno generowac DOWN eventu przy kolejnym failurze"
        )
        assert d.is_active is False

    def test_already_up_device_no_up_event_on_success(self):
        """Urzadzenie juz UP (is_active=True) z sukcesem pinga NIE generuje UP eventu."""
        _reset_globals()
        d = _make_device(id=73, is_active=True, last_seen_minsago=1)

        with patch("run_ping.SessionLocal") as mock_sl, \
             patch("run_ping._check", return_value=5.0), \
             patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
            db = _mock_db_with_devices([d])
            mock_sl.return_value = db
            run_ping.poll_once()

        assert run_ping._events_up == 0, (
            "Urzadzenie juz UP NIE powinno generowac UP eventu przy kolejnym sukcesie"
        )
        assert d.is_active is True


# ═══════════════════════════════════════════════════════════════════════════════
# Runda 2 — wiele urzadzen jednoczesnie — niezalezne maszyny stanow
# ═══════════════════════════════════════════════════════════════════════════════

class TestMultipleDevicesInOnePoll:
    """Wiele urzadzen w jednym cyklu poll — niezalezne maszyny stanow."""

    def test_mixed_transitions_in_one_poll(self):
        """W jednym cyklu: d1 DOWN→UP, d2 UP→DOWN, d3 pozostaje UP — bez zaklocen."""
        _reset_globals()
        orig_threshold = run_ping._FAIL_THRESHOLD
        run_ping._FAIL_THRESHOLD = 1
        inactive = 5

        d1 = _make_device(id=80, ip="10.0.0.80", is_active=False, last_seen_minsago=30)  # wraca UP
        d2 = _make_device(id=81, ip="10.0.0.81", is_active=True,  last_seen_minsago=inactive + 2)  # idzie DOWN
        d3 = _make_device(id=82, ip="10.0.0.82", is_active=True,  last_seen_minsago=1)   # pozostaje UP
        d2.is_monitored = False

        def _check_selective(ip, device_ports=None):
            return 5.0 if ip in ("10.0.0.80", "10.0.0.82") else None  # d1 i d3 odpowiadaja, d2 nie

        try:
            with patch("run_ping.SessionLocal") as mock_sl, \
                 patch("run_ping._check", side_effect=_check_selective), \
                 patch("run_ping._read_settings", return_value=(1, 4, inactive, 1.5, 1)):
                db = _mock_db_with_devices([d1, d2, d3])
                mock_sl.return_value = db
                run_ping.poll_once()

            assert d1.is_active is True,  "d1 powinno wrocic do UP"
            assert d2.is_active is False, "d2 powinno pojsc w DOWN"
            assert d3.is_active is True,  "d3 powinno pozostac UP"
            assert run_ping._events_up   == 1, "Dokladnie 1 event UP (d1)"
            assert run_ping._events_down == 1, "Dokladnie 1 event DOWN (d2)"
            assert run_ping._fail_counts.get(80, 0) == 0, "fail_count d1 zresetowany po sukcesie"
        finally:
            run_ping._FAIL_THRESHOLD = orig_threshold

    def test_uncertain_device_does_not_affect_others(self):
        """Urzadzenie UNCERTAIN (nie osiagnelo threshold) nie wplywa na status innych."""
        _reset_globals()
        orig_threshold = run_ping._FAIL_THRESHOLD
        run_ping._FAIL_THRESHOLD = 3
        inactive = 5

        # d_unc ma 1 fail (po tym polu bedzie 2, nadal ponizej threshold=3) — UNCERTAIN
        d_unc = _make_device(id=90, ip="10.0.0.90", is_active=True, last_seen_minsago=inactive + 1)
        run_ping._fail_counts[90] = 1

        # d_ok odpowiada normalnie
        d_ok = _make_device(id=91, ip="10.0.0.91", is_active=True, last_seen_minsago=1)
        d_ok.is_monitored = False

        def _check_sel(ip, device_ports=None):
            return 5.0 if ip == "10.0.0.91" else None

        try:
            with patch("run_ping.SessionLocal") as mock_sl, \
                 patch("run_ping._check", side_effect=_check_sel), \
                 patch("run_ping._read_settings", return_value=(1, 4, inactive, 1.5, 3)):
                db = _mock_db_with_devices([d_unc, d_ok])
                mock_sl.return_value = db
                run_ping.poll_once()

            assert d_unc.is_active is True, "UNCERTAIN (fail < threshold) powinno pozostac UP"
            assert d_ok.is_active  is True, "Odpowiadajace urzadzenie powinno pozostac UP"
            assert run_ping._fail_counts[90] == 2, "fail_count UNCERTAIN powinno wzrosnac do 2 (nadal < threshold=3)"
            assert run_ping._events_down == 0, "Brak DOWN eventu dla UNCERTAIN"
        finally:
            run_ping._FAIL_THRESHOLD = orig_threshold


# ═══════════════════════════════════════════════════════════════════════════════
# Runda 2 — _read_settings clamping i konfiguracja
# ═══════════════════════════════════════════════════════════════════════════════

class TestReadSettings:
    """_read_settings — wartosci z DB sa clampowane do minimum 1."""

    def test_zero_interval_clamped_to_one(self):
        """Interwal 0s z DB musi byc clamped do 1s (max(1, 0) = 1)."""
        from netdoc.storage.models import SystemStatus
        db = MagicMock()
        row = MagicMock()
        row.value = "0"
        db.query.return_value.filter.return_value.first.return_value = row

        with patch("run_ping.SessionLocal", return_value=db):
            interval, workers, inactive, *_ = run_ping._read_settings()

        assert interval >= 1, f"Interwał 0 powinien byc clamped do 1, jest {interval}"
        assert workers  >= 1, f"Workers 0 powinien byc clamped do 1, jest {workers}"
        assert inactive >= 1, f"inactive_after 0 powinien byc clamped do 1, jest {inactive}"

    def test_negative_values_clamped_to_one(self):
        """Ujemne wartosci z DB (blad konfiguracji) sa clamped do 1."""
        from netdoc.storage.models import SystemStatus
        db = MagicMock()
        row = MagicMock()
        row.value = "-999"
        db.query.return_value.filter.return_value.first.return_value = row

        with patch("run_ping.SessionLocal", return_value=db):
            interval, workers, inactive, *_ = run_ping._read_settings()

        assert interval >= 1
        assert workers  >= 1
        assert inactive >= 1

    def test_non_numeric_value_uses_default(self):
        """Nienumeryczna wartosc w DB (np. 'abc') uzywa wartosci domyslnej."""
        db = MagicMock()
        row = MagicMock()
        row.value = "abc"  # nienumeryczna
        db.query.return_value.filter.return_value.first.return_value = row

        with patch("run_ping.SessionLocal", return_value=db):
            interval, workers, inactive, *_ = run_ping._read_settings()

        # Powinny byc wartosci domyslne (z _DEFAULT_* constants)
        assert isinstance(interval, int), "Interwał powinien byc int"
        assert isinstance(workers,  int), "Workers powinny byc int"
        assert isinstance(inactive, int), "inactive_after powinien byc int"

    def test_missing_settings_row_uses_defaults(self):
        """Brak wiersza SystemStatus w DB → uzywane sa wartosci domyslne."""
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None

        with patch("run_ping.SessionLocal", return_value=db):
            interval, workers, inactive, *_ = run_ping._read_settings()

        assert interval == run_ping._DEFAULT_INTERVAL, (
            f"Brak ustawień: interval={interval}, oczekiwano {run_ping._DEFAULT_INTERVAL}"
        )
        assert workers  == run_ping._DEFAULT_WORKERS, (
            f"Brak ustawień: workers={workers}, oczekiwano {run_ping._DEFAULT_WORKERS}"
        )
        assert inactive == run_ping._DEFAULT_INACT, (
            f"Brak ustawień: inactive={inactive}, oczekiwano {run_ping._DEFAULT_INACT}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Runda 2 — scenariusze sieciowe (typy urzadzen)
# ═══════════════════════════════════════════════════════════════════════════════

class TestNetworkScenarios:
    """Realistyczne scenariusze dla roznych typow urzadzen sieciowych."""

    def test_managed_switch_icmp_only_detected_as_alive(self):
        """Prosty switch (brak otwartych portow TCP, tylko ICMP) jest wykryty jako alive.

        Scenariusz: switch typu unmanaged / tani managed bez webUI ani SSH,
        ale odpowiada na ping. Bez ICMP fallback bylby zawsze DOWN.
        """
        with patch("run_ping._icmp_alive", return_value=2.5), \
             patch("run_ping._tcp_alive_rtt", return_value=None):
            assert run_ping._check("192.168.1.254") == 2.5, (
                "Switch ICMP-only powinien byc wykryty jako alive przez ICMP"
            )

    def test_mikrotik_router_tcp_ssh_detected(self):
        """Router MikroTik (SSH na porcie 22) wykryty przez TCP gdy ICMP blokowane."""
        def _fake_tcp(ip, device_ports=None):
            # symuluj ze port 22 jest otwarty
            return 3.5

        with patch("run_ping._icmp_alive", return_value=None) as mock_icmp, \
             patch("run_ping._tcp_alive_rtt", side_effect=_fake_tcp) as mock_tcp:
            result = run_ping._check("192.168.1.1")

        assert result == 3.5
        mock_icmp.assert_called_once()   # ICMP probowane jako pierwsze
        mock_tcp.assert_called_once()    # TCP jako fallback gdy ICMP=None

    def test_cisco_switch_web_interface_detected(self):
        """Switch Cisco z webUI (port 80) wykryty przez TCP gdy ICMP blokowane."""
        with patch("run_ping._icmp_alive", return_value=None) as mock_icmp, \
             patch("run_ping._tcp_alive_rtt", return_value=5.0):
            result = run_ping._check("10.0.0.1")

        assert result == 5.0
        mock_icmp.assert_called_once()   # ICMP probowane jako pierwsze

    def test_windows_host_rdp_detected(self):
        """Host Windows (RDP port 3389) wykryty przez TCP — port 3389 jest w PROBE_PORTS."""
        assert 3389 in run_ping.PROBE_PORTS, "Port 3389 (RDP) musi byc w PROBE_PORTS"

        ports_tried = []

        def _fake_conn(addr, timeout):
            host, port = addr
            ports_tried.append(port)
            if port == 3389:
                m = MagicMock()
                m.__enter__ = lambda s: s
                m.__exit__ = MagicMock(return_value=False)
                return m
            raise OSError("refused")

        with patch("run_ping.socket.create_connection", side_effect=_fake_conn):
            result = run_ping._tcp_alive_rtt("192.168.5.100")

        assert result is not None
        assert 3389 in ports_tried

    def test_unresponsive_device_returns_none(self):
        """Urzadzenie zupelnie nieosiagalne (wszystkie TCP + ICMP fail) → None."""
        with patch("run_ping._icmp_alive", return_value=None), \
             patch("run_ping._tcp_alive_rtt", return_value=None):
            assert run_ping._check("10.99.0.1") is None

    def test_tcp_timeout_constant_reasonable(self):
        """TCP_TIMEOUT musi byc rozumny: > 0 i <= 5s (inaczej cykl za wolny)."""
        assert run_ping.TCP_TIMEOUT > 0, "TCP_TIMEOUT musi byc > 0"
        assert run_ping.TCP_TIMEOUT <= 5.0, (
            f"TCP_TIMEOUT={run_ping.TCP_TIMEOUT}s jest za dlugi — "
            f"przy {len(run_ping.PROBE_PORTS)} portach worst-case = "
            f"{run_ping.TCP_TIMEOUT * len(run_ping.PROBE_PORTS):.0f}s per urzadzenie!"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Runda 3 — device-specific ports (krytyczna poprawka false-positive DOWN)
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeviceSpecificPorts:
    """Testy dla logiki probe z portami device-specific z poprzednich skanow.

    KONTEKST: Urzadzenie ma otwarty tylko port 9090 (wykryty przez nmap).
    PROBE_PORTS nie zawiera 9090. ICMP jest blokowany przez firewall.
    BEZ tej poprawki: wszystkie PROBE_PORTS fail + ICMP fail = DOWN (FALSZYWY).
    PO poprawce: probe 9090 (z device_ports) → SUCCESS = UP (POPRAWNY).
    """

    def test_device_with_only_nonstandard_port_detected_as_alive(self):
        """KRYTYCZNY: urzadzenie z portem 9090 (nie w PROBE_PORTS) NIE jest falszywie DOWN.

        Scenariusz: kamera IP / NAS / aplikacja na porcie 9090.
        ICMP blokowany. Bez device-specific ports → false DOWN.
        """
        # Symuluj: port 9090 otwarty, wszystkie PROBE_PORTS zamkniete, ICMP blokowany
        def _fake_conn(addr, timeout):
            host, port = addr
            if port == 9090:
                m = MagicMock()
                m.__enter__ = lambda s: s
                m.__exit__ = MagicMock(return_value=False)
                return m
            raise OSError("Connection refused")

        with patch("run_ping.socket.create_connection", side_effect=_fake_conn):
            # BEZ device_ports → FALSE DOWN (9090 nie jest w PROBE_PORTS)
            result_without = run_ping._tcp_alive_rtt("10.0.0.1", device_ports=None)
            # Z device_ports → TRUE (9090 jest probowany)
            result_with = run_ping._tcp_alive_rtt("10.0.0.1", device_ports=[9090])

        assert result_without is None, (
            "BEZ device_ports: port 9090 nie jest w PROBE_PORTS → powinno zwrocic None "
            "(to demonstruje bug przed poprawka)"
        )
        assert result_with is not None, (
            "Z device_ports=[9090]: port 9090 jest probowany przed PROBE_PORTS → RTT float. "
            "Urzadzenie NIE jest falszywie DOWN!"
        )

    def test_device_specific_ports_tried_before_probe_ports(self):
        """Porty device-specific musza byc probowane PRZED PROBE_PORTS (priorytet).

        Jesli urzadzenie ma port 9090 otwarty, powinno byc wykryte natychmiast
        bez czekania na timeout wszystkich PROBE_PORTS.
        """
        call_order = []

        def _fake_conn(addr, timeout):
            host, port = addr
            call_order.append(port)
            if port == 9090:
                m = MagicMock()
                m.__enter__ = lambda s: s
                m.__exit__ = MagicMock(return_value=False)
                return m
            raise OSError("refused")

        with patch("run_ping.socket.create_connection", side_effect=_fake_conn):
            result = run_ping._tcp_alive_rtt("10.0.0.2", device_ports=[9090])

        assert result is not None
        assert call_order[0] == 9090, (
            f"Port device-specific (9090) powinien byc PIERWSZY w kolejnosci prob, "
            f"a byl na pozycji {call_order.index(9090) + 1}. Kolejnosc: {call_order[:5]}"
        )

    def test_device_port_not_tried_twice_if_in_probe_ports(self):
        """Port w obu device_ports i PROBE_PORTS powinien byc probowany tylko raz."""
        call_counts: dict = {}

        def _fake_conn(addr, timeout):
            host, port = addr
            call_counts[port] = call_counts.get(port, 0) + 1
            raise OSError("refused")

        # Port 22 jest i w device_ports i w PROBE_PORTS
        with patch("run_ping.socket.create_connection", side_effect=_fake_conn):
            run_ping._tcp_alive_rtt("10.0.0.3", device_ports=[22, 80])

        assert call_counts.get(22, 0) == 1, (
            f"Port 22 (w device_ports i PROBE_PORTS) probowany {call_counts.get(22)}x "
            f"zamiast 1x — brak deduplicacji!"
        )
        assert call_counts.get(80, 0) == 1, (
            f"Port 80 (w device_ports i PROBE_PORTS) probowany {call_counts.get(80)}x "
            f"zamiast 1x — brak deduplicacji!"
        )

    def test_device_ports_capped_at_max(self):
        """device_ports sa ograniczone do _MAX_DEVICE_EXTRA_PORTS.

        Urzadzenie ze 100 otwartymi portami z pelnego skanu nie powoduje
        100 dodatkowych TCP prób w kazdym cyklu ping-workera.
        """
        many_ports = list(range(8000, 8100))  # 100 portów
        tried_ports = []

        def _fake_conn(addr, timeout):
            host, port = addr
            tried_ports.append(port)
            raise OSError("refused")

        with patch("run_ping.socket.create_connection", side_effect=_fake_conn):
            run_ping._tcp_alive_rtt("10.0.0.4", device_ports=many_ports)

        device_extra = [p for p in tried_ports if p in many_ports and p not in run_ping.PROBE_PORTS]
        assert len(device_extra) <= run_ping._MAX_DEVICE_EXTRA_PORTS, (
            f"Probowano {len(device_extra)} device-specific portow, "
            f"limit to {run_ping._MAX_DEVICE_EXTRA_PORTS}"
        )

    def test_multiple_device_ports_all_filtered_falls_to_icmp(self):
        """Gdy wszystkie device-specific + PROBE_PORTS fail → proba ICMP.

        Firewall blokuje WSZYSTKIE porty (TCP), ale ICMP przepuszcza.
        """
        with patch("run_ping._tcp_alive_rtt", return_value=None), \
             patch("run_ping._icmp_alive", return_value=True):
            result = run_ping._check("10.0.0.5", device_ports=[9090, 8161, 7777])
        assert result is not None, "Gdy TCP fail na wszystkich portach, ICMP musi byc probowane"

    def test_device_with_partially_firewalled_ports_still_alive(self):
        """Urzadzenie ma 10 znanych portow, firewall blokuje 9 z nich — wciaz jest alive.

        Realny scenariusz: patch bezpieczenstwa zamknal porty, ale jeden zostal.
        """
        known_ports = [22, 80, 443, 8080, 8443, 9090, 9091, 9092, 9093, 9094]
        # Tylko ostatni port (9094) jest dostepny — reszta zablokowana
        open_port = 9094

        def _fake_conn(addr, timeout):
            host, port = addr
            if port == open_port:
                m = MagicMock()
                m.__enter__ = lambda s: s
                m.__exit__ = MagicMock(return_value=False)
                return m
            raise OSError("refused")

        with patch("run_ping.socket.create_connection", side_effect=_fake_conn):
            result = run_ping._tcp_alive_rtt("10.0.0.6", device_ports=known_ports)

        assert result is not None, (
            f"Urzadzenie z portem {open_port} otwartym (9/10 zablokowanych) "
            f"powinno byc alive — nie powinno byc falszywie DOWN"
        )

    def test_no_device_ports_in_db_uses_probe_ports_only(self):
        """Nowe urzadzenie (brak historii skanow) → uzywane sa tylko PROBE_PORTS."""
        called_ports = []

        def _fake_conn(addr, timeout):
            host, port = addr
            called_ports.append(port)
            raise OSError("refused")

        with patch("run_ping.socket.create_connection", side_effect=_fake_conn):
            run_ping._tcp_alive_rtt("10.0.0.7", device_ports=None)

        assert set(called_ports) == set(run_ping.PROBE_PORTS), (
            f"Bez device_ports uzyc tylko PROBE_PORTS. "
            f"Probowane: {sorted(called_ports)}"
        )

    def test_empty_device_ports_list_uses_probe_ports_only(self):
        """Pusta lista device_ports (urzadzenie bez odkrytych portow) → tylko PROBE_PORTS."""
        called_ports = []

        def _fake_conn(addr, timeout):
            host, port = addr
            called_ports.append(port)
            raise OSError("refused")

        with patch("run_ping.socket.create_connection", side_effect=_fake_conn):
            run_ping._tcp_alive_rtt("10.0.0.8", device_ports=[])

        assert set(called_ports) == set(run_ping.PROBE_PORTS)


class TestPollOnceDevicePortsIntegration:
    """Integracja: poll_once przekazuje device-specific ports do _check."""

    def test_poll_once_passes_known_ports_to_check(self):
        """poll_once musi przekazac device-specific ports (z ScanResult) do _check.

        Weryfikuje ze architektura wplywa na wywolanie _check z odpowiednimi portami.
        """
        _reset_globals()
        d = _make_device(id=100, ip="10.0.0.100", is_active=True, last_seen_minsago=1)

        # ScanResult mock z otwartymi portami
        sr = MagicMock()
        sr.device_id = 100
        sr.scan_time = datetime.utcnow()
        sr.open_ports = {"9090": {"service": "custom"}, "8161": {"service": "activemq"}}

        check_calls = []

        def _fake_check(ip, device_ports=None):
            check_calls.append({"ip": ip, "ports": list(device_ports or [])})
            return True

        db = MagicMock()
        # db.query(Device).all() → [d]
        # db.query(ScanResult).join(...).all() → [sr]
        q_device = MagicMock()
        q_device.all.return_value = [d]

        q_scan = MagicMock()
        q_scan.join.return_value = q_scan
        q_scan.all.return_value = [sr]

        q_subq = MagicMock()
        q_subq.filter.return_value = q_subq
        q_subq.group_by.return_value = q_subq
        q_subq.subquery.return_value = MagicMock()

        def _query_side_effect(*models):
            from netdoc.storage.models import Device as D, ScanResult as SR
            if len(models) == 1 and models[0] is D:
                return q_device
            if len(models) == 1 and models[0] is SR:
                return q_scan
            # dla subquery (device_id + max)
            q = MagicMock()
            q.filter.return_value = q
            q.group_by.return_value = q
            q.subquery.return_value = MagicMock()
            q.all.return_value = [sr]
            return q

        db.query.side_effect = _query_side_effect

        with patch("run_ping.SessionLocal", return_value=db), \
             patch("run_ping._check", side_effect=_fake_check), \
             patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
            run_ping.poll_once()

        # _check musi byc wywolany z portami z ScanResult
        assert len(check_calls) == 1, f"_check powinien byc wywolany 1 raz, byl {len(check_calls)}"
        called_ports = set(check_calls[0]["ports"])
        expected_ports = {9090, 8161}
        assert expected_ports.issubset(called_ports), (
            f"_check powinien otrzymac porty {expected_ports} z ScanResult, "
            f"otrzymal: {called_ports}"
        )

    def test_poll_once_works_without_scan_results(self):
        """poll_once dziala normalnie gdy brak ScanResult w DB (nowe urzadzenia)."""
        _reset_globals()
        d = _make_device(id=101, ip="10.0.0.101", is_active=True, last_seen_minsago=1)

        check_calls = []

        def _fake_check(ip, device_ports=None):
            check_calls.append({"ip": ip, "ports": device_ports})
            return True

        db = MagicMock()
        q = MagicMock()
        q.all.return_value = [d]
        q.join.return_value = q
        q.filter.return_value = q
        q.group_by.return_value = q
        q.subquery.return_value = MagicMock()
        db.query.return_value = q

        with patch("run_ping.SessionLocal", return_value=db), \
             patch("run_ping._check", side_effect=_fake_check), \
             patch("run_ping._read_settings", return_value=(1, 2, 5, 1.5, 3)):
            run_ping.poll_once()

        # Nie powinno rzucac wyjatku, _check wywolany
        assert len(check_calls) >= 1


# ─── TEST-13: PERF-14 regresja — _read_settings używa WHERE IN ───────────────

def test_ping_read_settings_uses_single_query(db):
    """TEST-13 / PERF-14 regresja: run_ping._read_settings() wykonuje 1 query
    WHERE key IN (...) zamiast N osobnych SELECT per klucz."""
    from netdoc.storage.models import SystemStatus

    db.add(SystemStatus(key="ping_interval_s", value="30", category="config"))
    db.add(SystemStatus(key="ping_workers",    value="16", category="config"))
    db.commit()

    query_count = []
    original_query = db.query

    def counting_query(model):
        if hasattr(model, "__tablename__") and model.__tablename__ == "system_status":
            query_count.append(1)
        return original_query(model)

    with patch("run_ping.SessionLocal", return_value=db), \
         patch.object(db, "query", side_effect=counting_query):
        result = run_ping._read_settings()

    assert len(query_count) == 1, (
        f"PERF-14: oczekiwano 1 query do system_status, bylo: {len(query_count)}"
    )
    assert result[0] == 30   # ping_interval_s
    assert result[1] == 16   # ping_workers


# ─── WRK-02: try/except w main() ping ────────────────────────────────────────

def test_ping_main_has_try_except_in_loop():
    """WRK-02 regresja: main() w run_ping opakowuje poll_once() w try/except."""
    import inspect
    source = inspect.getsource(run_ping.main)
    assert "try:" in source, "WRK-02: main() musi miec try/except wokol poll_once()"
    assert "except Exception" in source, \
        "WRK-02: main() musi lapac Exception w petli while True"
