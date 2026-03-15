"""Testy dla _ensure_docker_services() z run_scanner.py."""
import subprocess
import socket
from unittest.mock import patch, MagicMock, call

import pytest


# ── Import run_scanner (ustawia env i logging; bezpieczne w testach) ──────────
import run_scanner


# ── Helpery ───────────────────────────────────────────────────────────────────

ALL_CONTAINERS = run_scanner._DOCKER_SERVICES  # pelen zestaw 11 kontenerow


def _make_docker_ps_result(names: list) -> MagicMock:
    """Zwraca mock subprocess.CompletedProcess z podana lista kontenerow."""
    r = MagicMock()
    r.returncode = 0
    r.stdout = "\n".join(names)
    return r


def _make_docker_info_ok() -> MagicMock:
    r = MagicMock()
    r.returncode = 0
    return r


def _sock_ok(*args, **kwargs):
    """Symuluje udane polaczenie TCP — zwraca context manager."""
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=MagicMock())
    cm.__exit__ = MagicMock(return_value=False)
    return cm


def _sock_fail(*args, **kwargs):
    raise OSError("connection refused")


# ── Testy ─────────────────────────────────────────────────────────────────────

def test_docker_not_found_returns_false():
    """Gdy docker nie jest zainstalowany (FileNotFoundError) — zwraca False."""
    with patch("subprocess.run", side_effect=FileNotFoundError("docker not found")):
        with patch("socket.create_connection", side_effect=_sock_fail):
            with patch("time.sleep"):
                result = run_scanner._ensure_docker_services()
    assert result is False


def test_docker_daemon_not_responding_returns_false():
    """Gdy docker info zwraca blad (daemon nie dziala) — zwraca False."""
    info_fail = MagicMock()
    info_fail.returncode = 1

    with patch("subprocess.run", return_value=info_fail):
        with patch("socket.create_connection", side_effect=_sock_fail):
            with patch("time.sleep"):
                result = run_scanner._ensure_docker_services()
    assert result is False


def test_all_containers_running_returns_true():
    """Gdy wszystkie kontenery dzialaja i postgres odpowiada — zwraca True."""
    ps_result = _make_docker_ps_result(ALL_CONTAINERS)

    def _fake_run(cmd, **kwargs):
        if "info" in cmd:
            return _make_docker_info_ok()
        if "ps" in cmd:
            return ps_result
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=_fake_run):
        with patch("socket.create_connection", side_effect=_sock_ok):
            with patch("time.sleep"):
                result = run_scanner._ensure_docker_services()

    assert result is True


def test_all_containers_running_no_compose_up_called():
    """Gdy wszystkie kontenery dzialaja — docker compose up nie jest wywolywany."""
    ps_result = _make_docker_ps_result(ALL_CONTAINERS)
    compose_called = []

    def _fake_run(cmd, **kwargs):
        if "info" in cmd:
            return _make_docker_info_ok()
        if "ps" in cmd:
            return ps_result
        if "compose" in cmd and "up" in cmd:
            compose_called.append(cmd)
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=_fake_run):
        with patch("socket.create_connection", side_effect=_sock_ok):
            with patch("time.sleep"):
                run_scanner._ensure_docker_services()

    assert len(compose_called) == 0, "docker compose up nie powinno byc wywolywane gdy wszystko dziala"


def test_missing_containers_triggers_compose_up():
    """Gdy brakuje kontenerow — docker compose up -d jest wywolywany."""
    ps_missing = _make_docker_ps_result([])   # zadnych kontenerow
    ps_full    = _make_docker_ps_result(ALL_CONTAINERS)  # po up wszystkie

    call_count = {"ps": 0}
    compose_calls = []

    def _fake_run(cmd, **kwargs):
        if "info" in cmd:
            return _make_docker_info_ok()
        if "ps" in cmd:
            call_count["ps"] += 1
            # Pierwsze wywolanie: brak kontenerow; kolejne: wszystkie uruchomione
            return ps_missing if call_count["ps"] == 1 else ps_full
        if "compose" in cmd and "up" in cmd:
            compose_calls.append(list(cmd))
            return MagicMock(returncode=0)
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=_fake_run):
        with patch("socket.create_connection", side_effect=_sock_ok):
            with patch("time.sleep"):
                result = run_scanner._ensure_docker_services()

    assert result is True
    assert len(compose_calls) >= 1, "docker compose up powinno byc wywolane"
    # Pierwsza proba powinna byc bez --build
    assert "--build" not in compose_calls[0], "Pierwsza proba nie powinna uzywac --build"


def test_compose_up_falls_back_to_build_on_failure():
    """Gdy docker compose up -d zawiedzie — ponawia z --build."""
    ps_missing = _make_docker_ps_result([])
    ps_full    = _make_docker_ps_result(ALL_CONTAINERS)

    call_count = {"ps": 0, "compose": 0}
    compose_cmds = []

    def _fake_run(cmd, **kwargs):
        if "info" in cmd:
            return _make_docker_info_ok()
        if "ps" in cmd:
            call_count["ps"] += 1
            return ps_missing if call_count["ps"] <= 2 else ps_full
        if "compose" in cmd and "up" in cmd:
            call_count["compose"] += 1
            compose_cmds.append(list(cmd))
            # Pierwsza proba (bez --build) zawodzi
            if "--build" not in cmd:
                return MagicMock(returncode=1)
            return MagicMock(returncode=0)
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=_fake_run):
        with patch("socket.create_connection", side_effect=_sock_ok):
            with patch("time.sleep"):
                run_scanner._ensure_docker_services()

    has_build = any("--build" in c for c in compose_cmds)
    assert has_build, "Po bledzie up -d powinno nastapic wywolanie z --build"


def test_postgres_not_reachable_after_all_attempts_returns_false():
    """Gdy postgres nie odpowiada na TCP po wszystkich probach — zwraca False."""
    ps_full = _make_docker_ps_result(ALL_CONTAINERS)

    def _fake_run(cmd, **kwargs):
        if "info" in cmd:
            return _make_docker_info_ok()
        if "ps" in cmd:
            return ps_full
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=_fake_run):
        with patch("socket.create_connection", side_effect=_sock_fail):
            with patch("time.sleep"):
                result = run_scanner._ensure_docker_services()

    assert result is False


def test_postgres_reachable_on_second_attempt_returns_true():
    """Postgres niedostepny przy pierwszej probie TCP — dostepny przy drugiej — True."""
    ps_full = _make_docker_ps_result(ALL_CONTAINERS)
    tcp_calls = {"n": 0}

    def _sock_retry(*args, **kwargs):
        tcp_calls["n"] += 1
        if tcp_calls["n"] < 2:
            raise OSError("not yet")
        return _sock_ok()

    def _fake_run(cmd, **kwargs):
        if "info" in cmd:
            return _make_docker_info_ok()
        if "ps" in cmd:
            return ps_full
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=_fake_run):
        with patch("socket.create_connection", side_effect=_sock_retry):
            with patch("time.sleep"):
                result = run_scanner._ensure_docker_services()

    assert result is True
    assert tcp_calls["n"] == 2


def test_docker_timeout_returns_false():
    """Gdy docker info timeout — zwraca False."""
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 8)):
        with patch("socket.create_connection", side_effect=_sock_fail):
            with patch("time.sleep"):
                result = run_scanner._ensure_docker_services()
    assert result is False


def test_compose_up_timeout_is_not_fatal():
    """Gdy docker compose up -d przekroczy timeout (np. pobieranie obrazow)
    — funkcja kontynuuje i zwraca True gdy kontenery ostatecznie wstana."""
    ps_missing = _make_docker_ps_result([])
    ps_full    = _make_docker_ps_result(ALL_CONTAINERS)
    call_count = {"ps": 0}

    def _fake_run(cmd, **kwargs):
        if "info" in cmd:
            return _make_docker_info_ok()
        if "ps" in cmd:
            call_count["ps"] += 1
            # Po pierwszym sprawdzeniu (brak) Docker pobiera obrazy (timeout),
            # przy kolejnym sprawdzeniu kontenery juz dzialaja
            return ps_missing if call_count["ps"] == 1 else ps_full
        if "compose" in cmd and "up" in cmd:
            # Symulacja dlugiego pobierania obrazow — compose up timeout
            raise subprocess.TimeoutExpired(cmd, run_scanner._COMPOSE_TIMEOUT)
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=_fake_run):
        with patch("socket.create_connection", side_effect=_sock_ok):
            with patch("time.sleep"):
                result = run_scanner._ensure_docker_services()

    assert result is True, "Timeout compose up NIE powinien byc traktowany jako blad krytyczny"


def test_compose_up_timeout_then_postgres_comes_up():
    """Compose timeout + postgres niedostepny przy pierwszej probie TCP — True przy kolejnej."""
    ps_missing = _make_docker_ps_result([])
    ps_full    = _make_docker_ps_result(ALL_CONTAINERS)
    ps_call = {"n": 0}
    tcp_call = {"n": 0}

    def _fake_run(cmd, **kwargs):
        if "info" in cmd:
            return _make_docker_info_ok()
        if "ps" in cmd:
            ps_call["n"] += 1
            return ps_missing if ps_call["n"] == 1 else ps_full
        if "compose" in cmd and "up" in cmd:
            raise subprocess.TimeoutExpired(cmd, run_scanner._COMPOSE_TIMEOUT)
        return MagicMock(returncode=0)

    def _sock_retry(*args, **kwargs):
        tcp_call["n"] += 1
        if tcp_call["n"] < 3:
            raise OSError("postgres still initializing")
        return _sock_ok()

    with patch("subprocess.run", side_effect=_fake_run):
        with patch("socket.create_connection", side_effect=_sock_retry):
            with patch("time.sleep"):
                result = run_scanner._ensure_docker_services()

    assert result is True
    assert tcp_call["n"] == 3, "Powinno byc dokladnie 3 proby TCP"


def test_pg_tcp_retries_count():
    """Weryfikuje ze liczba prob TCP odpowiada stalej _PG_TCP_RETRIES."""
    ps_full = _make_docker_ps_result(ALL_CONTAINERS)
    tcp_call = {"n": 0}

    def _fake_run(cmd, **kwargs):
        if "info" in cmd:
            return _make_docker_info_ok()
        if "ps" in cmd:
            return ps_full
        return MagicMock(returncode=0)

    def _sock_fail_n(*args, **kwargs):
        tcp_call["n"] += 1
        raise OSError("still down")

    with patch("subprocess.run", side_effect=_fake_run):
        with patch("socket.create_connection", side_effect=_sock_fail_n):
            with patch("time.sleep"):
                result = run_scanner._ensure_docker_services()

    assert result is False
    assert tcp_call["n"] == run_scanner._PG_TCP_RETRIES, (
        f"Oczekiwano {run_scanner._PG_TCP_RETRIES} prob TCP, wykonano {tcp_call['n']}"
    )


def test_missing_postgres_after_max_retries_returns_false():
    """Gdy netdoc-postgres nie uruchamia sie po wszystkich probach — zwraca False."""
    ps_no_postgres = _make_docker_ps_result(
        [c for c in ALL_CONTAINERS if c != "netdoc-postgres"]
    )

    def _fake_run(cmd, **kwargs):
        if "info" in cmd:
            return _make_docker_info_ok()
        if "ps" in cmd:
            return ps_no_postgres
        if "compose" in cmd and "up" in cmd:
            return MagicMock(returncode=0)
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=_fake_run):
        with patch("socket.create_connection", side_effect=_sock_fail):
            with patch("time.sleep"):
                result = run_scanner._ensure_docker_services()

    assert result is False
