"""Testy _start_screenshot_fill_worker — daemon thread uzupelniajacy screenshoty.

Testujemy:
- thread jest daemon=True i ma nazwe "screenshot-fill"
- thread jest startowany przez _start_screenshot_fill_worker
- worker spi startup_delay_s przed pierwszym wywolaniem fill
- worker wywoluje _fill_missing_screenshots w petli
- worker spi interval_s po kazdym wywolaniu fill
- worker nie zatrzymuje sie gdy _fill_missing_screenshots rzuca wyjatek
- worker loguje informacje gdy capture > 0
- worker loguje ostrzezenie przy wyjatku
- create_app() startuje worker thread
"""
from unittest.mock import patch, MagicMock, call
import threading
import pytest


# Uzywamy BaseException (nie Exception) jako sygnalu stopu w testach,
# poniewaz _worker lapie tylko `except Exception`, a StopIteration jest
# jego podklasa — stad nieskonczona petla gdybysmy uzyli StopIteration.
class _StopWorker(BaseException):
    pass


# ─── helpers ──────────────────────────────────────────────────────────────────

def _extract_worker_fn(startup_delay_s=0, interval_s=0):
    """Uruchamia _start_screenshot_fill_worker z patchowanym Thread.
    Zwraca funkcje _worker przekazana do Thread (do bezposredniego testowania).
    """
    import netdoc.web.app as web_app

    captured = {}

    class FakeThread:
        def __init__(self, target, name, daemon):
            captured["target"] = target
            captured["name"]   = name
            captured["daemon"] = daemon
        def start(self):
            captured["started"] = True

    with patch("threading.Thread", FakeThread):
        with patch("time.sleep"):
            web_app._start_screenshot_fill_worker(
                interval_s=interval_s, startup_delay_s=startup_delay_s
            )

    return captured


# ─── wlasciwosci threadu ──────────────────────────────────────────────────────

def test_worker_thread_is_daemon():
    """Thread musi byc daemon=True — ginie razem z procesem."""
    info = _extract_worker_fn()
    assert info["daemon"] is True


def test_worker_thread_name():
    """Thread ma nazwe 'screenshot-fill'."""
    info = _extract_worker_fn()
    assert info["name"] == "screenshot-fill"


def test_worker_thread_is_started():
    """Thread.start() jest wywolywane."""
    info = _extract_worker_fn()
    assert info.get("started") is True


def test_worker_thread_has_callable_target():
    """Target threadu jest callable."""
    info = _extract_worker_fn()
    assert callable(info["target"])


# ─── logika _worker ───────────────────────────────────────────────────────────

def _run_worker_iterations(n_iterations, fill_return=0,
                            fill_side_effect=None,
                            startup_delay_s=0, interval_s=0):
    """Uruchamia funkcje _worker przez dokladnie n_iterations wywolan fill.
    StopIteration jest rzucane po n-tym wywolaniu _fill_missing_screenshots.
    """
    import netdoc.web.app as web_app

    sleep_calls = []
    fill_count  = [0]

    def _fake_sleep(s):
        sleep_calls.append(s)

    # Buduj side_effect: uzytkownikowe efekty + StopIteration na koncu
    user_effects = list(fill_side_effect) if fill_side_effect else []

    def _fill_side_effect_fn(*args, **kwargs):
        fill_count[0] += 1
        # Pobierz efekt uzytkownika jesli dostepny
        if user_effects:
            effect = user_effects.pop(0)
            if isinstance(effect, BaseException):
                raise effect
            if isinstance(effect, type) and issubclass(effect, BaseException):
                raise effect()
            return effect
        # Po n_iterations wywolaniach zatrzymaj petle (_StopWorker nie jest Exception)
        if fill_count[0] >= n_iterations:
            raise _StopWorker
        return fill_return

    fill_mock = MagicMock(side_effect=_fill_side_effect_fn)

    captured = {}

    class FakeThread:
        def __init__(self, target, name, daemon):
            captured["target"] = target
        def start(self): pass

    with patch("threading.Thread", FakeThread):
        web_app._start_screenshot_fill_worker(
            interval_s=interval_s, startup_delay_s=startup_delay_s
        )

    worker_fn = captured["target"]

    with patch("netdoc.web.app._fill_missing_screenshots", fill_mock):
        with patch("time.sleep", _fake_sleep):
            try:
                worker_fn()
            except _StopWorker:
                pass

    return sleep_calls, fill_mock


def test_worker_sleeps_startup_delay_first():
    """Pierwsza operacja to sleep(startup_delay_s)."""
    sleep_calls, _ = _run_worker_iterations(1, startup_delay_s=42, interval_s=99)
    assert sleep_calls[0] == 42


def test_worker_calls_fill_after_startup():
    """_fill_missing_screenshots wywolane po startup sleep."""
    _, fill_mock = _run_worker_iterations(1, startup_delay_s=5, interval_s=0)
    fill_mock.assert_called()


def test_worker_calls_fill_with_correct_args():
    """_fill_missing_screenshots wywolywane z max_devices=5, delay_s=3.0."""
    _, fill_mock = _run_worker_iterations(1)
    fill_mock.assert_called_with(max_devices=5, delay_s=3.0)


def test_worker_sleeps_interval_after_fill():
    """Po wywolaniu fill worker spi interval_s.
    n_iterations=2: 1. iteracja zwraca normalnie → sleep(interval), 2. iteracja konczy petle.
    """
    sleep_calls, _ = _run_worker_iterations(2, startup_delay_s=0, interval_s=1800)
    assert 1800 in sleep_calls


def test_worker_repeats_fill_multiple_times():
    """Worker wywoluje fill wielokrotnie (petla while True)."""
    _, fill_mock = _run_worker_iterations(3, interval_s=0)
    assert fill_mock.call_count == 3


def test_worker_continues_after_fill_exception():
    """Wyjatek w _fill_missing_screenshots nie zatrzymuje workera."""
    import netdoc.web.app as web_app

    captured = {}

    class FakeThread:
        def __init__(self, target, name, daemon):
            captured["target"] = target
        def start(self): pass

    with patch("threading.Thread", FakeThread):
        web_app._start_screenshot_fill_worker(interval_s=0, startup_delay_s=0)

    worker_fn = captured["target"]
    call_count = [0]

    def _fill(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            raise Exception("DB error")  # wyjatek w 1. iteracji
        if call_count[0] >= 3:
            raise _StopWorker            # zatrzymaj po 3 wywolaniach
        return 0

    with patch("netdoc.web.app._fill_missing_screenshots", side_effect=_fill):
        with patch("time.sleep"):
            try:
                worker_fn()
            except _StopWorker:
                pass

    # Pomimo wyjatku w 1. iteracji, fill zostal wywolany 3 razy
    assert call_count[0] == 3


def test_worker_logs_info_when_captured(caplog):
    """Gdy fill zwroci > 0, worker loguje info."""
    import logging
    import netdoc.web.app as web_app

    captured = {}

    class FakeThread:
        def __init__(self, target, name, daemon):
            captured["target"] = target
        def start(self): pass

    with patch("threading.Thread", FakeThread):
        web_app._start_screenshot_fill_worker(interval_s=0, startup_delay_s=0)

    worker_fn = captured["target"]

    with patch("netdoc.web.app._fill_missing_screenshots", return_value=3):
        with patch("time.sleep", side_effect=[None, StopIteration]):
            with caplog.at_level(logging.INFO, logger="netdoc.web.app"):
                try:
                    worker_fn()
                except StopIteration:
                    pass

    assert any("3" in r.message for r in caplog.records)


def test_worker_logs_warning_on_exception(caplog):
    """Wyjatek w fill — worker loguje WARNING."""
    import logging
    import netdoc.web.app as web_app

    captured = {}

    class FakeThread:
        def __init__(self, target, name, daemon):
            captured["target"] = target
        def start(self): pass

    with patch("threading.Thread", FakeThread):
        web_app._start_screenshot_fill_worker(interval_s=0, startup_delay_s=0)

    worker_fn = captured["target"]

    with patch("netdoc.web.app._fill_missing_screenshots",
               side_effect=[RuntimeError("test error"), 0]):
        with patch("time.sleep", side_effect=[None, StopIteration]):
            with caplog.at_level(logging.WARNING, logger="netdoc.web.app"):
                try:
                    worker_fn()
                except StopIteration:
                    pass

    assert any("test error" in r.message for r in caplog.records)


# ─── create_app startuje worker ──────────────────────────────────────────────

def test_create_app_starts_fill_worker():
    """create_app() wywoluje _start_screenshot_fill_worker."""
    import netdoc.web.app as web_app

    with patch("netdoc.web.app._start_screenshot_fill_worker") as mock_start:
        with patch("netdoc.web.app.SessionLocal"):
            web_app.create_app()

    mock_start.assert_called_once()


def test_create_app_worker_uses_default_intervals():
    """create_app() uruchamia worker z interval_s=1800 i startup_delay_s=60."""
    import netdoc.web.app as web_app

    with patch("netdoc.web.app._start_screenshot_fill_worker") as mock_start:
        with patch("netdoc.web.app.SessionLocal"):
            web_app.create_app()

    _, kwargs = mock_start.call_args
    assert kwargs.get("interval_s", mock_start.call_args[0][0] if mock_start.call_args[0] else None) == 1800 or \
           mock_start.call_args == call(interval_s=1800, startup_delay_s=60)
