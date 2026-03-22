"""Testy dla run_internet.py — check_dns, check_http, latency/jitter, speed, _save."""
import json
import math
import socket
from unittest.mock import MagicMock, patch

import pytest
import httpx

import run_internet


# ── check_dns ─────────────────────────────────────────────────────────────────

def test_check_dns_success():
    """TCP connect do DNS server dziala — zwraca ok=True i ms >= 0."""
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=cm)
    cm.__exit__ = MagicMock(return_value=False)

    with patch("socket.create_connection", return_value=cm):
        result = run_internet.check_dns("8.8.8.8")

    assert result["ok"] is True
    assert isinstance(result["ms"], int)
    assert result["ms"] >= 0


def test_check_dns_failure_returns_ok_false():
    """Gdy DNS server nieosiagalny — zwraca ok=False."""
    with patch("socket.create_connection", side_effect=OSError("connection refused")):
        result = run_internet.check_dns("8.8.8.8", timeout=1)

    assert result["ok"] is False
    assert result["ms"] is None
    assert "err" in result


def test_check_dns_uses_correct_port():
    """check_dns domyslnie laczy do portu 53."""
    calls = []
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=cm)
    cm.__exit__ = MagicMock(return_value=False)

    def _fake_connect(addr, timeout):
        calls.append(addr)
        return cm

    with patch("socket.create_connection", side_effect=_fake_connect):
        run_internet.check_dns("1.1.1.1")

    assert calls[0] == ("1.1.1.1", 53)


# ── check_http ────────────────────────────────────────────────────────────────

def test_check_http_success_200():
    """HTTP GET zwraca 200 — ok=True i ms >= 0."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("httpx.get", return_value=mock_resp):
        result = run_internet.check_http("https://1.1.1.1")

    assert result["ok"] is True
    assert result["code"] == 200
    assert isinstance(result["ms"], int)


def test_check_http_server_error_500():
    """HTTP 500 — ok=False (status >= 500)."""
    mock_resp = MagicMock()
    mock_resp.status_code = 500

    with patch("httpx.get", return_value=mock_resp):
        result = run_internet.check_http("https://1.1.1.1")

    assert result["ok"] is False


def test_check_http_connection_error():
    """Wyjatel polaczenia — ok=False z polem err."""
    with patch("httpx.get", side_effect=httpx.ConnectError("timeout")):
        result = run_internet.check_http("https://1.1.1.1")

    assert result["ok"] is False
    assert result["ms"] is None
    assert "err" in result


# ── measure_latency_and_jitter ────────────────────────────────────────────────

def test_latency_jitter_returns_stats():
    """N prob HTTP — zwraca avg, min, max, jitter."""
    latencies = [10, 20, 15, 25, 12]
    call_idx = {"n": 0}

    def _fake_http(url, timeout=None):
        ms = latencies[call_idx["n"] % len(latencies)]
        call_idx["n"] += 1
        return {"ok": True, "ms": ms, "code": 200}

    with patch("run_internet.check_http", side_effect=_fake_http):
        result = run_internet.measure_latency_and_jitter("https://1.1.1.1", pings=5)

    assert result["ok"] is True
    assert result["avg_ms"] == round(sum(latencies) / len(latencies), 1)
    assert result["min_ms"] == min(latencies)
    assert result["max_ms"] == max(latencies)
    assert result["jitter_ms"] >= 0
    assert result["pings"] == 5


def test_latency_jitter_all_fail():
    """Gdy wszystkie proby HTTP zawodza — ok=False, brak avg/jitter."""
    with patch("run_internet.check_http", return_value={"ok": False, "ms": None}):
        result = run_internet.measure_latency_and_jitter("https://1.1.1.1", pings=3)

    assert result["ok"] is False
    assert result["avg_ms"] is None
    assert result["jitter_ms"] is None
    assert result["errors"] == 3


def test_latency_jitter_single_probe():
    """Jitter z 1 proby = 0.0 (brak wariancji)."""
    with patch("run_internet.check_http", return_value={"ok": True, "ms": 42, "code": 200}):
        result = run_internet.measure_latency_and_jitter("https://1.1.1.1", pings=1)

    assert result["ok"] is True
    assert result["avg_ms"] == 42.0
    assert result["jitter_ms"] == 0.0


def test_jitter_formula_is_stdev():
    """Jitter obliczany jako odchylenie standardowe — weryfikacja formuly."""
    latencies = [10, 20, 30]
    call_idx = {"n": 0}

    def _fake_http(url, timeout=None):
        ms = latencies[call_idx["n"]]
        call_idx["n"] += 1
        return {"ok": True, "ms": ms, "code": 200}

    with patch("run_internet.check_http", side_effect=_fake_http):
        result = run_internet.measure_latency_and_jitter("x", pings=3)

    avg = sum(latencies) / 3  # 20
    variance = sum((s - avg) ** 2 for s in latencies) / 3
    expected_jitter = round(math.sqrt(variance), 1)
    assert result["jitter_ms"] == expected_jitter


# ── speed_download ────────────────────────────────────────────────────────────

def test_speed_download_calculates_mbps():
    """speed_download oblicza Mbps na podstawie bajtow i czasu."""
    chunk = b"x" * 65536
    mock_resp = MagicMock()
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.iter_bytes.return_value = iter([chunk] * 80)  # 80*64KB = 5MB

    with patch("httpx.stream", return_value=mock_resp):
        with patch("time.monotonic", side_effect=[0.0, 0.5]):
            result = run_internet.speed_download()

    assert result["ok"] is True
    assert result["download_mbps"] is not None
    assert result["download_mbps"] > 0


def test_speed_download_failure():
    """Wyjatel podczas download — ok=False."""
    with patch("httpx.stream", side_effect=httpx.ConnectError("timeout")):
        result = run_internet.speed_download()

    assert result["ok"] is False
    assert result.get("download_mbps") is None


# ── speed_upload ──────────────────────────────────────────────────────────────

def test_speed_upload_calculates_mbps():
    """speed_upload mierzy predkosc wysylania na podstawie bajtow i czasu."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("httpx.post", return_value=mock_resp):
        with patch("time.monotonic", side_effect=[0.0, 0.2]):
            result = run_internet.speed_upload(bytes_count=1_000_000)

    assert result["ok"] is True
    assert result["upload_mbps"] is not None
    assert result["upload_mbps"] > 0
    assert result["sent_bytes"] == 1_000_000


def test_speed_upload_failure():
    """Wyjatel podczas upload — ok=False."""
    with patch("httpx.post", side_effect=httpx.ConnectError("timeout")):
        result = run_internet.speed_upload()

    assert result["ok"] is False
    assert result.get("upload_mbps") is None
    assert "err" in result


def test_speed_upload_sends_correct_payload_size():
    """speed_upload wysyla dokladnie bytes_count bajtow."""
    captured = {}
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    def _fake_post(url, content, **kwargs):
        captured["len"] = len(content)
        return mock_resp

    with patch("httpx.post", side_effect=_fake_post):
        run_internet.speed_upload(bytes_count=512_000)

    assert captured["len"] == 512_000


# ── _save ─────────────────────────────────────────────────────────────────────

def test_save_creates_new_row():
    """_save dodaje nowy rekord gdy klucz nie istnieje."""
    db = MagicMock()
    db.query.return_value.filter_by.return_value.first.return_value = None

    with patch("run_internet.SessionLocal", return_value=db):
        run_internet._save("test_key", "internet", {"ok": True, "ms": 10})

    db.add.assert_called_once()
    db.commit.assert_called_once()


def test_save_updates_existing_row():
    """_save aktualizuje wartosc gdy klucz juz istnieje."""
    existing = MagicMock()
    existing.value = '{"ok": false}'
    db = MagicMock()
    db.query.return_value.filter_by.return_value.first.return_value = existing

    with patch("run_internet.SessionLocal", return_value=db):
        run_internet._save("internet_status", "internet", {"ok": True, "ms": 5})

    assert json.loads(existing.value)["ok"] is True
    db.add.assert_not_called()


def test_save_handles_db_error_gracefully():
    """_save nie propaguje wyjatkow DB."""
    db = MagicMock()
    db.query.return_value.filter_by.return_value.first.side_effect = Exception("DB error")

    with patch("run_internet.SessionLocal", return_value=db):
        run_internet._save("test_key", "internet", {"ok": True})

    db.rollback.assert_called_once()


# ── run_checks integracyjny ───────────────────────────────────────────────────

def test_run_checks_calls_dns_and_latency():
    """run_checks sprawdza oba DNS i latencje/jitter HTTP."""
    dns_calls = []

    def _fake_dns(ip, *args, **kwargs):
        dns_calls.append(ip)
        return {"ok": True, "ms": 10}

    lat_result = {"ok": True, "avg_ms": 20, "min_ms": 15, "max_ms": 30,
                  "jitter_ms": 5.0, "errors": 0, "pings": 6}

    with patch("run_internet.check_dns", side_effect=_fake_dns), \
         patch("run_internet.measure_latency_and_jitter", return_value=lat_result), \
         patch("run_internet._save"):
        run_internet.run_checks()

    assert "8.8.8.8" in dns_calls
    assert "1.1.1.1" in dns_calls


def test_run_checks_saves_jitter_in_status():
    """run_checks zapisuje jitter w http_cloudflare wewnatrz internet_status."""
    saved = {}

    lat = {"ok": True, "avg_ms": 25, "min_ms": 10, "max_ms": 50,
           "jitter_ms": 12.3, "errors": 0, "pings": 6}

    with patch("run_internet.check_dns", return_value={"ok": True, "ms": 5}), \
         patch("run_internet.measure_latency_and_jitter", return_value=lat), \
         patch("run_internet._save", side_effect=lambda k, c, v: saved.update({k: v})):
        run_internet.run_checks()

    assert "internet_status" in saved
    hc = saved["internet_status"]["http_cloudflare"]
    assert hc["jitter_ms"] == 12.3
    assert hc["avg_ms"] == 25


def test_run_speed_test_saves_both_dl_and_ul():
    """run_speed_test zapisuje download_mbps i upload_mbps w internet_speed."""
    saved = {}

    dl = {"ok": True, "download_mbps": 94.2, "received_bytes": 5_242_880, "elapsed_s": 0.44}
    ul = {"ok": True, "upload_mbps": 48.1, "sent_bytes": 2_097_152, "elapsed_s": 0.35}

    with patch("run_internet.speed_download", return_value=dl), \
         patch("run_internet.speed_upload", return_value=ul), \
         patch("run_internet._save", side_effect=lambda k, c, v: saved.update({k: v})):
        run_internet.run_speed_test()

    spd = saved.get("internet_speed", {})
    assert spd["download_mbps"] == 94.2
    assert spd["upload_mbps"] == 48.1


# ── Stale konfiguracyjne ──────────────────────────────────────────────────────

def test_constants_exist_and_are_positive():
    """Stale konfiguracyjne istnieja i maja sensowne wartosci."""
    assert run_internet.CHECK_INTERVAL_S > 0
    assert run_internet.SPEED_INTERVAL_S > run_internet.CHECK_INTERVAL_S
    assert run_internet.METRICS_PORT > 0
    assert run_internet.SPEED_BYTES > 0
    assert run_internet.UPLOAD_BYTES > 0
    assert run_internet.JITTER_PINGS >= 2


# ── BUG-WRK-04: check_http must not follow redirects ─────────────────────────

def test_check_http_does_not_follow_redirects():
    """BUG-WRK-04 regresja: check_http() uzywa follow_redirects=False.

    Cloudflare zwraca 301 z Location zawierajacym przecinek (malformed URL),
    co powoduje 404 i zafalszowanie pomiaru latencji. Bez podazania za
    przekierowaniami 3xx jest traktowane jako ok=True (status < 500).
    """
    import inspect
    source = inspect.getsource(run_internet.check_http)
    assert "follow_redirects=False" in source, (
        "BUG-WRK-04: check_http() musi uzywac follow_redirects=False "
        "aby unikac malformed redirect URL z Cloudflare"
    )


def test_check_http_301_is_ok():
    """BUG-WRK-04 regresja: odpowiedz 301 (redirect) jest traktowana jako ok=True."""
    mock_resp = MagicMock()
    mock_resp.status_code = 301

    with patch("httpx.get", return_value=mock_resp):
        result = run_internet.check_http("https://1.1.1.1")

    assert result["ok"] is True, (
        "BUG-WRK-04: 301 Moved Permanently to ok=True (status < 500) — "
        "przekierowanie nie jest bledem polaczenia"
    )
    assert result["code"] == 301
