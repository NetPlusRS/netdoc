"""Testy dla check_wan_ip i run_wan_check w run_internet.py."""
import json
from unittest.mock import MagicMock, patch

import pytest

import run_internet


# ── check_wan_ip ──────────────────────────────────────────────────────────────

def test_check_wan_ip_success():
    """ipinfo.io zwraca dane — ok=True z ip, country, city, org."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "ip": "5.1.2.3",
        "city": "Warsaw",
        "region": "Masovian Voivodeship",
        "country": "PL",
        "org": "AS5617 Orange Polska",
        "timezone": "Europe/Warsaw",
        "loc": "52.2297,21.0122",
    }

    with patch("httpx.get", return_value=mock_resp):
        result = run_internet.check_wan_ip()

    assert result["ok"] is True
    assert result["ip"] == "5.1.2.3"
    assert result["country"] == "PL"
    assert result["city"] == "Warsaw"
    assert result["org"] == "AS5617 Orange Polska"
    assert result["timezone"] == "Europe/Warsaw"
    assert result["loc"] == "52.2297,21.0122"
    assert "updated_at" in result


def test_check_wan_ip_failure_returns_ok_false():
    """Blad polaczenia — ok=False z polem err."""
    import httpx
    with patch("httpx.get", side_effect=httpx.ConnectError("timeout")):
        result = run_internet.check_wan_ip()

    assert result["ok"] is False
    assert "err" in result


def test_check_wan_ip_partial_data():
    """ipinfo.io zwraca tylko IP bez lokalizacji — ok=True, reszta None."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"ip": "1.2.3.4"}

    with patch("httpx.get", return_value=mock_resp):
        result = run_internet.check_wan_ip()

    assert result["ok"] is True
    assert result["ip"] == "1.2.3.4"
    assert result["city"] is None
    assert result["country"] is None


def test_check_wan_ip_uses_correct_url():
    """check_wan_ip wywoluje ipinfo.io."""
    calls = []
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"ip": "1.2.3.4"}

    def _fake_get(url, **kwargs):
        calls.append(url)
        return mock_resp

    with patch("httpx.get", side_effect=_fake_get):
        run_internet.check_wan_ip()

    assert len(calls) == 1
    assert "ipinfo.io" in calls[0]


def test_check_wan_ip_uses_timeout():
    """check_wan_ip przekazuje timeout do httpx.get."""
    captured = {}
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"ip": "1.2.3.4"}

    def _fake_get(url, timeout=None, **kwargs):
        captured["timeout"] = timeout
        return mock_resp

    with patch("httpx.get", side_effect=_fake_get):
        run_internet.check_wan_ip(timeout=15.0)

    assert captured["timeout"] == 15.0


# ── run_wan_check ─────────────────────────────────────────────────────────────

def test_run_wan_check_saves_to_db():
    """run_wan_check zapisuje internet_wan do DB."""
    saved = {}
    wan_data = {
        "ok": True, "ip": "5.1.2.3", "city": "Warsaw",
        "region": "Masovian", "country": "PL",
        "org": "AS5617 Orange", "timezone": "Europe/Warsaw", "loc": "52,21",
        "updated_at": "2026-01-01T12:00:00",
    }

    with patch("run_internet.check_wan_ip", return_value=wan_data), \
         patch("run_internet._save", side_effect=lambda k, c, v: saved.update({k: v})), \
         patch("run_internet.g_wan_ok"):
        run_internet.run_wan_check()

    assert "internet_wan" in saved
    assert saved["internet_wan"]["ip"] == "5.1.2.3"
    assert saved["internet_wan"]["country"] == "PL"


def test_run_wan_check_sets_gauge_ok():
    """run_wan_check ustawia g_wan_ok=1 gdy ok=True."""
    from unittest.mock import patch
    gauge_mock = MagicMock()

    with patch("run_internet.check_wan_ip", return_value={"ok": True, "ip": "1.2.3.4"}), \
         patch("run_internet._save"), \
         patch("run_internet.g_wan_ok", gauge_mock):
        run_internet.run_wan_check()

    gauge_mock.set.assert_called_once_with(1)


def test_run_wan_check_sets_gauge_fail():
    """run_wan_check ustawia g_wan_ok=0 gdy ok=False."""
    gauge_mock = MagicMock()

    with patch("run_internet.check_wan_ip", return_value={"ok": False, "err": "timeout"}), \
         patch("run_internet._save"), \
         patch("run_internet.g_wan_ok", gauge_mock):
        run_internet.run_wan_check()

    gauge_mock.set.assert_called_once_with(0)


# ── Stale konfiguracyjne WAN ──────────────────────────────────────────────────

def test_wan_constants_exist():
    """Stale WAN_INTERVAL_S i _WAN_INFO_URL istnieja."""
    assert run_internet.WAN_INTERVAL_S > 0
    assert "ipinfo.io" in run_internet._WAN_INFO_URL
