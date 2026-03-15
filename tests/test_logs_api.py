"""Testy API endpointu /api/logs/scanner."""
import os
import tempfile
from unittest.mock import patch

import netdoc.api.routes.logs as logs_module


def test_scanner_log_file_not_exists(client):
    """Gdy plik logu nie istnieje, endpoint zwraca komunikat."""
    with patch.object(logs_module, "LOG_FILE", "/nonexistent/path/scanner.log"):
        r = client.get("/api/logs/scanner")
    assert r.status_code == 200
    assert "nie istnieje" in r.text


def test_scanner_log_file_exists_returns_content(client):
    """Gdy plik logu istnieje, endpoint zwraca jego zawartosc."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as f:
        for i in range(10):
            f.write("linia {} ".format(i) + chr(10))
        tmp_path = f.name
    try:
        with patch.object(logs_module, "LOG_FILE", tmp_path):
            r = client.get("/api/logs/scanner")
        assert r.status_code == 200
        assert "linia 9" in r.text
    finally:
        os.unlink(tmp_path)


def test_scanner_log_tail_limits_lines(client):
    """Parametr tail ogranicza liczbe zwracanych linii."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as f:
        for i in range(50):
            f.write("log line {} ".format(i) + chr(10))
        tmp_path = f.name
    try:
        with patch.object(logs_module, "LOG_FILE", tmp_path):
            r = client.get("/api/logs/scanner?tail=10")
        assert r.status_code == 200
        lines = [l for l in r.text.splitlines() if l.strip()]
        assert len(lines) == 10
        assert "log line 49" in r.text
        assert "log line 0" not in r.text
    finally:
        os.unlink(tmp_path)
