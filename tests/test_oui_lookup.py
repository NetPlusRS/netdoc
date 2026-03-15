"""Testy modulu oui_lookup — parsowanie IEEE OUI i lookup MAC->vendor."""
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from netdoc.collector.oui_lookup import OUIDatabase


# Przykladowe linie IEEE OUI w formacie pliku oui.txt (MA-L)
_SAMPLE_MA_L = """00-00-0C   (hex)\t\tCisco Systems, Inc
00-1B-9D   (hex)\t\tNovus Security Sp. z o.o.
90-09-D0   (hex)\t\tSynology Incorporated
3C-EF-8C   (hex)\t\tZhejiang Dahua Technology Co., Ltd.
00-12-34   (hex)\t\tPRIVATE
"""

# MA-M: 28-bit prefix (7 hex chars)
_SAMPLE_MA_M = """00-50-C2-A   (hex)\t\tIEEE Registration Authority
F4-F5-D8-C   (hex)\t\tGoogle LLC
"""

# MA-S: 36-bit prefix (9 hex chars)
_SAMPLE_MA_S = """70-B3-D5-77-D   (hex)\t\tPeopleNet
9C-05-D6-00-0   (hex)\t\tUbiquiti Inc
"""


@pytest.fixture
def tmp_oui_db(tmp_path):
    """OUIDatabase z plikami testowymi w katalogu tymczasowym."""
    oui_l = tmp_path / "ieee_oui.txt"
    oui_m = tmp_path / "ieee_mam.txt"
    oui_s = tmp_path / "ieee_oui36.txt"
    oui_l.write_text(_SAMPLE_MA_L, encoding="utf-8")
    oui_m.write_text(_SAMPLE_MA_M, encoding="utf-8")
    oui_s.write_text(_SAMPLE_MA_S, encoding="utf-8")

    db = OUIDatabase()
    # Podmien _DATA_DIR
    import netdoc.collector.oui_lookup as mod
    orig = mod._DATA_DIR
    mod._DATA_DIR = tmp_path

    # Podmien sciezki w IEEE_SOURCES
    orig_sources = mod.IEEE_SOURCES
    mod.IEEE_SOURCES = [
        {"name": "IEEE MA-L", "url": "", "file": "ieee_oui.txt",   "prefix_chars": 6},
        {"name": "IEEE MA-M", "url": "", "file": "ieee_mam.txt",   "prefix_chars": 7},
        {"name": "IEEE MA-S", "url": "", "file": "ieee_oui36.txt", "prefix_chars": 9},
    ]
    db.load()
    yield db

    mod._DATA_DIR = orig
    mod.IEEE_SOURCES = orig_sources


# --- load / parsing ---

def test_load_parses_ma_l(tmp_oui_db):
    """Parsuje linie MA-L (24-bit OUI)."""
    assert tmp_oui_db.lookup("00:00:0C:01:02:03") == "Cisco Systems, Inc"


def test_load_parses_ma_l_novus(tmp_oui_db):
    """Parsuje OUI Novus Security."""
    assert tmp_oui_db.lookup("00:1B:9D:05:6F:AC") == "Novus Security Sp. z o.o."


def test_load_parses_ma_l_synology(tmp_oui_db):
    assert tmp_oui_db.lookup("90:09:D0:8C:5E:D5") == "Synology Incorporated"


def test_load_skips_private(tmp_oui_db):
    """Wpisy oznaczone PRIVATE sa pomijane."""
    assert tmp_oui_db.lookup("00:12:34:00:00:00") is None


def test_load_parses_ma_m(tmp_oui_db):
    """Parsuje linie MA-M (28-bit), 7 hex chars."""
    result = tmp_oui_db.lookup("F4:F5:D8:C0:00:00")
    assert result == "Google LLC"


def test_load_parses_ma_s(tmp_oui_db):
    """Parsuje linie MA-S (36-bit), 9 hex chars."""
    result = tmp_oui_db.lookup("9C:05:D6:00:00:00")
    assert result == "Ubiquiti Inc"


def test_longest_prefix_match(tmp_oui_db):
    """MA-S (9 chars) bierze pierwszenstwo przed MA-L (6 chars) dla tego samego MAC."""
    # 9C:05:D6 jest w MA-L jako... nie ma w sample. Ale 9C:05:D6:00:0 jest w MA-S = Ubiquiti Inc
    result = tmp_oui_db.lookup("9C:05:D6:00:00:00")
    assert result == "Ubiquiti Inc"


# --- lookup edge cases ---

def test_lookup_none_returns_none(tmp_oui_db):
    assert tmp_oui_db.lookup(None) is None


def test_lookup_empty_string_returns_none(tmp_oui_db):
    assert tmp_oui_db.lookup("") is None


def test_lookup_too_short_returns_none(tmp_oui_db):
    assert tmp_oui_db.lookup("00:11") is None


def test_lookup_case_insensitive(tmp_oui_db):
    """Lookup ignoruje wielkosc liter w MAC."""
    assert tmp_oui_db.lookup("00:00:0c:ff:ff:ff") == "Cisco Systems, Inc"
    assert tmp_oui_db.lookup("00:00:0C:FF:FF:FF") == "Cisco Systems, Inc"


def test_lookup_various_separators(tmp_oui_db):
    """Akceptuje MAC z rozymi separatorami: : - i brak."""
    assert tmp_oui_db.lookup("00-00-0C-01-02-03") == "Cisco Systems, Inc"
    assert tmp_oui_db.lookup("00000C010203")       == "Cisco Systems, Inc"


def test_lookup_unknown_returns_none(tmp_oui_db):
    """Nieznany OUI zwraca None, nie zgaduje."""
    assert tmp_oui_db.lookup("AA:BB:CC:DD:EE:FF") is None


# --- lazy load ---

def test_lazy_load_on_first_lookup(tmp_path):
    """lookup() triggeruje load() jesli baza nie jest zaladowana."""
    oui_l = tmp_path / "ieee_oui.txt"
    oui_l.write_text("00-1A-2B   (hex)\t\tTestVendor\n", encoding="utf-8")

    import netdoc.collector.oui_lookup as mod
    orig_dir = mod._DATA_DIR
    orig_sources = mod.IEEE_SOURCES
    mod._DATA_DIR = tmp_path
    mod.IEEE_SOURCES = [{"name": "IEEE MA-L", "url": "", "file": "ieee_oui.txt", "prefix_chars": 6}]

    db = OUIDatabase()
    assert not db._loaded
    result = db.lookup("00:1A:2B:00:00:00")
    assert db._loaded
    assert result == "TestVendor"

    mod._DATA_DIR = orig_dir
    mod.IEEE_SOURCES = orig_sources


# --- status ---

def test_status_shows_entries(tmp_oui_db):
    status = tmp_oui_db.status()
    assert status["loaded"] is True
    assert status["entries"] > 0


def test_status_needs_update_when_file_missing(tmp_path):
    """needs_update() zwraca True jesli plik nie istnieje."""
    import netdoc.collector.oui_lookup as mod
    orig = mod._DATA_DIR
    mod._DATA_DIR = tmp_path  # pusty katalog

    db = OUIDatabase()
    assert db.needs_update() is True
    mod._DATA_DIR = orig


# --- thread safety ---

def test_concurrent_lookups_safe(tmp_oui_db):
    """Rownoczesne lookup() nie powoduja bledow."""
    errors = []

    def _lookup():
        try:
            for _ in range(50):
                tmp_oui_db.lookup("00:00:0C:01:02:03")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=_lookup) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
