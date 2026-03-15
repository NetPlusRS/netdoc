"""
OUI Lookup — baza producentow na podstawie adresow MAC.

Zrodla danych (priorytet od najdluzszego dopasowania):
  1. IEEE MA-S (36-bit OUI, ~12k wpisow)  — najbardziej szczegolowe
  2. IEEE MA-M (28-bit OUI, ~5k wpisow)
  3. IEEE MA-L (24-bit OUI, ~37k wpisow)  — standardowe OUI
  4. manuf (Wireshark, ~45k wpisow)        — fallback, przyjazne nazwy

Aktualizacja:
  - Bazy IEEE pobierane automatycznie raz na 30 dni
  - Pliki w data/oui/ wzgledem katalogu projektu
"""
import re
import logging
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent.parent.parent / "data" / "oui"

IEEE_SOURCES = [
    {"name": "IEEE MA-L", "url": "https://standards-oui.ieee.org/oui/oui.txt",     "file": "ieee_oui.txt",   "prefix_chars": 6},
    {"name": "IEEE MA-M", "url": "https://standards-oui.ieee.org/oui28/mam.txt",    "file": "ieee_mam.txt",   "prefix_chars": 7},
    {"name": "IEEE MA-S", "url": "https://standards-oui.ieee.org/oui36/oui36.txt",  "file": "ieee_oui36.txt", "prefix_chars": 9},
]

_IEEE_LINE_RE = re.compile(
    r"^([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2})+(?:-[0-9A-Fa-f])?)"
    r"\s+\(hex\)\s+(.+)$"
)


class OUIDatabase:
    def __init__(self):
        self._db: dict = {}
        self._lock = threading.RLock()
        self._loaded = False

    def _parse_ieee_file(self, filepath: Path) -> int:
        count = 0
        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                for line in f:
                    m = _IEEE_LINE_RE.match(line)
                    if m:
                        prefix = m.group(1).replace("-", "").lower()
                        vendor = m.group(2).strip()
                        if prefix and vendor and vendor != "PRIVATE":
                            self._db[prefix] = vendor
                            count += 1
        except Exception as exc:
            logger.warning("Blad parsowania %s: %s", filepath.name, exc)
        return count

    def _load_manuf_fallback(self) -> int:
        count = 0
        try:
            import manuf
            p = manuf.MacParser()
            for mac_key, vendor_data in p.manuf_dict.items():
                key = mac_key.replace(":", "").lower()
                if key not in self._db:
                    vendor = vendor_data[0] if isinstance(vendor_data, (list, tuple)) else vendor_data
                    if vendor:
                        self._db[key] = str(vendor)
                        count += 1
        except Exception as exc:
            logger.debug("manuf fallback niedostepny: %s", exc)
        return count

    def load(self) -> None:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        with self._lock:
            self._db.clear()
            ieee_total = 0
            for source in reversed(IEEE_SOURCES):
                fpath = _DATA_DIR / source["file"]
                if fpath.exists():
                    n = self._parse_ieee_file(fpath)
                    ieee_total += n
                    logger.debug("OUI %s: %d wpisow", source["name"], n)
            manuf_n = self._load_manuf_fallback()
            self._loaded = len(self._db) > 0
            logger.info("OUI database: %d wpisow (%d IEEE + %d manuf)", len(self._db), ieee_total, manuf_n)

    def lookup(self, mac: Optional[str]) -> Optional[str]:
        if not mac:
            return None
        if not self._loaded:
            self.load()
        if not self._loaded:
            return None
        clean = re.sub(r"[:\-\.]", "", mac).lower()
        if len(clean) < 6:
            return None
        with self._lock:
            for prefix_len in (9, 7, 6):
                if len(clean) >= prefix_len:
                    vendor = self._db.get(clean[:prefix_len])
                    if vendor:
                        return vendor
        return None

    _HEADERS = {
        "User-Agent": "Mozilla/5.0 (compatible; OUI-Lookup/1.0; +https://github.com/netdoc)"
    }

    def update(self, timeout: int = 30) -> dict:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        results = {}
        for source in IEEE_SOURCES:
            fpath = _DATA_DIR / source["file"]
            try:
                logger.info("Pobieranie %s ...", source["name"])
                resp = requests.get(source["url"], timeout=timeout, stream=True,
                                    headers=self._HEADERS)
                resp.raise_for_status()
                fpath.write_bytes(resp.content)
                size_kb = len(resp.content) // 1024
                logger.info("%s: pobrano %d KB", source["name"], size_kb)
                results[source["name"]] = {"ok": True, "size_kb": size_kb}
            except Exception as exc:
                logger.warning("Blad pobierania %s: %s", source["name"], exc)
                results[source["name"]] = {"ok": False, "error": str(exc)}
        if any(v["ok"] for v in results.values()):
            self.load()
        return results

    def needs_update(self, max_age_days: int = 30) -> bool:
        for source in IEEE_SOURCES:
            fpath = _DATA_DIR / source["file"]
            if not fpath.exists():
                return True
            age = datetime.now() - datetime.fromtimestamp(fpath.stat().st_mtime)
            if age > timedelta(days=max_age_days):
                return True
        return False

    def status(self) -> dict:
        files = {}
        for source in IEEE_SOURCES:
            fpath = _DATA_DIR / source["file"]
            if fpath.exists():
                age = datetime.now() - datetime.fromtimestamp(fpath.stat().st_mtime)
                files[source["name"]] = {
                    "exists": True,
                    "age_days": round(age.total_seconds() / 86400, 1),
                    "size_kb": fpath.stat().st_size // 1024,
                }
            else:
                files[source["name"]] = {"exists": False}
        return {
            "loaded": self._loaded,
            "entries": len(self._db),
            "needs_update": self.needs_update(),
            "files": files,
        }


oui_db = OUIDatabase()
