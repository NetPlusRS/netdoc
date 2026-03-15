"""Enterprise OID Lookup — mapowanie sysObjectID SNMP na producenta urządzenia.

Źródło danych:
  data/oid/enterprise_vendors.json — statyczny plik z ~90 głównymi vendorami.

Jak działa sysObjectID:
  Format: 1.3.6.1.4.1.<enterprise_number>.<...>
  Numer enterprise (np. 14988 = MikroTik) wystarczy do identyfikacji producenta.
  Pełne OID (np. 1.3.6.1.4.1.9.1.1045) identyfikuje konkretny model (przyszłość).
"""
import json
import logging
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DATA_FILE = Path(__file__).parent.parent.parent / "data" / "oid" / "enterprise_vendors.json"

# Prefiks prywatnych numerów enterprise w drzewie SMI
_ENTERPRISE_PREFIX = "1.3.6.1.4.1."


def _extract_enterprise_number(oid: str) -> Optional[str]:
    """Wyciąga numer enterprise z sysObjectID.

    Przykłady:
      "1.3.6.1.4.1.14988.1" -> "14988"
      ".1.3.6.1.4.1.9.1.1"  -> "9"
      "iso.org.dod..."        -> None (nieobsługiwany format)
    """
    if not oid:
        return None
    oid = oid.strip().lstrip(".")
    if oid.startswith(_ENTERPRISE_PREFIX.lstrip(".")):
        rest = oid[len(_ENTERPRISE_PREFIX.lstrip(".")):]
        parts = rest.split(".")
        if parts and parts[0].isdigit():
            return parts[0]
    return None


class OIDDatabase:
    """Baza Enterprise OID — mapuje numer enterprise na producenta."""

    def __init__(self):
        self._db: dict = {}
        self._lock = threading.RLock()
        self._loaded = False
        self._attempted = False  # True po pierwszej probie zaladowania

    def load(self) -> None:
        with self._lock:
            self._attempted = True
            try:
                with open(_DATA_FILE, encoding="utf-8") as f:
                    self._db = json.load(f)
                self._loaded = True
                logger.debug("OID database: %d enterprise wpisow", len(self._db))
            except FileNotFoundError:
                logger.warning("OID database nie znaleziona: %s", _DATA_FILE)
            except Exception as exc:
                logger.warning("Blad ladowania OID database: %s", exc)

    def _ensure_loaded(self) -> None:
        if not self._attempted:
            self.load()

    def lookup(self, oid: str) -> Optional[dict]:
        """Zwraca {vendor, description} dla podanego sysObjectID lub None.

        Przykład:
          lookup("1.3.6.1.4.1.14988.1") -> {"vendor": "MikroTik", "description": "MikroTik RouterOS"}
          lookup("1.3.6.1.4.1.99999.1") -> None
        """
        if not oid:
            return None
        self._ensure_loaded()
        enterprise_num = _extract_enterprise_number(oid)
        if not enterprise_num:
            return None
        with self._lock:
            return self._db.get(enterprise_num)

    def lookup_vendor(self, oid: str) -> Optional[str]:
        """Skrócona wersja — zwraca tylko nazwę vendora lub None."""
        result = self.lookup(oid)
        return result["vendor"] if result else None

    def status(self) -> dict:
        return {
            "loaded": self._loaded,
            "entries": len(self._db),
            "file": str(_DATA_FILE),
            "file_exists": _DATA_FILE.exists(),
        }


oid_db = OIDDatabase()
