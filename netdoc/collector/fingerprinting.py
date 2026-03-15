"""Banner fingerprinting — identyfikacja vendora/modelu z nagłówków HTTP Server: i bannerów SSH.

Źródło danych:
  data/fingerprints/banners.yaml — edytowalny plik YAML z regułami dopasowania.

Reguły:
  - Dopasowanie case-insensitive (pattern musi być podstringiem bannera).
  - Reguły przetwarzane w kolejności; zwracany jest PIERWSZY pasujący wpis.
  - Wpisy z vendor=null i device_type=null są jawnie ignorowane (generic software).
"""
import logging
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DATA_FILE = Path(__file__).parent.parent.parent / "data" / "fingerprints" / "banners.yaml"


class BannerDatabase:
    """Baza sygnatur bannerów HTTP/SSH."""

    def __init__(self):
        self._http: list = []    # lista dict z kluczami: pattern, vendor, model, device_type
        self._ssh: list = []
        self._lock = threading.RLock()
        self._loaded = False
        self._attempted = False  # True po pierwszej probie zaladowania

    def load(self) -> None:
        with self._lock:
            self._attempted = True
            try:
                import yaml
                with open(_DATA_FILE, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                self._http = data.get("http_server", []) or []
                self._ssh = data.get("ssh_banner", []) or []
                self._loaded = True
                logger.debug(
                    "Banner database: %d HTTP + %d SSH reguł",
                    len(self._http), len(self._ssh),
                )
            except FileNotFoundError:
                logger.warning("Banner database nie znaleziona: %s", _DATA_FILE)
            except ImportError:
                logger.warning("PyYAML niedostepny — banner fingerprinting wylaczony")
            except Exception as exc:
                logger.warning("Blad ladowania banner database: %s", exc)

    def _ensure_loaded(self) -> None:
        if not self._attempted:
            self.load()

    def _match(self, rules: list, text: str) -> Optional[dict]:
        """Zwraca pierwszy pasujący wpis lub None."""
        text_low = text.lower()
        for rule in rules:
            pattern = rule.get("pattern", "")
            if not pattern or pattern.lower() == "xxxxxxxx":  # placeholder
                continue
            if pattern.lower() in text_low:
                # Pomijaj wpisy bez vendora — device_type bez vendora nie jest użyteczny
                if rule.get("vendor") is None:
                    continue
                return {
                    "vendor":      rule.get("vendor"),
                    "model":       rule.get("model"),
                    "device_type": rule.get("device_type"),
                }
        return None

    def fingerprint_server_header(self, server_header: str) -> Optional[dict]:
        """Identyfikuje vendora z nagłówka HTTP Server:.

        Zwraca dict {vendor, model, device_type} lub None.

        Przykłady:
          "ZyXEL-RomPager/4.51"  -> {vendor: "ZyXEL", device_type: "router", model: None}
          "Microsoft-IIS/10.0"   -> {vendor: "Microsoft", device_type: "server", model: None}
          "Apache/2.4.41"        -> None (generic, nie identyfikuje vendora)
        """
        if not server_header:
            return None
        self._ensure_loaded()
        return self._match(self._http, server_header)

    def fingerprint_ssh_banner(self, banner: str) -> Optional[dict]:
        """Identyfikuje vendora z bannera SSH (SSH-2.0-...).

        Zwraca dict {vendor, model, device_type} lub None.

        Przykłady:
          "SSH-2.0-ROSSSH"         -> {vendor: "MikroTik", model: "RouterOS", ...}
          "SSH-2.0-OpenSSH_8.9p1" -> None (generic OpenSSH, nie identyfikuje)
        """
        if not banner:
            return None
        self._ensure_loaded()
        return self._match(self._ssh, banner)

    def status(self) -> dict:
        return {
            "loaded": self._loaded,
            "http_rules": len(self._http),
            "ssh_rules": len(self._ssh),
            "file": str(_DATA_FILE),
            "file_exists": _DATA_FILE.exists(),
        }


banner_db = BannerDatabase()
