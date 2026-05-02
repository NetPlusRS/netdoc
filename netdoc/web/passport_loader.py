"""Loader paszportów urządzeń — YAML → dict, cache, fuzzy matching.

Passport = wiedza NetDoc o tym co potrafi zebrać z danego modelu sprzętu.
Pliki YAML w device_passports/*.yaml są wersjonowane w git i ładowane raz przy starcie.
"""
from __future__ import annotations

import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Katalog z plikami paszportów (względem korzenia projektu)
_PASSPORT_DIR = Path(__file__).parent.parent.parent / "device_passports"

# Cache — słownik {slug: passport_dict}
_PASSPORTS: list[dict] = []
_LOADED = False


def _load_passports() -> list[dict]:
    """Wczytuje wszystkie pliki YAML z device_passports/."""
    global _LOADED, _PASSPORTS
    if _LOADED:
        return _PASSPORTS

    passports = []
    if not _PASSPORT_DIR.exists():
        logger.warning("passport_loader: katalog %s nie istnieje", _PASSPORT_DIR)
        _LOADED = True
        _PASSPORTS = passports
        return passports

    try:
        import yaml
    except ImportError:
        logger.warning("passport_loader: brak PyYAML — paszporty niedostępne")
        _LOADED = True
        _PASSPORTS = passports
        return passports

    for fpath in sorted(_PASSPORT_DIR.glob("*.yaml")):
        try:
            with open(fpath, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict):
                data["_file"] = fpath.name
                passports.append(data)
        except Exception as exc:
            logger.warning("passport_loader: błąd wczytywania %s: %s", fpath.name, exc)

    logger.info("passport_loader: wczytano %d paszportów z %s", len(passports), _PASSPORT_DIR)
    _LOADED = True
    _PASSPORTS = passports
    return passports


def _score_match(passport: dict, vendor: str, model: str, os_version: str) -> int:
    """Zwraca wynik dopasowania (0 = brak, wyższy = lepszy)."""
    score = 0
    vendor_l   = (vendor or "").lower()
    model_l    = (model or "").lower()
    os_l       = (os_version or "").lower()

    # Sprawdź vendor
    p_vendors = [v.lower() for v in (passport.get("match_vendors") or [])]
    if p_vendors:
        if not any(pv in vendor_l or vendor_l in pv for pv in p_vendors):
            return 0  # vendor nie pasuje — dyskwalifikacja
        score += 10

    # Sprawdź model keywords
    p_models = [m.lower() for m in (passport.get("match_models") or [])]
    for pm in p_models:
        if pm in model_l or pm in os_l:
            score += 5

    # Sprawdź os keywords
    p_os = [o.lower() for o in (passport.get("match_os") or [])]
    for po in p_os:
        if po in os_l or po in model_l:
            score += 3

    return score


def find_passport(vendor: Optional[str], model: Optional[str], os_version: Optional[str]) -> Optional[dict]:
    """Zwraca najlepiej pasujący paszport lub None."""
    passports = _load_passports()
    if not passports:
        return None

    best_score = 0
    best = None
    for p in passports:
        s = _score_match(p, vendor or "", model or "", os_version or "")
        if s > best_score:
            best_score = s
            best = p

    return best if best_score > 10 else None  # vendor alone is not enough — need at least one model/OS keyword


def find_passports_bulk(devices: list[dict]) -> dict[int, Optional[dict]]:
    """Batch lookup paszportów dla listy urządzeń.

    Args:
        devices: lista słowników z kluczami: id, vendor, model, os_version
    Returns:
        {device_id: passport_dict or None}
    """
    passports = _load_passports()
    result = {}
    for d in devices:
        did = d.get("id") or d.get("device_id")
        result[did] = find_passport(
            d.get("vendor"),
            d.get("model"),
            d.get("os_version"),
        )
    return result


def reload():
    """Wymusza ponowne wczytanie paszportów (np. po zmianie plików)."""
    global _LOADED
    _LOADED = False
    _load_passports()
