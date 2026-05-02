"""API dla CLI Command Reference — baza komend urządzeń per model+firmware."""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

router = APIRouter(prefix="/api/command-ref", tags=["command-ref"])

_COMMANDS_DIR = Path(__file__).parent.parent.parent.parent / "device_commands"


# ─────────────────────────────────────────────────────────────
# Loader z cache
# ─────────────────────────────────────────────────────────────

def _load_all() -> list[dict]:
    """Wczytuje wszystkie pliki YAML z device_commands/."""
    try:
        import yaml
    except ImportError:
        return []

    if not _COMMANDS_DIR.exists():
        return []

    result = []
    for fpath in sorted(_COMMANDS_DIR.glob("*.yaml")):
        if fpath.stem.endswith(".partial"):
            continue
        try:
            with open(fpath, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict):
                data["_slug"] = fpath.stem
                data["_file"] = fpath.name
                result.append(data)
        except Exception:
            pass
    return result


def _get_db() -> list[dict]:
    return _load_all()


def _slugify(model: str, firmware: str) -> str:
    def clean(s: str) -> str:
        s = s.lower().strip()
        return re.sub(r"[^a-z0-9.]+", "_", s).strip("_")
    fw_short = ".".join(firmware.split(".")[:2]) if firmware else "unknown"
    return f"{clean(model)}_{clean(fw_short)}"


def _collect_tags(tree: dict, path: str = "") -> set[str]:
    """Zbiera wszystkie unikalne tagi z całego drzewa."""
    tags: set[str] = set()
    for key, val in tree.items():
        if key.startswith("_"):
            continue
        if isinstance(val, dict):
            for t in val.get("_tags", []):
                tags.add(t)
            tags |= _collect_tags(val, path + key + " ")
    return tags


def _count_commands(tree: dict) -> int:
    """Liczy łączną liczbę komend w drzewie."""
    count = 0
    for key, val in tree.items():
        if key.startswith("_"):
            continue
        count += 1
        if isinstance(val, dict):
            count += _count_commands(val)
    return count


def _search_tree(tree: dict, query: str, path: str = "") -> list[dict]:
    """Szuka komend pasujących do query (nazwa lub opis)."""
    q = query.lower()
    results: list[dict] = []
    for key, val in tree.items():
        if key.startswith("_"):
            continue
        full_path = (path + " " + key).strip()
        desc = val.get("_desc", "") if isinstance(val, dict) else ""
        tags = val.get("_tags", []) if isinstance(val, dict) else []
        if q in full_path.lower() or q in desc.lower() or q in " ".join(tags):
            results.append({
                "path": full_path,
                "description": desc,
                "tags": tags,
            })
        if isinstance(val, dict):
            results.extend(_search_tree(val, query, full_path))
    return results


def _flatten_tree(tree: dict, path: str = "") -> list[dict]:
    """Spłaszcza drzewo do listy komend (dla eksportu / full-text search)."""
    results: list[dict] = []
    for key, val in tree.items():
        if key.startswith("_"):
            continue
        full_path = (path + " " + key).strip()
        desc = val.get("_desc", "") if isinstance(val, dict) else ""
        tags = val.get("_tags", []) if isinstance(val, dict) else []
        results.append({"path": full_path, "description": desc, "tags": tags})
        if isinstance(val, dict):
            results.extend(_flatten_tree(val, full_path))
    return results


# ─────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────

@router.get("/")
def list_refs():
    """Lista dostępnych baz komend (model + firmware)."""
    db = _get_db()
    return [
        {
            "slug": d["_slug"],
            "model": d.get("model", ""),
            "firmware": d.get("firmware", ""),
            "system": d.get("system", ""),
            "source_ip": d.get("source_ip", ""),
            "notes": d.get("notes", ""),
            "command_count": _count_commands(d.get("commands", {})),
            "tags": sorted(_collect_tags(d.get("commands", {}))),
        }
        for d in db
    ]


@router.get("/{slug}")
def get_ref(slug: str):
    """Pełne drzewo komend dla danego slug."""
    db = _get_db()
    for d in db:
        if d["_slug"] == slug:
            return {
                "slug": slug,
                "model": d.get("model", ""),
                "firmware": d.get("firmware", ""),
                "source_ip": d.get("source_ip", ""),
                "notes": d.get("notes", ""),
                "commands": d.get("commands", {}),
                "tags": sorted(_collect_tags(d.get("commands", {}))),
                "command_count": _count_commands(d.get("commands", {})),
            }
    raise HTTPException(404, f"Baza komend '{slug}' nie istnieje")


@router.get("/{slug}/search")
def search_ref(slug: str, q: str = Query(..., min_length=1)):
    """Szuka komend po nazwie, opisie lub tagu."""
    db = _get_db()
    for d in db:
        if d["_slug"] == slug:
            results = _search_tree(d.get("commands", {}), q)
            return {"slug": slug, "query": q, "count": len(results), "results": results}
    raise HTTPException(404, f"Baza komend '{slug}' nie istnieje")


@router.get("/{slug}/flat")
def flat_ref(slug: str, tag: Optional[str] = None):
    """Spłaszczona lista wszystkich komend (opcjonalnie filtrowana po tagu)."""
    db = _get_db()
    for d in db:
        if d["_slug"] == slug:
            flat = _flatten_tree(d.get("commands", {}))
            if tag:
                flat = [c for c in flat if tag in c.get("tags", [])]
            return {"slug": slug, "tag": tag, "count": len(flat), "commands": flat}
    raise HTTPException(404, f"Baza komend '{slug}' nie istnieje")
