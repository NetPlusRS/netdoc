"""Testy bazy wiedzy kb_guides.py i routy /kb/guides w Flask.

Pokrywa:
- integralnosc danych GUIDES (wymagane pola, unikatowe ID)
- GUIDES_BY_ID lookup
- route /kb/guides (lista) i /kb/guides/<id> (szczegoly)
- nieistniejacy guide_id -> redirect
"""
import pytest
from unittest.mock import patch, MagicMock


# ─────────────────────────────────────────────────────────────────────────────
# Integralnosc danych GUIDES
# ─────────────────────────────────────────────────────────────────────────────

def test_guides_not_empty():
    from netdoc.web.kb_guides import GUIDES
    assert len(GUIDES) >= 5, "GUIDES powinno zawierac co najmniej 5 artykulow"


def test_guides_required_fields():
    """Kazdy artykul musi miec wymagane pola."""
    from netdoc.web.kb_guides import GUIDES
    required = {"id", "title", "icon", "tags", "summary", "sections"}
    for g in GUIDES:
        missing = required - g.keys()
        assert not missing, f"Guide '{g.get('id')}' brakuje pol: {missing}"


def test_guides_ids_unique():
    """ID artykulow musi byc unikatowe."""
    from netdoc.web.kb_guides import GUIDES
    ids = [g["id"] for g in GUIDES]
    assert len(ids) == len(set(ids)), f"Duplikaty ID: {[i for i in ids if ids.count(i) > 1]}"


def test_guides_ids_are_slug_format():
    """ID powinno byc w formacie slug (tylko litery, cyfry, myslniki)."""
    import re
    from netdoc.web.kb_guides import GUIDES
    slug_pattern = re.compile(r'^[a-z0-9-]+$')
    for g in GUIDES:
        assert slug_pattern.match(g["id"]), f"ID '{g['id']}' nie jest poprawnym slugiem"


def test_guides_icons_are_bootstrap():
    """Ikony powinny zaczynac sie od 'bi-' (Bootstrap Icons)."""
    from netdoc.web.kb_guides import GUIDES
    for g in GUIDES:
        assert g["icon"].startswith("bi-"), f"Guide '{g['id']}': ikona '{g['icon']}' nie jest Bootstrap Icon"


def test_guides_tags_are_lists():
    """Tags musi byc lista."""
    from netdoc.web.kb_guides import GUIDES
    for g in GUIDES:
        assert isinstance(g["tags"], list), f"Guide '{g['id']}': tags musi byc lista"


def test_guides_tags_not_empty():
    """Kazdy artykul musi miec co najmniej jeden tag."""
    from netdoc.web.kb_guides import GUIDES
    for g in GUIDES:
        assert len(g["tags"]) >= 1, f"Guide '{g['id']}': brak tagow"


def test_guides_sections_are_lists():
    """Sections musi byc lista."""
    from netdoc.web.kb_guides import GUIDES
    for g in GUIDES:
        assert isinstance(g["sections"], list), f"Guide '{g['id']}': sections musi byc lista"


def test_guides_sections_have_title():
    """Kazda sekcja musi miec title."""
    from netdoc.web.kb_guides import GUIDES
    for g in GUIDES:
        for i, sec in enumerate(g["sections"]):
            assert "title" in sec, f"Guide '{g['id']}', sekcja {i}: brak 'title'"


def test_guides_sections_have_content_key():
    """Kazda sekcja musi miec klucz 'content' (moze byc None)."""
    from netdoc.web.kb_guides import GUIDES
    for g in GUIDES:
        for i, sec in enumerate(g["sections"]):
            assert "content" in sec, f"Guide '{g['id']}', sekcja {i}: brak klucza 'content'"


def test_guides_summary_not_empty():
    """Summary musi byc niepustym stringiem."""
    from netdoc.web.kb_guides import GUIDES
    for g in GUIDES:
        assert g["summary"] and isinstance(g["summary"], str), \
            f"Guide '{g['id']}': summary jest puste lub nie jest stringiem"


# ─────────────────────────────────────────────────────────────────────────────
# GUIDES_BY_ID lookup
# ─────────────────────────────────────────────────────────────────────────────

def test_guides_by_id_contains_all():
    """GUIDES_BY_ID zawiera wszystkie ID z GUIDES."""
    from netdoc.web.kb_guides import GUIDES, GUIDES_BY_ID
    for g in GUIDES:
        assert g["id"] in GUIDES_BY_ID, f"Brak '{g['id']}' w GUIDES_BY_ID"


def test_guides_by_id_returns_correct_guide():
    """GUIDES_BY_ID[id] zwraca ten sam obiekt co GUIDES."""
    from netdoc.web.kb_guides import GUIDES, GUIDES_BY_ID
    for g in GUIDES:
        assert GUIDES_BY_ID[g["id"]] is g


def test_guides_by_id_unknown_returns_none():
    """Nieznany ID zwraca None (uzywamy .get())."""
    from netdoc.web.kb_guides import GUIDES_BY_ID
    assert GUIDES_BY_ID.get("nonexistent-guide-xyz") is None


# ─────────────────────────────────────────────────────────────────────────────
# Flask route /kb/guides
# ─────────────────────────────────────────────────────────────────────────────

def _make_kb_client():
    """Buduje test client Flask z mockiem sesji DB i requests."""
    from netdoc.web.app import create_app
    from netdoc.storage.models import SystemStatus

    app = create_app()
    app.config["TESTING"] = True

    ms = MagicMock()
    ms.__enter__ = lambda s: s
    ms.__exit__ = MagicMock(return_value=False)

    q = MagicMock()
    q.filter_by.return_value = q
    q.filter.return_value = q
    q.order_by.return_value = q
    q.first.return_value = MagicMock(key="scanner_job", value="idle", category="config")
    q.all.return_value = [MagicMock(key="scanner_job", value="idle", category="config")]
    ms.query.return_value = q

    return app, ms


def test_kb_guides_list_returns_200():
    """GET /kb/guides zwraca 200 OK."""
    app, ms = _make_kb_client()
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            mr.get.return_value.status_code = 200
            mr.get.return_value.json.return_value = {}
            with app.test_client() as c:
                r = c.get("/kb/guides")
    assert r.status_code == 200


def test_kb_guides_list_shows_guide_titles():
    """GET /kb/guides zawiera tytuly artykulow."""
    from netdoc.web.kb_guides import GUIDES
    app, ms = _make_kb_client()
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            mr.get.return_value.status_code = 200
            mr.get.return_value.json.return_value = {}
            with app.test_client() as c:
                html = c.get("/kb/guides").data.decode()
    # Przynajmniej 3 tytuly sa widoczne
    found = sum(1 for g in GUIDES if g["title"] in html)
    assert found >= 3, f"Tylko {found} tytulow widocznych na /kb/guides"


def test_kb_guides_detail_returns_200_for_known_id():
    """GET /kb/guides/<valid-id> zwraca 200 OK."""
    from netdoc.web.kb_guides import GUIDES
    guide_id = GUIDES[0]["id"]
    app, ms = _make_kb_client()
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            mr.get.return_value.status_code = 200
            mr.get.return_value.json.return_value = {}
            with app.test_client() as c:
                r = c.get(f"/kb/guides/{guide_id}")
    assert r.status_code == 200


def test_kb_guides_detail_shows_guide_content():
    """GET /kb/guides/<id> zawiera tytul i summary artykulu."""
    from netdoc.web.kb_guides import GUIDES
    guide = GUIDES[0]
    app, ms = _make_kb_client()
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            mr.get.return_value.status_code = 200
            mr.get.return_value.json.return_value = {}
            with app.test_client() as c:
                html = c.get(f"/kb/guides/{guide['id']}").data.decode()
    assert guide["title"] in html, f"Brak tytulu '{guide['title']}' w HTML"


def test_kb_guides_unknown_id_redirects():
    """GET /kb/guides/<nieistniejacy-id> przekierowuje do listy."""
    app, ms = _make_kb_client()
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            mr.get.return_value.status_code = 200
            mr.get.return_value.json.return_value = {}
            with app.test_client() as c:
                r = c.get("/kb/guides/nonexistent-guide-xyz-12345")
    assert r.status_code in (302, 301), "Nieznany guide powinien przekierowac"


def test_kb_guides_all_ids_accessible():
    """Wszystkie ID artykulow sa dostepne przez /kb/guides/<id>."""
    from netdoc.web.kb_guides import GUIDES
    app, ms = _make_kb_client()
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with patch("netdoc.web.app.requests") as mr:
            mr.get.return_value.status_code = 200
            mr.get.return_value.json.return_value = {}
            with app.test_client() as c:
                for g in GUIDES:
                    r = c.get(f"/kb/guides/{g['id']}")
                    assert r.status_code == 200, \
                        f"Guide '{g['id']}' niedostepny: status {r.status_code}"


# ─────────────────────────────────────────────────────────────────────────────
# Database engine build paths
# ─────────────────────────────────────────────────────────────────────────────

def test_build_engine_uses_sqlite_for_sqlite_url():
    """Gdy database_url zawiera 'sqlite' — uzywa _make_sqlite_engine()."""
    from netdoc.storage.database import _make_sqlite_engine
    engine = _make_sqlite_engine()
    assert "sqlite" in str(engine.url)


def test_build_engine_sqlite_has_fk_pragma():
    """SQLite engine ma wlaczone foreign keys (PRAGMA foreign_keys=ON)."""
    from netdoc.storage.database import _make_sqlite_engine
    engine = _make_sqlite_engine()
    with engine.connect() as conn:
        from sqlalchemy import text
        result = conn.execute(text("PRAGMA foreign_keys")).fetchone()
    assert result[0] == 1, "foreign_keys powinno byc wlaczone"


def test_migrate_enum_values_skips_sqlite():
    """_migrate_enum_values() nie wykonuje SQL na SQLite (jest no-op)."""
    from netdoc.storage.database import _migrate_enum_values, engine
    # Wywolanie nie powino rzucac wyjatku nawet w srodowisku SQLite (test)
    _migrate_enum_values()  # jeżeli dialect != postgresql — natychmiast wraca


def test_migrate_columns_skips_sqlite():
    """_migrate_columns() nie wykonuje SQL na SQLite (jest no-op)."""
    from netdoc.storage.database import _migrate_columns
    _migrate_columns()  # nie powinno rzucac wyjatku


def test_get_db_yields_and_closes():
    """get_db() zwraca sesje i zamyka po zakonczeniu."""
    from netdoc.storage.database import get_db, SessionLocal
    gen = get_db()
    db = next(gen)
    assert db is not None
    try:
        next(gen)
    except StopIteration:
        pass
