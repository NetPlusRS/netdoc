"""
Wspolne fixtures dla testow pytest.

Testy uzywaja SQLite in-memory — szybkie i izolowane.
Produkcja uzywa PostgreSQL (docker-compose.yml).
"""
import pytest
from unittest.mock import patch
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from netdoc.storage.models import Base
from netdoc.storage.database import get_db
from netdoc.api.main import app


@pytest.fixture(autouse=True)
def _no_fill_worker(request):
    """Blokuje uruchamianie fill workera podczas testow.

    Testy w test_screenshot_worker.py bezposrednio testuja _start_screenshot_fill_worker
    i uzywaja wlasnych patchow threading.Thread — ten fixture ich nie dotyczy.
    Pozostale testy (test_web_app, test_full_scan_indicator itp.) wolaja create_app()
    co uruchamialoby prawdziwy daemon thread laczacy sie z PostgreSQL po 60s.
    """
    if "test_screenshot_worker" in request.node.nodeid:
        yield
        return
    with patch("netdoc.web.app._start_screenshot_fill_worker"):
        yield


@pytest.fixture(scope="function")
def db_engine():
    """In-memory SQLite dla testow. StaticPool = jedna baza dla wszystkich polaczen."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    # SQLite wymaga jawnego wlaczenia foreign keys
    @event.listens_for(engine, "connect")
    def set_fk(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def db(db_engine):
    """Sesja bazy danych dla pojedynczego testu."""
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="function")
def client(db):
    """FastAPI TestClient z podmieniona baza danych (SQLite in-memory).

    init_db() jest mockowana — testy uzywaja SQLite z db_engine fixture,
    wiec migracje na PostgreSQL sa zbedne i spowalniaja caly suite.
    """
    app.dependency_overrides[get_db] = lambda: db
    with patch("netdoc.api.main.init_db"):
        with TestClient(app) as c:
            yield c
    app.dependency_overrides.clear()
