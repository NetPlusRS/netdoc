"""Testy dla schedulera."""
from unittest.mock import patch, MagicMock
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from netdoc.storage.models import Base, SystemStatus
from netdoc.collector.scheduler import _set_status, write_config_status


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def test_set_status_creates(db):
    _set_status(db, {"k": "v"}, category="test")
    row = db.query(SystemStatus).filter_by(key="k").first()
    assert row.value == "v" and row.category == "test"


def test_set_status_updates(db):
    _set_status(db, {"k": "v1"}, category="c")
    _set_status(db, {"k": "v2"}, category="c")
    assert db.query(SystemStatus).filter_by(key="k").count() == 1
    assert db.query(SystemStatus).filter_by(key="k").first().value == "v2"


def test_set_status_multi_keys(db):
    _set_status(db, {"a": "1", "b": "2", "c": "3"}, category="cfg")
    assert db.query(SystemStatus).filter_by(category="cfg").count() == 3


def test_write_config_status(db):
    mock_oui = MagicMock()
    mock_oui._loaded = True
    mock_oui.status.return_value = {"entries": 1000}
    with patch("netdoc.collector.oui_lookup.oui_db", mock_oui), \
         patch("netdoc.collector.scheduler.oui_db", mock_oui):
        write_config_status(db)
    keys = {r.key for r in db.query(SystemStatus).all()}
    assert "scan_interval_minutes" in keys
    assert "scheduler_running" in keys


def test_write_config_status_loads_oui(db):
    mock_oui = MagicMock()
    mock_oui._loaded = False
    mock_oui.status.return_value = {"entries": 0}
    with patch("netdoc.collector.oui_lookup.oui_db", mock_oui), \
         patch("netdoc.collector.scheduler.oui_db", mock_oui):
        write_config_status(db)
    mock_oui.load.assert_called_once()
