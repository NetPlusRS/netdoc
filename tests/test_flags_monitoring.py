"""Testy flag kolorowych i monitorowania dostepnosci urzadzen."""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from netdoc.storage.models import (
    Device, DeviceType, MonitoringAlert, NotificationChannel,
)


# ── Flag color ────────────────────────────────────────────────────────────────

def test_device_flag_color_default_none(db):
    """Nowe urzadzenie ma flag_color=None."""
    d = Device(ip="10.11.0.1", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit(); db.refresh(d)
    assert d.flag_color is None


def test_device_flag_color_can_be_set(db):
    """Mozna ustawic kolorowa flage na urzadzeniu."""
    d = Device(ip="10.11.0.2", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit()
    d.flag_color = "red"
    db.commit(); db.refresh(d)
    assert d.flag_color == "red"


def test_device_flag_color_can_be_cleared(db):
    """Mozna usunac flage ustawiajac None."""
    d = Device(ip="10.11.0.3", flag_color="blue", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit()
    d.flag_color = None
    db.commit(); db.refresh(d)
    assert d.flag_color is None


def test_api_set_flag_red(client, db):
    """PATCH /api/devices/{id}/flag ustawia kolor flagi."""
    d = Device(ip="10.11.0.10", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit(); db.refresh(d)
    r = client.patch(f"/api/devices/{d.id}/flag", json={"color": "red"})
    assert r.status_code == 200
    assert r.json()["flag_color"] == "red"


def test_api_set_flag_invalid_color(client, db):
    """PATCH /api/devices/{id}/flag odrzuca nieznany kolor."""
    d = Device(ip="10.11.0.11", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit(); db.refresh(d)
    r = client.patch(f"/api/devices/{d.id}/flag", json={"color": "pink"})
    assert r.status_code == 422


def test_api_clear_flag(client, db):
    """PATCH /api/devices/{id}/flag z color=null usuwa flage."""
    d = Device(ip="10.11.0.12", flag_color="green", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit(); db.refresh(d)
    r = client.patch(f"/api/devices/{d.id}/flag", json={"color": None})
    assert r.status_code == 200
    assert r.json()["flag_color"] is None


def test_api_flag_device_not_found(client):
    """PATCH /api/devices/9999/flag zwraca 404."""
    r = client.patch("/api/devices/9999/flag", json={"color": "red"})
    assert r.status_code == 404


def test_api_flag_in_device_list(client, db):
    """GET /api/devices/ zawiera flag_color w odpowiedzi."""
    d = Device(ip="10.11.0.13", flag_color="purple", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit()
    r = client.get("/api/devices/")
    found = next((x for x in r.json() if x["ip"] == "10.11.0.13"), None)
    assert found is not None
    assert found["flag_color"] == "purple"


# ── Monitoring ────────────────────────────────────────────────────────────────

def test_device_is_monitored_default_false(db):
    """Nowe urzadzenie ma is_monitored=False."""
    d = Device(ip="10.12.0.1", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit(); db.refresh(d)
    assert d.is_monitored is False


def test_device_can_be_monitored(db):
    """Mozna wlaczyc monitorowanie urzadzenia."""
    d = Device(ip="10.12.0.2", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit()
    d.is_monitored = True
    d.monitor_note = "Krytyczny serwer"
    d.monitor_since = datetime.utcnow()
    db.commit(); db.refresh(d)
    assert d.is_monitored is True
    assert d.monitor_note == "Krytyczny serwer"
    assert d.monitor_since is not None


def test_api_enable_monitoring(client, db):
    """PATCH /api/devices/{id}/monitor wlacza monitorowanie."""
    d = Device(ip="10.12.0.10", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit(); db.refresh(d)
    r = client.patch(f"/api/devices/{d.id}/monitor",
                     json={"monitored": True, "note": "Test monitoring"})
    assert r.status_code == 200
    data = r.json()
    assert data["is_monitored"] is True
    assert data["monitor_note"] == "Test monitoring"
    assert data["monitor_since"] is not None


def test_api_disable_monitoring(client, db):
    """PATCH /api/devices/{id}/monitor wylacza monitorowanie i czysci notatke."""
    d = Device(ip="10.12.0.11", is_active=True, device_type=DeviceType.unknown,
               is_monitored=True, monitor_note="stara notatka")
    db.add(d); db.commit(); db.refresh(d)
    r = client.patch(f"/api/devices/{d.id}/monitor", json={"monitored": False})
    assert r.status_code == 200
    data = r.json()
    assert data["is_monitored"] is False
    assert data["monitor_note"] is None


def test_api_monitor_device_not_found(client):
    """PATCH /api/devices/9999/monitor zwraca 404."""
    r = client.patch("/api/devices/9999/monitor", json={"monitored": True})
    assert r.status_code == 404


def test_api_get_device_alerts_empty(client, db):
    """GET /api/devices/{id}/alerts zwraca pusta liste dla urzadzenia bez alertow."""
    d = Device(ip="10.12.0.20", is_active=True, device_type=DeviceType.unknown)
    db.add(d); db.commit(); db.refresh(d)
    r = client.get(f"/api/devices/{d.id}/alerts")
    assert r.status_code == 200
    assert r.json() == []


def test_api_get_device_alerts_not_found(client):
    """GET /api/devices/9999/alerts zwraca 404."""
    r = client.get("/api/devices/9999/alerts")
    assert r.status_code == 404


def test_monitoring_alert_model(db):
    """MonitoringAlert zapisuje sie do bazy poprawnie."""
    d = Device(ip="10.12.0.30", is_active=True, device_type=DeviceType.unknown,
               is_monitored=True)
    db.add(d); db.commit(); db.refresh(d)
    alert = MonitoringAlert(
        device_id=d.id,
        alert_type="offline",
        message="Test offline",
        channel="telegram",
        delivered=False,
    )
    db.add(alert); db.commit(); db.refresh(alert)
    assert alert.id is not None
    assert alert.alert_type == "offline"
    assert alert.delivered is False


def test_api_get_device_alerts_with_data(client, db):
    """GET /api/devices/{id}/alerts zwraca liste alertow."""
    d = Device(ip="10.12.0.31", is_active=True, device_type=DeviceType.unknown,
               is_monitored=True)
    db.add(d); db.commit(); db.refresh(d)
    a = MonitoringAlert(device_id=d.id, alert_type="offline",
                        message="Test", channel="telegram", delivered=True)
    db.add(a); db.commit()
    r = client.get(f"/api/devices/{d.id}/alerts")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["alert_type"] == "offline"
    assert data[0]["delivered"] is True


# ── Telegram helper ───────────────────────────────────────────────────────────

def test_notification_channel_model(db):
    """NotificationChannel zapisuje konfiguracje Telegram."""
    ch = NotificationChannel(
        key="telegram",
        is_active=True,
        config={"bot_token": "test_token", "chat_id": "123456"},
    )
    db.add(ch); db.commit(); db.refresh(ch)
    assert ch.key == "telegram"
    assert ch.config["bot_token"] == "test_token"


def test_set_telegram_config(db):
    """set_telegram_config zapisuje konfiguracje do DB."""
    from netdoc.notifications.telegram import set_telegram_config, get_telegram_config
    set_telegram_config(db, "mytoken123", "987654321", is_active=True)
    cfg = get_telegram_config(db)
    assert cfg is not None
    assert cfg["bot_token"] == "mytoken123"
    assert cfg["chat_id"] == "987654321"


def test_get_telegram_config_none_when_not_configured(db):
    """get_telegram_config zwraca None gdy brak konfiguracji."""
    from netdoc.notifications.telegram import get_telegram_config
    result = get_telegram_config(db)
    assert result is None


def test_get_telegram_config_none_when_inactive(db):
    """get_telegram_config zwraca None gdy kanal jest wylaczony."""
    from netdoc.notifications.telegram import set_telegram_config, get_telegram_config
    set_telegram_config(db, "token", "chat", is_active=False)
    result = get_telegram_config(db)
    assert result is None


def test_send_telegram_returns_false_on_error():
    """send_telegram zwraca False gdy siec rzuci wyjatek (nie rzuca wyjatku na zewnatrz).
    Mockujemy urllib zeby nie wykonywac prawdziwego polaczenia sieciowego."""
    from unittest.mock import patch
    import urllib.error
    from netdoc.notifications.telegram import send_telegram
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("mocked network error")):
        result = send_telegram("invalid_token", "123", "test", timeout=1)
    assert result is False


def test_send_telegram_returns_false_on_http_error():
    """send_telegram zwraca False gdy serwer zwroci HTTP 4xx/5xx."""
    from unittest.mock import patch, MagicMock
    import urllib.error
    from netdoc.notifications.telegram import send_telegram
    http_err = urllib.error.HTTPError(url="", code=401, msg="Unauthorized", hdrs=None, fp=None)
    with patch("urllib.request.urlopen", side_effect=http_err):
        result = send_telegram("bad_token", "123", "test", timeout=5)
    assert result is False


def test_send_telegram_returns_true_on_success():
    """send_telegram zwraca True gdy API odpowie {"ok": true}."""
    from unittest.mock import patch, MagicMock
    import json as _json
    from netdoc.notifications.telegram import send_telegram
    mock_resp = MagicMock()
    mock_resp.read.return_value = _json.dumps({"ok": True}).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = send_telegram("valid_token", "123", "hello", timeout=5)
    assert result is True


def test_send_monitoring_alert_without_telegram_config(db):
    """send_monitoring_alert zapisuje alert w DB nawet bez konfiguracji Telegram."""
    from netdoc.notifications.telegram import send_monitoring_alert
    d = Device(ip="10.12.0.40", is_active=False, device_type=DeviceType.unknown,
               is_monitored=True)
    db.add(d); db.commit(); db.refresh(d)
    result = send_monitoring_alert(db, d, "offline")
    assert result is False  # brak konfiguracji → False
    # Alert zostal zapisany w DB
    alert = db.query(MonitoringAlert).filter_by(device_id=d.id).first()
    assert alert is not None
    assert alert.alert_type == "offline"
    assert alert.delivered is False


def test_send_monitoring_alert_online_without_config(db):
    """send_monitoring_alert dla typu 'online' tez zapisuje alert."""
    from netdoc.notifications.telegram import send_monitoring_alert
    d = Device(ip="10.12.0.41", is_active=True, device_type=DeviceType.unknown,
               is_monitored=True, monitor_note="Serwer glowny")
    db.add(d); db.commit(); db.refresh(d)
    send_monitoring_alert(db, d, "online")
    alert = db.query(MonitoringAlert).filter_by(device_id=d.id).first()
    assert alert.alert_type == "online"


def test_flag_colors_constant():
    """FLAG_COLORS zawiera oczekiwane wartosci."""
    from netdoc.notifications.telegram import FLAG_COLORS
    for color in ("red", "orange", "yellow", "green", "blue", "purple"):
        assert color in FLAG_COLORS
