"""Powiadomienia Telegram — wysylanie alertow przez Telegram Bot API.

Konfiguracja przechowywana w tabeli NotificationChannel, klucz "telegram":
  {"bot_token": "<token>", "chat_id": "<chat_id>"}

Uzycie:
  from netdoc.notifications.telegram import send_telegram, get_telegram_config, set_telegram_config
"""
import logging
import urllib.request
import urllib.parse
import json
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"
CHANNEL_KEY = "telegram"

# Dozwolone kolory flag na urzadzeniach
FLAG_COLORS = ("red", "orange", "yellow", "green", "blue", "purple")


def get_telegram_config(db) -> Optional[dict]:
    """Zwraca konfiguracje Telegram z DB lub None jesli nie skonfigurowano."""
    from netdoc.storage.models import NotificationChannel
    ch = db.query(NotificationChannel).filter_by(key=CHANNEL_KEY).first()
    if ch and ch.is_active and ch.config:
        token = ch.config.get("bot_token", "").strip()
        chat_id = ch.config.get("chat_id", "").strip()
        if token and chat_id:
            return {"bot_token": token, "chat_id": chat_id}
    return None


def set_telegram_config(db, bot_token: str, chat_id: str, is_active: bool = True) -> None:
    """Zapisuje konfiguracje Telegram do DB."""
    from netdoc.storage.models import NotificationChannel
    ch = db.query(NotificationChannel).filter_by(key=CHANNEL_KEY).first()
    if ch is None:
        ch = NotificationChannel(key=CHANNEL_KEY)
        db.add(ch)
    ch.config = {"bot_token": bot_token.strip(), "chat_id": chat_id.strip()}
    ch.is_active = is_active
    ch.updated_at = datetime.utcnow()
    db.commit()
    logger.info("Telegram config zapisano (chat_id=%s, active=%s)", chat_id, is_active)


def send_telegram(bot_token: str, chat_id: str, message: str, timeout: int = 10) -> bool:
    """Wysyla wiadomosc przez Telegram Bot API.

    Zwraca True jesli wyslano pomyslnie, False w przypadku bledu.
    Nie rzuca wyjatkow — bledy logowane jako WARNING.
    """
    url = TELEGRAM_API.format(token=bot_token)
    payload = json.dumps({
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            if data.get("ok"):
                logger.info("Telegram: wyslano wiadomosc (chat_id=%s)", chat_id)
                return True
            logger.warning("Telegram API blad: %s", data)
            return False
    except Exception as exc:
        logger.warning("Telegram: blad wyslania: %s", exc)
        return False


def send_monitoring_alert(db, device, alert_type: str) -> bool:
    """Wysyla alert monitorowania dla urzadzenia i zapisuje go w MonitoringAlert.

    alert_type: "offline" lub "online"
    Zwraca True jesli wyslano pomyslnie.
    """
    from netdoc.storage.models import MonitoringAlert

    hostname = device.hostname or device.ip
    if alert_type == "offline":
        icon = "\U0001F534"  # czerwone kolko
        status_text = "NIEDOSTEPNE"
    else:
        icon = "\U0001F7E2"  # zielone kolko
        status_text = "DOSTEPNE PONOWNIE"

    message = (
        f"{icon} <b>NetDoc Alert</b>\n"
        f"Urzadzenie <b>{hostname}</b> ({device.ip}) jest teraz <b>{status_text}</b>.\n"
        f"Czas: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
    )
    if device.monitor_note:
        message += f"\nNotatka: {device.monitor_note}"

    cfg = get_telegram_config(db)
    delivered = False
    if cfg:
        delivered = send_telegram(cfg["bot_token"], cfg["chat_id"], message)
    else:
        logger.info("Telegram: brak konfiguracji — alert nie wyslany dla %s", device.ip)

    alert = MonitoringAlert(
        device_id=device.id,
        alert_type=alert_type,
        message=message,
        channel="telegram" if cfg else None,
        delivered=delivered,
    )
    db.add(alert)
    db.commit()
    return delivered
