"""Wazuh integration — forward NetDoc events as syslog alerts.

Wazuh accepts syslog on UDP 514 (or configurable port) and creates alerts from them.
No auth is needed for syslog delivery — the server-side ruleset matches on program name.

Config keys (SystemStatus table, category='config'):
  wazuh_enabled   — "1" / "0"
  wazuh_host      — IP or hostname of Wazuh manager
  wazuh_port      — UDP port (default "5141", mapped in docker-compose)

Syslog format: RFC 3164 with CEF-style body so Wazuh can parse severity/event fields.
Program name: "netdoc" — add Wazuh custom ruleset to match on this.

Usage:
  from netdoc.integrations.wazuh import get_wazuh_config, send_event
  cfg = get_wazuh_config(db)
  if cfg:
      send_event(cfg, event_type="new_device", ip="192.168.1.50", hostname="switch01")
"""
import logging
import socket
import datetime
from typing import Optional

logger = logging.getLogger(__name__)

PROGRAM_NAME = "netdoc"
_TIMEOUT = 2  # seconds


def get_wazuh_config(db) -> Optional[dict]:
    """Returns Wazuh config from DB or None if disabled / not configured / not Pro."""
    try:
        from netdoc_pro import PRO_ENABLED
    except ImportError:
        PRO_ENABLED = False
    if not PRO_ENABLED:
        return None
    from netdoc.storage.models import SystemStatus
    rows = {r.key: r.value for r in db.query(SystemStatus).filter(
        SystemStatus.key.in_(["wazuh_enabled", "wazuh_host", "wazuh_port"])
    ).all()}
    if rows.get("wazuh_enabled", "0") not in ("1", "true", "yes"):
        return None
    host = rows.get("wazuh_host", "").strip()
    if not host:
        return None
    try:
        port = int(rows.get("wazuh_port", "5141"))
    except ValueError:
        port = 5141
    return {"host": host, "port": port}


def _send_syslog(cfg: dict, message: str) -> bool:
    """Sends a single syslog UDP message. Returns True on success."""
    _dt = datetime.datetime.utcnow()
    now = _dt.strftime("%b ") + str(_dt.day).rjust(2) + _dt.strftime(" %H:%M:%S")
    # RFC 3164: <priority>timestamp hostname program: message
    # Priority 14 = facility 1 (user) + severity 6 (info)
    line = f"<14>{now} netdoc-collector {PROGRAM_NAME}: {message}\n"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(_TIMEOUT)
            s.sendto(line.encode("utf-8", errors="replace"), (cfg["host"], cfg["port"]))
        return True
    except Exception as exc:
        logger.warning("Wazuh syslog send to %s:%s failed: %s", cfg["host"], cfg["port"], exc)
        return False


def send_event(cfg: dict, event_type: str, ip: str, **details) -> bool:
    """Sends a NetDoc event to Wazuh via syslog UDP.

    event_type values:
      new_device    — new device discovered on the network
      new_vuln      — new vulnerability found on a device
      port_change   — open ports changed significantly
      ip_conflict   — two devices fighting for the same IP

    details: arbitrary key=value pairs appended to the message (hostname, severity, port, …)
    """
    parts = [f"event={event_type}", f"src_ip={ip}"]
    for k, v in details.items():
        if v is not None and v != "":
            safe_v = str(v).replace(" ", "_").replace("\n", " ")
            parts.append(f"{k}={safe_v}")
    message = " ".join(parts)
    ok = _send_syslog(cfg, message)
    if ok:
        logger.debug("Wazuh event sent: %s", message)
    return ok


def send_new_device(cfg: dict, ip: str, hostname: str = "", mac: str = "",
                    vendor: str = "", device_type: str = "") -> bool:
    return send_event(cfg, "new_device", ip,
                      hostname=hostname, mac=mac, vendor=vendor, device_type=device_type)


def send_new_vuln(cfg: dict, ip: str, hostname: str = "", vuln_type: str = "",
                  severity: str = "", title: str = "", port=None) -> bool:
    return send_event(cfg, "new_vuln", ip,
                      hostname=hostname, vuln_type=vuln_type, severity=severity,
                      title=title, port=port)


def send_port_change(cfg: dict, ip: str, hostname: str = "",
                     added: str = "", removed: str = "") -> bool:
    return send_event(cfg, "port_change", ip,
                      hostname=hostname, ports_added=added, ports_removed=removed)


def send_ip_conflict(cfg: dict, ip: str, hostname: str = "",
                     old_mac: str = "", new_mac: str = "") -> bool:
    return send_event(cfg, "ip_conflict", ip,
                      hostname=hostname, old_mac=old_mac, new_mac=new_mac)


# ── Local storage (always, regardless of Wazuh config) ────────────────────────

_SEVERITY_MAP = {
    "new_device":  "info",
    "port_change": "info",
    "ip_conflict": "warning",
    "new_vuln":    "warning",
}


def store_security_event(db, device_id, event_type: str, ip: str,
                         description: str, severity: str = "",
                         details: dict | None = None) -> None:
    """Stores a security event in the local DB so it appears in NetDoc's UI.

    Called from discovery.py and worker scripts alongside (or instead of) the
    Wazuh syslog send. Does NOT require Wazuh to be configured.
    """
    from netdoc.storage.models import SecurityEvent
    if not severity:
        severity = _SEVERITY_MAP.get(event_type, "info")
    try:
        ev = SecurityEvent(
            device_id=device_id,
            event_type=event_type,
            severity=severity,
            ip=ip,
            description=description,
            details=details or {},
        )
        # Use a savepoint so a failure here does NOT roll back the caller's transaction.
        with db.begin_nested():
            db.add(ev)
        logger.debug("SecurityEvent stored: %s %s", event_type, ip)
    except Exception as exc:
        logger.warning("Failed to store SecurityEvent: %s", exc)
