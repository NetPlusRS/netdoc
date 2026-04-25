"""Wazuh alert reader — parses alerts.json and queries Wazuh Manager REST API.

Two data sources:
  1. /wazuh_logs/alerts/alerts.json  — mounted read-only from the wazuh_logs Docker volume.
     Contains every alert Wazuh generated, in NDJSON format (one JSON object per line).
  2. Wazuh Manager REST API at https://netdoc-wazuh:55000 — agents, SCA, vuln detection.

Config keys (SystemStatus, category='config'):
  wazuh_api_url      — e.g. "https://netdoc-wazuh:55000" (default when using bundled container)
  wazuh_api_user     — default "wazuh"
  wazuh_api_password — default "wazuh"
"""
import json
import logging
import os
import datetime
from typing import Optional

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

logger = logging.getLogger(__name__)

ALERTS_JSON_PATH = os.environ.get("WAZUH_ALERTS_PATH", "/wazuh_logs/alerts/alerts.json")
_DEFAULT_API_URL  = "https://netdoc-wazuh:55000"
_DEFAULT_API_USER = "wazuh"
_DEFAULT_API_PASS = "wazuh"

# Wazuh rule level → NetDoc severity mapping
def _level_to_severity(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 7:
        return "warning"
    return "info"


def get_wazuh_api_config(db) -> Optional[dict]:
    """Returns Wazuh API config from DB. Falls back to bundled-container defaults."""
    from netdoc.storage.models import SystemStatus
    rows = {r.key: r.value for r in db.query(SystemStatus).filter(
        SystemStatus.key.in_(["wazuh_api_url", "wazuh_api_user", "wazuh_api_password",
                               "wazuh_enabled"])
    ).all()}
    if rows.get("wazuh_enabled", "0") not in ("1", "true", "yes"):
        return None
    return {
        "url":      rows.get("wazuh_api_url", "").strip() or _DEFAULT_API_URL,
        "user":     rows.get("wazuh_api_user", "").strip() or _DEFAULT_API_USER,
        "password": rows.get("wazuh_api_password", "").strip() or _DEFAULT_API_PASS,
    }


def _get_token(cfg: dict) -> Optional[str]:
    """Authenticates with Wazuh API, returns JWT token or None."""
    try:
        import requests as _req
        r = _req.post(
            f"{cfg['url']}/security/user/authenticate",
            auth=(cfg["user"], cfg["password"]),
            verify=False,
            timeout=5,
        )
        if r.status_code == 200:
            return r.json()["data"]["token"]
        logger.warning("Wazuh API auth failed: %s %s", r.status_code, r.text[:200])
    except Exception as exc:
        logger.warning("Wazuh API auth error: %s", exc)
    return None


def get_agents(cfg: dict) -> list[dict]:
    """Returns list of Wazuh agents with status info."""
    token = _get_token(cfg)
    if not token:
        return []
    try:
        import requests as _req
        r = _req.get(
            f"{cfg['url']}/agents",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": 500},
            verify=False,
            timeout=8,
        )
        if r.status_code != 200:
            return []
        items = r.json().get("data", {}).get("affected_items", [])
        return [
            {
                "id":          a.get("id"),
                "name":        a.get("name"),
                "ip":          a.get("ip"),
                "status":      a.get("status"),
                "os_name":     (a.get("os") or {}).get("name", ""),
                "os_platform": (a.get("os") or {}).get("platform", ""),
                "version":     a.get("version", ""),
                "last_keepalive": a.get("lastKeepAlive", ""),
            }
            for a in items
        ]
    except Exception as exc:
        logger.warning("Wazuh agents fetch failed: %s", exc)
        return []


def _parse_alerts_json(
    ip_filter: Optional[str] = None,
    since_hours: int = 24,
    limit: int = 100,
    tail_bytes: int = 4 * 1024 * 1024,   # read last 4 MB to avoid loading huge file
) -> list[dict]:
    """Reads alerts.json from the shared volume, filters by IP and time window."""
    if not os.path.exists(ALERTS_JSON_PATH):
        return []

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=since_hours)
    results = []

    try:
        fsize = os.path.getsize(ALERTS_JSON_PATH)
        seek_pos = max(0, fsize - tail_bytes)

        with open(ALERTS_JSON_PATH, "rb") as fh:
            fh.seek(seek_pos)
            if seek_pos > 0:
                fh.readline()   # skip partial first line
            lines = fh.read().decode("utf-8", errors="replace").splitlines()

        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Time filter — file is chronological; reversed → newest first,
            # so once we hit an entry older than cutoff all remaining are older too.
            ts_str = alert.get("timestamp", "")
            ts_utc = None
            try:
                ts = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=datetime.timezone.utc)
                ts_utc = ts
                if ts_utc < cutoff:
                    continue
            except Exception:
                pass
            if ts_utc is None:
                continue   # skip alerts with unparseable timestamp

            # IP filter — check agent IP and data.srcip
            if ip_filter:
                agent_ip = (alert.get("agent") or {}).get("ip", "")
                src_ip   = (alert.get("data") or {}).get("srcip", "")
                if ip_filter not in (agent_ip, src_ip):
                    continue

            rule = alert.get("rule") or {}
            level = int(rule.get("level", 0))
            results.append({
                "ts":          ts_str[:19].replace("T", " "),
                "rule_id":     rule.get("id", ""),
                "rule_level":  level,
                "severity":    _level_to_severity(level),
                "description": rule.get("description", ""),
                "agent_name":  (alert.get("agent") or {}).get("name", ""),
                "agent_ip":    (alert.get("agent") or {}).get("ip", ""),
                "location":    alert.get("location", ""),
                "full_log":    alert.get("full_log", "")[:300],
                "groups":      rule.get("groups", []),
            })
            if len(results) >= limit:
                break

    except Exception as exc:
        logger.warning("Failed to parse Wazuh alerts.json: %s", exc)

    return results


def get_recent_alerts(since_hours: int = 24, limit: int = 100) -> list[dict]:
    """Returns recent Wazuh alerts from alerts.json (no IP filter)."""
    return _parse_alerts_json(since_hours=since_hours, limit=limit)


def get_alerts_for_ip(ip: str, since_hours: int = 72, limit: int = 50) -> list[dict]:
    """Returns Wazuh alerts matching a specific device IP."""
    return _parse_alerts_json(ip_filter=ip, since_hours=since_hours, limit=limit)


def alerts_file_available() -> bool:
    return os.path.exists(ALERTS_JSON_PATH)
