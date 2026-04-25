"""ntopng integration — REST API client for querying per-host flow data.

Config keys (SystemStatus table, category='config'):
  ntopng_enabled  — "1" / "0"
  ntopng_url      — e.g. "http://192.168.1.100:3000"
  ntopng_api_token — REST API token from ntopng Settings → API
  ntopng_ifid     — interface index (default "0")

Usage:
  from netdoc.integrations.ntopng import get_ntopng_config, get_host_flows
  cfg = get_ntopng_config(db)
  if cfg:
      flows = get_host_flows(cfg, ip="192.168.1.50")
"""
import logging
import urllib.request
import urllib.parse
import json
from typing import Optional

logger = logging.getLogger(__name__)

_TIMEOUT = 5  # seconds


def get_ntopng_config(db) -> Optional[dict]:
    """Returns ntopng config from DB or None if disabled / not configured / not Pro."""
    try:
        from netdoc_pro import PRO_ENABLED
    except ImportError:
        PRO_ENABLED = False
    if not PRO_ENABLED:
        return None
    from netdoc.storage.models import SystemStatus
    rows = {r.key: r.value for r in db.query(SystemStatus).filter(
        SystemStatus.key.in_(["ntopng_enabled", "ntopng_url", "ntopng_api_token", "ntopng_ifid"])
    ).all()}
    if rows.get("ntopng_enabled", "0") == "0":
        return None
    url = rows.get("ntopng_url", "").strip().rstrip("/")
    token = rows.get("ntopng_api_token", "").strip()
    if not url or not token:
        return None
    return {
        "url": url,
        "token": token,
        "ifid": rows.get("ntopng_ifid", "0").strip(),
    }


def _ntopng_get(cfg: dict, path: str, params: dict = None) -> Optional[dict]:
    """HTTP GET to ntopng REST API. Returns parsed JSON or None on error."""
    base = cfg["url"]
    if params:
        path = path + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(
        f"{base}{path}",
        headers={"Authorization": f"Token {cfg['token']}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        logger.warning("ntopng GET %s failed: %s", path, exc)
        return None


def get_host_flows(cfg: dict, ip: str, limit: int = 10) -> list:
    """Returns top active flows for a given host IP from ntopng.

    Returns list of dicts with keys: src_ip, dst_ip, proto, bytes, packets, info.
    Empty list on any error.
    """
    ifid = cfg.get("ifid", "0")
    # ntopng REST v2: GET /lua/rest/v2/get/host/active_flows.lua
    data = _ntopng_get(cfg, "/lua/rest/v2/get/host/active_flows.lua", {
        "ifid": ifid,
        "host": ip,
        "format": "json",
        "max_num_flows": limit,
    })
    if not data:
        return []
    # Response: {"rc": 0, "rc_str": "OK", "rsp": {"flows": [...]}}
    flows_raw = []
    if isinstance(data, dict):
        rsp = data.get("rsp", data)
        if isinstance(rsp, dict):
            flows_raw = rsp.get("flows", [])
        elif isinstance(rsp, list):
            flows_raw = rsp
    flows = []
    for f in flows_raw[:limit]:
        flows.append({
            "src_ip":  f.get("cli.ip") or f.get("src_ip", "?"),
            "dst_ip":  f.get("srv.ip") or f.get("dst_ip", "?"),
            "src_port": f.get("cli.port") or f.get("src_port"),
            "dst_port": f.get("srv.port") or f.get("dst_port"),
            "proto":   f.get("proto.l7_full") or f.get("proto.l7") or f.get("proto", "?"),
            "bytes":   f.get("bytes") if f.get("bytes") is not None else (f.get("cli2srv.bytes", 0) + f.get("srv2cli.bytes", 0)),
            "packets": f.get("packets", 0),
            "info":    f.get("info", ""),
        })
    return flows


def get_top_talkers(cfg: dict, limit: int = 10) -> list:
    """Returns top hosts by traffic volume from ntopng.

    Returns list of dicts with keys: ip, hostname, bytes_sent, bytes_rcvd, proto.
    Empty list on any error.
    """
    ifid = cfg.get("ifid", "0")
    data = _ntopng_get(cfg, "/lua/rest/v2/get/host/top_hosts.lua", {
        "ifid": ifid,
        "max_num_hosts": limit,
        "format": "json",
    })
    if not data:
        return []
    hosts_raw = []
    if isinstance(data, dict):
        rsp = data.get("rsp", data)
        if isinstance(rsp, dict):
            hosts_raw = rsp.get("hosts", [])
        elif isinstance(rsp, list):
            hosts_raw = rsp
    result = []
    for h in hosts_raw[:limit]:
        result.append({
            "ip":         h.get("ip", "?"),
            "hostname":   h.get("name") or h.get("hostname", ""),
            "bytes_sent": h.get("bytes.sent", 0),
            "bytes_rcvd": h.get("bytes.rcvd", 0),
        })
    return result
