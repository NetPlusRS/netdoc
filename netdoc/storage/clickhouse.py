"""ClickHouse client — singleton dla zapytań do netdoc_logs.

Używa clickhouse-connect (HTTP/8123) — nie wymaga dodatkowej konfiguracji sieci,
łączy się przez ten sam port co Grafana i Vector.

Lazy init: połączenie nawiązywane przy pierwszym zapytaniu.
"""
import logging
import os
import threading
from typing import Any

logger = logging.getLogger(__name__)

_client = None
_client_lock = threading.Lock()


def _get_client():
    global _client
    if _client is not None:
        return _client
    with _client_lock:
        if _client is not None:  # double-checked locking
            return _client
        try:
            import clickhouse_connect
            host     = os.getenv("CLICKHOUSE_HOST", "netdoc-clickhouse")
            port     = int(os.getenv("CLICKHOUSE_HTTP_PORT", "8123"))
            user     = os.getenv("CLICKHOUSE_USER", "netdoc")
            password = os.getenv("CLICKHOUSE_PASSWORD", "netdoc")
            _client = clickhouse_connect.get_client(
                host=host,
                port=port,
                username=user,
                password=password,
                database="netdoc_logs",
                connect_timeout=5,
                send_receive_timeout=30,
            )
            logger.info("ClickHouse: połączono z %s:%s", host, port)
        except Exception as exc:
            logger.warning("ClickHouse niedostępny: %s", exc)
            raise
        return _client


def query_syslog(
    device_id: int | None = None,
    src_ip: str | None = None,
    hostname: str | None = None,
    severity_max: int | None = None,
    program: str | None = None,
    search: str | None = None,
    since_hours: int = 24,
    limit: int = 200,
    offset: int = 0,
    pro: bool = False,
) -> list[dict[str, Any]]:
    """Zwraca logi syslog z ClickHouse.

    Parametry:
        device_id    — filtruj po device_id (0 = nieznane)
        src_ip       — filtruj po IP źródłowym (alternatywa dla device_id)
        hostname     — filtruj po hostname z nagłówka syslog (obejście Docker NAT)
        severity_max — maksymalny poziom (0=EMERG, 7=DEBUG); np. 3 = ERROR i poważniejsze
        program      — filtruj po nazwie procesu (LIKE %program%)
        search       — wyszukiwanie w treści wiadomości (ILIKE; Pro: przeszukuje cały zakres)
        since_hours  — zakres czasu wstecz (domyślnie 24h)
        limit        — max wierszy w odpowiedzi (Free: max 1000, Pro: max 5000)
        offset       — pomijaj pierwsze N wierszy (paginacja; Pro only)
        pro          — True = zniesione limity Free
    """
    max_limit = 5000 if pro else 1000
    max_hours = 24 * 365 if pro else 24 * 30
    limit = min(limit, max_limit)
    since_hours = max(1, min(since_hours, max_hours))
    offset = max(0, offset) if pro else 0

    where = ["timestamp >= now() - INTERVAL {since_hours:UInt32} HOUR"]
    params: dict[str, Any] = {"since_hours": since_hours, "limit": limit}

    if device_id is not None:
        where.append("device_id = {device_id:UInt32}")
        params["device_id"] = device_id
    if src_ip:
        where.append("src_ip = {src_ip:String}")
        params["src_ip"] = src_ip
    if hostname:
        where.append("hostname = {hostname:String}")
        params["hostname"] = hostname
    if severity_max is not None:
        where.append("severity <= {severity_max:UInt8}")
        params["severity_max"] = severity_max
    if program:
        where.append("program ILIKE {program:String}")
        params["program"] = f"%{program}%"
    if search:
        where.append("message ILIKE {search:String}")
        params["search"] = f"%{search}%"

    sql = (
        "SELECT timestamp, src_ip, device_id, hostname, facility, severity, program, message"
        " FROM netdoc_logs.syslog"
        " WHERE " + " AND ".join(where) +
        " ORDER BY timestamp DESC"
        " LIMIT {limit:UInt32}"
        + (" OFFSET {offset:UInt32}" if offset else "")
    )
    if offset:
        params["offset"] = offset

    client = _get_client()
    result = client.query(sql, parameters=params)

    cols = result.column_names
    return [dict(zip(cols, row)) for row in result.result_rows]


def get_syslog_retention_days() -> int:
    """Zwraca aktualny TTL tabeli syslog w dniach (domyślnie 30)."""
    try:
        result = _get_client().query(
            "SELECT toInt32(extract(toString(engine_full), 'toIntervalDay\\((\\d+)\\)')) AS days"
            " FROM system.tables WHERE database='netdoc_logs' AND name='syslog'"
        )
        if result.result_rows:
            return int(result.result_rows[0][0]) or 30
    except Exception as exc:
        logger.warning("get_syslog_retention_days failed: %s", exc)
    return 30


def set_syslog_retention_days(days: int) -> None:
    """Zmienia TTL tabeli syslog (PRO). Dozwolony zakres: 7–365 dni."""
    if not isinstance(days, int):
        raise TypeError(f"days must be int, got {type(days).__name__}")
    days = max(7, min(365, days))
    _get_client().command(
        f"ALTER TABLE netdoc_logs.syslog MODIFY TTL toDateTime(timestamp) + toIntervalDay({days})"
    )
    logger.info("Syslog TTL zmieniony na %d dni", days)


def insert_ping_batch(rows: list[tuple]) -> None:
    """Wstawia batch wyników pingów do device_ping.

    rows: lista krotek (ts: datetime, ip: str, rtt_ms: float, is_up: int)
    Wywołuj co cykl ping-workera (nie per każdy ping — batch!).
    """
    if not rows:
        return
    try:
        _get_client().insert(
            "netdoc_logs.device_ping",
            rows,
            column_names=["ts", "ip", "rtt_ms", "is_up"],
        )
    except Exception as exc:
        logger.warning("insert_ping_batch failed (%d rows): %s", len(rows), exc)


def query_ping_history(
    ip: str | None = None,
    device_id: int | None = None,
    since_hours: int = 24,
    step_minutes: int = 5,
) -> list[dict]:
    """Zwraca zagregowaną historię pingów (avg RTT, % dostępności) per okno czasowe.

    step_minutes: granularność agregacji (domyślnie 5 min)
    Zwraca listę słowników: {bucket, avg_rtt_ms, uptime_pct, total}
    """
    where = ["ts >= now() - INTERVAL {since_hours:UInt32} HOUR"]
    params: dict = {"since_hours": since_hours, "step": step_minutes * 60}
    if ip:
        where.append("ip = {ip:String}")
        params["ip"] = ip
    elif device_id is not None:
        where.append("device_id = {device_id:UInt32}")
        params["device_id"] = device_id

    sql = (
        "SELECT"
        "  toStartOfInterval(ts, toIntervalSecond({step:UInt32})) AS bucket,"
        "  ifNull(round(avgIf(rtt_ms, is_up = 1), 2), 0.0)        AS avg_rtt_ms,"
        "  round(100.0 * countIf(is_up = 1) / count(), 1)         AS uptime_pct,"
        "  count()                                                  AS total"
        " FROM netdoc_logs.device_ping"
        " WHERE " + " AND ".join(where) +
        " GROUP BY bucket ORDER BY bucket"
    )
    try:
        result = _get_client().query(sql, parameters=params)
        cols = result.column_names
        return [dict(zip(cols, row)) for row in result.result_rows]
    except Exception as exc:
        logger.warning("query_ping_history failed: %s", exc)
        return []


def query_ping_stats(
    ip: str | None = None,
    device_id: int | None = None,
    since_hours: int = 24,
) -> dict:
    """Zwraca statystyki pingów: avg/min/max RTT, uptime%, liczba pomiarów."""
    where = ["ts >= now() - INTERVAL {since_hours:UInt32} HOUR"]
    params: dict = {"since_hours": since_hours}
    if ip:
        where.append("ip = {ip:String}")
        params["ip"] = ip
    elif device_id is not None:
        where.append("device_id = {device_id:UInt32}")
        params["device_id"] = device_id

    sql = (
        "SELECT"
        "  round(avgIf(rtt_ms, is_up=1), 2)    AS avg_rtt_ms,"
        "  round(minIf(rtt_ms, is_up=1), 2)    AS min_rtt_ms,"
        "  round(maxIf(rtt_ms, is_up=1), 2)    AS max_rtt_ms,"
        "  round(100.0*countIf(is_up=1)/count(),1) AS uptime_pct,"
        "  count()                              AS total"
        " FROM netdoc_logs.device_ping"
        " WHERE " + " AND ".join(where)
    )
    try:
        result = _get_client().query(sql, parameters=params)
        if result.result_rows:
            cols = result.column_names
            return dict(zip(cols, result.result_rows[0]))
    except Exception as exc:
        logger.warning("query_ping_stats failed: %s", exc)
    return {"avg_rtt_ms": None, "min_rtt_ms": None, "max_rtt_ms": None, "uptime_pct": None, "total": 0}


_METRICS_TABLE_CREATED = False


def _ensure_metrics_table() -> None:
    """Tworzy tabele device_metrics jesli nie istnieje (lazy-init, wywolywane przy starcie workera)."""
    global _METRICS_TABLE_CREATED
    if _METRICS_TABLE_CREATED:
        return
    try:
        _get_client().command("""
            CREATE TABLE IF NOT EXISTS netdoc_logs.device_metrics
            (
                ts        DateTime                  COMMENT 'Czas pomiaru (UTC)',
                device_id UInt32                    COMMENT 'ID urzadzenia z NetDoc',
                if_index  UInt32                    COMMENT 'ifIndex (0 = metryka calego urzadzenia)',
                metric    LowCardinality(String)    COMMENT 'Nazwa metryki: in_octets, out_octets, in_errors...',
                value     Float64                   COMMENT 'Wartosc numeryczna'
            )
            ENGINE = MergeTree()
            PARTITION BY toYYYYMM(ts)
            ORDER BY (device_id, if_index, metric, ts)
            TTL toDateTime(ts) + INTERVAL 90 DAY
            SETTINGS index_granularity = 8192
        """)
        # Migracja: UInt16 → UInt32 dla ifIndex (ifIndex może przekraczać 65535 na IOS-XR/Juniper)
        try:
            _get_client().command(
                "ALTER TABLE netdoc_logs.device_metrics"
                " MODIFY COLUMN if_index UInt32"
            )
        except Exception:
            pass  # ignoruj jeśli już UInt32 lub brak uprawnień
        _METRICS_TABLE_CREATED = True
        logger.info("ClickHouse: tabela device_metrics gotowa")
    except Exception as exc:
        logger.warning("_ensure_metrics_table failed: %s", exc)


def insert_if_metrics(rows: list[tuple]) -> None:
    """Wstawia batch metryk interfejsow do device_metrics.

    rows: lista krotek (ts: datetime, device_id: int, if_index: int, metric: str, value: float)
    Wywolywane co cykl SNMP workera — batch, nie per-wiersz.
    """
    if not rows:
        return
    try:
        _get_client().insert(
            "netdoc_logs.device_metrics",
            rows,
            column_names=["ts", "device_id", "if_index", "metric", "value"],
        )
    except Exception as exc:
        logger.warning("insert_if_metrics failed (%d rows): %s", len(rows), exc)


def query_if_metrics_history(
    device_id: int,
    if_index: int,
    metric: str,
    since_hours: int = 24,
    step_minutes: int = 5,
) -> list[dict]:
    """Zwraca zagregowaną historię prędkości interfejsu (bajty/s) per okno czasowe.

    Dla liczników kumulatywnych (octets_hc/octets): oblicza pochodną:
      delta = max(value_w_bucket) - max(value_w_poprzednim_bucket)
      rate  = delta / krok_sekundy  [bajty/s]
    Zwraca listę słowników: {bucket, avg_value, max_value}
    avg_value = max_value = bytes/s (identyczne — dla kompatybilności z API)
    Uwaga: pierwszy bucket zawsze 0 (brak poprzedniego punktu referencyjnego).
    """
    params: dict = {
        "device_id":   device_id,
        "if_index":    if_index,
        "metric":      metric,
        "since_hours": since_hours,
        "step":        step_minutes * 60,
    }
    # Oblicza maksymalną wartość licznika per bucket, potem różnicę między
    # sąsiednimi bucketami dzieloną przez krok [s] → bytes/s.
    # Używa lagInFrame() (window function) zamiast neighbor() — neighbor() jest
    # deprecated/wyłączony w ClickHouse 24.8+ (allow_deprecated_error_prone_window_functions=0).
    sql = (
        "SELECT"
        "  bucket,"
        "  round(if(prev_max >= 0 AND cur_max >= prev_max,"
        "     (cur_max - prev_max) / {step:Float64}, 0), 2) AS avg_value,"
        "  round(if(prev_max >= 0 AND cur_max >= prev_max,"
        "     (cur_max - prev_max) / {step:Float64}, 0), 2) AS max_value"
        " FROM ("
        "  SELECT bucket, cur_max,"
        "    lagInFrame(cur_max, 1, toFloat64(-1))"
        "      OVER (ORDER BY bucket ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)"
        "      AS prev_max"
        "  FROM ("
        "    SELECT"
        "      toStartOfInterval(ts, toIntervalSecond({step:UInt32})) AS bucket,"
        "      max(value) AS cur_max"
        "    FROM netdoc_logs.device_metrics"
        "    WHERE device_id = {device_id:UInt32}"
        "      AND if_index  = {if_index:UInt32}"
        "      AND metric    = {metric:String}"
        "      AND ts >= now() - INTERVAL {since_hours:UInt32} HOUR"
        "    GROUP BY bucket"
        "    ORDER BY bucket"
        "  )"
        " )"
        " ORDER BY bucket"
    )
    try:
        result = _get_client().query(sql, parameters=params)
        cols = result.column_names
        return [dict(zip(cols, row)) for row in result.result_rows]
    except Exception as exc:
        logger.warning("query_if_metrics_history failed: %s", exc)
        return []


def query_if_current_rates(device_id: int, since_minutes: int = 10) -> list[dict]:
    """Zwraca biezace predkosci (bps) per interfejs dla danego urzadzenia.

    Oblicza roznice ostatnich dwoch pomiarow in_octets_hc/out_octets_hc (lub 32-bit).
    Zwraca liste: {if_index, in_bps, out_bps, in_errors, out_errors, in_discards, out_discards}
    Uwaga: wartosc ujemna oznacza counter wrap — klient powinien to ignorowac.
    """
    params: dict = {"device_id": device_id, "since_minutes": since_minutes}
    sql = (
        "SELECT"
        "  if_index,"
        "  metric,"
        "  argMax(value, ts) AS last_val,"
        "  argMin(value, ts) AS first_val,"
        "  max(ts) AS last_ts,"
        "  min(ts) AS first_ts"
        " FROM netdoc_logs.device_metrics"
        " WHERE device_id = {device_id:UInt32}"
        "   AND ts >= now() - INTERVAL {since_minutes:UInt32} MINUTE"
        "   AND metric IN ('in_octets_hc','out_octets_hc','in_octets','out_octets',"
        "                  'in_errors','out_errors','in_discards','out_discards')"
        " GROUP BY if_index, metric"
    )
    try:
        result = _get_client().query(sql, parameters=params)
        rows = {}
        for if_index, metric, last_val, first_val, last_ts, first_ts in result.result_rows:
            dt = (last_ts - first_ts).total_seconds()
            if dt <= 0:
                continue
            diff = last_val - first_val
            rate = diff / dt
            rows.setdefault(if_index, {})[metric] = rate

        out = []
        for if_index, metrics in rows.items():
            in_bps  = metrics.get("in_octets_hc",  metrics.get("in_octets",  0.0)) * 8
            out_bps = metrics.get("out_octets_hc", metrics.get("out_octets", 0.0)) * 8
            out.append({
                "if_index":     if_index,
                "in_bps":       max(0.0, in_bps),
                "out_bps":      max(0.0, out_bps),
                "in_errors":    metrics.get("in_errors",   0.0),
                "out_errors":   metrics.get("out_errors",  0.0),
                "in_discards":  metrics.get("in_discards", 0.0),
                "out_discards": metrics.get("out_discards",0.0),
            })
        return out
    except Exception as exc:
        logger.warning("query_if_current_rates failed: %s", exc)
        return []


def query_error_totals(device_id: int, hours: int = 24) -> dict[int, float]:
    """Łączna liczba błędów (in+out) per interfejs w ostatnich `hours` godzinach.

    Używa max-min (counter monotoniczny) — ignoruje resety licznika (<0 → 0).
    Zwraca {if_index: total_errors}.
    """
    params = {"device_id": device_id, "hours": hours}
    sql = (
        "SELECT if_index, metric,"
        "       greatest(0, max(value) - min(value)) AS total"
        " FROM netdoc_logs.device_metrics"
        " WHERE device_id = {device_id:UInt32}"
        "   AND ts >= now() - INTERVAL {hours:UInt32} HOUR"
        "   AND metric IN ('in_errors', 'out_errors')"
        " GROUP BY if_index, metric"
    )
    try:
        result = _get_client().query(sql, parameters=params)
        totals: dict[int, float] = {}
        for if_index, _, total in result.result_rows:
            totals[if_index] = totals.get(if_index, 0.0) + float(total)
        return totals
    except Exception as exc:
        logger.warning("query_error_totals(%d, %dh) failed: %s", device_id, hours, exc)
        return {}


def query_resource_history(device_id: int, hours: int = 24, step_minutes: int = 10) -> list[dict]:
    """Zwraca historię CPU i pamięci dla urządzenia (if_index=0) z device_metrics.

    Zwraca listę: {bucket: str, cpu_percent: float|None, mem_used_pct: float|None}
    """
    params = {
        "device_id":   device_id,
        "since_hours": hours,
        "step":        step_minutes * 60,
    }
    sql = (
        "SELECT"
        "  toStartOfInterval(ts, INTERVAL {step:UInt32} SECOND) AS bucket,"
        "  metric,"
        "  avg(value) AS avg_val"
        " FROM netdoc_logs.device_metrics"
        " WHERE device_id = {device_id:UInt32}"
        "   AND if_index = 0"
        "   AND ts >= now() - INTERVAL {since_hours:UInt32} HOUR"
        "   AND metric IN ('cpu_percent', 'mem_used_pct')"
        " GROUP BY bucket, metric"
        " ORDER BY bucket"
    )
    try:
        result = _get_client().query(sql, parameters=params)
        # Konwertuj do {bucket_str: {metric: value}}
        buckets: dict[str, dict] = {}
        for bucket, metric, avg_val in result.result_rows:
            key = bucket.isoformat() if hasattr(bucket, "isoformat") else str(bucket)
            buckets.setdefault(key, {})[metric] = round(float(avg_val), 1)
        out = []
        for key in sorted(buckets):
            row = buckets[key]
            out.append({
                "bucket":       key,
                "cpu_percent":  row.get("cpu_percent"),
                "mem_used_pct": row.get("mem_used_pct"),
            })
        return out
    except Exception as exc:
        logger.warning("query_resource_history(%d) failed: %s", device_id, exc)
        return []


def count_syslog_by_severity(device_id: int, since_hours: int = 24) -> dict[int, int]:
    """Zlicza logi per severity dla jednego urządzenia (do badge'ów w UI)."""
    sql = (
        "SELECT severity, count() AS cnt"
        " FROM netdoc_logs.syslog"
        " WHERE device_id = {device_id:UInt32}"
        "   AND timestamp >= now() - INTERVAL {since_hours:UInt32} HOUR"
        " GROUP BY severity"
        " ORDER BY severity"
    )
    try:
        result = _get_client().query(sql, parameters={"device_id": device_id, "since_hours": since_hours})
        return {row[0]: row[1] for row in result.result_rows}
    except Exception as exc:
        logger.warning("count_syslog_by_severity failed: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Broadcast / multicast traffic analytics
# ---------------------------------------------------------------------------

_BCAST_METRICS_IN  = ("in_bcast_pkts", "in_mcast_pkts", "in_nucast_pkts", "passive_bcast_pkts")
_BCAST_METRICS_OUT = ("out_bcast_pkts", "out_mcast_pkts", "out_nucast_pkts")


def query_broadcast_top_devices(since_hours: int = 24, limit: int = 30) -> list[dict]:
    """Top-N urządzeń wg łącznego ruchu broadcast+multicast z ClickHouse.

    Dla urządzeń z osobnymi licznikami (in_bcast_pkts + in_mcast_pkts) używa ich sumy.
    Dla urządzeń ze starszym in_nucast_pkts (łączony bcast+mcast) używa tego jako fallback.
    passive_bcast_pkts jest zapisywane jako delty co 30s (nie cumulative) — używa sum().
    Zwraca: [{device_id, in_bcast, out_bcast, in_mcast, out_mcast, in_nucast, out_nucast, passive, total_in}]
    """
    # passive_bcast_pkts zapisywane jako 30s delty — wymaga sum() zamiast max()-min()
    snmp_metrics = tuple(m for m in _BCAST_METRICS_IN + _BCAST_METRICS_OUT
                         if m != "passive_bcast_pkts")
    snmp_tuple = "(" + ",".join(f"'{m}'" for m in snmp_metrics) + ")"
    params = {"since_hours": since_hours}
    client = _get_client()

    sql_snmp = (
        f"SELECT device_id, metric,"
        f"  greatest(0, max(value) - min(value)) AS delta"
        f" FROM netdoc_logs.device_metrics"
        f" WHERE ts >= now() - INTERVAL {{since_hours:UInt32}} HOUR"
        f"   AND metric IN {snmp_tuple}"
        f" GROUP BY device_id, if_index, metric"
    )
    sql_passive = (
        f"SELECT device_id, sum(value) AS total"
        f" FROM netdoc_logs.device_metrics"
        f" WHERE ts >= now() - INTERVAL {{since_hours:UInt32}} HOUR"
        f"   AND metric = 'passive_bcast_pkts'"
        f" GROUP BY device_id"
    )
    try:
        per_device: dict[int, dict[str, float]] = {}

        for device_id, metric, delta in client.query(sql_snmp, parameters=params).result_rows:
            row = per_device.setdefault(int(device_id), {m: 0.0 for m in snmp_metrics + ("passive_bcast_pkts",)})
            row[metric] += float(delta)

        for device_id, total in client.query(sql_passive, parameters=params).result_rows:
            did = int(device_id)
            per_device.setdefault(did, {m: 0.0 for m in snmp_metrics + ("passive_bcast_pkts",)})
            per_device[did]["passive_bcast_pkts"] = float(total)

        out = []
        for device_id, row in per_device.items():
            # Prefer bcast+mcast (newer, granular) when available; fall back to nucast.
            # Avoids double-counting on mixed devices where some interfaces report both sets.
            if row.get("in_bcast_pkts", 0) > 0 or row.get("in_mcast_pkts", 0) > 0:
                total_in = row.get("in_bcast_pkts", 0) + row.get("in_mcast_pkts", 0) + row.get("passive_bcast_pkts", 0)
            else:
                total_in = row.get("in_nucast_pkts", 0) + row.get("passive_bcast_pkts", 0)
            out.append({
                "device_id":    device_id,
                "in_bcast":     row.get("in_bcast_pkts", 0.0),
                "out_bcast":    row.get("out_bcast_pkts", 0.0),
                "in_mcast":     row.get("in_mcast_pkts", 0.0),
                "out_mcast":    row.get("out_mcast_pkts", 0.0),
                "in_nucast":    row.get("in_nucast_pkts", 0.0),
                "out_nucast":   row.get("out_nucast_pkts", 0.0),
                "passive_pkts": row.get("passive_bcast_pkts", 0.0),
                "total_in":     total_in,
            })
        out.sort(key=lambda r: r["total_in"], reverse=True)
        return out[:limit]
    except Exception as exc:
        logger.warning("query_broadcast_top_devices failed: %s", exc)
        return []


def query_broadcast_history(device_id: int, since_hours: int = 24, step_minutes: int = 5) -> list[dict]:
    """Historia ruchu broadcast+multicast per urządzenie (wszystkie interfejsy łącznie).

    Zwraca serię czasową: [{bucket, in_bcast_rate, out_bcast_rate, in_mcast_rate, out_mcast_rate, ...}]
    SNMP metryki = pkts/s (pochodna licznika kumulatywnego via lagInFrame).
    passive_bcast_pkts = pkts/s (dane zapisywane jako delty 30s, dzielone przez step).
    """
    snmp_metrics = tuple(m for m in _BCAST_METRICS_IN + _BCAST_METRICS_OUT
                         if m != "passive_bcast_pkts")
    metrics_tuple = "(" + ",".join(f"'{m}'" for m in snmp_metrics) + ")"
    step_sec = step_minutes * 60
    params = {
        "device_id":   device_id,
        "since_hours": since_hours,
        "step_sec":    step_sec,          # UInt32 — used in toIntervalSecond()
        "step_f":      float(step_sec),   # Float64 — used in rate division
    }
    sql_snmp = (
        f"SELECT bucket, metric, prev_max, cur_max, step"
        f" FROM ("
        f"  SELECT bucket, metric,"
        f"    sum_max AS cur_max,"
        f"    lagInFrame(sum_max, 1, toFloat64(-1))"
        f"      OVER (PARTITION BY metric ORDER BY bucket"
        f"            ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) AS prev_max,"
        f"    {{step_f:Float64}} AS step"
        f"  FROM ("
        f"    SELECT bucket, metric, sum(max_val) AS sum_max"
        f"    FROM ("
        f"      SELECT"
        f"        toStartOfInterval(ts, toIntervalSecond({{step_sec:UInt32}})) AS bucket,"
        f"        if_index, metric,"
        f"        max(value) AS max_val"
        f"      FROM netdoc_logs.device_metrics"
        f"      WHERE device_id = {{device_id:UInt32}}"
        f"        AND ts >= now() - INTERVAL {{since_hours:UInt32}} HOUR"
        f"        AND metric IN {metrics_tuple}"
        f"      GROUP BY bucket, if_index, metric"
        f"    )"
        f"    GROUP BY bucket, metric"
        f"  )"
        f" )"
        f" ORDER BY bucket"
    )
    sql_passive = (
        f"SELECT toStartOfInterval(ts, toIntervalSecond({{step_sec:UInt32}})) AS bucket,"
        f"       sum(value) / {{step_f:Float64}} AS rate"
        f" FROM netdoc_logs.device_metrics"
        f" WHERE device_id = {{device_id:UInt32}}"
        f"   AND ts >= now() - INTERVAL {{since_hours:UInt32}} HOUR"
        f"   AND metric = 'passive_bcast_pkts'"
        f" GROUP BY bucket"
        f" ORDER BY bucket"
    )
    try:
        client = _get_client()
        buckets: dict[str, dict[str, float]] = {}
        for bucket, metric, prev_max, cur_max, step in client.query(sql_snmp, parameters=params).result_rows:
            key = bucket.isoformat() if hasattr(bucket, "isoformat") else str(bucket)
            if prev_max >= 0 and cur_max >= prev_max and step > 0:
                rate = round((cur_max - prev_max) / step, 4)
            else:
                rate = 0.0
            buckets.setdefault(key, {})[metric] = rate
        for bucket, rate in client.query(sql_passive, parameters=params).result_rows:
            key = bucket.isoformat() if hasattr(bucket, "isoformat") else str(bucket)
            buckets.setdefault(key, {})["passive_bcast_pkts"] = round(float(rate), 4)
        out = []
        for key in sorted(buckets):
            row = buckets[key]
            out.append({
                "bucket":          key,
                "in_bcast_rate":   row.get("in_bcast_pkts", 0.0),
                "out_bcast_rate":  row.get("out_bcast_pkts", 0.0),
                "in_mcast_rate":   row.get("in_mcast_pkts", 0.0),
                "out_mcast_rate":  row.get("out_mcast_pkts", 0.0),
                "in_nucast_rate":  row.get("in_nucast_pkts", 0.0),
                "out_nucast_rate": row.get("out_nucast_pkts", 0.0),
                "passive_rate":    row.get("passive_bcast_pkts", 0.0),
            })
        return out
    except Exception as exc:
        logger.warning("query_broadcast_history(%d) failed: %s", device_id, exc)
        return []
