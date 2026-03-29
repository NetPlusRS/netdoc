-- NetDoc ClickHouse — historia pingów urządzeń (RTT + dostępność)
-- Wykonywane automatycznie przy pierwszym starcie kontenera.

-- ─── Tabela: device_ping ─────────────────────────────────────────────────────
-- Przechowuje wyniki pingów co ~18s dla wszystkich monitorowanych urządzeń.
-- device_id wyliczany z IP przez dictionary (jak w syslog).
-- rtt_ms = 0.0 oznacza timeout (urządzenie nie odpowiedziało).
-- is_up   = 1 odpowiada, 0 = timeout/unreachable.
-- Wolumen: 50 urządzeń × ~4800 pingów/dzień = 240k rekordów/dzień → TTL 30 dni.
CREATE TABLE IF NOT EXISTS netdoc_logs.device_ping
(
    ts          DateTime64(3)  DEFAULT now64()   COMMENT 'Czas pomiaru (ms precision)',
    ip          String                            COMMENT 'IP urządzenia',
    device_id   UInt32         MATERIALIZED
                dictGetOrDefault('netdoc_logs.devices_dict', 'device_id', ip, 0)
                                                  COMMENT 'device_id z NetDoc (0 = nieznane)',
    rtt_ms      Float32                           COMMENT 'Round-trip time w ms; 0 = timeout',
    is_up       UInt8                             COMMENT '1 = odpowiada, 0 = brak odpowiedzi'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ip, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- Skipping index na device_id — szybkie zapytania per device_id
ALTER TABLE netdoc_logs.device_ping
    ADD INDEX IF NOT EXISTS idx_device_id device_id TYPE minmax GRANULARITY 4;
