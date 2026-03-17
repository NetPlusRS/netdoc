-- NetDoc ClickHouse — inicjalizacja bazy netdoc_logs
-- Wykonywane automatycznie przy pierwszym starcie kontenera.

-- ─── Baza danych ─────────────────────────────────────────────────────────────
CREATE DATABASE IF NOT EXISTS netdoc_logs;

-- ─── Dictionary: enrichment device_id z PostgreSQL ───────────────────────────
-- ClickHouse pobiera mapowanie IP → device_id bezpośrednio z PostgreSQL.
-- Odświeżanie co 300s (5 min). Lookup O(1) w pamięci (HASHED layout).
-- device_id=0 oznacza "IP nieznane w NetDoc".
-- Uwaga: PostgreSQL używa kolumny 'id', nie 'device_id' — renaming przez query.
--        device_type jest ENUM w PG — rzutujemy na text.
CREATE DICTIONARY IF NOT EXISTS netdoc_logs.devices_dict
(
    ip          String,
    device_id   UInt32,
    hostname    String,
    device_type String,
    location    String
)
PRIMARY KEY ip
SOURCE(POSTGRESQL(
    host     'postgres'
    port     5432
    database 'netdoc'
    user     'netdoc'
    password 'netdoc'
    query    'SELECT ip, id AS device_id, COALESCE(hostname, '''') AS hostname, device_type::text AS device_type, COALESCE(location, '''') AS location FROM devices WHERE ip IS NOT NULL'
))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 0 MAX 300);

-- ─── Tabela: syslog ───────────────────────────────────────────────────────────
-- received_at / timestamp jako DateTime64(9) — Vector wysyła ISO 8601 z ns.
-- device_id wyliczany automatycznie przez dictGet przy INSERT.
-- ORDER BY (device_id, timestamp) — optymalizuje zapytania per urządzenie.
-- PARTITION BY miesiąc — ułatwia zarządzanie retencją i DROP PARTITION.
-- TTL 30 dni — automatyczne usuwanie starych logów (community limit).
CREATE TABLE IF NOT EXISTS netdoc_logs.syslog
(
    received_at  DateTime64(9)  DEFAULT now64()               COMMENT 'Czas odbioru przez rsyslog/Vector',
    timestamp    DateTime64(9)                                 COMMENT 'Czas z nagłówka syslog urządzenia',
    src_ip       String                                        COMMENT 'IP źródłowe urządzenia',
    device_id    UInt32         MATERIALIZED
                 dictGetOrDefault('netdoc_logs.devices_dict', 'device_id', src_ip, 0)
                                                               COMMENT 'device_id z NetDoc (0 = nieznane)',
    hostname     String                                        COMMENT 'Hostname z nagłówka syslog',
    facility     UInt8                                         COMMENT 'Syslog facility (0-23)',
    severity     UInt8                                         COMMENT 'Syslog severity (0=EMERG..7=DEBUG)',
    program      String                                        COMMENT 'Nazwa procesu/programu',
    message      String                                        COMMENT 'Treść logu'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (device_id, timestamp)
TTL toDateTime(timestamp) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- ─── Indeksy pomocnicze ───────────────────────────────────────────────────────
-- Skipping index na src_ip — szybkie filtrowanie po IP bez skanowania całej tabeli
ALTER TABLE netdoc_logs.syslog
    ADD INDEX IF NOT EXISTS idx_src_ip src_ip TYPE bloom_filter(0.01) GRANULARITY 4;

-- Skipping index na severity — szybkie filtrowanie po poziomie ważności
ALTER TABLE netdoc_logs.syslog
    ADD INDEX IF NOT EXISTS idx_severity severity TYPE minmax GRANULARITY 1;

-- ─── Widok: ostatnie logi (wygoda dla Grafana) ────────────────────────────────
CREATE VIEW IF NOT EXISTS netdoc_logs.syslog_recent AS
SELECT
    timestamp,
    src_ip,
    device_id,
    hostname,
    multiIf(
        facility = 0,  'kern',
        facility = 1,  'user',
        facility = 3,  'daemon',
        facility = 4,  'auth',
        facility = 16, 'local0',
        facility = 17, 'local1',
        facility = 23, 'local7',
        toString(facility)
    )                  AS facility_name,
    multiIf(
        severity = 0, 'EMERGENCY',
        severity = 1, 'ALERT',
        severity = 2, 'CRITICAL',
        severity = 3, 'ERROR',
        severity = 4, 'WARNING',
        severity = 5, 'NOTICE',
        severity = 6, 'INFO',
        severity = 7, 'DEBUG',
        'UNKNOWN'
    )                  AS severity_name,
    program,
    message
FROM netdoc_logs.syslog
ORDER BY timestamp DESC;
