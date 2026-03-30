import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session, DeclarativeBase
from sqlalchemy import event as sa_event
from netdoc.config.settings import settings
from netdoc.storage.models import Base

logger = logging.getLogger(__name__)


def _make_postgres_engine():
    import os
    pool_size   = int(os.getenv("DB_POOL_SIZE",    "10"))
    max_overflow= int(os.getenv("DB_MAX_OVERFLOW", "20"))
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_recycle=1800,          # odświeżaj połączenia co 30 min (przed idle timeout)
        echo=False,
        connect_args={
            "connect_timeout": 10,
            "keepalives": 1,        # TCP keepalives — wykrywaj martwe połączenia
            "keepalives_idle": 60,  # zacznij po 60s bezczynności
            "keepalives_interval": 10,
            "keepalives_count": 3,
        },
    )


def _make_sqlite_engine(url: str = "sqlite:///:memory:"):
    """Tworzy SQLite engine z wlaczonymi foreign keys (do testow i fallbacku)."""
    from sqlalchemy.pool import StaticPool
    eng = create_engine(url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
    sa_event.listen(eng, "connect", lambda conn, _: conn.execute("PRAGMA foreign_keys=ON"))
    return eng


def _build_engine():
    """Laczy sie z PostgreSQL. Rzuca RuntimeError jesli baza niedostepna."""
    try:
        eng = _make_postgres_engine()
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("Polaczono z PostgreSQL: %s", settings.database_url)
        return eng
    except Exception as exc:
        raise RuntimeError(
            f"PostgreSQL niedostepny: {exc}\n"
            "Sprawdz czy kontener netdoc-postgres dziala (docker compose ps).\n"
            "Uzyj run_broadcast_worker.py --wait lub poczekaj az baza bedzie gotowa."
        ) from exc


engine = _build_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _migrate_enum_values() -> None:
    """Dodaje brakujace wartosci do PostgreSQL ENUM bezpiecznie (ALTER TYPE ... ADD VALUE IF NOT EXISTS).

    Wywolywane przy kazdym starcie — bezpieczne gdy wartosc juz istnieje.
    Nie robi nic w SQLite (enums sa tam przechowywane jako TEXT).
    """
    enum_updates = [
        ("devicetype",      ["inverter", "workstation", "phone", "domain_controller"]),
        ("credentialmethod", ["rdp", "vnc", "ftp", "postgres", "mssql", "mysql", "rtsp"]),
        ("vulntype",        ["rdp_exposed", "vnc_noauth", "vnc_weak_creds", "mongo_noauth", "rtsp_noauth", "modbus_exposed", "mysql_noauth", "postgres_weak_creds", "mssql_weak_creds", "couchdb_noauth", "memcached_exposed", "influxdb_noauth", "cassandra_noauth", "rtsp_weak_creds", "firewall_disabled", "onvif_noauth", "mjpeg_noauth", "rtmp_exposed", "dahua_dvr_exposed", "xmeye_dvr_exposed", "tftp_exposed"]),
        ("eventtype",       ["ip_conflict"]),
    ]
    try:
        with engine.begin() as conn:
            for enum_name, values in enum_updates:
                for val in values:
                    conn.execute(text(
                        f"DO $$ BEGIN "
                        f"ALTER TYPE {enum_name} ADD VALUE IF NOT EXISTS :val; "
                        f"EXCEPTION WHEN duplicate_object THEN NULL; "
                        f"END $$"
                    ).bindparams(val=val))
        logger.info("Migracja ENUM: sprawdzono devicetype+credentialmethod+vulntype")
    except Exception as exc:
        logger.warning("Migracja ENUM pominięta: %s", exc)


def _migrate_columns() -> None:
    """Dodaje brakujace kolumny do istniejacych tabel (bezpieczne - IF NOT EXISTS)."""
    migrations = [
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS suppressed BOOLEAN DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_trusted BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS trust_note VARCHAR(255)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS trust_category VARCHAR(50)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS trusted_at TIMESTAMP",
        # Flagi i monitorowanie (2026-03-09)
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS flag_color VARCHAR(20)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_monitored BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS monitor_note VARCHAR(255)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS monitor_since TIMESTAMP",
        # Inwentaryzacja / Środki trwałe (2026-03-09)
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS serial_number VARCHAR(255)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS asset_tag VARCHAR(100)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS purchase_date DATE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS purchase_vendor VARCHAR(255)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS responsible_person VARCHAR(255)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS asset_notes TEXT",
        # Typ adresacji IP (2026-03-09)
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS ip_type VARCHAR(10) NOT NULL DEFAULT 'unknown'",
        # Stabilizacja zamykania podatnosci — counter nietrafionych skanow (2026-03-09)
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS consecutive_ok INTEGER NOT NULL DEFAULT 0",
        # SNMP community discovery (2026-03-12)
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS snmp_community VARCHAR(64)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS snmp_ok_at TIMESTAMP",
        # SNMP sysContact — osoba kontaktowa (2026-03-24)
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS sys_contact VARCHAR(255)",
        # SNMP sysUpTime — dedykowana kolumna, nie zapisujemy do asset_notes (2026-03-29)
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS snmp_uptime VARCHAR(64)",
        # Historia zmian pól urządzenia (2026-03-29)
        """CREATE TABLE IF NOT EXISTS device_field_history (
            id         SERIAL PRIMARY KEY,
            device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            field_name VARCHAR(50) NOT NULL,
            old_value  TEXT,
            new_value  TEXT,
            changed_at TIMESTAMP NOT NULL DEFAULT NOW(),
            source     VARCHAR(20) NOT NULL DEFAULT 'snmp'
        )""",
        "CREATE INDEX IF NOT EXISTS ix_dfh_device_changed ON device_field_history (device_id, changed_at)",
        # Historia zmian interfejsów (2026-03-29)
        """CREATE TABLE IF NOT EXISTS interface_history (
            id             SERIAL PRIMARY KEY,
            device_id      INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            interface_name VARCHAR(100) NOT NULL,
            event_type     VARCHAR(20) NOT NULL,
            old_speed      INTEGER,
            new_speed      INTEGER,
            changed_at     TIMESTAMP NOT NULL DEFAULT NOW()
        )""",
        "CREATE INDEX IF NOT EXISTS ix_ifh_device_changed ON interface_history (device_id, changed_at)",
        # Device sensors — SNMP temperature, CPU, RAM, voltage, fans (2026-03-30)
        """CREATE TABLE IF NOT EXISTS device_sensors (
            id          SERIAL PRIMARY KEY,
            device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            sensor_name VARCHAR(100) NOT NULL,
            value       DOUBLE PRECISION,
            unit        VARCHAR(20),
            raw_str     VARCHAR(200),
            source      VARCHAR(50),
            polled_at   TIMESTAMP NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_sensor_dev_name UNIQUE (device_id, sensor_name)
        )""",
        "CREATE INDEX IF NOT EXISTS ix_sensor_device_id ON device_sensors (device_id)",
        # Ping worker — czas ostatniego udanego pingu (2026-03-24)
        # Oddzielony od last_seen (ktory jest odswiezany przez discovery/ARP),
        # pozwala na prawidlowe oznaczanie DOWN nawet gdy discovery falszywie odswierza last_seen.
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_ping_ok_at TIMESTAMP",
        # Interfejsy SNMP — bieżący stan portów (2026-03-30)
        "ALTER TABLE interfaces ADD COLUMN IF NOT EXISTS if_index INTEGER",
        "ALTER TABLE interfaces ADD COLUMN IF NOT EXISTS alias VARCHAR(255)",
        "ALTER TABLE interfaces ADD COLUMN IF NOT EXISTS polled_at TIMESTAMP",
        # Zmień speed z INTEGER (Mbps) na INTEGER (bez zmiany — już jest Mbps)
        # Dodaj UNIQUE constraint (device_id, if_index) gdy if_index NOT NULL
        """DO $$ BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM pg_constraint WHERE conname = 'uq_iface_dev_ifindex'
          ) THEN
            ALTER TABLE interfaces
              ADD CONSTRAINT uq_iface_dev_ifindex UNIQUE (device_id, if_index);
          END IF;
        END $$""",
        "CREATE INDEX IF NOT EXISTS ix_iface_device_id ON interfaces (device_id)",
        # Device passports — eksport do sprzedaży (2026-03-30)
        """CREATE TABLE IF NOT EXISTS device_passports (
            id            SERIAL PRIMARY KEY,
            token         VARCHAR(12) NOT NULL UNIQUE,
            device_id     INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            device_ip     VARCHAR(45),
            device_type   VARCHAR(50),
            generated_at  TIMESTAMP NOT NULL DEFAULT NOW(),
            html_filename VARCHAR(100),
            data_snapshot JSONB
        )""",
        "CREATE INDEX IF NOT EXISTS ix_passport_device_id ON device_passports (device_id)",
        "CREATE INDEX IF NOT EXISTS ix_passport_token ON device_passports (token)",
        # RAM całkowita z SNMP UCD-MIB memTotalReal (2026-03-30)
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS ram_total_mb INTEGER",
        # Flaga wyłączenia automatycznego full scan 1-65535 (2026-03-30)
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS no_full_scan BOOLEAN NOT NULL DEFAULT FALSE",
        # Usun stary constraint (za wazki — blokuje wiele hasel dla jednego usera)
        """
        DO $$ BEGIN
          IF EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'uq_credential_dev_method_user'
          ) THEN
            ALTER TABLE credentials DROP CONSTRAINT uq_credential_dev_method_user;
          END IF;
        END $$
        """,
        # Deduplikacja credentials przed dodaniem UNIQUE constraint (2026-03-12)
        # Zachowuje rekord z nizszym id (wyzszy priorytet), usuwa pozniejsze duplikaty
        """
        DELETE FROM credentials a USING credentials b
        WHERE a.id > b.id
          AND (a.device_id IS NOT DISTINCT FROM b.device_id)
          AND a.method = b.method
          AND (a.username IS NOT DISTINCT FROM b.username)
          AND (a.password_encrypted IS NOT DISTINCT FROM b.password_encrypted)
        """,
        # Unique constraint: (device_id, method, username, password) — zapobiega duplikatom tej samej pary user+pass
        """
        DO $$ BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'uq_credential_dev_method_user_pass'
          ) THEN
            ALTER TABLE credentials
              ADD CONSTRAINT uq_credential_dev_method_user_pass
              UNIQUE NULLS NOT DISTINCT (device_id, method, username, password_encrypted);
          END IF;
        END $$
        """,
    ]
    try:
        with engine.begin() as conn:
            for sql in migrations:
                conn.execute(text(sql))
        logger.info("Migracja kolumn: sprawdzono vulnerabilities + devices (flagi/monitorowanie/inwentaryzacja)")
    except Exception as exc:
        logger.warning("Migracja kolumn pominięta: %s", exc)


def init_db() -> None:
    """Tworzy wszystkie tabele jesli nie istnieja i migruje ENUM.

    Kolejnosc ma znaczenie: najpierw create_all (tworzy typy i tabele na swiezej bazie),
    potem migracje (dodaja brakujace wartosci/kolumny przy upgrade ze starszej wersji).
    Na swiezej instalacji migracje beda no-op (IF NOT EXISTS chroni przed duplikatami).
    """
    import time as _time
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as exc:
        # Race condition: kilka workerow startuje rownoczesnie i kazdy probuje CREATE TYPE.
        # PostgreSQL rzuca UniqueViolation gdy typ juz istnieje. Ponowiamy po krotkim opoznieniu.
        logger.warning("create_all nieudane (%s) — ponawiam za 2s", exc)
        _time.sleep(2)
        Base.metadata.create_all(bind=engine)
    # Migracje po create_all — bezpieczne dzieki IF NOT EXISTS / EXCEPTION WHEN duplicate_object.
    # Na swiezej bazie wszystkie wartosci juz sa w schemacie wiec migracje sa no-op.
    # Przy upgrade ze starszej wersji dodaja brakujace wartosci ENUM i kolumny.
    _migrate_enum_values()
    _migrate_columns()
    dialect = engine.dialect.name
    logger.info("Baza danych zainicjalizowana (%s)", dialect)


def get_db():
    """Dependency dla FastAPI — zwraca sesje i zamyka po uzyciu."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
