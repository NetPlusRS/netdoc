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
        echo=False,
        connect_args={"connect_timeout": 10},
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
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS purchase_price NUMERIC(12,2)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS purchase_currency VARCHAR(3) DEFAULT 'PLN'",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS purchase_vendor VARCHAR(255)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS invoice_number VARCHAR(100)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS support_end DATE",
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
        # Ping worker — czas ostatniego udanego pingu (2026-03-24)
        # Oddzielony od last_seen (ktory jest odswiezany przez discovery/ARP),
        # pozwala na prawidlowe oznaczanie DOWN nawet gdy discovery falszywie odswierza last_seen.
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_ping_ok_at TIMESTAMP",
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
