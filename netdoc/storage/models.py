from datetime import datetime
from sqlalchemy import (
    Column, Integer, BigInteger, String, Boolean, DateTime, Float,
    ForeignKey, Text, JSON, Enum as SAEnum, LargeBinary,
    Numeric, Date, UniqueConstraint, Index,
)
from sqlalchemy.orm import DeclarativeBase, relationship
import enum


class Base(DeclarativeBase):
    pass


class DeviceType(str, enum.Enum):
    router = "router"
    switch = "switch"
    ap = "ap"
    firewall = "firewall"
    server = "server"
    camera = "camera"       # kamery IP
    iot = "iot"             # IoT / smart home / industrial
    printer = "printer"     # drukarki sieciowe
    nas = "nas"             # NAS (Synology, QNAP)
    inverter = "inverter"       # falownik PV / UPS / zasilacz sieciowy (SunSpec/Modbus)
    workstation = "workstation"           # stacja robocza / laptop (Windows/macOS bez serwerów)
    phone = "phone"                       # smartfon / tablet (iOS, Android)
    domain_controller = "domain_controller"  # kontroler domeny AD lub Samba DC
    unknown = "unknown"


class CredentialMethod(str, enum.Enum):
    ssh = "ssh"
    snmp = "snmp"
    api = "api"
    telnet = "telnet"
    rdp = "rdp"
    vnc = "vnc"
    ftp = "ftp"
    postgres = "postgres"
    mssql = "mssql"
    mysql = "mysql"
    rtsp = "rtsp"


class TopologyProtocol(str, enum.Enum):
    lldp = "lldp"
    cdp = "cdp"
    manual = "manual"


class Confidence(str, enum.Enum):
    auto = "auto"
    verified = "verified"


class EventType(str, enum.Enum):
    device_appeared = "device_appeared"
    device_disappeared = "device_disappeared"
    topology_changed = "topology_changed"
    config_changed = "config_changed"
    port_opened = "port_opened"
    port_closed = "port_closed"
    vulnerability_detected = "vulnerability_detected"
    vulnerability_resolved = "vulnerability_resolved"
    ip_conflict = "ip_conflict"      # Ten sam IP, rozne MAC — dwa urzadzenia walcza o adres


class VulnSeverity(str, enum.Enum):
    critical = "critical"
    high     = "high"
    medium   = "medium"
    low      = "low"
    info     = "info"


class VulnType(str, enum.Enum):
    default_credentials  = "default_credentials"
    open_telnet          = "open_telnet"
    anonymous_ftp        = "anonymous_ftp"
    open_ftp             = "open_ftp"
    snmp_public          = "snmp_public"
    mqtt_noauth          = "mqtt_noauth"
    redis_noauth         = "redis_noauth"
    elasticsearch_noauth = "elasticsearch_noauth"
    docker_api_exposed   = "docker_api_exposed"
    http_management      = "http_management"
    ssl_expired          = "ssl_expired"
    ssl_self_signed      = "ssl_self_signed"
    ipmi_exposed         = "ipmi_exposed"
    rdp_exposed          = "rdp_exposed"
    vnc_noauth           = "vnc_noauth"
    mongo_noauth         = "mongo_noauth"
    rtsp_noauth          = "rtsp_noauth"
    modbus_exposed       = "modbus_exposed"
    mysql_noauth         = "mysql_noauth"
    postgres_weak_creds  = "postgres_weak_creds"
    mssql_weak_creds     = "mssql_weak_creds"
    vnc_weak_creds       = "vnc_weak_creds"
    couchdb_noauth       = "couchdb_noauth"
    memcached_exposed    = "memcached_exposed"
    influxdb_noauth      = "influxdb_noauth"
    cassandra_noauth     = "cassandra_noauth"
    rtsp_weak_creds      = "rtsp_weak_creds"
    firewall_disabled    = "firewall_disabled"
    # Kamery / streaming video — nieautoryzowany dostęp do obrazu
    onvif_noauth         = "onvif_noauth"    # ONVIF bez uwierzytelnienia (zarządzanie kamerą)
    mjpeg_noauth         = "mjpeg_noauth"    # Strumień MJPEG dostępny bez logowania
    rtmp_exposed         = "rtmp_exposed"    # RTMP streaming serwer bez auth (port 1935)
    dahua_dvr_exposed    = "dahua_dvr_exposed"   # Dahua DVR/NVR na porcie 37777 bez auth
    xmeye_dvr_exposed    = "xmeye_dvr_exposed"   # XMEye/generyczny DVR na porcie 34567
    unauth_reboot        = "unauth_reboot"        # Endpoint restartu dostepny bez uwierzytelnienia
    tftp_exposed         = "tftp_exposed"         # TFTP (UDP 69) dostepny bez uwierzytelnienia
    cisco_smart_install  = "cisco_smart_install"  # Cisco Smart Install TCP 4786 (CVE-2018-0171)
    cisco_web_exec       = "cisco_web_exec"        # Cisco IOS HTTP exec /level/15/exec/-



class NetworkSource(str, enum.Enum):
    manual = "manual"       # podana recznie w .env / przez API
    auto = "auto"           # wykryta z lokalnych interfejsow
    lldp = "lldp"           # odkryta przez LLDP/CDP z sasiadow
    vpn = "vpn"             # wykryta jako interfejs VPN (nie skanowana domyslnie)

class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), nullable=True)
    ip = Column(String(45), nullable=False, unique=True, index=True)
    mac = Column(String(17), nullable=True, index=True)
    vendor = Column(String(255), nullable=True)
    model = Column(String(255), nullable=True)
    os_version = Column(String(255), nullable=True)
    device_type = Column(SAEnum(DeviceType), default=DeviceType.unknown)
    site_id = Column(String(100), nullable=True)
    location = Column(String(255), nullable=True)
    owner_dept = Column(String(255), nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_ping_ok_at = Column(DateTime, nullable=True)  # ustawiany TYLKO przez ping worker gdy alive=True
    is_active = Column(Boolean, default=True)
    last_credential_ok_at = Column(DateTime, nullable=True)

    # SNMP — aktywne odkrywanie community
    snmp_community = Column(String(64), nullable=True)   # dzialajaca community lub NULL
    snmp_ok_at     = Column(DateTime, nullable=True)     # ostatni udany poll SNMP

    # Zaufanie — czy urzadzenie jest swiadomie znane i zatwierdzone
    is_trusted    = Column(Boolean, default=False, nullable=False)
    trust_note     = Column(String(255), nullable=True)   # powod / opis
    trust_category = Column(String(50),  nullable=True)   # infrastructure/endpoint/iot/guest/other
    trusted_at     = Column(DateTime, nullable=True)      # kiedy oznaczono

    # Kolorowe flagi uzytkownika (wzorem flag w Outlook)
    # Dozwolone: red, orange, yellow, green, blue, purple, None (brak flagi)
    flag_color = Column(String(20), nullable=True, default=None)

    # Typ adresacji IP — oznaczany ręcznie przez użytkownika
    # Dozwolone: "static", "dhcp", "unknown" (domyślnie)
    ip_type = Column(String(10), nullable=False, default="unknown")

    # Monitorowanie dostepnosci — alert gdy urzadzenie staje sie niedostepne
    is_monitored  = Column(Boolean, default=False, nullable=False)
    monitor_note  = Column(String(255), nullable=True)    # opis co jest monitorowane
    monitor_since = Column(DateTime, nullable=True)       # kiedy wlaczono monitorowanie

    # Inwentaryzacja / dane urządzenia
    serial_number      = Column(String(255),    nullable=True)
    asset_tag          = Column(String(100),    nullable=True)
    sys_contact        = Column(String(255),    nullable=True)   # sysContact z SNMP (1.3.6.1.2.1.1.4.0)
    snmp_uptime        = Column(String(64),     nullable=True)   # sysUpTime z SNMP (czytelny string, np. "10d 5h 23m")
    ram_total_mb       = Column(Integer,        nullable=True)   # całkowita RAM z UCD-SNMP memTotalReal (w MB)
    no_full_scan       = Column(Boolean,        nullable=False, default=False)  # wyłącz automatyczny full scan 1-65535
    skip_cred_scan     = Column(Boolean,        nullable=False, default=False)  # wyłącz testowanie haseł dla tego urządzenia
    skip_port_scan     = Column(Boolean,        nullable=False, default=False)  # wyłącz skan portów (vuln worker + nmap)
    # SNMP vendor detection + STP (2026-04-04)
    snmp_sys_object_id = Column(String(100),    nullable=True)   # sysObjectID np. "1.3.6.1.4.1.9.1.1"
    stp_root_mac       = Column(String(17),     nullable=True)   # MAC root bridge z STP
    stp_root_cost      = Column(Integer,        nullable=True)   # koszt sciezki do root
    # Kolumny zakupowe — zachowane w DB dla kompatybilności, nieużywane w UI od 2026-03-29
    purchase_date      = Column(Date,           nullable=True)
    purchase_vendor    = Column(String(255),    nullable=True)
    responsible_person = Column(String(255),    nullable=True)
    asset_notes        = Column(Text,           nullable=True)

    interfaces = relationship("Interface", back_populates="device", cascade="all, delete-orphan")
    credentials = relationship("Credential", back_populates="device", cascade="all, delete-orphan")
    scan_results = relationship("ScanResult", back_populates="device", cascade="all, delete-orphan")
    config_snapshots = relationship("ConfigSnapshot", back_populates="device", cascade="all, delete-orphan")
    events = relationship("Event", back_populates="device", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="device", cascade="all, delete-orphan")
    screenshot = relationship("DeviceScreenshot", back_populates="device",
                              cascade="all, delete-orphan", uselist=False)


class Interface(Base):
    __tablename__ = "interfaces"
    __table_args__ = (
        UniqueConstraint("device_id", "if_index", name="uq_iface_dev_ifindex"),
        Index("ix_iface_device_id", "device_id"),
    )

    id           = Column(Integer, primary_key=True)
    device_id    = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    if_index     = Column(Integer,     nullable=True)   # ifIndex (SNMP)
    name         = Column(String(100), nullable=False)  # ifDescr
    alias        = Column(String(255), nullable=True)   # ifAlias (human label)
    mac          = Column(String(17),  nullable=True)
    ip           = Column(String(45),  nullable=True)
    speed        = Column(Integer,     nullable=True)   # Mbps (ifHighSpeed lub ifSpeed/1e6)
    duplex       = Column(String(20),  nullable=True)
    admin_status = Column(Boolean,     nullable=True)   # True=up, False=down (ifAdminStatus)
    oper_status  = Column(Boolean,     nullable=True)   # True=up, False=down (ifOperStatus)
    description  = Column(String(255), nullable=True)   # dodatkowy opis (np. z CDP/LLDP)
    port_mode    = Column(String(10),  nullable=True)   # "access" | "trunk" | "routed" (Cisco VTP MIB)
    native_vlan  = Column(Integer,     nullable=True)   # native VLAN (trunk) lub access VLAN
    trunk_encap  = Column(String(8),   nullable=True)   # "dot1q" | "isl" | "none"
    trunk_vlans  = Column(Integer,     nullable=True)   # liczba dozwolonych VLANów na trunk
    polled_at    = Column(DateTime,    nullable=True)   # ostatni SNMP poll

    device = relationship("Device", back_populates="interfaces")
    src_links = relationship("TopologyLink", foreign_keys="TopologyLink.src_interface_id", back_populates="src_interface")
    dst_links = relationship("TopologyLink", foreign_keys="TopologyLink.dst_interface_id", back_populates="dst_interface")


class TopologyLink(Base):
    __tablename__ = "topology_links"

    id = Column(Integer, primary_key=True, index=True)
    src_device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    src_interface_id = Column(Integer, ForeignKey("interfaces.id", ondelete="SET NULL"), nullable=True)
    dst_device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    dst_interface_id = Column(Integer, ForeignKey("interfaces.id", ondelete="SET NULL"), nullable=True)
    protocol = Column(SAEnum(TopologyProtocol), default=TopologyProtocol.lldp)
    confidence = Column(SAEnum(Confidence), default=Confidence.auto)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    src_device = relationship("Device", foreign_keys=[src_device_id])
    dst_device = relationship("Device", foreign_keys=[dst_device_id])
    src_interface = relationship("Interface", foreign_keys=[src_interface_id], back_populates="src_links")
    dst_interface = relationship("Interface", foreign_keys=[dst_interface_id], back_populates="dst_links")


class Credential(Base):
    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)  # None = global default
    method = Column(SAEnum(CredentialMethod), nullable=False)
    username = Column(String(255), nullable=True)   # SNMP: community string; SSH: username
    password_encrypted = Column(Text, nullable=True)
    api_key_encrypted = Column(Text, nullable=True)
    priority = Column(Integer, default=100)          # nizszy = wyzszy priorytet probowania
    last_success_at = Column(DateTime, nullable=True)  # kiedy ostatnio ten credential zadzialal
    success_count = Column(Integer, default=0, nullable=False, server_default="0")  # ile razy uzyty skutecznie
    notes = Column(String(255), nullable=True)        # etykieta np. "public default", "Cisco office"

    __table_args__ = (
        UniqueConstraint("device_id", "method", "username", "password_encrypted", name="uq_credential_dev_method_user_pass"),
    )

    device = relationship("Device", back_populates="credentials")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    scan_time = Column(DateTime, default=datetime.utcnow)
    scan_type = Column(String(50), nullable=False)  # nmap / nuclei / openvas
    open_ports = Column(JSON, nullable=True)
    vulnerabilities = Column(JSON, nullable=True)
    risk_score = Column(Float, nullable=True)

    # PERF-13: indeks złożony dla GROUP BY w /devices (device_id, scan_type, scan_time)
    # Eliminuje Seq Scan + Sort przy dużej tabeli (minuty → milisekundy przy 10M rekordach)
    __table_args__ = (
        Index("ix_scanresult_device_type_time", "device_id", "scan_type", "scan_time"),
    )

    device = relationship("Device", back_populates="scan_results")


class ConfigSnapshot(Base):
    __tablename__ = "config_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    captured_at = Column(DateTime, default=datetime.utcnow)
    config_text = Column(Text, nullable=True)
    config_hash = Column(String(64), nullable=True)
    diff_from_previous = Column(Text, nullable=True)

    device = relationship("Device", back_populates="config_snapshots")


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    event_time = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(SAEnum(EventType), nullable=False)
    details = Column(JSON, nullable=True)

    device = relationship("Device", back_populates="events")

class DiscoveredNetwork(Base):
    """
    Rejestr podsieci do skanowania.
    Uzupelniana automatycznie (lokalne interfejsy, LLDP) i recznie (.env / API).
    """
    __tablename__ = "discovered_networks"

    id = Column(Integer, primary_key=True, index=True)
    cidr = Column(String(43), nullable=False, unique=True, index=True)
    source = Column(SAEnum(NetworkSource), default=NetworkSource.auto)
    is_active = Column(Boolean, default=True)
    last_credential_ok_at = Column(DateTime, nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_vpn = Column(Boolean, default=False)
    vpn_reason = Column(String(100), nullable=True)
    notes = Column(String(255), nullable=True)



class Vulnerability(Base):
    """Zidentyfikowana podatnosc bezpieczenstwa na urzadzeniu."""
    __tablename__ = "vulnerabilities"

    id          = Column(Integer, primary_key=True, index=True)
    device_id   = Column(Integer, ForeignKey("devices.id"), nullable=False)
    vuln_type   = Column(SAEnum(VulnType), nullable=False)
    severity    = Column(SAEnum(VulnSeverity), nullable=False)
    title       = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    port        = Column(Integer, nullable=True)
    evidence    = Column(Text, nullable=True)   # co dokladnie wykryto (banner, response)
    first_seen  = Column(DateTime, default=datetime.utcnow)
    last_seen   = Column(DateTime, default=datetime.utcnow)
    is_open        = Column(Boolean, default=True)   # False = rozwiazana/niewidoczna
    suppressed     = Column(Boolean, default=False)  # True = swiadomie zaakceptowane ryzyko (skaner nie wznawia)
    consecutive_ok = Column(Integer, default=0, nullable=False, server_default="0")
    # Ile razy z rzędu skan NIE wykrył tej podatności.
    # Worker zamknie podatność dopiero gdy consecutive_ok >= vuln_close_after (domyślnie 3).

    device = relationship("Device", back_populates="vulnerabilities")

class SystemStatus(Base):
    """Konfiguracja i status biezacych operacji collectora.

    Klucze grupowane po category:
      config    — ustawienia (scan_interval, workers, porty)
      scheduler — stan schedulera i aktualnie wykonywane zadanie
      last_run  — statystyki ostatnich uruchomien jobow
    """
    __tablename__ = "system_status"

    key = Column(String(64), primary_key=True)
    category = Column(String(32), nullable=False, default="config")
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DeviceScreenshot(Base):
    """Zrzut ekranu strony HTTP urzadzenia — przechowywany w bazie jako PNG."""
    __tablename__ = "device_screenshots"

    id           = Column(Integer, primary_key=True)
    device_id    = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"),
                          unique=True, nullable=False, index=True)
    mac          = Column(String(17), nullable=True, index=True)  # referencyjna — moze byc null
    ip           = Column(String(45), nullable=False)             # IP w momencie capture
    http_port    = Column(Integer, nullable=True)
    http_scheme  = Column(String(5), nullable=True)   # "http" lub "https"
    png_data     = Column(LargeBinary, nullable=False)
    captured_at  = Column(DateTime, default=datetime.utcnow, nullable=False)

    device = relationship("Device", back_populates="screenshot")


class PortAcceptance(Base):
    """Swiadoma akceptacja ryzyka dla konkretnego portu na konkretnym urzadzeniu.

    Uzytkownik moze zaznaczyc ze dany port na danym urzadzeniu jest znany i
    swiadomie zaakceptowany (np. Grafana :3000 w sieci LAN to nie jest problem).
    Skaner nadal go widzi — tylko w widoku KB Ports pojawia sie znacznik akceptacji.
    """
    __tablename__ = "port_acceptances"

    id         = Column(Integer, primary_key=True, index=True)
    device_id  = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    port       = Column(Integer, nullable=False)
    reason     = Column(Text, nullable=True)
    accepted_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (UniqueConstraint("device_id", "port", name="uq_port_acceptance"),)

    device = relationship("Device", backref="port_acceptances")


class ChatMessage(Base):
    """Historia rozmow z asystentem AI."""
    __tablename__ = "chat_messages"

    id         = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), nullable=False, index=True)
    role       = Column(String(16), nullable=False)   # 'user' | 'assistant'
    content    = Column(Text, nullable=False)
    tools_used = Column(JSON, nullable=True)           # lista narzedzi uzytych przez agenta
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class MonitoringAlert(Base):
    """Historia alertow monitorowania dostepnosci urzadzen.

    Generowany gdy urzadzenie z is_monitored=True zmienia status is_active.
    """
    __tablename__ = "monitoring_alerts"

    id         = Column(Integer, primary_key=True, index=True)
    device_id  = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    alert_type = Column(String(32), nullable=False)   # "offline" | "online"
    message    = Column(String(512), nullable=True)
    sent_at    = Column(DateTime, default=datetime.utcnow, index=True)
    channel    = Column(String(32), nullable=True)    # "telegram" | "email" | itp.
    delivered  = Column(Boolean, default=False)       # True gdy wyslano pomyslnie

    device = relationship("Device")


class NotificationChannel(Base):
    """Konfiguracja kanalow powiadomien (Telegram, email itp.).

    Przechowuje po jednym wpisie na typ kanalu (key=channel_type).
    """
    __tablename__ = "notification_channels"

    key       = Column(String(64), primary_key=True)  # "telegram", "email"
    is_active = Column(Boolean, default=False)
    config    = Column(JSON, nullable=True)  # {"bot_token": "...", "chat_id": "..."}
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DeviceAssessment(Base):
    """Historia ocen sprzetu AI per urzadzenie.

    Kazde wywolanie AI dla konkretnego urzadzenia jest zapisywane tutaj.
    Przechowuje ostatnie N wpisow (czyszczone po stronie aplikacji).
    """
    __tablename__ = "device_assessments"

    id          = Column(Integer, primary_key=True, index=True)
    device_id   = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    assessed_at = Column(DateTime, default=datetime.utcnow, index=True)
    prompt      = Column(Text, nullable=True)    # pelne zapytanie wyslane do modelu
    result      = Column(Text, nullable=False)   # JSON: is_obsolete, reason, replacements, summary
    model       = Column(String(64), nullable=True)

    device = relationship("Device")


class DeviceFieldHistory(Base):
    """Historia zmian pól urządzenia (hostname, firmware, vendor, model, location...).

    Zapisywana przez snmp-worker przy wykryciu zmiany wartości pola.
    Retencja: 90 dni (czyszczone przez worker).
    """
    __tablename__ = "device_field_history"
    __table_args__ = (
        Index("ix_dfh_device_changed", "device_id", "changed_at"),
    )

    id          = Column(Integer, primary_key=True)
    device_id   = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"),
                         nullable=False)
    field_name  = Column(String(50),  nullable=False)   # "hostname","os_version","vendor","model"...
    old_value   = Column(Text,        nullable=True)
    new_value   = Column(Text,        nullable=True)
    changed_at  = Column(DateTime,    default=datetime.utcnow, nullable=False)
    source      = Column(String(20),  nullable=False, default="snmp")  # "snmp","discovery","manual"

    device = relationship("Device", foreign_keys=[device_id])


class DeviceVap(Base):
    """VAP (Virtual Access Point) — dane per SSID/ifname z AP Ubiquiti UniFi.

    Zbierane przez SNMP z ubntUnifiVapTable (1.3.6.1.4.1.41112.1.6.1.2.1).
    Jeden wiersz = jeden VAP (unikalny: device_id + ifname).
    BSSID może się powtarzać na tym samym radiu dla różnych SSIDów.
    """
    __tablename__ = "device_vap"
    __table_args__ = (
        UniqueConstraint("device_id", "ifname", name="uq_vap_device_ifname"),
        Index("ix_vap_device_id", "device_id"),
    )

    id           = Column(Integer, primary_key=True)
    device_id    = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    bssid        = Column(String(17), nullable=True)         # XX:XX:XX:XX:XX:XX (może być NULL lub zduplikowany)
    ssid         = Column(String(64), nullable=True)         # nazwa sieci WiFi
    ifname       = Column(String(30), nullable=False)        # wifi0ap1, wifi1ap2... — klucz unikatu
    radio_band   = Column(String(10), nullable=True)         # ng=2.4GHz, na=5GHz
    sta_count    = Column(Integer,    nullable=True)         # podłączeni klienci
    tx_bytes     = Column(BigInteger, nullable=True)         # Counter32 (reset przy overflow)
    rx_bytes     = Column(BigInteger, nullable=True)
    polled_at    = Column(DateTime,   nullable=True)

    device = relationship("Device", foreign_keys=[device_id])


class DeviceSensor(Base):
    """Odczyty sensorów urządzenia pobierane przez SNMP (temperatura, CPU, RAM, napięcie, fan...).

    Każdy sensor to osobny wiersz (unikalne: device_id + sensor_name).
    Wartość aktualizowana in-place przy każdym cyklu SNMP workera.
    """
    __tablename__ = "device_sensors"
    __table_args__ = (
        UniqueConstraint("device_id", "sensor_name", name="uq_sensor_dev_name"),
        Index("ix_sensor_device_id", "device_id"),
    )

    id          = Column(Integer, primary_key=True)
    device_id   = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    sensor_name = Column(String(100), nullable=False)   # e.g. "cpu_load", "temp_cpu", "fan_1"
    value       = Column(Float,       nullable=True)    # numeric value
    unit        = Column(String(20),  nullable=True)    # "°C", "%", "V", "rpm", "mW", "dBm"
    raw_str     = Column(String(200), nullable=True)    # original string if non-numeric
    source      = Column(String(50),  nullable=True)    # "entity_sensor", "cisco_envmon", "mikrotik"...
    polled_at   = Column(DateTime,    default=datetime.utcnow, nullable=False)

    device = relationship("Device", foreign_keys=[device_id])


class InterfaceHistory(Base):
    """Historia zmian stanu interfejsów (port up/down, zmiana prędkości, dodany/usunięty).

    Zapisywana przez snmp-worker przy wykryciu zmiany w ifTable.
    Retencja: 30 dni.
    """
    __tablename__ = "interface_history"
    __table_args__ = (
        Index("ix_ifh_device_changed", "device_id", "changed_at"),
    )

    id             = Column(Integer, primary_key=True)
    device_id      = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"),
                            nullable=False)
    interface_name = Column(String(100), nullable=False)
    event_type     = Column(String(20),  nullable=False)  # "up","down","speed_change","added","removed"
    old_speed      = Column(Integer,     nullable=True)   # Mbps
    new_speed      = Column(Integer,     nullable=True)   # Mbps
    changed_at     = Column(DateTime,    default=datetime.utcnow, nullable=False)

    device = relationship("Device", foreign_keys=[device_id])


class DevicePassport(Base):
    """Wygenerowany paszport urządzenia — statyczny HTML eksportowany do sprzedaży.

    Token jest krótkim losowym identyfikatorem URL (np. k7x2m9).
    data_snapshot przechowuje JSON ze wszystkimi zebranymi danymi w momencie generowania.
    """
    __tablename__ = "device_passports"
    __table_args__ = (
        Index("ix_passport_device_id", "device_id"),
    )

    id            = Column(Integer,     primary_key=True)
    token         = Column(String(12),  unique=True, nullable=False, index=True)
    device_id     = Column(Integer,     ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    device_ip     = Column(String(45),  nullable=True)
    device_type   = Column(String(50),  nullable=True)
    generated_at  = Column(DateTime,    default=datetime.utcnow, nullable=False)
    html_filename = Column(String(100), nullable=True)
    data_snapshot = Column(JSON,        nullable=True)


class DeviceFdbEntry(Base):
    """Tablica przekazywania MAC (FDB) switcha — mapowanie MAC -> port fizyczny.

    Aktualizowana co cykl SNMP workera przez collect_fdb() z snmp_l2.py.
    Pozwala znalezc na ktorym porcie switcha znajduje sie dane urzadzenie.

    fdb_status: wartosci z dot1dTpFdbStatus (1=other, 2=invalid, 3=learned, 4=self, 5=mgmt)
    """
    __tablename__ = "device_fdb"
    __table_args__ = (
        UniqueConstraint("device_id", "mac", name="uq_fdb_dev_mac"),
        Index("ix_fdb_device_id", "device_id"),
        Index("ix_fdb_mac", "mac"),
        Index("ix_fdb_polled_at", "polled_at"),
    )

    id             = Column(Integer,     primary_key=True)
    device_id      = Column(Integer,     ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    mac            = Column(String(17),  nullable=False)   # XX:XX:XX:XX:XX:XX
    bridge_port    = Column(Integer,     nullable=False)   # dot1dTpFdbPort (numer w bridge)
    if_index       = Column(Integer,     nullable=True)    # zmapowany ifIndex (dot1dBasePortIfIndex)
    interface_name = Column(String(100), nullable=True)    # ifDescr (lookup z interfaces)
    vlan_id        = Column(Integer,     nullable=True)    # VLAN (gdy dostepny)
    fdb_status     = Column(Integer,     nullable=True)    # dot1dTpFdbStatus: 3=learned, 5=static
    polled_at      = Column(DateTime,    default=datetime.utcnow, nullable=False)

    device = relationship("Device", foreign_keys=[device_id])


class DeviceVlanPort(Base):
    """Przynaleznosc portow do VLAN na urzadzeniu (switchu).

    Aktualizowana co cykl SNMP workera przez collect_vlan_port() z snmp_l2.py.
    port_mode: 'access' (untagged), 'trunk' (tagged), None (nieznany)
    is_pvid: True jezeli to domyslny VLAN portu (PVID)
    """
    __tablename__ = "device_vlan_port"
    __table_args__ = (
        UniqueConstraint("device_id", "vlan_id", "if_index", name="uq_vlan_port"),
        Index("ix_vlan_port_device_id", "device_id"),
    )

    id         = Column(Integer,    primary_key=True)
    device_id  = Column(Integer,    ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    vlan_id    = Column(Integer,    nullable=False)   # numer VLAN (1-4094)
    vlan_name  = Column(String(64), nullable=True)    # nazwa VLAN (gdy dostepna)
    if_index   = Column(Integer,    nullable=False)   # ifIndex portu
    port_mode  = Column(String(10), nullable=True)    # 'access' | 'trunk' | None
    is_pvid    = Column(Boolean,    nullable=False, default=False)  # True = PVID portu
    polled_at  = Column(DateTime,   default=datetime.utcnow, nullable=False)

    device = relationship("Device", foreign_keys=[device_id])


class DeviceStpPort(Base):
    """Stan STP (Spanning Tree Protocol) per port switcha.

    Aktualizowana co cykl SNMP workera przez collect_stp_ports() z snmp_l2.py.

    stp_state (dot1dStpPortState):
        1=disabled, 2=blocking, 3=listening, 4=learning, 5=forwarding, 6=broken
    stp_role (RSTP dot1dStpPortRole):
        'root', 'designated', 'alternate', 'backup', 'disabled'
    """
    __tablename__ = "device_stp_port"
    __table_args__ = (
        UniqueConstraint("device_id", "stp_port_num", name="uq_stp_dev_port"),
        Index("ix_stp_port_device_id", "device_id"),
    )

    id           = Column(Integer,    primary_key=True)
    device_id    = Column(Integer,    ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    stp_port_num = Column(Integer,    nullable=False)   # dot1dStpPort
    if_index     = Column(Integer,    nullable=True)    # zmapowany ifIndex
    stp_state    = Column(Integer,    nullable=True)    # 1-6, patrz docstring
    stp_role     = Column(String(20), nullable=True)    # 'root'|'designated'|'alternate'|'backup'
    path_cost    = Column(Integer,    nullable=True)    # dot1dStpPortPathCost
    polled_at    = Column(DateTime,   default=datetime.utcnow, nullable=False)

    device = relationship("Device", foreign_keys=[device_id])
