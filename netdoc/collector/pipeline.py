"""
Collector Pipeline — dobiera driver do urzadzenia i zbiera szczegolowe dane.

Logika dzialania (graceful degradation):
  1. Discovery (nmap) dziala zawsze — bez credentials.
  2. Po discovery pipeline probuje uzyskac szczegoly z urzadzenia:
     - SNMP (community "public") — dziala bez konfiguracji, daje hostname / interfejsy
     - UniFi API              — jezeli skonfigurowane unifi_username w settings
     - SSH Cisco / MikroTik   — jezeli sa credentials w tabeli Credential
  3. Jezeli zadna metoda nie zadziala — urzadzenie zostaje z danymi z nmap.

Nie ma bledow krytycznych — kazdy krok jest opcjonalny.
"""
import logging
from typing import Optional, List, Type

from sqlalchemy.orm import Session

from netdoc.collector.drivers.base import BaseDriver
from netdoc.collector.drivers.snmp import SNMPDriver
from netdoc.collector.drivers.unifi import UnifiDriver
from netdoc.collector.drivers.cisco import CiscoDriver
from netdoc.collector.drivers.mikrotik import MikrotikDriver
from netdoc.collector.drivers.modbus import ModbusDriver
from netdoc.collector.normalizer import DeviceData
from netdoc.config.settings import settings
from netdoc.collector.network_detect import subnet_from_ip, infer_prefix_from_ip, is_private
from netdoc.collector.discovery import register_network
from netdoc.storage.models import (
    Device, Interface, Credential, CredentialMethod,
    TopologyLink, TopologyProtocol, Confidence,
)

logger = logging.getLogger(__name__)

# Popularne SNMP community stringi — probowane gdy brak skonfigurowanego credentials.
# Pierwsza ktora odpowie zostaje zapisana w tabeli Credential jako globalny default.
SNMP_COMMUNITY_FALLBACK = [
    "public",     # RFC default — wiekszos urzadzen sieciowych
    "private",    # Cisco, Juniper write community (czesto tez do odczytu)
    "community",  # Cisco legacy IOS
    "admin",      # NetGear, D-Link, TP-Link
    "cisco",      # Cisco starsze IOS
    "mngt",       # HP ProCurve
    "manager",    # HP / 3Com
    "monitor",    # HP / 3Com
    "network",    # generic
    "snmp",       # generic
    "default",    # generic
    "secret",     # generic
    "SNMP_trap",  # niektore Cisco
]


def _get_credential(db: Session, device: Device, method: CredentialMethod) -> Optional[Credential]:
    """Szuka credentials dla urzadzenia — najpierw dedykowane, potem domyslne (device_id=None).

    Kolejnosc: nizszy numer priority = wyzszy priorytet (bardziej niezawodny/manualny).
    Spojne z kolejnoscia community w _get_db_communities (ASC = nizszy numer pierwszy).
    """
    cred = (
        db.query(Credential)
        .filter(Credential.device_id == device.id, Credential.method == method)
        .order_by(Credential.priority)
        .first()
    )
    if cred:
        return cred
    return (
        db.query(Credential)
        .filter(Credential.device_id == None, Credential.method == method)
        .order_by(Credential.priority)
        .first()
    )


def _has_open_port(device: Device, port: int) -> bool:
    """Sprawdza czy ostatni skan wykazal otwarty port (JSON w scan_results)."""
    if not device.scan_results:
        return False
    latest = max(device.scan_results, key=lambda s: s.scan_time)
    open_ports = latest.open_ports or {}
    return str(port) in open_ports or port in open_ports


def _try_snmp_communities(ip: str, communities: list, delay: float = 3.0) -> Optional[str]:
    """Probuje community stringi sekwencyjnie z opoznieniem — zwraca pierwszy ktory odpowiada.

    Sekwencyjne wysylanie chroni urzadzenia przed burstami UDP i pozwala uniknac
    problemow ze starymi urzadzeniami sieciowymi przy duzej bazie community.
    delay=0 wyłącza opoznienie (np. w testach).
    """
    import time
    from netdoc.collector.drivers.snmp import _snmp_get, OID_SYSNAME

    if not communities:
        return None

    for community in communities:
        try:
            result = _snmp_get(ip, community, OID_SYSNAME, timeout=1)
            if result:
                logger.info("SNMP community '%s' dziala dla %s", community, ip)
                return community
        except Exception:
            pass
        if delay > 0:
            time.sleep(delay)

    return None


def _ensure_snmp_credential(db: Session, device: Device) -> Optional["Credential"]:
    """Zwraca istniejacy credential SNMP lub probuje autodiscovery z listy popularnych.

    Jesli uda sie znalezc dzialajaca community, zapisuje ja w bazie jako global default
    (jezeli nie istnieje) lub per-device (jezeli global juz istnieje z inna wartoscia).

    WAZNE: delay=0 — pipeline skanera nie wprowadza opoznien miedzy community.
    Polite discovery (delay 3s+) nalezy do community-worker (run_community_worker.py).
    Jesli community-worker juz znalazl community (device.snmp_community ustawione),
    pipeline uzywa jej bezposrednio z pomincieciem autodiscovery.
    """
    # Fast-path: community-worker juz znalazl dzialajaca community — uzyj jej
    if device.snmp_community:
        existing = _get_credential(db, device, CredentialMethod.snmp)
        if existing:
            return existing
        # Cred moze byc w DB pod inna nazwa — zwroc syntetyczny z community
        from netdoc.storage.models import Credential as Cred
        fast = db.query(Cred).filter(
            Cred.device_id == None, Cred.method == CredentialMethod.snmp,
            Cred.username == device.snmp_community,
        ).first()
        if fast:
            return fast

    # Sprawdz czy juz mamy credential (device-specific lub global)
    existing = _get_credential(db, device, CredentialMethod.snmp)
    if existing:
        return existing

    # Sprawdz czy SNMP credential testing jest wlaczony w ustawieniach
    from netdoc.storage.models import SystemStatus
    _snmp_flag = db.query(SystemStatus).filter(SystemStatus.key == "cred_snmp_enabled").first()
    if _snmp_flag and _snmp_flag.value == "0":
        return None

    # Autodiscovery — tylko jesli port 161 otwarty
    if not _has_open_port(device, 161):
        return None

    # Odczytaj community strings z DB (posortowane po priorytecie), fallback do hardcoded listy
    db_communities = [
        c.username for c in
        db.query(Credential)
          .filter(Credential.device_id == None, Credential.method == CredentialMethod.snmp)
          .order_by(Credential.priority)
          .all()
        if c.username
    ]
    # delay=0: pipeline nie czeka miedzy probami — to zadanie community-worker
    working = _try_snmp_communities(device.ip, db_communities or SNMP_COMMUNITY_FALLBACK, delay=0)
    if not working:
        logger.debug("SNMP: zadna community nie dziala dla %s", device.ip)
        return None

    # Sprawdz czy global default juz istnieje z ta sama wartoscia
    from datetime import datetime
    global_cred = (
        db.query(Credential)
        .filter(Credential.device_id == None, Credential.method == CredentialMethod.snmp,
                Credential.username == working)
        .first()
    )
    if global_cred:
        global_cred.last_success_at = datetime.utcnow()
        global_cred.success_count = (global_cred.success_count or 0) + 1
        db.commit()
        return global_cred

    # Zapisz jako nowy global default (lub per-device jesli global ma inna wartosc)
    global_any = (
        db.query(Credential)
        .filter(Credential.device_id == None, Credential.method == CredentialMethod.snmp)
        .first()
    )
    if global_any is None:
        # Pierwszy dzialajacy — zapisz jako global default
        cred = Credential(
            device_id=None,
            method=CredentialMethod.snmp,
            username=working,
            notes=f"Auto-discovered: {working}",
            priority=50,
            last_success_at=datetime.utcnow(),
        )
        logger.info("SNMP: zapisano nowy global default community '%s'", working)
    else:
        # Global ma inna wartosc — zapisz per-device
        cred = Credential(
            device_id=device.id,
            method=CredentialMethod.snmp,
            username=working,
            notes=f"Auto-discovered: {working}",
            priority=10,
            last_success_at=datetime.utcnow(),
        )
        logger.info("SNMP: zapisano per-device community '%s' dla %s", working, device.ip)
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return cred


def _pick_drivers(db: Session, device: Device) -> List[BaseDriver]:
    """
    Zwraca liste driverow do uzycia dla danego urzadzenia, w kolejnosci priorytetu.
    Kazdy driver jest opcjonalny — pomijamy jesli brak credentials lub portow.
    """
    drivers: List[BaseDriver] = []

    # 1. SNMP — probuj TYLKO na urzadzeniach gdzie SNMP ma sens:
    #   a) port 161 wykryty (UDP — rzadkie w TCP scan, ale mozliwe po pelnym skanie)
    #   b) typ urzadzenia = znane urzadzenie sieciowe (router/switch/ap/firewall)
    #   c) snmp_community juz znana (wczesniej dzialalo — fast-path)
    # NIE probujemy: unknown, camera, printer, workstation, iot bez wcześniejszego SNMP
    from netdoc.storage.models import DeviceType as DT
    _snmp_candidates = {DT.router, DT.switch, DT.ap, DT.firewall}
    if (_has_open_port(device, 161)
            or device.device_type in _snmp_candidates
            or device.snmp_community is not None):
        snmp_cred = _ensure_snmp_credential(db, device)
        if snmp_cred:
            community = snmp_cred.username or "public"
            drivers.append(SNMPDriver(ip=device.ip, credential=snmp_cred, community=community))

    # 2. UniFi API — TYLKO dla urzadzen Ubiquiti i tylko gdy credentials skonfigurowane
    # Warunek: vendor zawiera "ubiquiti"/"ubnt" LUB device_id ma per-device api credential
    _vendor_lower = (device.vendor or "").lower()
    _is_ubiquiti = any(k in _vendor_lower for k in ("ubiquiti", "ubnt", "unifi"))
    if _is_ubiquiti or settings.unifi_username:
        unifi_cred = _get_credential(db, device, CredentialMethod.api)
        # Jesli nie znamy vendora (brak info) i brak explicit config — pomijamy
        if settings.unifi_username or (_is_ubiquiti and unifi_cred):
            drivers.append(UnifiDriver(ip=device.ip, credential=unifi_cred))

    # 3. Cisco SSH — jezeli port 22 otwarty i sa credentials
    ssh_cred = _get_credential(db, device, CredentialMethod.ssh)
    if ssh_cred and _has_open_port(device, 22):
        # Rozroznij Cisco vs MikroTik po vendorze (z discovery)
        vendor = (device.vendor or "").lower()
        if "cisco" in vendor:
            drivers.append(CiscoDriver(ip=device.ip, credential=ssh_cred))
        elif "mikrotik" in vendor or "routeros" in vendor:
            drivers.append(MikrotikDriver(ip=device.ip, credential=ssh_cred))
        else:
            # nieznany vendor z SSH — sprobuj Cisco (ntc-templates, najszersza baza)
            drivers.append(CiscoDriver(ip=device.ip, credential=ssh_cred))


    # 4. Modbus TCP / SunSpec — falowniki PV, UPS, systemy energetyczne (port 502)
    if _has_open_port(device, 502):
        drivers.append(ModbusDriver(ip=device.ip))

    return drivers


def _apply_device_data(db: Session, device: Device, data: DeviceData) -> None:
    """Zapisuje szczegolowe dane z drivera do bazy (interfejsy, sasiedzi)."""
    # Aktualizuj pola urzadzenia
    hostname_before = device.hostname
    for field in ("hostname", "mac", "vendor", "model", "os_version"):
        value = getattr(data, field, None)
        if value and not getattr(device, field):
            setattr(device, field, value)
    if data.location and not device.location:
        device.location = data.location

    # Reklasyfikuj jesli hostname sie zmienil (np. Ubiquiti switch/AP po SNMP)
    if data.hostname and data.hostname != hostname_before and device.vendor:
        from netdoc.collector.discovery import _guess_device_type
        # Pobierz rzeczywiste porty z ostatniego skanu (nie pusty set!)
        _reclass_ports: set = set()
        _reclass_detail: dict = {}
        if device.scan_results:
            _latest = max(device.scan_results, key=lambda s: s.scan_time)
            if _latest.open_ports:
                try:
                    _reclass_ports = {int(p) for p in _latest.open_ports.keys()}
                    _reclass_detail = {int(p): v for p, v in _latest.open_ports.items()
                                       if isinstance(v, dict)}
                except (ValueError, TypeError):
                    pass
        new_type = _guess_device_type(
            _reclass_ports, device.os_version, device.vendor, device.mac,
            hostname=device.hostname, open_ports_detail=_reclass_detail,
        )
        if new_type not in ("unknown",) and new_type != device.device_type:
            from netdoc.storage.models import DeviceType
            if new_type != DeviceType.unknown:
                device.device_type = new_type

    # Interfejsy — upsert po nazwie
    existing = {iface.name: iface for iface in device.interfaces}
    for idata in data.interfaces:
        if idata.name in existing:
            iface = existing[idata.name]
            iface.oper_status = idata.oper_status
            iface.admin_status = idata.admin_status
            if idata.speed:
                iface.speed = idata.speed
            if idata.ip:
                iface.ip = idata.ip
        else:
            db.add(Interface(
                device_id=device.id,
                name=idata.name,
                ip=idata.ip,
                mac=idata.mac,
                speed=idata.speed,
                duplex=idata.duplex,
                admin_status=idata.admin_status,
                oper_status=idata.oper_status,
                description=idata.description,
            ))

    # Polaczenia topologiczne z LLDP/CDP
    for neighbor in data.neighbors:
        if not neighbor.remote_ip:
            continue
        remote_device = db.query(Device).filter(Device.ip == neighbor.remote_ip).first()
        if not remote_device:
            continue
        existing_link = (
            db.query(TopologyLink)
            .filter(
                TopologyLink.src_device_id == device.id,
                TopologyLink.dst_device_id == remote_device.id,
            )
            .first()
        )
        if not existing_link:
            db.add(TopologyLink(
                src_device_id=device.id,
                dst_device_id=remote_device.id,
                protocol=TopologyProtocol(neighbor.protocol),
                confidence=Confidence.auto,
            ))

    # Rejestruj podsieci odkryte przez LLDP jako nowe cele skanowania
    for neighbor in data.neighbors:
        if not neighbor.remote_ip or not is_private(neighbor.remote_ip):
            continue
        prefix = infer_prefix_from_ip(neighbor.remote_ip)
        cidr = subnet_from_ip(neighbor.remote_ip, prefix)
        if cidr:
            try:
                register_network(db, cidr)
                logger.debug("LLDP: zarejestrowano nowa siec %s", cidr)
            except Exception:
                pass  # nie przerywaj pipeline z powodu rejestracji sieci

    db.commit()


def collect_device(db: Session, device: Device) -> bool:
    """
    Zbiera szczegolowe dane z pojedynczego urzadzenia.

    Returns:
        True jezeli przynajmniej jeden driver zdal dane, False jezeli brak danych.
    """
    drivers = _pick_drivers(db, device)

    if not drivers:
        logger.debug("%s: brak driverow (brak credentials / portow) — tylko dane z discovery", device.ip)
        return False

    for driver in drivers:
        try:
            logger.debug("%s: probuje driver %s", device.ip, driver.name)
            data = driver.collect()
            if data and (data.hostname or data.interfaces or data.neighbors):
                _apply_device_data(db, device, data)
                from datetime import datetime
                device.last_credential_ok_at = datetime.utcnow()
                # Policz sukces na uzywanym credentialu
                if driver.credential is not None:
                    driver.credential.last_success_at = datetime.utcnow()
                    driver.credential.success_count = (driver.credential.success_count or 0) + 1
                db.commit()
                logger.info("%s: zebrano dane przez %s", device.ip, driver.name)
                return True
        except Exception as exc:
            logger.warning("%s: driver %s nieudany: %s", device.ip, driver.name, exc)

    return False


def run_pipeline(db: Session, devices: List[Device]) -> dict:
    """
    Uruchamia pipeline dla listy urzadzen (po discovery).

    Returns:
        Slownik statystyk: {total, enriched, basic_only}
    """
    enriched = 0
    for device in devices:
        if collect_device(db, device):
            enriched += 1

    stats = {
        "total": len(devices),
        "enriched": enriched,           # dane z drivera (SSH/SNMP/API)
        "basic_only": len(devices) - enriched,  # tylko dane z nmap
    }
    logger.info(
        "Pipeline zakonczone: %d urzadzen, %d wzbogaconych, %d tylko discovery",
        stats["total"], stats["enriched"], stats["basic_only"],
    )
    return stats
