#!/usr/bin/env python
"""
run_scanner.py — Skaner sieciowy NetDoc uruchamiany na hoście Windows.

Uruchamiaj bezpośrednio (nie w Dockerze) — ma pełny dostęp do sieci, ARP, nmap.

Użycie:
    python run_scanner.py             # tryb ciągły — skanuje co SCAN_INTERVAL_MINUTES
    python run_scanner.py --once      # jeden skan i wyjście (debug/test)
    python run_scanner.py --full      # pełny skan portów 1-65535 (wolny)

Wymagania:
    - nmap zainstalowany w C:/Program Files (x86)/Nmap/ lub w PATH
    - psycopg2 w środowisku Python (pip install psycopg2-binary)
    - PostgreSQL w Dockerze (docker compose up -d postgres)

Status skanera widoczny w panelu: http://localhost:5000/settings
"""
import sys
import atexit
import os
import time
import logging
import argparse
from datetime import datetime

# Ustaw DB na localhost:15432 (PostgreSQL w Dockerze) jesli nie ma innego ustawienia
if "DB_URL" not in os.environ:
    os.environ.setdefault("DB_URL", "postgresql+psycopg2://netdoc:netdoc@localhost:15432/netdoc")

# Dodaj katalog projektu do PATH
sys.path.insert(0, os.path.dirname(__file__))

# Katalog logów
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "scanner.log")

_log_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

# Handler stdout
_stdout_handler = logging.StreamHandler(sys.stdout)
_stdout_handler.setFormatter(_log_fmt)

# Handler plik (rotacja 5MB × 5 kopii)
from logging.handlers import RotatingFileHandler
_file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
_file_handler.setFormatter(_log_fmt)

logging.basicConfig(level=logging.INFO, handlers=[_stdout_handler, _file_handler])

# Wycisz nadmierny output z bibliotek
for _noisy in ("paramiko", "urllib3", "requests", "asyncio"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

logger = logging.getLogger("scanner")

# Cooldown między skanami w trybie ciągłym (sekundy)
COOLDOWN_SECONDS = 60


# ── Popularne SNMP community strings do seedowania ────────────────────────────
# Zrodla: SecLists/SNMP, dokumentacja vendorow, SNMP-Brute (SECFORCE), badania publiczne
_DEFAULT_SNMP_COMMUNITIES = [
    # --- Standardowe / RFC ---
    ("public",          10,  "RFC 1157 domyslny read-only — niemal kazde urzadzenie"),
    ("private",         20,  "RFC 1157 domyslny read-write"),
    ("PUBLIC",          25,  "public uppercase — niektorzy producenci case-sensitive"),

    # --- Cisco ---
    ("cisco",           30,  "Cisco IOS/IOS-XE domyslny"),
    ("ILMI",            35,  "Cisco ATM ILMI management"),
    ("cable-docsis",    38,  "Cisco/DOCSIS cable modems i CMTS"),

    # --- HP / HPE / ProCurve / Aruba ---
    ("manager",         40,  "HP ProCurve / HPE domyslny"),
    ("operator",        45,  "HP ProCurve operator"),
    ("hp_admin",        48,  "HP domyslny admin"),
    ("openview",        50,  "HP OpenView NMS"),

    # --- 3Com / SuperStack ---
    ("comcomcom",       55,  "3Com SuperStack II domyslny"),
    ("ITOUCH",          58,  "3Com ITOUCH / NetBuilder"),
    ("3com",            60,  "3Com generic"),

    # --- Juniper / NetScreen ---
    ("netscreen",       63,  "Juniper NetScreen firewall domyslny"),
    ("ns3read",         65,  "Juniper NetScreen SSG read"),
    ("ns3write",        67,  "Juniper NetScreen SSG write"),

    # --- Extreme Networks / Brocade ---
    ("extreme",         70,  "Extreme Networks domyslny"),
    ("brocade",         73,  "Brocade / Ruckus domyslny"),
    ("NetIron",         75,  "Brocade NetIron"),

    # --- Nortel / Avaya ---
    ("nortel",          78,  "Nortel Ethernet Routing Switch"),
    ("avaya",           80,  "Avaya Communications"),

    # --- Monitoring ogolny ---
    ("monitor",         83,  "Monitoring default — wiele urzadzen"),
    ("community",       85,  "Generic fallback"),
    ("snmp",            87,  "Generic SNMP daemon"),
    ("mngt",            89,  "Management generic"),
    ("admin",           91,  "Admin default — D-Link, NetGear, TP-Link"),
    ("network",         93,  "Generic network management"),
    ("ro",              95,  "Read-only skrot"),
    ("rw",              97,  "Read-write skrot"),

    # --- Kamery IP / CCTV ---
    ("write",          101,  "Axis Communications kamera domyslny write"),

    # --- UPS ---
    ("ups",            105,  "Generic UPS SNMP"),
    ("apc",            107,  "APC Smart-UPS / Schneider Electric UPS"),
    ("eaton",          109,  "Eaton UPS domyslny"),
    ("liebert",        111,  "Vertiv / Liebert UPS"),

    # --- Drukarki / urządzenia biurowe ---
    ("printer",        113,  "Generic printer SNMP"),
    ("internal",       115,  "HP LaserJet internal management"),

    # --- OT / BAS / Building Automation ---
    ("siemens",        120,  "Siemens Desigo / PXC / BACnet gateway"),
    ("schneider",      122,  "Schneider Electric EcoStruxure / BMS"),
    ("bacnet",         124,  "BACnet/IP SNMP proxy gateway"),
    ("tac",            126,  "TAC / Andover Controls BAS"),
    ("johnson",        128,  "Johnson Controls Metasys BMS"),
    ("honeywell",      130,  "Honeywell BMS / EBI"),

    # --- IBM / Sun ---
    ("tivoli",         133,  "IBM Tivoli Network Manager"),
    ("netman",         135,  "Ogolny NMS fallback"),

    # --- Telecom / ISP (popularne w Polsce: ZTE w FTTB/GPON, Huawei OLT, Nokia) ---
    ("zte",            175,  "ZTE GPON/FTTB/router — popularne u polskich ISP"),
    ("huawei",         177,  "Huawei OLT / ONU / router / switch"),
    ("alcatel",        179,  "Alcatel-Lucent / Nokia 7750 SR / ISAM"),
    ("nokia",          181,  "Nokia (dawniej Alcatel-Lucent) sprzet sieciowy"),
    ("dasan",          183,  "DASAN Networks GPON OLT/ONU"),
    ("zhone",          185,  "Zhone / DZS DSL/GPON"),
    ("ubnt",           187,  "Ubiquiti Networks (EdgeSwitch, EdgeRouter, UniFi)"),
    ("mikrotik",       189,  "MikroTik RouterOS — bardzo popularny w Polsce"),
    ("zyxel",          191,  "ZyXEL switch/router/modem"),
    ("dlink",          193,  "D-Link domyslny"),
    ("tplink",         195,  "TP-Link domyslny (czesto 'public' ale bywa 'tplink')"),

    # --- Wirtualizacja / serwery ---
    ("vmware",         200,  "VMware ESXi SNMP agent"),
    ("sun",            202,  "Sun Microsystems / Oracle Solaris domyslny"),
    ("oracle",         204,  "Oracle hardware (SPARC, x86 servers)"),
    ("ibm",            206,  "IBM BladeCenter / System x"),
    ("dell",           208,  "Dell iDRAC / OpenManage SNMP"),
    ("supermicro",     210,  "Supermicro IPMI / BMC SNMP"),
    ("linux",          212,  "snmpd domyslna konfiguracja Linux (net-snmp)"),

    # --- Energia / falowniki PV / OZE ---
    # Wiekszosc falownikow (SMA, Fronius, SolarEdge) uzywa Modbus/SunSpec.
    # Niektore starsze lub bramki SNMP uzyja ponizszych.
    ("sma",            215,  "SMA Solar (starsze urzadzenia z SNMP, np. Sunny WebBox)"),
    ("fronius",        217,  "Fronius Solar / Datamanager (niektore wersje)"),
    ("sungrow",        219,  "Sungrow logger / bramka SNMP"),
    ("growatt",        221,  "Growatt ShineWifi / logger"),
    ("solaredge",      223,  "SolarEdge Gateway / monitoring"),
    ("victron",        225,  "Victron Energy Color Control GX"),
    ("power",          227,  "Generic power/energy management"),
    ("energy",         229,  "Generic energy system SNMP"),

    # --- Switche zarzadzalne / biurowe ---
    ("netgear",        232,  "NetGear Smart Switch domyslny"),
    ("linksys",        234,  "Linksys / Belkin domyslny"),
    ("buffalo",        236,  "Buffalo NAS/switch domyslny"),
    ("edimax",         238,  "Edimax switch / AP domyslny"),
    ("allied",         240,  "Allied Telesis switch domyslny"),
    ("transition",     242,  "Transition Networks media converter"),

    # --- Fallback ogolny ---
    ("readonly",       140,  "Read-only generic"),
    ("secret",         145,  "Generic — czasem uzywany zamiast private"),
    ("default",        148,  "Generic default"),
    ("security",       150,  "Generic security community"),
    ("test",           155,  "Test/dev community — czesto zostawiane na produkcji"),
    ("debug",          158,  "Debug community — stare firmware"),
    ("system",         160,  "System generic"),
    ("pass",           163,  "Generic password-as-community"),
    ("access",         165,  "Generic access"),
    ("enable",         167,  "Cisco-like generic"),
    ("SNMP_trap",      170,  "SNMP trap receiver community"),
    ("trap",           173,  "Trap community generic"),

    # --- Drukarki / MFP — specyficzne community ---
    ("hp_admin",       245,  "HP LaserJet admin community (niektorze modele)"),
    ("hppassword",     247,  "HP LaserJet hppassword (stare JetDirect)"),
    ("KONICA_MINOLTA", 249,  "Konica Minolta PageScope SNMP — domyslny"),
    ("KonicaMinolta",  251,  "Konica Minolta alternatywny"),
    ("XeroxShared",    253,  "Xerox WorkCentre / AltaLink SNMP community"),
    ("epsonpublic",    255,  "Epson EpsonNet SNMP community"),
    ("SharpMFP",       257,  "Sharp MFP SNMP community domyslny"),
    ("lexmark",        259,  "Lexmark SNMP community"),
    ("ricoh",          261,  "Ricoh MFP / Aficio SNMP community"),
    ("kyocera",        263,  "Kyocera Ecosys / TASKalfa community"),
    ("canon",          265,  "Canon imageRUNNER / LBP SNMP community"),
    ("oki",            267,  "OKI MC/C series SNMP community"),
    ("samsung",        269,  "Samsung Printing / Xpress SNMP"),
    ("develop",        271,  "Develop Ineo (OEM Konica Minolta) community"),
    ("nashuatec",      273,  "Nashuatec / Gestetner (OEM Ricoh) community"),
    ("lanier",         275,  "Lanier (OEM Ricoh USA) community"),
    ("savin",          277,  "Savin (OEM Ricoh USA) community"),
    ("infotec",        279,  "Infotec (OEM Ricoh EU) community"),

    # --- Load balancery / ADC ---
    ("f5",             281,  "F5 BIG-IP SNMP community"),
    ("bigip",          283,  "F5 BIG-IP alternatywny"),
    ("netscaler",      285,  "Citrix NetScaler / ADC SNMP"),
    ("a10",            287,  "A10 Networks Thunder / vThunder SNMP"),
    ("kemp",           289,  "Kemp LoadMaster SNMP"),
    ("radware",        291,  "Radware Alteon / Appsafe SNMP"),
    ("barracuda",      293,  "Barracuda Load Balancer ADC SNMP"),

    # --- SAN / Fibre Channel ---
    ("OrigEquipMfr",   295,  "Brocade FC switch domyslny SNMP"),
    ("netman",         297,  "Generic SAN/NAS management (juz mamy ale duplikat ok)"),
    ("storageWorks",   299,  "HP StorageWorks / MSA SNMP"),
    ("IBM_TS",         301,  "IBM Tape Storage SNMP community"),

    # --- Wideokonferencje ---
    ("tandberg",       303,  "Cisco Webex Room / Tandberg SNMP community"),
    ("polycom",        305,  "Polycom RealPresence / Group SNMP"),
    ("lifesize",       307,  "Lifesize Icon SNMP community"),

    # --- KVM / Console servers ---
    ("raritan",        309,  "Raritan KVM / PX PDU SNMP"),
    ("cyclades",       311,  "Cyclades / Avocent console server SNMP"),
    ("opengear",       313,  "Opengear console server SNMP"),
    ("lantronix",      315,  "Lantronix EDS / SCS SNMP"),

    # --- PDU / Intelligent Power ---
    ("sysuser",        317,  "Server Technology POPS / Switched CDU domyslny"),
    ("geist",          319,  "Geist / Vertiv Watchdog PDU SNMP"),
    ("akcp",           321,  "AKCP SensorProbe / MasterProbe SNMP"),
    ("emerson",        323,  "Emerson / Liebert (PDU i monitoring) SNMP"),

    # --- Switche zarzadzalne (brakujace) ---
    ("arista",         325,  "Arista EOS switch SNMP community"),
    ("juniper",        327,  "Juniper EX/QFX switch SNMP (juz mamy 'netscreen' ale to inny produkt)"),
    ("omniswitch",     329,  "Alcatel-Lucent Enterprise OmniSwitch SNMP"),
    ("moxa",           331,  "Moxa industrial switch / serial server SNMP"),
    ("hirschmann",     333,  "Hirschmann / Belden industrial switch SNMP"),
    ("tplink",         335,  "TP-Link Omada managed switch/AP SNMP"),

    # --- Firewalle (brakujace) ---
    ("paloalto",       337,  "Palo Alto Networks PA-series SNMP community"),
    ("panorama",       339,  "Palo Alto Panorama management SNMP"),
    ("checkpoint",     341,  "Check Point Firewall-1 / Gaia SNMP"),
    ("cpublic",        343,  "Check Point alternatywny read community"),
    ("sophos",         345,  "Sophos XG / UTM / SG SNMP community"),
    ("stormshield",    347,  "Stormshield SNS / SN SNMP"),
    ("watchguard",     349,  "WatchGuard Firebox SNMP"),
    ("barracuda",      351,  "Barracuda CloudGen / NextGen Firewall SNMP"),
    ("pfsense",        353,  "pfSense / OPNsense SNMP community"),

    # --- NAS (brakujace) ---
    ("asustor",        355,  "Asustor NAS ADM SNMP"),
    ("terramaster",    357,  "Terramaster TOS NAS SNMP"),

    # --- Telecom (brakujace) ---
    ("audiocodes",     359,  "AudioCodes Mediant SBC/GW SNMP community"),
    ("patton",         361,  "Patton SmartNode / SN gateway SNMP"),
    ("ribbon",         363,  "Ribbon / GENBAND SBC SNMP"),
    ("isadmin",        365,  "Alcatel-Lucent ISAM DSLAM admin community"),

    # --- Serwery BMC (brakujace) ---
    ("iDRAC",          367,  "Dell iDRAC SNMP community (wielka litera)"),
    ("iLO",            369,  "HPE iLO SNMP community"),

    # --- Routery/modemy szerokopasmowe ---
    ("fritzbox",       371,  "AVM Fritz!Box (popularny w DE/AT/PL z DSL) SNMP"),
    ("technicolor",    373,  "Technicolor / Thomson DSL modem SNMP"),
    ("sagemcom",       375,  "Sagemcom DSL/fiber modem SNMP"),
    ("speedtouch",     377,  "Speedtouch / Alcatel DSL modem SNMP"),
    # ═══════════════════════════════════════════════════════════════════════════
    # KAMERY IP — dedykowane community
    # ═══════════════════════════════════════════════════════════════════════════

    # Hikvision (najpopularniejszy na swiecie)
    ("hikvision",   55, "Hikvision IP camera/NVR — custom community"),
    ("hiksnmp",     55, "Hikvision alternatywny community string"),

    # Dahua (drugi co do popularnosci)
    ("dahua",       56, "Dahua IP camera/NVR — custom community"),

    # Axis Communications (Szwecja, czesto w korporacjach)
    ("axis",        57, "Axis IP camera — SNMP community"),

    # Uniview / UNV (Chiny)
    ("uniview",     58, "Uniview/UNV camera — SNMP community"),
    ("unv",         58, "Uniview short alias"),

    # Vivotek (Tajwan)
    ("vivotek",     59, "Vivotek IP camera — SNMP community"),

    # Mobotix (Niemcy)
    ("mobotix",     60, "Mobotix MxPEG camera — SNMP"),

    # Pelco (USA, Schneider Electric)
    ("pelco",       61, "Pelco IP camera / Endura VMS — SNMP"),

    # GeoVision (Tajwan)
    ("geovision",   62, "GeoVision NVR/DVR/camera — SNMP"),

    # FLIR / Teledyne
    ("flir",        63, "FLIR thermal / IP camera — SNMP"),

    # Sony (kamery sieciowe)
    ("sony",        64, "Sony SNC / SSC IP camera — SNMP"),

    # Panasonic (kamery/PBX)
    ("panasonic",   65, "Panasonic WV / BB series camera — SNMP"),

    # Foscam / Amcrest
    ("foscam",      66, "Foscam IP camera — SNMP community"),
    ("amcrest",     66, "Amcrest / Q-See / Lorex — SNMP"),

    # Bosch (kamery / DIVAR NVR)
    ("bosch",       67, "Bosch FLEXIDOME / DIVAR — SNMP"),

    # ACTi (Tajwan)
    ("acti",        68, "ACTi IP camera — SNMP community"),

    # Avigilon (Motorola Solutions)
    ("avigilon",    69, "Avigilon IP camera / ACC — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # NAS — dedykowane community
    # ═══════════════════════════════════════════════════════════════════════════

    # QNAP
    ("qnap",        75, "QNAP NAS — SNMP community"),
    ("qnapSnmp",    75, "QNAP NAS alternatywny"),

    # WD My Cloud
    ("wd",          76, "WD My Cloud NAS — SNMP"),
    ("wdnas",       76, "WD My Cloud NAS alternatywny"),

    # NetApp (enterprise)
    ("netapp",      77, "NetApp ONTAP — SNMP community"),
    ("ntap",        77, "NetApp short alias"),

    # TrueNAS / FreeNAS
    ("truenas",     78, "TrueNAS CORE/SCALE — SNMP"),
    ("freenas",     78, "FreeNAS legacy — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # WIFI / WIRELESS — brakujace marki
    # ═══════════════════════════════════════════════════════════════════════════

    # Ruckus / CommScope
    ("ruckus",      82, "Ruckus ZoneDirector / SmartZone AP — SNMP"),
    ("unleashed",   82, "Ruckus Unleashed — SNMP community"),

    # Cambium Networks
    ("cambium",     83, "Cambium ePMP / cnMaestro AP — SNMP"),
    ("cambiumNetworks", 83, "Cambium alternatywny"),

    # Peplink / Pepwave
    ("peplink",     84, "Peplink / Pepwave router — SNMP"),

    # EnGenius
    ("engenius",    85, "EnGenius AP / switch — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # FIREWALL — brakujace marki
    # ═══════════════════════════════════════════════════════════════════════════

    # FortiGate / Fortinet
    ("fortinet",    90, "Fortinet FortiGate — SNMP community"),
    ("fortigate",   90, "FortiGate alternatywny"),
    ("FGTread",     90, "FortiGate read-only community string"),

    # SonicWall
    ("sonicwall",   91, "SonicWall firewall — SNMP"),
    ("SonicWall",   91, "SonicWall case-sensitive"),

    # OPNsense
    ("opnsense",    92, "OPNsense — SNMP community"),

    # ═══════════════════════════════════════════════════════════════════════════
    # DRUKARKI — brakujace marki
    # ═══════════════════════════════════════════════════════════════════════════

    # Brother
    ("brother",    100, "Brother laser/inkjet — SNMP community"),
    ("BRAdmin",    100, "Brother BRAdmin alternatywny"),

    # ═══════════════════════════════════════════════════════════════════════════
    # PBX / TELEFONY — brakujace marki
    # ═══════════════════════════════════════════════════════════════════════════

    # Grandstream (UCM PBX + GXP phones)
    ("grandstream",105, "Grandstream UCM PBX / GXP phone — SNMP"),

    # Yealink (phones)
    ("yealink",    106, "Yealink T/W/CP series — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # NVR/DVR — dodatkowe marki
    # ═══════════════════════════════════════════════════════════════════════════

    # Tiandy
    ("tiandy",     110, "Tiandy NVR/DVR — SNMP community"),

    # Kedacom
    ("kedacom",    111, "Kedacom NVR — SNMP"),

    # NUUO
    ("nuuo",       112, "NUUO Titan/Crystal NVR — SNMP"),

    # ANNKE (OEM Hikvision)
    ("annke",      113, "ANNKE NVR — SNMP community"),

    # ═══════════════════════════════════════════════════════════════════════════
    # ROUTERY SOFTWARE / NOWE MARKI
    # ═══════════════════════════════════════════════════════════════════════════
    ("vyos",        145, "VyOS software router — SNMP"),
    ("cumulus",     146, "Cumulus Linux (NVIDIA) — SNMP"),
    ("teltonika",   147, "Teltonika RUT series — SNMP community"),
    ("gliinet",     148, "GL.iNet router — SNMP"),
    ("aruba",       149, "HPE Aruba (AP / switch / ClearPass) — SNMP"),
    ("clearpass",   149, "Aruba ClearPass NAC — SNMP"),
    ("draytek",     150, "DrayTek Vigor router — SNMP"),
    ("cradlepoint", 151, "Cradlepoint / NetCloud — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # SYSTEMY POZAROWE
    # ═══════════════════════════════════════════════════════════════════════════
    ("notifier",    155, "Notifier / Fire-Lite Honeywell Fire — SNMP"),
    ("cerberus",    156, "Siemens Cerberus PRO / Desigo Fire — SNMP"),
    ("esser",       157, "Esser / Hochiki fire panel — SNMP"),
    ("mircom",      158, "Mircom FX fire panel — SNMP"),
    ("kentec",      159, "Kentec Syncro fire panel — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # BRAMY / KONTROLERY DOSTEPU
    # ═══════════════════════════════════════════════════════════════════════════
    ("faac",        162, "FAAC gate controller — SNMP"),
    ("satel",       163, "SATEL INTEGRA alarm / dostepu — SNMP"),
    ("roger",       164, "Roger RACS5 kontroler dostepu — SNMP"),
    ("doorbird",    165, "DoorBird IP interkom — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # MIERNIKI ENERGII
    # ═══════════════════════════════════════════════════════════════════════════
    ("janitza",     168, "Janitza UMG / GridVis power meter — SNMP"),
    ("kamstrup",    169, "Kamstrup OMNIPOWER meter — SNMP"),
    ("landis",      170, "Landis+Gyr smart meter — SNMP"),
    ("itron",       171, "Itron smart meter — SNMP"),
    ("socomec",     172, "Socomec DIRIS / NETYS — SNMP"),
    ("powerlogic",  173, "Schneider PowerLogic PM — SNMP"),
    ("gavazzi",     174, "Carlo Gavazzi EM / VMU-C — SNMP"),
    ("iskra",       175, "Iskraemeco smart meter — SNMP"),
    ("abb",         176, "ABB B-Series / Ability power meter — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # STACJE POGODOWE
    # ═══════════════════════════════════════════════════════════════════════════
    ("vaisala",     179, "Vaisala HMT / RFL sensor — SNMP"),
    ("campbell",    180, "Campbell Scientific datalogger — SNMP"),
    ("davis",       181, "Davis WeatherLink — SNMP"),
    ("lufft",       182, "Lufft / OTT HydroMet sensor — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # LADOWARKI EV
    # ═══════════════════════════════════════════════════════════════════════════
    ("keba",        185, "Keba KeContact P30 — SNMP"),
    ("wallbox",     186, "Wallbox Pulsar / Commander — SNMP"),
    ("evlink",      187, "Schneider EVlink — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # MONITORING / NMS
    # ═══════════════════════════════════════════════════════════════════════════
    ("prtg",        190, "PRTG Network Monitor — SNMP trap community"),
    ("solarwinds",  191, "SolarWinds Orion — SNMP"),
    ("nagios",      192, "Nagios / Icinga — SNMP trap community"),

    # ═══════════════════════════════════════════════════════════════════════════
    # SMART HOME
    # ═══════════════════════════════════════════════════════════════════════════
    ("loxone",      195, "Loxone Miniserver — SNMP"),
    ("crestron",    196, "Crestron control system — SNMP"),
    ("control4",    197, "Control4 Director — SNMP"),
    ("amx",         198, "AMX NetLinx — SNMP"),
    ("rademacher",  199, "Rademacher HomePilot — SNMP"),
    ("devolo",      200, "devolo Home Control — SNMP"),
    ("somfy",       201, "Somfy TaHoma — SNMP"),
    ("gira",        202, "Gira HomeServer / KNX — SNMP"),
    ("hager",       203, "Hager Domovea — SNMP"),
    ("bticino",     204, "Bticino / Legrand MyHOME — SNMP"),
    ("zipato",      205, "Zipato Hub — SNMP"),

]


# ── Domyslne credentials SSH/Telnet — audit niezabezpieczonych urzadzen ───────
# Zrodla: CIRT.net default passwords, SecLists/Passwords/Default-Credentials,
# dokumentacja producencka, badania CVE (publiczne).
# Kolejnosc = priorytet proby (nizszy numer = wyzszy priorytet / czesciej skuteczny).
_DEFAULT_SSH_CREDENTIALS = [
    # (username, password, priority, notes)

    # --- Brak hasla / puste haslo (najczesciej skuteczne) ---
    ("admin",        "",              10,  "admin / brak hasla — MikroTik, ZTE, Huawei ONU, tanie routery"),
    ("root",         "",              12,  "root / brak hasla — wbudowane Linux, embedded firmware"),
    ("admin",        "admin",         15,  "admin/admin — klasyczny niezabezpieczony default (D-Link, Asus, wiele tanich)"),
    ("admin",        "password",      20,  "admin/password — Windows Server, generyczny domyslny"),
    ("admin",        "1234",          22,  "admin/1234 — TP-Link, D-Link, ZTE starsze"),
    ("admin",        "12345",         24,  "admin/12345 — tanie routery i kamery"),
    ("admin",        "123456",        26,  "admin/123456 — bardzo popularny w chinskich OEM"),
    ("admin",        "admin123",      28,  "admin/admin123 — alternatywny default"),

    # --- root ---
    ("root",         "root",          30,  "root/root — embedded Linux (OpenWrt fresh install)"),
    ("root",         "password",      32,  "root/password — generyczny Linux"),
    ("root",         "admin",         34,  "root/admin — niektorze urzadzenia NAS/kamera"),
    ("root",         "toor",          36,  "root/toor — Kali/BackTrack reversed root"),
    ("root",         "1234",          38,  "root/1234 — tanie urzadzenia CCTV"),

    # --- Cisco ---
    ("cisco",        "cisco",         40,  "cisco/cisco — Cisco IOS klasyczny default"),
    ("cisco",        "",              42,  "cisco / brak hasla — niektorzy operatorzy"),
    ("admin",        "cisco",         44,  "admin/cisco — Cisco ISE / Cisco WAP"),
    ("enable",       "",              46,  "enable / brak hasla — Cisco enable mode"),
    ("cisco",        "password",      48,  "cisco/password — generyczny Cisco"),

    # --- MikroTik ---
    ("admin",        "",              50,  "admin / brak hasla — MikroTik RouterOS domyslny (do wersji 6.49)"),

    # --- Ubiquiti ---
    ("ubnt",         "ubnt",          55,  "ubnt/ubnt — Ubiquiti AirOS / EdgeOS domyslny"),
    ("admin",        "ubnt",          57,  "admin/ubnt — Ubiquiti UniFi niektorze firmware"),

    # --- Huawei ---
    ("admin",        "Admin@huawei",  60,  "admin/Admin@huawei — Huawei enterprise (nowe firmware)"),
    ("admin",        "huawei@123",    62,  "admin/huawei@123 — Huawei OLT / ONU"),
    ("root",         "huawei123",     64,  "root/huawei123 — Huawei serwisowy"),
    ("huawei",       "huawei",        66,  "huawei/huawei — stare Huawei DSL/ONU"),
    ("admin",        "Huawei@123456", 68,  "admin/Huawei@123456 — Huawei nowsza seria"),

    # --- ZTE ---
    ("admin",        "zte_admin",     70,  "admin/zte_admin — ZTE OLT/ONT domyslny"),
    ("admin",        "Admin1234!",    72,  "admin/Admin1234! — ZTE nowszy firmware"),
    ("zte",          "zte",           74,  "zte/zte — ZTE alternatywny default"),
    ("support",      "zte_support",   76,  "support/zte_support — ZTE serwisowy"),

    # --- Juniper / NetScreen ---
    ("netscreen",    "netscreen",     80,  "netscreen/netscreen — Juniper NetScreen domyslny"),
    ("admin",        "netscreen",     82,  "admin/netscreen — NetScreen alternatywny"),

    # --- HP ProCurve / Aruba ---
    ("manager",      "manager",       85,  "manager/manager — HP ProCurve switch domyslny"),
    ("operator",     "operator",      87,  "operator/operator — HP ProCurve operator"),
    ("admin",        "HP@1234",       89,  "admin/HP@1234 — HPE Aruba nowy default"),

    # --- Fortinet / FortiGate ---
    ("admin",        "",              91,  "admin / brak hasla — FortiGate domyslny (stary firmware)"),

    # --- SonicWall ---
    ("admin",        "password",      93,  "admin/password — SonicWall domyslny"),

    # --- Ruckus / Brocade ---
    ("super",        "sp-admin",      98,  "super/sp-admin — Ruckus ZoneDirector / Unleashed"),
    ("admin",        "ruckus",       100,  "admin/ruckus — Ruckus generic"),

    # --- Axis (kamery IP) ---
    ("root",         "pass",         103,  "root/pass — Axis Communications kamera domyslny"),
    ("admin",        "axis",         105,  "admin/axis — Axis alternatywny"),

    # --- DAHUA / Hikvision (CCTV) ---
    ("admin",        "12345",        107,  "admin/12345 — Dahua NVR/DVR domyslny"),
    ("admin",        "Admin12345",   111,  "admin/Admin12345 — Hikvision nowszy"),

    # --- NAS (QNAP / Synology) ---
    ("admin",        "admin",        113,  "admin/admin — QNAP NAS domyslny"),

    # --- Ogolne serwery / OT / SCADA ---
    ("user",         "user",         120,  "user/user — generyczny konto uzytkownika"),
    ("user",         "password",     122,  "user/password — generyczny"),
    ("guest",        "guest",        124,  "guest/guest — konto goscia"),
    ("test",         "test",         126,  "test/test — konta testowe zostawiane na produkcji"),
    ("service",      "service",      128,  "service/service — konto serwisowe"),
    ("support",      "support",      130,  "support/support — konto supportowe"),
    ("monitor",      "monitor",      132,  "monitor/monitor — konto monitoringu"),
    ("operator",     "",             134,  "operator / brak hasla — OT/SCADA"),
    ("supervisor",   "",             136,  "supervisor / brak hasla — OT/SCADA Schneider, Rockwell"),
    ("admin",        "0000",         138,  "admin/0000 — niektorze chiskie urzadzenia"),
    ("admin",        "111111",       140,  "admin/111111 — popularny w azjatyckich OEM"),
    ("admin",        "888888",       142,  "admin/888888 — chiski default IoT"),

    # --- Raspberry Pi ---
    ("pi",           "raspberry",    150,  "pi/raspberry — Raspberry Pi OS domyslny"),
    ("pi",           "pi",           152,  "pi/pi — alternatywny Raspberry"),

    # --- Serwery IPMI / iDRAC / iLO ---
    ("root",         "calvin",       155,  "root/calvin — Dell iDRAC domyslny"),
    ("Administrator","",             157,  "Administrator / brak hasla — HPE iLO inicjalne"),
    ("ADMIN",        "ADMIN",        159,  "ADMIN/ADMIN — Supermicro IPMI domyslny"),

    # ═══════════════════════════════════════════════════════════════════════════
    # KAMERY IP / REJESTRATORY DVR/NVR / CCTV
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Hikvision (najpopularniejsze kamery IP na swiecie) ---
    ("admin",        "12345",        160,  "admin/12345 — Hikvision starszy firmware (do 2016)"),
    ("admin",        "Admin12345",   161,  "admin/Admin12345 — Hikvision nowszy (polityka hasel)"),
    ("admin",        "hik12345",     162,  "admin/hik12345 — Hikvision OEM"),
    ("888888",       "888888",       163,  "888888/888888 — Hikvision legacy PIN"),
    ("666666",       "666666",       164,  "666666/666666 — Hikvision legacy alternatywny"),

    # --- Dahua (drugie miejsce na rynku CCTV) ---
    ("admin",        "admin",        165,  "admin/admin — Dahua starszy firmware"),
    ("admin",        "",             166,  "admin / brak hasla — Dahua nowszy (wymusze ustawienia)"),
    ("admin",        "dahua1234",    167,  "admin/dahua1234 — Dahua OEM"),
    ("888888",       "888888",       168,  "888888/888888 — Dahua 'super' konto"),
    ("666666",       "666666",       169,  "666666/666666 — Dahua operator legacy"),

    # --- Axis Communications ---
    ("root",         "pass",         170,  "root/pass — Axis domyslny do firmware 5.51"),
    ("root",         "root",         171,  "root/root — Axis alternatywny"),
    ("admin",        "admin",        172,  "admin/admin — Axis kamer starszych linii"),

    # --- Amcrest / Lorex / Q-See (OEM Dahua) ---
    ("admin",        "admin",        173,  "admin/admin — Amcrest/Q-See/Lorex (OEM Dahua)"),
    ("admin",        "amcrest2021",  174,  "admin/amcrest2021 — Amcrest nowszy"),
    ("admin",        "admin1234",    175,  "admin/admin1234 — Lorex"),

    # --- Foscam ---
    ("admin",        "",             176,  "admin / brak hasla — Foscam starszy"),
    ("admin",        "foscam",       177,  "admin/foscam — Foscam"),

    # --- Reolink ---
    ("admin",        "",             178,  "admin / brak hasla — Reolink (wymagane ustawienie przy pierwszym uruchomieniu)"),

    # --- Vivotek ---
    ("root",         "",             179,  "root / brak hasla — Vivotek domyslny"),
    ("admin",        "admin",        180,  "admin/admin — Vivotek alternatywny"),

    # --- Hanwha / Samsung Techwin ---
    ("admin",        "4321",         181,  "admin/4321 — Hanwha/Samsung Techwin domyslny"),
    ("admin",        "no1done",      182,  "admin/no1done — Samsung starsze kamery"),

    # --- Mobotix ---
    ("admin",        "meinsm",       183,  "admin/meinsm — Mobotix domyslny haslo"),
    ("root",         "meinsm",       184,  "root/meinsm — Mobotix root"),

    # --- Bosch / Pelco / FLIR ---
    ("service",      "service",      185,  "service/service — Bosch IP-kamera serwisowe"),
    ("admin",        "admin",        186,  "admin/admin — Pelco domyslny"),
    ("admin",        "admin",        187,  "admin/admin — FLIR / Teledyne"),

    # --- Uniview (UNV) ---
    ("admin",        "123456",       188,  "admin/123456 — Uniview/UNV domyslny"),

    # --- TVT / Jovision / CP Plus ---
    ("admin",        "1111",         189,  "admin/1111 — TVT DVR"),
    ("admin",        "jvs2011",      190,  "admin/jvs2011 — Jovision"),
    ("admin",        "admin",        191,  "admin/admin — CP Plus (Aditya Infotech OEM)"),

    # --- Zmodo / Night Owl / Swann ---
    ("admin",        "111111",       192,  "admin/111111 — Zmodo"),
    ("admin",        "admin",        193,  "admin/admin — Night Owl / Swann DVR"),

    # ═══════════════════════════════════════════════════════════════════════════
    # REJESTRATORY NVR/DVR — dedykowane marki
    # ═══════════════════════════════════════════════════════════════════════════

    # --- GeoVision (popularny w PL, Tajwan) ---
    ("admin",        "admin",        194,  "admin/admin — GeoVision GV-NVR/DVR domyslny"),
    ("admin",        "",             194,  "admin / brak hasla — GeoVision starszy"),
    ("admin",        "1234",         194,  "admin/1234 — GeoVision alternatywny"),

    # --- LILIN / Merit LILIN (Tajwan, popularny w EU) ---
    ("admin",        "1111",         194,  "admin/1111 — LILIN NVR domyslny PIN"),
    ("admin",        "admin",        194,  "admin/admin — LILIN alternatywny"),
    ("root",         "admin",        194,  "root/admin — LILIN SSH embedded"),

    # --- NUUO (Tajwan, producent NVR/VMS) ---
    ("admin",        "admin",        194,  "admin/admin — NUUO Titan/Crystal domyslny"),
    ("root",         "admin",        194,  "root/admin — NUUO SSH"),

    # --- Avigilon / Motorola Solutions ---
    ("administrator","administrator",194,  "administrator/administrator — Avigilon ACC domyslny"),
    ("admin",        "admin",        194,  "admin/admin — Avigilon NVR"),

    # --- Bosch DIVAR (popularny w korporacjach w PL) ---
    ("admin",        "1234",         194,  "admin/1234 — Bosch DIVAR IP 2000/3000/7000 domyslny"),
    ("service",      "service",      194,  "service/service — Bosch DIVAR serwisowy"),
    ("live",         "live",         194,  "live/live — Bosch DIVAR live view konto"),

    # --- Tiandy (duzy chiński producent NVR, rosnacy udzial w PL) ---
    ("admin",        "111111",       194,  "admin/111111 — Tiandy NVR domyslny"),
    ("admin",        "admin",        194,  "admin/admin — Tiandy alternatywny"),

    # --- Kedacom (Chiny, sporo instalacji w EU) ---
    ("admin",        "admin",        194,  "admin/admin — Kedacom NVR domyslny"),
    ("admin",        "1234",         194,  "admin/1234 — Kedacom alternatywny"),

    # --- ZKTeco NVR (ta sama firma co kontrolery dostepu) ---
    ("admin",        "123456",       194,  "admin/123456 — ZKTeco NVR domyslny"),
    ("admin",        "admin",        194,  "admin/admin — ZKTeco NVR alternatywny"),

    # --- ANNKE (OEM Hikvision, ale inne domyslne) ---
    ("admin",        "admin123",     194,  "admin/admin123 — ANNKE NVR domyslny"),
    ("admin",        "12345",        194,  "admin/12345 — ANNKE alternatywny"),

    # --- IDIS (Korea, popularny w korporacjach) ---
    ("admin",        "admin1234",    194,  "admin/admin1234 — IDIS DirectIP NVR"),
    ("admin",        "",             194,  "admin / brak hasla — IDIS starszy firmware"),

    # --- Provision ISR (Izrael / EU) ---
    ("admin",        "admin",        194,  "admin/admin — Provision ISR NVR"),
    ("admin",        "1234",         194,  "admin/1234 — Provision ISR alternatywny"),

    # --- Sunell (Chiny) ---
    ("admin",        "123456",       194,  "admin/123456 — Sunell NVR domyslny"),

    # --- Vicon Industries ---
    ("admin",        "admin",        194,  "admin/admin — Vicon VALERUS NVR"),

    # --- Speco Technologies (USA) ---
    ("admin",        "1234",         194,  "admin/1234 — Speco SecureGuard NVR"),
    ("admin",        "admin",        194,  "admin/admin — Speco alternatywny"),

    # --- IC Realtime ---
    ("admin",        "123456",       194,  "admin/123456 — IC Realtime NVR"),

    # --- Digital Watchdog ---
    ("admin",        "admin",        194,  "admin/admin — Digital Watchdog Blackjack NVR"),
    ("admin",        "DW1234",       194,  "admin/DW1234 — Digital Watchdog alternatywny"),

    # --- Exacq Vision (Johnson Controls) ---
    ("admin",        "admin256",     194,  "admin/admin256 — Exacq Vision NVR domyslny"),
    ("admin",        "admin",        194,  "admin/admin — Exacq Vision alternatywny"),

    # --- IndigoVision ---
    ("admin",        "admin",        194,  "admin/admin — IndigoVision NVR"),
    ("administrator","password",     194,  "administrator/password — IndigoVision starszy"),

    # --- March Networks ---
    ("admin",        "march",        194,  "admin/march — March Networks CMR/ME NVR"),
    ("admin",        "admin",        194,  "admin/admin — March Networks alternatywny"),

    # --- Digifort (Brazylia / EU) ---
    ("admin",        "digifort",     194,  "admin/digifort — Digifort VMS domyslny"),

    # --- Qvis (UK brand, OEM chineski) ---
    ("admin",        "1234",         194,  "admin/1234 — Qvis NVR domyslny"),

    # --- Epcom / Epcom Tech (Meksyk / LAC) ---
    ("admin",        "admin",        194,  "admin/admin — Epcom NVR"),

    # --- Reolink NVR (dedykowany rekorder) ---
    ("admin",        "",             194,  "admin / brak hasla — Reolink NVR (wymagane ustawienie)"),
    ("admin",        "reolink",      194,  "admin/reolink — Reolink NVR alternatywny"),

    # --- Acti (Tajwan) ---
    ("admin",        "123456",       194,  "admin/123456 — ACTi NVR domyslny"),
    ("Admin",        "123456",       194,  "Admin/123456 — ACTi wielka litera"),

    # --- Honeywell Performance NVR (equip z linii CCTV) ---
    ("admin",        "admin1234",    194,  "admin/admin1234 — Honeywell Performance NVR"),
    ("admin",        "1234",         194,  "admin/1234 — Honeywell NVR alternatywny"),


    # ═══════════════════════════════════════════════════════════════════════════
    # ACCESS POINTY WIFI
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Cisco Aironet / Catalyst AP ---
    ("Cisco",        "Cisco",        195,  "Cisco/Cisco — Cisco Aironet domyslny (wielka litera)"),
    ("admin",        "Cisco",        196,  "admin/Cisco — Cisco WAP domyslny"),

    # --- EnGenius ---
    ("admin",        "admin",        197,  "admin/admin — EnGenius AP domyslny"),
    ("admin",        "1234",         198,  "admin/1234 — EnGenius starsze modele"),

    # --- Cambium (ePMP / cnPilot / Force) ---
    ("admin",        "admin",        199,  "admin/admin — Cambium cnPilot / ePMP"),
    ("cambium",      "cambium",      200,  "cambium/cambium — Cambium ePMP starszy"),
    ("installer",    "installer",    201,  "installer/installer — Cambium ePMP instalator"),

    # --- Peplink / Pepwave ---
    ("admin",        "admin",        202,  "admin/admin — Peplink / Pepwave domyslny"),

    # --- Cradlepoint ---
    ("admin",        "",             203,  "admin / brak hasla — Cradlepoint (MAC-based default)"),

    # --- Ruckus Wireless ---
    ("super",        "sp-admin",     204,  "super/sp-admin — Ruckus ZoneDirector"),
    ("admin",        "admin",        205,  "admin/admin — Ruckus Unleashed alternatywny"),

    # --- Netgear (AP / switch) ---
    ("admin",        "password",     206,  "admin/password — Netgear domyslny"),
    ("admin",        "1234",         207,  "admin/1234 — Netgear starsze modele"),

    # --- Edimax ---
    ("admin",        "1234",         208,  "admin/1234 — Edimax AP domyslny"),

    # --- LigoWave (Deliberant) ---
    ("admin",        "admin01",      209,  "admin/admin01 — LigoWave / Deliberant"),

    # ═══════════════════════════════════════════════════════════════════════════
    # SMART HOME / IoT / AUTOMATYKA BUDYNKOWA
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Shelly (bardzo popularny w PL integracje z Home Assistant) ---
    ("admin",        "",             210,  "admin / brak hasla — Shelly Gen1 (bez autentykacji domyslnie)"),
    ("admin",        "admin",        211,  "admin/admin — Shelly Gen2/Gen3 nowe API"),

    # --- Sonoff / eWeLink (Itead) ---
    ("admin",        "admin",        212,  "admin/admin — Sonoff LAN/SSH"),
    ("root",         "root",         213,  "root/root — Sonoff OpenWrt firmware"),

    # --- Xiaomi / Roborock (odkurzacze i IoT) ---
    ("root",         "rockrobo",     214,  "root/rockrobo — Xiaomi Roborock SSH (klasyczny exploit)"),
    ("root",         "",             215,  "root / brak hasla — Xiaomi Mi Smart urządzenia early firmware"),

    # --- Xiaomi Router (MiWiFi) ---
    ("root",         "root",         216,  "root/root — Xiaomi MiWiFi router SSH"),
    ("admin",        "admin",        217,  "admin/admin — Xiaomi MiWiFi panel"),

    # --- Tuya / Smart Life (OEM masowy) ---
    ("admin",        "admin",        218,  "admin/admin — Tuya-based devices generic"),
    ("root",         "tuyaroot",     219,  "root/tuyaroot — Tuya BK7231 SSH"),

    # --- Smart TV (Samsung / LG / Sony) ---
    ("admin",        "admin",        220,  "admin/admin — Samsung Smart TV diagnostyczny"),
    ("admin",        "1234",         221,  "admin/1234 — LG Smart TV domyslny"),
    ("admin",        "admin",        222,  "admin/admin — Sony Bravia admin panel"),
    ("root",         "",             223,  "root / brak hasla — Android TV / Chromecast ADB"),

    # --- Philips Hue Bridge ---
    ("root",         "",             224,  "root / brak hasla — Philips Hue Bridge SSH"),

    # --- Sterowanie oswietleniem (DALI / KNX / Lutron) ---
    ("admin",        "admin",        225,  "admin/admin — DALI-2 gateway / KNX IP router domyslny"),
    ("admin",        "lutron",       226,  "admin/lutron — Lutron RadioRA domyslny"),
    ("user",         "user",         227,  "user/user — Lutron alternatywny"),
    ("admin",        "1234",         228,  "admin/1234 — KNX IP gateway (np. MDT, Gira)"),

    # --- Sterowanie ogrzewaniem / klimatyzacja (HVAC) ---
    ("admin",        "admin",        229,  "admin/admin — Daikin Intelligent Manager / BRP"),
    ("admin",        "admin",        230,  "admin/admin — Mitsubishi Electric MELCloud gateway"),
    ("admin",        "admin",        231,  "admin/admin — Fujitsu UTY-TWGUWA web gateway"),

    # --- Systemy automatyki budynkowej (BMS / BAS) ---
    ("admin",        "admin",        232,  "admin/admin — Johnson Controls Metasys SSH"),
    ("jci",          "jci",          233,  "jci/jci — Johnson Controls serwisowy"),
    ("admin",        "1234",         234,  "admin/1234 — Honeywell WEBs / EBI"),
    ("admin",        "admin",        235,  "admin/admin — Siemens Desigo PXC / Climatix"),
    ("admin",        "admin",        236,  "admin/admin — Schneider Electric TAC Vista / EcoStruxure"),
    ("admin",        "admin",        237,  "admin/admin — Trend Controls IQ / TONN"),
    ("admin",        "admin",        238,  "admin/admin — Distech Controls ECY"),

    # --- Systemy nawadniania ---
    ("admin",        "admin",        240,  "admin/admin — Hunter Pro-C / ICC SSH"),
    ("admin",        "1234",         241,  "admin/1234 — Rain Bird ESP-TM2 / ST8O"),

    # --- Lodowki / AGD (smart) ---
    ("admin",        "admin",        245,  "admin/admin — Samsung Family Hub / smart AGD SSH"),
    ("root",         "",             246,  "root / brak hasla — LG ThinQ embedded Linux"),

    # --- Drukarki sieciowe (SSH/FTP) ---
    ("admin",        "admin",        250,  "admin/admin — HP LaserJet SSH/FTP embedded"),
    ("admin",        "",             251,  "admin / brak hasla — Kyocera / Ricoh / Canon SSH"),
    ("admin",        "1234",         252,  "admin/1234 — Epson ET sieciowe"),
    ("root",         "",             253,  "root / brak hasla — Brother MFC embedded"),

    # --- Swiatlowody / media konwertery / sfp ---
    ("admin",        "admin",        255,  "admin/admin — TP-Link media converter / SFP"),
    ("admin",        "1234",         256,  "admin/1234 — Transition Networks / Perle"),

    # --- UPS (SSH/Telnet) ---
    ("apc",          "apc",          260,  "apc/apc — APC Smart-UPS Network Management Card"),
    ("device",       "apc",          261,  "device/apc — APC NMC read-only"),
    ("readonly",     "apc",          262,  "readonly/apc — APC NMC readonly"),
    ("admin",        "admin",        263,  "admin/admin — Eaton UPS Gigabit Network Card"),
    ("admin",        "admin",        264,  "admin/admin — Vertiv / Liebert IntelliSlot"),
    ("localadmin",   "localadmin",   265,  "localadmin/localadmin — Riello / SDT UPS"),

    # --- Kontrolery dostępu / domofonowe ---
    ("admin",        "admin",        270,  "admin/admin — Hikvision / ZKTeco interkom / kontroler dostepu"),
    ("admin",        "1234",         271,  "admin/1234 — Dahua interkom VTO"),
    ("admin",        "admin",        272,  "admin/admin — 2N Helios domyslny (do v2.25)"),
    ("admin",        "2n",           273,  "admin/2n — 2N Helios nowszy firmware"),

    # --- VoIP / telefony IP ---
    ("admin",        "admin",        275,  "admin/admin — Yealink telefon SIP domyslny"),
    ("admin",        "1234",         276,  "admin/1234 — Grandstream GXP / UCM"),
    ("admin",        "admin",        277,  "admin/admin — Cisco SPA / CP SSH"),
    ("admin",        "admin",        278,  "admin/admin — Snom / Fanvil VoIP"),

    # --- Snmp/telnet PLC / OT (dodatkowe) ---
    ("USER",         "USER",         280,  "USER/USER — Schneider Modicon PLC Telnet"),
    ("USER",         "",             281,  "USER / brak hasla — Schneider Modicon legacy"),
    ("admin",        "",             282,  "admin / brak hasla — Beckhoff TwinCAT / CX embedded"),
    ("Administrator","1",            283,  "Administrator/1 — Siemens SCALANCE switch"),

    # ═══════════════════════════════════════════════════════════════════════════
    # CENTRALE TELEFONICZNE IP (PBX / UC)
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Asterisk / FreePBX (Linux-based, bardzo popularne w PL) ---
    ("admin",        "admin",        285,  "admin/admin — FreePBX Web + SSH default"),
    ("root",         "password",     286,  "root/password — Asterisk AMI / SSH generic"),
    ("admin",        "jEkiN3dW",     287,  "admin/jEkiN3dW — FreePBX 2.x domyslne haslo instalatora"),

    # --- Cisco Call Manager (CUCM) / Unified Communications ---
    ("admin",        "cisco",        288,  "admin/cisco — Cisco CUCM domyslny"),
    ("admin",        "Cisco1234",    289,  "admin/Cisco1234 — Cisco UCM alternatywny"),
    ("ccmadmin",     "cisco",        290,  "ccmadmin/cisco — Cisco Call Manager SSH"),

    # --- 3CX (Windows/Linux PBX, bardzo popularny w Polsce) ---
    ("admin",        "admin",        291,  "admin/admin — 3CX Management Console domyslny"),
    ("3CX",          "3CX",          292,  "3CX/3CX — 3CX legacy"),

    # --- Avaya IP Office / Aura ---
    ("Administrator","Administrator",293,  "Administrator/Administrator — Avaya IP Office"),
    ("admin",        "avaya",        294,  "admin/avaya — Avaya System Manager SSH"),
    ("craft",        "craft",        295,  "craft/craft — Avaya serwisowy"),

    # --- Mitel / ShoreTel ---
    ("admin",        "admin",        296,  "admin/admin — Mitel MiVoice / ShoreTel Director"),
    ("maintenance",  "maintenance",  297,  "maintenance/maintenance — Mitel serwisowy"),

    # --- Panasonic KX (popularne w biurach w PL) ---
    ("admin",        "admin",        298,  "admin/admin — Panasonic KX-NS/NCP Web"),
    ("admin",        "1234",         299,  "admin/1234 — Panasonic KX starsze modele"),

    # --- NEC UNIVERGE ---
    ("admin",        "admin",        300,  "admin/admin — NEC UNIVERGE SSH"),

    # --- Grandstream UCM (PBX) ---
    ("admin",        "admin",        301,  "admin/admin — Grandstream UCM6xxx Web"),
    ("admin",        "password",     302,  "admin/password — Grandstream UCM alternatywny"),

    # ═══════════════════════════════════════════════════════════════════════════
    # TELEFONY IP (VoIP) — SIP
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Yealink (najpopularniejszy w Polsce) ---
    ("admin",        "admin",        305,  "admin/admin — Yealink T/W/CP series Web (stary firmware)"),
    ("admin",        "admin1",       306,  "admin/admin1 — Yealink starszy firmware"),
    ("user",         "user",         307,  "user/user — Yealink uzytkownik"),

    # --- Grandstream (GXP/GRP) ---
    ("admin",        "admin",        308,  "admin/admin — Grandstream GXP domyslny"),
    ("user",         "",             309,  "user / brak hasla — Grandstream GXP user"),

    # --- Cisco IP Phone (SPA/CP) ---
    ("admin",        "admin",        310,  "admin/admin — Cisco SPA/CP Web"),
    ("cisco",        "cisco",        311,  "cisco/cisco — Cisco IP Phone SSH"),

    # --- Snom ---
    ("admin",        "",             312,  "admin / brak hasla — Snom Web (domyslnie bez autentykacji)"),

    # --- Fanvil ---
    ("admin",        "admin",        313,  "admin/admin — Fanvil X/H series Web"),

    # --- Polycom / Poly ---
    ("admin",        "456",          314,  "admin/456 — Polycom VVX domyslny"),
    ("user",         "123",          315,  "user/123 — Polycom VVX uzytkownik"),
    ("admin",        "admin",        316,  "admin/admin — Poly Edge B/E series"),
    ("PlcmSpIp",     "PlcmSpIp",     317,  "PlcmSpIp/PlcmSpIp — Polycom SSH serwisowy"),

    # --- Avaya IP Deskphone ---
    ("admin",        "27238",        318,  "admin/27238 — Avaya 9600 series domyslny PIN"),
    ("craft",        "crftpw",       319,  "craft/crftpw — Avaya serwisowy"),

    # --- Aastra / Mitel Deskphone ---
    ("admin",        "22222",        320,  "admin/22222 — Aastra 6700 series"),

    # ═══════════════════════════════════════════════════════════════════════════
    # GLOSNIKI SMART / ASYSTENCI GLOSOWI
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Amazon Echo / Alexa (SSH przez exploit / developer mode) ---
    ("root",         "",             325,  "root / brak hasla — Amazon Echo SSH (developer mode)"),
    ("root",         "toor",         326,  "root/toor — Amazon Echo niektorze firmware"),

    # --- Sonos ---
    ("admin",        "admin",        327,  "admin/admin — Sonos Web Interface"),
    ("root",         "",             328,  "root / brak hasla — Sonos SSH embedded Linux"),

    # --- Bose SoundTouch ---
    ("admin",        "admin",        329,  "admin/admin — Bose SoundTouch panel"),

    # --- Denon HEOS ---
    ("admin",        "admin",        330,  "admin/admin — Denon/Marantz HEOS"),

    # --- Google Home / Nest Hub (SSH przez exploit) ---
    ("root",         "",             331,  "root / brak hasla — Google Home SSH (rzadki exploit)"),

    # ═══════════════════════════════════════════════════════════════════════════
    # UPS — rozszerzone
    # ═══════════════════════════════════════════════════════════════════════════

    # --- APC / Schneider (NMC karta sieciowa) ---
    ("apc",          "apc",          335,  "apc/apc — APC Network Management Card SSH"),
    ("device",       "apc",          336,  "device/apc — APC NMC read-only SSH"),

    # --- Eaton (Gigabit Network Card) ---
    ("admin",        "admin",        337,  "admin/admin — Eaton Gigabit Network Card SSH"),
    ("admin",        "",             338,  "admin / brak hasla — Eaton NetAgent"),

    # --- Vertiv / Liebert / Emerson ---
    ("admin",        "admin",        339,  "admin/admin — Vertiv Liebert GXT / SXLI SSH"),
    ("localadmin",   "localadmin",   340,  "localadmin/localadmin — Riello / Power Shield"),

    # --- Riello UPS ---
    ("admin",        "admin",        341,  "admin/admin — Riello NetMan 204"),

    # ═══════════════════════════════════════════════════════════════════════════
    # DODATKOWE POPULARNE IoT / SMART HOME
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Tapo (TP-Link) ---
    ("admin",        "admin",        345,  "admin/admin — TP-Link Tapo SSH/Web"),
    ("admin",        "tp-link",      346,  "admin/tp-link — TP-Link Tapo alternatywny"),

    # --- Eufy (Anker) ---
    ("admin",        "admin",        347,  "admin/admin — Eufy camera / Smart Home SSH"),

    # --- Wyze ---
    ("admin",        "admin",        348,  "admin/admin — Wyze camera SSH"),

    # --- Arlo ---
    ("admin",        "admin",        349,  "admin/admin — Arlo camera embedded"),

    # --- Hik-Connect / Ezviz (Hikvision cloud kamery) ---
    ("admin",        "admin123",     350,  "admin/admin123 — Ezviz / Hik-Connect kamera"),

    # --- Ajax Systems (popularne w PL — alarmy) ---
    ("admin",        "admin",        351,  "admin/admin — Ajax Hub embedded panel"),

    # --- DSC / Tyco / Bosch (centrale alarmowe) ---
    ("admin",        "1234",         352,  "admin/1234 — DSC PowerSeries Neo"),
    ("installer",    "1234",         353,  "installer/1234 — Tyco / DSC instalator"),
    ("admin",        "admin",        354,  "admin/admin — Bosch Solution alarm panel"),

    # --- Paradox (popularne w Polsce centrale alarmowe) ---
    ("installer",    "0000",         355,  "installer/0000 — Paradox MG/SP central"),

    # --- Intelbras (popularny w LAC / niektore PL) ---
    ("admin",        "intelbras",    356,  "admin/intelbras — Intelbras DVR/kamera"),
    ("admin",        "admin",        357,  "admin/admin — Intelbras generic"),

    # --- Tuya / Smartlife OEM embedded ---
    ("root",         "tuyaroot",     358,  "root/tuyaroot — Tuya BK7231 chipset SSH"),
    ("root",         "",             359,  "root / brak hasla — Tuya ESP8266/ESP32 SSH (dev mode)"),

    # --- Xiaomi Smart Home (dodatkowe) ---
    ("root",         "rockrobo",     360,  "root/rockrobo — Xiaomi Roborock / Mi Robot"),
    ("admin",        "xiaomi1234",   361,  "admin/xiaomi1234 — Xiaomi router alternatywny"),

    # --- Fibaro (Z-Wave, popularny w Polsce) ---
    ("admin",        "admin",        362,  "admin/admin — Fibaro HC2/HC3 SSH"),
    ("admin",        "fibaro",       363,  "admin/fibaro — Fibaro alternatywny"),

    # --- Homey (Athom) ---
    ("admin",        "admin",        364,  "admin/admin — Homey Pro SSH (developer)"),

    # --- Home Assistant OS (gdy SSH addon) ---
    ("root",         "",             365,  "root / brak hasla — Home Assistant OS SSH addon (brak ustawionego hasla)"),

    # ═══════════════════════════════════════════════════════════════════════════
    # DRUKARKI / MFP — szczegolowe credentials SSH/FTP
    # ═══════════════════════════════════════════════════════════════════════════

    # --- HP LaserJet / OfficeJet / PageWide ---
    ("admin",        "admin",        370,  "admin/admin — HP LaserJet EWS SSH (niektorze modele)"),
    ("admin",        "",             371,  "admin / brak hasla — HP JetDirect embedded"),
    ("admin",        "hp",           372,  "admin/hp — HP LaserJet starszy firmware"),
    ("JetDirect",    "",             373,  "JetDirect / brak hasla — HP JetDirect FTP (anonymous-like)"),
    ("anonymous",    "",             374,  "anonymous / brak hasla — HP FTP scan to folder"),

    # --- Kyocera Ecosys / TASKalfa ---
    ("Admin",        "Admin00",      375,  "Admin/Admin00 — Kyocera TASKalfa domyslny (wielka A)"),
    ("admin",        "admin",        376,  "admin/admin — Kyocera Ecosys alternatywny"),
    ("anonymous",    "",             377,  "anonymous / brak hasla — Kyocera FTP scan"),

    # --- Ricoh / Nashuatec / Lanier / Savin ---
    ("supervisor",   "supervisor",   378,  "supervisor/supervisor — Ricoh Aficio domyslny"),
    ("admin",        "",             379,  "admin / brak hasla — Ricoh MFP Web/SSH"),
    ("admin",        "password",     380,  "admin/password — Ricoh nowszy firmware"),
    ("anonymous",    "",             381,  "anonymous / brak hasla — Ricoh FTP scan to folder"),

    # --- Canon imageRUNNER / LBP ---
    ("admin",        "7654321",      382,  "admin/7654321 — Canon iR domyslny PIN administratora"),
    ("7654321",      "",             383,  "7654321 / brak hasla — Canon iR PIN jako login"),
    ("anonymous",    "",             384,  "anonymous / brak hasla — Canon FTP scan"),
    ("admin",        "canon",        385,  "admin/canon — Canon LBP Web admin"),

    # --- Konica Minolta / Develop / Olivetti ---
    ("administrator","",             386,  "administrator / brak hasla — Konica Minolta PageScope domyslny"),
    ("Administrator","",             387,  "Administrator / brak hasla — KM wielka litera"),
    ("admin",        "1234567890",   388,  "admin/1234567890 — Konica Minolta nowszy firmware"),
    ("admin",        "12345678",     389,  "admin/12345678 — Konica Minolta alternatywny"),
    ("anonymous",    "",             390,  "anonymous / brak hasla — Konica Minolta FTP scan"),

    # --- Xerox WorkCentre / AltaLink / VersaLink ---
    ("admin",        "1111",         391,  "admin/1111 — Xerox WorkCentre/VersaLink domyslny"),
    ("admin",        "admin",        392,  "admin/admin — Xerox AltaLink alternatywny"),
    ("anonymous",    "",             393,  "anonymous / brak hasla — Xerox FTP scan to folder"),
    ("11111",        "",             394,  "11111 / brak hasla — Xerox stary PIN"),

    # --- Lexmark ---
    ("admin",        "",             395,  "admin / brak hasla — Lexmark brak autentykacji (domyslnie otwarty!)"),
    ("admin",        "1234",         396,  "admin/1234 — Lexmark alternatywny"),
    ("anonymous",    "",             397,  "anonymous / brak hasla — Lexmark FTP scan"),

    # --- Brother ---
    ("admin",        "access",       398,  "admin/access — Brother MFC Web/FTP domyslny"),
    ("anonymous",    "",             399,  "anonymous / brak hasla — Brother FTP scan to folder"),
    ("root",         "",             400,  "root / brak hasla — Brother embedded Linux SSH"),

    # --- OKI MC/C series ---
    ("admin",        "aaaaaa",       401,  "admin/aaaaaa — OKI MC/C series domyslny (specyficzny!)"),
    ("admin",        "admin",        402,  "admin/admin — OKI alternatywny"),

    # --- Epson ET / WorkForce Pro ---
    ("admin",        "epsonaq",      403,  "admin/epsonaq — Epson WorkForce Pro Web domyslny"),
    ("admin",        "admin",        404,  "admin/admin — Epson ET Network alternatywny"),
    ("epson",        "epson",        405,  "epson/epson — Epson EpsonNet konto"),
    ("anonymous",    "",             406,  "anonymous / brak hasla — Epson FTP scan"),

    # --- Sharp ---
    ("admin",        "admin",        407,  "admin/admin — Sharp MFP domyslny"),
    ("admin",        "Sharp",        408,  "admin/Sharp — Sharp alternatywny"),
    ("anonymous",    "",             409,  "anonymous / brak hasla — Sharp FTP scan"),

    # --- Samsung Printing / Xpress (HP przejal linie) ---
    ("admin",        "sec00000",     410,  "admin/sec00000 — Samsung Xpress domyslny"),
    ("admin",        "admin",        411,  "admin/admin — Samsung Printing alternatywny"),

    # --- Toshiba e-Studio ---
    ("admin",        "",             412,  "admin / brak hasla — Toshiba e-Studio domyslny"),
    ("admin",        "123456",       413,  "admin/123456 — Toshiba e-Studio nowszy"),
    ("anonymous",    "",             414,  "anonymous / brak hasla — Toshiba FTP scan"),

    # --- Fujifilm Business Innovation / Fuji Xerox ---
    ("admin",        "1111",         415,  "admin/1111 — Fujifilm / Fuji Xerox DocuCentre domyslny"),
    ("admin",        "admin",        416,  "admin/admin — Fuji Xerox ApeosPort alternatywny"),
    ("anonymous",    "",             417,  "anonymous / brak hasla — Fuji Xerox FTP scan"),

    # --- Pantum (rosnacy rynek, tani laser) ---
    ("admin",        "",             418,  "admin / brak hasla — Pantum Web domyslny"),
    ("admin",        "admin",        419,  "admin/admin — Pantum alternatywny"),

    # ═══════════════════════════════════════════════════════════════════════════
    # WIDEOKONFERENCJE (Cisco/Poly/Lifesize/Huawei/Yealink VC)
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Cisco Webex Room / TelePresence (dawniej Tandberg) ---
    ("admin",        "TANDBERG",     422,  "admin/TANDBERG — Cisco Webex Room / Tandberg C/SX/MX domyslny"),
    ("admin",        "admin",        423,  "admin/admin — Cisco Webex Board/Desk/Room alternatywny"),
    ("root",         "TANDBERG",     424,  "root/TANDBERG — Tandberg SSH serwisowy"),
    ("cisco",        "cisco",        425,  "cisco/cisco — Cisco TelePresence Server SSH"),

    # --- Polycom RealPresence (Group, HDX) ---
    ("admin",        "456",          426,  "admin/456 — Polycom Group Series / HDX domyslny"),
    ("admin",        "",             427,  "admin / brak hasla — Polycom RealPresence Trio"),
    ("polycom",      "polycom",      428,  "polycom/polycom — Polycom serwisowy konto"),

    # --- Lifesize Icon ---
    ("admin",        "1234",         429,  "admin/1234 — Lifesize Icon 300/400/500 domyslny"),
    ("admin",        "admin",        430,  "admin/admin — Lifesize Icon alternatywny"),

    # --- Yealink MVC / VC (sale konferencyjne) ---
    ("admin",        "admin",        431,  "admin/admin — Yealink VC120/VC200/MVC domyslny"),

    # --- Huawei TE (videokonferencje korporacyjne) ---
    ("admin",        "Change_Me",    432,  "admin/Change_Me — Huawei TE30/40/60 domyslny"),
    ("admin",        "Admin1234",    433,  "admin/Admin1234 — Huawei TE nowszy firmware"),

    # --- Avaya Scopia / Radvision ---
    ("admin",        "admin",        434,  "admin/admin — Avaya Scopia Desktop / Radvision"),

    # --- Sony Bravia (sala konf.) ---
    ("admin",        "admin",        435,  "admin/admin — Sony SRG/BRC PTZ camera"),

    # ═══════════════════════════════════════════════════════════════════════════
    # KVM / CONSOLE SERVERS (data center remote access)
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Raritan Dominion KX / SX ---
    ("admin",        "raritan",      438,  "admin/raritan — Raritan Dominion KX/SX SSH domyslny"),
    ("admin",        "admin",        439,  "admin/admin — Raritan KX alternatywny"),

    # --- Avocent DSR / ACS (Vertiv) ---
    ("admin",        "avocent",      440,  "admin/avocent — Avocent DSR KVM domyslny"),
    ("admin",        "cyclades",     441,  "admin/cyclades — Avocent ACS (dawniej Cyclades) SSH"),
    ("root",         "cyclades",     442,  "root/cyclades — Cyclades AlterPath SSH"),

    # --- Opengear IM / CM / ACM ---
    ("root",         "default",      443,  "root/default — Opengear CM/IM console server domyslny"),
    ("admin",        "admin",        444,  "admin/admin — Opengear nowsze modele"),

    # --- Lantronix EDS / SCS / UDS ---
    ("root",         "admin",        445,  "root/admin — Lantronix EDS/SCS domyslny"),
    ("manager",      "manager",      446,  "manager/manager — Lantronix UDS SSH"),

    # --- Digi International (Connect ME, CM) ---
    ("root",         "dbps",         447,  "root/dbps — Digi ConnectPort / CM SSH domyslny"),
    ("admin",        "admin",        448,  "admin/admin — Digi Connect IT alternatywny"),

    # --- Black Box (Remote Access Servers) ---
    ("admin",        "admin",        449,  "admin/admin — Black Box ServSwitch / LB Series"),

    # ═══════════════════════════════════════════════════════════════════════════
    # PDU — inteligentne listwy zasilajace (Rack PDU)
    # ═══════════════════════════════════════════════════════════════════════════

    # --- APC Switched / Metered PDU (Rack PDU) ---
    ("apc",          "apc",          452,  "apc/apc — APC Rack PDU / Switched PDU SSH domyslny"),
    ("device",       "apc",          453,  "device/apc — APC PDU device konto"),
    ("readonly",     "apc",          454,  "readonly/apc — APC PDU readonly"),

    # --- Raritan PX / PX3 ---
    ("admin",        "raritan",      455,  "admin/raritan — Raritan PX Rack PDU domyslny"),
    ("admin",        "admin",        456,  "admin/admin — Raritan PX alternatywny"),

    # --- Server Technology Switched CDU (POPS) ---
    ("sysuser",      "sysuser",      457,  "sysuser/sysuser — Server Technology POPS CDU domyslny"),
    ("admn",         "admn",         458,  "admn/admn — Server Technology starszy firmware"),

    # --- Eaton ePDU / Managed PDU ---
    ("admin",        "admin",        459,  "admin/admin — Eaton ePDU managed domyslny"),

    # --- Vertiv / Geist Rack PDU ---
    ("admin",        "admin",        460,  "admin/admin — Geist / Vertiv PDU domyslny"),

    # --- Panduit SmartZone ---
    ("admin",        "admin",        461,  "admin/admin — Panduit SmartZone PDU"),

    # ═══════════════════════════════════════════════════════════════════════════
    # LOAD BALANCERY / ADC
    # ═══════════════════════════════════════════════════════════════════════════

    # --- F5 BIG-IP ---
    ("admin",        "admin",        464,  "admin/admin — F5 BIG-IP SSH domyslny (wymagana zmiana!)"),
    ("root",         "default",      465,  "root/default — F5 BIG-IP root SSH"),

    # --- Citrix ADC / NetScaler ---
    ("nsroot",       "nsroot",       466,  "nsroot/nsroot — Citrix NetScaler / ADC SSH domyslny"),
    ("admin",        "admin",        467,  "admin/admin — NetScaler Web NSIP"),

    # --- Kemp LoadMaster ---
    ("bal",          "1fourall",     468,  "bal/1fourall — Kemp LoadMaster SSH domyslny"),
    ("admin",        "admin",        469,  "admin/admin — Kemp WebUI domyslny"),

    # --- A10 Networks Thunder ---
    ("admin",        "a10",          470,  "admin/a10 — A10 Networks Thunder domyslny"),
    ("admin",        "admin",        471,  "admin/admin — A10 alternatywny"),

    # --- Radware Alteon ---
    ("admin",        "admin",        472,  "admin/admin — Radware Alteon SSH domyslny"),
    ("admin",        "radware",      473,  "admin/radware — Radware alternatywny"),

    # --- HAProxy (embedded linux) ---
    ("root",         "",             474,  "root / brak hasla — HAProxy embedded Linux (OpenWrt/Vyos)"),

    # ═══════════════════════════════════════════════════════════════════════════
    # SAN / STORAGE SWITCH / NAS ENTERPRISE
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Brocade FC Switch (Broadcom) ---
    ("admin",        "password",     477,  "admin/password — Brocade Fibre Channel switch SSH domyslny"),
    ("root",         "fibranne",     478,  "root/fibranne — Brocade FC starszy SSH konto serwisowe"),
    ("admin",        "admin",        479,  "admin/admin — Brocade Fabric OS alternatywny"),

    # --- Cisco MDS 9000 (SAN switch) ---
    ("admin",        "admin",        480,  "admin/admin — Cisco MDS 9000 SAN SSH domyslny"),

    # --- HP StorageWorks (MSA / EVA / Primera) ---
    ("admin",        "admin",        481,  "admin/admin — HP MSA / HPE Primera SSH"),
    ("monitor",      "monitor",      482,  "monitor/monitor — HP StorageWorks read-only"),

    # --- NetApp ONTAP ---
    ("admin",        "netapp1!",     483,  "admin/netapp1! — NetApp ONTAP domyslny (nowe)"),
    ("admin",        "admin",        484,  "admin/admin — NetApp ONTAP alternatywny"),
    ("root",         "netapp",       485,  "root/netapp — NetApp ONTAP root SSH"),

    # --- EMC VNX / Unity / PowerStore ---
    ("admin",        "Password123#", 486,  "admin/Password123# — Dell EMC Unity / PowerStore"),
    ("sysadmin",     "sysadmin",     487,  "sysadmin/sysadmin — Dell EMC VNX serwisowy"),

    # --- Pure Storage FlashArray ---
    ("pureuser",     "pureuser",     488,  "pureuser/pureuser — Pure Storage FlashArray SSH domyslny"),

    # --- Quantum Tape Library ---
    ("admin",        "password",     489,  "admin/password — Quantum Scalar tape library"),

    # ═══════════════════════════════════════════════════════════════════════════
    # MONITORING SRODOWISKOWY / INFRASTRUKTURA DC
    # ═══════════════════════════════════════════════════════════════════════════

    # --- AKCP SensorProbe / MasterProbe ---
    ("admin",        "admin",        492,  "admin/admin — AKCP SensorProbe / MasterProbe SSH"),

    # --- Geist / Vertiv WatchDog ---
    ("admin",        "admin",        493,  "admin/admin — Geist WatchDog monitoring SSH"),

    # --- Raritan DominionSX / NetBotz (APC) ---
    ("admin",        "admin",        494,  "admin/admin — APC NetBotz monitoring SSH"),
    ("apc",          "apc",          495,  "apc/apc — APC NetBotz / InRow SSH"),

    # --- RF Code Zone Manager ---
    ("admin",        "admin",        496,  "admin/admin — RF Code Zone Manager SSH"),

    # --- Schneider EcoStruxure IT ---
    ("admin",        "admin",        497,  "admin/admin — Schneider EcoStruxure IT Gateway"),
]

# Telnet uzywamy tych samych par co SSH — seedowane osobno z method=telnet
_DEFAULT_TELNET_CREDENTIALS = _DEFAULT_SSH_CREDENTIALS

# ── Domyslne credentials Web / HTTP(S) API ────────────────────────────────────
# Uzywane do proba logowania do paneli zarzadzania (port 80/443/8080/8443).
_DEFAULT_API_CREDENTIALS = [
    # (username, password, priority, notes)

    # --- Najpopularniejsze ---
    ("admin",         "",             10,  "admin / brak hasla — Fortinet, MikroTik, tanie AP"),
    ("admin",         "admin",        15,  "admin/admin — D-Link, Asus, TP-Link, NetGear"),
    ("admin",         "password",     20,  "admin/password — generyczny panel HTTP"),
    ("admin",         "1234",         22,  "admin/1234 — TP-Link DSL/router"),
    ("admin",         "12345",        24,  "admin/12345 — tanie chiskie urzadzenia"),
    ("admin",         "123456",       26,  "admin/123456 — bardzo popularny IoT"),

    # --- root ---
    ("root",          "",             30,  "root / brak hasla — OpenWrt, embedded Linux"),
    ("root",          "admin",        32,  "root/admin"),
    ("root",          "root",         34,  "root/root"),

    # --- Cisco ---
    ("cisco",         "cisco",        40,  "cisco/cisco — Cisco SG-300/500, IOS Web UI"),
    ("cisco",         "",             41,  "cisco / brak hasla — Cisco SG-xxx factory reset (firmware <1.3)"),
    ("admin",         "cisco",        42,  "admin/cisco — Cisco WAP / ISE"),
    ("admin",         "",             43,  "admin / brak hasla — Cisco SG-200/300 starsze firmware"),

    # --- Ubiquiti ---
    ("ubnt",          "ubnt",         50,  "ubnt/ubnt — AirOS"),
    ("admin",         "ubnt",         52,  "admin/ubnt"),

    # --- Huawei ---
    ("admin",         "Admin@huawei", 60,  "admin/Admin@huawei — Huawei Web Manager"),
    ("admin",         "huawei@123",   62,  "admin/huawei@123"),

    # --- ZTE ---
    ("admin",         "zte_admin",    70,  "admin/zte_admin — ZTE Web Panel"),
    ("admin",         "Admin1234!",   72,  "admin/Admin1234!"),
    ("user",          "user",         74,  "user/user — ZTE panel uzytkownika"),

    # --- HP ProCurve / Aruba ---
    ("manager",       "manager",      85,  "manager/manager — HP ProCurve Web"),
    ("admin",         "HP@1234",      87,  "admin/HP@1234 — HPE Aruba Web"),

    # --- QNAP / Synology NAS ---
    ("admin",         "admin",        90,  "admin/admin — QNAP QTS"),

    # --- CCTV / NVR / DVR ---
    ("admin",         "12345",        95,  "admin/12345 — Dahua Web"),
    ("admin",         "Admin12345",   99,  "admin/Admin12345 — Hikvision nowszy"),

    # --- IPMI / iDRAC / iLO Web ---
    ("root",          "calvin",      105,  "root/calvin — Dell iDRAC Web"),
    ("Administrator", "",            107,  "Administrator / brak — HPE iLO Web"),
    ("ADMIN",         "ADMIN",       109,  "ADMIN/ADMIN — Supermicro IPMI Web"),

    # --- Ogolne ---
    ("user",          "user",        120,  "user/user — generyczne konto"),
    ("guest",         "guest",       122,  "guest/guest — konto goscia"),
    ("test",          "test",        124,  "test/test — konta testowe"),
    ("support",       "support",     126,  "support/support"),

    # ═══════════════════════════════════════════════════════════════════════════
    # KAMERY IP / REJESTRATORY DVR/NVR
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Hikvision ---
    ("admin",        "12345",       130,  "admin/12345 — Hikvision starszy"),
    ("admin",        "Admin12345",  131,  "admin/Admin12345 — Hikvision nowszy"),
    ("888888",       "888888",      132,  "888888/888888 — Hikvision legacy"),
    ("666666",       "666666",      133,  "666666/666666 — Hikvision operator legacy"),

    # --- Dahua ---
    ("admin",        "admin",       134,  "admin/admin — Dahua Web starszy"),
    ("admin",        "",            135,  "admin / brak — Dahua Web nowy"),
    ("888888",       "888888",      136,  "888888/888888 — Dahua admin legacy"),

    # --- Axis ---
    ("root",         "pass",        137,  "root/pass — Axis Web (stary firmware)"),
    ("admin",        "admin",       138,  "admin/admin — Axis Web alternatywny"),

    # --- Foscam / Reolink / Amcrest ---
    ("admin",        "",            139,  "admin / brak — Foscam / Reolink inicjalny"),
    ("admin",        "amcrest2021", 140,  "admin/amcrest2021 — Amcrest Web"),

    # --- Mobotix ---
    ("admin",        "meinsm",      141,  "admin/meinsm — Mobotix Web Panel"),

    # --- Hanwha / Samsung Techwin ---
    ("admin",        "4321",        142,  "admin/4321 — Hanwha Web"),

    # --- Uniview / TVT / Jovision ---
    ("admin",        "123456",      143,  "admin/123456 — Uniview Web"),
    ("admin",        "1111",        144,  "admin/1111 — TVT DVR Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # ACCESS POINTY / ROUTERY WIFI
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Cambium ---
    ("admin",        "admin",       150,  "admin/admin — Cambium cnPilot / ePMP Web"),
    ("cambium",      "cambium",     151,  "cambium/cambium — Cambium Web"),

    # --- EnGenius ---
    ("admin",        "1234",        152,  "admin/1234 — EnGenius Web Panel"),

    # --- LigoWave ---
    ("admin",        "admin01",     153,  "admin/admin01 — LigoWave Web"),

    # --- Peplink ---
    ("admin",        "admin",       154,  "admin/admin — Peplink Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # SMART HOME / IoT
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Shelly ---
    ("admin",        "",            160,  "admin / brak — Shelly Web Gen1 (brak auth domyslnie)"),
    ("admin",        "admin",       161,  "admin/admin — Shelly Gen2+ Web API"),

    # --- Xiaomi MiWiFi ---
    ("admin",        "admin",       162,  "admin/admin — Xiaomi MiWiFi Web"),

    # --- Smart TV ---
    ("admin",        "admin",       163,  "admin/admin — Samsung Smart TV diagnostyczny"),
    ("admin",        "1234",        164,  "admin/1234 — LG webOS panel"),

    # --- Sterowanie oswietleniem ---
    ("admin",        "admin",       165,  "admin/admin — DALI gateway / KNX IP router"),
    ("admin",        "lutron",      166,  "admin/lutron — Lutron Web"),
    ("admin",        "1234",        167,  "admin/1234 — KNX IP gateway Web"),

    # --- HVAC / klimatyzacja ---
    ("admin",        "admin",       168,  "admin/admin — Daikin/Mitsubishi/Fujitsu HVAC gateway"),

    # --- BMS / BAS ---
    ("admin",        "admin",       169,  "admin/admin — Johnson Controls / Honeywell / Siemens BMS Web"),
    ("admin",        "1234",        170,  "admin/1234 — Honeywell WEBs"),

    # --- Kontrolery dostepu / interkom ---
    ("admin",        "admin",       172,  "admin/admin — ZKTeco / Hikvision interkom Web"),
    ("admin",        "1234",        173,  "admin/1234 — Dahua VTO interkom Web"),
    ("admin",        "2n",          174,  "admin/2n — 2N Helios Web nowszy"),

    # --- VoIP ---
    ("admin",        "admin",       175,  "admin/admin — Yealink / Grandstream Web"),
    ("admin",        "1234",        176,  "admin/1234 — Grandstream GXP Web"),

    # --- Drukarki sieciowe (Web) ---
    ("admin",        "admin",       180,  "admin/admin — HP LaserJet Embedded Web Server"),
    ("admin",        "",            181,  "admin / brak — Kyocera / Ricoh Command Center"),
    ("admin",        "1234",        182,  "admin/1234 — Canon / Epson Web"),

    # --- UPS (Web) ---
    ("apc",          "apc",         185,  "apc/apc — APC Network Management Card Web"),
    ("admin",        "admin",       186,  "admin/admin — Eaton / Vertiv UPS Web"),

    # --- NAS dodatkowe ---
    ("admin",        "",            190,  "admin / brak — WD MyCloud Web inicjalny"),
    ("admin",        "infrant1",    191,  "admin/infrant1 — Netgear ReadyNAS (legacy Infrant)"),
    ("admin",        "password",    192,  "admin/password — Netgear ReadyNAS nowszy"),

    # ═══════════════════════════════════════════════════════════════════════════
    # CENTRALE TELEFONICZNE (PBX / UC)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       195,  "admin/admin — FreePBX / 3CX Web Admin"),
    ("admin",        "jEkiN3dW",    196,  "admin/jEkiN3dW — FreePBX 2.x instalator Web"),
    ("admin",        "cisco",       197,  "admin/cisco — Cisco CUCM Web"),
    ("Administrator","Administrator",198, "Administrator/Administrator — Avaya IP Office Web"),
    ("admin",        "admin",       199,  "admin/admin — Grandstream UCM Web"),
    ("admin",        "1234",        200,  "admin/1234 — Panasonic KX-NS Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # TELEFONY IP (Web panels)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       202,  "admin/admin — Yealink / Fanvil / Grandstream Web"),
    ("admin",        "456",         203,  "admin/456 — Polycom VVX Web"),
    ("PlcmSpIp",     "PlcmSpIp",    204,  "PlcmSpIp/PlcmSpIp — Polycom serwisowy Web"),
    ("admin",        "27238",       205,  "admin/27238 — Avaya 9600 Web"),
    ("admin",        "22222",       206,  "admin/22222 — Aastra 6700 Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # GLOSNIKI / SMART HOME
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       210,  "admin/admin — Sonos / Denon HEOS Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # CENTRALE ALARMOWE (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "1234",        215,  "admin/1234 — DSC PowerSeries Neo Web"),
    ("installer",    "1234",        216,  "installer/1234 — Tyco / DSC instalator Web"),
    ("admin",        "admin",       217,  "admin/admin — Bosch Solution / Ajax Hub Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # DODATKOWE IoT
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       220,  "admin/admin — Fibaro HC2/HC3 Web"),
    ("admin",        "fibaro",      221,  "admin/fibaro — Fibaro Web alternatywny"),
    ("admin",        "admin",       222,  "admin/admin — Tapo / Wyze / Eufy Web"),
    ("admin",        "admin123",    223,  "admin/admin123 — Ezviz / Hik-Connect Web"),
    ("admin",        "intelbras",   224,  "admin/intelbras — Intelbras Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # DRUKARKI / MFP — Web panels szczegolowo
    # ═══════════════════════════════════════════════════════════════════════════

    # --- HP LaserJet Embedded Web Server (EWS) ---
    ("admin",        "",            226,  "admin / brak hasla — HP LaserJet EWS (czesto otwarty!)"),
    ("admin",        "hp",          227,  "admin/hp — HP LaserJet EWS starszy"),
    ("JetDirect",    "",            228,  "JetDirect / brak — HP JetDirect Web"),

    # --- Kyocera Command Center RX ---
    ("Admin",        "Admin00",     229,  "Admin/Admin00 — Kyocera Command Center domyslny"),
    ("admin",        "admin",       230,  "admin/admin — Kyocera alternatywny"),

    # --- Ricoh SmartDeviceMonitor / EWS ---
    ("supervisor",   "supervisor",  231,  "supervisor/supervisor — Ricoh Aficio/MP Web"),
    ("admin",        "",            232,  "admin / brak — Ricoh MFP Web inicjalny"),

    # --- Canon Remote UI / iW Management ---
    ("admin",        "7654321",     233,  "admin/7654321 — Canon imageRUNNER Web Admin PIN"),
    ("7654321",      "",            234,  "7654321 / brak — Canon iR alternatywny"),
    ("admin",        "canon",       235,  "admin/canon — Canon LBP Web"),

    # --- Konica Minolta PageScope Web Connection ---
    ("administrator","",            236,  "administrator / brak — Konica Minolta PageScope (otwarty domyslnie!)"),
    ("Administrator","",            237,  "Administrator / brak — KM wielka litera"),
    ("admin",        "1234567890",  238,  "admin/1234567890 — KM nowszy firmware"),

    # --- Xerox CentreWare / EIP ---
    ("admin",        "1111",        239,  "admin/1111 — Xerox WorkCentre / VersaLink Web domyslny"),
    ("",             "",            240,  "brak/brak — Xerox stary otwarty Web (bez autentykacji!)"),
    ("11111",        "",            241,  "11111 / brak — Xerox PIN login"),

    # --- Lexmark Embedded Web Server ---
    ("",             "",            242,  "brak/brak — Lexmark EWS (domyslnie bez autentykacji!)"),
    ("admin",        "1234",        243,  "admin/1234 — Lexmark z wlaczona autentykacja"),

    # --- Brother Web Based Management ---
    ("",             "",            244,  "brak/brak — Brother Web (brak autentykacji domyslnie!)"),
    ("admin",        "access",      245,  "admin/access — Brother Web z haslem"),
    ("admin",        "initpass",    246,  "admin/initpass — Brother nowszy firmware"),

    # --- OKI Web Management ---
    ("admin",        "aaaaaa",      247,  "admin/aaaaaa — OKI MC/C Web domyslny"),

    # --- Epson Web Config ---
    ("admin",        "epsonaq",     248,  "admin/epsonaq — Epson WorkForce Pro Web"),
    ("",             "",            249,  "brak/brak — Epson starszy Web bez autentykacji"),

    # --- Sharp OSA / Web UI ---
    ("admin",        "admin",       250,  "admin/admin — Sharp MFP Web domyslny"),
    ("admin",        "Sharp",       251,  "admin/Sharp — Sharp Web alternatywny"),

    # --- Samsung / HP Xpress ---
    ("admin",        "sec00000",    252,  "admin/sec00000 — Samsung Xpress Web domyslny"),

    # --- Toshiba e-Bridge ---
    ("admin",        "",            253,  "admin / brak — Toshiba e-Studio Web domyslny"),
    ("admin",        "123456",      254,  "admin/123456 — Toshiba nowszy firmware"),

    # --- Fujifilm / Fuji Xerox ---
    ("admin",        "1111",        255,  "admin/1111 — Fujifilm ApeosPort / Fuji Xerox Web"),

    # --- Pantum ---
    ("admin",        "",            256,  "admin / brak — Pantum Web domyslny"),

    # ═══════════════════════════════════════════════════════════════════════════
    # WIDEOKONFERENCJE — Web panels
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "TANDBERG",    258,  "admin/TANDBERG — Cisco Webex Room / Tandberg Web"),
    ("admin",        "456",         259,  "admin/456 — Polycom Group Series Web"),
    ("admin",        "1234",        260,  "admin/1234 — Lifesize Icon Web"),
    ("admin",        "Change_Me",   261,  "admin/Change_Me — Huawei TE Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # KVM / CONSOLE SERVERS — Web
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "raritan",     263,  "admin/raritan — Raritan Dominion KX Web"),
    ("admin",        "avocent",     264,  "admin/avocent — Avocent DSR Web"),
    ("root",         "default",     265,  "root/default — Opengear Web"),
    ("root",         "admin",       266,  "root/admin — Lantronix Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # PDU — Web panels
    # ═══════════════════════════════════════════════════════════════════════════

    ("apc",          "apc",         268,  "apc/apc — APC Rack PDU Web domyslny"),
    ("admin",        "raritan",     269,  "admin/raritan — Raritan PX Web"),
    ("sysuser",      "sysuser",     270,  "sysuser/sysuser — Server Technology CDU Web"),
    ("admin",        "admin",       271,  "admin/admin — Eaton / Geist / Panduit PDU Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # LOAD BALANCERY — Web
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       273,  "admin/admin — F5 BIG-IP TMUI Web"),
    ("nsroot",       "nsroot",      274,  "nsroot/nsroot — Citrix NetScaler Web NSIP"),
    ("bal",          "1fourall",    275,  "bal/1fourall — Kemp LoadMaster Web"),
    ("admin",        "a10",         276,  "admin/a10 — A10 Thunder Web"),
    ("admin",        "admin",       277,  "admin/admin — Radware Alteon Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # STORAGE — Web
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       279,  "admin/admin — NetApp ONTAP System Manager Web"),
    ("admin",        "Password123#",280,  "admin/Password123# — Dell EMC Unity Web"),
    ("pureuser",     "pureuser",    281,  "pureuser/pureuser — Pure Storage Web"),
    ("admin",        "password",    282,  "admin/password — Brocade Fabric Watch Web / Quantum"),

    # ═══════════════════════════════════════════════════════════════════════════
    # MONITORING DC — Web
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       284,  "admin/admin — AKCP / Geist / RF Code / NetBotz Web"),
    ("apc",          "apc",         285,  "apc/apc — APC NetBotz / EcoStruxure IT Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # NAS — brakujace (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       287,  "admin/admin — TrueNAS SCALE / Terramaster / Asustor Web"),
    ("root",         "",            288,  "root / brak — TrueNAS CORE Web inicjalny"),

    # ═══════════════════════════════════════════════════════════════════════════
    # SERWERY BMC — brakujace (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       290,  "admin/admin — Fujitsu iRMC Web domyslny"),
    ("USERID",       "PASSW0RD",    291,  "USERID/PASSW0RD — Lenovo IMM2/XCC Web domyslny (zero=O!)"),
    ("admin",        "password",    292,  "admin/password — Cisco CIMC / UCS Web domyslny"),

    # ═══════════════════════════════════════════════════════════════════════════
    # SWITCHE — brakujace (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("root",         "",            294,  "root / brak — Juniper EX Web domyslny"),
    ("admin",        "",            295,  "admin / brak — Arista EOS Web (otwarty!)"),
    ("admin",        "password",    296,  "admin/password — Netgear ProSafe Web"),
    ("admin",        "switch",      297,  "admin/switch — ALE OmniSwitch Web"),
    ("admin",        "moxa",        298,  "admin/moxa — Moxa industrial Web"),
    ("admin",        "private",     299,  "admin/private — Hirschmann industrial Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # FIREWALLE — brakujace (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       301,  "admin/admin — Palo Alto PAN-OS Web UI domyslny"),
    ("admin",        "admin",       302,  "admin/admin — Check Point Gaia WebUI"),
    ("admin",        "pfsense",     303,  "admin/pfsense — pfSense WebGUI domyslny"),
    ("root",         "opnsense",    304,  "root/opnsense — OPNsense WebGUI domyslny"),
    ("admin",        "admin",       305,  "admin/admin — Sophos XG / Stormshield / Barracuda Web"),
    ("admin",        "readwrite",   306,  "admin/readwrite — WatchGuard WebUI"),

    # ═══════════════════════════════════════════════════════════════════════════
    # ROUTERY / AP — brakujace (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       308,  "admin/admin — ASUS RT-AC/AX Web Panel"),
    ("admin",        "admin",       309,  "admin/admin — D-Link Web domyslny"),
    ("admin",        "",            310,  "admin / brak — D-Link starszy Web"),
    ("admin",        "",            311,  "admin / brak — Belkin / Draytek Web domyslny"),
    ("admin",        "1234",        312,  "admin/1234 — Zyxel AP / Draytek Web"),
    ("admin",        "admin",       313,  "admin/admin — TP-Link Omada / Sophos AP / Meraki Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # TELECOM — brakujace (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("Admin",        "Admin",       315,  "Admin/Admin — AudioCodes Mediant Web (wielka A!)"),
    ("administrator","",            316,  "administrator / brak — Patton SmartNode Web"),
    ("isadmin",      "isadmin",     317,  "isadmin/isadmin — Nokia ISAM DSLAM Web"),
    ("admin",        "1234",        318,  "admin/1234 — ZyXEL IES DSLAM Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # MODEMY DSL / GPON ONT — brakujace (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "",            320,  "admin / brak — AVM Fritz!Box Web domyslny"),
    ("admin",        "admin",       321,  "admin/admin — Technicolor / Sagemcom / Comtrend Web"),
    ("Administrator","",            322,  "Administrator / brak — Technicolor / Speedtouch Web"),
    ("user",         "user",        323,  "user/user — Technicolor / Sagemcom konto uzytkownika"),
    ("telecomadmin", "admintelecom",324,  "telecomadmin/admintelecom — Huawei ONT ukryte konto ISP"),
    ("root",         "ztetC3.0ZDe", 325,  "root/ztetC3.0ZDe — ZTE ZXHN ONT ukryte konto ISP (CVE!)"),

    # ═══════════════════════════════════════════════════════════════════════════
    # MEDIA PLAYERY — brakujace (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       327,  "admin/admin — Philips Android TV serwisowy Web"),
]



def seed_snmp_communities(db):
    """Upsert domyslnych SNMP community strings — dodaje brakujace, nie nadpisuje istniejacych."""
    from netdoc.storage.models import Credential, CredentialMethod
    existing_names = {
        r.username for r in db.query(Credential.username).filter(
            Credential.method == CredentialMethod.snmp,
            Credential.device_id.is_(None),
        ).all()
    }
    added = 0
    for community, priority, notes in _DEFAULT_SNMP_COMMUNITIES:
        if community in existing_names:
            continue
        db.add(Credential(
            device_id=None,
            method=CredentialMethod.snmp,
            username=community,
            priority=priority,
            notes=notes,
        ))
        existing_names.add(community)
        added += 1
    if added:
        db.commit()
        logger.info("SNMP seed: dodano %d nowych community strings (lacznie: %d)", added, len(existing_names))
    else:
        logger.info("SNMP seed: brak nowych community strings do dodania (%d juz w bazie)", len(existing_names))



_LAB_DEVICES = [
    # (ip, hostname, device_type, vendor, os_version, location)
    ("172.28.0.10", "S7-1200-PLC",    "iot",     "Siemens",            "SIMATIC S7-1200 PLC v4.5",           "Lab / Hala produkcyjna A / Szafa sterownicza 1"),
    ("172.28.0.11", "Modicon-M340",   "iot",     "Schneider Electric", "Modicon M340 PLC",                   "Lab / Rozdzielnia glowna / Licznik energii"),
    ("172.28.0.12", "ABB-AC500-Tank", "iot",     "ABB",               "AC500 PLC v3.0 Tank Control",         "Lab / Zbiornik paliwa / Sekcja B"),
    ("172.28.0.20", "MikroTik-RB750", "router",  "MikroTik",          "RouterOS 6.49.10 (stable) RB750Gr3",  "Lab / Server Room A / Rack 2"),
    ("172.28.0.30", "lab-switch",     "switch",  "Cisco",             "IOS 15.2(7)E",                        "Lab / Switch room"),
    ("172.28.0.40", "netdoc-lab-hmi",  "unknown", None,                "SCADA HMI WebServer",                 "Lab / Panel HMI"),
]


def seed_lab_devices(db):
    """Dodaje symulowane urzadzenia lab (172.28.0.0/24) jesli jeszcze nie istnieja w bazie.

    Wywoływane przy każdym starcie skanera — ON CONFLICT DO NOTHING, wiec bezpieczne.
    Aktywuje sie tylko gdy siec 172.28.0.0/24 jest w NETWORK_RANGES lub gdy kontenery lab istnieja.
    """
    import subprocess
    from netdoc.storage.models import Device, DeviceType
    from datetime import datetime as dt

    # Sprawdz czy lab istnieje (kontener netdoc-lab-plc-s7 musi byc uruchomiony)
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", "netdoc-lab-plc-s7"],
            capture_output=True, text=True, timeout=5,
        )
        if result.stdout.strip() != "true":
            return  # lab nie dziala — nie seeduj
    except Exception:
        return  # brak dockera lub inny blad

    existing_ips = {r.ip for r in db.query(Device.ip).all()}
    added = 0
    now = dt.utcnow()
    for ip, hostname, dtype, vendor, os_version, location in _LAB_DEVICES:
        if ip in existing_ips:
            continue
        try:
            dev_type = DeviceType(dtype)
        except ValueError:
            dev_type = DeviceType.unknown
        db.add(Device(
            ip=ip,
            hostname=hostname,
            device_type=dev_type,
            vendor=vendor,
            os_version=os_version,
            location=location,
            is_active=True,
            is_trusted=False,
            first_seen=now,
            last_seen=now,
        ))
        existing_ips.add(ip)
        added += 1
    if added:
        db.commit()
        logger.info("Lab seed: dodano %d urzadzen lab (172.28.0.0/24)", added)
    else:
        logger.debug("Lab seed: brak nowych urzadzen lab do dodania")


# ── Domyslne credentials RDP ──────────────────────────────────────────────────
# RDP (port 3389) — Windows Remote Desktop Protocol.
# Zrodla: SecLists/RDP, CIRT.net, CVE defaults, badania pentesterow.
# Wiele urzadzen embeddowanych (NVR, thin client, OT HMI) ma RDP z domyslnymi hasami.
_DEFAULT_RDP_CREDENTIALS = [
    # (username, password, priority, notes)

    # --- Brak hasla / puste ---
    ("Administrator", "",              10,  "Administrator / brak hasla — Windows Server fresh install"),
    ("admin",         "",              12,  "admin / brak hasla — Windows embedded / thin client"),

    # --- Najpopularniejsze slabe hasla Windows ---
    ("Administrator", "administrator", 15,  "Administrator/administrator — klasyczny default Windows"),
    ("Administrator", "Admin",         17,  "Administrator/Admin"),
    ("Administrator", "Admin123",      19,  "Administrator/Admin123 — wymagana polityka hasel"),
    ("Administrator", "Admin@123",     21,  "Administrator/Admin@123"),
    ("Administrator", "Password1",     23,  "Administrator/Password1 — spelniony wymog zlozonosci"),
    ("Administrator", "P@ssw0rd",      25,  "Administrator/P@ssw0rd — klasyczny obejscie polityki"),
    ("Administrator", "Welcome1",      27,  "Administrator/Welcome1 — popularny 'pierwszy login'"),
    ("Administrator", "changeme",      29,  "Administrator/changeme — do zmiany (ale nikt nie zmienia)"),
    ("Administrator", "1234",          31,  "Administrator/1234"),
    ("Administrator", "12345",         33,  "Administrator/12345"),
    ("Administrator", "123456",        35,  "Administrator/123456"),
    ("Administrator", "password",      37,  "Administrator/password"),
    ("Administrator", "Password123",   39,  "Administrator/Password123"),
    ("Administrator", "Passw0rd",      41,  "Administrator/Passw0rd"),
    ("Administrator", "admin",         43,  "Administrator/admin"),
    ("Administrator", "Admin1234",     45,  "Administrator/Admin1234"),
    ("Administrator", "qwerty",        47,  "Administrator/qwerty"),
    ("Administrator", "abc123",        49,  "Administrator/abc123"),
    ("Administrator", "Windows1",      51,  "Administrator/Windows1"),
    ("Administrator", "Qwerty123",     53,  "Administrator/Qwerty123"),

    # --- admin user ---
    ("admin",         "admin",         60,  "admin/admin — Windows embedded (thin clients, NVR)"),
    ("admin",         "Admin",         61,  "admin/Admin"),
    ("admin",         "Admin123",      62,  "admin/Admin123"),
    ("admin",         "Password1",     63,  "admin/Password1"),
    ("admin",         "password",      64,  "admin/password"),
    ("admin",         "P@ssw0rd",      65,  "admin/P@ssw0rd"),
    ("admin",         "1234",          66,  "admin/1234"),
    ("admin",         "12345",         67,  "admin/12345"),
    ("admin",         "123456",        68,  "admin/123456"),

    # --- Vendor-specific defaults ---
    # Windows Server instalacje przez OEM/producentow
    ("Administrator", "Passw0rd!",     70,  "Dell/HP serwer factory default"),
    ("Administrator", "Dell1234",      71,  "Dell PowerEdge Windows default"),
    ("Administrator", "HP@dmin",       72,  "HP ProLiant Windows default"),
    ("Administrator", "Lenovo1234",    73,  "Lenovo ThinkSystem Windows default"),
    ("Administrator", "ibmpassw0rd",   74,  "IBM System x Windows default"),

    # NVR / DVR z Windows Embedded (Hikvision, Dahua iVMS)
    ("Administrator", "12345",         80,  "Hikvision iVMS-4200 / Windows Embedded NVR"),
    ("Administrator", "Admin12345",    81,  "Hikvision nowszy Windows NVR"),
    ("admin",         "12345",         82,  "Dahua SmartPSS / Windows NVR"),
    ("admin",         "admin123",      83,  "Generic Windows NVR admin"),

    # VMS (Video Management Software) — Windows
    ("Administrator", "supervisor",    85,  "Milestone XProtect VMS domyslny"),
    ("administrator", "administrator", 86,  "Milestone / Genetec alternatywny"),
    ("admin",         "admin",         87,  "Genetec Security Center"),
    ("admin",         "123456",        88,  "Exacq Vision / Bosch VideoSDK"),
    ("admin",         "admin256",      89,  "Exacq Vision Windows"),

    # SCADA / HMI (Windows Embedded Standard)
    ("Administrator", "Siemens1234",   92,  "Siemens WinCC / SIMATIC HMI"),
    ("Administrator", "rockwell",      93,  "Rockwell FactoryTalk View SE"),
    ("Administrator", "schneider",     94,  "Schneider EcoStruxure SCADA"),
    ("Administrator", "scada",         95,  "Generic SCADA HMI Windows"),
    ("operator",      "operator",      96,  "OT HMI operator konto"),
    ("engineer",      "engineer",      97,  "OT inzynier konto"),

    # Thin clients (Windows Embedded Compact / IoT)
    ("Administrator", "Wyse",          100, "Dell Wyse thin client Windows Embedded"),
    ("Administrator", "ThinClient",    101, "Generic thin client default"),
    ("user",          "user",          102, "HP t520 / t620 thin client"),
    ("admin",         "admin",         103, "Igel thin client Windows"),

    # Kiosks / Digital Signage
    ("kiosk",         "kiosk",         105, "Windows kiosk mode"),
    ("Administrator", "kiosk1234",     106, "Digital signage Windows kiosk"),

    # Popularne konta nieadministratorskie (ale z prawem RDP)
    ("user",          "user",          110, "user/user — konto uzytkownika"),
    ("user",          "User1234",      111, "user/User1234"),
    ("guest",         "",              112, "guest / brak hasla — Windows Guest"),
    ("guest",         "guest",         113, "guest/guest"),
    ("test",          "test",          114, "test/test — konto testowe"),
    ("test",          "",              115, "test / brak hasla"),
    ("support",       "support",       116, "support/support — konto wsparcia"),
    ("helpdesk",      "helpdesk",      117, "helpdesk/helpdesk"),
    ("operator",      "",              118, "operator / brak hasla"),
    ("service",       "service",       119, "service/service — konto serwisowe"),

    # Popularne konta devops / automatyzacja
    ("vagrant",       "vagrant",       120, "vagrant/vagrant — Vagrant / VirtualBox VM"),
    ("ansible",       "ansible",       121, "ansible/ansible — Ansible managed host"),
    ("deploy",        "deploy",        122, "deploy/deploy — konto deployu"),
    ("backup",        "backup",        123, "backup/backup — konto backupu"),

    # Popularne slabe hasla z listy Pwned / NIST
    ("Administrator", "Summer2023",    130, "Seasonalpassword — Summer2023"),
    ("Administrator", "Spring2024",    131, "Spring2024"),
    ("Administrator", "Winter2024",    132, "Winter2024"),
    ("Administrator", "Autumn2023",    133, "Autumn/Fall seasonal"),
    ("Administrator", "Company123",    134, "Company name + 123"),
    ("Administrator", "Monday1",       135, "Day-based password"),
    ("Administrator", "Polska1",       136, "Polska — popularne w PL"),
    ("Administrator", "Warszawa1",     137, "Warszawa — popularne w PL"),

    # Popularne nazwy domenowe jako hasla
    ("administrator", "administrator", 140, "administrator/administrator — domena lowercase"),
    ("Admin",         "Admin",         141, "Admin/Admin — wielka litera"),
]

# ── Domyslne credentials VNC ───────────────────────────────────────────────────
# VNC (port 5900-5909) — Virtual Network Computing (RFB protocol).
# UWAGA: VNC nie ma nazwy uzytkownika — tylko haslo (max 8 znakow!).
#        username = "" (puste), password = haslo VNC.
# Zrodla: SecLists/VNC, CIRT.net defaults, vendor docs, Shodan research.
_DEFAULT_VNC_CREDENTIALS = [
    # (username, password, priority, notes)

    # --- Brak hasla / puste (najczesciej skuteczne!) ---
    ("",  "",              10,  "VNC bez hasla — domyslne wiele urzadzen, UltraVNC bez auth"),
    ("",  "password",      15,  "password — najpopularniejsze VNC haslo"),
    ("",  "admin",         17,  "admin — drugie najpopularniejsze"),
    ("",  "1234",          19,  "1234"),
    ("",  "12345",         21,  "12345"),
    ("",  "123456",        23,  "123456"),
    ("",  "vnc",           25,  "vnc — nazwa protokolu jako haslo"),

    # --- Vendor defaults ---
    # Przemyslowe urzadzenia HMI/SCADA z VNC
    ("",  "Siemens",       30,  "Siemens SIMATIC HMI (TP/MP/Comfort) VNC domyslny"),
    ("",  "1",             31,  "Siemens alternatywny (pojedynczy znak)"),
    ("",  "100",           32,  "Siemens SIMATIC HMI skrot"),
    ("",  "Schneider",     33,  "Schneider Magelis / Harmony HMI VNC"),
    ("",  "Rockwell",      34,  "Rockwell PanelView Plus HMI VNC"),
    ("",  "1234",          35,  "PanelView Plus domyslny PIN"),
    ("",  "GE",            36,  "GE iFix / Proficy HMI VNC"),
    ("",  "Wonderware",    37,  "Wonderware / AVEVA InTouch VNC"),
    ("",  "Citect",        38,  "Schneider Citect SCADA VNC"),

    # NVR / thin client / Windows z VNC serverem
    ("",  "admin",         40,  "Hikvision / Dahua NVR VNC"),
    ("",  "12345",         41,  "NVR generic VNC pin"),
    ("",  "Admin12345",    42,  "Hikvision nowszy"),
    ("",  "TightVNC",      44,  "TightVNC server domyslny"),
    ("",  "UltraVNC",      45,  "UltraVNC server uzytkownicy"),
    ("",  "realvnc",       46,  "RealVNC domyslny"),
    ("",  "vncpasswd",     47,  "Generic VNC haslo ('vncpasswd')"),

    # Popularne krotkie hasla (VNC max 8 znakow!)
    ("",  "secret",        50,  "secret"),
    ("",  "pass",          51,  "pass"),
    ("",  "0000",          52,  "0000"),
    ("",  "1111",          53,  "1111"),
    ("",  "4321",          54,  "4321"),
    ("",  "qwerty",        55,  "qwerty"),
    ("",  "letmein",       56,  "letmein"),
    ("",  "test",          57,  "test"),
    ("",  "root",          58,  "root"),
    ("",  "abc123",        59,  "abc123 (skrocone do 8 znakow)"),
    ("",  "access",        60,  "access"),
    ("",  "welcome",       61,  "welcome"),
    ("",  "temp",          62,  "temp"),
    ("",  "desktop",       63,  "desktop"),
    ("",  "remote",        64,  "remote"),
    ("",  "connect",       65,  "connect"),
    ("",  "support",       66,  "support"),

    # Kamer y IP (niektore maja VNC) — typowe piny
    ("",  "666666",        70,  "Hikvision/Dahua legacy PIN (666666 = operator)"),
    ("",  "888888",        71,  "Hikvision/Dahua legacy PIN (888888 = admin)"),
    ("",  "000000",        72,  "000000 — banalny PIN"),
    ("",  "111111",        73,  "111111 — banalny PIN"),

    # Raspberry Pi / embedded Linux z VNC
    ("",  "raspberry",     75,  "raspberry — Raspberry Pi OS domyslne haslo VNC"),
    ("",  "pi",            76,  "pi — Raspberry Pi alternatywny"),

    # IoT / smart home z VNC
    ("",  "admin1234",     78,  "admin1234 — IoT generic"),
    ("",  "homevnc",       79,  "homevnc — smart home generic"),

    # Kiosk / Digital Signage
    ("",  "kiosk",         80,  "kiosk — Windows kiosk VNC"),
    ("",  "display",       81,  "display — digital signage"),

    # Slabe hasla z polityka min. 8 znakow (wiele VNC max8 z obcieciem)
    ("",  "Password",      85,  "Password (8 znakow — dokladnie limit VNC!)"),
    ("",  "passw0rd",      86,  "passw0rd"),
    ("",  "changeme",      87,  "changeme (8 znakow)"),
]

# ── Domyslne credentials FTP ───────────────────────────────────────────────────
# FTP (port 21) — File Transfer Protocol.
# Zrodla: SecLists/FTP, vendor docs, CIRT.net, badania CVE.
# FTP szeroko uzywany w urz. sieciowych do transferu logów, konfiguracji, firmware.
_DEFAULT_FTP_CREDENTIALS = [
    # (username, password, priority, notes)

    # --- Anonimowe (najczestszy problem na urz. biurowych!) ---
    ("anonymous", "",              10,  "anonymous / brak hasla — RFC domyslny anonymous FTP"),
    ("anonymous", "anonymous",     11,  "anonymous/anonymous — alternatywny"),
    ("anonymous", "ftp",           12,  "anonymous/ftp — wiele serwerow akceptuja"),
    ("anonymous", "guest",         13,  "anonymous/guest"),
    ("ftp",       "",              14,  "ftp / brak hasla — alias anonymous"),
    ("ftp",       "ftp",           15,  "ftp/ftp — klasyczny"),

    # --- Brak hasla / puste ---
    ("admin",     "",              20,  "admin / brak hasla — wiele FTP embedded"),
    ("root",      "",              22,  "root / brak hasla — Unix FTP embedded"),
    ("user",      "",              24,  "user / brak hasla — generic FTP user"),

    # --- Najpopularniejsze pary ---
    ("admin",     "admin",         30,  "admin/admin — najczestszy FTP default"),
    ("admin",     "password",      32,  "admin/password"),
    ("admin",     "1234",          34,  "admin/1234"),
    ("admin",     "12345",         36,  "admin/12345"),
    ("admin",     "ftp",           38,  "admin/ftp"),
    ("root",      "root",          40,  "root/root"),
    ("root",      "password",      42,  "root/password"),
    ("user",      "user",          44,  "user/user"),
    ("user",      "password",      46,  "user/password"),
    ("guest",     "guest",         48,  "guest/guest"),
    ("guest",     "",              49,  "guest / brak hasla"),

    # --- Drukarki sieciowe (scan-to-FTP) ---
    # Drukarki czesto maja FTP do odbierania skanow — domyslne konta
    ("JetDirect",  "",             55,  "HP JetDirect / LaserJet FTP embedded"),
    ("admin",      "hp",           56,  "HP LaserJet EWS FTP"),
    ("admin",      "",             57,  "HP / Kyocera / Canon FTP brak hasla"),
    ("Admin",      "Admin00",      58,  "Kyocera TASKalfa FTP domyslny"),
    ("admin",      "admin",        59,  "Ricoh / Xerox / Brother scan-to-FTP"),
    ("supervisor", "supervisor",   60,  "Ricoh Aficio FTP admin"),
    ("administrator","",           61,  "Konica Minolta PageScope FTP (brak hasla!)"),
    ("admin",      "1111",         62,  "Xerox WorkCentre FTP pin"),
    ("admin",      "7654321",      63,  "Canon imageRUNNER FTP admin PIN"),
    ("admin",      "access",       64,  "Brother MFC FTP domyslny"),
    ("admin",      "aaaaaa",       65,  "OKI MC series FTP"),

    # --- Kamery IP / NVR / DVR (FTP do nagrywania zdarzen) ---
    ("admin",     "12345",         70,  "Hikvision FTP upload zdarzen"),
    ("admin",     "Admin12345",    71,  "Hikvision nowszy"),
    ("admin",     "admin",         72,  "Dahua / Axis / generic kamera FTP"),
    ("root",      "pass",          73,  "Axis Communications FTP (stary firmware)"),
    ("admin",     "amcrest2021",   74,  "Amcrest FTP konfiguracja"),
    ("admin",     "meinsm",        75,  "Mobotix FTP domyslny"),

    # --- Routery / switche (FTP do backupu konfiguracji) ---
    ("cisco",     "cisco",         80,  "Cisco IOS FTP server"),
    ("admin",     "admin",         81,  "MikroTik / generic router FTP"),
    ("ubnt",      "ubnt",          82,  "Ubiquiti AirOS FTP"),
    ("admin",     "Admin@huawei",  83,  "Huawei FTP backup"),
    ("mikrotik",  "",              84,  "MikroTik FTP (brak hasla!)"),

    # --- Serwery NAS (FTP czesto domyslnie wlaczony) ---
    ("admin",     "admin",         88,  "QNAP / Synology / Netgear ReadyNAS FTP"),
    ("admin",     "infrant1",      89,  "Netgear ReadyNAS (legacy Infrant)"),
    ("root",      "",              90,  "TrueNAS CORE / TrueNAS SCALE FTP root"),
    ("admin",     "admin",         91,  "Asustor / Terramaster FTP"),

    # --- Kontrolery PLC / OT (TFTP/FTP do firmware/konfig) ---
    ("admin",     "admin",         95,  "Siemens SINEMA / S7 FTP gateway"),
    ("USER",      "USER",          96,  "Schneider Modicon FTP"),
    ("operator",  "",              97,  "OT operator FTP brak hasla"),

    # --- Serwery Windows (IIS FTP / FileZilla Server) ---
    ("Administrator","",           100, "Windows IIS FTP brak hasla"),
    ("Administrator","Administrator",101,"Windows IIS FTP klasyczny"),
    ("ftpuser",   "ftpuser",       102, "Windows FTP konto dedykowane"),
    ("upload",    "upload",        103, "upload/upload — konto uploadow"),
    ("backup",    "backup",        104, "backup/backup — konto backupow"),

    # --- Slabe hasla ogolne ---
    ("test",      "test",          110, "test/test — konto testowe"),
    ("support",   "support",       111, "support/support"),
    ("service",   "service",       112, "service/service"),
    ("ftpadmin",  "ftpadmin",      113, "ftpadmin/ftpadmin — konto FTP admin"),
    ("ftp",       "ftp123",        114, "ftp/ftp123"),
    ("admin",     "ftppassword",   115, "admin/ftppassword"),
    ("admin",     "transfer",      116, "admin/transfer"),
    ("admin",     "files",         117, "admin/files"),

    # --- Specyficzne dla warunkow polskich ---
    ("admin",     "Polska1",       120, "Polska admin FTP — PL specific"),
    ("admin",     "server",        121, "admin/server — polska instalacja serwerowa"),
]


def seed_default_credentials(db):
    """Upsert domyslnych credentials SSH/Telnet/API/RDP/VNC/FTP — dodaje brakujace, nie nadpisuje.

    Upsert key: (method, username, password) — ta sama para uzytkownik+haslo
    moze byc zarejestrowana tylko raz dla danej metody jako global default.
    """
    from netdoc.storage.models import Credential, CredentialMethod
    from netdoc.config.credentials import encrypt, decrypt

    _SEED_SETS = [
        (CredentialMethod.ssh,    _DEFAULT_SSH_CREDENTIALS,    "SSH"),
        (CredentialMethod.telnet, _DEFAULT_TELNET_CREDENTIALS, "Telnet"),
        (CredentialMethod.api,    _DEFAULT_API_CREDENTIALS,    "Web/API"),
        (CredentialMethod.rdp,    _DEFAULT_RDP_CREDENTIALS,    "RDP"),
        (CredentialMethod.vnc,    _DEFAULT_VNC_CREDENTIALS,    "VNC"),
        (CredentialMethod.ftp,    _DEFAULT_FTP_CREDENTIALS,    "FTP"),
    ]

    for method, cred_list, label in _SEED_SETS:
        # Zbierz istniejace pary (username, plaintext_password) dla tej metody
        # Obsluga wsteczna: stare wpisy moga miec plaintext w password_encrypted
        existing_pairs = set()
        for r in db.query(Credential).filter(
            Credential.method == method,
            Credential.device_id.is_(None),
        ).all():
            try:
                plain_pw = decrypt(r.password_encrypted or "")
            except Exception:
                plain_pw = r.password_encrypted or ""  # stare plaintext (przed migracją)
            existing_pairs.add((r.username or "", plain_pw))

        added = 0
        for username, password, priority, notes in cred_list:
            pair = (username, password)
            if pair in existing_pairs:
                continue
            db.add(Credential(
                device_id=None,
                method=method,
                username=username,
                password_encrypted=encrypt(password),
                priority=priority,
                notes=notes,
            ))
            existing_pairs.add(pair)
            added += 1
        if added:
            db.commit()
            logger.info("%s seed: dodano %d nowych credentials (lacznie: %d)",
                        label, added, len(existing_pairs))
        else:
            logger.info("%s seed: brak nowych credentials (%d juz w bazie)",
                        label, len(existing_pairs))


def _set_status(db, updates: dict, category: str = "scanner") -> None:
    """Zapisz status skanera do system_status (widoczny w panelu admin)."""
    from netdoc.storage.models import SystemStatus
    for key, value in updates.items():
        row = db.query(SystemStatus).filter(SystemStatus.key == key).first()
        if row is None:
            row = SystemStatus(key=key, category=category, value=str(value))
            db.add(row)
        else:
            row.value = str(value)
            row.updated_at = datetime.utcnow()
    db.commit()


def _get_status(db, key: str) -> str | None:
    """Odczytaj wartość z system_status."""
    from netdoc.storage.models import SystemStatus
    row = db.query(SystemStatus).filter(SystemStatus.key == key).first()
    return row.value if row else None


def run_scan_cycle(db, scan_type: str = "discovery") -> dict:
    """Uruchom jeden cykl skanowania. Zwraca statystyki."""
    from netdoc.collector.discovery import run_discovery, run_full_scan, _read_nmap_settings, _read_batch_scan_settings
    from netdoc.collector.pipeline import run_pipeline

    t0 = time.monotonic()
    _set_status(db, {
        "scanner_job": scan_type,
        "scanner_started_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    })

    # Loguj parametry skanowania na starcie kazdego cyklu
    try:
        nmap_rate, nmap_vi = _read_nmap_settings()
        batch = _read_batch_scan_settings()
        logger.info(
            "=== Cykl [%s] | nmap: min-rate=%d version-intensity=%d | "
            "batch: portow=%d pauza=%.1fs wznawianie=%s ===",
            scan_type, nmap_rate, nmap_vi,
            batch["batch_size"], batch["batch_pause_s"],
            "tak" if batch["resume_enabled"] else "nie",
        )
    except Exception:
        pass

    try:
        if scan_type == "full_single":
            # Pełny skan tylko dla IP z kolejki full_scan_ip_queue (żądanie per urządzenie z UI)
            from netdoc.collector.discovery import FULL_SCAN_BATCH_SIZE
            from netdoc.storage.models import SystemStatus
            import math as _math
            queue_row = db.query(SystemStatus).filter_by(key="full_scan_ip_queue").first()
            queued_ips = [x.strip() for x in (queue_row.value if queue_row else "").split(",") if x.strip()]
            if not queued_ips:
                logger.info("full_single: kolejka pusta — wykonuję discovery")
                scan_type = "discovery"
            else:
                logger.info("=== Pełny skan per urządzenie: %s ===", ", ".join(queued_ips))
                # Wyczyść kolejkę i zapisz status w jednym atomowym commicie
                if queue_row:
                    queue_row.value = ""
                _total_b = max(1, _math.ceil(len(queued_ips) / FULL_SCAN_BATCH_SIZE))
                _set_status(db, {"scanning_ips": ",".join(queued_ips), "scan_progress": f"0/{_total_b} batchy"})

                def _on_single_batch(done, total, batch_ips):
                    _set_status(db, {"scan_progress": f"{done}/{total} batchy"})

                n = run_full_scan(db, ips=queued_ips, progress_callback=_on_single_batch)
                _set_status(db, {"scanning_ips": "", "scan_progress": f"zakończono: {n} urządzeń"})
                return {"total": n, "enriched": 0, "basic_only": n}

        if scan_type == "full":
            from netdoc.collector.discovery import FULL_SCAN_BATCH_SIZE
            import math as _math
            logger.info("=== Pełny skan portów 1-65535 ===")
            active_ips = [d.ip for d in db.query(Device).filter(Device.is_active == True).all()]
            _total_b = max(1, _math.ceil(len(active_ips) / FULL_SCAN_BATCH_SIZE))
            _set_status(db, {"scanning_ips": ",".join(active_ips), "scan_progress": f"0/{_total_b} batchy"})

            def _on_full_batch(done, total, batch_ips):
                _set_status(db, {"scan_progress": f"{done}/{total} batchy"})

            n = run_full_scan(db, progress_callback=_on_full_batch)
            _set_status(db, {"scanning_ips": "", "scan_progress": f"zakończono: {n} urządzeń"})
            stats = {"total": n, "enriched": 0, "basic_only": n}
        else:
            logger.info("=== Discovery + pipeline ===")
            devices = run_discovery(db)
            stats = run_pipeline(db, devices) if devices else {}
            stats.setdefault("total", len(devices))

            # Auto full scan: urządzenia bez aktualnego pełnego skanu portów
            from netdoc.collector.discovery import get_stale_full_scan_ips
            max_age_days = int(_get_status(db, "full_scan_max_age_days") or 7)
            full_scan_enabled = _get_status(db, "full_scan_enabled") != "0"
            if max_age_days > 0 and full_scan_enabled:
                stale_ips = get_stale_full_scan_ips(db, max_age_days)
                # Zapisz liczbe oczekujacych do system_status (widoczne w Grafanie + panelu)
                _set_status(db, {"full_scan_pending": str(len(stale_ips))}, category="scanner")
                if stale_ips:
                    from netdoc.collector.discovery import FULL_SCAN_BATCH_SIZE
                    import math as _math
                    logger.info(
                        "Auto full scan: %d urządzeń bez pełnego skanu (max_age=%dd)",
                        len(stale_ips), max_age_days,
                    )
                    _total_batches = max(1, _math.ceil(len(stale_ips) / FULL_SCAN_BATCH_SIZE))
                    _set_status(db, {
                        "scanner_job": f"full scan ({len(stale_ips)} urządzeń)",
                        "scanning_ips": ",".join(stale_ips),
                        "scan_progress": f"0/{_total_batches} batchy",
                    })

                    def _on_auto_batch(done, total, batch_ips):
                        _set_status(db, {"scan_progress": f"{done}/{total} batchy"})

                    n = run_full_scan(db, ips=stale_ips, progress_callback=_on_auto_batch)
                    stats["full_scan_devices"] = n
                    _set_status(db, {
                        "full_scan_pending": "0",
                        "scanning_ips": "",
                        "scan_progress": f"zakończono: {n} urządzeń",
                    }, category="scanner")

        elapsed = round(time.monotonic() - t0, 1)
        logger.info("Skan zakończony: %s urządzeń w %.1fs", stats.get("total", "?"), elapsed)

        _set_status(db, {
            "scanner_job": "-",
            "scanner_last_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "scanner_last_devices": str(stats.get("total", 0)),
            "scanner_last_enriched": str(stats.get("enriched", 0)),
            "scanner_last_duration_s": str(elapsed),
            "scanner_last_type": scan_type,
        })
        return stats

    except Exception as exc:
        logger.exception("Błąd skanowania: %s", exc)
        _set_status(db, {"scanner_job": "-", "scanner_last_error": str(exc)})
        return {}



def _wait_cooldown(cooldown: int) -> str | None:
    """
    Czeka cooldown sekund między skanami.
    Co 5s sprawdza flagę scan_requested — jeśli jest ustawiona, przerywa cooldown wcześniej.
    Zwraca typ skanu z flagi (lub None jeśli normalny koniec cooldownu).
    """
    from netdoc.storage.database import SessionLocal
    logger.info("Cooldown %ds przed następnym skanem...", cooldown)
    deadline = time.monotonic() + cooldown
    while time.monotonic() < deadline:
        time.sleep(min(5, max(0.1, deadline - time.monotonic())))
        try:
            with SessionLocal() as db:
                req = _get_status(db, "scan_requested")
                if req and req not in ("-", ""):
                    logger.info("Przerwanie cooldown — trigger: %s", req)
                    with SessionLocal() as db2:
                        _set_status(db2, {"scan_requested": "-"})
                    return req if req in ("full", "discovery", "full_single") else "discovery"
        except Exception:
            pass
    return None



TASK_NAME = "NetDocScanner"


def _ensure_task_scheduled() -> bool:
    """Sprawdza czy zadanie NetDocScanner istnieje w Windows Task Scheduler.
    Jesli nie - rejestruje je automatycznie i startuje.
    Zwraca True jesli zadanie bylo zarejestrowane lub udalo sie je zarejestrowac.
    """
    if sys.platform != "win32":
        return True

    import subprocess
    python_exe = sys.executable
    script_path = os.path.abspath(__file__)
    working_dir = os.path.dirname(script_path)

    # Sprawdz czy task juz istnieje (schtasks nie wymaga PowerShell)
    check = subprocess.run(
        ["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "LIST"],
        capture_output=True,
    )
    if check.returncode == 0:
        logger.info("Task Scheduler: zadanie %r juz istnieje.", TASK_NAME)
        output = check.stdout.decode("cp1250", errors="replace")

        # Sprawdz czy ExecutionTimeLimit nie jest za maly (np. 15 min ze starej rejestracji).
        # Jesli linia "Stop Task If Runs" wskazuje na niezerowy limit — zaktualizuj ustawienia.
        needs_update = False
        for line in output.splitlines():
            if "Stop Task If Runs" in line and "0:00:00" not in line and "Disabled" not in line:
                logger.warning(
                    "Task Scheduler: wykryto ExecutionTimeLimit != 0 (%s) — aktualizuje ustawienia.",
                    line.strip(),
                )
                needs_update = True
                break

        if needs_update:
            ps_fix = ";".join([
                f"$s = (Get-ScheduledTask -TaskName '{TASK_NAME}').Settings",
                "$s.ExecutionTimeLimit = [System.Xml.XmlConvert]::ToString([TimeSpan]::Zero)",
                f"Set-ScheduledTask -TaskName '{TASK_NAME}' -Settings $s | Out-Null",
                "Write-Output UPDATED",
            ])
            fix_result = subprocess.run(
                ["powershell", "-NonInteractive", "-OutputFormat", "Text", "-Command", ps_fix],
                capture_output=True,
            )
            fix_out = fix_result.stdout.decode("utf-8", errors="replace")
            if "UPDATED" in fix_out:
                logger.info("Task Scheduler: ExecutionTimeLimit zaktualizowany do 0 (bez limitu).")
            else:
                logger.warning(
                    "Task Scheduler: nie udalo sie zaktualizowac ustawien: %s",
                    fix_result.stderr.decode("utf-8", errors="replace").strip(),
                )

        if "Running" not in output:
            logger.info("Task Scheduler: uruchamiam zadanie...")
            subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME], capture_output=True)
        return True

    # Nie istnieje - utworz przez PowerShell z UTF-8 output
    logger.info("Task Scheduler: zadanie %r nie istnieje - rejestruje...", TASK_NAME)
    ps_cmd = ";".join([
        f"$A = New-ScheduledTaskAction -Execute '{python_exe}' -Argument '-u \"{script_path}\"' -WorkingDirectory '{working_dir}'",
        "$T = New-ScheduledTaskTrigger -AtLogOn",
        "$S = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -StartWhenAvailable",
        "$P = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest",
        f"Register-ScheduledTask -TaskName '{TASK_NAME}' -Action $A -Trigger $T -Settings $S -Principal $P -Description 'NetDoc scanner' -Force | Out-Null",
        "Write-Output OK",
    ])
    result = subprocess.run(
        ["powershell", "-NonInteractive", "-OutputFormat", "Text", "-Command", ps_cmd],
        capture_output=True,
    )
    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    if result.returncode == 0 and "OK" in stdout:
        logger.info("Task Scheduler: zadanie %r zarejestrowane.", TASK_NAME)
        subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME], capture_output=True)
        return True
    logger.warning(
        "Task Scheduler: nie udalo sie zarejestrowac (brak uprawnien admin?). "
        "Uruchom recznie: powershell -ExecutionPolicy Bypass -File install_autostart.ps1 "
        "| stderr: %s", stderr.strip(),
    )
    return False


WATCHDOG_TASK_NAME = "NetDoc Watchdog"


def _ensure_watchdog_scheduled() -> None:
    """Sprawdza czy zadanie 'NetDoc Watchdog' istnieje w Task Scheduler.
    Jesli nie — rejestruje je przez install_watchdog.ps1.
    Wywolywane przez skaner, zeby pilnowac watchdoga (wzajemna opieka).
    """
    if sys.platform != "win32":
        return

    import subprocess
    check = subprocess.run(
        ["schtasks", "/Query", "/TN", WATCHDOG_TASK_NAME, "/FO", "LIST"],
        capture_output=True,
    )
    if check.returncode == 0:
        logger.info("Task Scheduler: watchdog %r istnieje.", WATCHDOG_TASK_NAME)
        return

    # Watchdog nie istnieje — sprobuj zarejestrowac przez install_watchdog.ps1
    working_dir = os.path.dirname(os.path.abspath(__file__))
    watchdog_script = os.path.join(working_dir, "install_watchdog.ps1")
    if not os.path.exists(watchdog_script):
        logger.warning(
            "Task Scheduler: watchdog %r nie istnieje i brak install_watchdog.ps1!",
            WATCHDOG_TASK_NAME,
        )
        return

    logger.warning(
        "Task Scheduler: watchdog %r nie istnieje — rejestruje przez install_watchdog.ps1...",
        WATCHDOG_TASK_NAME,
    )
    result = subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-NonInteractive", "-File", watchdog_script],
        capture_output=True,
    )
    out = result.stdout.decode("utf-8", errors="replace")
    err = result.stderr.decode("utf-8", errors="replace")
    if result.returncode == 0 and "OK" in out:
        logger.info("Task Scheduler: watchdog %r zarejestrowany pomyslnie.", WATCHDOG_TASK_NAME)
    else:
        logger.warning(
            "Task Scheduler: nie udalo sie zarejestrowac watchdoga (brak uprawnien admin?): %s",
            (err or out).strip()[:200],
        )


_COMPOSE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docker-compose.yml")

_DOCKER_SERVICES = [
    "netdoc-postgres",
    "netdoc-prometheus",
    "netdoc-loki",
    "netdoc-promtail",
    "netdoc-grafana",
    "netdoc-api",
    "netdoc-web",
    "netdoc-ping",
    "netdoc-snmp",
    "netdoc-community",
    "netdoc-cred",
    "netdoc-vuln",
    "netdoc-internet",
]

_POSTGRES_PORT = 15432
_DOCKER_MAX_ATTEMPTS = 5       # prob uruchomienia brakujacych kontenerow
_DOCKER_WAIT_SEC = 60          # sekund oczekiwania miedzy probami (pull obrazow trwa)
_COMPOSE_TIMEOUT = 600         # 10 min — pobieranie obrazow Docker moze dlugo trwac
_COMPOSE_BUILD_TIMEOUT = 900   # 15 min — przebudowa obrazow z Dockerfile
_PG_TCP_RETRIES = 12           # prob TCP do postgreSQLt (12 x 10s = 2 min)
_PG_TCP_WAIT_SEC = 10          # sekund miedzy probami TCP


def _dlog(msg: str, level: str = "INFO") -> None:
    """Wypisuje komunikat na konsole i do logu skanera."""
    icons = {"OK": "[OK]  ", "WARN": "[WARN]", "ERR": "[BLAD]", "WAIT": "[WAIT]", "INFO": "[INFO]"}
    prefix = icons.get(level, "[INFO]")
    print(f"{prefix} Docker: {msg}", flush=True)
    getattr(logger, "warning" if level in ("WARN", "ERR") else "info")("Docker: %s", msg)


def _docker_running_containers() -> set:
    """Zwraca zbior nazw aktualnie dzialajacych kontenerow netdoc."""
    import subprocess
    try:
        r = subprocess.run(
            ["docker", "ps", "--filter", "name=netdoc", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10,
        )
        return set(r.stdout.strip().splitlines())
    except Exception:
        return set()


def _postgres_reachable() -> bool:
    """Sprawdza czy PostgreSQL odpowiada na porcie TCP."""
    import socket
    try:
        with socket.create_connection(("127.0.0.1", _POSTGRES_PORT), timeout=3):
            return True
    except OSError:
        return False


def _ensure_docker_services() -> bool:
    """Sprawdza czy kontenery Docker sa uruchomione; startuje brakujace.

    Robi do _DOCKER_MAX_ATTEMPTS prob z oczekiwaniem _DOCKER_WAIT_SEC miedzy
    kolejnymi sprawdzeniami. Compose up moze pobierac obrazy (do 10 min) — jesli
    komenda przekroczy timeout, Docker daemon kontynuuje pobieranie w tle i funkcja
    czeka dalej. Fallback do SQLite nastepuje dopiero gdy po wszystkich probach
    postgres nadal nie odpowiada na TCP.
    """
    import subprocess

    print("", flush=True)
    _dlog("Sprawdzam stan serwisow Docker...", "INFO")

    # Sprawdz czy Docker daemon dziala
    _docker_available = True
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=15)
        if r.returncode != 0:
            _dlog("Docker daemon nie odpowiada — sprawdzam czy PostgreSQL juz dziala...", "WARN")
            _docker_available = False
    except FileNotFoundError:
        _dlog("Docker nie zainstalowany — sprawdzam czy PostgreSQL juz dziala...", "WARN")
        _docker_available = False
    except subprocess.TimeoutExpired:
        _dlog("Docker info timeout — sprawdzam czy PostgreSQL juz dziala...", "WARN")
        _docker_available = False

    if not _docker_available:
        # Docker niedostepny lub wolny — sprawdz czy postgres juz odpowiada (kontenery moga juz dzialac)
        if _postgres_reachable():
            _dlog(f"PostgreSQL na porcie {_POSTGRES_PORT} osiagalny mimo braku odpowiedzi Docker — kontynuuje.", "OK")
            print("", flush=True)
            return True
        _dlog("Docker niedostepny i PostgreSQL nie odpowiada — skaner zakończy pracę.", "ERR")
        print("", flush=True)
        return False

    compose_base = ["docker", "compose", "-f", _COMPOSE_FILE, "up", "-d"]

    for attempt in range(1, _DOCKER_MAX_ATTEMPTS + 1):
        running = _docker_running_containers()
        missing = [s for s in _DOCKER_SERVICES if s not in running]

        if not missing:
            _dlog(f"Wszystkie {len(_DOCKER_SERVICES)} kontenerow dziala.", "OK")
            break

        _dlog(
            f"Proba {attempt}/{_DOCKER_MAX_ATTEMPTS}: "
            f"brakuje {len(missing)}: {', '.join(missing)}",
            "WARN",
        )
        _dlog(
            f"Uruchamianie: docker compose up -d "
            f"(timeout {_COMPOSE_TIMEOUT}s, pobieranie obrazow moze trwac kilka minut)...",
            "WAIT",
        )
        print("", flush=True)

        try:
            r = subprocess.run(compose_base, timeout=_COMPOSE_TIMEOUT)
            if r.returncode != 0:
                # up -d moze zawiesc gdy lokalne obrazy sa uszkodzone — proba z przebudowa
                _dlog("up -d nie powiodlo sie — proba z --build ...", "WARN")
                try:
                    subprocess.run(
                        compose_base + ["--build"],
                        timeout=_COMPOSE_BUILD_TIMEOUT,
                    )
                except subprocess.TimeoutExpired:
                    _dlog(
                        f"docker compose up --build timeout ({_COMPOSE_BUILD_TIMEOUT}s)"
                        " — Docker kontynuuje budowanie w tle...",
                        "WAIT",
                    )
        except subprocess.TimeoutExpired:
            # Timeout NIE jest bledem — Docker daemon kontynuuje pobieranie obrazow
            # i uruchamianie kontenerow w tle; czekamy i sprawdzamy ponownie
            _dlog(
                f"docker compose up -d timeout ({_COMPOSE_TIMEOUT}s)"
                " — Docker daemon kontynuuje pobieranie obrazow w tle...",
                "WAIT",
            )
        print("", flush=True)

        if attempt < _DOCKER_MAX_ATTEMPTS:
            _dlog(f"Czekam {_DOCKER_WAIT_SEC}s na gotownosc serwisow...", "WAIT")
            time.sleep(_DOCKER_WAIT_SEC)
    else:
        # Wszystkie proby wyczerpane — sprawdz czy chociaz postgres dziala
        running = _docker_running_containers()
        if "netdoc-postgres" not in running:
            _dlog(
                f"BLAD: netdoc-postgres nie uruchomiony po {_DOCKER_MAX_ATTEMPTS} probach "
                "— skaner zakończy pracę.",
                "ERR",
            )
            return False
        _dlog("netdoc-postgres dziala mimo bledow innych serwisow — kontynuuje.", "WARN")

    # Weryfikacja TCP — postgres moze potrzebowac chwili na inicjalizacje po starcie
    for pg_attempt in range(1, _PG_TCP_RETRIES + 1):
        if _postgres_reachable():
            _dlog(f"PostgreSQL na porcie {_POSTGRES_PORT} gotowy.", "OK")
            print("", flush=True)
            return True
        if pg_attempt < _PG_TCP_RETRIES:
            _dlog(
                f"PostgreSQL (:{_POSTGRES_PORT}) jeszcze nie odpowiada "
                f"(proba {pg_attempt}/{_PG_TCP_RETRIES}) — czekam {_PG_TCP_WAIT_SEC}s...",
                "WAIT",
            )
            time.sleep(_PG_TCP_WAIT_SEC)

    _dlog(f"PostgreSQL niedostepny na :{_POSTGRES_PORT} — skaner zakończy pracę.", "ERR")
    print("", flush=True)
    return False


_LOCK_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner.pid")


def _is_scanner_process(pid: int) -> bool:
    """Sprawdza czy PID jest aktywna instancja skanera (run_scanner.py).

    Uzywamy psutil zamiast os.kill() bo na Windows os.kill(pid, 0) rzuca
    PermissionError dla procesow systemowych nawet gdy oryginalny proces juz
    nie istnieje a PID zostal ponownie uzyty przez system.
    """
    try:
        import psutil
        proc = psutil.Process(pid)
        if not proc.is_running():
            return False
        # Sprawdz czy to Python uruchamiajacy run_scanner.py
        name = proc.name().lower()
        if "python" not in name:
            return False
        try:
            cmdline = " ".join(proc.cmdline()).lower()
            return "run_scanner" in cmdline
        except (psutil.AccessDenied, psutil.ZombieProcess):
            # Brak dostepu do cmdline — zaloz ze to inny skaner (bezpieczniejsze)
            return "python" in name
    except (psutil.NoSuchProcess, psutil.AccessDenied, ImportError, OSError):
        return False


def _acquire_scanner_lock() -> bool:
    """Zapewnia ze tylko jedna instancja skanera dziala jednoczesnie (plik PID)."""
    my_pid = os.getpid()

    if os.path.exists(_LOCK_FILE):
        try:
            with open(_LOCK_FILE) as _f:
                old_pid = int(_f.read().strip())
            if old_pid != my_pid:
                if _is_scanner_process(old_pid):
                    logger.error("Inna instancja skanera juz dziala (PID=%d). Zamykam.", old_pid)
                    return False
                else:
                    logger.warning(
                        "Stary plik lock (PID=%d) — proces nie istnieje lub to nie skaner. "
                        "Nadpisuje lock.", old_pid,
                    )
        except (ValueError, OSError):
            pass  # uszkodzony plik — nadpisz

    # Zapisz nasz PID
    try:
        with open(_LOCK_FILE, "w") as _f:
            _f.write(str(my_pid))
    except OSError as e:
        logger.warning("Nie mozna zapisac pliku lock: %s", e)
        return True  # kontynuuj bez locka jesli plik niedostepny

    def _release():
        try:
            if os.path.exists(_LOCK_FILE):
                with open(_LOCK_FILE) as _f:
                    if _f.read().strip() == str(my_pid):
                        os.remove(_LOCK_FILE)
        except OSError:
            pass

    atexit.register(_release)
    return True

def main():
    parser = argparse.ArgumentParser(description="NetDoc host scanner")
    parser.add_argument("--once", action="store_true", help="Jeden skan i wyjscie")
    parser.add_argument("--full", action="store_true", help="Pelny skan portow 1-65535")
    args = parser.parse_args()

    if not _acquire_scanner_lock():
        sys.exit(0)

    # Sprawdz i uruchom serwisy Docker przed polaczeniem z baza
    if not _ensure_docker_services():
        logger.error("Serwisy Docker/PostgreSQL niedostepne — przerywam. Sprobuj ponownie za chwile.")
        sys.exit(1)

    from netdoc.storage.database import SessionLocal, init_db
    from netdoc.config.settings import settings

    logger.info("NetDoc Scanner startuje — DB: %s", settings.database_url)
    init_db()

    # Sprawdz i zarejestruj task w Windows Task Scheduler (autostart przy logowaniu)
    _ensure_task_scheduled()
    # Sprawdz czy watchdog tez istnieje (wzajemna opieka — skaner pilnuje watchdoga)
    _ensure_watchdog_scheduled()

    # Baza producentow OUI (IEEE MA-L/MA-M/MA-S) — pobierz jesli brak lub stara (>30 dni)
    try:
        from netdoc.collector.oui_lookup import oui_db
        if oui_db.needs_update():
            logger.info("Pobieranie bazy producentow OUI (IEEE MA-L/MA-M/MA-S)...")
            oui_db.update(timeout=60)
        else:
            oui_db.load()
    except Exception as _oui_exc:
        logger.warning("Nie udalo sie zaladowac/pobrac bazy OUI: %s", _oui_exc)

    with SessionLocal() as db:
        # Zarejestruj skaner w DB PRZED seedami — UI widzi status od razu
        _set_status(db, {
            "scanner_mode": "host",
            "scanner_pid": str(os.getpid()),
            "scanner_started_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "scanner_job": "-",
            "scanning_ips": "",   # wyczyść po ewentualnym poprzednim nieudanym skanie
        })
        seed_snmp_communities(db)
        seed_default_credentials(db)
        seed_lab_devices(db)
        # Inicjalizuj ustawienia konfiguracyjne (tylko jesli nie istnieja)
        from netdoc.storage.models import SystemStatus
        _config_defaults = {
            "full_scan_max_age_days":  ("7",  "config"),
            "full_scan_enabled":       ("1",  "config"),
            "inventory_enabled":       ("1",  "config"),
            "cred_snmp_enabled":       ("1",  "config"),
            "cred_ssh_enabled":        ("1",  "config"),
            "cred_ftp_enabled":        ("1",  "config"),
            "cred_web_enabled":        ("1",  "config"),
            "cred_rdp_enabled":        ("1",  "config"),
            "cred_mssql_enabled":      ("1",  "config"),
            "cred_mysql_enabled":      ("1",  "config"),
            "cred_postgres_enabled":   ("1",  "config"),
            "screenshot_ttl_hours":    ("12", "config"),
            "ai_assessment_enabled":   ("1",  "config"),
            # Network discovery overrides (puste = uzyj .env / auto-detect)
            "network_ranges":          ("",   "worker_settings"),
            "scan_vpn_networks":       ("0",  "worker_settings"),
            "scan_virtual_networks":   ("0",  "worker_settings"),
        }
        for cfg_key, (cfg_val, cfg_cat) in _config_defaults.items():
            if not db.query(SystemStatus).filter(SystemStatus.key == cfg_key).first():
                db.add(SystemStatus(key=cfg_key, category=cfg_cat, value=cfg_val))
        db.commit()

    if args.once or args.full:
        scan_type = "full" if args.full else "discovery"
        # W trybie --once sprawdź czy UI zleciło konkretny typ skanu (full_single / full)
        if not args.full:
            try:
                with SessionLocal() as db:
                    requested = _get_status(db, "scan_requested")
                    if requested and requested not in ("-", ""):
                        if requested in ("full", "discovery", "full_single"):
                            scan_type = requested
                            logger.info("--once: trigger z UI: %s", scan_type)
                        _set_status(db, {"scan_requested": "-"})
            except Exception:
                pass
        try:
            with SessionLocal() as db:
                run_scan_cycle(db, scan_type)
        except Exception as exc:
            logger.exception("Blad skanowania (--once): %s", exc)
            sys.exit(1)
        return

    # Tryb ciagly — skanowanie nieprzerwane z krotkim cooldown miedzy cyklami
    logger.info("Tryb ciagly: skanowanie nieprzerwane (cooldown %ds miedzy skanami).", COOLDOWN_SECONDS)

    next_scan_type = "discovery"  # typ pierwszego skanu

    while True:
        try:
            with SessionLocal() as db:
                # Sprawdz czy panel zlecil inny typ skanu
                requested = _get_status(db, "scan_requested")
                if requested and requested not in ("-", ""):
                    next_scan_type = requested if requested in ("full", "discovery", "full_single") else "discovery"
                    logger.info("Trigger z panelu admin: %s", next_scan_type)
                    _set_status(db, {"scan_requested": "-"})

                run_scan_cycle(db, next_scan_type)
                next_scan_type = "discovery"  # kolejne cykle zawsze discovery

        except Exception as exc:
            logger.exception("Blad petli schedulera: %s", exc)

        # Krotki cooldown — sprawdza flage co 5s, przerywa wczesniej przy triggerze
        triggered = _wait_cooldown(COOLDOWN_SECONDS)
        if triggered:
            next_scan_type = triggered


if __name__ == "__main__":
    main()
