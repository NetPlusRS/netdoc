#!/usr/bin/env python
"""
run_scanner.py — NetDoc network scanner running on the Windows host.

Run directly (not in Docker) — has full access to the network, ARP, nmap.

Usage:
    python run_scanner.py             # continuous mode — scans every SCAN_INTERVAL_MINUTES
    python run_scanner.py --once      # single scan and exit (debug/test)
    python run_scanner.py --full      # full port scan 1-65535 (slow)

Requirements:
    - nmap installed in C:/Program Files (x86)/Nmap/ or in PATH
    - psycopg2 in the Python environment (pip install psycopg2-binary)
    - PostgreSQL in Docker (docker compose up -d postgres)

Scanner status visible in the panel: http://localhost/settings
"""
import sys
import atexit
import os
import subprocess
import time
import logging
import argparse
from datetime import datetime

# On Windows: hide console windows spawned by subprocesses (schtasks, powershell,
# docker, arp, etc.) when running as pythonw.exe (no parent console).
if sys.platform == "win32":
    _OrigPopen = subprocess.Popen
    class _NoWindowPopen(_OrigPopen):
        def __init__(self, *args, **kwargs):
            kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)
            super().__init__(*args, **kwargs)
    subprocess.Popen = _NoWindowPopen

# Set DB to localhost:15432 (PostgreSQL in Docker) if no other setting is present
if "DB_URL" not in os.environ:
    os.environ.setdefault("DB_URL", "postgresql+psycopg2://netdoc:netdoc@localhost:15432/netdoc")

# Add the project directory to PATH
sys.path.insert(0, os.path.dirname(__file__))

# Log directory
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "scanner.log")

_log_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

# stdout handler
_stdout_handler = logging.StreamHandler(sys.stdout)
_stdout_handler.setFormatter(_log_fmt)

# File handler (rotation 1MB x 1 backup)
# _WinSafeRotatingFileHandler: on Windows os.rename() fails when OneDrive or another
# process holds the file open (PermissionError WinError 32). We ignore PermissionError
# during rotation — the file will temporarily exceed the limit, but won't crash the scanner.
from logging.handlers import RotatingFileHandler as _RFH


class _WinSafeRotatingFileHandler(_RFH):
    def doRollover(self):
        try:
            super().doRollover()
        except PermissionError:
            pass  # OneDrive / another process is locking the file — skipping rotation


_file_handler = _WinSafeRotatingFileHandler(LOG_FILE, maxBytes=1 * 1024 * 1024, backupCount=1, encoding="utf-8")
_file_handler.setFormatter(_log_fmt)

logging.basicConfig(level=logging.INFO, handlers=[_stdout_handler, _file_handler])

# Suppress excessive output from libraries
for _noisy in ("paramiko", "urllib3", "requests", "asyncio"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

logger = logging.getLogger("scanner")

# Cooldown between scans in continuous mode (seconds)
COOLDOWN_SECONDS = 60


# ── Popular SNMP community strings for seeding ────────────────────────────────
# Sources: SecLists/SNMP, vendor documentation, SNMP-Brute (SECFORCE), public research
_DEFAULT_SNMP_COMMUNITIES = [
    # --- Standard / RFC ---
    ("public",          10,  "RFC 1157 default read-only — almost every device"),
    ("private",         20,  "RFC 1157 default read-write"),
    ("PUBLIC",          25,  "public uppercase — some vendors are case-sensitive"),

    # --- Cisco ---
    ("cisco",           30,  "Cisco IOS/IOS-XE default"),
    ("ILMI",            35,  "Cisco ATM ILMI management"),
    ("cable-docsis",    38,  "Cisco/DOCSIS cable modems and CMTS"),

    # --- HP / HPE / ProCurve / Aruba ---
    ("manager",         40,  "HP ProCurve / HPE default"),
    ("operator",        45,  "HP ProCurve operator"),
    ("hp_admin",        48,  "HP default admin"),
    ("openview",        50,  "HP OpenView NMS"),

    # --- 3Com / SuperStack ---
    ("comcomcom",       55,  "3Com SuperStack II default"),
    ("ITOUCH",          58,  "3Com ITOUCH / NetBuilder"),
    ("3com",            60,  "3Com generic"),

    # --- Juniper / NetScreen ---
    ("netscreen",       63,  "Juniper NetScreen firewall default"),
    ("ns3read",         65,  "Juniper NetScreen SSG read"),
    ("ns3write",        67,  "Juniper NetScreen SSG write"),

    # --- Extreme Networks / Brocade ---
    ("extreme",         70,  "Extreme Networks default"),
    ("brocade",         73,  "Brocade / Ruckus default"),
    ("NetIron",         75,  "Brocade NetIron"),

    # --- Nortel / Avaya ---
    ("nortel",          78,  "Nortel Ethernet Routing Switch"),
    ("avaya",           80,  "Avaya Communications"),

    # --- General monitoring ---
    ("monitor",         83,  "Monitoring default — many devices"),
    ("community",       85,  "Generic fallback"),
    ("snmp",            87,  "Generic SNMP daemon"),
    ("mngt",            89,  "Management generic"),
    ("admin",           91,  "Admin default — D-Link, NetGear, TP-Link"),
    ("network",         93,  "Generic network management"),
    ("ro",              95,  "Read-only abbreviation"),
    ("rw",              97,  "Read-write abbreviation"),

    # --- IP Cameras / CCTV ---
    ("write",          101,  "Axis Communications camera default write"),

    # --- UPS ---
    ("ups",            105,  "Generic UPS SNMP"),
    ("apc",            107,  "APC Smart-UPS / Schneider Electric UPS"),
    ("eaton",          109,  "Eaton UPS default"),
    ("liebert",        111,  "Vertiv / Liebert UPS"),

    # --- Printers / office devices ---
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
    ("netman",         135,  "General NMS fallback"),

    # --- Telecom / ISP (popular in Poland: ZTE in FTTB/GPON, Huawei OLT, Nokia) ---
    ("zte",            175,  "ZTE GPON/FTTB/router — popular among Polish ISPs"),
    ("huawei",         177,  "Huawei OLT / ONU / router / switch"),
    ("alcatel",        179,  "Alcatel-Lucent / Nokia 7750 SR / ISAM"),
    ("nokia",          181,  "Nokia (formerly Alcatel-Lucent) network equipment"),
    ("dasan",          183,  "DASAN Networks GPON OLT/ONU"),
    ("zhone",          185,  "Zhone / DZS DSL/GPON"),
    ("ubnt",           187,  "Ubiquiti Networks (EdgeSwitch, EdgeRouter, UniFi)"),
    ("mikrotik",       189,  "MikroTik RouterOS — very popular in Poland"),
    ("zyxel",          191,  "ZyXEL switch/router/modem"),
    ("dlink",          193,  "D-Link default"),
    ("tplink",         195,  "TP-Link default (often 'public' but sometimes 'tplink')"),

    # --- Virtualization / servers ---
    ("vmware",         200,  "VMware ESXi SNMP agent"),
    ("sun",            202,  "Sun Microsystems / Oracle Solaris default"),
    ("oracle",         204,  "Oracle hardware (SPARC, x86 servers)"),
    ("ibm",            206,  "IBM BladeCenter / System x"),
    ("dell",           208,  "Dell iDRAC / OpenManage SNMP"),
    ("supermicro",     210,  "Supermicro IPMI / BMC SNMP"),
    ("linux",          212,  "snmpd default Linux configuration (net-snmp)"),

    # --- Energy / PV inverters / renewables ---
    # Most inverters (SMA, Fronius, SolarEdge) use Modbus/SunSpec.
    # Some older devices or SNMP gateways will use the ones below.
    ("sma",            215,  "SMA Solar (older devices with SNMP, e.g. Sunny WebBox)"),
    ("fronius",        217,  "Fronius Solar / Datamanager (some versions)"),
    ("sungrow",        219,  "Sungrow logger / SNMP gateway"),
    ("growatt",        221,  "Growatt ShineWifi / logger"),
    ("solaredge",      223,  "SolarEdge Gateway / monitoring"),
    ("victron",        225,  "Victron Energy Color Control GX"),
    ("power",          227,  "Generic power/energy management"),
    ("energy",         229,  "Generic energy system SNMP"),

    # --- Managed / office switches ---
    ("netgear",        232,  "NetGear Smart Switch default"),
    ("linksys",        234,  "Linksys / Belkin default"),
    ("buffalo",        236,  "Buffalo NAS/switch default"),
    ("edimax",         238,  "Edimax switch / AP default"),
    ("allied",         240,  "Allied Telesis switch default"),
    ("transition",     242,  "Transition Networks media converter"),

    # --- General fallback ---
    ("readonly",       140,  "Read-only generic"),
    ("secret",         145,  "Generic — sometimes used instead of private"),
    ("default",        148,  "Generic default"),
    ("security",       150,  "Generic security community"),
    ("test",           155,  "Test/dev community — often left on production"),
    ("debug",          158,  "Debug community — old firmware"),
    ("system",         160,  "System generic"),
    ("pass",           163,  "Generic password-as-community"),
    ("access",         165,  "Generic access"),
    ("enable",         167,  "Cisco-like generic"),
    ("SNMP_trap",      170,  "SNMP trap receiver community"),
    ("trap",           173,  "Trap community generic"),

    # --- Printers / MFP — specific communities ---
    ("hp_admin",       245,  "HP LaserJet admin community (some models)"),
    ("hppassword",     247,  "HP LaserJet hppassword (old JetDirect)"),
    ("KONICA_MINOLTA", 249,  "Konica Minolta PageScope SNMP — default"),
    ("KonicaMinolta",  251,  "Konica Minolta alternative"),
    ("XeroxShared",    253,  "Xerox WorkCentre / AltaLink SNMP community"),
    ("epsonpublic",    255,  "Epson EpsonNet SNMP community"),
    ("SharpMFP",       257,  "Sharp MFP SNMP community default"),
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

    # --- Load balancers / ADC ---
    ("f5",             281,  "F5 BIG-IP SNMP community"),
    ("bigip",          283,  "F5 BIG-IP alternative"),
    ("netscaler",      285,  "Citrix NetScaler / ADC SNMP"),
    ("a10",            287,  "A10 Networks Thunder / vThunder SNMP"),
    ("kemp",           289,  "Kemp LoadMaster SNMP"),
    ("radware",        291,  "Radware Alteon / Appsafe SNMP"),
    ("barracuda",      293,  "Barracuda Load Balancer ADC SNMP"),

    # --- SAN / Fibre Channel ---
    ("OrigEquipMfr",   295,  "Brocade FC switch default SNMP"),
    ("netman",         297,  "Generic SAN/NAS management (already have it but duplicate ok)"),
    ("storageWorks",   299,  "HP StorageWorks / MSA SNMP"),
    ("IBM_TS",         301,  "IBM Tape Storage SNMP community"),

    # --- Video conferencing ---
    ("tandberg",       303,  "Cisco Webex Room / Tandberg SNMP community"),
    ("polycom",        305,  "Polycom RealPresence / Group SNMP"),
    ("lifesize",       307,  "Lifesize Icon SNMP community"),

    # --- KVM / Console servers ---
    ("raritan",        309,  "Raritan KVM / PX PDU SNMP"),
    ("cyclades",       311,  "Cyclades / Avocent console server SNMP"),
    ("opengear",       313,  "Opengear console server SNMP"),
    ("lantronix",      315,  "Lantronix EDS / SCS SNMP"),

    # --- PDU / Intelligent Power ---
    ("sysuser",        317,  "Server Technology POPS / Switched CDU default"),
    ("geist",          319,  "Geist / Vertiv Watchdog PDU SNMP"),
    ("akcp",           321,  "AKCP SensorProbe / MasterProbe SNMP"),
    ("emerson",        323,  "Emerson / Liebert (PDU and monitoring) SNMP"),

    # --- Managed switches (missing) ---
    ("arista",         325,  "Arista EOS switch SNMP community"),
    ("juniper",        327,  "Juniper EX/QFX switch SNMP (already have 'netscreen' but different product)"),
    ("omniswitch",     329,  "Alcatel-Lucent Enterprise OmniSwitch SNMP"),
    ("moxa",           331,  "Moxa industrial switch / serial server SNMP"),
    ("hirschmann",     333,  "Hirschmann / Belden industrial switch SNMP"),
    ("tplink",         335,  "TP-Link Omada managed switch/AP SNMP"),

    # --- Firewalls (missing) ---
    ("paloalto",       337,  "Palo Alto Networks PA-series SNMP community"),
    ("panorama",       339,  "Palo Alto Panorama management SNMP"),
    ("checkpoint",     341,  "Check Point Firewall-1 / Gaia SNMP"),
    ("cpublic",        343,  "Check Point alternative read community"),
    ("sophos",         345,  "Sophos XG / UTM / SG SNMP community"),
    ("stormshield",    347,  "Stormshield SNS / SN SNMP"),
    ("watchguard",     349,  "WatchGuard Firebox SNMP"),
    ("barracuda",      351,  "Barracuda CloudGen / NextGen Firewall SNMP"),
    ("pfsense",        353,  "pfSense / OPNsense SNMP community"),

    # --- NAS (missing) ---
    ("asustor",        355,  "Asustor NAS ADM SNMP"),
    ("terramaster",    357,  "Terramaster TOS NAS SNMP"),

    # --- Telecom (missing) ---
    ("audiocodes",     359,  "AudioCodes Mediant SBC/GW SNMP community"),
    ("patton",         361,  "Patton SmartNode / SN gateway SNMP"),
    ("ribbon",         363,  "Ribbon / GENBAND SBC SNMP"),
    ("isadmin",        365,  "Alcatel-Lucent ISAM DSLAM admin community"),

    # --- BMC servers (missing) ---
    ("iDRAC",          367,  "Dell iDRAC SNMP community (uppercase)"),
    ("iLO",            369,  "HPE iLO SNMP community"),

    # --- Broadband routers/modems ---
    ("fritzbox",       371,  "AVM Fritz!Box (popular in DE/AT/PL with DSL) SNMP"),
    ("technicolor",    373,  "Technicolor / Thomson DSL modem SNMP"),
    ("sagemcom",       375,  "Sagemcom DSL/fiber modem SNMP"),
    ("speedtouch",     377,  "Speedtouch / Alcatel DSL modem SNMP"),
    # ═══════════════════════════════════════════════════════════════════════════
    # IP CAMERAS — dedicated communities
    # ═══════════════════════════════════════════════════════════════════════════

    # Hikvision (most popular in the world)
    ("hikvision",   55, "Hikvision IP camera/NVR — custom community"),
    ("hiksnmp",     55, "Hikvision alternative community string"),

    # Dahua (second most popular)
    ("dahua",       56, "Dahua IP camera/NVR — custom community"),

    # Axis Communications (Sweden, often in enterprises)
    ("axis",        57, "Axis IP camera — SNMP community"),

    # Uniview / UNV (China)
    ("uniview",     58, "Uniview/UNV camera — SNMP community"),
    ("unv",         58, "Uniview short alias"),

    # Vivotek (Taiwan)
    ("vivotek",     59, "Vivotek IP camera — SNMP community"),

    # Mobotix (Germany)
    ("mobotix",     60, "Mobotix MxPEG camera — SNMP"),

    # Pelco (USA, Schneider Electric)
    ("pelco",       61, "Pelco IP camera / Endura VMS — SNMP"),

    # GeoVision (Taiwan)
    ("geovision",   62, "GeoVision NVR/DVR/camera — SNMP"),

    # FLIR / Teledyne
    ("flir",        63, "FLIR thermal / IP camera — SNMP"),

    # Sony (network cameras)
    ("sony",        64, "Sony SNC / SSC IP camera — SNMP"),

    # Panasonic (cameras/PBX)
    ("panasonic",   65, "Panasonic WV / BB series camera — SNMP"),

    # Foscam / Amcrest
    ("foscam",      66, "Foscam IP camera — SNMP community"),
    ("amcrest",     66, "Amcrest / Q-See / Lorex — SNMP"),

    # Bosch (cameras / DIVAR NVR)
    ("bosch",       67, "Bosch FLEXIDOME / DIVAR — SNMP"),

    # ACTi (Taiwan)
    ("acti",        68, "ACTi IP camera — SNMP community"),

    # Avigilon (Motorola Solutions)
    ("avigilon",    69, "Avigilon IP camera / ACC — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # NAS — dedicated communities
    # ═══════════════════════════════════════════════════════════════════════════

    # QNAP
    ("qnap",        75, "QNAP NAS — SNMP community"),
    ("qnapSnmp",    75, "QNAP NAS alternative"),

    # WD My Cloud
    ("wd",          76, "WD My Cloud NAS — SNMP"),
    ("wdnas",       76, "WD My Cloud NAS alternative"),

    # NetApp (enterprise)
    ("netapp",      77, "NetApp ONTAP — SNMP community"),
    ("ntap",        77, "NetApp short alias"),

    # TrueNAS / FreeNAS
    ("truenas",     78, "TrueNAS CORE/SCALE — SNMP"),
    ("freenas",     78, "FreeNAS legacy — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # WIFI / WIRELESS — missing brands
    # ═══════════════════════════════════════════════════════════════════════════

    # Ruckus / CommScope
    ("ruckus",      82, "Ruckus ZoneDirector / SmartZone AP — SNMP"),
    ("unleashed",   82, "Ruckus Unleashed — SNMP community"),

    # Cambium Networks
    ("cambium",     83, "Cambium ePMP / cnMaestro AP — SNMP"),
    ("cambiumNetworks", 83, "Cambium alternative"),

    # Peplink / Pepwave
    ("peplink",     84, "Peplink / Pepwave router — SNMP"),

    # EnGenius
    ("engenius",    85, "EnGenius AP / switch — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # FIREWALL — missing brands
    # ═══════════════════════════════════════════════════════════════════════════

    # FortiGate / Fortinet
    ("fortinet",    90, "Fortinet FortiGate — SNMP community"),
    ("fortigate",   90, "FortiGate alternative"),
    ("FGTread",     90, "FortiGate read-only community string"),

    # SonicWall
    ("sonicwall",   91, "SonicWall firewall — SNMP"),
    ("SonicWall",   91, "SonicWall case-sensitive"),

    # OPNsense
    ("opnsense",    92, "OPNsense — SNMP community"),

    # ═══════════════════════════════════════════════════════════════════════════
    # PRINTERS — missing brands
    # ═══════════════════════════════════════════════════════════════════════════

    # Brother
    ("brother",    100, "Brother laser/inkjet — SNMP community"),
    ("BRAdmin",    100, "Brother BRAdmin alternative"),

    # ═══════════════════════════════════════════════════════════════════════════
    # PBX / PHONES — missing brands
    # ═══════════════════════════════════════════════════════════════════════════

    # Grandstream (UCM PBX + GXP phones)
    ("grandstream",105, "Grandstream UCM PBX / GXP phone — SNMP"),

    # Yealink (phones)
    ("yealink",    106, "Yealink T/W/CP series — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # NVR/DVR — additional brands
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
    # SOFTWARE ROUTERS / NEW BRANDS
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
    # FIRE ALARM SYSTEMS
    # ═══════════════════════════════════════════════════════════════════════════
    ("notifier",    155, "Notifier / Fire-Lite Honeywell Fire — SNMP"),
    ("cerberus",    156, "Siemens Cerberus PRO / Desigo Fire — SNMP"),
    ("esser",       157, "Esser / Hochiki fire panel — SNMP"),
    ("mircom",      158, "Mircom FX fire panel — SNMP"),
    ("kentec",      159, "Kentec Syncro fire panel — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # GATE CONTROLLERS / ACCESS CONTROLLERS
    # ═══════════════════════════════════════════════════════════════════════════
    ("faac",        162, "FAAC gate controller — SNMP"),
    ("satel",       163, "SATEL INTEGRA alarm / access — SNMP"),
    ("roger",       164, "Roger RACS5 access controller — SNMP"),
    ("doorbird",    165, "DoorBird IP intercom — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # ENERGY METERS
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
    # WEATHER STATIONS
    # ═══════════════════════════════════════════════════════════════════════════
    ("vaisala",     179, "Vaisala HMT / RFL sensor — SNMP"),
    ("campbell",    180, "Campbell Scientific datalogger — SNMP"),
    ("davis",       181, "Davis WeatherLink — SNMP"),
    ("lufft",       182, "Lufft / OTT HydroMet sensor — SNMP"),

    # ═══════════════════════════════════════════════════════════════════════════
    # EV CHARGERS
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


# ── Default SSH/Telnet credentials — audit of unsecured devices ───────────────
# Sources: CIRT.net default passwords, SecLists/Passwords/Default-Credentials,
# vendor documentation, CVE research (public).
# Order = attempt priority (lower number = higher priority / more often effective).
_DEFAULT_SSH_CREDENTIALS = [
    # (username, password, priority, notes)

    # --- No password / empty password (most often effective) ---
    ("admin",        "",              10,  "admin / no password — MikroTik, ZTE, Huawei ONU, cheap routers"),
    ("root",         "",              12,  "root / no password — embedded Linux, embedded firmware"),
    ("admin",        "admin",         15,  "admin/admin — classic unsecured default (D-Link, Asus, many cheap devices)"),
    ("admin",        "password",      20,  "admin/password — Windows Server, generic default"),
    ("admin",        "1234",          22,  "admin/1234 — TP-Link, D-Link, ZTE older"),
    ("admin",        "12345",         24,  "admin/12345 — cheap routers and cameras"),
    ("admin",        "123456",        26,  "admin/123456 — very common in Chinese OEM"),
    ("admin",        "admin123",      28,  "admin/admin123 — alternative default"),

    # --- root ---
    ("root",         "root",          30,  "root/root — embedded Linux (OpenWrt fresh install)"),
    ("root",         "password",      32,  "root/password — generic Linux"),
    ("root",         "admin",         34,  "root/admin — some NAS/camera devices"),
    ("root",         "toor",          36,  "root/toor — Kali/BackTrack reversed root"),
    ("root",         "1234",          38,  "root/1234 — cheap CCTV devices"),

    # --- Cisco ---
    ("cisco",        "cisco",         40,  "cisco/cisco — Cisco IOS classic default"),
    ("cisco",        "",              42,  "cisco / no password — some operators"),
    ("admin",        "cisco",         44,  "admin/cisco — Cisco ISE / Cisco WAP"),
    ("enable",       "",              46,  "enable / no password — Cisco enable mode"),
    ("cisco",        "password",      48,  "cisco/password — generic Cisco"),

    # --- MikroTik ---
    ("admin",        "",              50,  "admin / no password — MikroTik RouterOS default (up to version 6.49)"),

    # --- Ubiquiti ---
    ("ubnt",         "ubnt",          55,  "ubnt/ubnt — Ubiquiti AirOS / EdgeOS default"),
    ("admin",        "ubnt",          57,  "admin/ubnt — Ubiquiti UniFi some firmware"),

    # --- Huawei ---
    ("admin",        "Admin@huawei",  60,  "admin/Admin@huawei — Huawei enterprise (new firmware)"),
    ("admin",        "huawei@123",    62,  "admin/huawei@123 — Huawei OLT / ONU"),
    ("root",         "huawei123",     64,  "root/huawei123 — Huawei service account"),
    ("huawei",       "huawei",        66,  "huawei/huawei — old Huawei DSL/ONU"),
    ("admin",        "Huawei@123456", 68,  "admin/Huawei@123456 — Huawei newer series"),

    # --- ZTE ---
    ("admin",        "zte_admin",     70,  "admin/zte_admin — ZTE OLT/ONT default"),
    ("admin",        "Admin1234!",    72,  "admin/Admin1234! — ZTE newer firmware"),
    ("zte",          "zte",           74,  "zte/zte — ZTE alternative default"),
    ("support",      "zte_support",   76,  "support/zte_support — ZTE service account"),

    # --- Juniper / NetScreen ---
    ("netscreen",    "netscreen",     80,  "netscreen/netscreen — Juniper NetScreen default"),
    ("admin",        "netscreen",     82,  "admin/netscreen — NetScreen alternative"),

    # --- HP ProCurve / Aruba ---
    ("manager",      "manager",       85,  "manager/manager — HP ProCurve switch default"),
    ("operator",     "operator",      87,  "operator/operator — HP ProCurve operator"),
    ("admin",        "HP@1234",       89,  "admin/HP@1234 — HPE Aruba new default"),

    # --- Fortinet / FortiGate ---
    ("admin",        "",              91,  "admin / no password — FortiGate default (old firmware)"),

    # --- SonicWall ---
    ("admin",        "password",      93,  "admin/password — SonicWall default"),

    # --- Ruckus / Brocade ---
    ("super",        "sp-admin",      98,  "super/sp-admin — Ruckus ZoneDirector / Unleashed"),
    ("admin",        "ruckus",       100,  "admin/ruckus — Ruckus generic"),

    # --- Axis (IP cameras) ---
    ("root",         "pass",         103,  "root/pass — Axis Communications camera default"),
    ("admin",        "axis",         105,  "admin/axis — Axis alternative"),

    # --- DAHUA / Hikvision (CCTV) ---
    ("admin",        "12345",        107,  "admin/12345 — Dahua NVR/DVR default"),
    ("admin",        "Admin12345",   111,  "admin/Admin12345 — Hikvision newer"),

    # --- NAS (QNAP / Synology) ---
    ("admin",        "admin",        113,  "admin/admin — QNAP NAS default"),

    # --- General servers / OT / SCADA ---
    ("user",         "user",         120,  "user/user — generic user account"),
    ("user",         "password",     122,  "user/password — generic"),
    ("guest",        "guest",        124,  "guest/guest — guest account"),
    ("test",         "test",         126,  "test/test — test accounts left on production"),
    ("service",      "service",      128,  "service/service — service account"),
    ("support",      "support",      130,  "support/support — support account"),
    ("monitor",      "monitor",      132,  "monitor/monitor — monitoring account"),
    ("operator",     "",             134,  "operator / no password — OT/SCADA"),
    ("supervisor",   "",             136,  "supervisor / no password — OT/SCADA Schneider, Rockwell"),
    ("admin",        "0000",         138,  "admin/0000 — some Chinese devices"),
    ("admin",        "111111",       140,  "admin/111111 — common in Asian OEM"),
    ("admin",        "888888",       142,  "admin/888888 — Chinese IoT default"),

    # --- Raspberry Pi ---
    ("pi",           "raspberry",    150,  "pi/raspberry — Raspberry Pi OS default"),
    ("pi",           "pi",           152,  "pi/pi — Raspberry Pi alternative"),

    # --- IPMI / iDRAC / iLO servers ---
    ("root",         "calvin",       155,  "root/calvin — Dell iDRAC default"),
    ("Administrator","",             157,  "Administrator / no password — HPE iLO initial"),
    ("ADMIN",        "ADMIN",        159,  "ADMIN/ADMIN — Supermicro IPMI default"),

    # ═══════════════════════════════════════════════════════════════════════════
    # IP CAMERAS / DVR/NVR RECORDERS / CCTV
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Hikvision (most popular IP cameras in the world) ---
    ("admin",        "12345",        160,  "admin/12345 — Hikvision older firmware (up to 2016)"),
    ("admin",        "Admin12345",   161,  "admin/Admin12345 — Hikvision newer (password policy)"),
    ("admin",        "hik12345",     162,  "admin/hik12345 — Hikvision OEM"),
    ("888888",       "888888",       163,  "888888/888888 — Hikvision legacy PIN"),
    ("666666",       "666666",       164,  "666666/666666 — Hikvision legacy alternative"),

    # --- Dahua (second place in the CCTV market) ---
    ("admin",        "admin",        165,  "admin/admin — Dahua older firmware"),
    ("admin",        "",             166,  "admin / no password — Dahua newer (force settings)"),
    ("admin",        "dahua1234",    167,  "admin/dahua1234 — Dahua OEM"),
    ("888888",       "888888",       168,  "888888/888888 — Dahua 'super' account"),
    ("666666",       "666666",       169,  "666666/666666 — Dahua operator legacy"),

    # --- Axis Communications ---
    ("root",         "pass",         170,  "root/pass — Axis default up to firmware 5.51"),
    ("root",         "root",         171,  "root/root — Axis alternative"),
    ("admin",        "admin",        172,  "admin/admin — Axis older camera lines"),

    # --- Amcrest / Lorex / Q-See (OEM Dahua) ---
    ("admin",        "admin",        173,  "admin/admin — Amcrest/Q-See/Lorex (OEM Dahua)"),
    ("admin",        "amcrest2021",  174,  "admin/amcrest2021 — Amcrest newer"),
    ("admin",        "admin1234",    175,  "admin/admin1234 — Lorex"),

    # --- Foscam ---
    ("admin",        "",             176,  "admin / no password — Foscam older"),
    ("admin",        "foscam",       177,  "admin/foscam — Foscam"),

    # --- Reolink ---
    ("admin",        "",             178,  "admin / no password — Reolink (required setting on first startup)"),

    # --- Vivotek ---
    ("root",         "",             179,  "root / no password — Vivotek default"),
    ("admin",        "admin",        180,  "admin/admin — Vivotek alternative"),

    # --- Hanwha / Samsung Techwin ---
    ("admin",        "4321",         181,  "admin/4321 — Hanwha/Samsung Techwin default"),
    ("admin",        "no1done",      182,  "admin/no1done — Samsung older cameras"),

    # --- Mobotix ---
    ("admin",        "meinsm",       183,  "admin/meinsm — Mobotix default password"),
    ("root",         "meinsm",       184,  "root/meinsm — Mobotix root"),

    # --- Bosch / Pelco / FLIR ---
    ("service",      "service",      185,  "service/service — Bosch IP camera service account"),
    ("admin",        "admin",        186,  "admin/admin — Pelco default"),
    ("admin",        "admin",        187,  "admin/admin — FLIR / Teledyne"),

    # --- Uniview (UNV) ---
    ("admin",        "123456",       188,  "admin/123456 — Uniview/UNV default"),

    # --- TVT / Jovision / CP Plus ---
    ("admin",        "1111",         189,  "admin/1111 — TVT DVR"),
    ("admin",        "jvs2011",      190,  "admin/jvs2011 — Jovision"),
    ("admin",        "admin",        191,  "admin/admin — CP Plus (Aditya Infotech OEM)"),

    # --- Zmodo / Night Owl / Swann ---
    ("admin",        "111111",       192,  "admin/111111 — Zmodo"),
    ("admin",        "admin",        193,  "admin/admin — Night Owl / Swann DVR"),

    # ═══════════════════════════════════════════════════════════════════════════
    # NVR/DVR RECORDERS — dedicated brands
    # ═══════════════════════════════════════════════════════════════════════════

    # --- GeoVision (popular in PL, Taiwan) ---
    ("admin",        "admin",        194,  "admin/admin — GeoVision GV-NVR/DVR default"),
    ("admin",        "",             194,  "admin / no password — GeoVision older"),
    ("admin",        "1234",         194,  "admin/1234 — GeoVision alternative"),

    # --- LILIN / Merit LILIN (Taiwan, popular in EU) ---
    ("admin",        "1111",         194,  "admin/1111 — LILIN NVR default PIN"),
    ("admin",        "admin",        194,  "admin/admin — LILIN alternative"),
    ("root",         "admin",        194,  "root/admin — LILIN SSH embedded"),

    # --- NUUO (Taiwan, NVR/VMS manufacturer) ---
    ("admin",        "admin",        194,  "admin/admin — NUUO Titan/Crystal default"),
    ("root",         "admin",        194,  "root/admin — NUUO SSH"),

    # --- Avigilon / Motorola Solutions ---
    ("administrator","administrator",194,  "administrator/administrator — Avigilon ACC default"),
    ("admin",        "admin",        194,  "admin/admin — Avigilon NVR"),

    # --- Bosch DIVAR (popular in enterprises in PL) ---
    ("admin",        "1234",         194,  "admin/1234 — Bosch DIVAR IP 2000/3000/7000 default"),
    ("service",      "service",      194,  "service/service — Bosch DIVAR service account"),
    ("live",         "live",         194,  "live/live — Bosch DIVAR live view account"),

    # --- Tiandy (large Chinese NVR manufacturer, growing share in PL) ---
    ("admin",        "111111",       194,  "admin/111111 — Tiandy NVR default"),
    ("admin",        "admin",        194,  "admin/admin — Tiandy alternative"),

    # --- Kedacom (China, many installations in EU) ---
    ("admin",        "admin",        194,  "admin/admin — Kedacom NVR default"),
    ("admin",        "1234",         194,  "admin/1234 — Kedacom alternative"),

    # --- ZKTeco NVR (same company as access controllers) ---
    ("admin",        "123456",       194,  "admin/123456 — ZKTeco NVR default"),
    ("admin",        "admin",        194,  "admin/admin — ZKTeco NVR alternative"),

    # --- ANNKE (OEM Hikvision, but different defaults) ---
    ("admin",        "admin123",     194,  "admin/admin123 — ANNKE NVR default"),
    ("admin",        "12345",        194,  "admin/12345 — ANNKE alternative"),

    # --- IDIS (Korea, popular in enterprises) ---
    ("admin",        "admin1234",    194,  "admin/admin1234 — IDIS DirectIP NVR"),
    ("admin",        "",             194,  "admin / no password — IDIS older firmware"),

    # --- Provision ISR (Israel / EU) ---
    ("admin",        "admin",        194,  "admin/admin — Provision ISR NVR"),
    ("admin",        "1234",         194,  "admin/1234 — Provision ISR alternative"),

    # --- Sunell (China) ---
    ("admin",        "123456",       194,  "admin/123456 — Sunell NVR default"),

    # --- Vicon Industries ---
    ("admin",        "admin",        194,  "admin/admin — Vicon VALERUS NVR"),

    # --- Speco Technologies (USA) ---
    ("admin",        "1234",         194,  "admin/1234 — Speco SecureGuard NVR"),
    ("admin",        "admin",        194,  "admin/admin — Speco alternative"),

    # --- IC Realtime ---
    ("admin",        "123456",       194,  "admin/123456 — IC Realtime NVR"),

    # --- Digital Watchdog ---
    ("admin",        "admin",        194,  "admin/admin — Digital Watchdog Blackjack NVR"),
    ("admin",        "DW1234",       194,  "admin/DW1234 — Digital Watchdog alternative"),

    # --- Exacq Vision (Johnson Controls) ---
    ("admin",        "admin256",     194,  "admin/admin256 — Exacq Vision NVR default"),
    ("admin",        "admin",        194,  "admin/admin — Exacq Vision alternative"),

    # --- IndigoVision ---
    ("admin",        "admin",        194,  "admin/admin — IndigoVision NVR"),
    ("administrator","password",     194,  "administrator/password — IndigoVision older"),

    # --- March Networks ---
    ("admin",        "march",        194,  "admin/march — March Networks CMR/ME NVR"),
    ("admin",        "admin",        194,  "admin/admin — March Networks alternative"),

    # --- Digifort (Brazil / EU) ---
    ("admin",        "digifort",     194,  "admin/digifort — Digifort VMS default"),

    # --- Qvis (UK brand, Chinese OEM) ---
    ("admin",        "1234",         194,  "admin/1234 — Qvis NVR default"),

    # --- Epcom / Epcom Tech (Mexico / LAC) ---
    ("admin",        "admin",        194,  "admin/admin — Epcom NVR"),

    # --- Reolink NVR (dedicated recorder) ---
    ("admin",        "",             194,  "admin / no password — Reolink NVR (required setting)"),
    ("admin",        "reolink",      194,  "admin/reolink — Reolink NVR alternative"),

    # --- Acti (Taiwan) ---
    ("admin",        "123456",       194,  "admin/123456 — ACTi NVR default"),
    ("Admin",        "123456",       194,  "Admin/123456 — ACTi uppercase"),

    # --- Honeywell Performance NVR (CCTV product line) ---
    ("admin",        "admin1234",    194,  "admin/admin1234 — Honeywell Performance NVR"),
    ("admin",        "1234",         194,  "admin/1234 — Honeywell NVR alternative"),


    # ═══════════════════════════════════════════════════════════════════════════
    # WIFI ACCESS POINTS
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Cisco Aironet / Catalyst AP ---
    ("Cisco",        "Cisco",        195,  "Cisco/Cisco — Cisco Aironet default (uppercase)"),
    ("admin",        "Cisco",        196,  "admin/Cisco — Cisco WAP default"),

    # --- EnGenius ---
    ("admin",        "admin",        197,  "admin/admin — EnGenius AP default"),
    ("admin",        "1234",         198,  "admin/1234 — EnGenius older models"),

    # --- Cambium (ePMP / cnPilot / Force) ---
    ("admin",        "admin",        199,  "admin/admin — Cambium cnPilot / ePMP"),
    ("cambium",      "cambium",      200,  "cambium/cambium — Cambium ePMP older"),
    ("installer",    "installer",    201,  "installer/installer — Cambium ePMP installer"),

    # --- Peplink / Pepwave ---
    ("admin",        "admin",        202,  "admin/admin — Peplink / Pepwave default"),

    # --- Cradlepoint ---
    ("admin",        "",             203,  "admin / no password — Cradlepoint (MAC-based default)"),

    # --- Ruckus Wireless ---
    ("super",        "sp-admin",     204,  "super/sp-admin — Ruckus ZoneDirector"),
    ("admin",        "admin",        205,  "admin/admin — Ruckus Unleashed alternative"),

    # --- Netgear (AP / switch) ---
    ("admin",        "password",     206,  "admin/password — Netgear default"),
    ("admin",        "1234",         207,  "admin/1234 — Netgear older models"),

    # --- Edimax ---
    ("admin",        "1234",         208,  "admin/1234 — Edimax AP default"),

    # --- LigoWave (Deliberant) ---
    ("admin",        "admin01",      209,  "admin/admin01 — LigoWave / Deliberant"),

    # ═══════════════════════════════════════════════════════════════════════════
    # SMART HOME / IoT / BUILDING AUTOMATION
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Shelly (very popular in PL, Home Assistant integrations) ---
    ("admin",        "",             210,  "admin / no password — Shelly Gen1 (no authentication by default)"),
    ("admin",        "admin",        211,  "admin/admin — Shelly Gen2/Gen3 new API"),

    # --- Sonoff / eWeLink (Itead) ---
    ("admin",        "admin",        212,  "admin/admin — Sonoff LAN/SSH"),
    ("root",         "root",         213,  "root/root — Sonoff OpenWrt firmware"),

    # --- Xiaomi / Roborock (vacuums and IoT) ---
    ("root",         "rockrobo",     214,  "root/rockrobo — Xiaomi Roborock SSH (classic exploit)"),
    ("root",         "",             215,  "root / no password — Xiaomi Mi Smart devices early firmware"),

    # --- Xiaomi Router (MiWiFi) ---
    ("root",         "root",         216,  "root/root — Xiaomi MiWiFi router SSH"),
    ("admin",        "admin",        217,  "admin/admin — Xiaomi MiWiFi panel"),

    # --- Tuya / Smart Life (mass OEM) ---
    ("admin",        "admin",        218,  "admin/admin — Tuya-based devices generic"),
    ("root",         "tuyaroot",     219,  "root/tuyaroot — Tuya BK7231 SSH"),

    # --- Smart TV (Samsung / LG / Sony) ---
    ("admin",        "admin",        220,  "admin/admin — Samsung Smart TV diagnostic"),
    ("admin",        "1234",         221,  "admin/1234 — LG Smart TV default"),
    ("admin",        "admin",        222,  "admin/admin — Sony Bravia admin panel"),
    ("root",         "",             223,  "root / no password — Android TV / Chromecast ADB"),

    # --- Philips Hue Bridge ---
    ("root",         "",             224,  "root / no password — Philips Hue Bridge SSH"),

    # --- Lighting control (DALI / KNX / Lutron) ---
    ("admin",        "admin",        225,  "admin/admin — DALI-2 gateway / KNX IP router default"),
    ("admin",        "lutron",       226,  "admin/lutron — Lutron RadioRA default"),
    ("user",         "user",         227,  "user/user — Lutron alternative"),
    ("admin",        "1234",         228,  "admin/1234 — KNX IP gateway (e.g. MDT, Gira)"),

    # --- Heating / air conditioning control (HVAC) ---
    ("admin",        "admin",        229,  "admin/admin — Daikin Intelligent Manager / BRP"),
    ("admin",        "admin",        230,  "admin/admin — Mitsubishi Electric MELCloud gateway"),
    ("admin",        "admin",        231,  "admin/admin — Fujitsu UTY-TWGUWA web gateway"),

    # --- Building automation systems (BMS / BAS) ---
    ("admin",        "admin",        232,  "admin/admin — Johnson Controls Metasys SSH"),
    ("jci",          "jci",          233,  "jci/jci — Johnson Controls service account"),
    ("admin",        "1234",         234,  "admin/1234 — Honeywell WEBs / EBI"),
    ("admin",        "admin",        235,  "admin/admin — Siemens Desigo PXC / Climatix"),
    ("admin",        "admin",        236,  "admin/admin — Schneider Electric TAC Vista / EcoStruxure"),
    ("admin",        "admin",        237,  "admin/admin — Trend Controls IQ / TONN"),
    ("admin",        "admin",        238,  "admin/admin — Distech Controls ECY"),

    # --- Irrigation systems ---
    ("admin",        "admin",        240,  "admin/admin — Hunter Pro-C / ICC SSH"),
    ("admin",        "1234",         241,  "admin/1234 — Rain Bird ESP-TM2 / ST8O"),

    # --- Refrigerators / smart appliances ---
    ("admin",        "admin",        245,  "admin/admin — Samsung Family Hub / smart appliances SSH"),
    ("root",         "",             246,  "root / no password — LG ThinQ embedded Linux"),

    # --- Network printers (SSH/FTP) ---
    ("admin",        "admin",        250,  "admin/admin — HP LaserJet SSH/FTP embedded"),
    ("admin",        "",             251,  "admin / no password — Kyocera / Ricoh / Canon SSH"),
    ("admin",        "1234",         252,  "admin/1234 — Epson ET network printers"),
    ("root",         "",             253,  "root / no password — Brother MFC embedded"),

    # --- Fiber optics / media converters / SFP ---
    ("admin",        "admin",        255,  "admin/admin — TP-Link media converter / SFP"),
    ("admin",        "1234",         256,  "admin/1234 — Transition Networks / Perle"),

    # --- UPS (SSH/Telnet) ---
    ("apc",          "apc",          260,  "apc/apc — APC Smart-UPS Network Management Card"),
    ("device",       "apc",          261,  "device/apc — APC NMC read-only"),
    ("readonly",     "apc",          262,  "readonly/apc — APC NMC readonly"),
    ("admin",        "admin",        263,  "admin/admin — Eaton UPS Gigabit Network Card"),
    ("admin",        "admin",        264,  "admin/admin — Vertiv / Liebert IntelliSlot"),
    ("localadmin",   "localadmin",   265,  "localadmin/localadmin — Riello / SDT UPS"),

    # --- Access controllers / intercoms ---
    ("admin",        "admin",        270,  "admin/admin — Hikvision / ZKTeco intercom / access controller"),
    ("admin",        "1234",         271,  "admin/1234 — Dahua intercom VTO"),
    ("admin",        "admin",        272,  "admin/admin — 2N Helios default (up to v2.25)"),
    ("admin",        "2n",           273,  "admin/2n — 2N Helios newer firmware"),

    # --- VoIP / IP phones ---
    ("admin",        "admin",        275,  "admin/admin — Yealink SIP phone default"),
    ("admin",        "1234",         276,  "admin/1234 — Grandstream GXP / UCM"),
    ("admin",        "admin",        277,  "admin/admin — Cisco SPA / CP SSH"),
    ("admin",        "admin",        278,  "admin/admin — Snom / Fanvil VoIP"),

    # --- SNMP/telnet PLC / OT (additional) ---
    ("USER",         "USER",         280,  "USER/USER — Schneider Modicon PLC Telnet"),
    ("USER",         "",             281,  "USER / no password — Schneider Modicon legacy"),
    ("admin",        "",             282,  "admin / no password — Beckhoff TwinCAT / CX embedded"),
    ("Administrator","1",            283,  "Administrator/1 — Siemens SCALANCE switch"),

    # ═══════════════════════════════════════════════════════════════════════════
    # IP PBX / UC PHONE SYSTEMS
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Asterisk / FreePBX (Linux-based, very popular in PL) ---
    ("admin",        "admin",        285,  "admin/admin — FreePBX Web + SSH default"),
    ("root",         "password",     286,  "root/password — Asterisk AMI / SSH generic"),
    ("admin",        "jEkiN3dW",     287,  "admin/jEkiN3dW — FreePBX 2.x default installer password"),

    # --- Cisco Call Manager (CUCM) / Unified Communications ---
    ("admin",        "cisco",        288,  "admin/cisco — Cisco CUCM default"),
    ("admin",        "Cisco1234",    289,  "admin/Cisco1234 — Cisco UCM alternative"),
    ("ccmadmin",     "cisco",        290,  "ccmadmin/cisco — Cisco Call Manager SSH"),

    # --- 3CX (Windows/Linux PBX, very popular in Poland) ---
    ("admin",        "admin",        291,  "admin/admin — 3CX Management Console default"),
    ("3CX",          "3CX",          292,  "3CX/3CX — 3CX legacy"),

    # --- Avaya IP Office / Aura ---
    ("Administrator","Administrator",293,  "Administrator/Administrator — Avaya IP Office"),
    ("admin",        "avaya",        294,  "admin/avaya — Avaya System Manager SSH"),
    ("craft",        "craft",        295,  "craft/craft — Avaya service account"),

    # --- Mitel / ShoreTel ---
    ("admin",        "admin",        296,  "admin/admin — Mitel MiVoice / ShoreTel Director"),
    ("maintenance",  "maintenance",  297,  "maintenance/maintenance — Mitel service account"),

    # --- Panasonic KX (popular in offices in PL) ---
    ("admin",        "admin",        298,  "admin/admin — Panasonic KX-NS/NCP Web"),
    ("admin",        "1234",         299,  "admin/1234 — Panasonic KX older models"),

    # --- NEC UNIVERGE ---
    ("admin",        "admin",        300,  "admin/admin — NEC UNIVERGE SSH"),

    # --- Grandstream UCM (PBX) ---
    ("admin",        "admin",        301,  "admin/admin — Grandstream UCM6xxx Web"),
    ("admin",        "password",     302,  "admin/password — Grandstream UCM alternative"),

    # ═══════════════════════════════════════════════════════════════════════════
    # IP PHONES (VoIP) — SIP
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Yealink (most popular in Poland) ---
    ("admin",        "admin",        305,  "admin/admin — Yealink T/W/CP series Web (old firmware)"),
    ("admin",        "admin1",       306,  "admin/admin1 — Yealink older firmware"),
    ("user",         "user",         307,  "user/user — Yealink user"),

    # --- Grandstream (GXP/GRP) ---
    ("admin",        "admin",        308,  "admin/admin — Grandstream GXP default"),
    ("user",         "",             309,  "user / no password — Grandstream GXP user"),

    # --- Cisco IP Phone (SPA/CP) ---
    ("admin",        "admin",        310,  "admin/admin — Cisco SPA/CP Web"),
    ("cisco",        "cisco",        311,  "cisco/cisco — Cisco IP Phone SSH"),

    # --- Snom ---
    ("admin",        "",             312,  "admin / no password — Snom Web (no authentication by default)"),

    # --- Fanvil ---
    ("admin",        "admin",        313,  "admin/admin — Fanvil X/H series Web"),

    # --- Polycom / Poly ---
    ("admin",        "456",          314,  "admin/456 — Polycom VVX default"),
    ("user",         "123",          315,  "user/123 — Polycom VVX user"),
    ("admin",        "admin",        316,  "admin/admin — Poly Edge B/E series"),
    ("PlcmSpIp",     "PlcmSpIp",     317,  "PlcmSpIp/PlcmSpIp — Polycom SSH service account"),

    # --- Avaya IP Deskphone ---
    ("admin",        "27238",        318,  "admin/27238 — Avaya 9600 series default PIN"),
    ("craft",        "crftpw",       319,  "craft/crftpw — Avaya service account"),

    # --- Aastra / Mitel Deskphone ---
    ("admin",        "22222",        320,  "admin/22222 — Aastra 6700 series"),

    # ═══════════════════════════════════════════════════════════════════════════
    # SMART SPEAKERS / VOICE ASSISTANTS
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Amazon Echo / Alexa (SSH via exploit / developer mode) ---
    ("root",         "",             325,  "root / no password — Amazon Echo SSH (developer mode)"),
    ("root",         "toor",         326,  "root/toor — Amazon Echo some firmware"),

    # --- Sonos ---
    ("admin",        "admin",        327,  "admin/admin — Sonos Web Interface"),
    ("root",         "",             328,  "root / no password — Sonos SSH embedded Linux"),

    # --- Bose SoundTouch ---
    ("admin",        "admin",        329,  "admin/admin — Bose SoundTouch panel"),

    # --- Denon HEOS ---
    ("admin",        "admin",        330,  "admin/admin — Denon/Marantz HEOS"),

    # --- Google Home / Nest Hub (SSH via exploit) ---
    ("root",         "",             331,  "root / no password — Google Home SSH (rare exploit)"),

    # ═══════════════════════════════════════════════════════════════════════════
    # UPS — extended
    # ═══════════════════════════════════════════════════════════════════════════

    # --- APC / Schneider (NMC network card) ---
    ("apc",          "apc",          335,  "apc/apc — APC Network Management Card SSH"),
    ("device",       "apc",          336,  "device/apc — APC NMC read-only SSH"),

    # --- Eaton (Gigabit Network Card) ---
    ("admin",        "admin",        337,  "admin/admin — Eaton Gigabit Network Card SSH"),
    ("admin",        "",             338,  "admin / no password — Eaton NetAgent"),

    # --- Vertiv / Liebert / Emerson ---
    ("admin",        "admin",        339,  "admin/admin — Vertiv Liebert GXT / SXLI SSH"),
    ("localadmin",   "localadmin",   340,  "localadmin/localadmin — Riello / Power Shield"),

    # --- Riello UPS ---
    ("admin",        "admin",        341,  "admin/admin — Riello NetMan 204"),

    # ═══════════════════════════════════════════════════════════════════════════
    # ADDITIONAL POPULAR IoT / SMART HOME
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Tapo (TP-Link) ---
    ("admin",        "admin",        345,  "admin/admin — TP-Link Tapo SSH/Web"),
    ("admin",        "tp-link",      346,  "admin/tp-link — TP-Link Tapo alternative"),

    # --- Eufy (Anker) ---
    ("admin",        "admin",        347,  "admin/admin — Eufy camera / Smart Home SSH"),

    # --- Wyze ---
    ("admin",        "admin",        348,  "admin/admin — Wyze camera SSH"),

    # --- Arlo ---
    ("admin",        "admin",        349,  "admin/admin — Arlo camera embedded"),

    # --- Hik-Connect / Ezviz (Hikvision cloud cameras) ---
    ("admin",        "admin123",     350,  "admin/admin123 — Ezviz / Hik-Connect camera"),

    # --- Ajax Systems (popular in PL — alarms) ---
    ("admin",        "admin",        351,  "admin/admin — Ajax Hub embedded panel"),

    # --- DSC / Tyco / Bosch (alarm panels) ---
    ("admin",        "1234",         352,  "admin/1234 — DSC PowerSeries Neo"),
    ("installer",    "1234",         353,  "installer/1234 — Tyco / DSC installer"),
    ("admin",        "admin",        354,  "admin/admin — Bosch Solution alarm panel"),

    # --- Paradox (popular in Poland alarm panels) ---
    ("installer",    "0000",         355,  "installer/0000 — Paradox MG/SP panel"),

    # --- Intelbras (popular in LAC / some PL) ---
    ("admin",        "intelbras",    356,  "admin/intelbras — Intelbras DVR/camera"),
    ("admin",        "admin",        357,  "admin/admin — Intelbras generic"),

    # --- Tuya / Smartlife OEM embedded ---
    ("root",         "tuyaroot",     358,  "root/tuyaroot — Tuya BK7231 chipset SSH"),
    ("root",         "",             359,  "root / no password — Tuya ESP8266/ESP32 SSH (dev mode)"),

    # --- Xiaomi Smart Home (additional) ---
    ("root",         "rockrobo",     360,  "root/rockrobo — Xiaomi Roborock / Mi Robot"),
    ("admin",        "xiaomi1234",   361,  "admin/xiaomi1234 — Xiaomi router alternative"),

    # --- Fibaro (Z-Wave, popular in Poland) ---
    ("admin",        "admin",        362,  "admin/admin — Fibaro HC2/HC3 SSH"),
    ("admin",        "fibaro",       363,  "admin/fibaro — Fibaro alternative"),

    # --- Homey (Athom) ---
    ("admin",        "admin",        364,  "admin/admin — Homey Pro SSH (developer)"),

    # --- Home Assistant OS (when SSH addon) ---
    ("root",         "",             365,  "root / no password — Home Assistant OS SSH addon (no password set)"),

    # ═══════════════════════════════════════════════════════════════════════════
    # PRINTERS / MFP — detailed SSH/FTP credentials
    # ═══════════════════════════════════════════════════════════════════════════

    # --- HP LaserJet / OfficeJet / PageWide ---
    ("admin",        "admin",        370,  "admin/admin — HP LaserJet EWS SSH (some models)"),
    ("admin",        "",             371,  "admin / no password — HP JetDirect embedded"),
    ("admin",        "hp",           372,  "admin/hp — HP LaserJet older firmware"),
    ("JetDirect",    "",             373,  "JetDirect / no password — HP JetDirect FTP (anonymous-like)"),
    ("anonymous",    "",             374,  "anonymous / no password — HP FTP scan to folder"),

    # --- Kyocera Ecosys / TASKalfa ---
    ("Admin",        "Admin00",      375,  "Admin/Admin00 — Kyocera TASKalfa default (uppercase A)"),
    ("admin",        "admin",        376,  "admin/admin — Kyocera Ecosys alternative"),
    ("anonymous",    "",             377,  "anonymous / no password — Kyocera FTP scan"),

    # --- Ricoh / Nashuatec / Lanier / Savin ---
    ("supervisor",   "supervisor",   378,  "supervisor/supervisor — Ricoh Aficio default"),
    ("admin",        "",             379,  "admin / no password — Ricoh MFP Web/SSH"),
    ("admin",        "password",     380,  "admin/password — Ricoh newer firmware"),
    ("anonymous",    "",             381,  "anonymous / no password — Ricoh FTP scan to folder"),

    # --- Canon imageRUNNER / LBP ---
    ("admin",        "7654321",      382,  "admin/7654321 — Canon iR default administrator PIN"),
    ("7654321",      "",             383,  "7654321 / no password — Canon iR PIN as login"),
    ("anonymous",    "",             384,  "anonymous / no password — Canon FTP scan"),
    ("admin",        "canon",        385,  "admin/canon — Canon LBP Web admin"),

    # --- Konica Minolta / Develop / Olivetti ---
    ("administrator","",             386,  "administrator / no password — Konica Minolta PageScope default"),
    ("Administrator","",             387,  "Administrator / no password — KM uppercase"),
    ("admin",        "1234567890",   388,  "admin/1234567890 — Konica Minolta newer firmware"),
    ("admin",        "12345678",     389,  "admin/12345678 — Konica Minolta alternative"),
    ("anonymous",    "",             390,  "anonymous / no password — Konica Minolta FTP scan"),

    # --- Xerox WorkCentre / AltaLink / VersaLink ---
    ("admin",        "1111",         391,  "admin/1111 — Xerox WorkCentre/VersaLink default"),
    ("admin",        "admin",        392,  "admin/admin — Xerox AltaLink alternative"),
    ("anonymous",    "",             393,  "anonymous / no password — Xerox FTP scan to folder"),
    ("11111",        "",             394,  "11111 / no password — Xerox old PIN"),

    # --- Lexmark ---
    ("admin",        "",             395,  "admin / no password — Lexmark no authentication (open by default!)"),
    ("admin",        "1234",         396,  "admin/1234 — Lexmark alternative"),
    ("anonymous",    "",             397,  "anonymous / no password — Lexmark FTP scan"),

    # --- Brother ---
    ("admin",        "access",       398,  "admin/access — Brother MFC Web/FTP default"),
    ("anonymous",    "",             399,  "anonymous / no password — Brother FTP scan to folder"),
    ("root",         "",             400,  "root / no password — Brother embedded Linux SSH"),

    # --- OKI MC/C series ---
    ("admin",        "aaaaaa",       401,  "admin/aaaaaa — OKI MC/C series default (specific!)"),
    ("admin",        "admin",        402,  "admin/admin — OKI alternative"),

    # --- Epson ET / WorkForce Pro ---
    ("admin",        "epsonaq",      403,  "admin/epsonaq — Epson WorkForce Pro Web default"),
    ("admin",        "admin",        404,  "admin/admin — Epson ET Network alternative"),
    ("epson",        "epson",        405,  "epson/epson — Epson EpsonNet account"),
    ("anonymous",    "",             406,  "anonymous / no password — Epson FTP scan"),

    # --- Sharp ---
    ("admin",        "admin",        407,  "admin/admin — Sharp MFP default"),
    ("admin",        "Sharp",        408,  "admin/Sharp — Sharp alternative"),
    ("anonymous",    "",             409,  "anonymous / no password — Sharp FTP scan"),

    # --- Samsung Printing / Xpress (HP acquired the line) ---
    ("admin",        "sec00000",     410,  "admin/sec00000 — Samsung Xpress default"),
    ("admin",        "admin",        411,  "admin/admin — Samsung Printing alternative"),

    # --- Toshiba e-Studio ---
    ("admin",        "",             412,  "admin / no password — Toshiba e-Studio default"),
    ("admin",        "123456",       413,  "admin/123456 — Toshiba e-Studio newer"),
    ("anonymous",    "",             414,  "anonymous / no password — Toshiba FTP scan"),

    # --- Fujifilm Business Innovation / Fuji Xerox ---
    ("admin",        "1111",         415,  "admin/1111 — Fujifilm / Fuji Xerox DocuCentre default"),
    ("admin",        "admin",        416,  "admin/admin — Fuji Xerox ApeosPort alternative"),
    ("anonymous",    "",             417,  "anonymous / no password — Fuji Xerox FTP scan"),

    # --- Pantum (growing market, cheap laser) ---
    ("admin",        "",             418,  "admin / no password — Pantum Web default"),
    ("admin",        "admin",        419,  "admin/admin — Pantum alternative"),

    # ═══════════════════════════════════════════════════════════════════════════
    # VIDEO CONFERENCING (Cisco/Poly/Lifesize/Huawei/Yealink VC)
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Cisco Webex Room / TelePresence (formerly Tandberg) ---
    ("admin",        "TANDBERG",     422,  "admin/TANDBERG — Cisco Webex Room / Tandberg C/SX/MX default"),
    ("admin",        "admin",        423,  "admin/admin — Cisco Webex Board/Desk/Room alternative"),
    ("root",         "TANDBERG",     424,  "root/TANDBERG — Tandberg SSH service account"),
    ("cisco",        "cisco",        425,  "cisco/cisco — Cisco TelePresence Server SSH"),

    # --- Polycom RealPresence (Group, HDX) ---
    ("admin",        "456",          426,  "admin/456 — Polycom Group Series / HDX default"),
    ("admin",        "",             427,  "admin / no password — Polycom RealPresence Trio"),
    ("polycom",      "polycom",      428,  "polycom/polycom — Polycom service account"),

    # --- Lifesize Icon ---
    ("admin",        "1234",         429,  "admin/1234 — Lifesize Icon 300/400/500 default"),
    ("admin",        "admin",        430,  "admin/admin — Lifesize Icon alternative"),

    # --- Yealink MVC / VC (conference rooms) ---
    ("admin",        "admin",        431,  "admin/admin — Yealink VC120/VC200/MVC default"),

    # --- Huawei TE (enterprise video conferencing) ---
    ("admin",        "Change_Me",    432,  "admin/Change_Me — Huawei TE30/40/60 default"),
    ("admin",        "Admin1234",    433,  "admin/Admin1234 — Huawei TE newer firmware"),

    # --- Avaya Scopia / Radvision ---
    ("admin",        "admin",        434,  "admin/admin — Avaya Scopia Desktop / Radvision"),

    # --- Sony Bravia (conference room) ---
    ("admin",        "admin",        435,  "admin/admin — Sony SRG/BRC PTZ camera"),

    # ═══════════════════════════════════════════════════════════════════════════
    # KVM / CONSOLE SERVERS (data center remote access)
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Raritan Dominion KX / SX ---
    ("admin",        "raritan",      438,  "admin/raritan — Raritan Dominion KX/SX SSH default"),
    ("admin",        "admin",        439,  "admin/admin — Raritan KX alternative"),

    # --- Avocent DSR / ACS (Vertiv) ---
    ("admin",        "avocent",      440,  "admin/avocent — Avocent DSR KVM default"),
    ("admin",        "cyclades",     441,  "admin/cyclades — Avocent ACS (formerly Cyclades) SSH"),
    ("root",         "cyclades",     442,  "root/cyclades — Cyclades AlterPath SSH"),

    # --- Opengear IM / CM / ACM ---
    ("root",         "default",      443,  "root/default — Opengear CM/IM console server default"),
    ("admin",        "admin",        444,  "admin/admin — Opengear newer models"),

    # --- Lantronix EDS / SCS / UDS ---
    ("root",         "admin",        445,  "root/admin — Lantronix EDS/SCS default"),
    ("manager",      "manager",      446,  "manager/manager — Lantronix UDS SSH"),

    # --- Digi International (Connect ME, CM) ---
    ("root",         "dbps",         447,  "root/dbps — Digi ConnectPort / CM SSH default"),
    ("admin",        "admin",        448,  "admin/admin — Digi Connect IT alternative"),

    # --- Black Box (Remote Access Servers) ---
    ("admin",        "admin",        449,  "admin/admin — Black Box ServSwitch / LB Series"),

    # ═══════════════════════════════════════════════════════════════════════════
    # PDU — intelligent power strips (Rack PDU)
    # ═══════════════════════════════════════════════════════════════════════════

    # --- APC Switched / Metered PDU (Rack PDU) ---
    ("apc",          "apc",          452,  "apc/apc — APC Rack PDU / Switched PDU SSH default"),
    ("device",       "apc",          453,  "device/apc — APC PDU device account"),
    ("readonly",     "apc",          454,  "readonly/apc — APC PDU readonly"),

    # --- Raritan PX / PX3 ---
    ("admin",        "raritan",      455,  "admin/raritan — Raritan PX Rack PDU default"),
    ("admin",        "admin",        456,  "admin/admin — Raritan PX alternative"),

    # --- Server Technology Switched CDU (POPS) ---
    ("sysuser",      "sysuser",      457,  "sysuser/sysuser — Server Technology POPS CDU default"),
    ("admn",         "admn",         458,  "admn/admn — Server Technology older firmware"),

    # --- Eaton ePDU / Managed PDU ---
    ("admin",        "admin",        459,  "admin/admin — Eaton ePDU managed default"),

    # --- Vertiv / Geist Rack PDU ---
    ("admin",        "admin",        460,  "admin/admin — Geist / Vertiv PDU default"),

    # --- Panduit SmartZone ---
    ("admin",        "admin",        461,  "admin/admin — Panduit SmartZone PDU"),

    # ═══════════════════════════════════════════════════════════════════════════
    # LOAD BALANCERS / ADC
    # ═══════════════════════════════════════════════════════════════════════════

    # --- F5 BIG-IP ---
    ("admin",        "admin",        464,  "admin/admin — F5 BIG-IP SSH default (change required!)"),
    ("root",         "default",      465,  "root/default — F5 BIG-IP root SSH"),

    # --- Citrix ADC / NetScaler ---
    ("nsroot",       "nsroot",       466,  "nsroot/nsroot — Citrix NetScaler / ADC SSH default"),
    ("admin",        "admin",        467,  "admin/admin — NetScaler Web NSIP"),

    # --- Kemp LoadMaster ---
    ("bal",          "1fourall",     468,  "bal/1fourall — Kemp LoadMaster SSH default"),
    ("admin",        "admin",        469,  "admin/admin — Kemp WebUI default"),

    # --- A10 Networks Thunder ---
    ("admin",        "a10",          470,  "admin/a10 — A10 Networks Thunder default"),
    ("admin",        "admin",        471,  "admin/admin — A10 alternative"),

    # --- Radware Alteon ---
    ("admin",        "admin",        472,  "admin/admin — Radware Alteon SSH default"),
    ("admin",        "radware",      473,  "admin/radware — Radware alternative"),

    # --- HAProxy (embedded linux) ---
    ("root",         "",             474,  "root / no password — HAProxy embedded Linux (OpenWrt/Vyos)"),

    # ═══════════════════════════════════════════════════════════════════════════
    # SAN / STORAGE SWITCH / ENTERPRISE NAS
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Brocade FC Switch (Broadcom) ---
    ("admin",        "password",     477,  "admin/password — Brocade Fibre Channel switch SSH default"),
    ("root",         "fibranne",     478,  "root/fibranne — Brocade FC older SSH service account"),
    ("admin",        "admin",        479,  "admin/admin — Brocade Fabric OS alternative"),

    # --- Cisco MDS 9000 (SAN switch) ---
    ("admin",        "admin",        480,  "admin/admin — Cisco MDS 9000 SAN SSH default"),

    # --- HP StorageWorks (MSA / EVA / Primera) ---
    ("admin",        "admin",        481,  "admin/admin — HP MSA / HPE Primera SSH"),
    ("monitor",      "monitor",      482,  "monitor/monitor — HP StorageWorks read-only"),

    # --- NetApp ONTAP ---
    ("admin",        "netapp1!",     483,  "admin/netapp1! — NetApp ONTAP default (new)"),
    ("admin",        "admin",        484,  "admin/admin — NetApp ONTAP alternative"),
    ("root",         "netapp",       485,  "root/netapp — NetApp ONTAP root SSH"),

    # --- EMC VNX / Unity / PowerStore ---
    ("admin",        "Password123#", 486,  "admin/Password123# — Dell EMC Unity / PowerStore"),
    ("sysadmin",     "sysadmin",     487,  "sysadmin/sysadmin — Dell EMC VNX service account"),

    # --- Pure Storage FlashArray ---
    ("pureuser",     "pureuser",     488,  "pureuser/pureuser — Pure Storage FlashArray SSH default"),

    # --- Quantum Tape Library ---
    ("admin",        "password",     489,  "admin/password — Quantum Scalar tape library"),

    # ═══════════════════════════════════════════════════════════════════════════
    # ENVIRONMENTAL MONITORING / DC INFRASTRUCTURE
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

# Telnet uses the same pairs as SSH — seeded separately with method=telnet
_DEFAULT_TELNET_CREDENTIALS = _DEFAULT_SSH_CREDENTIALS

# ── Default Web / HTTP(S) API credentials ────────────────────────────────────
# Used for login attempts to management panels (port 80/443/8080/8443).
_DEFAULT_API_CREDENTIALS = [
    # (username, password, priority, notes)

    # --- Most popular ---
    ("admin",         "",             10,  "admin / no password — Fortinet, MikroTik, cheap APs"),
    ("admin",         "admin",        15,  "admin/admin — D-Link, Asus, TP-Link, NetGear"),
    ("admin",         "password",     20,  "admin/password — generic HTTP panel"),
    ("admin",         "1234",         22,  "admin/1234 — TP-Link DSL/router"),
    ("admin",         "12345",        24,  "admin/12345 — cheap Chinese devices"),
    ("admin",         "123456",       26,  "admin/123456 — very popular IoT"),

    # --- root ---
    ("root",          "",             30,  "root / no password — OpenWrt, embedded Linux"),
    ("root",          "admin",        32,  "root/admin"),
    ("root",          "root",         34,  "root/root"),

    # --- Cisco ---
    ("cisco",         "cisco",        40,  "cisco/cisco — Cisco SG-300/500, IOS Web UI"),
    ("cisco",         "",             41,  "cisco / no password — Cisco SG-xxx factory reset (firmware <1.3)"),
    ("admin",         "cisco",        42,  "admin/cisco — Cisco WAP / ISE"),
    ("admin",         "",             43,  "admin / no password — Cisco SG-200/300 older firmware"),

    # --- Ubiquiti ---
    ("ubnt",          "ubnt",         50,  "ubnt/ubnt — AirOS"),
    ("admin",         "ubnt",         52,  "admin/ubnt"),

    # --- Huawei ---
    ("admin",         "Admin@huawei", 60,  "admin/Admin@huawei — Huawei Web Manager"),
    ("admin",         "huawei@123",   62,  "admin/huawei@123"),

    # --- ZTE ---
    ("admin",         "zte_admin",    70,  "admin/zte_admin — ZTE Web Panel"),
    ("admin",         "Admin1234!",   72,  "admin/Admin1234!"),
    ("user",          "user",         74,  "user/user — ZTE user panel"),

    # --- HP ProCurve / Aruba ---
    ("manager",       "manager",      85,  "manager/manager — HP ProCurve Web"),
    ("admin",         "HP@1234",      87,  "admin/HP@1234 — HPE Aruba Web"),

    # --- QNAP / Synology NAS ---
    ("admin",         "admin",        90,  "admin/admin — QNAP QTS"),

    # --- CCTV / NVR / DVR ---
    ("admin",         "12345",        95,  "admin/12345 — Dahua Web"),
    ("admin",         "Admin12345",   99,  "admin/Admin12345 — Hikvision newer"),

    # --- IPMI / iDRAC / iLO Web ---
    ("root",          "calvin",      105,  "root/calvin — Dell iDRAC Web"),
    ("Administrator", "",            107,  "Administrator / no password — HPE iLO Web"),
    ("ADMIN",         "ADMIN",       109,  "ADMIN/ADMIN — Supermicro IPMI Web"),

    # --- General ---
    ("user",          "user",        120,  "user/user — generic account"),
    ("guest",         "guest",       122,  "guest/guest — guest account"),
    ("test",          "test",        124,  "test/test — test accounts"),
    ("support",       "support",     126,  "support/support"),

    # ═══════════════════════════════════════════════════════════════════════════
    # IP CAMERAS / DVR/NVR RECORDERS
    # ═══════════════════════════════════════════════════════════════════════════

    # --- Hikvision ---
    ("admin",        "12345",       130,  "admin/12345 — Hikvision older"),
    ("admin",        "Admin12345",  131,  "admin/Admin12345 — Hikvision newer"),
    ("888888",       "888888",      132,  "888888/888888 — Hikvision legacy"),
    ("666666",       "666666",      133,  "666666/666666 — Hikvision operator legacy"),

    # --- Dahua ---
    ("admin",        "admin",       134,  "admin/admin — Dahua Web older"),
    ("admin",        "",            135,  "admin / no password — Dahua Web newer"),
    ("888888",       "888888",      136,  "888888/888888 — Dahua admin legacy"),

    # --- Axis ---
    ("root",         "pass",        137,  "root/pass — Axis Web (old firmware)"),
    ("admin",        "admin",       138,  "admin/admin — Axis Web alternative"),

    # --- Foscam / Reolink / Amcrest ---
    ("admin",        "",            139,  "admin / no password — Foscam / Reolink initial"),
    ("admin",        "amcrest2021", 140,  "admin/amcrest2021 — Amcrest Web"),

    # --- Mobotix ---
    ("admin",        "meinsm",      141,  "admin/meinsm — Mobotix Web Panel"),

    # --- Hanwha / Samsung Techwin ---
    ("admin",        "4321",        142,  "admin/4321 — Hanwha Web"),

    # --- Uniview / TVT / Jovision ---
    ("admin",        "123456",      143,  "admin/123456 — Uniview Web"),
    ("admin",        "1111",        144,  "admin/1111 — TVT DVR Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # WIFI ACCESS POINTS / ROUTERS
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
    ("admin",        "",            160,  "admin / no password — Shelly Web Gen1 (no auth by default)"),
    ("admin",        "admin",       161,  "admin/admin — Shelly Gen2+ Web API"),

    # --- Xiaomi MiWiFi ---
    ("admin",        "admin",       162,  "admin/admin — Xiaomi MiWiFi Web"),

    # --- Smart TV ---
    ("admin",        "admin",       163,  "admin/admin — Samsung Smart TV diagnostic"),
    ("admin",        "1234",        164,  "admin/1234 — LG webOS panel"),

    # --- Lighting control ---
    ("admin",        "admin",       165,  "admin/admin — DALI gateway / KNX IP router"),
    ("admin",        "lutron",      166,  "admin/lutron — Lutron Web"),
    ("admin",        "1234",        167,  "admin/1234 — KNX IP gateway Web"),

    # --- HVAC / air conditioning ---
    ("admin",        "admin",       168,  "admin/admin — Daikin/Mitsubishi/Fujitsu HVAC gateway"),

    # --- BMS / BAS ---
    ("admin",        "admin",       169,  "admin/admin — Johnson Controls / Honeywell / Siemens BMS Web"),
    ("admin",        "1234",        170,  "admin/1234 — Honeywell WEBs"),

    # --- Access controllers / intercoms ---
    ("admin",        "admin",       172,  "admin/admin — ZKTeco / Hikvision intercom Web"),
    ("admin",        "1234",        173,  "admin/1234 — Dahua VTO intercom Web"),
    ("admin",        "2n",          174,  "admin/2n — 2N Helios Web newer"),

    # --- VoIP ---
    ("admin",        "admin",       175,  "admin/admin — Yealink / Grandstream Web"),
    ("admin",        "1234",        176,  "admin/1234 — Grandstream GXP Web"),

    # --- Network printers (Web) ---
    ("admin",        "admin",       180,  "admin/admin — HP LaserJet Embedded Web Server"),
    ("admin",        "",            181,  "admin / no password — Kyocera / Ricoh Command Center"),
    ("admin",        "1234",        182,  "admin/1234 — Canon / Epson Web"),

    # --- UPS (Web) ---
    ("apc",          "apc",         185,  "apc/apc — APC Network Management Card Web"),
    ("admin",        "admin",       186,  "admin/admin — Eaton / Vertiv UPS Web"),

    # --- Additional NAS ---
    ("admin",        "",            190,  "admin / no password — WD MyCloud Web initial"),
    ("admin",        "infrant1",    191,  "admin/infrant1 — Netgear ReadyNAS (legacy Infrant)"),
    ("admin",        "password",    192,  "admin/password — Netgear ReadyNAS newer"),

    # ═══════════════════════════════════════════════════════════════════════════
    # PBX / UC PHONE SYSTEMS
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       195,  "admin/admin — FreePBX / 3CX Web Admin"),
    ("admin",        "jEkiN3dW",    196,  "admin/jEkiN3dW — FreePBX 2.x installer Web"),
    ("admin",        "cisco",       197,  "admin/cisco — Cisco CUCM Web"),
    ("Administrator","Administrator",198, "Administrator/Administrator — Avaya IP Office Web"),
    ("admin",        "admin",       199,  "admin/admin — Grandstream UCM Web"),
    ("admin",        "1234",        200,  "admin/1234 — Panasonic KX-NS Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # IP PHONES (Web panels)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       202,  "admin/admin — Yealink / Fanvil / Grandstream Web"),
    ("admin",        "456",         203,  "admin/456 — Polycom VVX Web"),
    ("PlcmSpIp",     "PlcmSpIp",    204,  "PlcmSpIp/PlcmSpIp — Polycom service account Web"),
    ("admin",        "27238",       205,  "admin/27238 — Avaya 9600 Web"),
    ("admin",        "22222",       206,  "admin/22222 — Aastra 6700 Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # SMART SPEAKERS / SMART HOME
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       210,  "admin/admin — Sonos / Denon HEOS Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # ALARM PANELS (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "1234",        215,  "admin/1234 — DSC PowerSeries Neo Web"),
    ("installer",    "1234",        216,  "installer/1234 — Tyco / DSC installer Web"),
    ("admin",        "admin",       217,  "admin/admin — Bosch Solution / Ajax Hub Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # ADDITIONAL IoT
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       220,  "admin/admin — Fibaro HC2/HC3 Web"),
    ("admin",        "fibaro",      221,  "admin/fibaro — Fibaro Web alternative"),
    ("admin",        "admin",       222,  "admin/admin — Tapo / Wyze / Eufy Web"),
    ("admin",        "admin123",    223,  "admin/admin123 — Ezviz / Hik-Connect Web"),
    ("admin",        "intelbras",   224,  "admin/intelbras — Intelbras Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # PRINTERS / MFP — Web panels detailed
    # ═══════════════════════════════════════════════════════════════════════════

    # --- HP LaserJet Embedded Web Server (EWS) ---
    ("admin",        "",            226,  "admin / no password — HP LaserJet EWS (often open!)"),
    ("admin",        "hp",          227,  "admin/hp — HP LaserJet EWS older"),
    ("JetDirect",    "",            228,  "JetDirect / no password — HP JetDirect Web"),

    # --- Kyocera Command Center RX ---
    ("Admin",        "Admin00",     229,  "Admin/Admin00 — Kyocera Command Center default"),
    ("admin",        "admin",       230,  "admin/admin — Kyocera alternative"),

    # --- Ricoh SmartDeviceMonitor / EWS ---
    ("supervisor",   "supervisor",  231,  "supervisor/supervisor — Ricoh Aficio/MP Web"),
    ("admin",        "",            232,  "admin / no password — Ricoh MFP Web initial"),

    # --- Canon Remote UI / iW Management ---
    ("admin",        "7654321",     233,  "admin/7654321 — Canon imageRUNNER Web Admin PIN"),
    ("7654321",      "",            234,  "7654321 / no password — Canon iR alternative"),
    ("admin",        "canon",       235,  "admin/canon — Canon LBP Web"),

    # --- Konica Minolta PageScope Web Connection ---
    ("administrator","",            236,  "administrator / no password — Konica Minolta PageScope (open by default!)"),
    ("Administrator","",            237,  "Administrator / no password — KM uppercase"),
    ("admin",        "1234567890",  238,  "admin/1234567890 — KM newer firmware"),

    # --- Xerox CentreWare / EIP ---
    ("admin",        "1111",        239,  "admin/1111 — Xerox WorkCentre / VersaLink Web default"),
    ("",             "",            240,  "no/no — Xerox old open Web (no authentication!)"),
    ("11111",        "",            241,  "11111 / no password — Xerox PIN login"),

    # --- Lexmark Embedded Web Server ---
    ("",             "",            242,  "no/no — Lexmark EWS (no authentication by default!)"),
    ("admin",        "1234",        243,  "admin/1234 — Lexmark with authentication enabled"),

    # --- Brother Web Based Management ---
    ("",             "",            244,  "no/no — Brother Web (no authentication by default!)"),
    ("admin",        "access",      245,  "admin/access — Brother Web with password"),
    ("admin",        "initpass",    246,  "admin/initpass — Brother newer firmware"),

    # --- OKI Web Management ---
    ("admin",        "aaaaaa",      247,  "admin/aaaaaa — OKI MC/C Web default"),

    # --- Epson Web Config ---
    ("admin",        "epsonaq",     248,  "admin/epsonaq — Epson WorkForce Pro Web"),
    ("",             "",            249,  "no/no — Epson older Web without authentication"),

    # --- Sharp OSA / Web UI ---
    ("admin",        "admin",       250,  "admin/admin — Sharp MFP Web default"),
    ("admin",        "Sharp",       251,  "admin/Sharp — Sharp Web alternative"),

    # --- Samsung / HP Xpress ---
    ("admin",        "sec00000",    252,  "admin/sec00000 — Samsung Xpress Web default"),

    # --- Toshiba e-Bridge ---
    ("admin",        "",            253,  "admin / no password — Toshiba e-Studio Web default"),
    ("admin",        "123456",      254,  "admin/123456 — Toshiba newer firmware"),

    # --- Fujifilm / Fuji Xerox ---
    ("admin",        "1111",        255,  "admin/1111 — Fujifilm ApeosPort / Fuji Xerox Web"),

    # --- Pantum ---
    ("admin",        "",            256,  "admin / no password — Pantum Web default"),

    # ═══════════════════════════════════════════════════════════════════════════
    # VIDEO CONFERENCING — Web panels
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

    ("apc",          "apc",         268,  "apc/apc — APC Rack PDU Web default"),
    ("admin",        "raritan",     269,  "admin/raritan — Raritan PX Web"),
    ("sysuser",      "sysuser",     270,  "sysuser/sysuser — Server Technology CDU Web"),
    ("admin",        "admin",       271,  "admin/admin — Eaton / Geist / Panduit PDU Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # LOAD BALANCERS — Web
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
    # DC MONITORING — Web
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       284,  "admin/admin — AKCP / Geist / RF Code / NetBotz Web"),
    ("apc",          "apc",         285,  "apc/apc — APC NetBotz / EcoStruxure IT Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # NAS — missing (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       287,  "admin/admin — TrueNAS SCALE / Terramaster / Asustor Web"),
    ("root",         "",            288,  "root / no password — TrueNAS CORE Web initial"),

    # ═══════════════════════════════════════════════════════════════════════════
    # BMC SERVERS — missing (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       290,  "admin/admin — Fujitsu iRMC Web default"),
    ("USERID",       "PASSW0RD",    291,  "USERID/PASSW0RD — Lenovo IMM2/XCC Web default (zero=O!)"),
    ("admin",        "password",    292,  "admin/password — Cisco CIMC / UCS Web default"),

    # ═══════════════════════════════════════════════════════════════════════════
    # SWITCHES — missing (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("root",         "",            294,  "root / no password — Juniper EX Web default"),
    ("admin",        "",            295,  "admin / no password — Arista EOS Web (open!)"),
    ("admin",        "password",    296,  "admin/password — Netgear ProSafe Web"),
    ("admin",        "switch",      297,  "admin/switch — ALE OmniSwitch Web"),
    ("admin",        "moxa",        298,  "admin/moxa — Moxa industrial Web"),
    ("admin",        "private",     299,  "admin/private — Hirschmann industrial Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # FIREWALLS — missing (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       301,  "admin/admin — Palo Alto PAN-OS Web UI default"),
    ("admin",        "admin",       302,  "admin/admin — Check Point Gaia WebUI"),
    ("admin",        "pfsense",     303,  "admin/pfsense — pfSense WebGUI default"),
    ("root",         "opnsense",    304,  "root/opnsense — OPNsense WebGUI default"),
    ("admin",        "admin",       305,  "admin/admin — Sophos XG / Stormshield / Barracuda Web"),
    ("admin",        "readwrite",   306,  "admin/readwrite — WatchGuard WebUI"),

    # ═══════════════════════════════════════════════════════════════════════════
    # ROUTERS / AP — missing (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       308,  "admin/admin — ASUS RT-AC/AX Web Panel"),
    ("admin",        "admin",       309,  "admin/admin — D-Link Web default"),
    ("admin",        "",            310,  "admin / no password — D-Link older Web"),
    ("admin",        "",            311,  "admin / no password — Belkin / Draytek Web default"),
    ("admin",        "1234",        312,  "admin/1234 — Zyxel AP / Draytek Web"),
    ("admin",        "admin",       313,  "admin/admin — TP-Link Omada / Sophos AP / Meraki Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # TELECOM — missing (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("Admin",        "Admin",       315,  "Admin/Admin — AudioCodes Mediant Web (uppercase A!)"),
    ("administrator","",            316,  "administrator / no password — Patton SmartNode Web"),
    ("isadmin",      "isadmin",     317,  "isadmin/isadmin — Nokia ISAM DSLAM Web"),
    ("admin",        "1234",        318,  "admin/1234 — ZyXEL IES DSLAM Web"),

    # ═══════════════════════════════════════════════════════════════════════════
    # DSL MODEMS / GPON ONT — missing (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "",            320,  "admin / no password — AVM Fritz!Box Web default"),
    ("admin",        "admin",       321,  "admin/admin — Technicolor / Sagemcom / Comtrend Web"),
    ("Administrator","",            322,  "Administrator / no password — Technicolor / Speedtouch Web"),
    ("user",         "user",        323,  "user/user — Technicolor / Sagemcom user account"),
    ("telecomadmin", "admintelecom",324,  "telecomadmin/admintelecom — Huawei ONT hidden ISP account"),
    ("root",         "ztetC3.0ZDe", 325,  "root/ztetC3.0ZDe — ZTE ZXHN ONT hidden ISP account (CVE!)"),

    # ═══════════════════════════════════════════════════════════════════════════
    # MEDIA PLAYERS — missing (Web)
    # ═══════════════════════════════════════════════════════════════════════════

    ("admin",        "admin",       327,  "admin/admin — Philips Android TV service Web"),
]



def seed_snmp_communities(db):
    """Upsert default SNMP community strings — adds missing ones, does not overwrite existing."""
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
        logger.info("SNMP seed: added %d new community strings (total: %d)", added, len(existing_names))
    else:
        logger.info("SNMP seed: no new community strings to add (%d already in DB)", len(existing_names))



_LAB_DEVICES = [
    # (ip, hostname, device_type, vendor, os_version, location)
    ("172.28.0.10", "S7-1200-PLC",    "iot",     "Siemens",            "SIMATIC S7-1200 PLC v4.5",           "Lab / Production Hall A / Control Cabinet 1"),
    ("172.28.0.11", "Modicon-M340",   "iot",     "Schneider Electric", "Modicon M340 PLC",                   "Lab / Main Distribution Panel / Energy Meter"),
    ("172.28.0.12", "ABB-AC500-Tank", "iot",     "ABB",               "AC500 PLC v3.0 Tank Control",         "Lab / Fuel Tank / Section B"),
    ("172.28.0.20", "MikroTik-RB750", "router",  "MikroTik",          "RouterOS 6.49.10 (stable) RB750Gr3",  "Lab / Server Room A / Rack 2"),
    ("172.28.0.30", "lab-switch",     "switch",  "Cisco",             "IOS 15.2(7)E",                        "Lab / Switch room"),
    ("172.28.0.40", "netdoc-lab-hmi",  "unknown", None,                "SCADA HMI WebServer",                 "Lab / HMI Panel"),
]


def seed_lab_devices(db):
    """Adds simulated lab devices (172.28.0.0/24) if they don't already exist in the database.

    Called on every scanner startup — ON CONFLICT DO NOTHING, so safe.
    Activates only when the 172.28.0.0/24 network is in NETWORK_RANGES or when lab containers exist.
    """
    import subprocess
    from netdoc.storage.models import Device, DeviceType
    from datetime import datetime as dt

    # Check if lab exists (container netdoc-lab-plc-s7 must be running)
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", "netdoc-lab-plc-s7"],
            capture_output=True, text=True, timeout=5,
        )
        if result.stdout.strip() != "true":
            return  # lab is not running — don't seed
    except Exception:
        return  # no docker or other error

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
        logger.info("Lab seed: added %d lab devices (172.28.0.0/24)", added)
    else:
        logger.debug("Lab seed: no new lab devices to add")


# ── Default RDP credentials ───────────────────────────────────────────────────
# RDP (port 3389) — Windows Remote Desktop Protocol.
# Sources: SecLists/RDP, CIRT.net, CVE defaults, pentester research.
# Many embedded devices (NVR, thin client, OT HMI) have RDP with default passwords.
_DEFAULT_RDP_CREDENTIALS = [
    # (username, password, priority, notes)

    # --- No password / empty ---
    ("Administrator", "",              10,  "Administrator / no password — Windows Server fresh install"),
    ("admin",         "",              12,  "admin / no password — Windows embedded / thin client"),

    # --- Most popular weak Windows passwords ---
    ("Administrator", "administrator", 15,  "Administrator/administrator — classic Windows default"),
    ("Administrator", "Admin",         17,  "Administrator/Admin"),
    ("Administrator", "Admin123",      19,  "Administrator/Admin123 — required password policy"),
    ("Administrator", "Admin@123",     21,  "Administrator/Admin@123"),
    ("Administrator", "Password1",     23,  "Administrator/Password1 — complexity requirement met"),
    ("Administrator", "P@ssw0rd",      25,  "Administrator/P@ssw0rd — classic policy bypass"),
    ("Administrator", "Welcome1",      27,  "Administrator/Welcome1 — popular 'first login'"),
    ("Administrator", "changeme",      29,  "Administrator/changeme — to be changed (but nobody changes it)"),
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
    # Windows Server installations by OEM/manufacturers
    ("Administrator", "Passw0rd!",     70,  "Dell/HP server factory default"),
    ("Administrator", "Dell1234",      71,  "Dell PowerEdge Windows default"),
    ("Administrator", "HP@dmin",       72,  "HP ProLiant Windows default"),
    ("Administrator", "Lenovo1234",    73,  "Lenovo ThinkSystem Windows default"),
    ("Administrator", "ibmpassw0rd",   74,  "IBM System x Windows default"),

    # NVR / DVR with Windows Embedded (Hikvision, Dahua iVMS)
    ("Administrator", "12345",         80,  "Hikvision iVMS-4200 / Windows Embedded NVR"),
    ("Administrator", "Admin12345",    81,  "Hikvision newer Windows NVR"),
    ("admin",         "12345",         82,  "Dahua SmartPSS / Windows NVR"),
    ("admin",         "admin123",      83,  "Generic Windows NVR admin"),

    # VMS (Video Management Software) — Windows
    ("Administrator", "supervisor",    85,  "Milestone XProtect VMS default"),
    ("administrator", "administrator", 86,  "Milestone / Genetec alternative"),
    ("admin",         "admin",         87,  "Genetec Security Center"),
    ("admin",         "123456",        88,  "Exacq Vision / Bosch VideoSDK"),
    ("admin",         "admin256",      89,  "Exacq Vision Windows"),

    # SCADA / HMI (Windows Embedded Standard)
    ("Administrator", "Siemens1234",   92,  "Siemens WinCC / SIMATIC HMI"),
    ("Administrator", "rockwell",      93,  "Rockwell FactoryTalk View SE"),
    ("Administrator", "schneider",     94,  "Schneider EcoStruxure SCADA"),
    ("Administrator", "scada",         95,  "Generic SCADA HMI Windows"),
    ("operator",      "operator",      96,  "OT HMI operator account"),
    ("engineer",      "engineer",      97,  "OT engineer account"),

    # Thin clients (Windows Embedded Compact / IoT)
    ("Administrator", "Wyse",          100, "Dell Wyse thin client Windows Embedded"),
    ("Administrator", "ThinClient",    101, "Generic thin client default"),
    ("user",          "user",          102, "HP t520 / t620 thin client"),
    ("admin",         "admin",         103, "Igel thin client Windows"),

    # Kiosks / Digital Signage
    ("kiosk",         "kiosk",         105, "Windows kiosk mode"),
    ("Administrator", "kiosk1234",     106, "Digital signage Windows kiosk"),

    # Common non-administrator accounts (but with RDP rights)
    ("user",          "user",          110, "user/user — user account"),
    ("user",          "User1234",      111, "user/User1234"),
    ("guest",         "",              112, "guest / no password — Windows Guest"),
    ("guest",         "guest",         113, "guest/guest"),
    ("test",          "test",          114, "test/test — test account"),
    ("test",          "",              115, "test / no password"),
    ("support",       "support",       116, "support/support — support account"),
    ("helpdesk",      "helpdesk",      117, "helpdesk/helpdesk"),
    ("operator",      "",              118, "operator / no password"),
    ("service",       "service",       119, "service/service — service account"),

    # Common devops / automation accounts
    ("vagrant",       "vagrant",       120, "vagrant/vagrant — Vagrant / VirtualBox VM"),
    ("ansible",       "ansible",       121, "ansible/ansible — Ansible managed host"),
    ("deploy",        "deploy",        122, "deploy/deploy — deploy account"),
    ("backup",        "backup",        123, "backup/backup — backup account"),

    # Common weak passwords from Pwned / NIST list
    ("Administrator", "Summer2023",    130, "Seasonal password — Summer2023"),
    ("Administrator", "Spring2024",    131, "Spring2024"),
    ("Administrator", "Winter2024",    132, "Winter2024"),
    ("Administrator", "Autumn2023",    133, "Autumn/Fall seasonal"),
    ("Administrator", "Company123",    134, "Company name + 123"),
    ("Administrator", "Monday1",       135, "Day-based password"),
    ("Administrator", "Polska1",       136, "Polska — popular in PL"),
    ("Administrator", "Warszawa1",     137, "Warszawa — popular in PL"),

    # Common domain names as passwords
    ("administrator", "administrator", 140, "administrator/administrator — domain lowercase"),
    ("Admin",         "Admin",         141, "Admin/Admin — uppercase"),
]

# ── Default VNC credentials ────────────────────────────────────────────────────
# VNC (port 5900-5909) — Virtual Network Computing (RFB protocol).
# NOTE: VNC has no username — only password (max 8 characters!).
#       username = "" (empty), password = VNC password.
# Sources: SecLists/VNC, CIRT.net defaults, vendor docs, Shodan research.
_DEFAULT_VNC_CREDENTIALS = [
    # (username, password, priority, notes)

    # --- No password / empty (most often effective!) ---
    ("",  "",              10,  "VNC no password — default many devices, UltraVNC without auth"),
    ("",  "password",      15,  "password — most popular VNC password"),
    ("",  "admin",         17,  "admin — second most popular"),
    ("",  "1234",          19,  "1234"),
    ("",  "12345",         21,  "12345"),
    ("",  "123456",        23,  "123456"),
    ("",  "vnc",           25,  "vnc — protocol name as password"),

    # --- Vendor defaults ---
    # Industrial HMI/SCADA devices with VNC
    ("",  "Siemens",       30,  "Siemens SIMATIC HMI (TP/MP/Comfort) VNC default"),
    ("",  "1",             31,  "Siemens alternative (single character)"),
    ("",  "100",           32,  "Siemens SIMATIC HMI abbreviation"),
    ("",  "Schneider",     33,  "Schneider Magelis / Harmony HMI VNC"),
    ("",  "Rockwell",      34,  "Rockwell PanelView Plus HMI VNC"),
    ("",  "1234",          35,  "PanelView Plus default PIN"),
    ("",  "GE",            36,  "GE iFix / Proficy HMI VNC"),
    ("",  "Wonderware",    37,  "Wonderware / AVEVA InTouch VNC"),
    ("",  "Citect",        38,  "Schneider Citect SCADA VNC"),

    # NVR / thin client / Windows with VNC server
    ("",  "admin",         40,  "Hikvision / Dahua NVR VNC"),
    ("",  "12345",         41,  "NVR generic VNC pin"),
    ("",  "Admin12345",    42,  "Hikvision newer"),
    ("",  "TightVNC",      44,  "TightVNC server default"),
    ("",  "UltraVNC",      45,  "UltraVNC server users"),
    ("",  "realvnc",       46,  "RealVNC default"),
    ("",  "vncpasswd",     47,  "Generic VNC password ('vncpasswd')"),

    # Common short passwords (VNC max 8 characters!)
    ("",  "secret",        50,  "secret"),
    ("",  "pass",          51,  "pass"),
    ("",  "0000",          52,  "0000"),
    ("",  "1111",          53,  "1111"),
    ("",  "4321",          54,  "4321"),
    ("",  "qwerty",        55,  "qwerty"),
    ("",  "letmein",       56,  "letmein"),
    ("",  "test",          57,  "test"),
    ("",  "root",          58,  "root"),
    ("",  "abc123",        59,  "abc123 (truncated to 8 characters)"),
    ("",  "access",        60,  "access"),
    ("",  "welcome",       61,  "welcome"),
    ("",  "temp",          62,  "temp"),
    ("",  "desktop",       63,  "desktop"),
    ("",  "remote",        64,  "remote"),
    ("",  "connect",       65,  "connect"),
    ("",  "support",       66,  "support"),

    # IP Cameras (some have VNC) — typical PINs
    ("",  "666666",        70,  "Hikvision/Dahua legacy PIN (666666 = operator)"),
    ("",  "888888",        71,  "Hikvision/Dahua legacy PIN (888888 = admin)"),
    ("",  "000000",        72,  "000000 — trivial PIN"),
    ("",  "111111",        73,  "111111 — trivial PIN"),

    # Raspberry Pi / embedded Linux with VNC
    ("",  "raspberry",     75,  "raspberry — Raspberry Pi OS default VNC password"),
    ("",  "pi",            76,  "pi — Raspberry Pi alternative"),

    # IoT / smart home with VNC
    ("",  "admin1234",     78,  "admin1234 — IoT generic"),
    ("",  "homevnc",       79,  "homevnc — smart home generic"),

    # Kiosk / Digital Signage
    ("",  "kiosk",         80,  "kiosk — Windows kiosk VNC"),
    ("",  "display",       81,  "display — digital signage"),

    # Weak passwords with min. 8 char policy (many VNC max8 with truncation)
    ("",  "Password",      85,  "Password (8 characters — exactly the VNC limit!)"),
    ("",  "passw0rd",      86,  "passw0rd"),
    ("",  "changeme",      87,  "changeme (8 characters)"),
]

# ── Default FTP credentials ────────────────────────────────────────────────────
# FTP (port 21) — File Transfer Protocol.
# Sources: SecLists/FTP, vendor docs, CIRT.net, CVE research.
# FTP widely used in network devices for transferring logs, configs, firmware.
_DEFAULT_FTP_CREDENTIALS = [
    # (username, password, priority, notes)

    # --- Anonymous (most common problem on office devices!) ---
    ("anonymous", "",              10,  "anonymous / no password — RFC default anonymous FTP"),
    ("anonymous", "anonymous",     11,  "anonymous/anonymous — alternative"),
    ("anonymous", "ftp",           12,  "anonymous/ftp — many servers accept this"),
    ("anonymous", "guest",         13,  "anonymous/guest"),
    ("ftp",       "",              14,  "ftp / no password — anonymous alias"),
    ("ftp",       "ftp",           15,  "ftp/ftp — classic"),

    # --- No password / empty ---
    ("admin",     "",              20,  "admin / no password — many embedded FTP"),
    ("root",      "",              22,  "root / no password — Unix FTP embedded"),
    ("user",      "",              24,  "user / no password — generic FTP user"),

    # --- Most popular pairs ---
    ("admin",     "admin",         30,  "admin/admin — most common FTP default"),
    ("admin",     "password",      32,  "admin/password"),
    ("admin",     "1234",          34,  "admin/1234"),
    ("admin",     "12345",         36,  "admin/12345"),
    ("admin",     "ftp",           38,  "admin/ftp"),
    ("root",      "root",          40,  "root/root"),
    ("root",      "password",      42,  "root/password"),
    ("user",      "user",          44,  "user/user"),
    ("user",      "password",      46,  "user/password"),
    ("guest",     "guest",         48,  "guest/guest"),
    ("guest",     "",              49,  "guest / no password"),

    # --- Network printers (scan-to-FTP) ---
    # Printers often have FTP for receiving scans — default accounts
    ("JetDirect",  "",             55,  "HP JetDirect / LaserJet FTP embedded"),
    ("admin",      "hp",           56,  "HP LaserJet EWS FTP"),
    ("admin",      "",             57,  "HP / Kyocera / Canon FTP no password"),
    ("Admin",      "Admin00",      58,  "Kyocera TASKalfa FTP default"),
    ("admin",      "admin",        59,  "Ricoh / Xerox / Brother scan-to-FTP"),
    ("supervisor", "supervisor",   60,  "Ricoh Aficio FTP admin"),
    ("administrator","",           61,  "Konica Minolta PageScope FTP (no password!)"),
    ("admin",      "1111",         62,  "Xerox WorkCentre FTP pin"),
    ("admin",      "7654321",      63,  "Canon imageRUNNER FTP admin PIN"),
    ("admin",      "access",       64,  "Brother MFC FTP default"),
    ("admin",      "aaaaaa",       65,  "OKI MC series FTP"),

    # --- IP Cameras / NVR / DVR (FTP for event recording) ---
    ("admin",     "12345",         70,  "Hikvision FTP event upload"),
    ("admin",     "Admin12345",    71,  "Hikvision newer"),
    ("admin",     "admin",         72,  "Dahua / Axis / generic camera FTP"),
    ("root",      "pass",          73,  "Axis Communications FTP (old firmware)"),
    ("admin",     "amcrest2021",   74,  "Amcrest FTP configuration"),
    ("admin",     "meinsm",        75,  "Mobotix FTP default"),

    # --- Routers / switches (FTP for configuration backup) ---
    ("cisco",     "cisco",         80,  "Cisco IOS FTP server"),
    ("admin",     "admin",         81,  "MikroTik / generic router FTP"),
    ("ubnt",      "ubnt",          82,  "Ubiquiti AirOS FTP"),
    ("admin",     "Admin@huawei",  83,  "Huawei FTP backup"),
    ("mikrotik",  "",              84,  "MikroTik FTP (no password!)"),

    # --- NAS servers (FTP often enabled by default) ---
    ("admin",     "admin",         88,  "QNAP / Synology / Netgear ReadyNAS FTP"),
    ("admin",     "infrant1",      89,  "Netgear ReadyNAS (legacy Infrant)"),
    ("root",      "",              90,  "TrueNAS CORE / TrueNAS SCALE FTP root"),
    ("admin",     "admin",         91,  "Asustor / Terramaster FTP"),

    # --- PLC / OT controllers (TFTP/FTP for firmware/config) ---
    ("admin",     "admin",         95,  "Siemens SINEMA / S7 FTP gateway"),
    ("USER",      "USER",          96,  "Schneider Modicon FTP"),
    ("operator",  "",              97,  "OT operator FTP no password"),

    # --- Windows servers (IIS FTP / FileZilla Server) ---
    ("Administrator","",           100, "Windows IIS FTP no password"),
    ("Administrator","Administrator",101,"Windows IIS FTP classic"),
    ("ftpuser",   "ftpuser",       102, "Windows FTP dedicated account"),
    ("upload",    "upload",        103, "upload/upload — upload account"),
    ("backup",    "backup",        104, "backup/backup — backup account"),

    # --- General weak passwords ---
    ("test",      "test",          110, "test/test — test account"),
    ("support",   "support",       111, "support/support"),
    ("service",   "service",       112, "service/service"),
    ("ftpadmin",  "ftpadmin",      113, "ftpadmin/ftpadmin — FTP admin account"),
    ("ftp",       "ftp123",        114, "ftp/ftp123"),
    ("admin",     "ftppassword",   115, "admin/ftppassword"),
    ("admin",     "transfer",      116, "admin/transfer"),
    ("admin",     "files",         117, "admin/files"),

    # --- Specific to Polish conditions ---
    ("admin",     "Polska1",       120, "Polska admin FTP — PL specific"),
    ("admin",     "server",        121, "admin/server — Polish server installation"),
]


def seed_default_credentials(db):
    """Upsert default SSH/Telnet/API/RDP/VNC/FTP credentials — adds missing ones, does not overwrite.

    Upsert key: (method, username, password) — the same username+password pair
    can be registered only once per method as a global default.
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
        # Collect existing pairs (username, plaintext_password) for this method
        # Backward compatibility: old entries may have plaintext in password_encrypted
        existing_pairs = set()
        for r in db.query(Credential).filter(
            Credential.method == method,
            Credential.device_id.is_(None),
        ).all():
            try:
                plain_pw = decrypt(r.password_encrypted or "")
            except Exception:
                plain_pw = r.password_encrypted or ""  # old plaintext (before migration)
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
            logger.info("%s seed: added %d new credentials (total: %d)",
                        label, added, len(existing_pairs))
        else:
            logger.info("%s seed: no new credentials (%d already in DB)",
                        label, len(existing_pairs))


def _set_status(db, updates: dict, category: str = "scanner") -> None:
    """Save scanner status to system_status (visible in admin panel)."""
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
    """Read a value from system_status."""
    from netdoc.storage.models import SystemStatus
    row = db.query(SystemStatus).filter(SystemStatus.key == key).first()
    return row.value if row else None


def run_scan_cycle(db, scan_type: str = "discovery") -> dict:
    """Run one scan cycle. Returns statistics."""
    from netdoc.collector.discovery import run_discovery, run_full_scan, _read_nmap_settings, _read_batch_scan_settings
    from netdoc.collector.pipeline import run_pipeline

    t0 = time.monotonic()
    _set_status(db, {
        "scanner_job": scan_type,
        "scanner_started_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    })

    # Log scan parameters at the start of each cycle
    try:
        nmap_rate, nmap_vi = _read_nmap_settings()
        batch = _read_batch_scan_settings()
        logger.info(
            "=== Cycle [%s] | nmap: min-rate=%d version-intensity=%d | "
            "batch: ports=%d pause=%.1fs resume=%s ===",
            scan_type, nmap_rate, nmap_vi,
            batch["batch_size"], batch["batch_pause_s"],
            "yes" if batch["resume_enabled"] else "no",
        )
    except Exception:
        pass

    try:
        if scan_type == "full_single":
            # Full scan only for IPs from full_scan_ip_queue (per-device request from UI)
            from netdoc.collector.discovery import FULL_SCAN_BATCH_SIZE
            from netdoc.storage.models import SystemStatus
            import math as _math
            queue_row = db.query(SystemStatus).filter_by(key="full_scan_ip_queue").first()
            queued_ips = [x.strip() for x in (queue_row.value if queue_row else "").split(",") if x.strip()]
            if queued_ips:
                # BUG-FS-03: filter out inactive devices — scanning offline hosts wastes time
                # and can corrupt scan results (nmap returns no data for unreachable hosts)
                from netdoc.storage.models import Device as _Device
                # Pomijaj tylko urzadzenia które SĄ w DB i są nieaktywne
                # (IP których nie ma w DB przepuszczamy — mogą być nowe odkrycia)
                inactive_set = {d.ip for d in db.query(_Device).filter(
                    _Device.ip.in_(queued_ips), _Device.is_active == False).all()}
                if inactive_set:
                    logger.info("full_single: pomijam nieaktywne urzadzenia: %s", ", ".join(sorted(inactive_set)))
                queued_ips = [ip for ip in queued_ips if ip not in inactive_set]
                del _Device, inactive_set
            if not queued_ips:
                logger.info("full_single: queue empty — performing discovery")
                scan_type = "discovery"
            else:
                logger.info("=== Full scan per device: %s ===", ", ".join(queued_ips))
                # Clear the queue and save status in one atomic commit
                if queue_row:
                    queue_row.value = ""
                _total_b = max(1, _math.ceil(len(queued_ips) / FULL_SCAN_BATCH_SIZE))
                _set_status(db, {"scanning_ips": ",".join(queued_ips), "scan_progress": f"0/{_total_b} batches"})

                def _on_single_batch(done, total, batch_ips):
                    _set_status(db, {"scan_progress": f"{done}/{total} batches"})

                n = run_full_scan(db, ips=queued_ips, progress_callback=_on_single_batch)
                _set_status(db, {"scanning_ips": "", "scan_progress": f"completed: {n} devices"})
                return {"total": n, "enriched": 0, "basic_only": n}

        if scan_type == "full":
            from netdoc.collector.discovery import FULL_SCAN_BATCH_SIZE
            import math as _math
            logger.info("=== Full port scan 1-65535 ===")
            active_ips = [d.ip for d in db.query(Device).filter(Device.is_active == True).all()]
            _total_b = max(1, _math.ceil(len(active_ips) / FULL_SCAN_BATCH_SIZE))
            _set_status(db, {"scanning_ips": ",".join(active_ips), "scan_progress": f"0/{_total_b} batches"})

            def _on_full_batch(done, total, batch_ips):
                _set_status(db, {"scan_progress": f"{done}/{total} batches"})

            n = run_full_scan(db, progress_callback=_on_full_batch)
            _set_status(db, {"scanning_ips": "", "scan_progress": f"completed: {n} devices"})
            stats = {"total": n, "enriched": 0, "basic_only": n}
        else:
            logger.info("=== Discovery + pipeline ===")
            devices = run_discovery(db)
            stats = run_pipeline(db, devices) if devices else {}
            stats.setdefault("total", len(devices))

            # Auto full scan: devices without a current full port scan
            from netdoc.collector.discovery import get_stale_full_scan_ips
            max_age_days = int(_get_status(db, "full_scan_max_age_days") or 7)
            full_scan_enabled = _get_status(db, "full_scan_enabled") != "0"
            if max_age_days > 0 and full_scan_enabled:
                stale_ips = get_stale_full_scan_ips(db, max_age_days)
                # Save the number of pending to system_status (visible in Grafana + panel)
                _set_status(db, {"full_scan_pending": str(len(stale_ips))}, category="scanner")
                if stale_ips:
                    from netdoc.collector.discovery import FULL_SCAN_BATCH_SIZE
                    import math as _math
                    logger.info(
                        "Auto full scan: %d devices without full scan (max_age=%dd)",
                        len(stale_ips), max_age_days,
                    )
                    _total_batches = max(1, _math.ceil(len(stale_ips) / FULL_SCAN_BATCH_SIZE))
                    _set_status(db, {
                        "scanner_job": f"full scan ({len(stale_ips)} devices)",
                        "scanning_ips": ",".join(stale_ips),
                        "scan_progress": f"0/{_total_batches} batches",
                    })

                    def _on_auto_batch(done, total, batch_ips):
                        _set_status(db, {"scan_progress": f"{done}/{total} batches"})

                    n = run_full_scan(db, ips=stale_ips, progress_callback=_on_auto_batch)
                    stats["full_scan_devices"] = n
                    _set_status(db, {
                        "full_scan_pending": "0",
                        "scanning_ips": "",
                        "scan_progress": f"completed: {n} devices",
                    }, category="scanner")

        elapsed = round(time.monotonic() - t0, 1)
        logger.info("Scan completed: %s devices in %.1fs", stats.get("total", "?"), elapsed)

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
        logger.exception("Scan error: %s", exc)
        _set_status(db, {"scanner_job": "-", "scanner_last_error": str(exc)})
        return {}



def _wait_cooldown(cooldown: int) -> str | None:
    """
    Waits cooldown seconds between scans.
    Every 5s checks the scan_requested flag — if set, interrupts the cooldown early.
    Returns the scan type from the flag (or None if normal cooldown end).
    PERF-10: one DB session for the entire cooldown instead of a new one every 5s.
    """
    from netdoc.storage.database import SessionLocal
    logger.info("Cooldown %ds before next scan...", cooldown)
    deadline = time.monotonic() + cooldown
    try:
        with SessionLocal() as db:
            while time.monotonic() < deadline:
                time.sleep(min(5, max(0.1, deadline - time.monotonic())))
                try:
                    req = _get_status(db, "scan_requested")
                    if req and req not in ("-", ""):
                        logger.info("Cooldown interrupted — trigger: %s", req)
                        _set_status(db, {"scan_requested": "-"})
                        db.commit()
                        return req if req in ("full", "discovery", "full_single") else "discovery"
                except Exception:
                    pass
    except Exception:
        pass
    return None



TASK_NAME = "NetDocScanner"


def _ensure_task_scheduled() -> bool:
    """Checks whether the NetDocScanner task exists in Windows Task Scheduler.
    If not — registers it automatically and starts it.
    Returns True if the task was registered or could be registered successfully.
    """
    if sys.platform != "win32":
        return True

    import subprocess
    python_exe = sys.executable
    script_path = os.path.abspath(__file__)
    working_dir = os.path.dirname(script_path)

    # Check if the task already exists (schtasks doesn't require PowerShell)
    check = subprocess.run(
        ["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "LIST"],
        capture_output=True, timeout=30,  # BUG-CONC-8: brak timeout mogl zawiesic skaner
    )
    if check.returncode == 0:
        logger.info("Task Scheduler: task %r already exists.", TASK_NAME)
        output = check.stdout.decode("cp1250", errors="replace")

        # Check if ExecutionTimeLimit is not too small (e.g. 15 min from old registration).
        # If the "Stop Task If Runs" line indicates a non-zero limit — update settings.
        needs_update = False
        for line in output.splitlines():
            if "Stop Task If Runs" in line and "0:00:00" not in line and "Disabled" not in line:
                logger.warning(
                    "Task Scheduler: detected ExecutionTimeLimit != 0 (%s) — updating settings.",
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
                capture_output=True, timeout=30,
            )
            fix_out = fix_result.stdout.decode("utf-8", errors="replace")
            if "UPDATED" in fix_out:
                logger.info("Task Scheduler: ExecutionTimeLimit updated to 0 (no limit).")
            else:
                logger.warning(
                    "Task Scheduler: failed to update settings: %s",
                    fix_result.stderr.decode("utf-8", errors="replace").strip(),
                )

        if "Running" not in output:
            logger.info("Task Scheduler: starting task...")
            subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME], capture_output=True, timeout=30)
        return True

    # Does not exist — create via PowerShell with UTF-8 output
    logger.info("Task Scheduler: task %r does not exist — registering...", TASK_NAME)
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
        capture_output=True, timeout=60,
    )
    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    if result.returncode == 0 and "OK" in stdout:
        logger.info("Task Scheduler: task %r registered.", TASK_NAME)
        subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME], capture_output=True, timeout=30)
        return True
    logger.warning(
        "Task Scheduler: failed to register (missing admin rights?). "
        "Run manually: powershell -ExecutionPolicy Bypass -File install_autostart.ps1 "
        "| stderr: %s", stderr.strip(),
    )
    return False


WATCHDOG_TASK_NAME = "NetDoc Watchdog"


def _ensure_watchdog_scheduled() -> None:
    """Checks whether the 'NetDoc Watchdog' task exists in Task Scheduler.
    If not — registers it via install_watchdog.ps1.
    Called by the scanner to keep an eye on the watchdog (mutual guardianship).
    """
    if sys.platform != "win32":
        return

    import subprocess
    check = subprocess.run(
        ["schtasks", "/Query", "/TN", WATCHDOG_TASK_NAME, "/FO", "LIST"],
        capture_output=True, timeout=30,
    )
    if check.returncode == 0:
        logger.info("Task Scheduler: watchdog %r exists.", WATCHDOG_TASK_NAME)
        return

    # Watchdog does not exist — try to register via install_watchdog.ps1
    working_dir = os.path.dirname(os.path.abspath(__file__))
    watchdog_script = os.path.join(working_dir, "install_watchdog.ps1")
    if not os.path.exists(watchdog_script):
        logger.warning(
            "Task Scheduler: watchdog %r does not exist and install_watchdog.ps1 is missing!",
            WATCHDOG_TASK_NAME,
        )
        return

    logger.warning(
        "Task Scheduler: watchdog %r does not exist — registering via install_watchdog.ps1...",
        WATCHDOG_TASK_NAME,
    )
    result = subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-NonInteractive", "-File", watchdog_script],
        capture_output=True, timeout=60,
    )
    out = result.stdout.decode("utf-8", errors="replace")
    err = result.stderr.decode("utf-8", errors="replace")
    if result.returncode == 0 and "OK" in out:
        logger.info("Task Scheduler: watchdog %r registered successfully.", WATCHDOG_TASK_NAME)
    else:
        logger.warning(
            "Task Scheduler: failed to register watchdog (missing admin rights?): %s",
            (err or out).strip()[:200],
        )


_COMPOSE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docker-compose.yml")

_DOCKER_SERVICES = [
    "netdoc-postgres",
    "netdoc-prometheus",
    "netdoc-loki",
    "netdoc-promtail",
    "netdoc-grafana",
    "netdoc-nginx",
    "netdoc-api",
    "netdoc-web",
    "netdoc-ping",
    "netdoc-snmp",
    "netdoc-community",
    "netdoc-cred",
    "netdoc-vuln",
    "netdoc-internet",
    "netdoc-clickhouse",
    "netdoc-rsyslog",
    "netdoc-vector",
]

_POSTGRES_PORT = 15432
_DOCKER_MAX_ATTEMPTS = 5       # attempts to start missing containers
_DOCKER_WAIT_SEC = 60          # seconds to wait between attempts (image pull takes time)
_COMPOSE_TIMEOUT = 600         # 10 min — downloading Docker images can take a long time
_COMPOSE_BUILD_TIMEOUT = 900   # 15 min — rebuilding images from Dockerfile
_PG_TCP_RETRIES = 12           # TCP attempts to PostgreSQL (12 x 10s = 2 min)
_PG_TCP_WAIT_SEC = 10          # seconds between TCP attempts


def _dlog(msg: str, level: str = "INFO") -> None:
    """Prints a message to the console and to the scanner log."""
    icons = {"OK": "[OK]  ", "WARN": "[WARN]", "ERR": "[ERR] ", "WAIT": "[WAIT]", "INFO": "[INFO]"}
    prefix = icons.get(level, "[INFO]")
    print(f"{prefix} Docker: {msg}", flush=True)
    getattr(logger, "warning" if level in ("WARN", "ERR") else "info")("Docker: %s", msg)


def _docker_running_containers() -> set:
    """Returns a set of names of currently running netdoc containers."""
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
    """Checks whether PostgreSQL responds on the TCP port."""
    import socket
    try:
        with socket.create_connection(("127.0.0.1", _POSTGRES_PORT), timeout=3):
            return True
    except OSError:
        return False


def _ensure_docker_services() -> bool:
    """Checks whether Docker containers are running; starts missing ones.

    Makes up to _DOCKER_MAX_ATTEMPTS attempts with _DOCKER_WAIT_SEC wait between
    consecutive checks. Compose up may download images (up to 10 min) — if the
    command exceeds timeout, Docker daemon continues downloading in the background
    and the function waits further. SQLite fallback only occurs after all attempts
    if postgres still doesn't respond on TCP.
    """
    import subprocess

    print("", flush=True)
    _dlog("Checking Docker services status...", "INFO")

    # Check if Docker daemon is running
    _docker_available = True
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=15)
        if r.returncode != 0:
            _dlog("Docker daemon not responding — checking if PostgreSQL is already running...", "WARN")
            _docker_available = False
    except FileNotFoundError:
        _dlog("Docker not installed — checking if PostgreSQL is already running...", "WARN")
        _docker_available = False
    except subprocess.TimeoutExpired:
        _dlog("Docker info timeout — checking if PostgreSQL is already running...", "WARN")
        _docker_available = False

    if not _docker_available:
        # Docker unavailable or slow — check if postgres is already responding (containers may already be running)
        if _postgres_reachable():
            _dlog(f"PostgreSQL on port {_POSTGRES_PORT} reachable despite Docker not responding — continuing.", "OK")
            print("", flush=True)
            return True
        _dlog("Docker unavailable and PostgreSQL not responding — scanner will exit.", "ERR")
        print("", flush=True)
        return False

    compose_base = ["docker", "compose", "-f", _COMPOSE_FILE, "up", "-d"]

    for attempt in range(1, _DOCKER_MAX_ATTEMPTS + 1):
        running = _docker_running_containers()
        missing = [s for s in _DOCKER_SERVICES if s not in running]

        if not missing:
            _dlog(f"All {len(_DOCKER_SERVICES)} containers running.", "OK")
            break

        _dlog(
            f"Attempt {attempt}/{_DOCKER_MAX_ATTEMPTS}: "
            f"missing {len(missing)}: {', '.join(missing)}",
            "WARN",
        )
        _dlog(
            f"Starting: docker compose up -d "
            f"(timeout {_COMPOSE_TIMEOUT}s, image download may take several minutes)...",
            "WAIT",
        )
        print("", flush=True)

        try:
            r = subprocess.run(compose_base, timeout=_COMPOSE_TIMEOUT)
            if r.returncode != 0:
                # up -d may fail when local images are corrupted — try with rebuild
                _dlog("up -d failed — trying with --build ...", "WARN")
                try:
                    subprocess.run(
                        compose_base + ["--build"],
                        timeout=_COMPOSE_BUILD_TIMEOUT,
                    )
                except subprocess.TimeoutExpired:
                    _dlog(
                        f"docker compose up --build timeout ({_COMPOSE_BUILD_TIMEOUT}s)"
                        " — Docker continues building in the background...",
                        "WAIT",
                    )
        except subprocess.TimeoutExpired:
            # Timeout is NOT an error — Docker daemon continues downloading images
            # and starting containers in the background; we wait and check again
            _dlog(
                f"docker compose up -d timeout ({_COMPOSE_TIMEOUT}s)"
                " — Docker daemon continues downloading images in the background...",
                "WAIT",
            )
        print("", flush=True)

        if attempt < _DOCKER_MAX_ATTEMPTS:
            _dlog(f"Waiting {_DOCKER_WAIT_SEC}s for services to be ready...", "WAIT")
            time.sleep(_DOCKER_WAIT_SEC)
    else:
        # All attempts exhausted — check if at least postgres is running
        running = _docker_running_containers()
        if "netdoc-postgres" not in running:
            _dlog(
                f"ERROR: netdoc-postgres not started after {_DOCKER_MAX_ATTEMPTS} attempts "
                "— scanner will exit.",
                "ERR",
            )
            return False
        _dlog("netdoc-postgres running despite errors in other services — continuing.", "WARN")

    # TCP verification — postgres may need a moment to initialize after startup
    for pg_attempt in range(1, _PG_TCP_RETRIES + 1):
        if _postgres_reachable():
            _dlog(f"PostgreSQL on port {_POSTGRES_PORT} ready.", "OK")
            print("", flush=True)
            return True
        if pg_attempt < _PG_TCP_RETRIES:
            _dlog(
                f"PostgreSQL (:{_POSTGRES_PORT}) not yet responding "
                f"(attempt {pg_attempt}/{_PG_TCP_RETRIES}) — waiting {_PG_TCP_WAIT_SEC}s...",
                "WAIT",
            )
            time.sleep(_PG_TCP_WAIT_SEC)

    _dlog(f"PostgreSQL unavailable on :{_POSTGRES_PORT} — scanner will exit.", "ERR")
    print("", flush=True)
    return False


_LOCK_FILE = os.path.join(os.environ.get("TEMP", os.path.dirname(os.path.abspath(__file__))), "netdoc_scanner.pid")


def _is_scanner_process(pid: int) -> bool:
    """Checks whether the PID is an active scanner instance (run_scanner.py).

    We use psutil instead of os.kill() because on Windows os.kill(pid, 0) raises
    PermissionError for system processes even when the original process no longer
    exists and the PID has been reused by the system.
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
            # No access to cmdline — assume it is another scanner instance (safer)
            return "python" in name
    except (psutil.NoSuchProcess, psutil.AccessDenied, ImportError, OSError):
        return False


def _acquire_scanner_lock() -> bool:
    """Ensures that only one scanner instance is running at a time (PID lock file)."""
    my_pid = os.getpid()

    if os.path.exists(_LOCK_FILE):
        try:
            with open(_LOCK_FILE) as _f:
                old_pid = int(_f.read().strip())
            if old_pid != my_pid:
                if _is_scanner_process(old_pid):
                    logger.error("Another scanner instance is already running (PID=%d). Exiting.", old_pid)
                    return False
                else:
                    logger.warning(
                        "Stale lock file (PID=%d) — process does not exist or is not a scanner. "
                        "Overwriting lock.", old_pid,
                    )
        except (ValueError, OSError):
            pass  # corrupted file — overwrite

    # BUG-CONC-1: atomic PID write — open("x") raises FileExistsError if
    # another process managed to write the lock between our check and write (TOCTOU fix)
    try:
        try:
            os.remove(_LOCK_FILE)
        except OSError:
            pass  # does not exist or cannot be removed — open("x") will detect this
        with open(_LOCK_FILE, "x") as _f:
            _f.write(str(my_pid))
    except FileExistsError:
        # Another process grabbed the lock between our check and write
        try:
            with open(_LOCK_FILE) as _f:
                other = _f.read().strip()
            logger.error("Race condition: scanner PID=%s got ahead. Exiting.", other)
        except OSError:
            logger.error("Race condition: another scanner got ahead. Exiting.")
        return False
    except OSError as e:
        logger.warning("Cannot write lock file: %s", e)
        return True  # continue without lock if file is unavailable

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
    parser.add_argument("--once", action="store_true", help="Single scan and exit")
    parser.add_argument("--full", action="store_true", help="Full port scan 1-65535")
    args = parser.parse_args()

    if not _acquire_scanner_lock():
        sys.exit(0)

    # Check and start Docker services before connecting to the database
    if not _ensure_docker_services():
        logger.error("Docker/PostgreSQL services unavailable — aborting. Try again in a moment.")
        sys.exit(1)

    from netdoc.storage.database import SessionLocal, init_db
    from netdoc.config.settings import settings

    logger.info("NetDoc Scanner starting — DB: %s", settings.database_url)
    init_db()

    # Check and register task in Windows Task Scheduler (autostart on login)
    _ensure_task_scheduled()
    # Check if watchdog also exists (mutual care — scanner watches the watchdog)
    _ensure_watchdog_scheduled()

    # OUI vendor database (IEEE MA-L/MA-M/MA-S) — download if missing or stale (>30 days)
    try:
        from netdoc.collector.oui_lookup import oui_db
        if oui_db.needs_update():
            logger.info("Downloading OUI vendor database (IEEE MA-L/MA-M/MA-S)...")
            oui_db.update(timeout=60)
        else:
            oui_db.load()
    except Exception as _oui_exc:
        logger.warning("Failed to load/download OUI database: %s", _oui_exc)

    with SessionLocal() as db:
        # Zapisz IP hosta (skanera) — workery Docker uzywaja tego do wykluczenia samego siebie
        import socket as _sock
        try:
            # Zbierz wszystkie IPv4 ze wszystkich interfejsow (LAN + WiFi + VPN itp.)
            _host_ips_set: set = set()
            # Metoda 1: getaddrinfo(hostname) — zwraca IPs z DNS/hosts
            for _info in _sock.getaddrinfo(_sock.gethostname(), None):
                if _info[0] == _sock.AF_INET and not _info[4][0].startswith("127."):
                    _host_ips_set.add(_info[4][0])
            # Metoda 2: connect trick — wykrywa IP aktywnego interfejsu dla kazdej sieci
            for _probe_dst in ("8.8.8.8", "192.168.0.1", "10.0.0.1", "172.16.0.1"):
                try:
                    _s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
                    _s.connect((_probe_dst, 80))
                    _host_ips_set.add(_s.getsockname()[0])
                    _s.close()
                except Exception:
                    pass
            _host_ips = [ip for ip in _host_ips_set if not ip.startswith("127.")]
        except Exception:
            _host_ips = []
        # Register scanner in DB BEFORE seeds — UI sees status immediately
        _set_status(db, {
            "scanner_mode": "host",
            "scanner_pid": str(os.getpid()),
            "scanner_started_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "scanner_job": "-",
            "scanning_ips": "",   # clear after any previous failed scan
            "scanner_host_ips": ",".join(_host_ips),
        })
        seed_snmp_communities(db)
        seed_default_credentials(db)
        seed_lab_devices(db)
        # Initialize configuration settings (only if they do not already exist)
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
            # Network discovery overrides (empty = use .env / auto-detect)
            "network_ranges":          ("",   "worker_settings"),
            "scan_vpn_networks":       ("0",  "worker_settings"),
            "scan_virtual_networks":   ("0",  "worker_settings"),
            "lab_monitoring_enabled":  ("0",  "config"),
            # Diagnostics / alerting
            "diag_enabled":                  ("1",   "config"),
            "diag_error_warn_per_hour":      ("10",  "config"),
            "diag_error_critical_per_hour":  ("100", "config"),
            "diag_error_trend_pct":          ("50",  "config"),
            "diag_error_trend_days":         ("7",   "config"),
            "diag_cpu_warn_pct":             ("80",  "config"),
            "diag_cpu_critical_pct":         ("95",  "config"),
            "diag_mem_warn_pct":             ("80",  "config"),
            "diag_mem_critical_pct":         ("90",  "config"),
        }
        for cfg_key, (cfg_val, cfg_cat) in _config_defaults.items():
            if not db.query(SystemStatus).filter(SystemStatus.key == cfg_key).first():
                db.add(SystemStatus(key=cfg_key, category=cfg_cat, value=cfg_val))
        db.commit()

    if args.once or args.full:
        scan_type = "full" if args.full else "discovery"
        # In --once mode check if UI requested a specific scan type (full_single / full)
        if not args.full:
            try:
                with SessionLocal() as db:
                    requested = _get_status(db, "scan_requested")
                    if requested and requested not in ("-", ""):
                        if requested in ("full", "discovery", "full_single"):
                            scan_type = requested
                            logger.info("--once: trigger from UI: %s", scan_type)
                        _set_status(db, {"scan_requested": "-"})
            except Exception:
                pass
        try:
            with SessionLocal() as db:
                run_scan_cycle(db, scan_type)
        except Exception as exc:
            logger.exception("Scan error (--once): %s", exc)
            sys.exit(1)
        return

    # Continuous mode — uninterrupted scanning with a short cooldown between cycles
    logger.info("Continuous mode: uninterrupted scanning (cooldown %ds between scans).", COOLDOWN_SECONDS)

    next_scan_type = "discovery"  # type of the first scan

    while True:
        try:
            with SessionLocal() as db:
                # Check if the admin panel requested a different scan type
                requested = _get_status(db, "scan_requested")
                if requested and requested not in ("-", ""):
                    next_scan_type = requested if requested in ("full", "discovery", "full_single") else "discovery"
                    logger.info("Trigger from admin panel: %s", next_scan_type)
                    _set_status(db, {"scan_requested": "-"})

                run_scan_cycle(db, next_scan_type)
                next_scan_type = "discovery"  # subsequent cycles always discovery

        except Exception as exc:
            logger.exception("Scheduler loop error: %s", exc)

        # Short cooldown — checks flag every 5s, exits early on trigger
        triggered = _wait_cooldown(COOLDOWN_SECONDS)
        if triggered:
            next_scan_type = triggered


if __name__ == "__main__":
    main()
