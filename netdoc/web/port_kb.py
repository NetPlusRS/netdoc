"""Baza wiedzy o portach sieciowych.

Struktura wpisu:
  port      : int
  proto     : "tcp" | "udp" | "tcp/udp"
  service   : str   - powszechna nazwa usługi
  category  : str   - kategoria
  desc      : str   - opis co robi usługa
  vendors   : list  - producenci / systemy często używające tego portu
  risk      : "critical" | "high" | "medium" | "low" | "info"
  risk_note : str   - dlaczego jest ryzyko (lub brak)
  ot        : bool  - protokół przemysłowy / OT
"""

PORT_CATEGORIES = {
    "web":        "Web / HTTP",
    "remote":     "Zdalny dostęp",
    "file":       "Transfery plików",
    "database":   "Bazy danych",
    "mail":       "Poczta",
    "mgmt":       "Zarządzanie urządzeniami",
    "monitor":    "Monitoring / SNMP",
    "ot":         "Przemysłowe / OT / SCADA",
    "iot":        "IoT / Smart devices",
    "vpn":        "VPN / Tunelowanie",
    "auth":       "Autoryzacja / Katalog",
    "voip":       "VoIP / Komunikacja",
    "network":    "Infrastruktura sieciowa",
    "media":      "Media / Streaming",
    "other":      "Inne",
}

PORT_KB = [
    # ── Web / HTTP ─────────────────────────────────────────────────────────────
    dict(port=80,   proto="tcp", service="HTTP",        category="web",
         desc="Niezaszyfrowany ruch WWW. Przeglądarki, panele admin, REST API.",
         vendors=["Ubiquiti", "MikroTik", "Cisco", "Hikvision", "Dahua", "Synology",
                  "Axis", "QNAP", "HPE", "Fortinet", "wszystkie"],
         risk="high",
         risk_note="Ruch niezaszyfrowany — hasła i dane przesyłane jawnym tekstem. "
                   "Panel admin na HTTP to krytyczne ryzyko — używaj HTTPS lub blokuj z WAN.", ot=False),

    dict(port=443,  proto="tcp", service="HTTPS",       category="web",
         desc="Zaszyfrowany ruch WWW (TLS). Panele zarządzania, REST API, web UI.",
         vendors=["wszystkie"],
         risk="low",
         risk_note="Bezpieczny przy aktualnym TLS (1.2+). Ryzyko przy przestarzałych szyfrach "
                   "(SSLv3, TLS 1.0) lub certyfikatach samopodpisanych.", ot=False),

    dict(port=8080, proto="tcp", service="HTTP-alt",    category="web",
         desc="Alternatywny port HTTP. Często panele zarządzania, proxy, aplikacje developerskie.",
         vendors=["MikroTik (Winbox)", "Axis", "Hikvision", "Tomcat", "Jenkins"],
         risk="high",
         risk_note="Niezaszyfrowany. Często używany gdy port 80 jest zajęty. "
                   "Sprawdź czy jest dostępny z WAN.", ot=False),

    dict(port=8443, proto="tcp", service="HTTPS-alt",   category="web",
         desc="Alternatywny port HTTPS. Panele zarządzania, UniFi Controller, VMware.",
         vendors=["Ubiquiti UniFi", "VMware", "Synology", "QNAP"],
         risk="low",
         risk_note="Zaszyfrowany. Sprawdź ważność certyfikatu i wersję TLS.", ot=False),

    dict(port=8888, proto="tcp", service="HTTP-alt2",   category="web",
         desc="Alternatywny port HTTP. Jupyter Notebook, panele zarządzania, aplikacje.",
         vendors=["Jupyter", "różne aplikacje"],
         risk="high",
         risk_note="Niezaszyfrowany. Jupyter bez hasła = pełny dostęp do systemu.", ot=False),

    # ── Zdalny dostęp ──────────────────────────────────────────────────────────
    dict(port=22,   proto="tcp", service="SSH",         category="remote",
         desc="Secure Shell — szyfrowane zdalne zarządzanie powłoką. Standard dla Linux/Unix, "
              "routerów, przełączników.",
         vendors=["wszystkie urządzenia Linux/Unix", "Cisco IOS", "MikroTik", "Ubiquiti",
                  "Fortinet", "Juniper"],
         risk="medium",
         risk_note="Bezpieczny przy kluczach RSA/ED25519. Ryzyko przy hasłach domyślnych, "
                   "słabych hasłach lub ekspozycji na WAN. Wyłącz logowanie hasłem, "
                   "używaj kluczy.", ot=False),

    dict(port=23,   proto="tcp", service="Telnet",      category="remote",
         desc="Niezaszyfrowana powłoka zdalna. Poprzednik SSH — przesyła dane jawnym tekstem "
              "włącznie z hasłami.",
         vendors=["stare Cisco IOS", "MikroTik (domyślnie wyłączony)", "stare kamery IP",
                  "drukarki", "urządzenia przemysłowe"],
         risk="critical",
         risk_note="KRYTYCZNE. Hasła przesyłane jawnym tekstem — sniffing = pełny dostęp. "
                   "Wyłącz natychmiast. Zastąp SSH.", ot=False),

    dict(port=3389, proto="tcp", service="RDP",         category="remote",
         desc="Remote Desktop Protocol — graficzny zdalny pulpit Windows.",
         vendors=["Microsoft Windows", "Windows Server"],
         risk="high",
         risk_note="Częsty cel ataków brute-force i exploitów (BlueKeep, DejaBlue). "
                   "Nie wystawiaj bezpośrednio na WAN. Używaj VPN lub RD Gateway. "
                   "Wymagaj MFA.", ot=False),

    dict(port=5900, proto="tcp", service="VNC",         category="remote",
         desc="Virtual Network Computing — grafyczny zdalny pulpit niezależny od systemu.",
         vendors=["RealVNC", "TightVNC", "UltraVNC", "kamery IP", "Raspberry Pi",
                  "Hikvision (DVR)"],
         risk="critical",
         risk_note="Często bez szyfrowania i ze słabymi hasłami. "
                   "Nigdy nie wystawiaj na WAN bez VPN. Liczne exploity.", ot=False),

    dict(port=5800, proto="tcp", service="VNC-HTTP",    category="remote",
         desc="VNC przez przeglądarkę (Java applet). Powiązany z portem 5900.",
         vendors=["RealVNC", "TightVNC"],
         risk="critical",
         risk_note="Taka sama podatność jak VNC (5900) + dodatkowa powierzchnia ataku.", ot=False),

    dict(port=4899, proto="tcp", service="Radmin",      category="remote",
         desc="Radmin — zdalny dostęp do pulpitu Windows (Famatech).",
         vendors=["Famatech Radmin"],
         risk="high",
         risk_note="Cel ataków brute-force. Upewnij się że szyfrowanie jest włączone "
                   "i port nie jest dostępny z WAN.", ot=False),

    # ── Transfery plików ───────────────────────────────────────────────────────
    dict(port=21,   proto="tcp", service="FTP",         category="file",
         desc="File Transfer Protocol — transfer plików, niezaszyfrowany.",
         vendors=["FileZilla Server", "IIS FTP", "routery", "drukarki", "NAS"],
         risk="critical",
         risk_note="Hasła i pliki przesyłane jawnym tekstem. Zastąp SFTP (port 22) "
                   "lub FTPS (port 990). Wyłącz anonymous FTP.", ot=False),

    dict(port=990,  proto="tcp", service="FTPS",        category="file",
         desc="FTP over TLS/SSL (implicit). Zaszyfrowany transfer plików.",
         vendors=["FileZilla Server", "IIS FTP"],
         risk="low",
         risk_note="Bezpieczny przy aktualnym TLS. Sprawdź certyfikat.", ot=False),

    dict(port=445,  proto="tcp", service="SMB",         category="file",
         desc="Server Message Block — udostępnianie plików Windows, drukarki sieciowe.",
         vendors=["Microsoft Windows", "Samba (Linux)", "NAS (Synology, QNAP, WD)"],
         risk="critical",
         risk_note="KRYTYCZNE jeśli dostępny z WAN. EternalBlue (MS17-010) = WannaCry. "
                   "Blokuj port 445 na granicy sieci. Wyłącz SMBv1.", ot=False),

    dict(port=139,  proto="tcp", service="NetBIOS-SSN", category="file",
         desc="NetBIOS Session Service — starsza wersja udostępniania plików Windows.",
         vendors=["Microsoft Windows (starsze)"],
         risk="high",
         risk_note="Przestarzały protokół. Blokuj na granicy sieci. "
                   "SMBv1 przez NetBIOS = liczne exploity.", ot=False),

    dict(port=2049, proto="tcp", service="NFS",         category="file",
         desc="Network File System — udostępnianie systemu plików (głównie Linux/Unix).",
         vendors=["Linux", "macOS", "Synology", "QNAP", "NetApp"],
         risk="high",
         risk_note="Brak uwierzytelnienia w starszych wersjach. "
                   "Nigdy nie wystawiaj na WAN. Ogranicz dostęp przez /etc/exports.", ot=False),

    dict(port=69,   proto="udp", service="TFTP",        category="file",
         desc="Trivial FTP — brak uwierzytelnienia, używany do ładowania firmware "
              "urządzeń sieciowych (PXE boot, Cisco IOS).",
         vendors=["Cisco (IOS boot)", "serwery PXE", "VoIP phones", "drukraki"],
         risk="high",
         risk_note="Brak uwierzytelnienia. Każdy może pobrać/nadpisać pliki. "
                   "Ogranicz dostęp do sieci zarządzania.", ot=False),

    # ── Bazy danych ────────────────────────────────────────────────────────────
    dict(port=3306, proto="tcp", service="MySQL/MariaDB", category="database",
         desc="MySQL i MariaDB — popularne relacyjne bazy danych.",
         vendors=["MySQL", "MariaDB", "XAMPP", "phpMyAdmin backend"],
         risk="critical",
         risk_note="Nigdy nie wystawiaj na WAN. Brute-force + liczne CVE. "
                   "Ogranicz bind-address do 127.0.0.1.", ot=False),

    dict(port=5432, proto="tcp", service="PostgreSQL",  category="database",
         desc="PostgreSQL — zaawansowana relacyjna baza danych open source.",
         vendors=["PostgreSQL"],
         risk="critical",
         risk_note="Ogranicz dostęp do localhost lub sieci zarządzania. "
                   "Sprawdź pg_hba.conf.", ot=False),

    dict(port=1433, proto="tcp", service="MSSQL",       category="database",
         desc="Microsoft SQL Server — baza danych Microsoft.",
         vendors=["Microsoft SQL Server"],
         risk="critical",
         risk_note="Częsty cel ataków. Nigdy nie wystawiaj na WAN bez VPN. "
                   "xp_cmdshell = exec systemowy.", ot=False),

    dict(port=6379, proto="tcp", service="Redis",       category="database",
         desc="Redis — baza klucz-wartość, cache in-memory.",
         vendors=["Redis"],
         risk="critical",
         risk_note="Domyślnie BEZ hasła i BEZ TLS. Zapis do pliku = RCE. "
                   "Nigdy nie wystawiaj na WAN.", ot=False),

    dict(port=27017, proto="tcp", service="MongoDB",    category="database",
         desc="MongoDB — nierelacyjna baza dokumentów.",
         vendors=["MongoDB"],
         risk="critical",
         risk_note="Historycznie brak uwierzytelnienia domyślnie. "
                   "Setki tysięcy baz publicznie dostępnych. Włącz auth.", ot=False),

    dict(port=9200, proto="tcp", service="Elasticsearch", category="database",
         desc="Elasticsearch — wyszukiwarka / baza analityczna.",
         vendors=["Elastic"],
         risk="critical",
         risk_note="Domyślnie brak uwierzytelnienia w starszych wersjach. "
                   "Ogranicz dostęp do localhost/sieci zarządzania.", ot=False),

    # ── Zarządzanie urządzeniami ───────────────────────────────────────────────
    dict(port=161,  proto="udp", service="SNMP",        category="mgmt",
         desc="Simple Network Management Protocol — monitorowanie i konfiguracja "
              "urządzeń sieciowych. Używany przez NetDoc do enrichmentu.",
         vendors=["Cisco", "MikroTik", "Ubiquiti", "HP/HPE", "Dell", "Fortinet",
                  "wszystkie urządzenia sieciowe"],
         risk="high",
         risk_note="SNMPv1/v2 = community string = hasło jawnym tekstem. "
                   "SNMPv3 z auth+priv jest bezpieczny. Użyj community 'public' tylko "
                   "w izolowanej sieci zarządzania. Wyłącz SNMP write.", ot=False),

    dict(port=162,  proto="udp", service="SNMP-trap",   category="mgmt",
         desc="SNMP Trap — urządzenie wysyła alerty do serwera zarządzania.",
         vendors=["Cisco", "MikroTik", "Ubiquiti", "wszystkie urządzenia sieciowe"],
         risk="medium",
         risk_note="Niskie ryzyko gdy tylko odbiór. Sprawdź kto może wysyłać trapy.", ot=False),

    dict(port=8291, proto="tcp", service="Winbox",      category="mgmt",
         desc="MikroTik Winbox — graficzny interfejs zarządzania routerami MikroTik.",
         vendors=["MikroTik RouterOS"],
         risk="high",
         risk_note="Nie wystawiaj na WAN. Luka CVE-2018-14847 (Winbox critical) — "
                   "aktualizuj RouterOS. Używaj tylko z VPN lub whitelist IP.", ot=False),

    dict(port=8728, proto="tcp", service="MikroTik API", category="mgmt",
         desc="MikroTik API — programowy dostęp do RouterOS (skrypty, NMS).",
         vendors=["MikroTik RouterOS"],
         risk="high",
         risk_note="Ogranicz dostęp do sieci zarządzania. Używaj API-SSL (8729).", ot=False),

    dict(port=8729, proto="tcp", service="MikroTik API-SSL", category="mgmt",
         desc="MikroTik API z SSL/TLS — zaszyfrowana wersja MikroTik API.",
         vendors=["MikroTik RouterOS"],
         risk="medium",
         risk_note="Bezpieczniejsza wersja API. Ogranicz dostęp do sieci zarządzania.", ot=False),

    dict(port=443,  proto="tcp", service="UniFi-HTTPS", category="mgmt",
         desc="Ubiquiti UniFi Controller — HTTPS panel zarządzania.",
         vendors=["Ubiquiti UniFi"],
         risk="low",
         risk_note="Zaszyfrowany. Sprawdź czy dostęp z WAN jest konieczny.", ot=False),

    dict(port=8443, proto="tcp", service="UniFi-mgmt",  category="mgmt",
         desc="Ubiquiti UniFi Controller — port zarządzania (legacy).",
         vendors=["Ubiquiti UniFi Controller"],
         risk="medium",
         risk_note="Ogranicz do sieci zarządzania jeśli nie potrzebujesz zdalnego dostępu.", ot=False),

    dict(port=10001, proto="udp", service="UniFi-disc", category="mgmt",
         desc="Ubiquiti Device Discovery — protokół wykrywania urządzeń UniFi.",
         vendors=["Ubiquiti UniFi"],
         risk="low",
         risk_note="Normalny ruch w sieciach z UniFi. Ogranicz do VLAN zarządzania.", ot=False),

    dict(port=9100, proto="tcp", service="Jetdirect",   category="mgmt",
         desc="HP JetDirect — drukarka sieciowa raw printing port.",
         vendors=["HP", "HPE", "Lexmark", "Samsung", "Kyocera", "Canon"],
         risk="medium",
         risk_note="Umożliwia drukowanie bez uwierzytelnienia. "
                   "Ogranicz dostęp do podsieci biurowej.", ot=False),

    dict(port=515,  proto="tcp", service="LPD",         category="mgmt",
         desc="Line Printer Daemon — protokół drukowania sieciowego.",
         vendors=["drukarki sieciowe (wszystkie)"],
         risk="medium",
         risk_note="Brak uwierzytelnienia. Ogranicz dostęp.", ot=False),

    dict(port=631,  proto="tcp", service="IPP",         category="mgmt",
         desc="Internet Printing Protocol — nowoczesny protokół drukowania (CUPS).",
         vendors=["CUPS (Linux)", "macOS", "drukarki HP/Canon/Epson"],
         risk="medium",
         risk_note="CVE-2024-47176 (CUPS RCE). Blokuj dostęp z Internetu.", ot=False),

    dict(port=6000, proto="tcp", service="X11",         category="mgmt",
         desc="X Window System — protokół graficznego środowiska Linux/Unix.",
         vendors=["Linux/Unix systemy z X11"],
         risk="critical",
         risk_note="X11 przez sieć = pełny dostęp do ekranu i klawiatury. "
                   "Nigdy nie wystawiaj na WAN. Używaj SSH X forwarding.", ot=False),

    # ── Monitoring ─────────────────────────────────────────────────────────────
    dict(port=9090, proto="tcp", service="Prometheus",  category="monitor",
         desc="Prometheus — system monitoringu i time-series database.",
         vendors=["Prometheus (open source)"],
         risk="medium",
         risk_note="Dostęp do danych monitoringu bez uwierzytelnienia w domyślnej konfiguracji. "
                   "Ogranicz do sieci zarządzania.", ot=False),

    dict(port=3000, proto="tcp", service="Grafana",     category="monitor",
         desc="Grafana — platforma wizualizacji i dashboardów dla monitoringu.",
         vendors=["Grafana Labs"],
         risk="medium",
         risk_note="CVE-2021-43798 (path traversal). Aktualizuj. "
                   "Ogranicz dostęp z WAN lub używaj odwrotnego proxy z auth.", ot=False),

    dict(port=2003, proto="tcp", service="Graphite",    category="monitor",
         desc="Graphite Carbon — przyjmowanie metryk time-series.",
         vendors=["Graphite"],
         risk="medium",
         risk_note="Brak uwierzytelnienia — każdy może wstrzyknąć metryki. "
                   "Ogranicz do localhost/sieci wewnętrznej.", ot=False),

    dict(port=8086, proto="tcp", service="InfluxDB",    category="monitor",
         desc="InfluxDB — time-series database, popularna w IoT i monitoringu.",
         vendors=["InfluxData"],
         risk="high",
         risk_note="InfluxDB 1.x domyślnie bez uwierzytelnienia. "
                   "Ogranicz dostęp, włącz auth.", ot=False),

    dict(port=4317, proto="tcp", service="OTLP-gRPC",   category="monitor",
         desc="OpenTelemetry Protocol — zbieranie telemetrii (traces, metrics, logs).",
         vendors=["OpenTelemetry Collector"],
         risk="low",
         risk_note="Ogranicz dostęp do sieci wewnętrznej.", ot=False),

    # ── VPN / Tunelowanie ──────────────────────────────────────────────────────
    dict(port=1194, proto="udp", service="OpenVPN",     category="vpn",
         desc="OpenVPN — popularny protokół VPN open source.",
         vendors=["OpenVPN", "pfSense", "OpenWRT", "MikroTik"],
         risk="low",
         risk_note="Bezpieczny przy aktualnej wersji i silnych certyfikatach.", ot=False),

    dict(port=500,  proto="udp", service="IKE",         category="vpn",
         desc="Internet Key Exchange — negocjacja kluczy dla IPsec VPN.",
         vendors=["Cisco", "Fortinet", "MikroTik", "Juniper", "wszystkie VPN IPsec"],
         risk="low",
         risk_note="Normalny ruch VPN. Sprawdź siłę algorytmów (unikaj 3DES, MD5).", ot=False),

    dict(port=4500, proto="udp", service="IPsec-NAT-T", category="vpn",
         desc="IPsec NAT Traversal — IPsec przez NAT.",
         vendors=["wszystkie implementacje IPsec"],
         risk="low",
         risk_note="Normalny ruch VPN przez NAT.", ot=False),

    dict(port=1723, proto="tcp", service="PPTP",        category="vpn",
         desc="Point-to-Point Tunneling Protocol — przestarzały protokół VPN.",
         vendors=["Windows Server (legacy)", "stare routery"],
         risk="critical",
         risk_note="PPTP jest złamany kryptograficznie od 1999 roku. "
                   "Zastąp OpenVPN, WireGuard lub IPsec.", ot=False),

    dict(port=51820, proto="udp", service="WireGuard",  category="vpn",
         desc="WireGuard — nowoczesny, szybki protokół VPN.",
         vendors=["Linux kernel", "MikroTik (RouterOS 7+)", "pfSense", "OPNsense"],
         risk="low",
         risk_note="Najlepsza opcja VPN. Prosty, szybki, bezpieczny.", ot=False),

    dict(port=443,  proto="tcp", service="SSL-VPN",     category="vpn",
         desc="SSL VPN przez HTTPS. Forticlient, AnyConnect, OpenVPN TCP mode.",
         vendors=["Fortinet FortiGate", "Cisco ASA", "Palo Alto", "Pulse Secure"],
         risk="high",
         risk_note="CVE-2023-27997 (Fortinet SSL VPN RCE) — aktualizuj firmware. "
                   "MFA obowiązkowe.", ot=False),

    # ── Autoryzacja / Katalog ──────────────────────────────────────────────────
    dict(port=389,  proto="tcp", service="LDAP",        category="auth",
         desc="Lightweight Directory Access Protocol — katalog użytkowników (Active Directory).",
         vendors=["Microsoft AD", "OpenLDAP", "Samba"],
         risk="high",
         risk_note="Niezaszyfrowany. Użyj LDAPS (636) lub StartTLS. "
                   "Ogranicz dostęp do sieci wewnętrznej.", ot=False),

    dict(port=636,  proto="tcp", service="LDAPS",       category="auth",
         desc="LDAP over SSL/TLS — zaszyfrowany katalog.",
         vendors=["Microsoft AD", "OpenLDAP"],
         risk="low",
         risk_note="Zaszyfrowany. Sprawdź certyfikat.", ot=False),

    dict(port=88,   proto="tcp", service="Kerberos",    category="auth",
         desc="Kerberos — protokół uwierzytelniania w Active Directory.",
         vendors=["Microsoft Windows / AD", "MIT Kerberos"],
         risk="low",
         risk_note="Normalny ruch AD. Ogranicz do sieci wewnętrznej.", ot=False),

    dict(port=1812, proto="udp", service="RADIUS-auth", category="auth",
         desc="RADIUS — scentralizowane uwierzytelnianie (WiFi 802.1X, VPN, NAS).",
         vendors=["FreeRADIUS", "Cisco ISE", "Microsoft NPS", "Ubiquiti"],
         risk="medium",
         risk_note="Ogranicz dostęp do serwera RADIUS tylko z NAS (switches, AP, VPN).", ot=False),

    # ── Infrastruktura sieciowa ────────────────────────────────────────────────
    dict(port=53,   proto="tcp/udp", service="DNS",     category="network",
         desc="Domain Name System — rozwiązywanie nazw domenowych.",
         vendors=["BIND", "Unbound", "Windows DNS", "routery wszystkich producentów"],
         risk="medium",
         risk_note="Otwarty resolver DNS = amplification DDoS. "
                   "Ogranicz query do sieci wewnętrznej (recursion). "
                   "Sprawdź czy resolver jest otwarty z WAN.", ot=False),

    dict(port=67,   proto="udp", service="DHCP",        category="network",
         desc="DHCP Server — przydzielanie adresów IP w sieci lokalnej.",
         vendors=["routery wszystkich producentów", "ISC DHCP", "Windows DHCP"],
         risk="low",
         risk_note="Normalny ruch LAN. Nie powinien być dostępny z WAN.", ot=False),

    dict(port=179,  proto="tcp", service="BGP",         category="network",
         desc="Border Gateway Protocol — routing między sieciami (Internet backbone).",
         vendors=["Cisco IOS", "Juniper JunOS", "MikroTik", "Bird", "Quagga"],
         risk="high",
         risk_note="BGP hijacking = przekierowanie ruchu Internet. "
                   "Implementuj BGP security (RPKI, MD5 auth, prefix filtering).", ot=False),

    dict(port=520,  proto="udp", service="RIP",         category="network",
         desc="Routing Information Protocol — starszy protokół routingu wewnętrznego.",
         vendors=["starsze routery"],
         risk="medium",
         risk_note="RIPv1 bez uwierzytelnienia — łatwy do sfałszowania. "
                   "Zastąp OSPF lub EIGRP.", ot=False),

    dict(port=5353, proto="udp", service="mDNS",        category="network",
         desc="Multicast DNS (Bonjour/Avahi) — wykrywanie usług w sieci lokalnej.",
         vendors=["Apple (Bonjour)", "Linux (Avahi)", "Chromecast", "AirPrint", "Sonos"],
         risk="low",
         risk_note="Normalne odkrywanie usług LAN. Nie powinno wychodzić poza VLAN.", ot=False),

    dict(port=1900, proto="udp", service="UPnP",        category="network",
         desc="UPnP SSDP — automatyczna konfiguracja urządzeń w sieci domowej.",
         vendors=["Windows", "routery domowe", "drukarki", "NAS", "smart devices"],
         risk="high",
         risk_note="UPnP na WAN = router otwiera porty dla atakującego. "
                   "Wyłącz UPnP na granicznym routerze. "
                   "CVE-2020-12695 (CallStranger).", ot=False),

    # ── Przemysłowe / OT / SCADA ──────────────────────────────────────────────
    dict(port=502,  proto="tcp", service="Modbus TCP",  category="ot",
         desc="Modbus TCP — przemysłowy protokół komunikacji PLC, czujniki, sterowniki. "
              "Powszechny w automatyce budynkowej, energetyce, przemyśle.",
         vendors=["Siemens", "Schneider Electric", "Rockwell Allen-Bradley",
                  "Wago", "Beckhoff", "Fronius", "ABB", "GE"],
         risk="critical",
         risk_note="KRYTYCZNE. Brak uwierzytelnienia i szyfrowania. "
                   "Umożliwia odczyt/zapis rejestrów PLC — manipulacja procesem fizycznym. "
                   "Izoluj w dedykowanej sieci OT. Blokuj z IT/WAN firewallem.", ot=True),

    dict(port=102,  proto="tcp", service="S7comm",      category="ot",
         desc="Siemens S7 Protocol — komunikacja z PLC Siemens SIMATIC S7. "
              "Stuxnet używał tego protokołu.",
         vendors=["Siemens SIMATIC S7-300/400/1200/1500", "WinCC", "TIA Portal"],
         risk="critical",
         risk_note="KRYTYCZNE. Stuxnet atakował przez S7. Brak uwierzytelnienia. "
                   "Absolutna izolacja sieciowa. Nigdy nie łącz z IT/WAN.", ot=True),

    dict(port=47808, proto="udp", service="BACnet",     category="ot",
         desc="BACnet — protokół automatyki budynkowej (HVAC, oświetlenie, alarmy, "
              "dostęp, windy).",
         vendors=["Honeywell", "Johnson Controls", "Siemens Building Tech",
                  "Schneider Electric", "Delta Controls"],
         risk="critical",
         risk_note="Brak uwierzytelnienia. Dostęp z Internetu = kontrola budynku. "
                   "Tysiące systemów BACnet publicznie dostępnych w Internecie. "
                   "Izoluj w sieci zarządzania budynkiem.", ot=True),

    dict(port=4840, proto="tcp", service="OPC-UA",      category="ot",
         desc="OPC Unified Architecture — nowoczesny standard komunikacji OT/IIoT. "
              "Bezpieczniejsza alternatywa dla S7/Modbus.",
         vendors=["Siemens", "ABB", "Rockwell", "Beckhoff", "ICONICS", "Kepware"],
         risk="medium",
         risk_note="Bezpieczniejszy niż Modbus/S7 (ma auth i TLS), ale wymaga "
                   "właściwej konfiguracji. Sprawdź czy anonimowy dostęp jest wyłączony.", ot=True),

    dict(port=20000, proto="tcp", service="DNP3",       category="ot",
         desc="DNP3 — protokół SCADA w energetyce i wodociągach (substacje, RTU).",
         vendors=["GE", "Schweitzer Engineering", "ABB", "Siemens Energy"],
         risk="critical",
         risk_note="Brak uwierzytelnienia w DNP3 Basic. Używany w elektrowniach i "
                   "wodociągach. Atak = wyłączenie zasilania/wody.", ot=True),

    dict(port=44818, proto="tcp", service="EtherNet/IP", category="ot",
         desc="EtherNet/IP — protokół CIP (Rockwell/Allen-Bradley) dla PLC i HMI.",
         vendors=["Rockwell Allen-Bradley", "Omron", "Schneider Electric"],
         risk="critical",
         risk_note="Brak uwierzytelnienia. Dostęp = odczyt/zapis do PLC. "
                   "Izoluj w sieci OT.", ot=True),

    dict(port=1911, proto="tcp", service="Niagara Fox",  category="ot",
         desc="Tridium Niagara Framework — platforma automatyki budynkowej (BMS/BAS).",
         vendors=["Tridium Niagara", "Honeywell", "Distech Controls"],
         risk="high",
         risk_note="CVE-2012-20004 (Niagara Fox exploit). Aktualizuj firmware. "
                   "Ogranicz dostęp do sieci zarządzania.", ot=True),

    dict(port=9600, proto="tcp", service="OMRON-FINS",  category="ot",
         desc="OMRON FINS — komunikacja z PLC Omron przez Ethernet.",
         vendors=["Omron"],
         risk="critical",
         risk_note="Brak uwierzytelnienia. Izoluj w sieci OT.", ot=True),

    # ── IoT / Smart devices ────────────────────────────────────────────────────
    dict(port=1883, proto="tcp", service="MQTT",        category="iot",
         desc="Message Queuing Telemetry Transport — protokół IoT publish/subscribe. "
              "Używany przez czujniki, inteligentne domy, Home Assistant.",
         vendors=["Mosquitto", "Home Assistant", "AWS IoT", "Azure IoT Hub",
                  "różne bramki IoT"],
         risk="high",
         risk_note="Domyślnie bez uwierzytelnienia i szyfrowania. "
                   "Atak = przejęcie urządzeń IoT lub wstrzyknięcie fałszywych danych. "
                   "Używaj MQTT TLS (8883) z auth.", ot=False),

    dict(port=8883, proto="tcp", service="MQTT-TLS",    category="iot",
         desc="MQTT over TLS — zaszyfrowany protokół IoT.",
         vendors=["Mosquitto (TLS)", "AWS IoT", "Azure IoT"],
         risk="low",
         risk_note="Bezpieczny przy aktualnym TLS i wymuszonym auth.", ot=False),

    dict(port=5683, proto="udp", service="CoAP",        category="iot",
         desc="Constrained Application Protocol — lekki protokół IoT (alternatywa HTTP).",
         vendors=["urządzenia IoT z ograniczonymi zasobami", "smart meters"],
         risk="medium",
         risk_note="Brak uwierzytelnienia w wersji podstawowej. "
                   "Używaj CoAP+DTLS.", ot=False),

    dict(port=554,  proto="tcp", service="RTSP",        category="iot",
         desc="Real Time Streaming Protocol — strumień wideo z kamer IP.",
         vendors=["Hikvision", "Dahua", "Axis", "Hanwha", "FLIR", "Vivotek",
                  "Sony", "Bosch Security"],
         risk="high",
         risk_note="Niezaszyfrowany strumień wideo. Domyślne hasła to epidemia. "
                   "Hikvision/Dahua mają znane backdoory w starym firmware. "
                   "Izoluj w VLAN kamer. Blokuj z WAN.", ot=False),

    dict(port=37777, proto="tcp", service="Dahua-mgmt", category="iot",
         desc="Dahua proprietary management protocol — zarządzanie DVR/NVR/kamerami.",
         vendors=["Dahua"],
         risk="critical",
         risk_note="CVE-2021-33044 (auth bypass), CVE-2022-30563. "
                   "Aktualizuj firmware. Blokuj z WAN.", ot=False),

    dict(port=8000, proto="tcp", service="Hikvision-mgmt", category="iot",
         desc="Hikvision SDK port — zarządzanie kamerami i rejestratorami Hikvision.",
         vendors=["Hikvision"],
         risk="critical",
         risk_note="CVE-2021-36260 (Hikvision RCE bez auth). "
                   "Aktualizuj firmware natychmiast. Blokuj z WAN.", ot=False),

    # ── VoIP / Komunikacja ─────────────────────────────────────────────────────
    dict(port=5060, proto="tcp/udp", service="SIP",     category="voip",
         desc="Session Initiation Protocol — nawiązywanie połączeń VoIP.",
         vendors=["Cisco", "Polycom", "Yealink", "Asterisk", "FreePBX",
                  "3CX", "Avaya", "wszystkie systemy VoIP"],
         risk="high",
         risk_note="Toll fraud — atakujący dzwoni na Twój koszt. "
                   "SIP brute-force jest powszechny. Używaj TLS/SRTP, silnych haseł, "
                   "ogranicz dostęp do WAN.", ot=False),

    dict(port=5061, proto="tcp", service="SIP-TLS",     category="voip",
         desc="SIP over TLS — zaszyfrowane sygnalizowanie VoIP.",
         vendors=["Cisco", "Polycom", "Yealink", "3CX"],
         risk="low",
         risk_note="Bezpieczniejsza wersja SIP. Użyj też SRTP dla szyfrowania mediów.", ot=False),

    # ── Media / Streaming ──────────────────────────────────────────────────────
    dict(port=32400, proto="tcp", service="Plex",       category="media",
         desc="Plex Media Server — strumieniowanie multimediów.",
         vendors=["Plex"],
         risk="medium",
         risk_note="Sprawdź czy dostęp z WAN jest konieczny. "
                   "Ogranicz dostęp lub używaj Plex Relay.", ot=False),

    # ── Inne ───────────────────────────────────────────────────────────────────
    dict(port=25,   proto="tcp", service="SMTP",        category="mail",
         desc="Simple Mail Transfer Protocol — wysyłanie poczty.",
         vendors=["Postfix", "Exim", "Microsoft Exchange", "Sendmail"],
         risk="high",
         risk_note="Otwarty relay SMTP = spam rozsyłany przez Twój serwer. "
                   "Sprawdź konfigurację relay i uwierzytelnianie.", ot=False),

    dict(port=587,  proto="tcp", service="SMTP-SUBMIT", category="mail",
         desc="SMTP Submission — wysyłanie poczty z klientów (wymagane STARTTLS+auth).",
         vendors=["Postfix", "Exchange", "Gmail SMTP"],
         risk="medium",
         risk_note="Wymaga uwierzytelnienia. Używaj TLS. Port preferowany nad 25.", ot=False),

    dict(port=993,  proto="tcp", service="IMAPS",       category="mail",
         desc="IMAP over SSL — odbieranie poczty z szyfrowaniem.",
         vendors=["Dovecot", "Cyrus", "Exchange"],
         risk="low",
         risk_note="Zaszyfrowany. Sprawdź certyfikat.", ot=False),

    dict(port=3128, proto="tcp", service="Squid Proxy", category="other",
         desc="Squid HTTP Proxy — serwer pośredniczący dla ruchu HTTP.",
         vendors=["Squid", "serwery proxy"],
         risk="high",
         risk_note="Otwarty proxy = każdy może używać Twojego IP. "
                   "Ogranicz dostęp do sieci wewnętrznej.", ot=False),

    dict(port=6443, proto="tcp", service="Kubernetes API", category="other",
         desc="Kubernetes API Server — zarządzanie klastrem Kubernetes.",
         vendors=["Kubernetes", "k3s", "OpenShift", "EKS/GKE/AKS"],
         risk="critical",
         risk_note="Dostęp do API = pełna kontrola klastra. "
                   "Nigdy nie wystawiaj na WAN bez auth i RBAC.", ot=False),

    dict(port=2375, proto="tcp", service="Docker API",  category="other",
         desc="Docker daemon API (niezaszyfrowany) — zarządzanie kontenerami.",
         vendors=["Docker"],
         risk="critical",
         risk_note="Docker API bez TLS = root na hoście. "
                   "Wyłącz TCP socket lub użyj TLS (port 2376). "
                   "Nigdy nie wystawiaj na WAN.", ot=False),

    dict(port=2376, proto="tcp", service="Docker API-TLS", category="other",
         desc="Docker daemon API z TLS — zaszyfrowane zarządzanie kontenerami.",
         vendors=["Docker"],
         risk="medium",
         risk_note="Zaszyfrowany, ale dostęp = root na hoście. "
                   "Ogranicz do sieci zarządzania.", ot=False),

    # ── Infrastruktura sieciowa (uzupełnienie) ────────────────────────────────
    dict(port=123,  proto="udp", service="NTP",          category="network",
         desc="Network Time Protocol — synchronizacja czasu w sieci. "
              "Używany przez wszystkie urządzenia sieciowe, serwery, kamery, PLC.",
         vendors=["wszystkie urządzenia sieciowe", "Windows", "Linux", "Cisco", "MikroTik"],
         risk="high",
         risk_note="NTP amplification DDoS — jeden pakiet 48B → odpowiedź 4096B (wzmocnienie 86x). "
                   "Wyłącz monlist na publicznych serwerach NTP (ntpdc -c monlist). "
                   "Złe zsynchronizowany czas = błędy TLS, Kerberos, logów i TOTP.", ot=False),

    dict(port=111,  proto="tcp/udp", service="RPCbind",  category="network",
         desc="RPC Portmapper — rejestrator usług RPC (NFS, NIS, mountd). "
              "Pozwala znaleźć port dynamiczny danej usługi RPC.",
         vendors=["Linux/Unix", "Solaris", "FreeBSD", "Synology", "QNAP"],
         risk="high",
         risk_note="Ujawnia mapę uruchomionych usług RPC. "
                   "Amplification DDoS (rpcbomb). "
                   "Blokuj z WAN — służy tylko w sieci lokalnej dla NFS.", ot=False),

    dict(port=135,  proto="tcp", service="MSRPC",        category="network",
         desc="Microsoft RPC Endpoint Mapper — odpowiednik RPCbind dla Windows. "
              "Punkt wejścia dla WMI, DCOM, Exchange, Active Directory.",
         vendors=["Microsoft Windows", "Windows Server"],
         risk="high",
         risk_note="EternalBlue powiązany z RPC. Liczne historyczne exploity (MS03-026, MS04-011). "
                   "Blokuj port 135 na granicy sieci. "
                   "Wymagany wewnętrznie dla AD/WMI.", ot=False),

    dict(port=137,  proto="udp", service="NetBIOS-NS",   category="network",
         desc="NetBIOS Name Service — rozwiązywanie nazw NetBIOS w Windows (starsza alternatywa DNS).",
         vendors=["Microsoft Windows (starsze)", "Samba"],
         risk="medium",
         risk_note="Ujawnia nazwy maszyn, grupy robocze, domeny. "
                   "NBNS poisoning (Responder) = przechwycenie hash NTLM. "
                   "Wyłącz NetBIOS over TCP/IP gdy używasz DNS.", ot=False),

    dict(port=138,  proto="udp", service="NetBIOS-DGM",  category="network",
         desc="NetBIOS Datagram Service — rozgłaszanie usług Windows (browser elections, shares).",
         vendors=["Microsoft Windows (starsze)", "Samba"],
         risk="medium",
         risk_note="Ujawnia informacje o sieci. Wyłącz razem z portem 137.", ot=False),

    dict(port=2222, proto="tcp", service="SSH-alt",       category="remote",
         desc="Alternatywny port SSH — administratorzy przenoszą SSH z 22 na 2222 "
              "żeby ograniczyć automatyczne skanowania botnetów.",
         vendors=["Linux/Unix", "Cisco", "MikroTik", "różne urządzenia sieciowe"],
         risk="medium",
         risk_note="Bezpieczniejszy niż port 22 ze względu na mniejszą liczbę botnetów. "
                   "Ale nie zastępuje silnego hasła lub kluczy. "
                   "Używaj kluczy RSA/ED25519 i wyłącz logowanie hasłem.", ot=False),

    # ── Zdalne zarządzanie Windows (uzupełnienie) ─────────────────────────────
    dict(port=5985, proto="tcp", service="WinRM-HTTP",   category="remote",
         desc="Windows Remote Management (WS-Management) — zdalne zarządzanie PowerShell "
              "i WSMan. Odpowiednik SSH dla Windows (używany przez Ansible, PSSession).",
         vendors=["Microsoft Windows Server 2008+", "Windows 10/11"],
         risk="high",
         risk_note="Niezaszyfrowane połączenie (HTTP). "
                   "Domyślnie dostępny w sieci domenowej. "
                   "Ogranicz dostęp do sieci zarządzania. "
                   "Używaj WinRM-HTTPS (5986) lub tunelu SSH.", ot=False),

    dict(port=5986, proto="tcp", service="WinRM-HTTPS",  category="remote",
         desc="Windows Remote Management over HTTPS — zaszyfrowane zdalne PowerShell.",
         vendors=["Microsoft Windows Server", "Windows 10/11"],
         risk="medium",
         risk_note="Zaszyfrowany. Sprawdź certyfikat. "
                   "Ogranicz dostęp do sieci zarządzania i wymagaj uwierzytelnienia.", ot=False),

    dict(port=3283, proto="tcp", service="Apple Remote Desktop", category="remote",
         desc="Apple Remote Desktop (ARD) — graficzny zdalny pulpit macOS.",
         vendors=["Apple macOS"],
         risk="high",
         risk_note="Nie wystawiaj na WAN. Wymaga silnego hasła i MFA. "
                   "Historycznie luki w implementacji VNC pod spodem.", ot=False),

    # ── Zarządzanie sieciowe (uzupełnienie) ────────────────────────────────────
    dict(port=830,  proto="tcp", service="NETCONF",      category="mgmt",
         desc="Network Configuration Protocol (NETCONF over SSH) — nowoczesny protokół "
              "konfiguracji urządzeń sieciowych (następca SNMP write). Używany przez NSO, "
              "Ansible, Terraform dla konfiguracji routerów i przełączników.",
         vendors=["Cisco IOS-XE/XR/NX-OS", "Juniper JunOS", "Huawei", "Nokia SR OS",
                  "Arista EOS", "Fortinet (FortiOS 7+)"],
         risk="medium",
         risk_note="Zaszyfrowany (SSH). Pełna kontrola konfiguracji urządzenia. "
                   "Ogranicz dostęp do sieci zarządzania i NMS. "
                   "Używaj dedykowanych kluczy SSH dla automatyzacji.", ot=False),

    dict(port=4786, proto="tcp", service="Cisco Smart Install", category="mgmt",
         desc="Cisco Smart Install (vstack) — protokół auto-konfiguracji nowych przełączników "
              "Cisco IOS/IOS-XE. Dyrektor Smart Install zarządza przez TCP 4786 zestawem klientów "
              "(nowe switche), wysyłając im konfigurację i obraz IOS przez TFTP.",
         vendors=["Cisco IOS", "Cisco IOS-XE", "Cisco Catalyst", "Cisco 2960/3750/3850"],
         risk="critical",
         risk_note="KRYTYCZNE. CVE-2018-0171 (CVSS 9.8) — protokół bez uwierzytelnienia. "
                   "Atakujący może odczytać i nadpisać konfigurację, skopiować ją na TFTP "
                   "(z hasłami enable/VTY), wymusić reload lub załadować złośliwy obraz IOS. "
                   "Port 4786 open = pełne przejęcie urządzenia bez żadnych credentiali. "
                   "Cisco zaleca wyłączenie: 'no vstack'. Jeśli wymagane — ogranicz ACL "
                   "tylko do IP dyrektora Smart Install.", ot=False),

    dict(port=623,  proto="udp", service="IPMI/IPMB",    category="mgmt",
         desc="Intelligent Platform Management Interface — zarządzanie serwerem "
              "sprzętowo (poza systemem operacyjnym). Używany przez iDRAC (Dell), "
              "iLO (HPE), IPMI (Supermicro). Pozwala włączyć/wyłączyć serwer, "
              "montować ISO, dostęp do konsoli KVM — niezależnie od OS.",
         vendors=["Dell iDRAC", "HPE iLO", "Supermicro BMC", "Lenovo XCC",
                  "IBM IMM", "wszystkie serwery rack"],
         risk="critical",
         risk_note="KRYTYCZNE. IPMI domyślnie na każdym porcie managementu serwera. "
                   "CVE-2013-4786 (IPMI 2.0 RAKP — hash administratora offline). "
                   "Cipher Suite 0 (brak uwierzytelnienia) aktywny na wielu BMC. "
                   "Nigdy nie wystawiaj IPMI na WAN lub na sieć produkcyjną. "
                   "Umieść w dedykowanym VLAN OOB (Out-of-Band).", ot=False),

    dict(port=443,  proto="tcp", service="iDRAC/iLO HTTPS", category="mgmt",
         desc="HTTPS panele zarządzania serwerów: Dell iDRAC, HPE iLO, Supermicro BMC — "
              "dostęp do KVM, konsoli, montowania ISO, aktualizacji firmware.",
         vendors=["Dell iDRAC", "HPE iLO", "Supermicro BMC", "Lenovo XCC"],
         risk="high",
         risk_note="Dostęp do BMC = pełna kontrola fizyczna serwera. "
                   "Domyślne hasła (admin/admin, root/calvin) = krytyczne ryzyko. "
                   "Umieść w dedykowanym VLAN OOB, zmień hasła, włącz MFA.", ot=False),

    # ── Poczta (uzupełnienie) ──────────────────────────────────────────────────
    dict(port=110,  proto="tcp", service="POP3",         category="mail",
         desc="Post Office Protocol v3 — odbieranie poczty przez klienta (Outlook, Thunderbird). "
              "Protokół bez szyfrowania — niezaszyfrowane hasła i treść.",
         vendors=["Dovecot", "Cyrus IMAP", "Microsoft Exchange", "Postfix"],
         risk="high",
         risk_note="Hasła i treść poczty przesyłane jawnym tekstem. "
                   "Używaj POP3S (995) lub IMAPS (993). "
                   "Wyłącz POP3 tam gdzie możliwe.", ot=False),

    dict(port=143,  proto="tcp", service="IMAP",         category="mail",
         desc="Internet Message Access Protocol — synchronizacja poczty między serwerem "
              "a klientem. Niezaszyfrowany.",
         vendors=["Dovecot", "Cyrus", "Exchange", "Zimbra"],
         risk="high",
         risk_note="Hasła przesyłane jawnym tekstem. Używaj IMAPS (993). "
                   "Wyłącz IMAP bez TLS.", ot=False),

    dict(port=465,  proto="tcp", service="SMTPS",        category="mail",
         desc="SMTP over SSL (implicit TLS) — wysyłanie poczty z szyfrowaniem. "
              "Starszy standard, ale nadal szeroko obsługiwany.",
         vendors=["Postfix", "Exchange", "Gmail", "Sendgrid"],
         risk="low",
         risk_note="Zaszyfrowany. Sprawdź certyfikat i wersję TLS.", ot=False),

    dict(port=995,  proto="tcp", service="POP3S",        category="mail",
         desc="POP3 over SSL — zaszyfrowane odbieranie poczty.",
         vendors=["Dovecot", "Exchange", "Gmail"],
         risk="low",
         risk_note="Zaszyfrowany. Preferuj IMAPS (993) nad POP3S.", ot=False),

    # ── Bazy danych (uzupełnienie) ─────────────────────────────────────────────
    dict(port=1521, proto="tcp", service="Oracle DB",    category="database",
         desc="Oracle Database — korporacyjna baza danych. Port TNS Listener.",
         vendors=["Oracle Database", "Oracle RAC"],
         risk="critical",
         risk_note="TNS Listener podatny na zdalne wykonanie kodu w starszych wersjach. "
                   "Domyślne konta (scott/tiger, sys/change_on_install). "
                   "Nigdy nie wystawiaj na WAN. Wymagaj silnej autentykacji.", ot=False),

    dict(port=9042, proto="tcp", service="Cassandra CQL", category="database",
         desc="Apache Cassandra — NoSQL baza danych, CQL protocol. "
              "Używana w wysokodostępnych systemach (Netflix, Discord, Uber).",
         vendors=["Apache Cassandra", "DataStax Enterprise", "ScyllaDB"],
         risk="critical",
         risk_note="Domyślnie brak uwierzytelnienia i szyfrowania. "
                   "Ogranicz dostęp do sieci wewnętrznej. Włącz auth i TLS.", ot=False),

    dict(port=5672, proto="tcp", service="AMQP",         category="database",
         desc="Advanced Message Queuing Protocol — RabbitMQ broker wiadomości. "
              "Używany do kolejkowania zadań, komunikacji między mikroserwisami.",
         vendors=["RabbitMQ", "Azure Service Bus", "ActiveMQ"],
         risk="high",
         risk_note="Domyślne konto guest/guest dostępne tylko z localhost, ale "
                   "inne konta mogą mieć słabe hasła. "
                   "Ogranicz dostęp do sieci wewnętrznej. Używaj TLS (5671).", ot=False),

    dict(port=5671, proto="tcp", service="AMQP-TLS",     category="database",
         desc="AMQP over TLS — zaszyfrowany RabbitMQ.",
         vendors=["RabbitMQ", "Azure Service Bus"],
         risk="medium",
         risk_note="Zaszyfrowany. Sprawdź certyfikat i uprawnienia użytkowników.", ot=False),

    dict(port=15672, proto="tcp", service="RabbitMQ-mgmt", category="database",
         desc="RabbitMQ Management UI — panel webowy do zarządzania kolejkami, "
              "użytkownikami i topologią brokera.",
         vendors=["RabbitMQ"],
         risk="high",
         risk_note="Panel admin — domyślne konto guest/guest aktywne. "
                   "Ogranicz dostęp do sieci zarządzania. Zmień hasła.", ot=False),

    dict(port=9092, proto="tcp", service="Kafka",        category="database",
         desc="Apache Kafka — platforma strumieniowania zdarzeń / broker wiadomości. "
              "Serce systemów big data (Confluent, LinkedIn, Uber).",
         vendors=["Apache Kafka", "Confluent Platform", "Azure Event Hubs"],
         risk="critical",
         risk_note="Domyślnie brak uwierzytelnienia i szyfrowania. "
                   "Dostęp = odczyt/zapis wszystkich tematów (events). "
                   "Włącz SASL + TLS. Ogranicz dostęp do sieci wewnętrznej.", ot=False),

    dict(port=2181, proto="tcp", service="Zookeeper",    category="database",
         desc="Apache Zookeeper — koordynacja rozproszonych usług (Kafka, Hadoop, HBase). "
              "Przechowuje konfiguracje, leader election, service discovery.",
         vendors=["Apache Kafka", "Apache Hadoop", "HBase", "Solr"],
         risk="critical",
         risk_note="Brak uwierzytelnienia w domyślnej konfiguracji. "
                   "Dostęp = pełna kontrola nad Kafką/Hadoopem. "
                   "Ogranicz dostęp do sieci wewnętrznej.", ot=False),

    dict(port=61616, proto="tcp", service="ActiveMQ",    category="database",
         desc="Apache ActiveMQ — broker wiadomości JMS. Używany w aplikacjach Java EE.",
         vendors=["Apache ActiveMQ", "Red Hat AMQ"],
         risk="critical",
         risk_note="CVE-2023-46604 (ActiveMQ RCE — CVSS 10.0, aktywnie exploitowany). "
                   "Aktualizuj do 5.15.16+/5.16.7+/5.17.6+/5.18.3+. "
                   "Ogranicz dostęp do sieci wewnętrznej.", ot=False),

    dict(port=8161, proto="tcp", service="ActiveMQ-Web", category="database",
         desc="ActiveMQ Web Console — panel zarządzania brokerem ActiveMQ.",
         vendors=["Apache ActiveMQ"],
         risk="high",
         risk_note="Domyślne konto admin/admin. "
                   "Ogranicz dostęp. CVE-2023-46604 dotyczy też web.", ot=False),

    dict(port=5984, proto="tcp", service="CouchDB",      category="database",
         desc="Apache CouchDB — dokumentowa baza danych z REST API przez HTTP.",
         vendors=["Apache CouchDB", "IBM Cloudant"],
         risk="critical",
         risk_note="Historycznie brak uwierzytelnienia domyślnie ('Admin Party'). "
                   "CVE-2017-12635 (privilege escalation). "
                   "Włącz wymagane uwierzytelnienie, ogranicz dostęp.", ot=False),

    # ── Przemysłowe OT (uzupełnienie) ──────────────────────────────────────────
    dict(port=2404, proto="tcp", service="IEC-60870-5-104", category="ot",
         desc="IEC 60870-5-104 — protokół SCADA dla energetyki i sieci elektroenergetycznych. "
              "Używany do monitorowania i sterowania stacjami elektroenergetycznymi, "
              "podstacjami, licznikami smart grid.",
         vendors=["Siemens Energy", "ABB", "Schneider Electric", "GE Grid Solutions",
                  "Eaton", "liczniki smart grid"],
         risk="critical",
         risk_note="KRYTYCZNE. Brak uwierzytelnienia. Kontrola infrastruktury energetycznej. "
                   "Atak może wyłączyć zasilanie. Absolutna izolacja sieci OT od IT/WAN. "
                   "Użyj firewalla ICS i white-listingu źródeł.", ot=True),

    dict(port=1962, proto="tcp", service="PCWorx",        category="ot",
         desc="Phoenix Contact PCWorx — protokół PLC i systemów automatyki "
              "Phoenix Contact (ILC, AXC, RFC).",
         vendors=["Phoenix Contact ILC", "Phoenix Contact AXC", "Phoenix Contact RFC"],
         risk="critical",
         risk_note="Brak uwierzytelnienia. Dostęp = odczyt/zapis rejestrów PLC. "
                   "Izoluj w sieci OT. Blokuj z IT/WAN.", ot=True),

    dict(port=2455, proto="tcp", service="WAGO-IO",       category="ot",
         desc="WAGO I/O System — programowanie i serwis sterowników WAGO PFC.",
         vendors=["WAGO PFC200", "WAGO PFC100", "WAGO e!COCKPIT"],
         risk="critical",
         risk_note="Brak uwierzytelnienia w starszych firmware. "
                   "Dostęp = modyfikacja programu PLC. Izoluj w sieci OT.", ot=True),

    dict(port=10000, proto="tcp", service="Modbus-GW",    category="ot",
         desc="Modbus TCP gateway — alternatywny port dla bramek Modbus/przemysłowych.",
         vendors=["różne bramki OT", "Moxa", "Advantech"],
         risk="critical",
         risk_note="Takie samo ryzyko jak Modbus TCP (502) — brak auth i szyfrowania. "
                   "Izoluj w sieci OT.", ot=True),

    # ── IoT (uzupełnienie) ─────────────────────────────────────────────────────
    dict(port=7547, proto="tcp", service="TR-069/CWMP",   category="iot",
         desc="TR-069 / CWMP (CPE WAN Management Protocol) — zdalny protokół zarządzania "
              "routerami przez operatora ISP. Operator może przez niego aktualizować firmware, "
              "zmieniać konfigurację, resetować router klienta.",
         vendors=["routery domowe (TP-Link, ZyXEL, AVM Fritz!Box, Huawei HG)",
                  "ISP provisioning systems (ACS servers)"],
         risk="critical",
         risk_note="Masowo wykorzystywany przez Mirai i pochodne. "
                   "CVE-2014-9222 (Misfortune Cookie — auth bypass). "
                   "Setki tysięcy routerów z TR-069 dostępnych z WAN. "
                   "Jeśli nie jesteś ISP — zablokuj ten port na firewallu.", ot=False),

    dict(port=8554, proto="tcp", service="RTSP-alt",      category="iot",
         desc="Alternatywny port RTSP — strumień wideo z kamer IP. "
              "Używany gdy port 554 jest zajęty.",
         vendors=["Hikvision", "Dahua", "różne kamery IP"],
         risk="high",
         risk_note="Taka sama podatność jak RTSP (554). "
                   "Niezaszyfrowany strumień. Izoluj w VLAN kamer.", ot=False),

    dict(port=9000, proto="tcp", service="Portainer",     category="other",
         desc="Portainer — webowy panel zarządzania Docker i Kubernetes.",
         vendors=["Portainer.io"],
         risk="critical",
         risk_note="Portainer = pełna kontrola Dockera (= root na hoście). "
                   "Ogranicz dostęp do sieci zarządzania lub VPN. "
                   "Wymagaj silnego hasła i MFA.", ot=False),

    dict(port=8123, proto="tcp", service="Home Assistant", category="iot",
         desc="Home Assistant — platforma automatyki domowej. "
              "Zarządza żarówkami, zamkami, alarmami, kamerami, ogrzewaniem.",
         vendors=["Home Assistant (Nabu Casa)", "HASS.io"],
         risk="high",
         risk_note="Dostęp z WAN bez VPN to ryzyko — HA kontroluje fizyczne urządzenia. "
                   "Używaj Nabu Casa lub VPN zamiast otwartego portu. "
                   "CVE-2023-27482 (auth bypass). Aktualizuj HA.", ot=False),

    # ── Monitoring (uzupełnienie) ──────────────────────────────────────────────
    dict(port=514,  proto="udp", service="Syslog",        category="monitor",
         desc="Syslog — zbieranie logów systemowych z urządzeń sieciowych, serwerów. "
              "Standard dla Cisco, MikroTik, Linux, kamer.",
         vendors=["wszystkie urządzenia sieciowe", "Linux", "Cisco", "Fortinet"],
         risk="medium",
         risk_note="Niezaszyfrowany. Logi mogą zawierać wrażliwe informacje. "
                   "Użyj Syslog TLS (6514). "
                   "Fałszowanie logów — ogranicz kto może wysyłać logi.", ot=False),

    dict(port=6514, proto="tcp", service="Syslog-TLS",    category="monitor",
         desc="Syslog over TLS — zaszyfrowane zbieranie logów (RFC 5425).",
         vendors=["rsyslog", "syslog-ng", "Graylog", "Splunk"],
         risk="low",
         risk_note="Bezpieczniejsza wersja syslog. Sprawdź certyfikaty.", ot=False),

    dict(port=9093, proto="tcp", service="Alertmanager",  category="monitor",
         desc="Prometheus Alertmanager — zarządzanie alertami, grupowanie, routing "
              "do Slack/PagerDuty/e-mail.",
         vendors=["Prometheus Alertmanager"],
         risk="medium",
         risk_note="Domyślnie bez uwierzytelnienia. "
                   "Dostęp = wyciszenie alertów bezpieczeństwa. "
                   "Ogranicz do sieci zarządzania.", ot=False),

    dict(port=9100, proto="tcp", service="Node Exporter", category="monitor",
         desc="Prometheus Node Exporter — eksportuje metryki systemu Linux "
              "(CPU, RAM, dysk, sieć) do Prometheus.",
         vendors=["Prometheus Node Exporter"],
         risk="medium",
         risk_note="Ujawnia szczegółowe informacje o systemie (ścieżki, procesy, zasoby). "
                   "Ogranicz dostęp do sieci monitoringu.", ot=False),

    # ── Inne / Aplikacje (uzupełnienie) ────────────────────────────────────────
    dict(port=8009, proto="tcp", service="AJP",           category="other",
         desc="Apache JServ Protocol — wewnętrzna komunikacja między Apache httpd "
              "a Tomcat/WildFly (przez mod_jk/mod_proxy_ajp). Nigdy nie powinien "
              "być dostępny z zewnątrz.",
         vendors=["Apache Tomcat", "WildFly/JBoss", "GlassFish", "WebSphere"],
         risk="critical",
         risk_note="CVE-2020-1938 'Ghostcat' — odczyt dowolnych plików z webaplikacji "
                   "i RCE bez uwierzytelnienia. CVSS 9.8. "
                   "Zablokuj port 8009 na firewallu lub wyłącz AJP Connector w server.xml. "
                   "Tysiące podatnych Tomcatów w Internecie.", ot=False),

    dict(port=7001, proto="tcp", service="WebLogic",      category="other",
         desc="Oracle WebLogic Server — serwer aplikacji Java EE. "
              "Wiele podatnych instancji dostępnych w Internecie.",
         vendors=["Oracle WebLogic Server"],
         risk="critical",
         risk_note="Wielokrotnie exploitowany przez ransomware (CVE-2023-21839, "
                   "CVE-2020-14882, CVE-2019-2725). "
                   "Aktualizuj natychmiast. Zablokuj z WAN.", ot=False),

    dict(port=4848, proto="tcp", service="GlassFish-Admin", category="other",
         desc="GlassFish Application Server Admin Console — panel zarządzania "
              "serwerem aplikacji Java EE.",
         vendors=["Oracle GlassFish", "Eclipse GlassFish", "Payara"],
         risk="high",
         risk_note="Domyślnie dostępny bez hasła na localhost. "
                   "CVE-2011-1511 (auth bypass). Ogranicz dostęp.", ot=False),

    dict(port=873,  proto="tcp", service="rsync",         category="file",
         desc="rsync daemon — synchronizacja i backup plików między serwerami. "
              "Popularny do backupów Linux, NAS, mirror repozytoriów.",
         vendors=["rsync (Linux/Unix)", "Synology", "QNAP", "TrueNAS"],
         risk="critical",
         risk_note="CVE-2024-12084 (rsync RCE — styczeń 2025, CVSS 9.8). "
                   "Anonimowy dostęp = odczyt/nadpisanie plików. "
                   "Nigdy nie wystawiaj na WAN bez auth. Ogranicz przez hosts allow.", ot=False),

    dict(port=8500, proto="tcp", service="Consul",        category="other",
         desc="HashiCorp Consul — service discovery, health checking, key-value store, "
              "service mesh. Używany w infrastrukturze cloud-native.",
         vendors=["HashiCorp Consul"],
         risk="critical",
         risk_note="Domyślnie bez ACL — każdy może czytać/pisać do K/V store "
                   "i modyfikować rejestr usług. "
                   "Włącz ACL. Ogranicz do sieci zarządzania.", ot=False),

    dict(port=8983, proto="tcp", service="Solr Admin",    category="other",
         desc="Apache Solr — wyszukiwarka enterprise. Panel admin na tym porcie.",
         vendors=["Apache Solr"],
         risk="critical",
         risk_note="CVE-2019-0193 (DataImportHandler RCE). "
                   "Brak uwierzytelnienia w starszych wersjach. "
                   "Ogranicz dostęp do localhost/sieci zarządzania.", ot=False),

    dict(port=5000, proto="tcp", service="Flask/Docker-Registry", category="other",
         desc="Popularny port dla aplikacji Flask (Python), lokalnych Docker Registry "
              "i wielu innych usług deweloperskich.",
         vendors=["Flask (Python)", "Docker Registry", "różne aplikacje dev"],
         risk="high",
         risk_note="Aplikacje Flask domyślnie w trybie debug = RCE przez debugger. "
                   "Docker Registry bez auth = push/pull dowolnych obrazów. "
                   "Wyłącz debug w produkcji. Zabezpiecz Registry hasłem.", ot=False),

    dict(port=4369, proto="tcp", service="EPMD",          category="other",
         desc="Erlang Port Mapper Daemon — służy do komunikacji między węzłami Erlang. "
              "Używany przez RabbitMQ, CouchDB, Ejabberd.",
         vendors=["RabbitMQ", "Apache CouchDB", "Ejabberd", "aplikacje Erlang/Elixir"],
         risk="high",
         risk_note="Ujawnia listę węzłów Erlang i ich porty. "
                   "Atakujący może połączyć się z węzłem Erlang jeśli cookie jest znany. "
                   "Ogranicz dostęp do sieci wewnętrznej.", ot=False),

    dict(port=1701, proto="udp", service="L2TP",          category="vpn",
         desc="Layer 2 Tunneling Protocol — protokół VPN, zwykle używany z IPsec (L2TP/IPsec). "
              "Wbudowany w Windows, macOS, iOS, Android.",
         vendors=["Microsoft Windows", "Cisco", "MikroTik", "macOS/iOS/Android"],
         risk="medium",
         risk_note="L2TP bez IPsec = brak szyfrowania. "
                   "L2TP/IPsec jest bezpieczny ale wolniejszy niż WireGuard. "
                   "Rozważ migrację na WireGuard lub IKEv2.", ot=False),

    dict(port=3268, proto="tcp", service="Global Catalog", category="auth",
         desc="LDAP Global Catalog — przeszukiwanie całego lasu Active Directory "
              "(wszystkich domen w lesie AD).",
         vendors=["Microsoft Active Directory"],
         risk="medium",
         risk_note="Niezaszyfrowany. Używaj GC over SSL (3269). "
                   "Ogranicz do sieci domenowej.", ot=False),

    dict(port=3269, proto="tcp", service="Global Catalog SSL", category="auth",
         desc="LDAP Global Catalog over SSL — zaszyfrowane przeszukiwanie lasu AD.",
         vendors=["Microsoft Active Directory"],
         risk="low",
         risk_note="Zaszyfrowany. Sprawdź certyfikat DC.", ot=False),

    dict(port=8008, proto="tcp", service="HTTP-Chromecast", category="web",
         desc="Alternatywny port HTTP — używany przez Google Chromecast, "
              "niektóre routery i aplikacje webowe.",
         vendors=["Google Chromecast", "Google Home", "routery TP-Link"],
         risk="medium",
         risk_note="Chromecast API bez uwierzytelnienia w sieci lokalnej. "
                   "Nie powinien być dostępny z WAN.", ot=False),

    dict(port=9090, proto="tcp", service="Cockpit",        category="mgmt",
         desc="Cockpit — webowy interfejs zarządzania serwerem Linux "
              "(systemd, kontenery, aktualizacje, sieć, logi).",
         vendors=["Red Hat RHEL", "Fedora", "CentOS", "Debian (opcjonalnie)"],
         risk="high",
         risk_note="Pełny dostęp do zarządzania serwerem przez przeglądarkę. "
                   "Ogranicz dostęp do sieci zarządzania lub VPN. "
                   "Wymagaj silnych haseł systemowych.", ot=False),
]

# Indeks port → lista wpisów (wiele wpisów może mieć ten sam port)
_PORT_INDEX: dict[int, list[dict]] = {}
for _entry in PORT_KB:
    _PORT_INDEX.setdefault(_entry["port"], []).append(_entry)


def lookup_port(port: int) -> list[dict]:
    """Zwraca listę wpisów encyklopedii dla danego numeru portu."""
    return _PORT_INDEX.get(port, [])


def lookup_ports(ports: list[int]) -> dict[int, list[dict]]:
    """Zwraca słownik port → wpisy dla listy portów."""
    return {p: _PORT_INDEX[p] for p in ports if p in _PORT_INDEX}
