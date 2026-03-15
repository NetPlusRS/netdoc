"""Baza wiedzy — poradniki bezpieczeństwa sieciowego.

Artykuły powiązane z tym co wykrywa skaner NetDoc.
Każdy artykuł zawiera: id, title, icon, tags, summary, sections[].
"""

GUIDES = [
    {
        "id": "guest-network",
        "title": "Sieć gości — jak powinna wyglądać",
        "icon": "bi-wifi",
        "tags": ["sieć gości", "VLAN", "izolacja", "WiFi"],
        "summary": (
            "Sieć gości (guest WiFi) powinna zapewniać dostęp do internetu "
            "bez możliwości dostępu do zasobów firmowych. Kluczowe elementy to "
            "izolacja klientów, osobny VLAN i ograniczenia pasma."
        ),
        "sections": [
            {
                "title": "Co to jest sieć gości",
                "content": (
                    "Sieć gości to wydzielona sieć WiFi przeznaczona dla odwiedzających, "
                    "gości lub urządzeń IoT, które nie powinny mieć dostępu do zasobów "
                    "wewnętrznych firmy. Goście otrzymują dostęp do internetu, ale są "
                    "odizolowani od sieci produkcyjnej, serwerów i innych urządzeń."
                ),
            },
            {
                "title": "Wymagane zabezpieczenia",
                "content": None,
                "checklist": [
                    ("Client isolation (AP Isolation)", True,
                     "Urządzenia w sieci gości nie widzą się nawzajem. "
                     "Goście mogą dotrzeć tylko do routera (internet), nie do innych gości."),
                    ("Osobny VLAN", True,
                     "Ruch gości powinien być w osobnym VLAN (np. VLAN 10) "
                     "oddzielonym od sieci produkcyjnej (VLAN 1/20/itd.)."),
                    ("Firewall między VLAN-ami", True,
                     "Reguła 'deny guest → lan' — goście nie mogą inicjować połączeń "
                     "do sieci wewnętrznej. Ruch w drugą stronę też powinien być zablokowany."),
                    ("Osobne hasło / portal captive", True,
                     "Inne hasło niż sieć firmowa. Opcjonalnie portal captive "
                     "z akceptacją regulaminu i logowaniem."),
                    ("Rate limiting / QoS", False,
                     "Ograniczenie przepustowości na gościa (np. 10 Mbps down/2 Mbps up) "
                     "zapobiega monopolizacji łącza przez jednego użytkownika."),
                    ("Brak dostępu do paneli zarządczych", True,
                     "Router, switche, NAS, serwery druku — żaden z tych zasobów "
                     "nie powinien być osiągalny z sieci gości."),
                    ("Monitoring ruchu", False,
                     "Logowanie połączeń gości (DNS, flow) — przydatne w przypadku "
                     "incydentu bezpieczeństwa lub naruszenia prawa."),
                ],
            },
            {
                "title": "Typowe błędy",
                "content": None,
                "warnings": [
                    "Sieć gości w tym samym VLAN co sieć firmowa — goście mają dostęp do zasobów wewnętrznych.",
                    "Brak client isolation — goście widzą się nawzajem, możliwy atak man-in-the-middle.",
                    "Panel zarządczy routera dostępny z sieci gości (port 80/443 na domyślnym GW).",
                    "Ten sam SSID i hasło co sieć firmowa — brak oddzielenia logicznego.",
                    "Urządzenia zarządcze (serwer, NAS, workstation admina) w tej samej podsieci co goście.",
                ],
            },
            {
                "title": "Jak sprawdzić poprawność konfiguracji",
                "content": (
                    "NetDoc wykrywa urządzenia widoczne z perspektywy skanera. "
                    "Przy poprawnie skonfigurowanej izolacji klientów skaner zobaczy "
                    "tylko hosty, które aktywnie komunikowały się z siecią (ARP). "
                    "Pełny obraz wszystkich podłączonych gości daje SNMP walk "
                    "na ARP table routera (OID 1.3.6.1.2.1.4.22) — to zaawansowana funkcja "
                    "planowana w kolejnej wersji NetDoc."
                ),
            },
        ],
    },
    {
        "id": "snmp-security",
        "title": "SNMP — bezpieczeństwo i zagrożenia",
        "icon": "bi-broadcast",
        "tags": ["SNMP", "community", "podatność", "UDP 161"],
        "summary": (
            "SNMP (Simple Network Management Protocol) to protokół zarządzania "
            "urządzeniami sieciowymi. Community string 'public' bez autentykacji "
            "to jedna z najczęstszych podatności w sieciach korporacyjnych."
        ),
        "sections": [
            {
                "title": "Czym jest SNMP",
                "content": (
                    "SNMP działa na UDP port 161 i umożliwia odpytywanie urządzeń sieciowych "
                    "o ich stan: nazwę hosta, opis systemu, wersję oprogramowania, listę interfejsów, "
                    "tablicę routingu, tablicę ARP, liczbę przesłanych pakietów i wiele więcej. "
                    "W wersji SNMPv1/v2c autentykacja opiera się wyłącznie na 'community string' — "
                    "hasłu przesyłanym otwartym tekstem w każdym pakiecie UDP."
                ),
            },
            {
                "title": "Dlaczego 'public' to podatność",
                "content": (
                    "Domyślny community string 'public' jest znany każdemu — to jak zostawienie "
                    "klucza pod wycieraczką. Atakujący z dostępem do sieci może:"
                ),
                "bullets": [
                    "Pobrać pełną tablicę ARP routera → odkryć wszystkie hosty w sieci (nawet ukryte)",
                    "Odczytać tablicę routingu → zrozumieć topologię sieci",
                    "Pobrać listę wszystkich interfejsów i VLAN-ów",
                    "Odczytać wersję firmware, model urządzenia → identyfikacja podatnych wersji",
                    "W SNMPv2c z community 'private' — zmienić konfigurację urządzenia (zapis)",
                    "Wykonać SNMP walk → pobrać całą bazę MIB urządzenia w kilka sekund",
                ],
            },
            {
                "title": "Jak wykrywa to NetDoc",
                "content": (
                    "NetDoc wysyła pakiet UDP SNMP GET na port 161 z community='public'. "
                    "Jeśli urządzenie odpowie — podatność jest potwierdzona. "
                    "Sam fakt posiadania community='public' w bazie credentiali "
                    "nie jest wystarczający — skaner weryfikuje to przez realny pakiet UDP "
                    "zanim oznaczy urządzenie jako podatne."
                ),
            },
            {
                "title": "Jak zabezpieczyć",
                "content": None,
                "checklist": [
                    ("Zmień community string z 'public' na losowe", True,
                     "Minimum 16 znaków, mix liter/cyfr/znaków specjalnych. "
                     "Inne dla read-only (RO) i read-write (RW)."),
                    ("Przejdź na SNMPv3", True,
                     "SNMPv3 oferuje prawdziwą autentykację (MD5/SHA) i szyfrowanie (DES/AES). "
                     "Brak community string — używa użytkownika i hasła."),
                    ("ACL na porcie UDP 161", True,
                     "Ogranicz dostęp do SNMP tylko dla adresów IP systemów monitoringu "
                     "(np. Zabbix, PRTG, NetDoc). Blokuj dostęp z sieci gości i internetu."),
                    ("Wyłącz SNMP jeśli nieużywane", True,
                     "Jeśli nie monitorujesz urządzenia przez SNMP — wyłącz usługę całkowicie."),
                    ("Ogranicz widoczność MIB", False,
                     "Niektóre urządzenia pozwalają ograniczyć które OID-y są dostępne "
                     "przez SNMP — ogranicz do minimum potrzebnego do monitoringu."),
                ],
            },
        ],
    },
    {
        "id": "network-segmentation",
        "title": "Segmentacja sieci — VLAN i strefy bezpieczeństwa",
        "icon": "bi-diagram-3",
        "tags": ["VLAN", "DMZ", "segmentacja", "firewall", "strefy"],
        "summary": (
            "Segmentacja sieci to podział infrastruktury na izolowane strefy "
            "z kontrolowanym ruchem między nimi. To podstawa bezpiecznej architektury — "
            "ogranicza zasięg ataku i chroni krytyczne zasoby."
        ),
        "sections": [
            {
                "title": "Po co segmentować sieć",
                "content": (
                    "W płaskiej sieci (jeden VLAN dla wszystkich) — zainfekowany laptop gościa "
                    "lub urządzenie IoT ma bezpośredni dostęp do serwerów, drukarek, kamer "
                    "i wszystkich innych urządzeń. Segmentacja ogranicza ten zasięg: "
                    "kompromitacja jednej strefy nie daje automatycznie dostępu do pozostałych."
                ),
            },
            {
                "title": "Typowe strefy bezpieczeństwa",
                "content": None,
                "bullets": [
                    "LAN / strefa produkcyjna — komputery pracowników, serwery plików, drukarki",
                    "Serwery — dedykowany VLAN dla serwerów (ogranicza lateral movement)",
                    "DMZ — serwery publicznie dostępne (web, mail, VPN gateway)",
                    "Zarządzanie (Management) — interfejsy zarządcze routerów, switchów, IPMI/BMC",
                    "IoT — kamery, czujniki, smart TV — izolowane od reszty",
                    "Goście (Guest) — dostęp tylko do internetu",
                    "OT/SCADA — systemy przemysłowe, BMS — najsurowsza izolacja",
                ],
            },
            {
                "title": "Jak NetDoc pomaga w segmentacji",
                "content": (
                    "NetDoc wykrywa urządzenia i ich typy (router, AP, kamera, workstation, serwer, IoT). "
                    "Jeśli kamera IP lub urządzenie IoT pojawia się w sieci produkcyjnej — "
                    "to sygnał że segmentacja jest nieprawidłowa. "
                    "Mapa sieci (zakładka Sieci) pokazuje które podsieci istnieją "
                    "i ile urządzeń każdego typu się w nich znajduje."
                ),
            },
            {
                "title": "Reguły firewall między strefami",
                "content": None,
                "checklist": [
                    ("Goście → LAN: DENY", True, "Goście nie mogą inicjować połączeń do sieci wewnętrznej."),
                    ("IoT → LAN: DENY (poza wyjątkami)", True,
                     "Kamera może potrzebować dostępu do NVR — reszta powinna być zablokowana."),
                    ("LAN → DMZ: ograniczone", True,
                     "Tylko konkretne porty do konkretnych serwerów w DMZ."),
                    ("Internet → DMZ: tylko publikowane usługi", True,
                     "Np. tylko TCP 443 do serwera web, TCP 25 do mail."),
                    ("Management VLAN: dostęp tylko dla adminów", True,
                     "Tylko stacje robocze administratorów mogą dotrzeć do interfejsów zarządczych."),
                ],
            },
        ],
    },
    {
        "id": "dangerous-protocols",
        "title": "Niebezpieczne protokoły — Telnet, FTP, HTTP",
        "icon": "bi-exclamation-triangle",
        "tags": ["Telnet", "FTP", "HTTP", "podatność", "szyfrowanie"],
        "summary": (
            "Telnet, FTP i nieszyfrowany HTTP to protokoły przesyłające dane "
            "otwartym tekstem. Każdy kto może podsłuchać ruch sieciowy "
            "widzi hasła, komendy i dane. NetDoc wykrywa je jako podatności high/medium."
        ),
        "sections": [
            {
                "title": "Telnet (port 23)",
                "content": (
                    "Telnet przesyła wszystko — w tym hasła — otwartym tekstem przez sieć. "
                    "Zastąpiony przez SSH w 1995 roku, ale wciąż aktywny na starszych routerach, "
                    "switchwch, kamerach IP i urządzeniach OT. "
                    "Atakujący w tej samej sieci (np. na WiFi) widzi każdą wpisaną komendę "
                    "używając prostego sniffera (Wireshark, tcpdump)."
                ),
                "checklist": [
                    ("Wyłącz Telnet, włącz SSH", True, "SSH szyfruje całą sesję. Dla starych urządzeń bez SSH — wymień firmware lub sprzęt."),
                    ("ACL blokujące port 23", True, "Jeśli Telnet musi być włączony — ogranicz dostęp tylko do konkretnych adresów IP."),
                ],
            },
            {
                "title": "FTP (port 21) i Anonymous FTP",
                "content": (
                    "FTP przesyła hasła i dane otwartym tekstem (jak Telnet). "
                    "Anonymous FTP (bez hasła) to podatność sama w sobie — "
                    "każdy może się zalogować i pobrać/wysłać pliki. "
                    "Alternatywy: SFTP (SSH), FTPS (FTP+TLS), SCP."
                ),
            },
            {
                "title": "HTTP bez HTTPS (panel zarządczy)",
                "content": (
                    "Panel zarządczy routera, switcha, kamery lub drukarki dostępny "
                    "przez HTTP (port 80) — hasło admina leci otwartym tekstem. "
                    "Szczególnie niebezpieczne jeśli panel jest dostępny z sieci gości "
                    "lub internetu. NetDoc flaguje to jako 'http_management'."
                ),
                "checklist": [
                    ("Wymuś HTTPS", True, "Wyłącz HTTP, zostaw tylko HTTPS (port 443)."),
                    ("Ogranicz dostęp do panelu", True, "Panel zarządczy tylko z VLAN-u zarządzającego lub konkretnych IP."),
                    ("Zmień domyślne hasło", True, "admin/admin, admin/password — pierwsze co sprawdza atakujący."),
                ],
            },
        ],
    },
    {
        "id": "ipmi-amt-security",
        "title": "Intel AMT i IPMI — zdalne zarządzanie firmware",
        "icon": "bi-cpu",
        "tags": ["Intel AMT", "IPMI", "BMC", "podatność", "port 623"],
        "summary": (
            "Intel AMT (Active Management Technology) i IPMI/BMC to interfejsy "
            "do zdalnego zarządzania sprzętem — niezależnie od systemu operacyjnego. "
            "Działają nawet gdy komputer jest wyłączony. Nieodpowiednio zabezpieczone "
            "stanowią krytyczną podatność."
        ),
        "sections": [
            {
                "title": "Czym jest Intel AMT",
                "content": (
                    "Intel AMT (Active Management Technology) to technologia wbudowana "
                    "w procesory Intel vPro. Działa na osobnym mikroprocesorze (ME — Management Engine) "
                    "niezależnie od głównego procesora i systemu operacyjnego. "
                    "Umożliwia zdalny dostęp, restart, instalację systemu i diagnostykę "
                    "nawet gdy komputer jest wyłączony lub OS jest zawieszony. "
                    "Działa na portach TCP 623 i 16992 (HTTP) / 16993 (HTTPS)."
                ),
            },
            {
                "title": "Dlaczego to zagrożenie",
                "content": None,
                "bullets": [
                    "CVE-2017-5689 — krytyczna podatność w Intel AMT pozwalająca zalogować się bez hasła (CVSS 9.8)",
                    "Dostęp do AMT = pełna kontrola nad sprzętem niezależnie od OS i oprogramowania zabezpieczającego",
                    "KVM (Keyboard-Video-Mouse) przez AMT — atakujący widzi ekran i może sterować myszą/klawiaturą",
                    "IPMI z domyślnymi hasłami (admin/admin, ADMIN/ADMIN) — powszechne na serwerach",
                    "Dostęp do iDRAC (Dell), iLO (HP) z internetu lub sieci gości — pełna kontrola serwera",
                ],
            },
            {
                "title": "Jak zabezpieczyć",
                "content": None,
                "checklist": [
                    ("Wyłącz AMT jeśli nieużywane", True,
                     "W BIOS/UEFI → Advanced → AMT Configuration → wyłącz. "
                     "Dla większości stacji roboczych AMT nie jest potrzebne."),
                    ("Ustaw silne hasło AMT", True,
                     "Domyślne hasło to 'admin' — zmień natychmiast."),
                    ("Ogranicz AMT/IPMI do VLAN zarządzania", True,
                     "Porty 623, 16992, 16993 dostępne tylko z dedykowanego VLAN-u Management."),
                    ("Zablokuj AMT z sieci gości", True,
                     "Żadne urządzenie zarządzane nie powinno być w sieci gości."),
                    ("Aktualizuj firmware ME/BMC", True,
                     "Intel regularnie wydaje poprawki do ME. "
                     "Sprawdź wersję i zaktualizuj do najnowszej."),
                    ("Monitoruj dostęp", False,
                     "Logi AMT/BMC powinny być wysyłane do syslog i monitorowane przez SIEM."),
                ],
            },
            {
                "title": "Jak NetDoc to wykrywa",
                "content": (
                    "NetDoc wykrywa otwarty port 623 TCP (IPMI/AMT) jako podatność 'ipmi_exposed'. "
                    "Urządzenia z portami 623 i 16992 są klasyfikowane jako workstation (Intel vPro) "
                    "lub serwer. Jeśli takie urządzenie pojawia się w sieci gości — "
                    "to sygnał krytycznego błędu konfiguracji."
                ),
            },
        ],
    },
    {
        "id": "default-credentials",
        "title": "Domyślne hasła — najczęstszy wektor ataku",
        "icon": "bi-key",
        "tags": ["hasła", "credentials", "brute force", "domyślne", "SSH"],
        "summary": (
            "Większość urządzeń sieciowych ma fabrycznie ustawione hasła (admin/admin, "
            "root/root, user/user). To pierwszy wektor sprawdzany przez atakujących "
            "i automatyczne narzędzia. NetDoc testuje setki domyślnych kombinacji "
            "na wykrytych urządzeniach."
        ),
        "sections": [
            {
                "title": "Skala problemu",
                "content": (
                    "Badania pokazują że ponad 15% urządzeń sieciowych w sieciach korporacyjnych "
                    "ma niezmienione domyślne hasła. Routery, switche, kamery IP, drukarki, "
                    "NAS-y, UPS-y — każdy producent ma swoje domyślne hasło, a lista tych haseł "
                    "jest publicznie dostępna (SecLists, routerpasswords.com, domainz.in). "
                    "Robaki takie jak Mirai zainfekuowały miliony urządzeń IoT właśnie przez "
                    "domyślne hasła Telnetu."
                ),
            },
            {
                "title": "Jak NetDoc testuje credentials",
                "content": (
                    "Cred-worker (worker działający w tle) testuje kombinacje login/hasło "
                    "przez SSH, HTTP, FTP i RDP na wszystkich aktywnych urządzeniach. "
                    "Baza zawiera setki domyślnych par dla popularnych producentów: "
                    "Cisco, MikroTik, Ubiquiti, Hikvision, HP, Fortinet i innych. "
                    "Jeśli logowanie się powiedzie — credential jest zapisany w bazie "
                    "i urządzenie jest oznaczone jako 'posiada działające credentials'."
                ),
            },
            {
                "title": "Co zrobić po wykryciu",
                "content": None,
                "checklist": [
                    ("Natychmiast zmień hasło", True,
                     "Zaloguj się na urządzenie i ustaw silne, unikalne hasło. "
                     "Minimum 12 znaków, wielkie/małe litery, cyfry, znaki specjalne."),
                    ("Wyłącz konto domyślne", True,
                     "Wiele urządzeń pozwala wyłączyć lub zmienić nazwę konta 'admin'. "
                     "Użyj innej nazwy użytkownika."),
                    ("Włącz 2FA gdzie możliwe", False,
                     "SSH z kluczem zamiast hasła, TOTP w panelach web."),
                    ("Wyłącz niepotrzebne protokoły", True,
                     "Jeśli nie używasz SSH — wyłącz. Jeśli nie używasz HTTP — wyłącz. "
                     "Każdy otwarty port to potencjalny wektor."),
                    ("Ogranicz dostęp do zarządzania", True,
                     "ACL/firewall: dostęp do SSH/HTTP zarządczego tylko z VLAN zarządzania."),
                ],
            },
        ],
    },
    {
        "id": "rtsp-camera-security",
        "title": "Kamery IP i RTSP — bezpieczeństwo monitoringu",
        "icon": "bi-camera-video",
        "tags": ["kamera", "RTSP", "ONVIF", "NVR", "IoT"],
        "summary": (
            "Kamery IP z otwartym streamem RTSP bez autentykacji lub z domyślnymi hasłami "
            "to jeden z najczęściej kompromitowanych typów urządzeń. "
            "Dostęp do obrazu z kamer to poważne naruszenie prywatności i bezpieczeństwa."
        ),
        "sections": [
            {
                "title": "Jak NetDoc wykrywa kamery",
                "content": (
                    "Skaner wykrywa kamery przez: vendora MAC (Hikvision, Dahua, Axis, Uniview), "
                    "otwarte porty (80/443/554/8000/8080), bannery HTTP "
                    "i odpowiedź na protokół RTSP (port 554). "
                    "Kamery bez autentykacji RTSP są flagowane jako 'rtsp_noauth' — "
                    "każdy w sieci może oglądać obraz bez hasła."
                ),
            },
            {
                "title": "Typowe podatności kamer IP",
                "content": None,
                "bullets": [
                    "RTSP bez hasła: rtsp://192.168.x.x/stream — dostępny bez logowania",
                    "Domyślne hasło HTTP: admin/admin, admin/12345, admin/password",
                    "Przestarzały firmware z krytycznymi podatnościami (Hikvision CVE-2021-36260, Dahua CVE-2021-33044)",
                    "ONVIF bez autentykacji — automatyczne wykrycie i konfiguracja bez hasła",
                    "Kamery w tej samej sieci co serwery — dostęp do kamery = dostęp do sieci",
                    "Dostęp do NVR/DVR z internetu bez VPN",
                ],
            },
            {
                "title": "Jak zabezpieczyć",
                "content": None,
                "checklist": [
                    ("Wydziel kamery w osobnym VLAN IoT", True,
                     "Kamery powinny mieć dostęp tylko do NVR. Brak dostępu do internetu "
                     "i innych sieci (chyba że wymagane przez producenta — minimum)."),
                    ("Zmień domyślne hasło na każdej kamerze", True,
                     "Używaj unikalnego hasła dla każdej kamery."),
                    ("Włącz autentykację RTSP", True,
                     "Digest authentication dla RTSP. Sprawdź ustawienia w panelu kamery."),
                    ("Aktualizuj firmware", True,
                     "Hikvision, Dahua i inne marki regularnie łatają krytyczne podatności."),
                    ("Zablokuj dostęp kamer do internetu", True,
                     "Firewall: deny IoT VLAN → WAN. Kamery nie potrzebują internetu "
                     "(chyba że używasz cloud storage — rozważ czy to konieczne)."),
                    ("NVR/DVR — brak ekspozycji na internet", True,
                     "Dostęp zdalny przez VPN, nie przez port-forwarding."),
                ],
            },
        ],
    },
]

# Indeks po id
GUIDES_BY_ID = {g["id"]: g for g in GUIDES}
