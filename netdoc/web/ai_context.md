# NetDoc AI Context
# Ten plik jest automatycznie ladowany przez chat_agent.py jako kontekst statyczny dla AI.
# Aktualizuj go przy kazdej istotnej zmianie architektury lub funkcjonalnosci systemu.

## CZYM JEST NETDOC

NetDoc to system do automatycznego wykrywania, dokumentowania i monitorowania infrastruktury sieciowej,
niezalezny od producenta (Cisco, MikroTik, Ubiquiti, Fortinet, HPE i inne).
System skanuje siec lokalna i zbiera dane o:
- Urzadzeniach sieciowych: routery, switche, punkty dostepu WiFi, serwery, kamery IP, drukarki, urzadzenia IoT/przemyslowe
- Statusie dostepnosci: ciagle pingowanie, wykrywanie awarii w czasie rzeczywistym (ping co ~18s)
- Podatnosciach bezpieczenstwa: otwarte porty, domyslne hasla, niezabezpieczone uslugi (Telnet, FTP, HTTP)
- Poswiadczeniach: automatyczne testowanie SSH/HTTP/RDP/FTP z baza hasel (cred-worker)
- Danych SNMP: hostname, opis systemu, lokalizacja, wersja systemu operacyjnego urzadzen
- Laczu internetowym: DNS, latencja HTTP, jitter, predkosc pobierania i wysylania (speed test)
- Zaufanych urzadzeniach: administrator moze oznaczyc urzadzenia jako zaufane z kategoria i notatka

## ARCHITEKTURA SYSTEMU

Docker Compose (9 kontenerow):
- postgres (port 15432): baza danych PostgreSQL — przechowuje wszystkie dane
- api (port 8000): REST API (FastAPI) — endpoint dla workerow i panelu web
- web (port 5000): panel administracyjny (Flask) — interfejs uzytkownika + AI chat
- grafana (port 3000): dashboardy wizualizacji danych sieciowych
- prometheus (port 9090): zbieranie metryk z workerow
- ping-worker (port 8001): ciagle pingowanie urzadzen ICMP co ~18s — wykrywa awarie
- snmp-worker (port 8002): SNMP enrichment co 5 min — hostname, opis, lokalizacja, OS urzadzen
- cred-worker (port 8003): testowanie SSH/HTTP/RDP/FTP z baza hasel co 60s (1 cykl ~13-20 min)
- vuln-worker (port 8004): skanowanie podatnosci TCP co 2 min (~67s na 15 urzadzen)
- internet-worker (port 8005): monitorowanie lacza WAN — DNS, HTTP latencja, speed test

Skan odkrycia: run_scanner.py (HOST Windows) — pelny dostep do sieci i tabeli ARP,
wykrywa nowe urzadzenia przez ping sweep + nmap, zapisuje do bazy.

## FUNKCJONALNOSCI

Panel webowy (Flask, port 5000):
- Zakladka Urzadzenia: lista wszystkich wykrytych urzadzen z filtrami
- Zakladka Podatnosci: lista wykrytych podatnosci bezpieczenstwa z poziomami zagrozenia
- Zakladka Poswiadczenia: status testowania hasel per urzadzenie, rotacja par
- Zakladka Internet: status lacza WAN, publiczne IP, DNS, speed test
- Zakladka Grafana: wbudowane dashboardy Grafana
- Asystent AI: chatbot NetDoc AI z dostepem do danych w czasie rzeczywistym (ten modul)
- Historia czatu: archiwum rozmow z AI

Oznaczanie urzadzen jako zaufanych:
- Administrator moze oznaczyc urzadzenie jako ZAUFANE z kategoria (infrastructure/endpoint/iot/guest/other)
- Zaufane urzadzenia sa uwzglednianie przy analizie ryzyka przez AI
- Nowe nieoznaczone urzadzenia traktowane jako potencjalnie ryzykowne

## SRODOWISKO TESTOWE (Lab)

Dostepna opcjonalna siec laboratoryjna (`docker-compose.lab.yml`) z symulowanymi urzadzeniami:
- 172.28.0.10 — Siemens S7-200 PLC (Conpot: Modbus/502, S7/102, SNMP, Telnet, FTP, HTTP)
- 172.28.0.11 — Kamstrup licznik energii (Conpot: Modbus, SNMP, HTTP)
- 172.28.0.12 — Guardian AST zbiornik paliwa (Conpot: Modbus, SNMP, HTTP)
- 172.28.0.20 — MikroTik RB750 router (snmpd: SNMP z sysDescr MikroTik, Telnet bez hasla)
- 172.28.0.30 — Cisco IOS switch (SSH ze slabymi haslami: admin/admin, cisco/cisco)
- 172.28.0.40 — Panel HMI WebServer (HTTP z formularzem logowania SCADA)
Podsiec lab: 172.28.0.0/24 (dodaj do NETWORK_RANGES w .env aby skanowac)
GNS3 planowany do integracji — symulacja sieci routerow/switchow Cisco/MikroTik.

## OSTATNIE ZMIANY (aktualizuj przy istotnych zmianach)

2026-03-08 v0.1.9:
- Dodano modul Asystenta AI (chat_agent.py) z dostepem do danych w czasie rzeczywistym
- Dodano oznaczanie urzadzen jako zaufanych (is_trusted, trust_category, trust_note)
- Dodano cred-worker: automatyczne testowanie SSH/HTTP/RDP/FTP z rotacja hasel
- Dodano vuln-worker: skanowanie podatnosci TCP
- Dodano internet-worker: monitorowanie lacza WAN
- Dodano _web_detect_auth: pomijanie urzadzen bez strony logowania (np. Philips Hue)
- Panel szybkich raportow AI z 7 predefiniowanymi pytaniami
- Eksport rozmowy AI do PDF przez drukowanie przegladarki
