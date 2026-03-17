# NetDoc — Roadmap

> Publiczna mapa rozwoju projektu. Szczegółowy backlog dostępny dla kontrybutorów po kontakcie.

## Zrealizowane (v0.2.x)

- Syslog pipeline — rsyslog → Vector → ClickHouse (archiwizacja logów sieciowych)
- Dashboard Grafana Syslog (severity, top urządzenia, top programy, tabela logów)
- Filtrowanie logów po severity, urządzeniu, programie, czasie i treści

## Aktualnie w trakcie (v0.2.x)

- SNMP Walk — pobieranie tablic ARP, routing, LLDP z routerów i switchy
- Mapa topologii sieci (graf połączeń L2/L3)
- WMI/WinRM enrichment dla urządzeń Windows
- ipCidrRouteTable support (Cisco IOS 12.x+)

## Planowane (v0.3.x)

- Alerty email (SMTP) + webhook forwarding
- Eksport raportów PDF
- **NetFlow / sFlow** — analiza ruchu sieciowego, wykrywanie anomalii (eksfiltracja, lateral movement)
- **NIS2 / DORA Compliance Pack** — retencja logów 12 mies., raporty compliance, export dla audytorów
- **Threat Intelligence** — sprawdzanie IP i domen z blacklistami (AbuseIPDB, Spamhaus DROP/EDROP, URLhaus, abuse.ch); alert gdy urządzenie nawiąże połączenie z infrastrukturą malware/ransomware/C2
- Integracja z Zabbix — auto-provisioning wykrytych urządzeń
- Mapa topologii w UI

## Planowane (v0.4.x)

- Autentykacja multi-user (OAuth2 / SSO)
- EoL/EoS daty per model urządzenia (End-of-Life badge)
- CVE per model (NVD feed)
- Wykrywanie serwisów infrastruktury (DHCP, DNS, AD, NTP)
- **DNS Monitoring** — integracja z Pi-hole / Unbound; zbieranie logów DNS zapytań z sieci, wykrywanie zapytań do złośliwych domen, historia połączeń per urządzenie (wymagane NIS2 Art. 21)
- **Integracje z systemami bezpieczeństwa (Pro)** — korelacja "który asset jest atakowany" → pełen kontekst dla NIS2 Art. 21(2)(b):
  Wazuh (SIEM alerts → asset), Suricata/Zeek (IDS/IPS + logi połączeń per host), CrowdSec (threat intel), Elastic/Splunk (SIEM forward)

## Długoterminowe

- Automatyczne raporty cykliczne (PDF/email co tydzień/miesiąc)
- Notatki per urządzenie
- Architektura SaaS / multi-tenant
- Integracja z Suricatą (IP reputation snapshot)
- Historia połączeń sieciowych per urządzenie — "kto z kim gadał" (NetFlow + DNS + Threat Intel)
- **AI Anomaly Detection (offline)** — lokalny model AI (Ollama/Isolation Forest) analizujący logi syslog bez wysyłania danych na zewnątrz; wykrywanie anomalii: nagły wzrost liczby błędów, nowe nieznane urządzenia w logach, sekwencje zdarzeń typowe dla ataku (failed login → scan → success); działa bez dodatkowych kosztów API

## Demo Lab

Repozytorium zawiera środowisko testowe (`docker-compose.lab.yml`) z symulowanymi urządzeniami:
- Siemens S7-1200 PLC (Modbus/502)
- Schneider Modicon M340 (licznik energii)
- MikroTik RB750 router (SNMP + Telnet)
- Cisco-like switch (SSH)
- Panel HMI WebServer (HTTP)

```bash
docker compose -f docker-compose.lab.yml up -d
```

---

*Masz pomysł na funkcję? Otwórz Issue na GitHub.*
