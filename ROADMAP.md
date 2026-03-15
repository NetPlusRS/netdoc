# NetDoc — Roadmap

> Publiczna mapa rozwoju projektu. Szczegółowy backlog dostępny dla kontrybutorów po kontakcie.

## Aktualnie w trakcie (v0.2.x)

- SNMP Walk — pobieranie tablic ARP, routing, LLDP z routerów i switchy
- Mapa topologii sieci (graf połączeń L2/L3)
- WMI/WinRM enrichment dla urządzeń Windows
- ipCidrRouteTable support (Cisco IOS 12.x+)

## Planowane (v0.3.x)

- Alerty email (SMTP) + webhook forwarding
- Eksport raportów PDF
- Integracja z Zabbix — auto-provisioning wykrytych urządzeń
- Mapa topologii w UI

## Planowane (v0.4.x)

- Autentykacja multi-user (OAuth2 / SSO)
- EoL/EoS daty per model urządzenia (End-of-Life badge)
- CVE per model (NVD feed)
- Wykrywanie serwisów infrastruktury (DHCP, DNS, AD, NTP)

## Długoterminowe

- Automatyczne raporty cykliczne (PDF/email co tydzień/miesiąc)
- Notatki per urządzenie
- Architektura SaaS / multi-tenant
- Integracja z Suricatą (IP reputation snapshot)
- NetFlow/sFlow analiza ruchu

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
