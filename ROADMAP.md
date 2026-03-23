# NetDoc — Roadmap

> Public development roadmap. Detailed backlog available for contributors on request.

## Completed (v0.2.x)

- Syslog pipeline — rsyslog → Vector → ClickHouse (network log archiving)
- Grafana Syslog dashboard (severity, top devices, top programs, log table)
- Log filtering by severity, device, program, time range and content

## In progress (v0.2.x)

- SNMP Walk — fetching ARP tables, routing, LLDP from routers and switches
- Network topology map (L2/L3 connection graph)
- WMI/WinRM enrichment for Windows devices
- ipCidrRouteTable support (Cisco IOS 12.x+)

## Planned (v0.3.x)

- Email alerts (SMTP) + webhook forwarding
- PDF report export
- **NetFlow / sFlow** — network traffic analysis, anomaly detection (exfiltration, lateral movement)
- **NIS2 / DORA Compliance Pack** — 12-month log retention, compliance reports, auditor export
- **Threat Intelligence** — checking IPs and domains against blocklists (AbuseIPDB, Spamhaus DROP/EDROP, URLhaus, abuse.ch); alert when a device connects to malware/ransomware/C2 infrastructure
- Zabbix integration — auto-provisioning of discovered devices
- Topology map in UI

## Planned (v0.4.x)

- Multi-user authentication (OAuth2 / SSO)
- EoL/EoS dates per device model (End-of-Life badge)
- CVE per model (NVD feed)
- Infrastructure service detection (DHCP, DNS, AD, NTP)
- **DNS Monitoring** — Pi-hole / Unbound integration; collecting DNS query logs from the network, detecting queries to malicious domains, per-device connection history (required by NIS2 Art. 21)
- **Security system integrations (Pro)** — correlating "which asset is under attack" → full context for NIS2 Art. 21(2)(b):
  Wazuh (SIEM alerts → asset), Suricata/Zeek (IDS/IPS + per-host connection logs), CrowdSec (threat intel), Elastic/Splunk (SIEM forward)

## Long-term

- Automated recurring reports (PDF/email weekly/monthly)
- Per-device notes
- SaaS / multi-tenant architecture
- Suricata integration (IP reputation snapshot)
- Per-device network connection history — "who talked to whom" (NetFlow + DNS + Threat Intel)
- **AI Anomaly Detection (offline)** — local AI model (Ollama/Isolation Forest) analyzing syslog without sending data externally; anomaly detection: sudden spike in error count, new unknown devices in logs, event sequences typical of an attack (failed login → scan → success); runs without additional API costs
- **GNS3 integration** — scanning virtual network topologies built with real Cisco IOS, Juniper and MikroTik images; testing NetDoc before production deployment, verifying vulnerability detectability and L2/L3 topology mapping in a controlled environment

## Demo Lab

The repository includes a test environment (`docker-compose.lab.yml`) with simulated devices — 16 hosts covering a typical industrial and office network:

**OT / Industrial:**

- Siemens S7-1200 PLC (Modbus/502, SNMP)
- Schneider Modicon M340 — energy meter (Modbus/502, SNMP)
- ABB AC500 — tank controller (Modbus/502, SNMP)
- Fronius Symo 15.0 — photovoltaic inverter (Modbus/502, HTTP, SNMP)
- MOXA NPort W2150A — RS-232/Ethernet converter (Telnet/23, HTTP, SNMP)

**Network / Infrastructure:**

- MikroTik RB750 router (SNMP, Telnet/23)
- Cisco-like switch (SSH)
- HMI WebServer panel (HTTP)
- Ubiquiti UniFi AP AC Pro (HTTP, SNMP)

**IP Cameras / Recorders:**

- Dahua IPC-HDW2831T — IP camera (ONVIF/80, RTSP/554, Dahua port/37777, SNMP)
- Hikvision DS-2CD2143G2 — IP camera (RTSP/554, XMEye port/34567, HTTP, SNMP)

**Office / Server devices:**

- HP LaserJet M404n — network printer (HTTP, JetDirect/9100, SNMP)
- Synology DS920+ NAS (HTTP, FTP anonymous/21, SNMP)
- APC Smart-UPS 1500 (HTTP, Telnet/23, SNMP)
- Ubuntu Server 22.04 (Redis/6379, MQTT/1883, Docker API/2375, HTTP, SNMP)
- Windows Server 2019 (RDP/3389, VNC no password/5900, HTTP, SNMP)

```bash
docker compose -f docker-compose.lab.yml up -d
```

---

*Have a feature idea? Open an Issue on GitHub.*
