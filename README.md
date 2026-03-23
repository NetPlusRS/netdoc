# NetDoc Collector

**Universal Network Discovery & Documentation System**

Automatic discovery, documentation and monitoring of network infrastructure.
Vendor-agnostic — Cisco, MikroTik, Ubiquiti, Fortinet and more.

🌐 **[netdoc.pl](https://netdoc.pl)** — project website with demo, screenshots and feature overview

> **⚠️ Beta Release — please read before running in a production network**
>
> Network scanning may cause unintended side effects:
>
> - **Printers** may print garbage (port 9100 / JetDirect scan)
> - **Older IoT devices and switches** may freeze or reboot under scanner traffic
> - **Full port scan** (1–65535) generates significant traffic and may trigger IDS/IPS systems
>
> **Recommended starting environment:** test network, lab, or the included Demo Lab (`docker compose -f docker-compose.lab.yml up`).

---

## Screenshots

| Device panel | Security |
|---|---|
| ![Devices](docs/screenshots/devices.png) | ![Security](docs/screenshots/security.png) |

| Inventory (S/N, warranty, prices) | Credentials — network coverage |
|---|---|
| ![Inventory](docs/screenshots/inventory.png) | ![Credentials](docs/screenshots/credentials.png) |

| AI Chat — vulnerability analysis | AI Chat — MOXA device (OT) |
|---|---|
| ![AI Security](docs/screenshots/ai_chat_security.png) | ![AI MOXA](docs/screenshots/ai_device_moxa.png) |

| Syslog — network logs | Grafana — network overview |
|---|---|
| ![Syslog](docs/screenshots/syslog.png) | ![Grafana](docs/screenshots/grafana_main.png) |

---

## Architecture

```
Network devices
  ├─ syslog UDP/TCP 514 → rsyslog → Vector → ClickHouse
  └─ nmap/ARP/SNMP ──→ Collector (host) → PostgreSQL → API (FastAPI)
                                                     ↓
                                              Flask Web Admin
                                                     ↑
                                   Docker workers (ping, snmp, cred, vuln,
                                                   community, internet)
```

| Layer | Technologies |
|-------|-------------|
| **Collector** | nmap, netmiko, pysnmp-lextudio, APScheduler |
| **Storage** | PostgreSQL (prod) / SQLite (dev), ClickHouse (syslog) |
| **API** | FastAPI + Uvicorn + Prometheus metrics |
| **Monitoring** | Grafana + Prometheus + Loki + Promtail |
| **Syslog pipeline** | rsyslog → Vector → ClickHouse |
| **Admin UI** | Flask web panel (via nginx, port 80) |

---

## Quick start — Windows (recommended)

Download the repository and double-click:

```
netdoc-setup.bat
```

The installer automatically:

- checks and installs requirements (WSL2, Docker Desktop, git, Python 3.11+)
- configures `.env` from the template
- starts all Docker containers
- verifies the state of 17 containers
- runs the first network scan
- opens the admin panel in the browser

Requirements: Windows 10 v2004+ (Build 19041), 8 GB RAM, ~10 GB free disk space.

> **Before starting Docker:** Docker Desktop → Settings → Advanced →
> enable *Allow the default Docker socket to be used* (required by web and promtail).

### Stop / uninstall

```
netdoc-uninstall.bat
```

Menu:

- **[1]** Stop containers — data preserved
- **[2]** Full uninstall — removes containers, volumes, Task Scheduler tasks

---

## Quick start — manual (Linux / macOS / Windows without installer)

**Requirements:** Docker + Docker Compose v2 (`docker compose`, not `docker-compose`), Python 3.10+, nmap in PATH.

```bash
# Linux/macOS
cp .env.example .env
# Edit .env if needed (NETWORK_RANGES, CLICKHOUSE_PASSWORD etc.)

docker compose up -d
```

```
# Windows cmd
copy .env.example .env
docker compose up -d
```

> **Linux — port 514 (syslog):** If network devices send syslog to the host,
> make sure the firewall allows port 514/UDP and 514/TCP from the local network:
> `sudo ufw allow 514/udp && sudo ufw allow 514/tcp`

| Service | URL |
|---------|-----|
| NetDoc Admin (Flask) | <http://localhost> |
| NetDoc API (FastAPI) | <http://localhost:8000> |
| Swagger UI | <http://localhost:8000/docs> |
| Grafana | <http://localhost/grafana> |
| Prometheus | <http://localhost:9090> |
| Loki | <http://localhost:3100> |
| ClickHouse HTTP | <http://localhost:8123> |

Default Grafana password: `admin / netdoc`

The scanner runs on the host (full network access, ARP table):

```bash
# Linux/macOS: make sure nmap is installed
# sudo apt install nmap   (Debian/Ubuntu)
# brew install nmap       (macOS)

pip install -r requirements.txt
python run_scanner.py --once
```

### Receiving syslog from network devices

Configure network devices (routers, switches, APs) to send syslog UDP to port 514
of the host running NetDoc. Logs will automatically flow into ClickHouse and appear
in the **Syslog** tab (NetDoc Pro) and on the Grafana dashboard.

### Autostart (Windows Task Scheduler)

```powershell
powershell -ExecutionPolicy Bypass -File install_autostart.ps1
```

---

## Configuration (.env)

```bash
cp .env.example .env
# Edit .env — network ranges, Telegram, SNMP community
```

Key variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `NETWORK_RANGES` | CIDR ranges to scan | auto-detect |
| `SCAN_INTERVAL_MINUTES` | Scan frequency | 5 |
| `LOG_LEVEL` | Log level | INFO |
| `FLASK_SECRET_KEY` | Flask session key | dev-only |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token for alerts | optional |
| `CLICKHOUSE_PASSWORD` | ClickHouse password (syslog) | netdoc |

When `NETWORK_RANGES` is empty, the system automatically detects local subnets.

---

## Development setup

```bash
# Install dependencies
pip install -r requirements-dev.txt

# Database (PostgreSQL in Docker)
docker compose up -d postgres

# API
uvicorn netdoc.api.main:app --reload --port 8000

# Flask Admin UI
flask --app netdoc.web.app run --port 5000

# Scanner (discovery + pipeline)
python run_scanner.py --once
```

---

## Tests

```bash
# Run all tests
pytest

# With coverage report
pytest --cov=netdoc --cov-report=html
```

Coverage of key modules:

- `models.py` — 100%
- `normalizer.py` — 100%
- `api/routes/devices.py` — 97%
- `network_detect.py` — 89%
- Overall — ~80%

Test count: **2470+** (unit + integration)

---

## Features

### Discovery

- **ARP scan** — detecting active hosts
- **nmap** — OS fingerprinting, port scanning (fast + full 1-65535)
- **OUI lookup** — vendor identification by MAC (IEEE MA-L/MA-M/MA-S, 39k+ entries)
- **Reclassification** — automatic device type assignment (router/switch/camera/nas/printer/workstation/iot/...)

### Collection

- **SNMP** — hostname, description, location, ARP/routing tables (v2c, community autodiscovery)
- **SSH/Netmiko** — Cisco IOS/NX-OS, MikroTik RouterOS
- **UniFi API** — Ubiquiti hardware (UniFi OS)
- **Modbus TCP** — inverters, PLCs, energy meters

### Syslog

- **Archiving** — network logs from routers, switches and APs in ClickHouse (rsyslog → Vector → ClickHouse)
- **Filtering** — severity, device, program, time range, full-text search
- **Grafana dashboard** — log timeline, top devices, top programs (public, no login required)
- **Pipeline** — Debian rsyslog (UDP/TCP 514), disk queue, auto-retry

### Security

- **Vulnerability scanning** — 33+ checks: default passwords, Telnet/RTSP/Modbus without auth, ONVIF cameras, DVRIP, Redis, MongoDB, Docker API
- **Credential testing** — SSH, HTTP Basic, SNMP, VNC, FTP, RDP, MySQL, MSSQL, PostgreSQL — 170+ pairs
- **Re-verification** — credentials checked on every scan cycle

### Monitoring

- **Ping worker** — continuous is_active monitoring every 18s
- **Telegram alerts** — device went offline/online/vulnerability detected
- **Prometheus metrics** — device, scan and error counters
- **Loki** — log aggregation from all containers
- **Grafana dashboards (6)** — inventory, security, workers, internet, logs, syslog

### Admin UI (Flask)

- Dashboard with network status summary
- Syslog tab — browsing and filtering network logs
- Network and credential management (CRUD)
- Scan triggers (standard / full port scan / OUI update)
- Logs, alerts and vulnerability viewer
- AI Assistant (requires your own Anthropic API key)

---

## Project structure

```
netdoc/
├── api/              # FastAPI endpoints
│   └── routes/       # devices, topology, events, scan, credentials, vulnerabilities, syslog
├── collector/        # Discovery engine
│   ├── discovery.py  # ARP + nmap + OUI + reclassification
│   ├── pipeline.py   # SNMP/SSH/Modbus collection
│   ├── normalizer.py # Data normalization
│   └── drivers/      # snmp, cisco, mikrotik, unifi, modbus
├── storage/          # SQLAlchemy models + database + clickhouse.py
├── notifications/    # Telegram alerts
└── web/              # Flask Admin UI + chat_agent
clickhouse/
└── init/             # netdoc_logs database init (Dictionary, syslog table)
config/
├── grafana/          # Provisioning: datasources, dashboards (6 dashboards)
├── loki/             # Loki config
├── promtail/         # Log shipper
├── nginx/            # nginx.conf (reverse proxy: port 80 → web:5000, /grafana/ → grafana:3000)
├── rsyslog/          # rsyslog.conf (syslog receiver)
├── vector/           # syslog.toml (pipeline rsyslog → ClickHouse)
├── clickhouse/       # users.xml (netdoc profile)
└── lab/              # Demo Lab: PLC, router, SSH, HMI
docker/
└── rsyslog/          # Dockerfile (Debian rsyslog)
run_scanner.py        # Main scanner (host)
run_ping.py           # Ping worker (Docker)
run_snmp_worker.py    # SNMP enrichment worker (Docker)
run_cred_worker.py    # Credential testing worker (Docker)
run_vuln_worker.py    # Vulnerability scanner (Docker)
run_community_worker.py  # SNMP community discovery (Docker)
run_internet.py       # Internet connectivity checks (Docker)
tests/                # 2470+ unit tests
```

---

## Deployment status

| Component | Status |
|-----------|--------|
| Discovery (ARP + nmap) | ✅ Done |
| OUI lookup (IEEE MA-L/MA-M/MA-S) | ✅ Done |
| Full port scan (1-65535, multi-threaded) | ✅ Done |
| SNMP collection + autodiscovery | ✅ Done |
| SSH collection (Cisco, MikroTik) | ✅ Done |
| Modbus TCP (PLC, inverters) | ✅ Done |
| Vulnerability scanning (33+ types) | ✅ Done |
| Credential testing (10 protocols) | ✅ Done |
| Ping monitoring (every 18s) | ✅ Done |
| Telegram alerts | ✅ Done |
| Syslog pipeline (rsyslog → Vector → ClickHouse) | ✅ Done |
| FastAPI REST | ✅ Done |
| PostgreSQL storage | ✅ Done |
| Prometheus metrics | ✅ Done |
| Grafana dashboards (6) | ✅ Done |
| Loki + Promtail | ✅ Done |
| Flask Admin UI + Syslog tab | ✅ Done |
| Docker Compose (17 containers) + nginx reverse proxy | ✅ Done |
| Demo Lab (simulated devices) | ✅ Done |
| Unit tests (2470+) | ✅ Done |
| Task Scheduler (Windows autostart) | ✅ Done |
| Watchdog (auto-restart containers) | ✅ Done |
| Network topology map | 🔄 In progress |
| SNMP Walk (ARP, routing, LLDP) | 🔄 In progress |
| PDF reports | 📋 Planned |
| NetFlow / sFlow traffic analysis | 📋 Planned |
| NIS2 / DORA Compliance Pack | 📋 Planned |
| Zabbix integration | 📋 Planned |
| Email alerts (SMTP) | 📋 Planned |

---

## Contact

- **Website:** [netdoc.pl](https://netdoc.pl)
- **Business:** [LinkedIn](https://www.linkedin.com/in/radoslawskonieczny/)
- **Technical questions:** [GitHub Issues](https://github.com/NetPlusRS/netdoc/issues)
- **Discussions:** [GitHub Discussions](https://github.com/NetPlusRS/netdoc/discussions)
