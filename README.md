# NetDoc Collector

**Universal Network Discovery & Documentation System**

Automatyczne odkrywanie, dokumentowanie i monitorowanie infrastruktury sieciowej.
Niezalezny od producenta urzadzen — Cisco, MikroTik, Ubiquiti, Fortinet i inne.

---

## Architektura

```
Collector → Storage → API (FastAPI) → Grafana
                   ↓
             Flask Web Admin
```

| Warstwa | Technologie |
|---------|-------------|
| **Collector** | nmap, netmiko, pysnmp-lextudio, APScheduler |
| **Storage** | SQLAlchemy, PostgreSQL (prod) / SQLite (dev) |
| **API** | FastAPI + Uvicorn + Prometheus metrics |
| **Monitoring** | Grafana + Prometheus + Loki + Promtail |
| **Admin UI** | Flask web panel (port 5000) |

---

## Szybki start — Docker

```bash
docker compose up -d
```

| Serwis | URL |
|--------|-----|
| NetDoc API (FastAPI) | http://localhost:8000 |
| Swagger UI | http://localhost:8000/docs |
| NetDoc Admin (Flask) | http://localhost:5000 |
| Grafana | http://localhost:3000 |
| Prometheus | http://localhost:9090 |
| Loki | http://localhost:3100 |

Domyslne haslo Grafana: `admin / netdoc`

---

## Konfiguracja (.env)

```bash
cp .env.example .env
# Edytuj .env — zakres sieci, interfaly schedulera
```

Kluczowe zmienne:

| Zmienna | Opis | Domyslna |
|---------|------|---------|
| `NETWORK_RANGES` | Zakresy CIDR do skanowania | auto-detect |
| `SCAN_INTERVAL_MINUTES` | Czestotliwosc skanowania | 60 |
| `LOG_LEVEL` | Poziom logow | INFO |
| `FLASK_SECRET_KEY` | Klucz sesji Flask | dev-only |

Gdy `NETWORK_RANGES` jest puste, system automatycznie wykrywa lokalne podsieci.

---

## Uruchomienie developerskie

```bash
# Instalacja
pip install -r requirements-dev.txt

# Baza (PostgreSQL w Dockerze)
docker compose up -d postgres

# API
uvicorn netdoc.api.main:app --reload --port 8000

# Flask Admin UI
flask --app netdoc.web.app run --port 5000

# Scheduler (discovery + kolekcja)
python -m netdoc.collector.scheduler
```

---

## Testy

```bash
# Uruchom wszystkie testy
pytest

# Z raportem pokrycia
pytest --cov=netdoc --cov-report=html
open htmlcov/index.html
```

Pokrycie kluczowych modulow:
- `models.py` — 100%
- `normalizer.py` — 100%
- `api/routes/devices.py` — 97%
- `network_detect.py` — 89%
- Ogolne — ~53%

---

## Funkcje

### Discovery
- **ARP scan** — wykrywanie aktywnych hostow
- **nmap** — fingerprinting OS, skanowanie portow (fast + full 1-65535)
- **OUI lookup** — identyfikacja producenta po MAC (IEEE MA-L/MA-M/MA-S, 39k+ wpisow)
- **Reklasyfikacja** — automatyczne przypisywanie typu urzadzenia (router/switch/camera/nas/printer/iot/...)

### Kolekcja
- **SNMP** — hosty, interfejsy, sasiedzi LLDP (v2c, autodiscovery community)
- **SSH/Netmiko** — Cisco IOS/NX-OS, MikroTik RouterOS
- **UniFi API** — sprzet Ubiquiti

### Monitorowanie
- **Prometheus metrics** — liczniki urzadzen, skanow, bledow
- **Loki** — agregacja logow ze wszystkich kontenerow
- **Grafana dashboardy** — inwentarz, topologia, credentials, konfiguracja systemu
- **Linki z Grafany do Flask Admin** — szybka nawigacja do konfiguracji

### Admin UI (Flask)
- Dashboard z podsumowaniem
- Zarzadzanie sieciami (CRUD)
- Zarzadzanie credentials SNMP/SSH
- Wyzwalanie skanowania (standard / full port scan / aktualizacja OUI)
- Podglad logow (Loki w iframe)
- Podglad ustawien systemu

---

## Struktura projektu

```
netdoc/
├── api/              # FastAPI endpoints
│   ├── routes/       # devices, topology, events, scan, credentials
│   └── metrics.py    # Prometheus /metrics
├── collector/        # Discovery engine
│   ├── discovery.py  # ARP + nmap + OUI + reklasyfikacja
│   ├── oui_lookup.py # IEEE OUI database (MA-L/MA-M/MA-S)
│   ├── pipeline.py   # SNMP/SSH kolekcja danych
│   ├── scheduler.py  # APScheduler jobs
│   ├── normalizer.py # Normalizacja danych
│   └── drivers/      # snmp, cisco, mikrotik, unifi
├── config/           # Settings (pydantic-settings)
├── storage/          # SQLAlchemy models + database
│   ├── models.py     # Device, Credential, SystemStatus, ...
│   └── database.py   # Engine, SessionLocal
└── web/              # Flask Admin UI
    ├── app.py
    └── templates/    # Jinja2 HTML templates
config/
├── grafana/          # Provisioning: datasources, dashboards
├── loki/             # Loki config
└── promtail/         # Promtail (log shipper) config
tests/
├── conftest.py
├── test_api_devices.py
├── test_discovery.py
├── test_discovery_vendors.py
├── test_models.py
├── test_network_detect.py
├── test_normalizer.py
├── test_oui_lookup.py
└── test_pipeline.py
```

---

## Status wdrozenia

| Komponent | Status |
|-----------|--------|
| Discovery (ARP + nmap) | Done |
| OUI lookup (IEEE MA-L/MA-M/MA-S) | Done |
| Full port scan (1-65535, wielowatkowy) | Done |
| SNMP kolekcja + autodiscovery | Done |
| SSH kolekcja (Cisco, MikroTik) | Done |
| FastAPI REST | Done |
| PostgreSQL storage | Done |
| Prometheus metrics | Done |
| Grafana dashboardy | Done |
| Loki + Promtail | Done |
| Flask Admin UI | Done |
| Docker Compose (7 serwisow) | Done |
| Testy jednostkowe (138 testow) | Done |
| Alembic migracje | Planned |
| Raporty PDF | Planned |
| GNS3 eksport topologii | Planned |
