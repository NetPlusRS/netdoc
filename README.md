# NetDoc Collector

**Universal Network Discovery & Documentation System**

Automatyczne odkrywanie, dokumentowanie i monitorowanie infrastruktury sieciowej.
Niezalezny od producenta urzadzen — Cisco, MikroTik, Ubiquiti, Fortinet i inne.

> **⚠️ Wersja Beta — przeczytaj przed uruchomieniem w sieci produkcyjnej**
>
> Skanowanie sieci moze powodowac niezamierzone skutki uboczne:
>
> - **Drukarki** mogą wykonac niechciany wydruk (skan portu 9100 / JetDirect)
> - **Starsze urzadzenia IoT i przelaczniki** moga zawiesic sie lub zrestartowac pod wplywem ruchu skanera
> - **Full port scan** (1–65535) generuje znaczny ruch i moze wyzwolic systemy IDS/IPS
>
> **Zalecane srodowisko startowe:** siec testowa, laboratorium lub dolaczone Demo Lab (`docker compose -f docker-compose.lab.yml up`).
> Projekt jest aktywnie rozwijany — przed wdrozeniem produkcyjnym przetestuj na wlasnym sprzecie.

---

## Architektura

```
Collector (host) → PostgreSQL → API (FastAPI) → Grafana
                             ↓
                       Flask Web Admin
                             ↑
              Docker workers (ping, snmp, cred, vuln)
```

| Warstwa | Technologie |
|---------|-------------|
| **Collector** | nmap, netmiko, pysnmp-lextudio, APScheduler |
| **Storage** | SQLAlchemy, PostgreSQL (prod) / SQLite (dev) |
| **API** | FastAPI + Uvicorn + Prometheus metrics |
| **Monitoring** | Grafana + Prometheus + Loki + Promtail |
| **Admin UI** | Flask web panel (port 5000) |

---

## Szybki start — Windows (zalecane)

Pobierz repozytorium i kliknij dwukrotnie:

```
netdoc-setup.bat
```

Instalator automatycznie:

- sprawdza i instaluje wymagania (WSL2, Docker Desktop, git, Python 3.11+)
- konfiguruje `.env` z szablonu
- uruchamia wszystkie kontenery Docker
- weryfikuje stan 9 kontenerow
- uruchamia pierwsze skanowanie sieci
- otwiera panel administracyjny w przegladarce

Wymagania: Windows 10 v2004+ (Build 19041), 8 GB RAM, ~10 GB wolnego miejsca.

> **Przed uruchomieniem Docker:** Docker Desktop → Settings → Advanced →
> wlacz *Allow the default Docker socket to be used* (wymagane przez web i promtail).

### Zatrzymanie / odinstalowanie

```
netdoc-uninstall.bat
```

Menu:

- **[1]** Zatrzymaj kontenery — dane zachowane
- **[2]** Pelne odinstalowanie — usuwa kontenery, voluminy, zadania Task Scheduler

---

## Szybki start — reczny (Linux / macOS / Windows bez instalatora)

```bash
cp .env.example .env   # Linux/macOS
# copy .env.example .env   # Windows cmd

docker compose up -d
```

| Serwis | URL |
|--------|-----|
| NetDoc Admin (Flask) | http://localhost:5000 |
| NetDoc API (FastAPI) | http://localhost:8000 |
| Swagger UI | http://localhost:8000/docs |
| Grafana | http://localhost:3000 |
| Prometheus | http://localhost:9090 |
| Loki | http://localhost:3100 |

Domyslne haslo Grafana: `admin / netdoc`

Skaner uruchamia sie na hoscie (pelny dostep do sieci, ARP table):

```bash
pip install -r requirements.txt
python run_scanner.py --once
```

### Autostart (Windows Task Scheduler)

```powershell
powershell -ExecutionPolicy Bypass -File install_autostart.ps1
```

---

## Konfiguracja (.env)

```bash
cp .env.example .env
# Edytuj .env — zakres sieci, Telegram, SNMP community
```

Kluczowe zmienne:

| Zmienna | Opis | Domyslna |
|---------|------|---------|
| `NETWORK_RANGES` | Zakresy CIDR do skanowania | auto-detect |
| `SCAN_INTERVAL_MINUTES` | Czestotliwosc skanowania | 5 |
| `LOG_LEVEL` | Poziom logow | INFO |
| `FLASK_SECRET_KEY` | Klucz sesji Flask | dev-only |
| `TELEGRAM_BOT_TOKEN` | Token bota Telegram do alertow | opcjonalne |

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

# Skaner (discovery + pipeline)
python run_scanner.py --once
```

---

## Testy

```bash
# Uruchom wszystkie testy
pytest

# Z raportem pokrycia
pytest --cov=netdoc --cov-report=html
```

Pokrycie kluczowych modulow:

- `models.py` — 100%
- `normalizer.py` — 100%
- `api/routes/devices.py` — 97%
- `network_detect.py` — 89%
- Ogolne — ~38%

---

## Funkcje

### Discovery

- **ARP scan** — wykrywanie aktywnych hostow
- **nmap** — fingerprinting OS, skanowanie portow (fast + full 1-65535)
- **OUI lookup** — identyfikacja producenta po MAC (IEEE MA-L/MA-M/MA-S, 39k+ wpisow)
- **Reklasyfikacja** — automatyczne przypisywanie typu urzadzenia (router/switch/camera/nas/printer/workstation/iot/...)

### Kolekcja

- **SNMP** — hostname, opis, lokalizacja, tablice ARP/routing (v2c, autodiscovery community)
- **SSH/Netmiko** — Cisco IOS/NX-OS, MikroTik RouterOS
- **UniFi API** — sprzet Ubiquiti (UniFi OS)
- **Modbus TCP** — inwertery, PLC, liczniki energii

### Bezpieczenstwo

- **Skanowanie podatnosci** — domyslne hasla, otwarty Telnet/RTSP/Modbus, ONVIF bez auth, DVRIP
- **Testowanie credentials** — SSH, HTTP Basic, SNMP, VNC, FTP — automatyczna weryfikacja
- **Re-weryfikacja** — credentials sprawdzane przy kazdym cyklu skanowania

### Monitorowanie

- **Ping worker** — ciagle monitorowanie is_active co 18s
- **Alerty Telegram** — urzadzenie zniklo/pojawilo sie/wykryto podatnosc
- **Prometheus metrics** — liczniki urzadzen, skanow, bledow
- **Loki** — agregacja logow ze wszystkich kontenerow
- **Grafana dashboardy** — inwentarz, security, workers, internet

### Admin UI (Flask)

- Dashboard z podsumowaniem stanu sieci
- Zarzadzanie sieciami i credentials (CRUD)
- Wyzwalanie skanowania (standard / full port scan / aktualizacja OUI)
- Podglad logow, alertow, podatnosci
- Asystent AI (wersja Pro)

---

## Struktura projektu

```
netdoc/
├── api/              # FastAPI endpoints
│   └── routes/       # devices, topology, events, scan, credentials, vulnerabilities
├── collector/        # Discovery engine
│   ├── discovery.py  # ARP + nmap + OUI + reklasyfikacja
│   ├── pipeline.py   # SNMP/SSH/Modbus kolekcja
│   ├── normalizer.py # Normalizacja danych
│   └── drivers/      # snmp, cisco, mikrotik, unifi, modbus
├── storage/          # SQLAlchemy models + database
├── notifications/    # Telegram alerts
└── web/              # Flask Admin UI + chat_agent
config/
├── grafana/          # Provisioning: datasources, dashboards (5 dashboardow)
├── loki/             # Loki config
├── promtail/         # Log shipper
└── lab/              # Demo Lab: PLC, router, SSH, HMI
run_scanner.py        # Glowny skaner (host)
run_ping.py           # Ping worker (Docker)
run_snmp_worker.py    # SNMP enrichment worker (Docker)
run_cred_worker.py    # Credential testing worker (Docker)
run_vuln_worker.py    # Vulnerability scanner (Docker)
tests/                # 500+ testow jednostkowych
```

---

## Status wdrozenia

| Komponent | Status |
|-----------|--------|
| Discovery (ARP + nmap) | ✅ Done |
| OUI lookup (IEEE MA-L/MA-M/MA-S) | ✅ Done |
| Full port scan (1-65535, wielowatkowy) | ✅ Done |
| SNMP kolekcja + autodiscovery | ✅ Done |
| SSH kolekcja (Cisco, MikroTik) | ✅ Done |
| Modbus TCP (PLC, inwertery) | ✅ Done |
| Skanowanie podatnosci | ✅ Done |
| Testowanie credentials (SSH/HTTP/SNMP/VNC/FTP) | ✅ Done |
| Ping monitoring (co 18s) | ✅ Done |
| Alerty Telegram | ✅ Done |
| FastAPI REST | ✅ Done |
| PostgreSQL storage | ✅ Done |
| Prometheus metrics | ✅ Done |
| Grafana dashboardy (5 szt.) | ✅ Done |
| Loki + Promtail | ✅ Done |
| Flask Admin UI | ✅ Done |
| Docker Compose (9 kontenerow) | ✅ Done |
| Demo Lab (symulowane urzadzenia) | ✅ Done |
| Testy jednostkowe (500+) | ✅ Done |
| Task Scheduler (Windows autostart) | ✅ Done |
| Mapa topologii sieci | 🔄 W trakcie |
| SNMP Walk (ARP, routing, LLDP) | 🔄 W trakcie |
| Raporty PDF | 📋 Planned |
| Integracja Zabbix | 📋 Planned |
| Alerty email (SMTP) | 📋 Planned |

---

## Kontakt

- **Strona:** [netdoc.pl](https://netdoc.pl)
- **Kontakt biznesowy:** [LinkedIn](https://www.linkedin.com/in/radoslawskonieczny/)
- **Pytania techniczne:** [GitHub Issues](https://github.com/NetPlusRS/netdoc/issues)
- **Dyskusje:** [GitHub Discussions](https://github.com/NetPlusRS/netdoc/discussions)
