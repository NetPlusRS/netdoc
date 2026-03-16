# CLAUDE.md — NetDoc Collector

Instrukcje dla modelu AI (Claude Code) oraz wytyczne dla deweloperów pracujących z tym projektem.

---

## Dla modelu AI — zasady pracy z tym projektem

### Konwencje kodu

**Python — co wolno, co niedozwolone:**
- Testy: NIE mockuj `SessionLocal` ani DB — używaj SQLite in-memory przez fixtures `db, client` z `tests/conftest.py`
- SQLAlchemy NULL: używaj `.is_(None)` zamiast `== None` (generuje SAWarning)
- Logowanie: każdy moduł definiuje `logger = logging.getLogger(__name__)` na poziomie modułu — NIE używaj `_log` wewnątrz funkcji bez definicji w tym samym scope
- Config DB: nowe klucze konfiguracyjne dodawaj w **obu** miejscach: `_config_defaults` w `run_scanner.py` ORAZ `_cfg_defaults_web` w `netdoc/web/app.py`
- Kategoria config: klucze edytowalne przez UI muszą mieć `category="config"`

**Docker — nazewnictwo:**
- Wszystkie kontenery mają prefix `netdoc-` (np. `netdoc-ping`, `netdoc-community`)
- Kontenery lab: `netdoc-lab-[nazwa]` (np. `netdoc-lab-plc-s7`)
- `"lab-"` bez `netdoc-` to zawsze błąd (stary pattern)

**SNMP:**
- Timeout: 2s, retries=0
- Prawidłowy timeout fix: daemon thread z `t.join(timeout=N)` — NIE `asyncio.wait_for`
- `nextCmd` (walk) nie działa w pysnmp-lextudio 6.x — tylko GET

**Flagi konfiguracyjne:**
- Pattern odczytu: `settings.get("key", "1") != "0"` (default włączony)
- NIE używaj `== "1"` (ignoruje inne truthy wartości)

### Struktura projektu

```
netdoc/                  # główny pakiet Python
  collector/             # discovery + pipeline (SSH, SNMP, Modbus)
  storage/               # modele SQLAlchemy, migracje
  api/routes/            # FastAPI endpoints
  web/                   # Flask admin panel + templates

run_scanner.py           # skaner HOST (Windows) — Task Scheduler, co 5 min
run_ping_worker.py       # Docker: ping monitoring co 18s
run_snmp_worker.py       # Docker: SNMP enrichment co 5min
run_cred_worker.py       # Docker: credential testing, cykl ~15min
run_vuln_worker.py       # Docker: vulnerability scanning, cykl ~67s
run_community_worker.py  # Docker: SNMP community strings
run_internet.py          # Docker: internet connectivity checks

tests/                   # pytest, ~1368 testów
  conftest.py            # fixtures: db, client, _no_fill_worker (autouse)

logs/                    # logi runtime — NIE w git (oprócz .gitkeep)
  scanner.log
  agents/                # raporty agentów AI — NIE w git (oprócz .gitkeep)

.claude/agents/          # agenci AI do analizy kodu — W git, wspólne dla zespołu
_private/                # notatki prywatne — NIE w git
netdoc_pro/              # pakiet Pro (płatny) — NIE w git community repo
```

### Uruchamianie

```bash
# Testy
cd C:/Users/Yeszie/OneDrive/Targi2026  # lub własna ścieżka
python -m pytest tests/ -q --tb=short

# Docker
docker compose up -d
docker compose ps

# Skaner ręcznie (host)
python run_scanner.py --once
```

### Ważne ograniczenia środowiska

- Write tool może zawieść z EEXIST na OneDrive — jeśli tak, użyj `Write` do katalogu Temp, potem uruchom plik przez Bash
- PostgreSQL: port 15432 (nie standardowy 5432) — inne narzędzia DB muszą używać tego portu
- Skaner działa na HOŚCIE (Windows) — ma dostęp do ARP table i pełnej sieci. Workery Docker uzupełniają, nie zastępują skanera

---

## Agenci AI (`.claude/agents/`)

Agenci to specjalizowane asystenty uruchamiane przez Claude Code. Każdy ma własny system prompt skupiony na konkretnym typie analizy. Wyniki zapisują do `logs/agents/[nazwa]-[timestamp].md`.

### Dostępni agenci

| Agent | Kiedy uruchomić | Opis |
|-------|-----------------|------|
| `@setup-diagnose` | Nowa instalacja / coś nie działa | Sprawdza .env, Docker, DB, API, Python deps, logi błędów |
| `@bug-logic` | Logika działa inaczej niż powinna | Złe warunki, odwrócone boole, off-by-one, złe typy |
| `@bug-db` | Problemy z bazą, aplikacja wisi | Wycieki sesji, N+1, null-checki, złe transakcje |
| `@bug-gui` | Coś w UI nie działa | Jinja2↔Flask, JS fetch, formularze, dynamiczne elementy |
| `@bug-concurrency` | Aplikacja wisi / zachowuje się nieregularnie | Race conditions, lock files, asyncio, threading |
| `@bug-regression` | Po merge coś przestało działać | Stare prefixe, niespójne listy kontenerów, desync config |
| `@bug-security` | Przed publikacją kodu | Injection, hardcoded secrets, brakująca autoryzacja |
| `@bug-worker` | Worker nie działa / daje złe wyniki | Crashe w pętli, memory leaks, złe interwały, API errors |
| `@bug-tests` | Po nowej funkcji / przed commitem | Brakujące testy, złe mockowanie, puste asercje |
| `@bug-performance` | Aplikacja zwalnia przy wielu urządzeniach | N+1 w pętlach, sleep w złym miejscu, blocking timeouts |

### Jak uruchomić agenta

W oknie Claude Code wpisz:
```
@setup-diagnose
```
lub z kontekstem:
```
@bug-worker zbadaj run_cred_worker.py — worker restartuje się co kilka godzin
```

Agenci są **read-only** — analizują, nie modyfikują kodu. Wyniki zwracają do głównej rozmowy i zapisują raport do `logs/agents/`.

### Jak działają agenci w Claude Code

1. Agent dostaje system prompt z pliku `.claude/agents/[nazwa].md`
2. Uruchamia się jako osobny kontekst (nie widzi historii rozmowy)
3. Ma dostęp do narzędzi: `Read`, `Grep`, `Glob`, `Bash`
4. Po zakończeniu zwraca wynik do głównej rozmowy
5. **Agenci podróżują z repo** — każdy kto sklonuje projekt i używa Claude Code ma do nich dostęp

---

## Dla deweloperów — onboarding

### Wymagania

- Python 3.10+
- Docker Desktop
- nmap (w PATH)
- Claude Code (opcjonalnie — do pracy z agentami AI)

### Pierwsza instalacja

```bash
git clone https://github.com/NetPlusRS/netdoc.git
cd netdoc

# 1. Środowisko Python
pip install -r requirements.txt

# 2. Konfiguracja
cp .env.example .env
# Edytuj .env — zmień SECRET_KEY, ustaw dane DB

# 3. Docker
docker compose up -d
docker compose ps   # wszystkie kontenery powinny być "Up"

# 4. Sprawdź instalację
# W Claude Code: @setup-diagnose
# lub ręcznie: python run_scanner.py --once

# 5. Testy
python -m pytest tests/ -q
```

### Gdy coś nie działa

1. Uruchom agenta diagnostycznego: `@setup-diagnose`
2. Sprawdź logi: `docker compose logs --tail=50`
3. Sprawdź `logs/scanner.log` (skaner hosta)
4. Typowe problemy → `logs/agents/setup-diagnose-*.md` po uruchomieniu agenta

### Dodawanie nowej funkcji — checklist

- [ ] Testy (pytest) — użyj fixtures `db, client` z conftest.py
- [ ] Jeśli nowy klucz config → dodaj do `_config_defaults` (scanner) I `_cfg_defaults_web` (app.py)
- [ ] Jeśli nowy kontener Docker → dodaj do `$ExpectedContainers` w watchdog i setup PS1
- [ ] Jeśli nowy serwis Docker → dodaj do `_DOCKER_SERVICES` w `netdoc/web/app.py`
- [ ] Uruchom `@bug-regression` przed commitem

### Architektura — skrót

```
HOST Windows
  run_scanner.py ──► PostgreSQL (15432)
       │
       ▼
  discovery (nmap) + pipeline (SNMP, SSH, Modbus)

Docker Compose
  api (FastAPI:8000) ◄──► PostgreSQL
  web (Flask:5000)   ◄──► PostgreSQL
  ping-worker   ─ co 18s pinguje wszystkie urządzenia
  snmp-worker   ─ co 5min SNMP GET dla aktywnych
  cred-worker   ─ testuje SSH/HTTP/RDP credentials (~15min/cykl)
  vuln-worker   ─ skanuje podatności TCP (~67s/cykl)
```

**Zasada**: skaner na hoście robi discovery. Docker workery uzupełniają dane i monitorują na bieżąco.
