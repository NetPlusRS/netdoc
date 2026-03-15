"""
Testy regresyjne: scenariusze pierwszego uruchomienia na nowym systemie.

Weryfikuja ze aplikacja:
  - uruchamia sie bez .env (domyslne wartosci)
  - poprawnie parsuje NETWORK_RANGES w roznych formatach
  - nie crashuje z pustym NETWORK_RANGES
  - zawiera wymagane pliki statyczne (OUI, fingerprints, OID) po git clone
  - docker-compose.yml jest odporny na brak .env (required: false)
  - instalator tworzy plik logu debugowania
  - .env.example nie zawiera wartosci powodujacych blad parsowania

Nie wymagaja dostepu do sieci, bazy danych ani Docker.
"""

import os
import pathlib
import re
import sys
import tempfile
import importlib

import pytest
import yaml

ROOT = pathlib.Path(__file__).parent.parent

COMPOSE_FILE  = ROOT / "docker-compose.yml"
ENV_EXAMPLE   = ROOT / ".env.example"
SETUP_PS      = ROOT / "netdoc-setup.ps1"
SETTINGS_PY   = ROOT / "netdoc" / "config" / "settings.py"
REQUIREMENTS  = ROOT / "requirements.txt"
DATA_DIR      = ROOT / "data"
LOGS_DIR      = ROOT / "logs"
GITIGNORE     = ROOT / ".gitignore"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_settings_with_env(**env_overrides):
    """Laduje Settings() z nadpisanymi zmiennymi srodowiskowymi."""
    # Usun istniejacy modul zeby wymusic swiezy import
    for mod in list(sys.modules.keys()):
        if "netdoc.config" in mod or mod == "netdoc.config.settings":
            del sys.modules[mod]

    old_env = {}
    try:
        # Ustaw tymczasowe zmienne
        for k, v in env_overrides.items():
            old_env[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = str(v)

        from netdoc.config.settings import Settings
        s = Settings(_env_file=None)   # nie czytaj .env z dysku
        return s
    finally:
        for k, v in old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        # Wymus ponowny import przy kolejnym wywolaniu
        for mod in list(sys.modules.keys()):
            if "netdoc.config" in mod:
                del sys.modules[mod]


# ── 1. Konfiguracja: parsowanie NETWORK_RANGES ────────────────────────────────

class TestNetworkRangesParsing:
    """Weryfikuje ze NETWORK_RANGES jest parsowany poprawnie w kazdym formacie."""

    def test_empty_network_ranges_does_not_crash(self):
        """Puste NETWORK_RANGES (domyslne) — brak bledu, auto-detect."""
        s = _load_settings_with_env(NETWORK_RANGES="")
        assert s.network_ranges == ""
        result = s.network_ranges_list
        # Pusta lista lub lista z pustym stringiem — oba sa akceptowalne
        assert isinstance(result, list)

    def test_single_cidr_parses_correctly(self):
        s = _load_settings_with_env(NETWORK_RANGES="192.168.1.0/24")
        result = s.network_ranges_list
        assert "192.168.1.0/24" in result

    def test_csv_multiple_ranges_parse_correctly(self):
        s = _load_settings_with_env(NETWORK_RANGES="192.168.1.0/24,10.0.0.0/8")
        result = s.network_ranges_list
        assert "192.168.1.0/24" in result
        assert "10.0.0.0/8" in result

    def test_csv_with_spaces_parses_correctly(self):
        s = _load_settings_with_env(NETWORK_RANGES="192.168.1.0/24, 10.0.0.0/8")
        result = s.network_ranges_list
        # network_ranges_list powinien stripowac biale znaki
        assert "192.168.1.0/24" in result
        assert "10.0.0.0/8" in result

    def test_json_encoded_empty_list_does_not_crash(self):
        """Stary format z pydantic-settings v1: NETWORK_RANGES=[] — nie crashuje."""
        s = _load_settings_with_env(NETWORK_RANGES="[]")
        # Wartosc trafia jako string "[]"
        assert isinstance(s.network_ranges, str)

    def test_network_ranges_field_is_str_not_list(self):
        """network_ranges musi byc typem str (fix na pydantic-settings v2 JSON-decode)."""
        src = SETTINGS_PY.read_text(encoding="utf-8")
        # Szukamy definicji pola — musi byc 'str', nie 'List[str]'
        m = re.search(r'network_ranges\s*:\s*(\S+)', src)
        assert m, "Nie znaleziono pola network_ranges w settings.py"
        field_type = m.group(1)
        assert "List" not in field_type, (
            "network_ranges jest typem List — spowoduje blad z pydantic-settings v2 "
            "gdy NETWORK_RANGES=192.168.1.0/24 (nie jest valid JSON)"
        )
        assert field_type.startswith("str"), (
            f"network_ranges powinien byc str, jest: {field_type}"
        )


# ── 2. Konfiguracja: domyslne wartosci bez .env ───────────────────────────────

class TestDefaultsWithoutEnv:
    """Sprawdza ze Settings() nie crashuje bez pliku .env."""

    def test_settings_instantiate_without_env_file(self):
        """Settings() powinien dzialac z samymi domyslnymi wartosciami."""
        s = _load_settings_with_env(
            DB_URL=None, DB_HOST=None, DB_PORT=None,
            DB_NAME=None, DB_USER=None, DB_PASSWORD=None,
            NETWORK_RANGES=None,
        )
        assert s is not None

    def test_default_db_host_is_localhost(self):
        s = _load_settings_with_env(DB_HOST=None, DB_URL=None)
        assert s.db_host == "localhost"

    def test_default_db_port_is_5432(self):
        s = _load_settings_with_env(DB_PORT=None, DB_URL=None)
        assert s.db_port == 5432

    def test_default_log_level_is_info(self):
        s = _load_settings_with_env(LOG_LEVEL=None)
        assert s.log_level == "INFO"

    def test_default_api_port_is_8000(self):
        s = _load_settings_with_env(API_PORT=None)
        assert s.api_port == 8000

    def test_database_url_computed_from_parts(self):
        """database_url powinien byc zbudowany z czesci gdy DB_URL nie jest ustawiony."""
        s = _load_settings_with_env(
            DB_URL=None,
            DB_HOST="testhost",
            DB_PORT="5432",
            DB_USER="testuser",
            DB_PASSWORD="testpass",
            DB_NAME="testdb",
        )
        assert "testhost" in s.database_url
        assert "testuser" in s.database_url

    def test_db_url_env_takes_priority(self):
        """DB_URL nadpisuje DB_HOST/DB_PORT gdy jest ustawiony."""
        s = _load_settings_with_env(
            DB_URL="postgresql+psycopg2://custom:custom@customhost:5432/customdb",
            DB_HOST="shouldbeignored",
        )
        assert "customhost" in s.database_url
        assert "shouldbeignored" not in s.database_url


# ── 3. .env.example ───────────────────────────────────────────────────────────

class TestEnvExample:
    """Sprawdza ze .env.example nie zawiera wartosci powodujacych blad parsowania."""

    def _parse_env_example(self) -> dict:
        result = {}
        for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, val = line.partition("=")
                result[key.strip()] = val.strip()
        return result

    def test_network_ranges_is_empty_in_example(self):
        """NETWORK_RANGES w .env.example powinno byc puste — auto-detect."""
        env = self._parse_env_example()
        val = env.get("NETWORK_RANGES", "BRAK")
        assert val == "", (
            f"NETWORK_RANGES w .env.example = '{val}'. "
            "Pusta wartosc = auto-detect. "
            "Konkretny IP/CIDR tutaj spowoduje problem u uzytkownikow z inna secia."
        )

    def test_network_ranges_not_json_encoded(self):
        """NETWORK_RANGES nie powinno byc JSON-encoded (np. []) — to stary format."""
        env = self._parse_env_example()
        val = env.get("NETWORK_RANGES", "")
        assert not val.startswith("["), (
            "NETWORK_RANGES=[] to stary format JSON-encoded List. "
            "Uzyj pustego stringa lub CSV."
        )

    def test_all_example_keys_are_valid_identifiers(self):
        """Wszystkie klucze w .env.example sa poprawne (wielkie litery + podkreslenia)."""
        env = self._parse_env_example()
        for key in env:
            assert re.match(r'^[A-Z][A-Z0-9_]*$', key), (
                f"Niepoprawny klucz w .env.example: '{key}'"
            )

    def test_no_real_credentials_in_example(self):
        """Plik .env.example nie zawiera prawdziwych hasel/tokenow."""
        text = ENV_EXAMPLE.read_text(encoding="utf-8")
        forbidden_patterns = [
            r'sk-[A-Za-z0-9]{20,}',          # OpenAI API key
            r'ghp_[A-Za-z0-9]{20,}',         # GitHub token
            r'AAAA[A-Za-z0-9+/]{20,}',       # JWT-like
        ]
        for pattern in forbidden_patterns:
            m = re.search(pattern, text)
            assert not m, f"Potencjalny token w .env.example: {m.group()}"


# ── 4. Docker Compose — odpornosc na brak .env ───────────────────────────────

class TestDockerComposeRobustness:
    """Sprawdza ze docker-compose.yml nie wymaga .env do uruchomienia."""

    def _load_compose(self) -> dict:
        return yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))

    def test_env_file_required_false_for_all_services(self):
        """Kazdy serwis z env_file musi miec required: false."""
        data = self._load_compose()
        for svc_name, svc in data.get("services", {}).items():
            env_file = svc.get("env_file")
            if env_file is None:
                continue
            # env_file moze byc string lub lista
            if isinstance(env_file, str):
                # Stary format — nie ma required: false
                pytest.fail(
                    f"Serwis '{svc_name}': env_file jako string nie ma 'required: false'. "
                    "Uzyj formatu listowego: env_file: [{path: .env, required: false}]"
                )
            for entry in env_file:
                if isinstance(entry, dict):
                    path = entry.get("path", "")
                    if ".env" in str(path) and not str(path).endswith(".example"):
                        required = entry.get("required", True)
                        assert required is False, (
                            f"Serwis '{svc_name}': env_file '{path}' musi miec 'required: false'. "
                            "Bez tego serwis nie uruchomi sie gdy .env nie istnieje (fresh clone)."
                        )

    def test_all_services_have_restart_policy(self):
        """Wszystkie serwisy powinny miec polityke restartu."""
        data = self._load_compose()
        no_restart = []
        for svc_name, svc in data.get("services", {}).items():
            if "restart" not in svc:
                no_restart.append(svc_name)
        assert not no_restart, (
            f"Serwisy bez polityki restart: {no_restart}. "
            "Bez tego kontenery nie wstana automatycznie po bledie."
        )

    def test_postgres_has_healthcheck(self):
        """PostgreSQL musi miec healthcheck — inne serwisy czekaja az bdzie gotowy."""
        data = self._load_compose()
        pg = data["services"].get("postgres", {})
        assert "healthcheck" in pg, (
            "postgres nie ma healthcheck. "
            "depends_on z condition: service_healthy nie bedzie dzialac."
        )

    def test_worker_services_depend_on_postgres_healthcheck(self):
        """Serwisy workerow zalezne od postgres musza czekac na healthcheck."""
        data = self._load_compose()
        for svc_name, svc in data.get("services", {}).items():
            deps = svc.get("depends_on", {})
            if isinstance(deps, list):
                # Stary format listy (np. grafana zalezy od postgres+prometheus+loki)
                # Nie mozna uzyc condition gdy nie wszystkie zaleznosci maja healthcheck
                continue
            if "postgres" not in deps:
                continue
            pg_dep = deps.get("postgres", {})
            condition = pg_dep.get("condition")
            assert condition == "service_healthy", (
                f"Serwis '{svc_name}': depends_on postgres ma condition='{condition}'. "
                "Uzyj 'service_healthy' aby czekac az baza bedzie gotowa."
            )

    def test_no_hardcoded_host_paths(self):
        """docker-compose.yml nie montuje sciezek specyficznych dla hosta dewelopera."""
        data = self._load_compose()
        forbidden_prefixes = [
            "C:/Users/", "C:\\Users\\",
            "/home/yeszie", "/Users/",
        ]
        for svc_name, svc in data.get("services", {}).items():
            for vol in svc.get("volumes", []):
                vol_str = str(vol)
                for prefix in forbidden_prefixes:
                    assert prefix not in vol_str, (
                        f"Serwis '{svc_name}': wolumen zawiera hardcoded sciezke hosta: {vol_str}"
                    )


# ── 5. Pliki statyczne wymagane po git clone ──────────────────────────────────

class TestStaticFilesAfterClone:
    """Sprawdza ze pliki statyczne bazy danych sa dostepne po git clone.

    Bez tych plikow skaner nie bedzie dzialac na swiezej instalacji.
    """

    def test_fingerprints_dir_exists(self):
        d = DATA_DIR / "fingerprints"
        assert d.exists(), (
            "Katalog data/fingerprints/ nie istnieje. "
            "Skaner uzywa go do identyfikacji urzadzen po bannerach."
        )

    def test_fingerprints_dir_not_empty(self):
        d = DATA_DIR / "fingerprints"
        if not d.exists():
            pytest.skip("data/fingerprints nie istnieje")
        files = list(d.iterdir())
        assert files, "data/fingerprints/ jest pusta — brak plikow fingerprint"

    def test_oui_dir_exists(self):
        d = DATA_DIR / "oui"
        assert d.exists(), (
            "Katalog data/oui/ nie istnieje. "
            "Skaner uzywa go do identyfikacji producenta po MAC (np. Ubiquiti, Cisco)."
        )

    def test_oui_dir_not_empty(self):
        d = DATA_DIR / "oui"
        if not d.exists():
            pytest.skip("data/oui nie istnieje")
        files = list(d.iterdir())
        assert files, "data/oui/ jest pusta"

    def test_oid_dir_exists(self):
        d = DATA_DIR / "oid"
        assert d.exists(), (
            "Katalog data/oid/ nie istnieje. "
            "Skaner uzywa go do translacji OID SNMP na nazwy."
        )

    def test_logs_dir_exists_or_has_gitkeep(self):
        """logs/ musi istniec po clone lub miec .gitkeep ktory wymusi jego tworzenie."""
        gitkeep = LOGS_DIR / ".gitkeep"
        assert LOGS_DIR.exists() or gitkeep.parent.exists(), (
            "Katalog logs/ nie istnieje. Skaner zapisuje tam logi."
        )
        if LOGS_DIR.exists() and not any(LOGS_DIR.iterdir()):
            # Pusta — sprawdz czy gitignore ma wyjatek
            gitignore_text = GITIGNORE.read_text(encoding="utf-8")
            assert "!logs/.gitkeep" in gitignore_text, (
                "logs/ jest pusta i brak !logs/.gitkeep w .gitignore. "
                "Po git clone katalog nie bedzie istnieal."
            )

    def test_gitignore_preserves_static_databases(self):
        """data/fingerprints, data/oui, data/oid musza byc wylaczone z ignora."""
        text = GITIGNORE.read_text(encoding="utf-8")
        required_exceptions = [
            "!data/fingerprints/",
            "!data/oui/",
            "!data/oid/",
        ]
        for exc in required_exceptions:
            assert exc in text, (
                f"Brak wyjatku '{exc}' w .gitignore. "
                f"Po git clone braknie plikow statycznych — skaner nie zadziala."
            )

    def test_gitignore_uses_wildcard_for_data(self):
        """data/* (a nie data/) — pozwala na wyjatki dla podkatalogow."""
        text = GITIGNORE.read_text(encoding="utf-8")
        lines = [l.strip() for l in text.splitlines()]
        assert "data/*" in lines, (
            "Uzyj 'data/*' zamiast 'data/' w .gitignore — "
            "sama 'data/' ignoruje CALY katalog, bez mozliwosci wyjatkow."
        )
        assert "data/" not in lines or "data/*" in lines, (
            "data/ bez wildcarda zablokuje !data/fingerprints/** itd."
        )


# ── 6. Instalator — debug log ─────────────────────────────────────────────────

class TestInstallerDebugLog:
    """Sprawdza ze instalator netdoc-setup.ps1 tworzy plik logu debugowania."""

    def test_setup_ps_uses_start_transcript(self):
        """Start-Transcript musi byc wywolany — rejestruje wszystko do pliku."""
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "Start-Transcript" in text, (
            "netdoc-setup.ps1 nie wywoluje Start-Transcript. "
            "Bez tego uzytkownik nie ma logu do zglaszania bledow."
        )

    def test_setup_ps_uses_stop_transcript(self):
        """Stop-Transcript zamyka plik logu poprawnie."""
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "Stop-Transcript" in text, (
            "netdoc-setup.ps1 nie wywoluje Stop-Transcript — log moze byc niekompletny."
        )

    def test_setup_ps_log_file_has_timestamp(self):
        """Nazwa pliku logu powinna zawierac timestamp — latwiejsze debugowanie."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Sprawdz ze log file nazwa zawiera format daty
        assert "yyyyMMdd" in text or "yyyy-MM-dd" in text, (
            "Nazwa pliku logu nie zawiera timestampa. "
            "Uzyj Get-Date -Format 'yyyyMMdd-HHmmss' w nazwie pliku."
        )

    def test_setup_ps_log_file_defined_before_transcript(self):
        """Zmienna $LogFile musi byc zdefiniowana PRZED wywolaniem Start-Transcript."""
        text = SETUP_PS.read_text(encoding="utf-8")
        log_pos        = text.find("$LogFile")
        transcript_pos = text.find("Start-Transcript")
        assert log_pos < transcript_pos, (
            "$LogFile musi byc zdefiniowany przed Start-Transcript"
        )

    def test_setup_ps_shows_log_path_to_user(self):
        """Uzytkownik powinien wiedziec gdzie jest plik logu."""
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "$LogFile" in text, "Brak referencji do $LogFile w tekscie skryptu"
        # Sprawdz ze wyswietlamy sciezke uzytkownikowi (nie tylko wewnetrznie)
        assert "Log" in text and "Write-Host" in text

    def test_setup_ps_logs_system_info(self):
        """Plik logu powinien zawierac informacje o systemie (OS, RAM, dysk itp.)."""
        text = SETUP_PS.read_text(encoding="utf-8")
        system_info_indicators = [
            "OSVersion", "Version",       # Windows version
            "RAM", "GB",                  # pamieci
            "MachineName", "UserName",    # informacje o hoscie
        ]
        found = [kw for kw in system_info_indicators if kw in text]
        assert len(found) >= 3, (
            f"Log powinien zawierac informacje systemowe. "
            f"Znaleziono tylko: {found}"
        )

    def test_setup_ps_logs_each_major_step(self):
        """Kazdy krok instalacji powinien byc logowany z informacja poziomem."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Write-Step lub Write-LogEntry powinny byc uzywane
        assert "Write-LogEntry" in text or "Write-LogSection" in text, (
            "Brak ustrukturyzowanego logowania krokow w netdoc-setup.ps1"
        )


# ── 7. Requirements — kluczowe zaleznoci ─────────────────────────────────────

class TestRequirements:
    """Sprawdza ze requirements.txt zawiera kluczowe zaleznosci."""

    def _get_packages(self) -> set:
        text = REQUIREMENTS.read_text(encoding="utf-8")
        pkgs = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Wyodrebnij nazwe bez wersji
            name = re.split(r'[>=<!]', line)[0].strip().lower()
            pkgs.add(name)
        return pkgs

    def test_pydantic_settings_in_requirements(self):
        pkgs = self._get_packages()
        assert "pydantic-settings" in pkgs, (
            "pydantic-settings nie jest w requirements.txt. "
            "Settings() uzywa BaseSettings z tego pakietu."
        )

    def test_sqlalchemy_in_requirements(self):
        pkgs = self._get_packages()
        assert "sqlalchemy" in pkgs

    def test_psycopg2_in_requirements(self):
        pkgs = self._get_packages()
        assert any("psycopg2" in p for p in pkgs), (
            "psycopg2 (lub psycopg2-binary) nie jest w requirements.txt"
        )

    def test_fastapi_in_requirements(self):
        pkgs = self._get_packages()
        assert "fastapi" in pkgs

    def test_no_git_plus_dependencies(self):
        """Zaleznoci przez git+https mogą nie dzialac w sieci korporacyjnej."""
        text = REQUIREMENTS.read_text(encoding="utf-8")
        git_deps = [
            l.strip() for l in text.splitlines()
            if l.strip().startswith("git+")
        ]
        assert not git_deps, (
            f"requirements.txt zawiera zaleznoci git+: {git_deps}. "
            "Moga nie dzialac za proxym korporacyjnym lub bez gita."
        )
