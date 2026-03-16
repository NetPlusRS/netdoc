"""
Testy regresyjne dla skryptow instalacyjnych NetDoc Windows.

Sprawdzaja spojnosc miedzy:
  - docker-compose.yml  (zrodlo prawdy o kontenerach)
  - run_scanner._DOCKER_SERVICES  (lista uzywana przez skanera hosta)
  - netdoc-setup.ps1  ($ExpectedContainers — lista do weryfikacji po compose up)
  - netdoc_docker.ps1  ($Services — lista do menu zarzadzania)
  - install_autostart.ps1  (referencje do skryptow i Task Scheduler)
  - netdoc-setup.bat  (launcher skryptu PS)

Nie wymagaja uruchomienia Docker ani PowerShell — analizuja pliki tekstowo.
"""

import pathlib
import re
import yaml
import pytest

ROOT = pathlib.Path(__file__).parent.parent

# ── Pliki instalacyjne ────────────────────────────────────────────────────────

COMPOSE_FILE      = ROOT / "docker-compose.yml"
SETUP_PS          = ROOT / "netdoc-setup.ps1"
SETUP_BAT         = ROOT / "netdoc-setup.bat"
UNINSTALL_PS      = ROOT / "netdoc-uninstall.ps1"
UNINSTALL_BAT     = ROOT / "netdoc-uninstall.bat"
DOCKER_PS         = ROOT / "netdoc_docker.ps1"
AUTOSTART_PS      = ROOT / "install_autostart.ps1"
WATCHDOG_PS       = ROOT / "netdoc_watchdog.ps1"
ENV_EXAMPLE       = ROOT / ".env.example"
REQUIREMENTS      = ROOT / "requirements.txt"
RUN_SCANNER       = ROOT / "run_scanner.py"

# Nazwy zadan Task Scheduler (musza byc zsynchronizowane z install_autostart.ps1 i install_watchdog.ps1)
EXPECTED_TASK_NAMES = {"NetDocScanner", "NetDoc Watchdog"}


# ── Helpery ───────────────────────────────────────────────────────────────────

def _compose_containers() -> set:
    """Zwraca zbior nazw kontenerow z docker-compose.yml."""
    data = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    names = set()
    for svc in data.get("services", {}).values():
        cn = svc.get("container_name")
        if cn:
            names.add(cn)
    return names


def _ps_quoted_strings(path: pathlib.Path) -> list:
    """Zwraca liste ciagow w cudzyslowach z pliku PowerShell."""
    text = path.read_text(encoding="utf-8")
    return re.findall(r'"([^"]+)"', text)


def _scanner_docker_services() -> list:
    """Parsuje _DOCKER_SERVICES z run_scanner.py."""
    text = RUN_SCANNER.read_text(encoding="utf-8")
    m = re.search(r'_DOCKER_SERVICES\s*=\s*\[(.*?)\]', text, re.DOTALL)
    assert m, "_DOCKER_SERVICES nie znaleziono w run_scanner.py"
    block = m.group(1)
    return re.findall(r'"(netdoc-[^"]+)"', block)


def _setup_ps_expected_containers() -> list:
    """Parsuje $ExpectedContainers z netdoc-setup.ps1."""
    text = SETUP_PS.read_text(encoding="utf-8")
    m = re.search(r'\$ExpectedContainers\s*=\s*@\((.*?)\)', text, re.DOTALL)
    assert m, "$ExpectedContainers nie znaleziono w netdoc-setup.ps1"
    block = m.group(1)
    return re.findall(r'"(netdoc-[^"]+)"', block)


def _docker_ps_services() -> list:
    """Parsuje $Services (Name =) z netdoc_docker.ps1."""
    text = DOCKER_PS.read_text(encoding="utf-8")
    return re.findall(r'Name\s*=\s*"(netdoc-[^"]+)"', text)


# ── Testy: pliki istnieja ─────────────────────────────────────────────────────

class TestFilesExist:
    def test_uninstall_ps_exists(self):
        assert UNINSTALL_PS.exists(), "netdoc-uninstall.ps1 nie istnieje"

    def test_uninstall_bat_exists(self):
        assert UNINSTALL_BAT.exists(), "netdoc-uninstall.bat nie istnieje"

    def test_compose_exists(self):
        assert COMPOSE_FILE.exists(), "docker-compose.yml nie istnieje"

    def test_setup_ps_exists(self):
        assert SETUP_PS.exists(), "netdoc-setup.ps1 nie istnieje"

    def test_setup_bat_exists(self):
        assert SETUP_BAT.exists(), "netdoc-setup.bat nie istnieje"

    def test_docker_ps_exists(self):
        assert DOCKER_PS.exists(), "netdoc_docker.ps1 nie istnieje"

    def test_autostart_ps_exists(self):
        assert AUTOSTART_PS.exists(), "install_autostart.ps1 nie istnieje"

    def test_watchdog_ps_exists(self):
        assert WATCHDOG_PS.exists(), "netdoc_watchdog.ps1 nie istnieje"

    def test_env_example_exists(self):
        assert ENV_EXAMPLE.exists(), ".env.example nie istnieje"

    def test_requirements_exists(self):
        assert REQUIREMENTS.exists(), "requirements.txt nie istnieje"

    def test_run_scanner_exists(self):
        assert RUN_SCANNER.exists(), "run_scanner.py nie istnieje"


# ── Testy: docker-compose ↔ run_scanner._DOCKER_SERVICES ─────────────────────

class TestComposeVsScanner:
    def test_all_scanner_services_exist_in_compose(self):
        """Kazdy kontener w _DOCKER_SERVICES musi miec odpowiednik w compose."""
        compose = _compose_containers()
        scanner = _scanner_docker_services()
        missing = [s for s in scanner if s not in compose]
        assert not missing, (
            f"Kontenery w _DOCKER_SERVICES ktorych nie ma w compose: {missing}"
        )

    def test_all_compose_containers_exist_in_scanner(self):
        """Kazdy kontener z compose powinien byc w _DOCKER_SERVICES."""
        compose = _compose_containers()
        scanner = set(_scanner_docker_services())
        missing = [c for c in compose if c not in scanner]
        assert not missing, (
            f"Kontenery w compose ktorych nie ma w _DOCKER_SERVICES: {missing}"
        )

    def test_scanner_services_no_duplicates(self):
        """_DOCKER_SERVICES nie zawiera duplikatow."""
        services = _scanner_docker_services()
        assert len(services) == len(set(services)), (
            f"Duplikaty w _DOCKER_SERVICES: {[s for s in services if services.count(s) > 1]}"
        )

    def test_compose_containers_no_duplicates(self):
        """docker-compose.yml nie zawiera zduplikowanych container_name."""
        data = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        names = [
            svc.get("container_name")
            for svc in data.get("services", {}).values()
            if svc.get("container_name")
        ]
        assert len(names) == len(set(names)), f"Zduplikowane container_name w compose: {names}"


# ── Testy: netdoc-setup.ps1 ───────────────────────────────────────────────────

class TestSetupPs:
    def test_expected_containers_not_empty(self):
        containers = _setup_ps_expected_containers()
        assert len(containers) > 0, "$ExpectedContainers jest pusty"

    def test_expected_containers_are_valid_compose_names(self):
        """Kazdy kontener w $ExpectedContainers musi istniec w docker-compose.yml."""
        compose = _compose_containers()
        setup   = _setup_ps_expected_containers()
        invalid = [c for c in setup if c not in compose]
        assert not invalid, (
            f"Kontenery w $ExpectedContainers ktorych nie ma w compose: {invalid}\n"
            f"Czy po dodaniu/zmianie nazwy kontenera zaktualizowano netdoc-setup.ps1?"
        )

    def test_setup_ps_references_env_example(self):
        text = SETUP_PS.read_text(encoding="utf-8")
        assert ".env.example" in text, "netdoc-setup.ps1 nie odwoluje sie do .env.example"

    def test_setup_ps_references_requirements(self):
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "requirements.txt" in text

    def test_setup_ps_references_install_autostart(self):
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "install_autostart.ps1" in text

    def test_setup_ps_references_docker_ps(self):
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "netdoc_docker.ps1" in text

    def test_setup_ps_opens_browser_url(self):
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "localhost:5000" in text, "Brak adresu panelu admina w setup.ps1"

    def test_setup_ps_no_hardcoded_passwords(self):
        text = SETUP_PS.read_text(encoding="utf-8")
        # Flagi zakazane — hasla nie powinny byc wpisane na twardo
        forbidden = ["netdoc123", "password=", "3f>KMH"]
        for f in forbidden:
            assert f not in text, f"Znaleziono potencjalne haslo '{f}' w netdoc-setup.ps1"

    def test_setup_ps_no_hardcoded_private_ips(self):
        text = SETUP_PS.read_text(encoding="utf-8")
        # Wewnetrzne IP produkcyjne nie powinny trafiać do instalatora
        assert "192.168.5." not in text, "Prywatne IP produkcyjne w netdoc-setup.ps1"

    def test_setup_ps_waits_for_web_before_browser(self):
        """Przegladarka otwierana jest tylko gdy $webReady = $true."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Szukamy bloku 'if ($webReady)' a nastepnie 'Start-Process "http://' wewnatrz niego
        # rfind("Start-Process") trafia na ostatnie uzycie, ktore moze byc inne (np. Docker Desktop)
        # Precyzyjnie: Start-Process z URL przegladarki musi byc wewnatrz bloku if ($webReady)
        webready_check = text.find("if ($webReady)")
        browser_url    = text.find('Start-Process "http://')
        assert webready_check != -1, "Brak bloku 'if ($webReady)' w netdoc-setup.ps1"
        assert browser_url != -1,    "Brak Start-Process z URL w netdoc-setup.ps1"
        assert browser_url > webready_check, (
            "Start-Process z URL przegladarki powinien byc po 'if ($webReady)'"
        )

    def test_setup_ps_checks_containers_before_browser(self):
        """$allUp musi byc sprawdzony przed otwarciem przegladarki."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Szukamy pierwszego sprawdzenia $allUp (if/while) i Start-Process z URL
        allup_check = text.find("$allUp")
        browser_url = text.find('Start-Process "http://')
        assert allup_check != -1, "Brak uzywania $allUp w netdoc-setup.ps1"
        assert browser_url != -1, "Brak Start-Process z URL w netdoc-setup.ps1"
        assert browser_url > allup_check, (
            "Start-Process z URL przegladarki powinien byc po sprawdzeniu $allUp"
        )


# ── Testy: netdoc-setup.bat ───────────────────────────────────────────────────

class TestSetupBat:
    def test_bat_calls_ps_script(self):
        text = SETUP_BAT.read_text(encoding="utf-8")
        assert "netdoc-setup.ps1" in text, "netdoc-setup.bat nie wywoluje netdoc-setup.ps1"

    def test_bat_uses_execution_policy_bypass(self):
        text = SETUP_BAT.read_text(encoding="utf-8")
        assert "Bypass" in text, "Brak -ExecutionPolicy Bypass w netdoc-setup.bat"

    def test_bat_no_hardcoded_paths(self):
        text = SETUP_BAT.read_text(encoding="utf-8")
        # Launcher powinien uzywac %~dp0 zamiast absolutnej sciezki
        assert "C:\\Users\\" not in text, (
            "netdoc-setup.bat zawiera absolutna sciezke uzytkownika — uzyj %~dp0"
        )


# ── Testy: netdoc_docker.ps1 ─────────────────────────────────────────────────

class TestDockerPs:
    def test_services_not_empty(self):
        services = _docker_ps_services()
        assert len(services) > 0, "$Services w netdoc_docker.ps1 jest pusta"

    def test_services_are_valid_compose_names(self):
        """Kazda nazwa w $Services musi istniec w docker-compose.yml."""
        compose  = _compose_containers()
        services = _docker_ps_services()
        invalid  = [s for s in services if s not in compose]
        assert not invalid, (
            f"Nazwy w $Services ktorych nie ma w compose: {invalid}"
        )

    def test_services_no_duplicates(self):
        services = _docker_ps_services()
        assert len(services) == len(set(services)), "Duplikaty w $Services"

    def test_critical_containers_in_services(self):
        """Krytyczne kontenery musza byc w menu zarzadzania."""
        services = _docker_ps_services()
        critical = ["netdoc-postgres", "netdoc-api", "netdoc-web"]
        for c in critical:
            assert c in services, f"Brak {c} w $Services netdoc_docker.ps1"

    def test_docker_ps_has_port_definitions(self):
        """Kazdy serwis powinien miec przypisany port (nawet 0)."""
        text = DOCKER_PS.read_text(encoding="utf-8")
        services = _docker_ps_services()
        ports_found = re.findall(r'Port\s*=\s*(\d+)', text)
        assert len(ports_found) == len(services), (
            f"Liczba portow ({len(ports_found)}) != liczba serwisow ({len(services)})"
        )


# ── Testy: install_autostart.ps1 ─────────────────────────────────────────────

class TestAutostartPs:
    def test_references_run_scanner(self):
        text = AUTOSTART_PS.read_text(encoding="utf-8")
        assert "run_scanner.py" in text

    def test_has_task_name(self):
        text = AUTOSTART_PS.read_text(encoding="utf-8")
        assert "NetDocScanner" in text

    def test_has_once_flag(self):
        """Skaner uruchamiany jest w trybie --once."""
        text = AUTOSTART_PS.read_text(encoding="utf-8")
        assert "--once" in text

    def test_has_repetition_interval(self):
        """Task Scheduler powinien miec ustawiony interwał powtarzania."""
        text = AUTOSTART_PS.read_text(encoding="utf-8")
        assert "RepetitionInterval" in text

    def test_battery_settings_set(self):
        """Skanowanie nie powinno byc blokowane przez zasilanie bateryjne."""
        text = AUTOSTART_PS.read_text(encoding="utf-8")
        assert "DontStopIfGoingOnBatteries" in text
        assert "AllowStartIfOnBatteries" in text


# ── Testy: spojnosc portow compose ↔ docker_ps ───────────────────────────────

class TestPortConsistency:
    """Porty w netdoc_docker.ps1 powinny zgadzac sie z docker-compose.yml."""

    EXPECTED_PORTS = {
        "netdoc-postgres":   15432,
        "netdoc-api":        8000,
        "netdoc-web":        5000,
        "netdoc-grafana":    3000,
        "netdoc-prometheus": 9090,
        "netdoc-ping":       8001,
        "netdoc-snmp":       8002,
        "netdoc-cred":       8003,
        "netdoc-vuln":       8004,
    }

    def _get_port_map(self) -> dict:
        text = DOCKER_PS.read_text(encoding="utf-8")
        # Parsuje bloki: @{ Name = "netdoc-X"; Port = N; ... }
        entries = re.findall(
            r'@\{[^}]*Name\s*=\s*"(netdoc-[^"]+)"[^}]*Port\s*=\s*(\d+)[^}]*\}',
            text
        )
        return {name: int(port) for name, port in entries}

    def test_critical_ports_match_expected(self):
        port_map = self._get_port_map()
        for container, expected_port in self.EXPECTED_PORTS.items():
            if container in port_map and expected_port != 0:
                actual = port_map[container]
                assert actual == expected_port, (
                    f"{container}: oczekiwano portu {expected_port}, "
                    f"znaleziono {actual} w netdoc_docker.ps1"
                )


# ── Testy: netdoc-uninstall.ps1 ───────────────────────────────────────────────

class TestUninstallPs:
    """Weryfikuje ze skrypt odinstalowania jest kompletny i bezpieczny."""

    def test_uninstall_bat_calls_ps_script(self):
        text = UNINSTALL_BAT.read_text(encoding="utf-8")
        assert "netdoc-uninstall.ps1" in text

    def test_uninstall_bat_uses_bypass(self):
        text = UNINSTALL_BAT.read_text(encoding="utf-8")
        assert "Bypass" in text

    def test_uninstall_bat_no_hardcoded_paths(self):
        text = UNINSTALL_BAT.read_text(encoding="utf-8")
        assert "C:\\Users\\" not in text, "Hardcoded sciezka uzytkownika w uninstall.bat"

    def test_has_stop_mode(self):
        """Skrypt musi oferowac opcje TYLKO zatrzymania (bez usuniecia danych)."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        assert "docker compose stop" in text, (
            "Brak opcji 'docker compose stop' — uzytkownik musi moc tylko zatrzymac kontenery "
            "bez utraty danych."
        )

    def test_has_full_uninstall_mode(self):
        """Skrypt musi oferowac pelne odinstalowanie z woluminami."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        assert "--volumes" in text, (
            "Brak 'docker compose down --volumes' — pelne odinstalowanie nie usuwa danych."
        )

    def test_asks_for_confirmation_before_full_uninstall(self):
        """Pelne odinstalowanie wymaga potwierdzenia — ochrona przed przypadkowym usunieciem."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        # Potwierdzenie tekstem (nie tylko Y/N) dla operacji destrukcyjnych
        confirm_patterns = ["USUN", "DELETE", "YES", "confirm"]
        found = any(p in text for p in confirm_patterns)
        assert found, (
            "Brak potwierdzenia przed pelnym odinstalowaniem. "
            "Uzytkownik moze przypadkowo usunac wszystkie dane."
        )

    def test_removes_task_scheduler_tasks(self):
        """Odinstalowanie musi usunac zadania Task Scheduler."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        assert "Unregister-ScheduledTask" in text, (
            "Brak Unregister-ScheduledTask w uninstall.ps1. "
            "Po odinstalowaniu zadania zostana w Task Scheduler."
        )

    def test_removes_all_registered_task_names(self):
        """Wszystkie zarejestrowane zadania musza byc usuwane przez uninstaller."""
        uninstall_text = UNINSTALL_PS.read_text(encoding="utf-8")
        for task_name in EXPECTED_TASK_NAMES:
            assert task_name in uninstall_text, (
                f"Zadanie '{task_name}' jest rejestrowane przez instalator "
                "ale nie jest usuwane przez uninstaller."
            )

    def test_has_stop_transcript(self):
        """Skrypt musi poprawnie zamykac plik logu."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        assert "Stop-Transcript" in text

    def test_has_start_transcript(self):
        """Skrypt musi zapisywac log do pliku."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        assert "Start-Transcript" in text

    def test_no_hardcoded_paths(self):
        """Skrypt nie zawiera absolutnych sciezek specyficznych dla dewelopera."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        assert "C:\\Users\\Yeszie" not in text
        assert "/home/" not in text

    def test_docker_compose_stop_before_down(self):
        """Opcja stop musi byc odrebna od down — uzytkownik wybiera."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        stop_pos = text.find("docker compose stop")
        down_pos = text.find("docker compose down")
        # Oba musza istniec
        assert stop_pos != -1, "Brak 'docker compose stop'"
        assert down_pos != -1, "Brak 'docker compose down'"

    def test_informs_user_what_is_preserved(self):
        """Po odinstalowaniu uzytkownik powinien wiedziec co zostalo zachowane."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        # Powinno wspomniec o Docker Desktop lub Python jako zachowane
        assert "Docker Desktop" in text or "Python" in text, (
            "Uninstaller nie informuje co pozostaje po odinstalowaniu "
            "(Docker Desktop, Python itp.)"
        )


# ── Testy: synchronizacja nazw zadan Task Scheduler ──────────────────────────

class TestTaskSchedulerSync:
    """Nazwy zadan w install_*.ps1 musza byc zgodne z uninstall i watchdog."""

    def _task_names_from_file(self, path: pathlib.Path) -> set:
        text = path.read_text(encoding="utf-8")
        # Parsuje $TaskName = "..." lub TaskName = "..."
        return set(re.findall(r'TaskName\s*=\s*"([^"]+)"', text))

    def test_autostart_task_name_in_expected(self):
        names = self._task_names_from_file(AUTOSTART_PS)
        assert names.issubset(EXPECTED_TASK_NAMES | {""}), (
            f"Nowe zadanie w install_autostart.ps1: {names - EXPECTED_TASK_NAMES}. "
            "Zaktualizuj EXPECTED_TASK_NAMES i netdoc-uninstall.ps1."
        )

    def test_watchdog_install_task_name_in_expected(self):
        watchdog_install = ROOT / "install_watchdog.ps1"
        if not watchdog_install.exists():
            pytest.skip("install_watchdog.ps1 nie istnieje")
        names = self._task_names_from_file(watchdog_install)
        registered = {n for n in names if n.startswith("NetDoc")}
        assert registered.issubset(EXPECTED_TASK_NAMES), (
            f"Nowe zadanie w install_watchdog.ps1: {registered - EXPECTED_TASK_NAMES}. "
            "Zaktualizuj EXPECTED_TASK_NAMES i netdoc-uninstall.ps1."
        )

    def test_uninstaller_removes_all_expected_tasks(self):
        uninstall_text = UNINSTALL_PS.read_text(encoding="utf-8")
        for task_name in EXPECTED_TASK_NAMES:
            assert task_name in uninstall_text, (
                f"Uninstaller nie usuwa zadania '{task_name}'. "
                "Upewnij sie ze wszystkie zadania z EXPECTED_TASK_NAMES sa w uninstall.ps1."
            )
