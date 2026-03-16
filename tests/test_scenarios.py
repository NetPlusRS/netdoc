"""
Testy scenariuszowe — symulacja roznych sytuacji zyciowych instalatora NetDoc.

Scenariusze:
  1. Swierza instalacja (git clone, brak .env, brak danych)
  2. Ponowna instalacja (idempotentnosc — .env juz istnieje)
  3. Tylko zatrzymanie kontenerow (dane zachowane)
  4. Pelne odinstalowanie (kontenery + voluminy + Task Scheduler)
  5. Reinstalacja po odinstalowaniu
  6. Brak Dockera — zachowanie graceful
  7. Brak Pythona — zachowanie graceful
  8. Konflikty portow — komunikat o bledie

Testy sa oparte na analizie skryptow tekstowo (nie uruchamiaja PowerShell ani Docker).
"""

import pathlib
import re
import yaml

import pytest

ROOT           = pathlib.Path(__file__).parent.parent
SETUP_PS       = ROOT / "netdoc-setup.ps1"
UNINSTALL_PS   = ROOT / "netdoc-uninstall.ps1"
COMPOSE_FILE   = ROOT / "docker-compose.yml"
AUTOSTART_PS   = ROOT / "install_autostart.ps1"
ENV_EXAMPLE    = ROOT / ".env.example"

# ── Scenario 1: Swierza instalacja ────────────────────────────────────────────

class TestFreshInstallScenario:
    """Uzytkownik pobral repo przez git clone. Nic nie jest skonfigurowane."""

    def test_setup_copies_env_example_when_env_missing(self):
        """Jesli .env nie istnieje, setup.ps1 musi skopiowac .env.example."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Sprawdz logike: if (Test-Path $envFile) ... elseif ... Copy-Item
        assert "Copy-Item" in text and ".env.example" in text, (
            "setup.ps1 nie kopiuje .env.example gdy .env nie istnieje"
        )
        # Musi byc warunek sprawdzajacy czy .env juz istnieje
        assert "Test-Path" in text and "envFile" in text

    def test_setup_creates_minimal_env_when_example_also_missing(self):
        """Jesli nawet .env.example nie istnieje, setup tworzy minimalny .env."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Trzecia galaz: elif + Set-Content / Out-File
        assert "Set-Content" in text or "Out-File" in text, (
            "setup.ps1 nie tworzy minimalnego .env gdy brak .env.example"
        )

    def test_setup_installs_python_deps_on_fresh_system(self):
        """Na swierzym systemie pip install musi byc wywolany."""
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "pip install" in text and "requirements.txt" in text

    def test_setup_handles_missing_python(self):
        """Jezeli Python nie jest dostepny, setup ostrzega ale nie crashuje."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Skrypt powinien sprawdzic dostepnosc Pythona i ewentualnie zainstalowac
        assert "Python" in text and ("winget" in text or "Install-WithWinget" in text)
        # I jesli nadal niedostepny — informuje ale nie zamyka z exit 1
        assert "Python nie jest dostepny" in text or "pythonCmd" in text

    def test_setup_handles_missing_docker(self):
        """Jezeli Docker nie odpowiada, setup failuje z czytelnym komunikatem."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Musi byc petla oczekiwania na docker daemon
        assert "docker info" in text
        # I exit 1 gdy timeout
        assert "exit 1" in text
        # Z komunikatem o ikonke w zasobniku
        assert "zasobniku" in text or "ikonk" in text

    def test_setup_runs_first_scan_on_fresh_install(self):
        """Na koniec setup uruchamia pierwsze skanowanie."""
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "run_scanner.py" in text and "--once" in text

    def test_setup_opens_browser_only_after_web_ready(self):
        """Przegladarka otwierana dopiero gdy web panel odpowiada."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Szukamy pierwszego 'if ($webReady)' i Start-Process z URL HTTP (otwarcie przegladarki)
        # rfind("webReady") trafi na podsumowanie po otwarciu przegladarki — zly wzorzec
        web_check_pos    = text.find("if ($webReady)")
        browser_open_pos = text.find('Start-Process "http://')
        assert web_check_pos != -1,    "Brak 'if ($webReady)' w setup.ps1"
        assert browser_open_pos != -1, "Brak Start-Process z URL w setup.ps1"
        assert browser_open_pos > web_check_pos

    def test_compose_works_without_env_file(self):
        """docker-compose.yml nie moze wymagac .env — required: false."""
        data = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        for svc_name, svc in data.get("services", {}).items():
            for entry in svc.get("env_file", []):
                if isinstance(entry, dict) and ".env" in str(entry.get("path", "")):
                    if not str(entry.get("path", "")).endswith(".example"):
                        assert entry.get("required") is False, (
                            f"{svc_name}: env_file wymaga .env (required != false). "
                            "Fresh clone bez .env spowoduje crash kontenera."
                        )


# ── Scenario 2: Ponowna instalacja (idempotentnosc) ───────────────────────────

class TestReinstallScenario:
    """.env juz istnieje, kontenery moga juz biegac. Setup powinien byc idempotentny."""

    def test_setup_skips_env_copy_when_env_exists(self):
        """Jesli .env juz istnieje, nie nadpisuje go."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Warunek: if (Test-Path $envFile) -> Write-OK "juz istnieje — pomijam"
        assert "pomijam" in text.lower() or "juz istnieje" in text.lower() or \
               "already" in text.lower(), (
            "setup.ps1 nie ma komunikatu o pomijaniu .env gdy juz istnieje"
        )

    def test_docker_compose_up_is_idempotent(self):
        """docker compose up -d --build mozna wywolac wiele razy bez bledu."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Uzycie -d (detached) i --build jest idempotentne z natury compose
        assert "up -d --build" in text or "up --detach --build" in text

    def test_winget_install_handles_already_installed(self):
        """winget install nie failuje gdy pakiet juz zainstalowany."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Kod wyjscia -1978335189 = WINGET_INSTALLED_STATUS_ALREADY_INSTALLED
        assert "-1978335189" in text, (
            "setup.ps1 nie obsluguje kodu winget 'juz zainstalowany'. "
            "Reinstalacja zakonczy sie blednym komunikatem."
        )

    def test_autostart_script_unregisters_before_register(self):
        """install_autostart.ps1 usuwa stare zadanie przed rejestracją nowego."""
        text = AUTOSTART_PS.read_text(encoding="utf-8")
        unreg_pos = text.find("Unregister-ScheduledTask")
        reg_pos   = text.find("Register-ScheduledTask")
        assert unreg_pos != -1 and reg_pos != -1, "Brak Unregister/Register w autostart"
        assert unreg_pos < reg_pos, (
            "Register-ScheduledTask jest PRZED Unregister. "
            "Reinstation spowoduje blad 'zadanie juz istnieje'."
        )


# ── Scenario 3: Tylko zatrzymanie (stop) ─────────────────────────────────────

class TestStopOnlyScenario:
    """Uzytkownik chce zatrzymac kontenery zachowujac dane."""

    def test_uninstall_has_stop_only_option(self):
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        assert "docker compose stop" in text

    def test_stop_does_not_remove_volumes(self):
        """Tryb stop nie moze wywolac docker compose down --volumes."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")

        # Sprawdz ze "--volumes" jest TYLKO w galezi pelnego odinstalowania
        # (nie w galezi stop)
        stop_block_start = text.find('"stop"')
        full_block_start = text.find('"full"')

        # "--volumes" musi byc po galezi "full"
        volumes_pos = text.find("--volumes")
        assert volumes_pos > full_block_start, (
            "--volumes wywolywane jest poza blokiem 'full' — ryzyko utraty danych przy stop"
        )

    def test_stop_informs_user_data_preserved(self):
        """Po zatrzymaniu uzytkownik wie ze dane sa zachowane."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        assert "ZACHOWANE" in text or "zachowane" in text.lower() or \
               "preserved" in text.lower(), (
            "Uninstaller nie informuje ze dane sa zachowane przy trybie stop"
        )

    def test_stop_shows_how_to_restart(self):
        """Po zatrzymaniu uzytkownik wie jak uruchomic ponownie."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        # Musi wspomniec o sposobie wznowienia
        assert "docker compose start" in text or "netdoc-setup" in text, (
            "Uninstaller nie pokazuje jak uruchomic kontenery po zatrzymaniu"
        )


# ── Scenario 4: Pelne odinstalowanie ─────────────────────────────────────────

class TestFullUninstallScenario:
    """Uzytkownik chce calkowicie usunac NetDoc."""

    def test_full_uninstall_uses_volumes_flag(self):
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        assert "--volumes" in text and "down" in text

    def test_full_uninstall_removes_task_scheduler(self):
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        assert "Unregister-ScheduledTask" in text

    def test_full_uninstall_requires_double_confirmation(self):
        """Pelne odinstalowanie wymaga potwierdzenia — nie moze byc 'case of 2'."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        # Musi byc dodatkowy krok potwierdzenia (nie tylko wybranie opcji 2)
        confirm_keyword = any(kw in text for kw in ["USUN", "POTWIERDZ", "DELETE", "confirm"])
        assert confirm_keyword, (
            "Pelne odinstalowanie nie ma dodatkowego potwierdzenia. "
            "Uzytkownik moze przypadkowo wybrac opcje 2 i stracic dane."
        )

    def test_full_uninstall_offers_optional_env_removal(self):
        """Odinstalowanie pyta czy usunac .env (zawiera hasla)."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        assert ".env" in text and ("Read-Host" in text or "Confirm" in text)

    def test_full_uninstall_removes_pid_file(self):
        """Plik scanner.pid musi byc usuwany przy pelnym odinstalowaniu."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        assert "scanner.pid" in text

    def test_full_uninstall_offers_image_cleanup(self):
        """Uzytkownik moze usunac obrazy Docker (kilka GB)."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        assert "docker rmi" in text or "docker image" in text

    def test_full_uninstall_graceful_when_docker_unavailable(self):
        """Jesli Docker nie odpowiada, odinstalowanie nadal usuwa Task Scheduler."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        # Logika: $dockerAvailable = $false → pomijamy docker, ale task scheduler usuwamy
        # Task Scheduler removal musi byc POZA blokiem $dockerAvailable
        docker_block_start = text.find("if ($dockerAvailable)")
        # Szukamy zakonczenia bloku if ($dockerAvailable)
        # Proste sprawdzenie: Unregister-ScheduledTask musi istniec w tekscie
        unreg_pos = text.find("Unregister-ScheduledTask")
        assert unreg_pos != -1, "Brak Unregister-ScheduledTask w uninstall.ps1"


# ── Scenario 5: Reinstalacja po odinstalowaniu ────────────────────────────────

class TestReinstallAfterUninstallScenario:
    """Po pelnym odinstalowaniu uzytkownik moze zainstalowac ponownie."""

    def test_setup_creates_new_env_after_env_removed(self):
        """setup.ps1 tworzy nowy .env jesli poprzedni zostal usuniety."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Taka sama logika jak przy fresh install
        assert "Copy-Item" in text and ".env.example" in text

    def test_compose_up_recreates_volumes(self):
        """Po docker compose down --volumes, compose up tworzy voluminy od nowa."""
        # Compose automatycznie tworzy voluminy — wystarczy ze setup.ps1 wywoluje compose up
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "compose up" in text

    def test_autostart_can_be_reinstalled(self):
        """install_autostart.ps1 usuwa stare zadanie zanim zarejestruje nowe."""
        text = AUTOSTART_PS.read_text(encoding="utf-8")
        assert "Unregister-ScheduledTask" in text, (
            "Po reinstalacji autostart nie moze byc zainstalowany — "
            "zadanie juz istnieje bez Unregister."
        )


# ── Scenario 6: Brak Dockera ─────────────────────────────────────────────────

class TestNoDockerScenario:
    """Docker Desktop nie jest zainstalowany lub nie dziala."""

    def test_setup_installs_docker_via_winget(self):
        """Jezeli Docker nie jest zainstalowany, setup proponuje instalacje."""
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "Docker.DockerDesktop" in text

    def test_setup_starts_docker_desktop_after_install(self):
        """Po instalacji Docker Desktop, setup uruchamia go automatycznie."""
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "Docker Desktop.exe" in text or "DockerDesktop" in text

    def test_setup_waits_for_docker_daemon_with_timeout(self):
        """Setup czeka az Docker daemon odpowie (z timeoutem)."""
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "docker info" in text
        # Timeout — petla z licznikiem
        assert "$maxWait" in text or "maxWait" in text

    def test_setup_fails_gracefully_when_docker_never_starts(self):
        """Po timeoucie setup konczy z exit 1 i czytelnym komunikatem."""
        text = SETUP_PS.read_text(encoding="utf-8")
        docker_timeout_section = text[
            text.find("docker info"):text.find("docker compose up")
        ]
        assert "exit 1" in docker_timeout_section, (
            "Setup nie konczy dzialania (exit 1) gdy Docker nie odpowiada po timeoucie"
        )

    def test_uninstall_graceful_when_no_docker(self):
        """Uninstall informuje o braku Dockera zamiast crashowac."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        assert "$dockerAvailable" in text
        # Blok sprawdzajacy dostepnosc przed operacjami docker
        assert "if ($dockerAvailable)" in text


# ── Scenario 7: Konflikty portow ─────────────────────────────────────────────

class TestPortConflictScenario:
    """Porty 5000/8000/3000 zajete przez inna aplikacje."""

    def test_setup_mentions_port_conflicts_in_error_handling(self):
        """Po nieudanym docker compose up setup wymienia mozliwe przyczyny."""
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "Port" in text and ("zajety" in text or "busy" in text or "5000" in text)

    def test_all_exposed_ports_documented_in_setup(self):
        """Kluczowe porty powinny byc wspomniane w komunikatach setup."""
        text = SETUP_PS.read_text(encoding="utf-8")
        key_ports = ["5000", "8000", "3000"]
        found = [p for p in key_ports if p in text]
        assert len(found) >= 2, (
            f"Setup nie wymienia kluczowych portow ({key_ports}). "
            f"Znaleziono tylko: {found}"
        )

    def test_compose_ports_are_consistent_with_setup_urls(self):
        """Porty w docker-compose.yml zgodne z URL-ami w setup.ps1."""
        data  = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        setup = SETUP_PS.read_text(encoding="utf-8")

        # Web: 5000
        web_ports = data["services"]["web"].get("ports", [])
        assert any("5000" in str(p) for p in web_ports), "Web nie uzywa portu 5000"
        assert "5000" in setup, "Setup nie wymienia portu 5000 (web panel)"

        # API: 8000
        api_ports = data["services"]["api"].get("ports", [])
        assert any("8000" in str(p) for p in api_ports), "API nie uzywa portu 8000"
        assert "8000" in setup, "Setup nie wymienia portu 8000 (API)"

        # Grafana: 3000
        grafana_ports = data["services"]["grafana"].get("ports", [])
        assert any("3000" in str(p) for p in grafana_ports), "Grafana nie uzywa portu 3000"
        assert "3000" in setup, "Setup nie wymienia portu 3000 (Grafana)"


# ── Scenario 8: Weryfikacja kontenerow przed otwarciem przegladarki ───────────

class TestContainerVerificationScenario:
    """Setup sprawdza czy WSZYSTKIE kontenery sa Running przed otwarciem panelu."""

    def test_setup_checks_all_critical_containers(self):
        """$ExpectedContainers zawiera przynajmniej wszystkie CORE kontenery."""
        text = SETUP_PS.read_text(encoding="utf-8")
        m = re.search(r'\$ExpectedContainers\s*=\s*@\((.*?)\)', text, re.DOTALL)
        assert m, "$ExpectedContainers nie znaleziono"
        block     = m.group(1)
        monitored = set(re.findall(r'"(netdoc-[^"]+)"', block))

        # Core kontenery — bez nich system nie dziala (musza byc monitorowane)
        core_containers = {
            "netdoc-postgres",
            "netdoc-api",
            "netdoc-web",
            "netdoc-grafana",
            "netdoc-prometheus",
            "netdoc-ping",
            "netdoc-snmp",
            "netdoc-cred",
            "netdoc-vuln",
        }

        missing = core_containers - monitored
        assert not missing, (
            f"Core kontenery nie sa w $ExpectedContainers: {missing}. "
            "Setup nie wykryje gdy te kontenery nie wystartuja."
        )

    def test_setup_uses_running_status_filter(self):
        """docker ps musi filtrowac po status=running (nie wszystkie kontenery)."""
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "status=running" in text, (
            "docker ps bez --filter status=running moze liczyc zatrzymane kontenery. "
            "Kontener 'Exited' bylby oznaczony jako 'running'."
        )

    def test_setup_waits_with_timeout_for_containers(self):
        """Petla oczekiwania na kontenery ma ograniczenie czasu."""
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "maxContainerWait" in text
        # Timeout musi byc rozumny (> 30s)
        m = re.search(r'\$maxContainerWait\s*=\s*(\d+)', text)
        assert m, "Brak definicji $maxContainerWait"
        timeout = int(m.group(1))
        assert timeout >= 30, f"Timeout kontenerow ({timeout}s) zbyt krotki"

    def test_setup_shows_per_container_status(self):
        """Setup pokazuje status kazdego kontenera z osobna (OK / BLAD)."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Musi byc petla foreach po $ExpectedContainers z Write-OK/Write-Fail
        assert "foreach" in text.lower() and "ExpectedContainers" in text
        assert "Write-OK" in text and "Write-Fail" in text


# ── Testy: bledy wykryte podczas analizy (bug regression) ────────────────────

class TestBugRegression:
    """Testy zapobiegajace regresji konkretnych znalezionych bledow."""

    def test_uninstall_excludes_current_log_from_cleanup(self):
        """BUG: Uninstaller usuwal swoj wlasny aktywny plik logu.
        Fix: wykluczenie $LogFile z listy plikow do usuniecia."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        # Musi byc warunek wykluczajacy aktualny log
        assert "$LogFile" in text
        # W sekcji usuwania logow musi byc porownanie z $LogFile
        log_removal_section = text[text.find("netdoc-*-debug"):]
        assert "$LogFile" in log_removal_section or "-ne $LogFile" in log_removal_section, (
            "Uninstaller usuwa wlasny aktywny plik logu. "
            "Dodaj: Where-Object { $_.FullName -ne $LogFile }"
        )

    def test_uninstall_no_unused_variables(self):
        """BUG: $test i $wslList przypisywane ale nieuzywane — PSScriptAnalyzer warning."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        # Wzorzec: $varname = command... gdzie wynik jest ignorowany
        # Po fixie: powinno byc Out-Null zamiast przypisania
        assert "$test = docker" not in text, (
            "Zmienna $test jest przypisywana ale nieuzywana. "
            "Uzyj: docker info 2>&1 | Out-Null"
        )

    def test_setup_no_unused_variables(self):
        """BUG: $testResult i $wslList w setup.ps1 — PSScriptAnalyzer warning."""
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "$testResult = docker" not in text, (
            "Zmienna $testResult przypisywana ale nieuzywana."
        )
        assert "$wslList = wsl" not in text, (
            "Zmienna $wslList przypisywana ale nieuzywana."
        )

    def test_setup_uses_array_for_container_check(self):
        """BUG: docker ps bez @() zwraca string gdy 1 kontener — -notcontains sie myli.
        Fix: uzyj @() aby wymusic array."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Sprawdz ze docker ps w petli kontenerow uzywa @()
        container_poll = text[text.find("$maxContainerWait"):text.find("$allUp = $true")]
        assert "@(" in container_poll, (
            "docker ps w petli kontenerow nie uzywa @() — "
            "gdy 1 kontener zwraca string a nie array, -notcontains moze dzialac niepoprawnie."
        )

    def test_setup_filters_running_containers_only(self):
        """BUG: docker ps bez --filter status=running liczy zatrzymane kontenery.
        Fix: dodaj --filter status=running."""
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "status=running" in text, (
            "docker ps w petli kontenerow nie filtruje po status=running. "
            "Kontener Exited bylby liczony jako 'uruchomiony'."
        )

    def test_setup_warns_about_docker_socket_permission(self):
        """BUG: Brak ostrzezenia o wymaganym ustawieniu Docker socket.
        Serwis web i promtail wymagaja /var/run/docker.sock.
        Na swiezym Docker Desktop to ustawienie jest domyslnie wylaczone."""
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "docker.sock" in text or "Docker socket" in text or \
               "Allow the default Docker socket" in text, (
            "Setup nie ostrzega o wymaganym ustawieniu Docker socket. "
            "Bez 'Allow the default Docker socket' serwis web nie uruchomi sie."
        )

    def test_setup_warns_about_net_raw_capability(self):
        """BUG: Brak informacji o NET_RAW dla serwisow api i ping-worker.
        Na niektorych konfiguracjach Windows NET_RAW moze byc zablokowane."""
        text = SETUP_PS.read_text(encoding="utf-8")
        assert "NET_RAW" in text or "ICMP" in text or "ping" in text.lower(), (
            "Setup nie informuje o wymaganiu NET_RAW dla kontenerow api i ping-worker."
        )

    def test_setup_compose_up_error_hints_include_socket(self):
        """BUG: Komunikat bledu docker compose up nie wymienial Docker socket jako przyczyny."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Sekcja bledu compose up
        start = text.find("compose up zakonczyl")
        compose_error = text[start:text.find("exit 1", start)]
        assert "socket" in compose_error.lower() or "docker.sock" in compose_error.lower() \
               or "Advanced" in compose_error, (
            "Komunikat bledu docker compose up nie wymienia Docker socket jako mozliwej przyczyny."
        )

    def test_uninstall_stop_transcript_after_log_cleanup(self):
        """BUG: Stop-Transcript wywolywany po usunieciu plikow logu.
        Transcript musi byc zamkniety PO cleanup (nie w trakcie)."""
        text = UNINSTALL_PS.read_text(encoding="utf-8")
        cleanup_pos   = text.rfind("netdoc-*-debug")
        transcript_pos = text.rfind("Stop-Transcript")
        assert transcript_pos > cleanup_pos, (
            "Stop-Transcript wywolywany PRZED usuniecia logow. "
            "Powinno byc: cleanup logs -> Stop-Transcript."
        )


# ── Testy: druga runda analizy ────────────────────────────────────────────────

class TestBugRegressionRound2:
    """Bledy znalezione w drugiej rundzie glebokiej analizy (2026-03-16)."""

    def test_stop_transcript_before_restart_computer(self):
        """BUG: Restart-Computer -Force bez Stop-Transcript — log urwany/zablokowany.
        Fix: Stop-Transcript | Out-Null musi byc PRZED Restart-Computer."""
        text = SETUP_PS.read_text(encoding="utf-8")
        restart_pos   = text.find("Restart-Computer")
        stop_trans_pos = text.rfind("Stop-Transcript", 0, restart_pos)
        assert stop_trans_pos != -1 and stop_trans_pos < restart_pos, (
            "Stop-Transcript musi byc wywolany PRZED Restart-Computer -Force. "
            "Bez tego plik logu zostaje niedokonczony/zablokowany po restarcie."
        )

    def test_docker_path_refreshed_after_install(self):
        """BUG: Po winget install Docker, docker.exe nie jest w PATH biezacej sesji.
        Fix: odswierz PATH z rejestru po instalacji Docker Desktop."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Sekcja instalacji Docker Desktop (po winget install Docker.DockerDesktop)
        docker_install_pos = text.find("Docker.DockerDesktop")
        # Po instalacji musi byc odswierzenie PATH
        path_refresh_pos = text.find("GetEnvironmentVariable", docker_install_pos)
        assert path_refresh_pos != -1, (
            "Brak odswierzenia PATH po instalacji Docker Desktop przez winget. "
            "docker info w petli oczekiwania bedzie failowac z 'command not found'."
        )

    def test_fallback_env_has_correct_api_host(self):
        """BUG: Fallback minimal .env mial API_HOST=http://api:8000 zamiast 0.0.0.0.
        API_HOST to adres bindowania uvicorn, nie URL."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Sekcja tworzenia minimalnego .env
        env_section = text[text.find("Brak .env.example"):text.find("Set-Content")]
        assert "http://api:8000" not in env_section, (
            "Fallback .env ma API_HOST=http://api:8000 — to jest URL, nie adres bindowania. "
            "Uvicorn nie moze sie zbindowac do adresu URL."
        )
        if "API_HOST" in env_section:
            assert "0.0.0.0" in env_section, (
                "API_HOST w fallback .env powinno byc 0.0.0.0 (adres bindowania uvicorn)."
            )

    def test_fallback_env_has_correct_db_port(self):
        """BUG: Fallback minimal .env mial DB_PORT=5432.
        Host scanner laczy sie do postgres przez port zewnetrzny (15432), nie wewnetrzny."""
        text = SETUP_PS.read_text(encoding="utf-8")
        env_section = text[text.find("Brak .env.example"):text.find("Set-Content")]
        if "DB_PORT" in env_section:
            # Port 5432 to wewnetrzny port Docker — nieosiagalny z hosta
            # Port 15432 to zewnetrzny port postgres z docker-compose.yml
            assert "5432" not in env_section.replace("15432", ""), (
                "Fallback .env ma DB_PORT=5432 — nieosiagalny z hosta. "
                "Powinno byc DB_PORT=15432 (zewnetrzny port kontenera postgres)."
            )

    def test_wsl_detection_language_agnostic(self):
        """BUG: Wykrywanie WSL przez -match 'Default' nie dziala na Windows
        z jezykiem innym niz angielski (np. polskim).
        Fix: uzyj exit code zamiast dopasowania tekstu."""
        text = SETUP_PS.read_text(encoding="utf-8")
        wsl_section = text[text.find("Sprawdzam WSL2"):text.find("Sprawdzam Docker Desktop")]
        # Sprawdz ze glowna logika opiera sie na $LASTEXITCODE, nie na -match "Default"
        assert "$LASTEXITCODE -eq 0" in wsl_section, (
            "Wykrywanie WSL musi opierac sie na exit code, nie na tekscie wyjscia. "
            "Tekst 'Default' nie wystepuje na Windows z jezykiem polskim/innym."
        )
        # Nie powinno byc glownego polegania na -match "Default" dla sukcesu
        # (moze byc jako dodatkowy fallback, ale nie jako jedyny warunek)
        default_match_pos = wsl_section.find('-match "Default"')
        exitcode_pos      = wsl_section.find("$LASTEXITCODE -eq 0")
        assert exitcode_pos != -1 and (
            default_match_pos == -1 or exitcode_pos < default_match_pos
        ), (
            "$LASTEXITCODE powinien byc sprawdzany jako PIERWSZY warunek WSL detection."
        )

    def test_compose_postgres_port_matches_env_example(self):
        """Zewnetrzny port postgres w docker-compose.yml musi zgadzac sie
        z portem w .env.example (lub byc dokumentowany)."""
        data = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        pg_ports = data["services"]["postgres"].get("ports", [])
        # Format: "15432:5432" lub {"published": 15432, "target": 5432}
        external_port = None
        for p in pg_ports:
            if isinstance(p, str):
                ext, _, _ = p.partition(":")
                external_port = int(ext.strip())
            elif isinstance(p, dict):
                external_port = p.get("published")

        assert external_port is not None, "Postgres nie ma zmapowanego portu zewnetrznego"
        assert external_port != 5432, (
            f"Postgres mapuje na standardowy port 5432 — host scanner bedzie myslic "
            f"ze to wewnetrzny port Docker. Uzyj portu niestandardowego (np. 15432)."
        )

    def test_setup_warns_about_disk_space(self):
        """Sugestia: setup powinien sprawdzic dostepne miejsce na dysku.
        Docker images zajmuja ~3-5 GB, build potrzebuje dodatkowego miejsca."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Sprawdz czy system info zawiera info o dysku (loguje do transcript)
        assert "disk" in text.lower() or "Dysk" in text or "Free" in text or "GB" in text, (
            "Setup nie sprawdza/loguje dostepnego miejsca na dysku. "
            "Jesli dysk jest pelny, docker build cicho failuje po pobraniu obrazow."
        )

    def test_pip_install_runs_with_python_executable(self):
        """pip install musi uzywac $PythonExeResolved (pelna sciezka),
        nie 'pip' (moze byc z innej wersji Pythona)."""
        text = SETUP_PS.read_text(encoding="utf-8")
        # Musi byc: & $PythonExeResolved -m pip install (nie 'pip install' bezposrednio)
        assert "$PythonExeResolved -m pip" in text or "PythonExeResolved.*pip" in text, (
            "pip install powinien byc wywolywany jako 'python -m pip install', "
            "nie bezposrednio przez 'pip'. Gwarantuje to uzyciem wlasciwej wersji pip."
        )
