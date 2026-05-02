"""CLI Command Reference extractor — zbiera drzewo komend z urządzeń przez SSH.

Obsługiwane tryby:
  - cisco_wlc       : Cisco Mobility Express / WLC (interaktywny shell)
  - cisco_ap_shell  : AP IOS Shell przez apciscoshell na WLC

Wynik zapisywany do device_commands/<slug>.yaml.
Uruchamiany ręcznie (jednorazowo per model+firmware) — nie jako worker.

Checkpoint: po każdej przetworzonej komendzie top-level zapisuje <slug>.partial.yaml.
Jeśli proces zostanie przerwany, wystarczy uruchomić ponownie z tymi samymi parametrami
— program wznowi od miejsca gdzie skończył.

Użycie:
    # WLC CLI (pełne drzewo)
    python -m netdoc.collector.cli_extractor \
        --ip 192.168.5.99 --user yeszie --password '23R@@t23r@@t' \
        --mode cisco_wlc --model "Cisco Mobility Express WLC" --firmware "8.10.196.0" \
        --max-depth 3

    # AP IOS Shell przez WLC
    python -m netdoc.collector.cli_extractor \
        --ip 192.168.5.99 --user yeszie --password '23R@@t23r@@t' \
        --mode cisco_ap_shell --ap-name "Cisco_AP" \
        --model "Cisco AP IOS (via WLC)" --firmware "8.10.196.0" \
        --max-depth 2
"""
from __future__ import annotations

import argparse
import logging
import re
import socket
import time
from pathlib import Path

logger = logging.getLogger(__name__)

_COMMANDS_DIR = Path(__file__).parent.parent.parent / "device_commands"

_AUTO_TAGS: list[tuple[list[str], str]] = [
    (["snmp", "community", "v3user", "snmpversion"], "snmp-config"),
    (["cpu", "memory", "ram", "utilization", "load", "stats", "statistics",
      "sysinfo", "summary", "client", "ap summary", "interface"], "stats"),
    (["reset", "erase", "factory", "wipe", "reload", "reboot"], "dangerous"),
    (["backup", "transfer", "tftp", "ftp", "archive", "export"], "backup"),
    (["debug", "trace", "packet", "capture"], "debug"),
    (["save", "write", "commit"], "save-config"),
    (["logging", "syslog", "log"], "syslog"),
    (["show version", "sysinfo", "product", "firmware", "version"], "version-info"),
    (["password", "user", "aaa", "radius", "tacacs", "auth"], "auth"),
    (["vlan", "trunk", "access port"], "vlan"),
    (["spanning", "stp", "rstp"], "stp"),
    (["lldp", "cdp", "neighbor"], "topology"),
    (["interface", "port", "ethernet", "gigabit"], "interfaces"),
    (["dhcp"], "dhcp"),
    (["ntp", "time", "clock"], "ntp"),
    (["acl", "access-list", "firewall", "filter"], "acl"),
    (["crypto", "certificate", "tls", "ssl", "pki"], "crypto"),
    (["qos", "dscp", "priority", "queue"], "qos"),
    (["radio", "802.11", "rf", "channel", "tx-power", "antenna"], "wireless-rf"),
    (["ap", "access-point", "mobility", "capwap"], "ap-management"),
]


def _slugify(model: str, firmware: str) -> str:
    def clean(s: str) -> str:
        s = s.lower().strip()
        s = re.sub(r"[^a-z0-9.]+", "_", s)
        return s.strip("_")
    fw_short = ".".join(firmware.split(".")[:2]) if firmware else "unknown"
    return f"{clean(model)}_{clean(fw_short)}"


def _auto_tags(cmd_path: str, description: str) -> list[str]:
    combined = (cmd_path + " " + description).lower()
    tags: list[str] = []
    for keywords, tag in _AUTO_TAGS:
        if any(kw in combined for kw in keywords):
            tags.append(tag)
    return tags


# ─────────────────────────────────────────────────────────────
# Wspólny parser outputu pomocy Cisco
# ─────────────────────────────────────────────────────────────

def _parse_help_output(raw: str) -> dict[str, str]:
    """Parsuje output 'cmd ?' do słownika {komenda: opis}.

    Obsługuje formaty:
      aaa            Displays AAA related information
      802.11a        Display 802.11a configuration.
      <cr>           (pomijane — marker końca listy)

    WLC dołącza sekcję edycji linii po 'HELP:' — przerywamy tam parsowanie.
    """
    result: dict[str, str] = {}
    lines = raw.replace("\r", "").split("\n")
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # WLC dołącza sekcję pomocy edycji linii — wszystko po niej to śmieci
        if line == "HELP:" or line.startswith("HELP:"):
            break
        # Pomiń linie z promptami obu shellu
        if "(Cisco Controller)" in line or line.endswith(">") or line.endswith("#"):
            continue
        # Pomiń paginację i znaczniki końca
        if line.startswith("--More--") or line == "<cr>" or line.startswith("% "):
            continue
        # Pomiń echowanie komendy (kończy się spacją bez podwójnej spacji)
        if line.endswith(" ") and not re.search(r"\s{2,}", line):
            continue
        # Format: "komenda     opis..." (min 2 spacje jako separator)
        m = re.match(r"^(\S+)\s{2,}(.+)$", line)
        if m:
            cmd, desc = m.group(1).strip(), m.group(2).strip()
            # Skip <cr>, parameter placeholders (<IP>, <ap-name>), and line-edit keys (Ctrl-X)
            if (cmd and len(cmd) < 50 and cmd != "<cr>"
                    and not cmd.startswith("<") and not cmd.startswith("Ctrl-")):
                result[cmd] = desc
        elif re.match(r"^(\S+)$", line):
            cmd = line.strip()
            if (cmd and len(cmd) < 50
                    and not cmd.startswith("-") and not cmd.startswith("<")
                    and not cmd.startswith("Ctrl-") and cmd != "<cr>"):
                result.setdefault(cmd, "")
    return result


# ─────────────────────────────────────────────────────────────
# Cisco WLC extractor
# ─────────────────────────────────────────────────────────────

class CiscoWlcExtractor:
    """Ekstraktor dla Cisco Mobility Express WLC."""

    # Tylko naprawdę niebezpieczne lub blokujące sesję — NIE debug/clear/test/transfer
    SKIP_RECURSE = {
        "?",                     # help — zwraca ten sam zestaw komend, tworzy nieskończoną rekurencję
        "apciscoshell",          # obsługiwany osobno przez CiscoApShellExtractor
        "reset", "restart", "reload",  # reboot urządzenia
        "logout",                # kończy sesję
        "linktest",              # wysyła pakiety testowe do MAC
        "eping", "cping", "ping",  # blokujące ICMP/CAPWAP
    }

    def __init__(self, ip: str, username: str, password: str,
                 timeout: int = 10, max_depth: int = 3):
        self.ip = ip
        self.username = username
        self.password = password
        self.timeout = timeout
        self.max_depth = max_depth
        self._shell = None
        self._client = None
        # checkpoint state — ustawiane przez main() przed connect()
        self._checkpoint_path: Path | None = None
        self._done_set: set[str] = set()
        self._partial_tree: dict = {}

    def connect(self):
        import paramiko, warnings
        warnings.filterwarnings("ignore")
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(self.ip, username=self.username, password=self.password,
                  timeout=self.timeout, auth_timeout=self.timeout,
                  allow_agent=False, look_for_keys=False)
        c.get_transport().set_keepalive(20)
        shell = c.invoke_shell(width=220, height=50)
        time.sleep(2)
        banner = shell.recv(4096).decode(errors="replace")
        if "User:" in banner:
            shell.send(self.username + "\n")
            time.sleep(1)
            shell.recv(1024)
            shell.send(self.password + "\n")
            time.sleep(2)
            shell.recv(4096)
        self._client = c
        self._shell = shell
        logger.info("Połączono z WLC %s", self.ip)

    def _reconnect(self):
        logger.warning("Sesja SSH zamknięta — rekonektuję...")
        try:
            self.disconnect()
        except Exception:
            pass
        time.sleep(3)
        self.connect()

    def disconnect(self):
        if self._client:
            self._client.close()

    def _is_wlc_prompt(self, text: str) -> bool:
        return "(Cisco Controller)" in text

    def _save_checkpoint(self) -> None:
        if not self._checkpoint_path:
            return
        try:
            import yaml
            _COMMANDS_DIR.mkdir(exist_ok=True)
            with open(self._checkpoint_path, "w", encoding="utf-8") as f:
                yaml.dump({"commands": self._partial_tree}, f,
                          allow_unicode=True, default_flow_style=False,
                          sort_keys=True, indent=2)
        except Exception as e:
            logger.warning("Błąd zapisu checkpointu: %s", e)

    def _drain(self) -> None:
        """Opróżnia bufor SSH przed nowym zapytaniem — usuwa resztkowe dane."""
        self._shell.settimeout(0.3)
        while True:
            try:
                leftover = self._shell.recv(4096)
                if not leftover:
                    break
            except socket.timeout:
                break

    def _last_prompt(self, raw: str) -> str:
        """Zwraca ostatnią linię z promptem WLC z raw output."""
        for line in reversed(raw.replace("\r", "").split("\n")):
            line = line.strip()
            if "(Cisco Controller)" in line:
                return line
        return ""

    def _ensure_toplevel(self, raw: str) -> None:
        """Jeśli jesteśmy w sub-mode (np. 'clear flexstats>'), wraca do top-level."""
        prompt = self._last_prompt(raw)
        # Top-level: "(Cisco Controller) >" — spacja przed ">"
        # Sub-mode:  "(Cisco Controller) clear flexstats>" — słowa między ) a >
        if not prompt or re.search(r'\(Cisco Controller\)\s+>', prompt):
            return  # jesteśmy na top-level
        logger.info("  sub-mode wykryty ('%s') — wychodzę...", prompt)
        for _ in range(5):
            self._shell.send("\x03")  # Ctrl+C cancels readline input completion
            time.sleep(0.5)
            self._drain()
            self._shell.settimeout(2)
            try:
                chunk = self._shell.recv(4096).decode(errors="replace")
            except socket.timeout:
                chunk = ""
            if re.search(r'\(Cisco Controller\)\s+>', chunk):
                logger.info("  wróciłem do top-level")
                return
        logger.warning("  nie udało się wrócić do top-level!")

    def _query_help(self, prefix: str) -> dict[str, str]:
        """Wysyła '<prefix> ?' i parsuje listę sub-komend."""
        cmd = (prefix + " ?\n") if prefix else "?\n"
        for attempt in range(3):
            try:
                self._drain()
                self._shell.send(cmd)
                time.sleep(2.5)
                self._shell.settimeout(5)
                raw = ""
                empty_streak = 0
                for _ in range(40):
                    try:
                        chunk = self._shell.recv(8192).decode(errors="replace")
                    except socket.timeout:
                        chunk = ""
                    if not chunk:
                        empty_streak += 1
                        if empty_streak >= 3 or self._is_wlc_prompt(raw):
                            break
                        continue
                    empty_streak = 0
                    raw += chunk
                    # --More-- MUSI być obsłużone PRZED sprawdzaniem promptu —
                    # oba mogą trafić do jednego chunka gdy strona jest ostatnia
                    if "--More--" in chunk:
                        self._shell.send(" ")
                        time.sleep(1.2)
                        continue
                    if self._is_wlc_prompt(chunk):
                        break
                self._ensure_toplevel(raw)
                return _parse_help_output(raw)
            except (OSError, EOFError, Exception) as exc:
                if attempt < 2:
                    logger.warning("_query_help błąd (%s), próba %d/3", exc, attempt + 1)
                    self._reconnect()
                else:
                    logger.error("_query_help nie powiodło się dla '%s': %s", prefix, exc)
                    return {}
        return {}

    def extract(self, prefix: str = "", depth: int = 0) -> dict:
        """Rekurencyjnie zbiera drzewo komend WLC (wszystkie poziomy)."""
        if depth > self.max_depth:
            return {}

        children = self._query_help(prefix)
        if not children:
            return {}

        # Na depth=0 akumulujemy do _partial_tree (checkpoint), głębiej — lokalny dict
        if depth == 0:
            tree = self._partial_tree
            total = len(children)
            for i, (cmd, desc) in enumerate(children.items()):
                if cmd in self._done_set:
                    logger.info("[%d/%d depth=0] skip (checkpoint): %s", i + 1, total, cmd)
                    continue

                full_path = cmd
                logger.info("[%d/%d depth=0] %s", i + 1, total, full_path)

                tags = _auto_tags(full_path, desc)
                node: dict = {"_desc": desc}
                if tags:
                    node["_tags"] = tags

                if cmd in self.SKIP_RECURSE:
                    logger.info("  skip: '%s'", cmd)
                else:
                    subtree = self.extract(full_path, depth + 1)
                    node.update(subtree)

                tree[cmd] = node
                self._done_set.add(cmd)
                self._save_checkpoint()
                logger.info("  checkpoint: %d/%d top-level gotowych", len(self._done_set), total)

            return tree

        else:
            tree = {}
            total = len(children)
            for i, (cmd, desc) in enumerate(children.items()):
                full_path = f"{prefix} {cmd}".strip()
                logger.info("[%d/%d depth=%d] %s", i + 1, total, depth, full_path)

                tags = _auto_tags(full_path, desc)
                node = {"_desc": desc}
                if tags:
                    node["_tags"] = tags

                if cmd in self.SKIP_RECURSE:
                    logger.info("  skip: '%s'", cmd)
                elif depth < self.max_depth:
                    subtree = self.extract(full_path, depth + 1)
                    node.update(subtree)

                tree[cmd] = node
            return tree


# ─────────────────────────────────────────────────────────────
# Cisco AP IOS Shell extractor (przez apciscoshell na WLC)
# ─────────────────────────────────────────────────────────────

class CiscoApShellExtractor:
    """Ekstraktor komend Cisco AP IOS Shell (wchodzi przez apciscoshell na WLC)."""

    # Tylko komendy które mogą wyrządzić szkody lub zakończyć sesję
    SKIP_RECURSE = {
        "reload", "erase",          # reboot / usunięcie konfiguracji AP
        "logout", "exit", "quit",   # kończy AP shell (wróciłoby do WLC)
    }

    # Prompt AP IOS: "hostname>" lub "hostname#" (nie zawiera "(Cisco Controller)")
    _AP_PROMPT_RE = re.compile(r"[\w][\w.\-]*\s*[>#]\s*$", re.MULTILINE)

    def __init__(self, ip: str, username: str, password: str,
                 ap_name: str = "", timeout: int = 10, max_depth: int = 2):
        self.ip = ip
        self.username = username
        self.password = password
        self.ap_name = ap_name
        self.timeout = timeout
        self.max_depth = max_depth
        self._shell = None
        self._client = None
        # checkpoint state — ustawiane przez main() przed connect()
        self._checkpoint_path: Path | None = None
        self._done_set: set[str] = set()
        self._partial_tree: dict = {}

    def connect(self):
        """Połącz z WLC, uwierzytelnij, wejdź do AP Shell."""
        import paramiko, warnings
        warnings.filterwarnings("ignore")
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(self.ip, username=self.username, password=self.password,
                  timeout=self.timeout, auth_timeout=self.timeout,
                  allow_agent=False, look_for_keys=False)
        c.get_transport().set_keepalive(20)

        shell = c.invoke_shell(width=220, height=50)
        time.sleep(2)
        banner = shell.recv(4096).decode(errors="replace")
        if "User:" in banner:
            shell.send(self.username + "\n")
            time.sleep(1)
            shell.recv(1024)
            shell.send(self.password + "\n")
            time.sleep(2)
            shell.recv(4096)

        self._client = c
        self._shell = shell
        logger.info("Połączono z WLC %s, wchodzę do AP Shell...", self.ip)

        # Wejście do AP Shell
        ap_cmd = f"apciscoshell {self.ap_name}\n" if self.ap_name else "apciscoshell\n"
        shell.send(ap_cmd)
        time.sleep(4)

        shell.settimeout(5)
        raw = ""
        for _ in range(30):
            try:
                chunk = shell.recv(4096).decode(errors="replace")
            except socket.timeout:
                chunk = ""
            raw += chunk
            if not chunk:
                # Brak danych — sprawdź czy już mamy prompt
                if self._is_ap_prompt(raw):
                    break
                continue
            if "Press Return" in chunk or "press return" in chunk.lower():
                shell.send("\n")
                time.sleep(2)
            if "AP Name" in chunk and not self.ap_name:
                raise RuntimeError(
                    "apciscoshell wymaga nazwy AP — podaj --ap-name. "
                    "Listę APów znajdziesz w: show ap summary"
                )
            if "AP Name" in chunk and self.ap_name:
                shell.send(self.ap_name + "\n")
                time.sleep(3)
            # Jeśli widzimy prompt AP (nie WLC), jesteśmy w środku
            if self._is_ap_prompt(chunk):
                break

        if not self._is_ap_prompt(raw):
            raise RuntimeError(
                f"Nie udało się wejść do AP Shell. Ostatnia odpowiedź:\n{raw[-300:]}"
            )
        logger.info("Jesteśmy w AP Shell. Prompt: %r", raw.strip().splitlines()[-1])

    def disconnect(self):
        if self._shell:
            try:
                self._shell.send("exit\n")
                time.sleep(1)
            except Exception:
                pass
        if self._client:
            self._client.close()

    def _is_ap_prompt(self, text: str) -> bool:
        """Wykrywa prompt AP IOS (nie WLC)."""
        if "(Cisco Controller)" in text:
            return False
        return bool(self._AP_PROMPT_RE.search(text))

    def _save_checkpoint(self) -> None:
        if not self._checkpoint_path:
            return
        try:
            import yaml
            _COMMANDS_DIR.mkdir(exist_ok=True)
            with open(self._checkpoint_path, "w", encoding="utf-8") as f:
                yaml.dump({"commands": self._partial_tree}, f,
                          allow_unicode=True, default_flow_style=False,
                          sort_keys=True, indent=2)
        except Exception as e:
            logger.warning("Błąd zapisu checkpointu: %s", e)

    def _drain(self) -> None:
        """Opróżnia bufor SSH przed nowym zapytaniem."""
        self._shell.settimeout(0.3)
        while True:
            try:
                leftover = self._shell.recv(4096)
                if not leftover:
                    break
            except socket.timeout:
                break

    def _query_help(self, prefix: str = "") -> dict[str, str]:
        """Wysyła '<prefix> ?' i parsuje listę komend IOS."""
        cmd = (prefix + " ?\n") if prefix else "?\n"
        for attempt in range(3):
            try:
                self._drain()
                self._shell.send(cmd)
                time.sleep(2.5)
                self._shell.settimeout(5)
                raw = ""
                empty_streak = 0
                for _ in range(40):
                    try:
                        chunk = self._shell.recv(8192).decode(errors="replace")
                    except socket.timeout:
                        chunk = ""
                    if not chunk:
                        empty_streak += 1
                        if empty_streak >= 3 or self._is_ap_prompt(raw):
                            break
                        continue
                    empty_streak = 0
                    raw += chunk
                    if "--More--" in chunk:
                        self._shell.send(" ")
                        time.sleep(1.2)
                        continue
                    if self._is_ap_prompt(chunk):
                        break
                return _parse_help_output(raw)
            except (OSError, EOFError, Exception) as exc:
                if attempt < 2:
                    logger.warning("AP _query_help błąd (%s), próba %d/3", exc, attempt + 1)
                else:
                    logger.error("AP _query_help nie powiodło się dla '%s': %s", prefix, exc)
                    return {}
        return {}

    def extract(self, prefix: str = "", depth: int = 0) -> dict:
        """Rekurencyjnie zbiera drzewo komend AP IOS."""
        if depth > self.max_depth:
            return {}

        children = self._query_help(prefix)
        if not children:
            return {}

        # Na depth=0 akumulujemy do _partial_tree (checkpoint), głębiej — lokalny dict
        if depth == 0:
            tree = self._partial_tree
            total = len(children)
            for i, (cmd, desc) in enumerate(children.items()):
                if cmd in self._done_set:
                    logger.info("[%d/%d depth=0] AP: skip (checkpoint): %s", i + 1, total, cmd)
                    continue

                full_path = cmd
                logger.info("[%d/%d depth=0] AP: %s", i + 1, total, full_path)

                tags = _auto_tags(full_path, desc)
                node: dict = {"_desc": desc}
                if tags:
                    node["_tags"] = tags

                if cmd in self.SKIP_RECURSE:
                    logger.info("  skip: '%s'", cmd)
                else:
                    subtree = self.extract(full_path, depth + 1)
                    node.update(subtree)

                tree[cmd] = node
                self._done_set.add(cmd)
                self._save_checkpoint()
                logger.info("  checkpoint: %d/%d top-level gotowych", len(self._done_set), total)

            return tree

        else:
            tree = {}
            total = len(children)
            for i, (cmd, desc) in enumerate(children.items()):
                full_path = f"{prefix} {cmd}".strip()
                logger.info("[%d/%d depth=%d] AP: %s", i + 1, total, depth, full_path)

                tags = _auto_tags(full_path, desc)
                node = {"_desc": desc}
                if tags:
                    node["_tags"] = tags

                if cmd in self.SKIP_RECURSE:
                    logger.info("  skip: '%s'", cmd)
                elif depth < self.max_depth:
                    subtree = self.extract(full_path, depth + 1)
                    node.update(subtree)

                tree[cmd] = node
            return tree


# ─────────────────────────────────────────────────────────────
# Zapis do YAML
# ─────────────────────────────────────────────────────────────

def save_command_ref(model: str, firmware: str, tree: dict,
                     source_ip: str = "", notes: str = "",
                     system: str = "") -> Path:
    """Zapisuje drzewo komend do device_commands/<slug>.yaml."""
    try:
        import yaml
    except ImportError:
        raise ImportError("PyYAML wymagany: pip install pyyaml")

    _COMMANDS_DIR.mkdir(exist_ok=True)
    slug = _slugify(model, firmware)
    out_path = _COMMANDS_DIR / f"{slug}.yaml"

    def count_all(d: dict) -> int:
        n = 0
        for k, v in d.items():
            if not k.startswith("_") and isinstance(v, dict):
                n += 1 + count_all(v)
        return n

    total = count_all(tree)
    data = {
        "model": model,
        "firmware": firmware,
        "source_ip": source_ip,
        "system": system,
        "notes": notes,
        "commands": tree,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, default_flow_style=False,
                  sort_keys=True, indent=2)

    logger.info("Zapisano %d komend (łącznie) do %s", total, out_path)
    return out_path


# ─────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────

def _load_checkpoint(checkpoint_path: Path, extractor: object) -> None:
    """Wczytuje checkpoint do extractora jeśli plik istnieje."""
    if not checkpoint_path.exists():
        extractor._checkpoint_path = checkpoint_path
        return
    try:
        import yaml
        with open(checkpoint_path, encoding="utf-8") as f:
            partial = yaml.safe_load(f) or {}
        commands = partial.get("commands") or {}
        extractor._partial_tree = dict(commands)
        extractor._done_set = set(commands.keys())
        extractor._checkpoint_path = checkpoint_path
        logger.info(
            "Wznawiam od checkpointu — już gotowe top-level: %s",
            sorted(extractor._done_set),
        )
    except Exception as e:
        logger.warning("Nie można wczytać checkpointu (%s) — zaczynam od nowa", e)
        extractor._checkpoint_path = checkpoint_path


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    p = argparse.ArgumentParser(description="Zbiera drzewo komend CLI z urządzenia SSH")
    p.add_argument("--ip", required=True)
    p.add_argument("--user", default="",
                   help="Nazwa użytkownika SSH (alternatywnie --cred-id)")
    p.add_argument("--password", default="",
                   help="Hasło SSH w plaintext — niezalecane, użyj --cred-id")
    p.add_argument("--cred-id", type=int, default=None,
                   help="ID credential z bazy NetDoc (bezpieczniejsze niż --password)")
    p.add_argument("--mode", default="cisco_wlc",
                   choices=["cisco_wlc", "cisco_ap_shell"],
                   help="Tryb ekstrakcji")
    p.add_argument("--ap-name", default="",
                   help="Nazwa AP dla trybu cisco_ap_shell (z 'show ap summary')")
    p.add_argument("--model", default="Unknown Device")
    p.add_argument("--firmware", default="unknown")
    p.add_argument("--max-depth", type=int, default=15,
                   help="Max recursion depth safety cap (default: 15, natural stop is earlier)")
    p.add_argument("--notes", default="")
    args = p.parse_args()

    # Rozwiązanie credentials — z DB (--cred-id) lub z argumentów
    username, password = args.user, args.password
    if args.cred_id:
        try:
            from netdoc.storage.database import SessionLocal
            from netdoc.storage.models import Credential
            from netdoc.config.credentials import decrypt
            db = SessionLocal()
            cred = db.query(Credential).filter(Credential.id == args.cred_id).first()
            db.close()
            if not cred:
                raise SystemExit(f"Credential ID={args.cred_id} nie istnieje w bazie")
            username = cred.username
            try:
                password = decrypt(cred.password_encrypted)
            except Exception:
                # Cred worker stores discovered passwords as plaintext in password_encrypted
                password = cred.password_encrypted
            logger.info("Użyto credential ID=%d (user=%s) z bazy", args.cred_id, username)
        except ImportError:
            raise SystemExit("Brak dostępu do bazy NetDoc — sprawdź czy DATABASE_URL jest ustawiony w .env")
    elif not username or not password:
        raise SystemExit("Podaj --cred-id LUB --user i --password")

    slug = _slugify(args.model, args.firmware)
    checkpoint_path = _COMMANDS_DIR / f"{slug}.partial.yaml"

    if args.mode == "cisco_wlc":
        extractor = CiscoWlcExtractor(
            ip=args.ip, username=username, password=password,
            max_depth=args.max_depth,
        )
        _load_checkpoint(checkpoint_path, extractor)
        extractor.connect()
        try:
            logger.info("Zaczynam zbieranie WLC (depth=%d)...", args.max_depth)
            tree = extractor.extract()
        finally:
            extractor.disconnect()
        system = "wlc-controller"

    elif args.mode == "cisco_ap_shell":
        extractor = CiscoApShellExtractor(
            ip=args.ip, username=username, password=password,
            ap_name=args.ap_name, max_depth=args.max_depth,
        )
        _load_checkpoint(checkpoint_path, extractor)
        extractor.connect()
        try:
            logger.info("Zaczynam zbieranie AP Shell (depth=%d)...", args.max_depth)
            tree = extractor.extract()
        finally:
            extractor.disconnect()
        system = "ap-shell"

    else:
        raise NotImplementedError(f"Tryb {args.mode} nie jest zaimplementowany")

    out_path = save_command_ref(
        model=args.model,
        firmware=args.firmware,
        tree=tree,
        source_ip=args.ip,
        notes=args.notes,
        system=system,
    )

    # Usuń checkpoint — ekstrakcja zakończona sukcesem
    if checkpoint_path.exists():
        checkpoint_path.unlink()
        logger.info("Usunięto checkpoint: %s", checkpoint_path)

    print(f"\nGotowe! Zapisano do: {out_path}")
    print(f"Top-level komend: {len(tree)}")


if __name__ == "__main__":
    main()
