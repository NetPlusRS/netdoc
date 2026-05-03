"""Shared SSH utilities and YAML I/O for NetDoc CLI extractors.

Tracked (public) — defines the interface that all vendor extractors implement.
Vendor-specific extractor modules (cisco_wlc.py, unifi_udm.py, ...) are
gitignored because the extraction mechanism is proprietary know-how.
"""

import re
from abc import ABC, abstractmethod
from pathlib import Path

# netdoc/collector/cli/base.py -> up 4 levels = project root
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
CLI_LIBRARY  = PROJECT_ROOT / "cli-library"


# ── Credentials ─────────────────────────────────────────────────────────────

def get_cred_from_db(cred_id: int) -> tuple:
    """Return (username, password) from DB.

    Loads .env BEFORE importing database.py (which builds the SQLAlchemy engine
    at module level — importing without a loaded DATABASE_URL causes a timeout).
    """
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")

    from netdoc.storage.database import SessionLocal
    from netdoc.storage.models import Credential
    from netdoc.config.credentials import decrypt

    with SessionLocal() as db:
        cred = db.query(Credential).filter(Credential.id == cred_id).first()
        if not cred:
            raise ValueError(f"Credential ID={cred_id} not found in DB")
        try:
            password = decrypt(cred.password_encrypted)
        except Exception:
            password = cred.password_encrypted
        return cred.username, password


# ── SSH helpers ──────────────────────────────────────────────────────────────

def ssh_connect(host: str, username: str, password: str,
                port: int = 22, timeout: int = 15):
    """Return a connected paramiko.SSHClient (password auth, no agent/keys)."""
    try:
        import paramiko
    except ImportError:
        raise RuntimeError("paramiko not installed — run: pip install paramiko")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host, port=port, username=username, password=password,
        timeout=timeout, allow_agent=False, look_for_keys=False,
    )
    return client


def exec_cmd(client, cmd: str, timeout: int = 10) -> str:
    """Run a command via exec_command (no PTY). Returns stdout."""
    try:
        _, stdout, _ = client.exec_command(cmd, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


# ── YAML path helpers ────────────────────────────────────────────────────────

def firmware_short(firmware: str) -> str:
    """Return major.minor from a firmware version string."""
    parts = re.split(r"[.\-]", firmware or "")
    return ".".join(parts[:2]) if len(parts) >= 2 else (firmware or "unknown")


def yaml_path(vendor: str, platform: str, firmware: str) -> Path:
    """Return canonical path: cli-library/<vendor>/<platform>/<fw_short>.yaml"""
    return CLI_LIBRARY / vendor / platform / f"{firmware_short(firmware)}.yaml"


def save_yaml(vendor: str, platform: str, firmware: str, doc: dict) -> Path:
    """Serialize doc to YAML at the canonical cli-library path."""
    try:
        import yaml
    except ImportError:
        raise RuntimeError("PyYAML not installed — run: pip install pyyaml")

    out = yaml_path(vendor, platform, firmware)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        yaml.dump(doc, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return out


# ── Abstract base extractor ──────────────────────────────────────────────────

class BaseCliExtractor(ABC):
    """Interface every vendor extractor must implement.

    Subclass this in your vendor module, set `vendor` and `platform`, then
    implement `run()`. The base provides `connect()`, `exec()`, and `save()`.
    """

    vendor: str   = ""   # e.g. "cisco"
    platform: str = ""   # e.g. "mobility-express"

    def __init__(self, host: str, username: str, password: str,
                 port: int = 22, timeout: int = 15):
        self.host     = host
        self.username = username
        self.password = password
        self.port     = port
        self.timeout  = timeout
        self._client  = None

    def connect(self):
        """Open SSH connection and store as self._client."""
        self._client = ssh_connect(
            self.host, self.username, self.password,
            port=self.port, timeout=self.timeout,
        )
        return self._client

    def exec(self, cmd: str, timeout: int = 10) -> str:
        """Run command via exec_command on the active SSH session."""
        return exec_cmd(self._client, cmd, timeout)

    def disconnect(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    def save(self, firmware: str, doc: dict) -> Path:
        """Save command reference to cli-library/<vendor>/<platform>/<fw>.yaml"""
        return save_yaml(self.vendor, self.platform, firmware, doc)

    @abstractmethod
    def run(self) -> Path:
        """Connect, extract, save YAML, disconnect. Return path to saved file."""
