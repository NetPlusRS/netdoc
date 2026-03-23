import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, computed_field
from typing import List, Optional

# Resolve .env from project root (2 levels up from netdoc/config/),
# regardless of working directory when the process was started.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_ENV_FILE = os.path.join(_PROJECT_ROOT, ".env")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database — mozna podac jako pelny URL lub jako osobne zmienne
    db_url: Optional[str] = Field(default=None)
    db_host: str = Field(default="localhost")
    db_port: int = Field(default=5432)
    db_name: str = Field(default="netdoc")
    db_user: str = Field(default="netdoc")
    db_password: str = Field(default="netdoc")

    @computed_field
    @property
    def database_url(self) -> str:
        """Zwraca finalny URL bazy danych. DB_URL ma pierwszenstwo."""
        if self.db_url:
            return self.db_url
        return (
            f"postgresql+psycopg2://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    # UniFi
    unifi_host: str = Field(default="https://api.ui.com")
    unifi_username: str = Field(default="")
    unifi_password: str = Field(default="")

    # Discovery
    # Puste = auto-wykrywanie z lokalnych interfejsow (zalecane — nie trzeba ustawiac)
    # Format CSV: "192.168.1.0/24" lub "192.168.1.0/24,10.0.0.0/8"
    # Typ str zamiast List[str] — pydantic-settings v2 nie probuje JSON-decode plain stringa
    network_ranges: str = Field(default="")
    scan_interval_minutes: int = Field(default=60)
    # Skanowanie przez VPN - domyslnie wylaczone (ryzyko skanowania sieci klienta)
    scan_vpn_networks: bool = Field(default=False)
    # Skanowanie sieci wirtualnych (Docker, Hyper-V, WSL, VMware) - domyslnie wylaczone
    scan_virtual_networks: bool = Field(default=False)

    # Security
    secret_key: str = Field(default="change-me-in-production")

    # Vulnerability — XMEye brute-force
    # Wlaczenie proba odgadniecia hasla przez brute-force (krótkie hasla cyfry/litery)
    # UWAGA: Uzywac tylko na wlasnej infrastrukturze lub za pisemna zgoda wlasciciela
    xmeye_bruteforce_enabled: bool = Field(default=False)
    # Maksymalna dlugosc hasla do sprawdzenia (1-6; >4 drastycznie wydluz czas)
    xmeye_bruteforce_max_len: int = Field(default=4)
    # Charset: "digits" (0-9), "lower" (a-z), "lower+digits" (a-z0-9)
    xmeye_bruteforce_charset: str = Field(default="digits")

    # API
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)

    # Logging
    log_level: str = Field(default="INFO")

    @property
    def network_ranges_list(self) -> List[str]:
        """Zwraca zakresy jako liste (obsluguje format CSV z .env)."""
        if isinstance(self.network_ranges, str):
            return [r.strip() for r in self.network_ranges.split(",")]
        return self.network_ranges


settings = Settings()
