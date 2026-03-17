import base64
import logging
import os
from cryptography.fernet import Fernet
from netdoc.config.settings import settings

_cred_logger = logging.getLogger(__name__)

_DEFAULT_SECRET_KEY = "change-me-in-production"


def _get_fernet() -> Fernet:
    # BUG-SEC-2: ostrzezenie gdy uzyty jest domyslny klucz szyfrowania
    if settings.secret_key == _DEFAULT_SECRET_KEY:
        _cred_logger.warning(
            "SECURITY: uzywany domyslny SECRET_KEY ('%s'). "
            "Ustaw SECRET_KEY w .env — credentials w bazie sa latwe do odszyfrowania!",
            _DEFAULT_SECRET_KEY,
        )
    key_bytes = settings.secret_key.encode()
    # Fernet wymaga 32-bajtowego klucza zakodowanego w base64 url-safe
    padded = key_bytes.ljust(32)[:32]
    encoded = base64.urlsafe_b64encode(padded)
    return Fernet(encoded)


def encrypt(plaintext: str) -> str:
    """Szyfruje ciag znakow i zwraca zakodowany string."""
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Deszyfruje zakodowany string."""
    return _get_fernet().decrypt(ciphertext.encode()).decode()
