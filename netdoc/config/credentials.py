import base64
import os
from cryptography.fernet import Fernet
from netdoc.config.settings import settings


def _get_fernet() -> Fernet:
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
