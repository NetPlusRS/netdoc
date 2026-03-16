"""Testy regresyjne dla seed_default_credentials().

Weryfikuje:
- hasla sa przechowywane zaszyfrowane (Fernet), nie jako plaintext
- powторne wywolanie nie dodaje duplikatow
- obsluga wsteczna: istniejace wpisy z plaintext sa tolerowane (brak wyjatku)
- wszystkie metody (ssh, telnet, api, rdp, vnc, ftp) sa seedowane
"""
import pytest
from unittest.mock import patch

from netdoc.storage.models import Credential, CredentialMethod
from netdoc.config.credentials import decrypt


def _call_seed(db):
    import run_scanner
    run_scanner.seed_default_credentials(db)


# ─── Szyfrowanie ──────────────────────────────────────────────────────────────

def test_passwords_are_encrypted(db):
    """Hasla w bazie musza byc zaszyfrowane Fernet, nie plaintext."""
    _call_seed(db)
    creds = db.query(Credential).filter(Credential.device_id == None).all()
    assert len(creds) > 0, "Seed nie dodal zadnych credentials"

    for c in creds:
        pw = c.password_encrypted or ""
        if not pw:
            continue  # puste haslo (np. SNMP community bez hasla) — OK
        # Zaszyfrowany Fernet token zaczyna sie od "gAAAAA" (base64 URL-safe)
        assert pw.startswith("gAAAAA"), (
            f"Credential {c.username!r} method={c.method}: "
            f"password_encrypted wyglada jak plaintext: {pw[:30]!r}"
        )


def test_passwords_can_be_decrypted(db):
    """Odszyfrowanie kazdego hasla nie rzuca wyjatku."""
    _call_seed(db)
    creds = db.query(Credential).filter(Credential.device_id == None).all()
    for c in creds:
        pw = c.password_encrypted or ""
        if not pw:
            continue
        try:
            plaintext = decrypt(pw)
        except Exception as e:
            pytest.fail(
                f"Nie mozna odszyfrować hasla dla {c.username!r} "
                f"method={c.method}: {e}. Wartosc: {pw[:30]!r}"
            )
        assert isinstance(plaintext, str)


# ─── Brak duplikatow ──────────────────────────────────────────────────────────

def test_no_duplicates_on_double_call(db):
    """Dwukrotne wywolanie nie duplikuje credentials."""
    _call_seed(db)
    count_after_first = db.query(Credential).filter(Credential.device_id == None).count()

    _call_seed(db)
    count_after_second = db.query(Credential).filter(Credential.device_id == None).count()

    assert count_after_first == count_after_second, (
        f"Duplikaty po 2. wywolaniu: {count_after_first} -> {count_after_second}"
    )


# ─── Wszystkie metody seedowane ───────────────────────────────────────────────

@pytest.mark.parametrize("method", [
    CredentialMethod.ssh,
    CredentialMethod.telnet,
    CredentialMethod.api,
    CredentialMethod.rdp,
    CredentialMethod.vnc,
    CredentialMethod.ftp,
])
def test_all_methods_seeded(db, method):
    """Kazda metoda ma co najmniej jeden seeded credential."""
    _call_seed(db)
    creds = db.query(Credential).filter(
        Credential.method == method,
        Credential.device_id == None,
    ).all()
    assert len(creds) > 0, f"Brak credentials dla metody: {method}"


# ─── Obsluga wsteczna: plaintext w bazie ─────────────────────────────────────

def test_backward_compat_plaintext_in_db(db):
    """Jesli w bazie sa stare wpisy z plaintext, seed nie rzuca wyjatku i nie duplikuje ich."""
    # Symuluj stary wpis (plaintext zamiast zaszyfrowanego)
    db.add(Credential(
        device_id=None,
        method=CredentialMethod.ssh,
        username="uniqueuser_test",
        password_encrypted="uniquepass_test",  # stary plaintext
        priority=999,
        notes="stary wpis (plaintext)",
    ))
    db.commit()

    count_before = db.query(Credential).filter(Credential.device_id == None).count()

    # Seed nie powinien rzucic wyjatku
    _call_seed(db)

    # Liczba credentials z username="uniqueuser_test" nie powinna wzrosnac
    # (seed nie doda go ponownie, bo nie ma go w liscie seedow)
    creds_unique = db.query(Credential).filter(
        Credential.method == CredentialMethod.ssh,
        Credential.device_id == None,
        Credential.username == "uniqueuser_test",
    ).all()
    assert len(creds_unique) == 1, f"Stary plaintext wpis zostal zduplikowany: {len(creds_unique)}"


# ─── Szczegolowy test: admin/admin jest w seedzie SSH ─────────────────────────

def test_admin_admin_in_ssh_seed(db):
    """admin/admin musi byc w seedzie SSH i zaszyfrowany."""
    _call_seed(db)
    all_admin_ssh = db.query(Credential).filter(
        Credential.method == CredentialMethod.ssh,
        Credential.device_id == None,
        Credential.username == "admin",
    ).all()
    assert len(all_admin_ssh) > 0, "Brak credentials admin/* w SSH seed"

    # Sprawdz ze istnieje admin/admin (odszyfrowany)
    admin_admin = [
        c for c in all_admin_ssh
        if (c.password_encrypted or "").startswith("gAAAAA")
        and decrypt(c.password_encrypted) == "admin"
    ]
    assert len(admin_admin) >= 1, (
        "Brak admin/admin w SSH seed lub haslo nie jest zaszyfrowane poprawnie"
    )
