"""Testy weryfikujace ze wymagane biblioteki sa zainstalowane i importowalne."""
import importlib
import sys
import pytest


REQUIRED_IMPORTS = [
    # (modul, atrybut_do_sprawdzenia, opis)
    ("fastapi",              "FastAPI",         "FastAPI framework"),
    ("sqlalchemy",           "create_engine",   "SQLAlchemy ORM"),
    ("pydantic",             "BaseModel",       "Pydantic validation"),
    ("psycopg2",             "connect",         "PostgreSQL driver"),
    ("flask",                "Flask",           "Flask web UI"),
    ("requests",             "get",             "HTTP requests"),
    ("cryptography.fernet",  "Fernet",          "Szyfrowanie credentials"),
    ("nmap",                 "PortScanner",     "python-nmap"),
    ("netmiko",              "ConnectHandler",  "Netmiko SSH"),
    ("pysnmp",               None,              "PySNMP SNMP"),
    ("pymodbus.client",      "ModbusTcpClient", "pymodbus Modbus TCP"),
    ("prometheus_client",    "Counter",         "Prometheus metrics"),
    ("networkx",             "Graph",           "NetworkX topologia"),
    ("apscheduler",          None,              "APScheduler"),
    ("psutil",               "net_if_addrs",    "psutil siec"),
    ("ping3",                "ping",            "ping3 ICMP probe (ping-worker)"),
]


@pytest.mark.parametrize("module,attr,desc", REQUIRED_IMPORTS, ids=[r[2] for r in REQUIRED_IMPORTS])
def test_required_import(module, attr, desc):
    """Sprawdza ze biblioteka jest zainstalowana i importowalna."""
    try:
        mod = importlib.import_module(module)
    except ImportError as e:
        pytest.fail(f"{desc}: nie mozna zaimportowac '{module}': {e}")
    if attr:
        assert hasattr(mod, attr), (
            f"{desc}: modul '{module}' nie ma atrybutu '{attr}' — "
            f"zla wersja biblioteki?"
        )


def test_pymodbus_client_importable():
    """pymodbus 3.x musi eksportowac ModbusTcpClient z pymodbus.client."""
    from pymodbus.client import ModbusTcpClient
    assert ModbusTcpClient is not None


def test_no_pymodbus_fallback_needed():
    """Sprawdza ze nie uzywamy fallback na pymodbus 2.x (stary import)."""
    try:
        from pymodbus.client import ModbusTcpClient  # noqa: F401
        ok = True
    except ImportError:
        ok = False
    assert ok, "pymodbus.client.ModbusTcpClient niedostepne — zainstaluj pymodbus>=3.0"


def test_netdoc_collector_imports():
    """Kluczowe moduly netdoc musza byc importowalne bez bledow."""
    import netdoc.storage.models      # noqa: F401
    import netdoc.storage.database    # noqa: F401
    import netdoc.collector.pipeline  # noqa: F401
    import netdoc.collector.drivers.modbus  # noqa: F401
    import netdoc.web.app             # noqa: F401


def test_modbus_driver_not_none():
    """ModbusTcpClient w netdoc.collector.drivers.modbus musi byc ustawiony (nie None)."""
    from netdoc.collector.drivers.modbus import ModbusTcpClient
    assert ModbusTcpClient is not None, (
        "pymodbus nie jest zainstalowany lub ma zly format importu — "
        "sprawdz ze pymodbus>=3.0 jest w requirements.txt i zainstalowany"
    )


def test_pysnmp_lextudio_not_in_requirements():
    """pysnmp-lextudio nie moze byc w requirements.txt — zastapiony przez pysnmp."""
    from pathlib import Path
    req = Path("requirements.txt").read_text(encoding="utf-8")
    assert "pysnmp-lextudio" not in req, (
        "pysnmp-lextudio znaleziony w requirements.txt — "
        "uzyj 'pysnmp' zamiast przestarzalego forka lextudio"
    )


def test_pysnmp_not_deprecated():
    """Importowanie pysnmp nie powinno emitowac RuntimeWarning o przestarzalosci."""
    import warnings
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", RuntimeWarning)
        import importlib
        importlib.import_module("pysnmp")
    runtime_warns = [str(w.message) for w in caught if issubclass(w.category, RuntimeWarning)]
    deprecated = [m for m in runtime_warns if "deprecated" in m.lower() and "pysnmp" in m.lower()]
    assert not deprecated, (
        f"pysnmp emituje RuntimeWarning o przestarzalosci: {deprecated[0]!r}\n"
        "Sprawdz ze requirements.txt uzywa 'pysnmp', nie 'pysnmp-lextudio'."
    )
