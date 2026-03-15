"""Testy modułu port_kb.py — baza wiedzy o portach."""
import pytest
from netdoc.web.port_kb import PORT_KB, PORT_CATEGORIES, lookup_port, lookup_ports


VALID_RISKS = {"critical", "high", "medium", "low", "info"}
REQUIRED_KEYS = {"port", "proto", "service", "category", "desc", "vendors", "risk", "risk_note"}


# ── Integralność danych PORT_KB ────────────────────────────────────────────────

def test_port_kb_not_empty():
    assert len(PORT_KB) > 50, "PORT_KB powinien mieć co najmniej 50 wpisów"


def test_port_kb_required_fields():
    """Każdy wpis musi mieć wszystkie wymagane klucze."""
    for e in PORT_KB:
        missing = REQUIRED_KEYS - e.keys()
        assert not missing, f"Port {e.get('port')} brakuje pól: {missing}"


def test_port_kb_risk_values():
    """Każdy wpis musi mieć dozwolony poziom ryzyka."""
    for e in PORT_KB:
        assert e["risk"] in VALID_RISKS, (
            f"Port {e['port']}: nieprawidłowe risk={e['risk']!r}. Dozwolone: {VALID_RISKS}"
        )


def test_port_kb_categories_valid():
    """Każdy wpis musi mieć kategorię zdefiniowaną w PORT_CATEGORIES."""
    for e in PORT_KB:
        assert e["category"] in PORT_CATEGORIES, (
            f"Port {e['port']}: nieznana kategoria {e['category']!r}"
        )


def test_port_kb_port_is_int():
    """Numer portu musi być int z zakresu 1–65535."""
    for e in PORT_KB:
        assert isinstance(e["port"], int), f"Port {e['port']} nie jest int"
        assert 1 <= e["port"] <= 65535, f"Port {e['port']} poza zakresem 1–65535"


def test_port_kb_proto_values():
    """Protokół musi być tcp, udp lub tcp/udp."""
    valid_protos = {"tcp", "udp", "tcp/udp"}
    for e in PORT_KB:
        assert e["proto"] in valid_protos, (
            f"Port {e['port']}: nieprawidłowy proto={e['proto']!r}"
        )


def test_port_kb_vendors_is_list():
    """vendors musi być listą."""
    for e in PORT_KB:
        assert isinstance(e["vendors"], list), f"Port {e['port']}: vendors nie jest listą"
        assert len(e["vendors"]) >= 1, f"Port {e['port']}: pusta lista vendors"


def test_port_kb_ot_is_bool():
    """Flaga ot musi być bool."""
    for e in PORT_KB:
        if "ot" in e:
            assert isinstance(e["ot"], bool), (
                f"Port {e['port']}: ot={e['ot']!r} nie jest bool"
            )


def test_port_kb_strings_nonempty():
    """service, desc i risk_note nie mogą być puste."""
    for e in PORT_KB:
        assert e["service"].strip(), f"Port {e['port']}: puste service"
        assert e["desc"].strip(),    f"Port {e['port']}: puste desc"
        assert e["risk_note"].strip(), f"Port {e['port']}: puste risk_note"


def test_port_kb_ot_ports_exist():
    """Port KB musi zawierać co najmniej kilka portów OT/SCADA."""
    ot_entries = [e for e in PORT_KB if e.get("ot")]
    assert len(ot_entries) >= 5, f"Za mało portów OT: {len(ot_entries)}"


def test_port_kb_critical_ports_present():
    """Krytyczne porty (Telnet 23, FTP 21, RDP 3389) muszą być w bazie."""
    ports_in_kb = {e["port"] for e in PORT_KB}
    for critical in (21, 22, 23, 80, 443, 3389):
        assert critical in ports_in_kb, f"Brak portu {critical} w PORT_KB"


def test_port_categories_not_empty():
    assert len(PORT_CATEGORIES) >= 10, "PORT_CATEGORIES powinien mieć co najmniej 10 kategorii"


def test_port_categories_values_are_strings():
    for key, label in PORT_CATEGORIES.items():
        assert isinstance(key, str) and key, f"Pusty klucz kategorii"
        assert isinstance(label, str) and label, f"Pusta etykieta dla {key!r}"


# ── Risk distribution — żaden poziom nie może być pusty ──────────────────────

def test_port_kb_risk_distribution():
    """Każdy poziom ryzyka musi mieć co najmniej 1 wpis."""
    from collections import Counter
    counts = Counter(e["risk"] for e in PORT_KB)
    for risk in ("critical", "high", "medium", "low"):
        assert counts[risk] >= 1, f"Brak wpisów z risk={risk!r}"


# ── lookup_port ────────────────────────────────────────────────────────────────

def test_lookup_port_known_port():
    """lookup_port(22) zwraca co najmniej 1 wpis dla SSH."""
    result = lookup_port(22)
    assert isinstance(result, list)
    assert len(result) >= 1
    assert result[0]["port"] == 22


def test_lookup_port_unknown_returns_empty():
    """lookup_port dla nieznanego portu zwraca pustą listę."""
    result = lookup_port(65534)
    assert result == []


def test_lookup_port_result_has_required_keys():
    """Wpis zwrócony przez lookup_port ma wszystkie wymagane pola."""
    result = lookup_port(80)
    assert result, "Port 80 musi być w bazie"
    for key in REQUIRED_KEYS:
        assert key in result[0], f"Brak klucza {key!r} w lookup_port(80)"


def test_lookup_port_telnet_is_critical():
    """Telnet (port 23) musi mieć risk=critical lub high."""
    result = lookup_port(23)
    assert result, "Port 23 (Telnet) musi być w bazie"
    assert result[0]["risk"] in ("critical", "high"), (
        f"Telnet powinien mieć wysokie ryzyko, got: {result[0]['risk']}"
    )


def test_lookup_port_modbus_is_ot():
    """Modbus (port 502) musi być oznaczony jako OT."""
    result = lookup_port(502)
    assert result, "Port 502 (Modbus) musi być w bazie"
    assert result[0].get("ot") is True, "Modbus musi mieć ot=True"


# ── lookup_ports ───────────────────────────────────────────────────────────────

def test_lookup_ports_returns_dict():
    result = lookup_ports([22, 80, 443])
    assert isinstance(result, dict)
    assert 22 in result
    assert 80 in result
    assert 443 in result


def test_lookup_ports_empty_list():
    result = lookup_ports([])
    assert result == {}


def test_lookup_ports_unknown_ports_excluded():
    """Nieznane porty nie trafiają do wyniku lookup_ports."""
    result = lookup_ports([65533, 65534])
    assert result == {}, "Nieznane porty nie powinny byc w wyniku"


def test_lookup_ports_mixed():
    """lookup_ports z mieszana lista — tylko znane porty w wyniku."""
    result = lookup_ports([22, 65534, 80])
    assert 22 in result
    assert 80 in result
    assert 65534 not in result
