"""Network Tier Analyzer — automatyczne wykrywanie roli urządzenia w topologii sieci.

Analizuje dostępne sygnały (LLDP, FDB, interfejsy, STP, typ urządzenia)
i przypisuje tier: core / dist / access / edge / undef.

Każdy sygnał ma wagę. Confidence = f(liczba_znanych_sygnałów, dominacja_zwycięzcy).
Przy tier_overridden=True wynik nie jest nadpisywany.

Uruchamiany:
  - automatycznie po każdym cyklu SNMP w run_snmp_worker.py
  - na żądanie przez API: POST /api/devices/{id}/tier/analyze
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ── Etykiety i opisy tierów ──────────────────────────────────────────────────

TIER_LABELS = {
    "core":   "Core",
    "dist":   "Distribution",
    "access": "Access",
    "edge":   "Edge / WAN",
    "undef":  "Unknown",
}

TIER_COLORS = {
    "core":   "danger",
    "dist":   "warning",
    "access": "success",
    "edge":   "info",
    "undef":  "secondary",
}

# ── Podpowiedzi konfiguracyjne per vendor/OS ─────────────────────────────────

_HINTS_CISCO_IOS = {
    "lldp": [
        "lldp run",
        "! (na każdym interface)",
        "interface range GigabitEthernet0/1 - 24",
        "  lldp transmit",
        "  lldp receive",
    ],
    "ssh": [
        "ip ssh version 2",
        "crypto key generate rsa modulus 2048",
        "username netdoc privilege 15 secret <haslo>",
        "line vty 0 15",
        "  login local",
        "  transport input ssh",
    ],
    "snmp": [
        "snmp-server community public ro",
        "snmp-server community private rw",
    ],
    "stp": [
        "! Sprawdź priorytety STP:",
        "show spanning-tree summary",
        "show spanning-tree vlan 1 detail",
    ],
    "interfaces": [
        "show interfaces trunk",
        "show interfaces status",
    ],
    "routing": [
        "show ip interface brief",
        "show ip route summary",
        "show ip protocols",
    ],
}

_HINTS_UBIQUITI = {
    "lldp": [
        "! UniFi: Settings → Site → Services → LLDP",
        "! lub w CLI urządzenia: set service lldp",
    ],
    "snmp": [
        "! UniFi Controller: Settings → System → SNMP",
        "! Community: public, port 161",
    ],
    "ssh": [
        "! UniFi: Settings → System → SSH",
        "! Włącz SSH i ustaw hasło",
    ],
}

_HINTS_GENERIC = {
    "lldp": ["! Włącz LLDP w konfiguracji urządzenia"],
    "snmp": ["! Włącz SNMP v2c z community 'public'"],
    "ssh":  ["! Włącz SSH (protocol v2)"],
}


def _get_hints(vendor: Optional[str], os_version: Optional[str], topic: str) -> list[str]:
    """Zwraca listę komend/wskazówek dla danego vendora i tematu."""
    v = (vendor or "").lower()
    o = (os_version or "").lower()
    if "cisco" in v or "ios" in o or "catalyst" in o:
        return _HINTS_CISCO_IOS.get(topic, _HINTS_GENERIC.get(topic, []))
    if "ubiquiti" in v or "ubnt" in v or "unifi" in o:
        return _HINTS_UBIQUITI.get(topic, _HINTS_GENERIC.get(topic, []))
    return _HINTS_GENERIC.get(topic, [])


# ── Główna funkcja analizy ────────────────────────────────────────────────────

def analyze_device_tier(device_id: int, db, force: bool = False) -> dict[str, Any]:
    """Analizuje tier urządzenia na podstawie dostępnych danych w DB.

    Args:
        device_id: ID urządzenia w tabeli devices
        db: aktywna sesja SQLAlchemy
        force: jeśli True — pomija sprawdzenie tier_overridden (używane przez /tier/analyze endpoint)

    Returns:
        dict z kluczami: tier, confidence, evidence (signals+missing)
        Zapisuje wynik do devices.network_tier / tier_confidence / tier_evidence / tier_analyzed_at
    """
    from netdoc.storage.models import (
        Device, DeviceType, Interface, TopologyLink,
        DeviceFdbEntry, DeviceVlanPort,
    )
    from sqlalchemy import func

    dev = db.query(Device).filter(Device.id == device_id).first()
    if not dev:
        return {"tier": "undef", "confidence": 0, "evidence": {"signals": [], "missing": []}}

    # Jeśli użytkownik ręcznie ustawił tier — nie nadpisuj (chyba że force=True)
    # BUG-L7 fix: sprawdzaj tylko tier_overridden (nie network_tier) — None traktowane jako False
    if not force and dev.tier_overridden:
        return {
            "tier": dev.network_tier or "undef",
            "confidence": dev.tier_confidence or 0,
            "evidence": dev.tier_evidence or {"signals": [], "missing": []},
        }

    vendor    = dev.vendor or ""
    os_ver    = dev.os_version or ""
    dev_type  = dev.device_type

    signals: list[dict] = []   # [{icon, text}] — sygnały które faktycznie wniosły punkty
    missing: list[dict] = []   # [{icon, text, hints:[str]}]

    scores = {"core": 0, "dist": 0, "access": 0, "edge": 0}
    scored_signal_count = 0  # tylko sygnały które zmieniły scores — do data_fraction
    max_signals = 0  # ile sygnałów mogło wnieść punkty

    # ── 1. Typ urządzenia ────────────────────────────────────────────────────
    max_signals += 1
    if dev_type in (DeviceType.router, DeviceType.firewall):
        scores["edge"] += 35
        scored_signal_count += 1
        signals.append({"icon": "✅", "text": f"Typ urządzenia: {dev_type.value} — typowo edge/WAN"})
    elif dev_type == DeviceType.switch:
        # Switch może być core/dist/access — nie dajemy punktów, informujemy tylko
        # BUG-L4 fix: NIE wliczamy do scored_signal_count (brak punktów = brak danych)
        signals.append({"icon": "ℹ️", "text": "Typ urządzenia: switch — wymaga dalszej analizy (LLDP/FDB/STP)"})
    elif dev_type == DeviceType.ap:
        scores["access"] += 40
        scored_signal_count += 1
        signals.append({"icon": "✅", "text": "Typ urządzenia: AP — warstwa dostępu (access)"})
    elif dev_type in (DeviceType.server, DeviceType.workstation, DeviceType.camera,
                       DeviceType.printer, DeviceType.iot, DeviceType.nas, DeviceType.phone):
        scores["access"] += 50  # endpoint — jednoznacznie w warstwie dostępu (jako cel, nie sw)
        scored_signal_count += 1
        signals.append({"icon": "✅", "text": f"Typ urządzenia: {dev_type.value} — endpoint w sieci dostępu"})
    else:
        missing.append({
            "icon": "🟡",
            "text": "Typ urządzenia nieznany — ustaw ręcznie w liście urządzeń",
            "hints": [],
        })

    # ── 2. LLDP degree (liczba sąsiadów) ────────────────────────────────────
    max_signals += 1
    lldp_degree = db.query(func.count()).filter(
        (TopologyLink.src_device_id == device_id) |
        (TopologyLink.dst_device_id == device_id)
    ).scalar() or 0

    # Sprawdź czy w ogóle mamy jakiekolwiek linki dla innych urządzeń (czy LLDP działa)
    any_lldp = db.query(func.count()).filter(TopologyLink.id > 0).scalar() or 0

    if lldp_degree >= 4:
        scores["core"] += 30
        scored_signal_count += 1
        signals.append({"icon": "✅", "text": f"LLDP: {lldp_degree} sąsiadów — wysoka łączność (core)"})
    elif lldp_degree in (2, 3):
        scores["dist"] += 25
        scored_signal_count += 1
        signals.append({"icon": "✅", "text": f"LLDP: {lldp_degree} sąsiadów — pośrednia łączność (distribution)"})
    elif lldp_degree == 1:
        scores["access"] += 28
        scored_signal_count += 1
        signals.append({"icon": "✅", "text": "LLDP: 1 sąsiad — pojedynczy uplink (access)"})
    elif any_lldp > 0:
        # BUG-L5 fix: brak LLDP gdy inne urządzenia mają → słaba sugestia access,
        # ale wliczamy do scored_signal_count (bo jednak coś wiemy) i dodajemy do signals
        scores["access"] += 10
        scored_signal_count += 1
        signals.append({
            "icon": "⚠️",
            "text": "LLDP: brak sąsiadów (inne urządzenia mają LLDP) — prawdopodobnie endpoint/edge sieci",
        })
        missing.append({
            "icon": "🔴",
            "text": "LLDP: włącz LLDP na urządzeniu — kluczowy sygnał dla dokładnej analizy tiera",
            "hints": _get_hints(vendor, os_ver, "lldp"),
        })
    else:
        # Brak LLDP w całej sieci — dane niedostępne
        missing.append({
            "icon": "🟡",
            "text": "LLDP: brak danych w całej sieci — włącz LLDP na urządzeniach",
            "hints": _get_hints(vendor, os_ver, "lldp"),
        })

    # ── 3. FDB — liczba wpisów MAC ──────────────────────────────────────────
    max_signals += 1
    cutoff_48h = datetime.utcnow() - timedelta(hours=48)
    fdb_count = db.query(func.count(DeviceFdbEntry.id)).filter(
        DeviceFdbEntry.device_id == device_id,
        DeviceFdbEntry.polled_at >= cutoff_48h,
    ).scalar() or 0

    if fdb_count > 0:
        # BUG-L3 fix: progi dopasowane do realnych sieci — dist może mieć 20-100 MAC
        # z podłączonych switchów access; próg access podniesiony do >150
        scored_signal_count += 1
        if fdb_count > 150:
            scores["access"] += 25
            signals.append({"icon": "✅", "text": f"FDB: {fdb_count} wpisów MAC — wiele urządzeń końcowych (access)"})
        elif fdb_count > 30:
            scores["access"] += 12
            scores["dist"] += 12
            signals.append({"icon": "✅", "text": f"FDB: {fdb_count} wpisów MAC — mieszana warstwa (dist/access)"})
        elif fdb_count <= 8:
            scores["core"] += 15
            scores["dist"] += 10
            signals.append({"icon": "✅", "text": f"FDB: tylko {fdb_count} wpisów MAC — tranzytowe urządzenie (core/dist)"})
        else:  # 9..30
            scores["dist"] += 15
            signals.append({"icon": "✅", "text": f"FDB: {fdb_count} wpisów MAC — typowy switch distribution"})
    else:
        missing.append({
            "icon": "🟡",
            "text": "FDB: brak danych (Q-BRIDGE MIB niedostępny) — potrzebny SNMP community",
            "hints": _get_hints(vendor, os_ver, "snmp"),
        })

    # ── 4. Tryb portów (trunk vs access) ────────────────────────────────────
    max_signals += 1
    trunk_cnt  = db.query(func.count(Interface.id)).filter(
        Interface.device_id == device_id,
        Interface.port_mode == "trunk",
    ).scalar() or 0
    access_cnt = db.query(func.count(Interface.id)).filter(
        Interface.device_id == device_id,
        Interface.port_mode == "access",
    ).scalar() or 0
    total_mode = trunk_cnt + access_cnt

    if total_mode > 0:
        trunk_ratio = trunk_cnt / total_mode
        scored_signal_count += 1
        if trunk_ratio >= 0.8:
            scores["core"] += 20
            scores["dist"] += 15
            signals.append({"icon": "✅", "text": f"Porty: {trunk_cnt} trunk / {access_cnt} access — agregacja (core/dist)"})
        elif trunk_ratio <= 0.2:
            scores["access"] += 20
            signals.append({"icon": "✅", "text": f"Porty: {access_cnt} access / {trunk_cnt} trunk — warstwa dostępu"})
        else:
            scores["dist"] += 15
            signals.append({"icon": "✅", "text": f"Porty: {trunk_cnt} trunk + {access_cnt} access — mieszana (dist?)"})
    else:
        missing.append({
            "icon": "🔴",
            "text": "Tryb portów nieznany — potrzebny SNMP lub SSH (show interfaces trunk)",
            "hints": _get_hints(vendor, os_ver, "interfaces"),
        })

    # ── 5. STP bridge priority ───────────────────────────────────────────────
    max_signals += 1
    # stp_root_cost == 0 → to urządzenie JEST root bridge
    # stp_root_cost == None → nie zebrano danych STP
    if dev.stp_root_cost is not None:
        scored_signal_count += 1
        if dev.stp_root_cost == 0:
            scores["core"] += 28
            signals.append({"icon": "✅", "text": "STP: to urządzenie jest root bridge — typowo core"})
        elif dev.stp_root_cost <= 2:
            # BUG-L8 fix: cost<=2 może być RSTP 10G access — nie klasyfikuj jako dist,
            # daj równe punkty dist i access
            scores["dist"] += 12
            scores["access"] += 12
            signals.append({"icon": "✅", "text": f"STP: koszt do root = {dev.stp_root_cost} — blisko root (RSTP 10G lub dist)"})
        elif dev.stp_root_cost <= 8:
            scores["dist"] += 20
            signals.append({"icon": "✅", "text": f"STP: koszt do root = {dev.stp_root_cost} — blisko root (distribution)"})
        elif dev.stp_root_cost <= 19:
            scores["dist"] += 10
            scores["access"] += 10
            signals.append({"icon": "✅", "text": f"STP: koszt do root = {dev.stp_root_cost} — pośredni"})
        else:
            scores["access"] += 18
            signals.append({"icon": "✅", "text": f"STP: koszt do root = {dev.stp_root_cost} — daleko od root (access)"})
    else:
        missing.append({
            "icon": "🟡",
            "text": "STP: brak danych (dot1dStp MIB) — potrzebny SNMP community z dostępem do bridge MIB",
            "hints": _get_hints(vendor, os_ver, "stp"),
        })

    # ── 6. Liczba unikalnych VLANów ──────────────────────────────────────────
    max_signals += 1
    vlan_count = db.query(func.count(DeviceVlanPort.vlan_id.distinct())).filter(
        DeviceVlanPort.device_id == device_id,
    ).scalar() or 0

    if vlan_count > 0:
        scored_signal_count += 1
        if vlan_count >= 8:
            scores["dist"] += 18
            scores["core"] += 12
            signals.append({"icon": "✅", "text": f"VLANy: {vlan_count} aktywnych — urządzenie wielu VLAN (dist/core)"})
        elif vlan_count >= 3:
            scores["dist"] += 10
            signals.append({"icon": "✅", "text": f"VLANy: {vlan_count} aktywnych"})
        else:
            scores["access"] += 12
            signals.append({"icon": "✅", "text": f"VLANy: tylko {vlan_count} — prosty segment (access)"})
    else:
        missing.append({
            "icon": "🟡",
            "text": "VLANy: brak danych (Q-BRIDGE VLAN MIB) — potrzebny SNMP",
            "hints": [],
        })

    # ── 7. SNMP aktywny (czy zbieramy dane) ─────────────────────────────────
    # Nie punktujemy, ale brak SNMP → wiele sygnałów brakuje
    if not dev.snmp_community:
        missing.append({
            "icon": "🔴",
            "text": "SNMP: brak dostępu — bez SNMP większość analizy jest niemożliwa",
            "hints": _get_hints(vendor, os_ver, "snmp"),
        })

    # ── Oblicz zwycięzcę i confidence ───────────────────────────────────────
    best_tier  = max(scores, key=lambda t: scores[t])
    best_score = scores[best_tier]

    # BUG-L4 fix: używamy scored_signal_count (faktyczne punktujące sygnały),
    # nie len(signals) (które zawiera też ℹ️ switch bez punktów)
    data_fraction = scored_signal_count / max(max_signals, 1)

    # Dominacja: zwycięzca vs drugi (im większa różnica, tym pewniej)
    sorted_scores = sorted(scores.values(), reverse=True)
    second_score = sorted_scores[1] if len(sorted_scores) > 1 else 0
    if best_score > 0:
        dominance = min(1.0, (best_score - second_score) / max(best_score, 1))
    else:
        dominance = 0.0

    confidence = int(data_fraction * 50 + dominance * 50)

    # BUG-L6 fix: cap confidence gdy mało sygnałów — 1 sygnał nie może dać >55%
    if scored_signal_count < 3:
        confidence = min(confidence, 55)

    if best_score == 0 or scored_signal_count == 0:
        tier = "undef"
        confidence = 0
    else:
        tier = best_tier

    evidence = {"signals": signals, "missing": missing, "scores": scores}

    # Zapisz do DB
    try:
        dev.network_tier     = tier
        dev.tier_confidence  = confidence
        dev.tier_evidence    = evidence
        dev.tier_analyzed_at = datetime.utcnow()
        db.add(dev)
        db.commit()
    except Exception as exc:
        logger.warning("Nie można zapisać tier dla device %d: %s", device_id, exc)
        db.rollback()

    return {"tier": tier, "confidence": confidence, "evidence": evidence}


def analyze_all_devices(db) -> int:
    """Analizuje tier dla wszystkich urządzeń bez ręcznego override.

    Urządzenia z tier_overridden=True są pomijane w zapytaniu (nie tylko w guard
    wewnątrz analyze_device_tier) — BUG-L1 fix.

    Zwraca liczbę faktycznie przeanalizowanych urządzeń.
    """
    from netdoc.storage.models import Device
    # BUG-L1 fix: filtruj na poziomie zapytania DB — nie ładuj overridden devices
    devs = db.query(Device.id).filter(
        (Device.tier_overridden.is_(None)) | (Device.tier_overridden == False)
    ).all()
    count = 0
    for (dev_id,) in devs:
        try:
            analyze_device_tier(dev_id, db)
            count += 1
        except Exception as exc:
            logger.warning("Błąd analizy tiera dla device %d: %s", dev_id, exc)
    logger.info("Tier analysis: przeanalizowano %d urządzeń (overridden pominięte)", count)
    return count
