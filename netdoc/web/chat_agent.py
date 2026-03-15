"""NetDoc AI Agent — diagnosta sieci z dostepem do danych w czasie rzeczywistym."""
import json
import logging
import os
import pathlib

# anthropic importowany lazily wewnatrz chat() — nie blokuje testow bez pakietu
from netdoc.storage.database import SessionLocal
from netdoc.storage.models import Device, ScanResult, Vulnerability, SystemStatus

logger = logging.getLogger(__name__)

AGENT_ENABLED = os.getenv("AGENT_ENABLED", "1").lower() not in ("0", "false", "no")
_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

_AI_CONTEXT_FILE = pathlib.Path(__file__).parent / "ai_context.md"


def _load_ai_context() -> str:
    """Laduje kontekst NetDoc z ai_context.md. Linie zaczynajace sie od '#' sa komentarzami."""
    try:
        lines = _AI_CONTEXT_FILE.read_text(encoding="utf-8").splitlines()
        content_lines = [ln for ln in lines if not ln.startswith("# ")]
        return "\n".join(content_lines).strip()
    except Exception as e:
        logger.warning("Nie mozna zaladowac ai_context.md: %s", e)
        return ""


_SYSTEM_PROMPT_BASE = """Jestes NetDoc AI — inteligentnym asystentem do monitorowania infrastruktury sieciowej.
Masz dostep do rzeczywistych danych o sieci uzytkownika w czasie rzeczywistym.

{ai_context}

ZAKRES TEMATYCZNY — odpowiadasz WYLACZNIE na pytania dotyczace:
- urzadzen sieciowych (routery, switche, AP, serwery, kamery, IoT, drukarki)
- bezpieczenstwa sieci (podatnosci, otwarte porty, slabe hasla, ataki)
- monitorowania i diagnostyki sieci (ping, SNMP, latencja, dostepnosc)
- lacza internetowego (WAN IP, DNS, predkosc, jitter)
- konfiguracji systemu NetDoc (zbieranie danych, workery, Grafana)

Jesli uzytkownik pyta o cos SPOZA powyzszego zakresu (pogoda, gotowanie, sport, polityka,
matematyka ogolna, programowanie niezwiazane z NetDoc itp.) — odpowiedz krotko:
"Jestem asystentem NetDoc i moge pomoc tylko w tematach zwiazanych z monitorowaniem sieci."
NIE odpowiadaj na takie pytania nawet jesli uzytkownik naleguje.

ZAUFANE URZADZENIA:
Urzadzenia moga byc oznaczone jako ZAUFANE przez administratora (is_trusted=True).
Kategorie: infrastructure (router/switch/firewall), endpoint (PC/serwer), iot (IoT/przemyslowe), guest (tymczasowe), other.
Przy analizie bezpieczenstwa:
- Jesli urzadzenie ZAUFANE ma otwarte porty/podatnosci — poinformuj, ale zaznacz ze jest swiadomie znane
- Jesli urzadzenie NIEZAUFANE ma podatnosci — priorytetyzuj jako wyzsze ryzyko
- Nowe urzadzenia (brak oznaczenia) wymienione bez zaufania — sugeruj weryfikacje i oznaczenie
Nie ignoruj podatnosci na zaufanych urzadzeniach — zaufanie ≠ brak ryzyka, to tylko kontekst.

Twoje zadania:
- Odpowiadaj ZAWSZE po polsku, konkretnie i technicznie
- Analizuj status urzadzen, podatnosci bezpieczenstwa, wydajnosc sieci
- Wskazuj ryzyka i sugeruj konkretne dzialania naprawcze
- Jesli pytanie wymaga danych, najpierw pobierz je narzedziami, potem odpowiedz

Styl: zwiezly, techniczny, bez zbednych wstepow. Uzywaj list i formatowania Markdown.
Jesli nie masz danych o czyms, powiedz to wprost — nie zgaduj.

Na koncu kazdej odpowiedzi (po tresci merytorycznej) dodaj blok sugestii w formacie:
<!--SUGGESTIONS:["pytanie 1","pytanie 2","pytanie 3"]-->
Zaproponuj 2-3 krotkie, konkretne pytania kontynuujace temat rozmowy.
Blok SUGGESTIONS umieszczaj zawsze na samym koncu, po calej odpowiedzi."""


def _build_system_prompt() -> str:
    """Buduje pelny system prompt z dynamicznym kontekstem z ai_context.md."""
    ctx = _load_ai_context()
    return _SYSTEM_PROMPT_BASE.format(ai_context=ctx)

_TOOLS = [
    {
        "name": "list_devices",
        "description": "Lista wszystkich urzadzen sieciowych z podstawowymi informacjami (IP, MAC, vendor, typ, status, kiedy ostatnio widziane)",
        "input_schema": {
            "type": "object",
            "properties": {
                "status_filter": {
                    "type": "string",
                    "enum": ["all", "up", "down"],
                    "description": "Filtruj po statusie: all=wszystkie, up=aktywne, down=nieaktywne"
                }
            }
        }
    },
    {
        "name": "get_device_details",
        "description": "Szczegolowe informacje o konkretnym urzadzeniu: otwarte porty, uslugi, credentials, podatnosci",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Adres IP urzadzenia"}
            },
            "required": ["ip"]
        }
    },
    {
        "name": "get_vulnerabilities",
        "description": "Lista wykrytych podatnosci bezpieczenstwa w calej sieci lub dla konkretnego urzadzenia",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["all", "critical", "high", "medium", "low"],
                    "description": "Filtruj po poziomie zagrozenia"
                },
                "ip": {
                    "type": "string",
                    "description": "Opcjonalnie: pokaz tylko podatnosci dla tego IP"
                }
            }
        }
    },
    {
        "name": "get_internet_status",
        "description": "Status polaczenia internetowego: publiczne IP/WAN, DNS, latencja HTTP, jitter, predkosc pobierania i wysylania",
        "input_schema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "get_network_summary",
        "description": "Ogolne podsumowanie sieci: liczba urzadzen, aktywne/nieaktywne, podatnosci, typy urzadzen",
        "input_schema": {
            "type": "object",
            "properties": {}
        }
    }
]


def _run_tool(name: str, inputs: dict) -> str:
    db = SessionLocal()
    try:
        if name == "list_devices":
            return _tool_list_devices(db, inputs)
        elif name == "get_device_details":
            return _tool_device_details(db, inputs)
        elif name == "get_vulnerabilities":
            return _tool_vulnerabilities(db, inputs)
        elif name == "get_internet_status":
            return _tool_internet_status(db)
        elif name == "get_network_summary":
            return _tool_network_summary(db)
        return f"Nieznane narzedzie: {name}"
    except Exception as e:
        logger.error("Agent tool error [%s]: %s", name, e)
        return f"Blad pobierania danych: {e}"
    finally:
        db.close()


def _tool_list_devices(db, inputs) -> str:
    q = db.query(Device)
    sf = inputs.get("status_filter", "all")
    if sf == "up":
        q = q.filter(Device.is_active == True)
    elif sf == "down":
        q = q.filter(Device.is_active == False)
    devices = q.order_by(Device.ip).all()
    if not devices:
        return "Brak urzadzen w bazie."
    rows = []
    for d in devices:
        status = "UP" if d.is_active else "DOWN"
        last = d.last_seen.strftime("%Y-%m-%d %H:%M") if d.last_seen else "?"
        trust = ""
        if getattr(d, "is_trusted", False):
            cat = getattr(d, "trust_category", None) or "?"
            trust = f" | ZAUFANE({cat})"
        rows.append(
            f"- {d.ip} | {status} | {d.device_type.value if d.device_type else '?'} | "
            f"vendor={d.vendor or '?'} | hostname={d.hostname or '?'} | ostatnio={last}{trust}"
        )
    trusted_cnt = sum(1 for d in devices if getattr(d, "is_trusted", False))
    return f"Urzadzenia ({len(devices)}, zaufane: {trusted_cnt}):\n" + "\n".join(rows)


def _tool_device_details(db, inputs) -> str:
    ip = inputs.get("ip", "")
    d = db.query(Device).filter(Device.ip == ip).first()
    if not d:
        return f"Nie znaleziono urzadzenia {ip}."
    info = [
        f"## {d.ip} — {d.hostname or 'brak hostname'}",
        f"Status: {'UP' if d.is_active else 'DOWN'}",
        f"Typ: {d.device_type.value if d.device_type else '?'}",
        f"Vendor: {d.vendor or '?'} | Model: {d.model or '?'}",
        f"MAC: {d.mac or '?'} | OS: {d.os_version or '?'}",
        f"Pierwsze wykrycie: {d.first_seen.strftime('%Y-%m-%d') if d.first_seen else '?'}",
        f"Ostatnio widziane: {d.last_seen.strftime('%Y-%m-%d %H:%M') if d.last_seen else '?'}",
    ]
    latest_scan = (db.query(ScanResult).filter(ScanResult.device_id == d.id)
                   .order_by(ScanResult.scan_time.desc()).first())
    if latest_scan and latest_scan.open_ports:
        ports = latest_scan.open_ports
        if isinstance(ports, list):
            info.append(f"Otwarte porty: {', '.join(str(p) for p in ports[:20])}")
        elif isinstance(ports, dict):
            plist = [f"{p}/{svc.get('name','?')}" for p, svc in list(ports.items())[:20]]
            info.append(f"Otwarte porty: {', '.join(plist)}")
    vulns = db.query(Vulnerability).filter(
        Vulnerability.device_id == d.id,
        Vulnerability.is_open == True,
        Vulnerability.suppressed == False
    ).all()
    if vulns:
        info.append(f"Podatnosci ({len(vulns)}):")
        for v in vulns:
            info.append(f"  [{v.severity.value.upper()}] {v.title} (port {v.port or '?'})")
    else:
        info.append("Podatnosci: brak aktywnych")
    is_trusted = getattr(d, "is_trusted", False)
    if is_trusted:
        cat  = getattr(d, "trust_category", None) or "nieokreslona"
        note = getattr(d, "trust_note", None) or ""
        info.append(f"Zaufanie: ZAUFANE — kategoria: {cat}" + (f" | notatka: {note}" if note else ""))
    else:
        info.append("Zaufanie: NIEZAUFANE — urzadzenie nie zostalo zaakceptowane przez administratora")
    return "\n".join(info)


def _tool_vulnerabilities(db, inputs) -> str:
    q = db.query(Vulnerability).filter(
        Vulnerability.is_open == True,
        Vulnerability.suppressed == False
    )
    sev = inputs.get("severity", "all")
    if sev and sev != "all":
        q = q.filter(Vulnerability.severity == sev)
    ip_filter = inputs.get("ip")
    if ip_filter:
        dev = db.query(Device).filter(Device.ip == ip_filter).first()
        if dev:
            q = q.filter(Vulnerability.device_id == dev.id)
    vulns = q.order_by(Vulnerability.severity).all()
    if not vulns:
        return "Brak aktywnych podatnosci."
    rows = []
    for v in vulns:
        dev = db.query(Device).filter(Device.id == v.device_id).first()
        dev_ip = dev.ip if dev else "?"
        rows.append(f"- [{v.severity.value.upper()}] {dev_ip} — {v.title} (port {v.port or '?'})")
    return f"Podatnosci ({len(vulns)}):\n" + "\n".join(rows)


def _tool_internet_status(db) -> str:
    rows = {r.key: r.value for r in db.query(SystemStatus).filter(
        SystemStatus.key.in_(["internet_status", "internet_speed", "internet_wan"])
    ).all()}
    parts = []
    wan = rows.get("internet_wan")
    if wan:
        try:
            w = json.loads(wan)
            if w.get("ok"):
                parts.append(
                    f"Publiczne IP (WAN): {w.get('ip', '?')} | "
                    f"Kraj: {w.get('country', '?')} | Miasto: {w.get('city', '?')} | "
                    f"ISP: {w.get('org', '?')} | TZ: {w.get('timezone', '?')}"
                )
        except Exception:
            pass
    ist = rows.get("internet_status")
    if ist:
        try:
            d = json.loads(ist)
            dg = d.get("dns_google", {})
            dc = d.get("dns_cloudflare", {})
            hc = d.get("http_cloudflare", {})
            parts.append(f"DNS Google (8.8.8.8): {'OK' if dg.get('ok') else 'FAIL'} {dg.get('ms') or '?'}ms")
            parts.append(f"DNS Cloudflare (1.1.1.1): {'OK' if dc.get('ok') else 'FAIL'} {dc.get('ms') or '?'}ms")
            if hc.get("ok"):
                parts.append(
                    f"HTTP latencja: avg={hc.get('avg_ms')}ms min={hc.get('min_ms')}ms "
                    f"max={hc.get('max_ms')}ms jitter={hc.get('jitter_ms')}ms ({hc.get('pings')} prob)"
                )
            parts.append(f"Sprawdzono: {d.get('updated_at', '?')}")
        except Exception:
            pass
    isp = rows.get("internet_speed")
    if isp:
        try:
            d = json.loads(isp)
            parts.append(f"Download: {d.get('download_mbps', '?')} Mbps | Upload: {d.get('upload_mbps', '?')} Mbps")
            parts.append(f"Test predkosci: {d.get('updated_at', '?')}")
        except Exception:
            pass
    return "\n".join(parts) if parts else "Brak danych o polaczeniu internetowym."


def _tool_network_summary(db) -> str:
    from sqlalchemy import func
    total = db.query(Device).count()
    active = db.query(Device).filter(Device.is_active == True).count()
    down = total - active
    crit = db.query(Vulnerability).filter(
        Vulnerability.is_open == True,
        Vulnerability.suppressed == False,
        Vulnerability.severity == "critical"
    ).count()
    high = db.query(Vulnerability).filter(
        Vulnerability.is_open == True,
        Vulnerability.suppressed == False,
        Vulnerability.severity == "high"
    ).count()
    type_counts = db.query(Device.device_type, func.count(Device.id)).group_by(Device.device_type).all()
    type_summary = ", ".join(f"{t.value}={c}" for t, c in type_counts if t)
    return (
        f"Urzadzenia: {total} lacznie ({active} UP, {down} DOWN)\n"
        f"Typy: {type_summary or 'brak danych'}\n"
        f"Podatnosci krytyczne: {crit} | wysokie: {high}"
    )


import re as _re


def _extract_suggestions(text: str) -> tuple[str, list[str]]:
    """Wyodrebnia sugestie z bloku <!--SUGGESTIONS:[...]-->. Zwraca (czysty_tekst, lista_sugestii)."""
    match = _re.search(r'<!--SUGGESTIONS:(\[.*?\])-->', text, _re.DOTALL)
    if not match:
        return text.strip(), []
    try:
        suggestions = json.loads(match.group(1))
        if not isinstance(suggestions, list):
            suggestions = []
    except Exception:
        suggestions = []
    clean = text[:match.start()].strip()
    return clean, suggestions


def chat(messages: list) -> dict:
    """Uruchamia agenta z historia wiadomosci.

    Zwraca dict: {reply, suggestions, tools_used, tool_details}
    tool_details: lista dict {tool, input, result} — pelne dane wymienione z AI
    """
    if not AGENT_ENABLED:
        return {"reply": "Agent AI jest wylaczony. Ustaw AGENT_ENABLED=1 w konfiguracji.",
                "suggestions": [], "tools_used": [], "tool_details": []}
    if not _API_KEY:
        return {"reply": "Brak klucza API Anthropic. Ustaw ANTHROPIC_API_KEY w pliku .env i zrestartuj kontener.",
                "suggestions": [], "tools_used": [], "tool_details": []}
    import anthropic  # lazy import — nie blokuje importu modulu gdy pakiet nieinstalowany
    client = anthropic.Anthropic(api_key=_API_KEY)
    tools_used: list[str] = []
    tool_details: list[dict] = []   # {tool, input, result} dla kazdego wywolania narzedzia
    for _ in range(10):
        response = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=2048,
            system=_build_system_prompt(),
            tools=_TOOLS,
            messages=messages,
        )
        if response.stop_reason == "end_turn":
            for block in response.content:
                if hasattr(block, "text"):
                    clean, suggestions = _extract_suggestions(block.text)
                    return {"reply": clean, "suggestions": suggestions,
                            "tools_used": tools_used, "tool_details": tool_details}
            return {"reply": "", "suggestions": [], "tools_used": tools_used, "tool_details": tool_details}
        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    tools_used.append(block.name)
                    result = _run_tool(block.name, block.input)
                    tool_details.append({
                        "tool":   block.name,
                        "input":  dict(block.input) if block.input else {},
                        "result": result,
                    })
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })
            # Konwertuj Pydantic ContentBlock na dict — Pydantic 2.10+ wymaga bool, nie None dla by_alias
            assistant_content = [
                b.model_dump(by_alias=True) if hasattr(b, "model_dump") else b
                for b in response.content
            ]
            messages = messages + [
                {"role": "assistant", "content": assistant_content},
                {"role": "user", "content": tool_results},
            ]
            continue
        break
    return {"reply": "Agent nie zdolal wygenerowac odpowiedzi.", "suggestions": [],
            "tools_used": tools_used, "tool_details": tool_details}
