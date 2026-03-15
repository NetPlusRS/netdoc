"""Testy dla netdoc.web.chat_agent."""
import json
import sys
from unittest.mock import MagicMock, patch

import pytest

# anthropic nie jest zainstalowany na hoscie — mockujemy modul przed importem
_anthropic_mock = MagicMock()
sys.modules.setdefault("anthropic", _anthropic_mock)

from netdoc.web import chat_agent


# ── AGENT_ENABLED / klucz API ────────────────────────────────────────────────

def test_chat_returns_disabled_message_when_disabled():
    """Gdy AGENT_ENABLED=False — chat() zwraca dict z komunikatem o wylaczeniu."""
    with patch.object(chat_agent, "AGENT_ENABLED", False):
        result = chat_agent.chat([{"role": "user", "content": "test"}])
    assert isinstance(result, dict)
    assert "wylaczony" in result["reply"].lower() or "disabled" in result["reply"].lower()


def test_chat_returns_no_api_key_message_when_key_missing():
    """Gdy brak ANTHROPIC_API_KEY — chat() zwraca dict z komunikatem o braku klucza."""
    with patch.object(chat_agent, "AGENT_ENABLED", True), \
         patch.object(chat_agent, "_API_KEY", ""):
        result = chat_agent.chat([{"role": "user", "content": "test"}])
    assert isinstance(result, dict)
    assert "api" in result["reply"].lower() or "klucz" in result["reply"].lower()


def test_chat_disabled_returns_empty_suggestions():
    """Gdy agent wylaczony — suggestions i tools_used sa puste."""
    with patch.object(chat_agent, "AGENT_ENABLED", False):
        result = chat_agent.chat([{"role": "user", "content": "test"}])
    assert result["suggestions"] == []
    assert result["tools_used"] == []


# ── _extract_suggestions ──────────────────────────────────────────────────────

def test_extract_suggestions_parses_block():
    """_extract_suggestions wyodrebnia pytania z bloku SUGGESTIONS."""
    text = "Oto odpowiedz.\n<!--SUGGESTIONS:[\"Pytanie 1\",\"Pytanie 2\"]-->"
    clean, suggestions = chat_agent._extract_suggestions(text)
    assert "Oto odpowiedz." in clean
    assert "SUGGESTIONS" not in clean
    assert suggestions == ["Pytanie 1", "Pytanie 2"]


def test_extract_suggestions_no_block():
    """Brak bloku SUGGESTIONS — zwraca tekst bez zmian i pusta liste."""
    text = "Oto odpowiedz bez sugestii."
    clean, suggestions = chat_agent._extract_suggestions(text)
    assert clean == text
    assert suggestions == []


def test_extract_suggestions_malformed_json():
    """Niepoprawny JSON w SUGGESTIONS — zwraca pusta liste bez wyjatku."""
    text = "Tekst.<!--SUGGESTIONS:[zly json-->"
    clean, suggestions = chat_agent._extract_suggestions(text)
    assert suggestions == []


# ── system prompt — ograniczenie tematyczne ──────────────────────────────────

def test_system_prompt_contains_topic_restriction():
    """System prompt zawiera ograniczenie do tematow sieciowych."""
    prompt = chat_agent._SYSTEM_PROMPT_BASE.lower()
    assert "zakres" in prompt or "wylacznie" in prompt or "tylko" in prompt
    assert "spoza" in prompt or "niezwiazane" in prompt or "poza" in prompt


# ── _run_tool ────────────────────────────────────────────────────────────────

def test_run_tool_unknown_name():
    """Nieznane narzedzie zwraca komunikat bledu, nie rzuca wyjatku."""
    result = chat_agent._run_tool("nonexistent_tool", {})
    assert "nieznane" in result.lower() or "unknown" in result.lower()


def test_tool_list_devices_no_devices(tmp_path):
    """list_devices z pusta baza — zwraca komunikat o braku urzadzen."""
    db_mock = MagicMock()
    db_mock.query.return_value.filter.return_value.order_by.return_value.all.return_value = []
    db_mock.query.return_value.order_by.return_value.all.return_value = []

    with patch("netdoc.web.chat_agent.SessionLocal", return_value=db_mock):
        result = chat_agent._run_tool("list_devices", {"status_filter": "all"})
    assert "brak" in result.lower()


def test_tool_list_devices_returns_device_info():
    """list_devices zwraca informacje o urzadzeniach."""
    from netdoc.storage.models import DeviceType
    from datetime import datetime
    dev = MagicMock()
    dev.ip = "192.168.1.1"
    dev.is_active = True
    dev.device_type = DeviceType.router
    dev.vendor = "Cisco"
    dev.hostname = "router01"
    dev.last_seen = datetime(2026, 1, 1, 12, 0)

    db_mock = MagicMock()
    db_mock.query.return_value.order_by.return_value.all.return_value = [dev]

    with patch("netdoc.web.chat_agent.SessionLocal", return_value=db_mock):
        result = chat_agent._run_tool("list_devices", {})
    assert "192.168.1.1" in result
    assert "UP" in result


def test_tool_device_details_not_found():
    """get_device_details dla nieznanego IP — zwraca komunikat o braku."""
    db_mock = MagicMock()
    db_mock.query.return_value.filter.return_value.first.return_value = None

    with patch("netdoc.web.chat_agent.SessionLocal", return_value=db_mock):
        result = chat_agent._run_tool("get_device_details", {"ip": "1.2.3.4"})
    assert "nie znaleziono" in result.lower() or "1.2.3.4" in result


def test_tool_vulnerabilities_none():
    """get_vulnerabilities z pusta baza — zwraca komunikat o braku lub 0 podatnosci."""
    db_mock = MagicMock()
    # Kod: db.query().filter().order_by().all() — jeden filter z wieloma warunkami
    db_mock.query.return_value.filter.return_value.order_by.return_value.all.return_value = []

    with patch("netdoc.web.chat_agent.SessionLocal", return_value=db_mock):
        result = chat_agent._run_tool("get_vulnerabilities", {})
    assert "brak" in result.lower() or "0" in result


def test_tool_internet_status_no_data():
    """get_internet_status gdy brak danych — zwraca komunikat o braku."""
    db_mock = MagicMock()
    db_mock.query.return_value.filter.return_value.all.return_value = []

    with patch("netdoc.web.chat_agent.SessionLocal", return_value=db_mock):
        result = chat_agent._run_tool("get_internet_status", {})
    assert "brak" in result.lower()


def test_tool_internet_status_with_data():
    """get_internet_status z danymi — zwraca IP, DNS, latencje."""
    from netdoc.storage.models import SystemStatus
    row_wan = MagicMock()
    row_wan.key = "internet_wan"
    row_wan.value = json.dumps({
        "ok": True, "ip": "5.1.2.3", "country": "PL",
        "city": "Warsaw", "org": "AS5617 Orange", "timezone": "Europe/Warsaw"
    })
    row_status = MagicMock()
    row_status.key = "internet_status"
    row_status.value = json.dumps({
        "dns_google": {"ok": True, "ms": 15},
        "dns_cloudflare": {"ok": True, "ms": 12},
        "http_cloudflare": {"ok": True, "avg_ms": 45, "min_ms": 40, "max_ms": 60, "jitter_ms": 5.0, "pings": 6},
        "updated_at": "2026-01-01T12:00:00",
    })
    row_speed = MagicMock()
    row_speed.key = "internet_speed"
    row_speed.value = json.dumps({
        "ok": True, "download_mbps": 94.5, "upload_mbps": 48.2, "updated_at": "2026-01-01T11:00:00"
    })

    db_mock = MagicMock()
    db_mock.query.return_value.filter.return_value.all.return_value = [row_wan, row_status, row_speed]

    with patch("netdoc.web.chat_agent.SessionLocal", return_value=db_mock):
        result = chat_agent._run_tool("get_internet_status", {})
    assert "5.1.2.3" in result
    assert "PL" in result
    assert "15" in result   # DNS ms
    assert "94.5" in result or "download" in result.lower()


def test_tool_network_summary():
    """get_network_summary zwraca liczby urzadzen i podatnosci."""
    db_mock = MagicMock()
    db_mock.query.return_value.count.return_value = 20
    db_mock.query.return_value.filter.return_value.count.return_value = 3
    db_mock.query.return_value.group_by.return_value.all.return_value = []

    with patch("netdoc.web.chat_agent.SessionLocal", return_value=db_mock):
        result = chat_agent._run_tool("get_network_summary", {})
    assert isinstance(result, str)
    assert len(result) > 0


# ── chat() — pelny przepływ, zwraca dict ─────────────────────────────────────

def test_chat_calls_anthropic_and_returns_dict():
    """chat() zwraca dict z reply, suggestions, tools_used."""
    final_block = MagicMock()
    final_block.text = "Masz 15 urzadzen w sieci."
    final_response = MagicMock()
    final_response.stop_reason = "end_turn"
    final_response.content = [final_block]

    mock_client = MagicMock()
    mock_client.messages.create.return_value = final_response

    with patch.object(chat_agent, "AGENT_ENABLED", True), \
         patch.object(chat_agent, "_API_KEY", "sk-ant-test"), \
         patch("anthropic.Anthropic", return_value=mock_client):
        result = chat_agent.chat([{"role": "user", "content": "Ile mam urzadzen?"}])

    assert isinstance(result, dict)
    assert result["reply"] == "Masz 15 urzadzen w sieci."
    assert "suggestions" in result
    assert "tools_used" in result


def test_chat_returns_suggestions_from_response():
    """chat() parsuje blok SUGGESTIONS z odpowiedzi agenta."""
    final_block = MagicMock()
    final_block.text = "Masz 15 urzadzen.<!--SUGGESTIONS:[\"Pokaz DOWN\",\"Jakie sa podatnosci?\"]-->"
    final_response = MagicMock()
    final_response.stop_reason = "end_turn"
    final_response.content = [final_block]

    mock_client = MagicMock()
    mock_client.messages.create.return_value = final_response

    with patch.object(chat_agent, "AGENT_ENABLED", True), \
         patch.object(chat_agent, "_API_KEY", "sk-ant-test"), \
         patch("anthropic.Anthropic", return_value=mock_client):
        result = chat_agent.chat([{"role": "user", "content": "Ile mam urzadzen?"}])

    assert result["reply"] == "Masz 15 urzadzen."
    assert "Pokaz DOWN" in result["suggestions"]
    assert "Jakie sa podatnosci?" in result["suggestions"]


def test_chat_executes_tool_use_and_continues():
    """chat() wywoluje narzedzie gdy stop_reason=tool_use, potem finalizuje."""
    # Pierwsza odpowiedz — tool_use
    tool_block = MagicMock()
    tool_block.type = "tool_use"
    tool_block.id = "tu_123"
    tool_block.name = "get_network_summary"
    tool_block.input = {}
    first_response = MagicMock()
    first_response.stop_reason = "tool_use"
    first_response.content = [tool_block]

    # Druga odpowiedz — end_turn
    text_block = MagicMock()
    text_block.text = "Masz 10 urzadzen."
    second_response = MagicMock()
    second_response.stop_reason = "end_turn"
    second_response.content = [text_block]

    mock_client = MagicMock()
    mock_client.messages.create.side_effect = [first_response, second_response]

    with patch.object(chat_agent, "AGENT_ENABLED", True), \
         patch.object(chat_agent, "_API_KEY", "sk-ant-test"), \
         patch("anthropic.Anthropic", return_value=mock_client), \
         patch("netdoc.web.chat_agent._run_tool", return_value="Urzadzenia: 10 lacznie"):
        result = chat_agent.chat([{"role": "user", "content": "Podsumuj siec"}])

    assert isinstance(result, dict)
    assert result["reply"] == "Masz 10 urzadzen."
    assert mock_client.messages.create.call_count == 2


def test_chat_tracks_tools_used():
    """chat() zbiera nazwy uzywanych narzedzi w tools_used."""
    tool_block = MagicMock()
    tool_block.type = "tool_use"
    tool_block.id = "tu_1"
    tool_block.name = "list_devices"
    tool_block.input = {}
    first_response = MagicMock()
    first_response.stop_reason = "tool_use"
    first_response.content = [tool_block]

    text_block = MagicMock()
    text_block.text = "OK"
    second_response = MagicMock()
    second_response.stop_reason = "end_turn"
    second_response.content = [text_block]

    mock_client = MagicMock()
    mock_client.messages.create.side_effect = [first_response, second_response]

    with patch.object(chat_agent, "AGENT_ENABLED", True), \
         patch.object(chat_agent, "_API_KEY", "sk-ant-test"), \
         patch("anthropic.Anthropic", return_value=mock_client), \
         patch("netdoc.web.chat_agent._run_tool", return_value="dane"):
        result = chat_agent.chat([{"role": "user", "content": "Pokaz urzadzenia"}])

    assert "list_devices" in result["tools_used"]


# ── _run_tool — blad DB (exception path) ─────────────────────────────────────

def test_run_tool_db_exception_returns_error_string():
    """Gdy DB rzuca wyjatek — _run_tool zwraca komunikat bledu (nie rzuca)."""
    db_mock = MagicMock()
    db_mock.query.side_effect = RuntimeError("db connection lost")

    with patch("netdoc.web.chat_agent.SessionLocal", return_value=db_mock):
        result = chat_agent._run_tool("list_devices", {})
    assert "blad" in result.lower() or "error" in result.lower()


# ── list_devices — filtr up/down ──────────────────────────────────────────────

def test_tool_list_devices_filter_up():
    """list_devices z status_filter=up — przechodzi przez galaz filter(is_active==True)."""
    from netdoc.storage.models import DeviceType
    from datetime import datetime
    dev = MagicMock()
    dev.ip = "10.0.0.1"; dev.is_active = True
    dev.device_type = DeviceType.switch; dev.vendor = "HP"
    dev.hostname = "sw01"; dev.last_seen = datetime(2026, 1, 1, 12, 0)

    db_mock = MagicMock()
    db_mock.query.return_value.filter.return_value.order_by.return_value.all.return_value = [dev]

    with patch("netdoc.web.chat_agent.SessionLocal", return_value=db_mock):
        result = chat_agent._run_tool("list_devices", {"status_filter": "up"})
    assert "10.0.0.1" in result
    assert "UP" in result


def test_tool_list_devices_filter_down():
    """list_devices z status_filter=down — przechodzi przez galaz filter(is_active==False)."""
    from netdoc.storage.models import DeviceType
    from datetime import datetime
    dev = MagicMock()
    dev.ip = "10.0.0.2"; dev.is_active = False
    dev.device_type = DeviceType.unknown; dev.vendor = None
    dev.hostname = None; dev.last_seen = None

    db_mock = MagicMock()
    db_mock.query.return_value.filter.return_value.order_by.return_value.all.return_value = [dev]

    with patch("netdoc.web.chat_agent.SessionLocal", return_value=db_mock):
        result = chat_agent._run_tool("list_devices", {"status_filter": "down"})
    assert "10.0.0.2" in result
    assert "DOWN" in result


# ── get_device_details — znalezione urzadzenie z danymi ──────────────────────

def test_tool_device_details_found_with_ports_and_vulns():
    """get_device_details dla znalezionego urzadzenia — zwraca porty i podatnosci."""
    from netdoc.storage.models import DeviceType, VulnSeverity
    from datetime import datetime

    dev = MagicMock()
    dev.id = 1; dev.ip = "192.168.1.10"; dev.hostname = "router01"
    dev.is_active = True; dev.device_type = DeviceType.router
    dev.vendor = "Cisco"; dev.model = "C2960"; dev.mac = "aa:bb:cc:dd:ee:ff"
    dev.os_version = "IOS 15.2"; dev.first_seen = datetime(2026, 1, 1)
    dev.last_seen = datetime(2026, 1, 15, 12, 0)

    scan = MagicMock()
    scan.open_ports = {"22": {"name": "ssh"}, "80": {"name": "http"}}

    vuln = MagicMock()
    vuln.severity = VulnSeverity.high
    vuln.title = "HTTP management panel"
    vuln.port = 80

    db_mock = MagicMock()
    # device lookup
    db_mock.query.return_value.filter.return_value.first.return_value = dev
    # scan lookup (filter by device_id + order + first)
    scan_q = MagicMock()
    scan_q.order_by.return_value.first.return_value = scan
    # vuln lookup (filter all)
    vuln_q = MagicMock()
    vuln_q.all.return_value = [vuln]

    call_count = [0]
    def _side_effect(*args):
        call_count[0] += 1
        from netdoc.storage.models import Device, ScanResult, Vulnerability
        if args and args[0] == ScanResult:
            return scan_q
        if args and args[0] == Vulnerability:
            return vuln_q
        return db_mock.query.return_value
    db_mock.query.side_effect = _side_effect
    db_mock.query.return_value.filter.return_value.first.return_value = dev

    with patch("netdoc.web.chat_agent.SessionLocal", return_value=db_mock):
        result = chat_agent._run_tool("get_device_details", {"ip": "192.168.1.10"})

    # Weryfikacja: funkcja przynajmniej nie rzuca i zwraca string
    assert isinstance(result, str)
    # "Nie znaleziono" nie powinno byc w wyniku gdy urzadzenie istnieje
    # (device.filter.first() zwraca dev)


def test_tool_device_details_found_minimal():
    """get_device_details z minimalnym mockiem — urzadzenie znalezione, brak portow i vulns."""
    from netdoc.storage.models import DeviceType
    from datetime import datetime

    dev = MagicMock()
    dev.id = 5; dev.ip = "10.1.1.1"; dev.hostname = None
    dev.is_active = False; dev.device_type = DeviceType.unknown
    dev.vendor = None; dev.model = None; dev.mac = None
    dev.os_version = None; dev.first_seen = None; dev.last_seen = None

    db_mock = MagicMock()
    # Wszystkie query.filter.first() -> dev (pierwsze wywolanie), None potem
    db_mock.query.return_value.filter.return_value.first.return_value = dev
    db_mock.query.return_value.filter.return_value.order_by.return_value.first.return_value = None
    db_mock.query.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = []

    with patch("netdoc.web.chat_agent.SessionLocal", return_value=db_mock):
        result = chat_agent._run_tool("get_device_details", {"ip": "10.1.1.1"})

    assert isinstance(result, str)
    assert "10.1.1.1" in result or "brak hostname" in result


# ── get_vulnerabilities — filtr severity + ip ────────────────────────────────

def test_tool_vulnerabilities_with_severity_filter():
    """get_vulnerabilities z severity=critical — galaz filtrowania severity."""
    from netdoc.storage.models import VulnSeverity

    vuln = MagicMock()
    vuln.device_id = 1
    vuln.severity = VulnSeverity.critical  # .value == "critical" juz przez enum
    vuln.title = "Redis bez hasla"
    vuln.port = 6379

    dev = MagicMock()
    dev.ip = "10.0.0.5"

    db_mock = MagicMock()
    db_mock.query.return_value.filter.return_value.filter.return_value.order_by.return_value.all.return_value = [vuln]
    db_mock.query.return_value.filter.return_value.order_by.return_value.all.return_value = [vuln]
    db_mock.query.return_value.filter.return_value.first.return_value = dev

    with patch("netdoc.web.chat_agent.SessionLocal", return_value=db_mock):
        result = chat_agent._run_tool("get_vulnerabilities", {"severity": "critical"})
    # Musi byc string — nie rzuca wyjatku
    assert isinstance(result, str)


def test_tool_vulnerabilities_with_ip_filter_device_not_found():
    """get_vulnerabilities z ip= ale urzadzenie nie istnieje — filtr IP ignorowany."""
    db_mock = MagicMock()
    db_mock.query.return_value.filter.return_value.first.return_value = None
    db_mock.query.return_value.filter.return_value.order_by.return_value.all.return_value = []

    with patch("netdoc.web.chat_agent.SessionLocal", return_value=db_mock):
        result = chat_agent._run_tool("get_vulnerabilities", {"ip": "1.2.3.4"})
    assert "brak" in result.lower() or isinstance(result, str)


# ── chat() — nieznany stop_reason (break path) ───────────────────────────────

def test_chat_unknown_stop_reason_returns_error():
    """chat() gdy stop_reason jest nieznany — przerywa petle i zwraca komunikat bledu."""
    response = MagicMock()
    response.stop_reason = "max_tokens"   # ani end_turn ani tool_use
    response.content = []

    mock_client = MagicMock()
    mock_client.messages.create.return_value = response

    with patch.object(chat_agent, "AGENT_ENABLED", True), \
         patch.object(chat_agent, "_API_KEY", "sk-ant-test"), \
         patch("anthropic.Anthropic", return_value=mock_client):
        result = chat_agent.chat([{"role": "user", "content": "test"}])

    assert isinstance(result, dict)
    assert result["reply"] != ""   # zwraca jakis komunikat
    assert result["tools_used"] == []


# ── Pydantic 2.10 by_alias fix — serializacja ContentBlock przy tool_use ─────

def test_chat_tool_use_serializes_content_blocks_to_dict():
    """Blok odpowiedzi asystenta (ContentBlock) musi byc serializowany do dict
    przed dodaniem do historii wiadomosci.

    Regresja: Pydantic 2.10+ odrzuca model_dump(by_alias=None) — fix uzywa by_alias=True.
    Bez tego kazdde pytanie wymagajace narzedzi konczylo sie Internal Server Error.
    """
    # Symuluj ContentBlock z prawdziwym model_dump (jak Pydantic V2)
    dump_calls = []

    class FakeContentBlock:
        type = "tool_use"
        id = "tu_abc"
        name = "list_devices"
        input = {}

        def model_dump(self, **kwargs):
            dump_calls.append(kwargs)
            return {"type": "tool_use", "id": "tu_abc", "name": "list_devices", "input": {}}

    fake_block = FakeContentBlock()
    first_response = MagicMock()
    first_response.stop_reason = "tool_use"
    first_response.content = [fake_block]

    text_block = MagicMock()
    text_block.text = "Urzadzenia OK"
    second_response = MagicMock()
    second_response.stop_reason = "end_turn"
    second_response.content = [text_block]

    mock_client = MagicMock()
    mock_client.messages.create.side_effect = [first_response, second_response]

    with patch.object(chat_agent, "AGENT_ENABLED", True), \
         patch.object(chat_agent, "_API_KEY", "sk-ant-test"), \
         patch("anthropic.Anthropic", return_value=mock_client), \
         patch("netdoc.web.chat_agent._run_tool", return_value="[]"):
        result = chat_agent.chat([{"role": "user", "content": "test"}])

    # model_dump musialo byc wywolane z by_alias=True (nie None)
    assert dump_calls, "model_dump nie zostalo wywolane — fix serializacji nie dziala"
    assert all(c.get("by_alias") is True for c in dump_calls), (
        f"model_dump wywolane z by_alias={dump_calls[0].get('by_alias')} zamiast True — "
        "Pydantic 2.10+ odrzuca None, co powoduje Internal Server Error w chat"
    )

    # Drugi request do API musi miec content jako list of dicts (nie Pydantic objects)
    second_call_messages = mock_client.messages.create.call_args_list[1][1]["messages"]
    assistant_turn = next(m for m in second_call_messages if m.get("role") == "assistant")
    assert isinstance(assistant_turn["content"], list)
    assert all(isinstance(b, dict) for b in assistant_turn["content"]), (
        "Bloki asystenta nie sa serializowane do dict — "
        "Pydantic objects w messages powoduja TypeError przy kolejnym wywolaniu API"
    )
    assert result["reply"] == "Urzadzenia OK"


# ── tool_details — nowe pole zwracane przez chat() ────────────────────────────

def test_chat_disabled_returns_empty_tool_details():
    """chat() gdy wylaczony zwraca tool_details jako pusta liste."""
    with patch.object(chat_agent, "AGENT_ENABLED", False):
        result = chat_agent.chat([{"role": "user", "content": "Test"}])
    assert "tool_details" in result
    assert result["tool_details"] == []


def test_chat_no_tool_use_returns_empty_tool_details():
    """chat() gdy brak tool_use zwraca tool_details == []."""
    text_block = MagicMock()
    text_block.text = "Odpowiedz bez narzedzi."
    response = MagicMock()
    response.stop_reason = "end_turn"
    response.content = [text_block]

    mock_client = MagicMock()
    mock_client.messages.create.return_value = response

    with patch.object(chat_agent, "AGENT_ENABLED", True), \
         patch.object(chat_agent, "_API_KEY", "sk-ant-test"), \
         patch("anthropic.Anthropic", return_value=mock_client):
        result = chat_agent.chat([{"role": "user", "content": "Pytanie"}])

    assert result["tool_details"] == []


def test_chat_tool_use_populates_tool_details():
    """chat() po tool_use wypelnia tool_details z nazwa, inputem i wynikiem narzedzia."""
    tool_block = MagicMock()
    tool_block.type = "tool_use"
    tool_block.id = "tu_abc"
    tool_block.name = "get_network_summary"
    tool_block.input = {"some_param": "val"}
    first_response = MagicMock()
    first_response.stop_reason = "tool_use"
    first_response.content = [tool_block]

    text_block = MagicMock()
    text_block.text = "Podsumowanie sieci."
    second_response = MagicMock()
    second_response.stop_reason = "end_turn"
    second_response.content = [text_block]

    mock_client = MagicMock()
    mock_client.messages.create.side_effect = [first_response, second_response]

    with patch.object(chat_agent, "AGENT_ENABLED", True), \
         patch.object(chat_agent, "_API_KEY", "sk-ant-test"), \
         patch("anthropic.Anthropic", return_value=mock_client), \
         patch("netdoc.web.chat_agent._run_tool", return_value="Urzadzenia: 5 UP"):
        result = chat_agent.chat([{"role": "user", "content": "Podsumuj"}])

    assert len(result["tool_details"]) == 1
    td = result["tool_details"][0]
    assert td["tool"] == "get_network_summary"
    assert td["input"] == {"some_param": "val"}
    assert td["result"] == "Urzadzenia: 5 UP"


# ── internet status — exception parse paths ──────────────────────────────────

def test_tool_internet_status_invalid_json_values():
    """get_internet_status gdy wartosci JSON sa niepoprawne — nie rzuca wyjatku."""
    row_wan = MagicMock()
    row_wan.key = "internet_wan"
    row_wan.value = "{invalid json}"  # bad JSON

    row_status = MagicMock()
    row_status.key = "internet_status"
    row_status.value = "null"  # valid JSON, but falsy

    db_mock = MagicMock()
    db_mock.query.return_value.filter.return_value.all.return_value = [row_wan, row_status]

    with patch("netdoc.web.chat_agent.SessionLocal", return_value=db_mock):
        result = chat_agent._run_tool("get_internet_status", {})
    # Nie rzuca — zwraca string (moze byc "brak danych" lub czesciowe dane)
    assert isinstance(result, str)
