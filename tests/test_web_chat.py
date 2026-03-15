"""Testy Flask routes: /chat, /chat/message, /chat/history, /internet."""
import json
from unittest.mock import MagicMock, patch

import pytest


def _build_app(chat_enabled=True):
    from netdoc.web.app import create_app
    from netdoc.storage.models import (
        Device, DiscoveredNetwork, Credential, SystemStatus, ChatMessage
    )

    app = create_app()
    app.config["TESTING"] = True

    ms = MagicMock()
    ms.__enter__ = lambda s: s
    ms.__exit__ = MagicMock(return_value=False)

    dm = {
        Device: [],
        DiscoveredNetwork: [],
        Credential: [],
        SystemStatus: [],
        ChatMessage: [],
    }

    def _q(*models):
        q = MagicMock()
        if len(models) == 1:
            data = dm.get(models[0], [])
        else:
            data = []
        q.all.return_value = data
        q.count.return_value = len(data)
        q.order_by.return_value = q
        q.filter.return_value = q
        q.filter_by.return_value = q
        q.join.return_value = q
        q.group_by.return_value = q
        q.limit.return_value = q
        q.first.return_value = None
        return q

    ms.query.side_effect = _q
    return app, ms, chat_enabled


# ── /chat GET ─────────────────────────────────────────────────────────────────

def test_chat_page_renders_when_enabled():
    """/chat GET — strona laduje sie gdy AGENT_ENABLED=True."""
    app, ms, _ = _build_app()
    with patch("netdoc.web.app.SessionLocal", return_value=ms), \
         patch("netdoc.web.app.chat_agent") as mock_agent:
        mock_agent.AGENT_ENABLED = True
        with app.test_client() as c:
            resp = c.get("/chat")
    assert resp.status_code == 200
    assert b"Asystent" in resp.data or b"chat" in resp.data.lower()


def test_chat_page_renders_when_disabled():
    """/chat GET — strona laduje sie gdy AGENT_ENABLED=False (badge Wylaczony)."""
    app, ms, _ = _build_app()
    with patch("netdoc.web.app.SessionLocal", return_value=ms), \
         patch("netdoc.web.app.chat_agent") as mock_agent:
        mock_agent.AGENT_ENABLED = False
        with app.test_client() as c:
            resp = c.get("/chat")
    assert resp.status_code == 200
    assert b"wylaczony" in resp.data.lower() or b"disabled" in resp.data.lower()


# ── /chat/message POST ────────────────────────────────────────────────────────

def test_chat_message_returns_403_when_disabled():
    """/chat/message POST — 403 gdy agent wylaczony."""
    app, ms, _ = _build_app()
    with patch("netdoc.web.app.SessionLocal", return_value=ms), \
         patch("netdoc.web.app.chat_agent") as mock_agent:
        mock_agent.AGENT_ENABLED = False
        with app.test_client() as c:
            resp = c.post("/chat/message",
                          data=json.dumps({"messages": [{"role": "user", "content": "test"}]}),
                          content_type="application/json")
    assert resp.status_code == 403


def test_chat_message_returns_400_when_no_messages():
    """/chat/message POST — 400 gdy brak messages."""
    app, ms, _ = _build_app()
    with patch("netdoc.web.app.SessionLocal", return_value=ms), \
         patch("netdoc.web.app.chat_agent") as mock_agent:
        mock_agent.AGENT_ENABLED = True
        with app.test_client() as c:
            resp = c.post("/chat/message",
                          data=json.dumps({}),
                          content_type="application/json")
    assert resp.status_code == 400


def test_chat_message_returns_reply_and_suggestions():
    """/chat/message POST — zwraca reply i suggestions z chat_agent.chat()."""
    app, ms, _ = _build_app()
    mock_result = {
        "reply": "Masz 10 urzadzen.",
        "suggestions": ["Pokaz DOWN", "Jakie podatnosci?"],
        "tools_used": ["list_devices"],
    }
    with patch("netdoc.web.app.SessionLocal", return_value=ms), \
         patch("netdoc.web.app.chat_agent") as mock_agent:
        mock_agent.AGENT_ENABLED = True
        mock_agent.chat.return_value = mock_result
        with app.test_client() as c:
            resp = c.post("/chat/message",
                          data=json.dumps({
                              "messages": [{"role": "user", "content": "Ile urzadzen?"}],
                              "session_id": "test-session-123",
                          }),
                          content_type="application/json")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["reply"] == "Masz 10 urzadzen."
    assert "Pokaz DOWN" in data["suggestions"]


def test_chat_message_truncates_long_history():
    """/chat/message POST — przycinanie historii do 20 wiadomosci."""
    app, ms, _ = _build_app()
    messages = [{"role": "user", "content": f"msg {i}"} for i in range(25)]
    mock_result = {"reply": "ok", "suggestions": [], "tools_used": []}
    with patch("netdoc.web.app.SessionLocal", return_value=ms), \
         patch("netdoc.web.app.chat_agent") as mock_agent:
        mock_agent.AGENT_ENABLED = True
        mock_agent.chat.return_value = mock_result
        with app.test_client() as c:
            resp = c.post("/chat/message",
                          data=json.dumps({"messages": messages}),
                          content_type="application/json")
    assert resp.status_code == 200
    # chat() powinien byc wywolany z co najwyzej 20 wiadomosciami
    call_args = mock_agent.chat.call_args[0][0]
    assert len(call_args) <= 20


def test_chat_message_saves_to_db_with_session_id():
    """/chat/message POST — zapisuje wiadomosci do DB gdy session_id podany."""
    app, ms, _ = _build_app()
    mock_result = {"reply": "Odpowiedz AI", "suggestions": [], "tools_used": []}
    added = []
    ms.add.side_effect = lambda obj: added.append(obj)
    with patch("netdoc.web.app.SessionLocal", return_value=ms), \
         patch("netdoc.web.app.chat_agent") as mock_agent:
        mock_agent.AGENT_ENABLED = True
        mock_agent.chat.return_value = mock_result
        with app.test_client() as c:
            c.post("/chat/message",
                   data=json.dumps({
                       "messages": [{"role": "user", "content": "Test"}],
                       "session_id": "sess-abc-123",
                   }),
                   content_type="application/json")
    from netdoc.storage.models import ChatMessage
    saved = [o for o in added if isinstance(o, ChatMessage)]
    assert len(saved) == 2  # user + assistant
    assert any(m.role == "user" for m in saved)
    assert any(m.role == "assistant" for m in saved)
    assert all(m.session_id == "sess-abc-123" for m in saved)


def test_chat_message_no_db_save_without_session_id():
    """/chat/message POST — bez session_id nie probuje zapisac do DB."""
    app, ms, _ = _build_app()
    mock_result = {"reply": "ok", "suggestions": [], "tools_used": []}
    with patch("netdoc.web.app.SessionLocal", return_value=ms), \
         patch("netdoc.web.app.chat_agent") as mock_agent:
        mock_agent.AGENT_ENABLED = True
        mock_agent.chat.return_value = mock_result
        with app.test_client() as c:
            resp = c.post("/chat/message",
                          data=json.dumps({"messages": [{"role": "user", "content": "Test"}]}),
                          content_type="application/json")
    assert resp.status_code == 200
    # SessionLocal() nie powinno byc uzyte do zapisu (nie ma session_id)
    # (ms.add nie powinno byc wywolane z ChatMessage gdy brak session_id)
    from netdoc.storage.models import ChatMessage
    from unittest.mock import call
    chat_saves = [c for c in ms.add.call_args_list
                  if c.args and isinstance(c.args[0], ChatMessage)]
    assert len(chat_saves) == 0


# ── /chat/history GET ─────────────────────────────────────────────────────────

def test_chat_history_200():
    """/chat/history GET — strona laduje sie (200)."""
    app, ms, _ = _build_app()
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with app.test_client() as c:
            resp = c.get("/chat/history")
    assert resp.status_code == 200


def test_chat_history_session_200():
    """/chat/history/<session_id> GET — strona laduje sie (200)."""
    app, ms, _ = _build_app()
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with app.test_client() as c:
            resp = c.get("/chat/history/test-session-abc")
    assert resp.status_code == 200


# ── /internet GET ─────────────────────────────────────────────────────────────

def test_internet_page_no_data():
    """/internet GET — strona laduje sie gdy brak danych (None/puste)."""
    app, ms, _ = _build_app()
    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with app.test_client() as c:
            resp = c.get("/internet")
    assert resp.status_code == 200


def test_internet_page_with_data():
    """/internet GET — renderuje dane WAN, DNS, speed gdy sa w DB."""
    app, ms, _ = _build_app()

    from netdoc.storage.models import SystemStatus
    row_wan = MagicMock(spec=SystemStatus)
    row_wan.key = "internet_wan"
    row_wan.value = json.dumps({"ok": True, "ip": "5.1.2.3", "country": "PL",
                                "city": "Warsaw", "org": "AS5617 Orange",
                                "timezone": "Europe/Warsaw", "loc": "52,21"})
    row_status = MagicMock(spec=SystemStatus)
    row_status.key = "internet_status"
    row_status.value = json.dumps({
        "dns_google": {"ok": True, "ms": 12},
        "dns_cloudflare": {"ok": True, "ms": 10},
        "http_cloudflare": {"ok": True, "avg_ms": 45, "min_ms": 40,
                            "max_ms": 60, "jitter_ms": 5.0, "pings": 6},
        "updated_at": "2026-01-01T12:00:00",
    })
    row_speed = MagicMock(spec=SystemStatus)
    row_speed.key = "internet_speed"
    row_speed.value = json.dumps({
        "ok": True, "download_mbps": 94.5, "upload_mbps": 48.2,
        "updated_at": "2026-01-01T11:00:00"
    })

    def _q(*models):
        q = MagicMock()
        q.all.return_value = [row_wan, row_status, row_speed]
        q.filter.return_value = q
        q.filter_by.return_value = q
        q.order_by.return_value = q
        return q

    ms.query.side_effect = _q

    with patch("netdoc.web.app.SessionLocal", return_value=ms):
        with app.test_client() as c:
            resp = c.get("/internet")
    assert resp.status_code == 200
    assert b"5.1.2.3" in resp.data or b"internet" in resp.data.lower()


# ── tool_details w odpowiedzi /chat/message ────────────────────────────────────

def test_chat_message_returns_tool_details_in_json():
    """/chat/message zwraca pole tool_details z wynikami narzedzi uzytych przez agenta."""
    app, ms, _ = _build_app()
    mock_result = {
        "reply": "Masz 5 urzadzen.",
        "suggestions": [],
        "tools_used": ["get_network_summary"],
        "tool_details": [{"tool": "get_network_summary", "input": {}, "result": "Urzadzenia: 5"}],
    }
    with patch("netdoc.web.app.SessionLocal", return_value=ms), \
         patch("netdoc.web.app.chat_agent") as mock_agent:
        mock_agent.AGENT_ENABLED = True
        mock_agent.chat.return_value = mock_result
        with app.test_client() as c:
            resp = c.post("/chat/message",
                          data=json.dumps({
                              "messages": [{"role": "user", "content": "Ile urzadzen?"}],
                          }),
                          content_type="application/json")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert "tool_details" in data
    assert len(data["tool_details"]) == 1
    assert data["tool_details"][0]["tool"] == "get_network_summary"


def test_chat_message_saves_tool_details_to_db():
    """/chat/message zapisuje tool_details do ChatMessage.tools_used (nie tylko nazwy)."""
    app, ms, _ = _build_app()
    tool_details = [{"tool": "list_devices", "input": {"status_filter": "down"}, "result": "DOWN: 2"}]
    mock_result = {
        "reply": "Masz 2 urzadzenia DOWN.",
        "suggestions": [],
        "tools_used": ["list_devices"],
        "tool_details": tool_details,
    }
    added = []
    ms.add.side_effect = lambda obj: added.append(obj)
    with patch("netdoc.web.app.SessionLocal", return_value=ms), \
         patch("netdoc.web.app.chat_agent") as mock_agent:
        mock_agent.AGENT_ENABLED = True
        mock_agent.chat.return_value = mock_result
        with app.test_client() as c:
            c.post("/chat/message",
                   data=json.dumps({
                       "messages": [{"role": "user", "content": "Pokaz DOWN"}],
                       "session_id": "sess-tool-test",
                   }),
                   content_type="application/json")
    from netdoc.storage.models import ChatMessage
    assistant_msg = next((o for o in added if isinstance(o, ChatMessage) and o.role == "assistant"), None)
    assert assistant_msg is not None
    # tools_used w DB powinno zawierac pelne detale (dict z tool/input/result), nie tylko nazwy
    assert isinstance(assistant_msg.tools_used, list)
    assert assistant_msg.tools_used[0]["tool"] == "list_devices"
    assert "result" in assistant_msg.tools_used[0]


def test_chat_message_strips_underscore_metadata_from_messages():
    """/chat/message usuwa pola _* z wiadomosci zanim wyśle je do Anthropic API.
    Pola jak _suggestions, _tool_details sa metadanymi JS — Anthropic je odrzuca (400 Bad Request).
    """
    app, ms, _ = _build_app()
    mock_result = {"reply": "OK", "suggestions": [], "tools_used": [], "tool_details": []}
    captured = {}
    def _fake_chat(msgs):
        captured["msgs"] = msgs
        return mock_result
    with patch("netdoc.web.app.SessionLocal", return_value=ms), \
         patch("netdoc.web.app.chat_agent") as mock_agent:
        mock_agent.AGENT_ENABLED = True
        mock_agent.chat.side_effect = _fake_chat
        with app.test_client() as c:
            c.post("/chat/message",
                   data=json.dumps({
                       "messages": [
                           {"role": "user", "content": "Pytanie"},
                           {"role": "assistant", "content": "Odpowiedz",
                            "_suggestions": ["q1", "q2"], "_tool_details": [{"tool": "x"}]},
                           {"role": "user", "content": "Kolejne pytanie"},
                       ],
                   }),
                   content_type="application/json")
    sent = captured.get("msgs", [])
    for m in sent:
        assert "_suggestions" not in m, "Pole _suggestions nie powinno trafic do Anthropic API"
        assert "_tool_details" not in m, "Pole _tool_details nie powinno trafic do Anthropic API"
