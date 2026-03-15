"""Testy dla netdoc.collector.snmp_walk — pure Python SNMP GET-NEXT walker."""
import sys
import os
import socket
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from netdoc.collector.snmp_walk import (
    _enc_oid, _enc_int, _enc_str, _enc_seq, _enc_len,
    _dec_oid, _dec_tlv, _dec_len, _parse_response,
    _build_get_next, snmp_walk,
    snmp_arp_table, snmp_mac_table, snmp_ifip_table, snmp_route_table,
    snmp_discover_networks, snmp_find_community,
    mask_to_prefix, _is_valid_private_ip,
)


# ─── BER encoding ─────────────────────────────────────────────────────────────

def test_enc_len_short():
    assert _enc_len(0) == b"\x00"
    assert _enc_len(127) == b"\x7f"


def test_enc_len_long():
    # 256 = 0x81 0x01 0x00
    result = _enc_len(256)
    assert result[0] == 0x82  # 2 bytes follow
    assert int.from_bytes(result[1:], "big") == 256


def test_enc_oid_basic():
    # OID 1.3.6 → first two: 40*1+3=43, then 6
    oid = _enc_oid("1.3.6")
    assert oid[0] == 0x06   # OID tag
    assert oid[2] == 43     # first byte = 40*1+3
    assert oid[3] == 6


def test_enc_oid_sysDescr():
    # 1.3.6.1.2.1.1.1 — standard sysDescr OID
    oid = _enc_oid("1.3.6.1.2.1.1.1")
    assert oid[0] == 0x06   # OID tag
    assert len(oid) > 4


def test_enc_int_zero():
    assert _enc_int(0) == b"\x02\x01\x00"


def test_enc_int_positive():
    enc = _enc_int(42)
    assert enc[0] == 0x02
    assert enc[1] == 1
    assert enc[2] == 42


def test_enc_str_empty():
    enc = _enc_str(b"")
    assert enc == b"\x04\x00"


def test_enc_str_content():
    enc = _enc_str(b"public")
    assert enc[0] == 0x04
    assert enc[1] == 6
    assert enc[2:] == b"public"


def test_build_get_next_returns_bytes():
    pdu = _build_get_next("public", "1.3.6.1.2.1.1.1", 1)
    assert isinstance(pdu, bytes)
    assert len(pdu) > 10
    assert pdu[0] == 0x30   # outer SEQUENCE tag


# ─── BER decoding ─────────────────────────────────────────────────────────────

def test_dec_len_short():
    length, off = _dec_len(b"\x05extra", 0)
    assert length == 5
    assert off == 1


def test_dec_len_long_form():
    # 2-byte length: 0x82 0x01 0x00 = 256
    data = bytes([0x82, 0x01, 0x00])
    length, off = _dec_len(data, 0)
    assert length == 256
    assert off == 3


def test_dec_tlv_basic():
    # OCTET STRING "hi"
    data = b"\x04\x02hi"
    tag, val, off = _dec_tlv(data, 0)
    assert tag == 0x04
    assert val == b"hi"
    assert off == 4


def test_dec_oid_basic():
    # Encode then decode
    oid_str = "1.3.6.1.2.1.1.1"
    enc = _enc_oid(oid_str)
    decoded = _dec_oid(enc[2:])  # skip tag and length
    assert decoded == oid_str


def test_roundtrip_oid_long():
    """Oid z duzymi wartosciami (multi-byte encoding)."""
    oid_str = "1.3.6.1.4.1.9.1.516"  # Cisco OID z enterprise
    enc = _enc_oid(oid_str)
    decoded = _dec_oid(enc[2:])
    assert decoded == oid_str


# ─── _parse_response ──────────────────────────────────────────────────────────

def _build_fake_response(oid_result: str, value_bytes: bytes, value_tag: int = 0x04) -> bytes:
    """Buduje minimalny prawidlowy pakiet SNMP GET-RESPONSE."""
    val_enc = bytes([value_tag]) + _enc_len(len(value_bytes)) + value_bytes
    oid_enc = _enc_oid(oid_result)
    var_bind = _enc_seq(oid_enc + val_enc)
    var_bind_list = _enc_seq(var_bind)
    pdu_body = _enc_int(1) + _enc_int(0) + _enc_int(0) + var_bind_list
    pdu = _enc_seq(pdu_body, tag=0xA2)   # GetResponse
    msg = _enc_int(1) + _enc_str(b"public") + pdu
    return _enc_seq(msg)


def test_parse_response_octet_string():
    resp = _build_fake_response("1.3.6.1.2.1.1.1.0", b"Linux 5.0", 0x04)
    result = _parse_response(resp)
    assert result is not None
    oid, val, tag = result
    assert oid == "1.3.6.1.2.1.1.1.0"
    assert val == b"Linux 5.0"
    assert tag == 0x04


def test_parse_response_error_status_nonzero_returns_none():
    """SNMP error-status != 0 → None (koniec tabeli)."""
    val_enc = b"\x04\x00"
    oid_enc = _enc_oid("1.3.6.1.2.1.1.1.0")
    var_bind = _enc_seq(oid_enc + val_enc)
    var_bind_list = _enc_seq(var_bind)
    pdu_body = _enc_int(1) + _enc_int(2) + _enc_int(0) + var_bind_list  # error=2
    pdu = _enc_seq(pdu_body, tag=0xA2)
    msg = _enc_int(1) + _enc_str(b"public") + pdu
    resp = _enc_seq(msg)
    assert _parse_response(resp) is None


def test_parse_response_garbage_returns_none():
    assert _parse_response(b"\x00\x01\x02garbage") is None


def test_parse_response_empty_returns_none():
    assert _parse_response(b"") is None


# ─── snmp_walk (mocked socket) ────────────────────────────────────────────────

def _mock_walk_socket(responses: list):
    """Helper: mock socket ktory zwraca kolejne odpowiedzi SNMP."""
    mock_sock = MagicMock()
    mock_sock.recv.side_effect = responses
    return mock_sock


def test_snmp_walk_empty_when_no_response():
    """Brak odpowiedzi (OSError) → pusta lista."""
    with patch("netdoc.collector.snmp_walk._socket.socket") as mock_cls:
        mock_s = MagicMock()
        mock_cls.return_value = mock_s
        mock_s.recv.side_effect = OSError("timed out")
        result = snmp_walk("10.0.0.1", "1.3.6.1.2.1.4.22.1.2", max_iter=3)
    assert result == []


def test_snmp_walk_stops_outside_subtree():
    """Walk zatrzymuje sie gdy OID opuszcza poddrzewo."""
    # Pierwsza odpowiedz jest w poddrzewie (1.3.6.1.2.1.4.22.1.2.x),
    # druga jest poza (1.3.6.1.2.1.4.23.1) → walk powinien zwrocic tylko 1 wynik
    resp1 = _build_fake_response("1.3.6.1.2.1.4.22.1.2.1.192.168.1.10",
                                  b"\xaa\xbb\xcc\xdd\xee\xff", 0x04)
    resp2 = _build_fake_response("1.3.6.1.2.1.4.23.1.0", b"\x00", 0x04)

    with patch("netdoc.collector.snmp_walk._socket.socket") as mock_cls:
        mock_s = MagicMock()
        mock_cls.return_value = mock_s
        mock_s.recv.side_effect = [resp1, resp2]
        result = snmp_walk("10.0.0.1", "1.3.6.1.2.1.4.22.1.2", max_iter=10)

    assert len(result) == 1
    assert result[0][0] == "1.3.6.1.2.1.4.22.1.2.1.192.168.1.10"


def test_snmp_walk_respects_max_iter():
    """Walk nie przekracza max_iter iteracji."""
    resp = _build_fake_response("1.3.6.1.2.1.4.22.1.2.1.10.0.0.1",
                                 b"\xaa\xbb\xcc\xdd\xee\xff", 0x04)
    # Zawsze zwraca ten sam OID → nieskonczona petla gdyby nie max_iter
    with patch("netdoc.collector.snmp_walk._socket.socket") as mock_cls:
        mock_s = MagicMock()
        mock_cls.return_value = mock_s
        mock_s.recv.return_value = resp
        result = snmp_walk("10.0.0.1", "1.3.6.1.2.1.4.22", max_iter=5)
    # max_iter=5, ale ten sam OID jest zwracany → walk zaptla sie w 1 kroku
    # (biezacy OID = wynikowy OID → brak posteppu → petla nigdy nie konczy)
    # Sprawdzamy ze nie wpadlismy w nieskonczona petle
    assert len(result) <= 5


# ─── snmp_arp_table ────────────────────────────────────────────────────────────

def test_snmp_arp_table_parses_correctly():
    """Poprawny ARP wpis: OID suffix = ifIdx.a.b.c.d, value = 6-bajtowy MAC."""
    mac_bytes = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    resp = _build_fake_response(
        "1.3.6.1.2.1.4.22.1.2.1.192.168.1.100",
        mac_bytes, 0x04
    )
    # Drugi recv: OSError → koniec walk
    with patch("netdoc.collector.snmp_walk._socket.socket") as mock_cls:
        mock_s = MagicMock()
        mock_cls.return_value = mock_s
        mock_s.recv.side_effect = [resp, OSError("timed out")]
        result = snmp_arp_table("10.0.0.1")

    assert "192.168.1.100" in result
    assert result["192.168.1.100"] == "aa:bb:cc:dd:ee:ff"


def test_snmp_arp_table_ignores_short_mac():
    """Wartosci krotsze niz 6 bajtow sa ignorowane."""
    resp = _build_fake_response(
        "1.3.6.1.2.1.4.22.1.2.1.192.168.1.1",
        b"\xAA\xBB\xCC", 0x04
    )
    with patch("netdoc.collector.snmp_walk._socket.socket") as mock_cls:
        mock_s = MagicMock()
        mock_cls.return_value = mock_s
        mock_s.recv.side_effect = [resp, OSError("timed out")]
        result = snmp_arp_table("10.0.0.1")
    assert result == {}


def test_snmp_arp_table_no_response_returns_empty():
    with patch("netdoc.collector.snmp_walk._socket.socket") as mock_cls:
        mock_s = MagicMock()
        mock_cls.return_value = mock_s
        mock_s.recv.side_effect = OSError("timed out")
        result = snmp_arp_table("10.0.0.1")
    assert result == {}


# ─── snmp_mac_table ────────────────────────────────────────────────────────────

def test_snmp_mac_table_parses_correctly():
    mac_bytes = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    resp = _build_fake_response(
        "1.3.6.1.2.1.17.4.3.1.1.0.17.34.51.68.85",
        mac_bytes, 0x04
    )
    with patch("netdoc.collector.snmp_walk._socket.socket") as mock_cls:
        mock_s = MagicMock()
        mock_cls.return_value = mock_s
        mock_s.recv.side_effect = [resp, OSError("timed out")]
        result = snmp_mac_table("10.0.0.1")
    assert "00:11:22:33:44:55" in result


def test_snmp_mac_table_empty_on_no_response():
    with patch("netdoc.collector.snmp_walk._socket.socket") as mock_cls:
        mock_s = MagicMock()
        mock_cls.return_value = mock_s
        mock_s.recv.side_effect = OSError("timed out")
        result = snmp_mac_table("10.0.0.1")
    assert result == []


# ─── snmp_ifip_table ───────────────────────────────────────────────────────────

def test_snmp_ifip_table_parses_ip_and_mask():
    """Interfejs 192.168.5.1 / 255.255.255.0 — z dwoch walk (addr + mask)."""
    resp_addr = _build_fake_response(
        "1.3.6.1.2.1.4.20.1.1.192.168.5.1",
        b"\xc0\xa8\x05\x01",  # 192.168.5.1
        0x40,  # ipAddress type
    )
    resp_mask = _build_fake_response(
        "1.3.6.1.2.1.4.20.1.3.192.168.5.1",
        b"\xff\xff\xff\x00",  # 255.255.255.0
        0x40,
    )

    call_count = [0]
    def fake_recv(size):
        call_count[0] += 1
        # Pierwsze dwa wywolania: adresy; kolejne dwa: maski
        if call_count[0] == 1:
            return resp_addr
        elif call_count[0] == 2:
            raise OSError("end")
        elif call_count[0] == 3:
            return resp_mask
        else:
            raise OSError("end")

    with patch("netdoc.collector.snmp_walk._socket.socket") as mock_cls:
        mock_s = MagicMock()
        mock_cls.return_value = mock_s
        mock_s.recv.side_effect = fake_recv
        result = snmp_ifip_table("10.0.0.1")

    # Powinien miec przynajmniej jeden interfejs
    assert len(result) >= 1
    ips = [r["ip"] for r in result]
    assert "192.168.5.1" in ips


# ─── snmp_route_table ──────────────────────────────────────────────────────────

def test_snmp_route_table_returns_direct_routes():
    """Trasa direct (type=3): dest=10.0.0.0, mask=255.255.255.0, nexthop=0.0.0.0."""
    # Budujemy odpowiedzi dla 4 walk: dest, mask, nexthop, type
    # Dla uproszczenia mockujemy snmp_walk bezposrednio

    with patch("netdoc.collector.snmp_walk.snmp_walk") as mock_walk:
        BASE_DEST    = "1.3.6.1.2.1.4.21.1.1"
        BASE_MASK    = "1.3.6.1.2.1.4.21.1.11"
        BASE_NEXTHOP = "1.3.6.1.2.1.4.21.1.7"
        BASE_TYPE    = "1.3.6.1.2.1.4.21.1.8"

        def side_effect(ip, base, community="public", timeout=2.0, max_iter=500):
            if base == BASE_DEST:
                return [(BASE_DEST + ".10.0.0.0", b"\x0a\x00\x00\x00", 0x40)]
            elif base == BASE_MASK:
                return [(BASE_MASK + ".10.0.0.0", b"\xff\xff\xff\x00", 0x40)]
            elif base == BASE_NEXTHOP:
                return [(BASE_NEXTHOP + ".10.0.0.0", b"\x00\x00\x00\x00", 0x40)]
            elif base == BASE_TYPE:
                return [(BASE_TYPE + ".10.0.0.0", b"\x03", 0x02)]  # direct
            return []

        mock_walk.side_effect = side_effect
        result = snmp_route_table("10.0.0.1")

    assert len(result) == 1
    assert result[0]["dest"] == "10.0.0.0"
    assert result[0]["mask"] == "255.255.255.0"
    assert result[0]["type"] == 3


# ─── Helper functions ──────────────────────────────────────────────────────────

def test_mask_to_prefix():
    assert mask_to_prefix("255.255.255.0") == 24
    assert mask_to_prefix("255.255.0.0") == 16
    assert mask_to_prefix("255.255.255.252") == 30
    assert mask_to_prefix("255.0.0.0") == 8


def test_is_valid_private_ip():
    assert _is_valid_private_ip("192.168.1.1") is True
    assert _is_valid_private_ip("10.0.0.1") is True
    assert _is_valid_private_ip("172.16.5.100") is True
    assert _is_valid_private_ip("172.31.255.255") is True
    assert _is_valid_private_ip("8.8.8.8") is False
    assert _is_valid_private_ip("127.0.0.1") is False
    assert _is_valid_private_ip("0.0.0.0") is False
    assert _is_valid_private_ip("255.255.255.255") is False
    assert _is_valid_private_ip("not.an.ip") is False


def test_is_valid_private_ip_boundary_172():
    """172.15.x.x i 172.32.x.x NIE sa prywatne."""
    assert _is_valid_private_ip("172.15.255.255") is False
    assert _is_valid_private_ip("172.32.0.0") is False


# ─── snmp_discover_networks ────────────────────────────────────────────────────

def test_snmp_discover_networks_no_response_returns_empty():
    """Brak odpowiedzi SNMP → pusty wynik, bez wyjatkow."""
    with patch("netdoc.collector.snmp_walk.snmp_walk", return_value=[]):
        result = snmp_discover_networks("10.0.0.1", communities=("public",))
    assert result == {"arp": {}, "macs": [], "ifaces": [], "routes": [], "community": None}


def test_snmp_discover_networks_community_field_set_on_success():
    """Gdy community dziala, pole 'community' jest ustawione w wyniku."""
    def fake_walk(ip, base, community="public", timeout=2.0, max_iter=500):
        if base == "1.3.6.1.2.1.1.1":
            return [("1.3.6.1.2.1.1.1.0", b"Linux", 0x04)]
        return []

    with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=fake_walk):
        result = snmp_discover_networks("10.0.0.1", communities=("public",),
                                        inter_probe_delay=0)
    assert result["community"] == "public"


def test_snmp_discover_networks_tries_second_community_if_first_fails():
    """Jesli 'public' nie odpowiada, probuje 'private'."""
    call_log = []

    def fake_walk(ip, base, community="public", timeout=2.0, max_iter=500):
        call_log.append(community)
        if community == "private" and base == "1.3.6.1.2.1.1.1":
            return [("1.3.6.1.2.1.1.1.0", b"Linux", 0x04)]
        return []

    with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=fake_walk):
        snmp_discover_networks("10.0.0.1", communities=("public", "private"))

    assert "public" in call_log
    assert "private" in call_log


def test_snmp_discover_networks_stops_after_first_working_community():
    """Po znalezieniu dzialajacei community nie probuje nastepnych."""
    call_log = []

    def fake_walk(ip, base, community="public", timeout=2.0, max_iter=500):
        call_log.append(community)
        if base == "1.3.6.1.2.1.1.1":
            return [("1.3.6.1.2.1.1.1.0", b"Linux", 0x04)]
        return []

    with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=fake_walk):
        snmp_discover_networks("10.0.0.1", communities=("public", "private"))

    # "private" nigdy nie powinna byc uzyta — "public" juz dzialala
    assert all(c == "public" for c in call_log)


# ─── snmp_find_community ───────────────────────────────────────────────────────

def test_snmp_find_community_returns_first_working():
    """snmp_find_community zwraca pierwsza dzialajaca community."""
    def fake_walk(ip, base, community="public", timeout=2.0, max_iter=500):
        if community == "private":
            return [("1.3.6.1.2.1.1.1.0", b"Linux", 0x04)]
        return []

    with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=fake_walk):
        result = snmp_find_community(
            "10.0.0.1", ("public", "private"), inter_probe_delay=0
        )
    assert result == "private"


def test_snmp_find_community_returns_none_when_all_fail():
    with patch("netdoc.collector.snmp_walk.snmp_walk", return_value=[]):
        result = snmp_find_community("10.0.0.1", ("public", "private"), inter_probe_delay=0)
    assert result is None


def test_snmp_find_community_stops_at_first_match():
    tried = []

    def fake_walk(ip, base, community="public", timeout=2.0, max_iter=500):
        tried.append(community)
        return [("1.3.6.1.2.1.1.1.0", b"Linux", 0x04)]

    with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=fake_walk):
        snmp_find_community("10.0.0.1", ("public", "private", "secret"), inter_probe_delay=0)

    assert tried == ["public"]


def test_snmp_find_community_applies_delay_between_probes():
    """Miedzy probami community jest pauza inter_probe_delay."""
    def fake_walk(ip, base, community="public", timeout=2.0, max_iter=500):
        return []

    with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=fake_walk):
        with patch("netdoc.collector.snmp_walk._time.sleep") as mock_sleep:
            snmp_find_community(
                "10.0.0.1", ("public", "private", "secret"),
                inter_probe_delay=0.15,
            )
            sleep_calls = mock_sleep.call_args_list

    assert len(sleep_calls) == 2
    for c in sleep_calls:
        assert c.args[0] >= 0.15


def test_snmp_find_community_adaptive_delay_large_list():
    """Dla listy >50 community delay jest automatycznie zwiekszony do min 0.3s."""
    communities = tuple(f"comm{i}" for i in range(60))
    sleep_vals = []

    def fake_walk(ip, base, community="public", timeout=2.0, max_iter=500):
        return []

    with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=fake_walk):
        with patch("netdoc.collector.snmp_walk._time.sleep") as mock_sleep:
            mock_sleep.side_effect = lambda s: sleep_vals.append(s)
            snmp_find_community("10.0.0.1", communities, inter_probe_delay=0.1)

    assert all(v >= 0.3 for v in sleep_vals)
