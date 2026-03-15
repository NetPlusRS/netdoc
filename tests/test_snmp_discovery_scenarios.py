"""Scenariusze testowe odkrywania sieci przez SNMP.

Symuluje rozne sytuacje w realnych sieciach:
- Rozna ilosc urzadzen (mala/srednia/duza siec)
- Zmiana community na urzadzeniu (stara zapamieta, nowa dziala)
- Mix urzadzen: jedne z public, inne z custom community
- Brak odpowiedzi SNMP (firewall, zly community)
- Rate-limiting przy duzej liscie community
- Integracja snmp_enrich_from_devices() z baza danych
"""
import sys
import os
import time
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from netdoc.collector.snmp_walk import (
    snmp_find_community, snmp_discover_networks,
    snmp_arp_table, snmp_walk, _is_valid_private_ip,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _arp_response(oid_base, ifidx, ip_str, mac_bytes):
    """Buduje (oid, value, tag) jak gdyby z ARP walk."""
    ip_suffix = ".".join(str(int(o)) for o in ip_str.split("."))
    oid = f"{oid_base}.{ifidx}.{ip_suffix}"
    return (oid, mac_bytes, 0x04)


def _make_snmp_walk_mock(community_map: dict, arp_data: dict = None):
    """Tworzy mock snmp_walk ktory:
    - Zwraca sysDescr jesli community jest w community_map[ip]
    - Zwraca ARP entries z arp_data[ip] jesli podane
    Sluzy do symulowania selektywnych odpowiedzi SNMP.
    """
    ARP_BASE = "1.3.6.1.2.1.4.22.1.2"
    SYSDESCR  = "1.3.6.1.2.1.1.1"

    def fake_walk(ip, base, community="public", timeout=2.0, max_iter=500):
        valid_communities = community_map.get(ip, set())
        if community not in valid_communities:
            return []
        if base == SYSDESCR:
            return [(SYSDESCR + ".0", b"Linux device", 0x04)]
        if base == ARP_BASE and arp_data and ip in arp_data:
            return [
                _arp_response(ARP_BASE, 1, remote_ip, bytes.fromhex(mac.replace(":", "")))
                for remote_ip, mac in arp_data[ip].items()
            ]
        return []

    return fake_walk


# ─── Scenariusz 1: Mala siec — 3 urzadzenia, wszystkie "public" ─────────────

class TestSmallNetwork:
    """3 routery/switche, community 'public' na wszystkich."""

    def test_find_community_all_public(self):
        cm = {
            "192.168.1.1": {"public"},
            "192.168.1.2": {"public"},
            "192.168.1.3": {"public"},
        }
        for ip in cm:
            with patch("netdoc.collector.snmp_walk.snmp_walk",
                       side_effect=_make_snmp_walk_mock(cm)):
                result = snmp_find_community(ip, ("public", "private"), inter_probe_delay=0)
            assert result == "public", f"{ip}: oczekiwano 'public', dostano {result!r}"

    def test_arp_tables_collected_from_all(self):
        """Kazdy router ma wpisy w ARP — wszystkie 3 powinny byc zebrane."""
        cm = {
            "192.168.1.1": {"public"},
            "192.168.1.2": {"public"},
        }
        arp = {
            "192.168.1.1": {"10.0.0.100": "aa:bb:cc:dd:ee:01"},
            "192.168.1.2": {"10.0.0.200": "aa:bb:cc:dd:ee:02"},
        }
        results = {}
        for ip in cm:
            with patch("netdoc.collector.snmp_walk.snmp_walk",
                       side_effect=_make_snmp_walk_mock(cm, arp)):
                data = snmp_discover_networks(ip, ("public",), inter_probe_delay=0)
            results.update(data["arp"])

        assert "10.0.0.100" in results
        assert "10.0.0.200" in results


# ─── Scenariusz 2: Duza siec — 100 switchy, community "public" lub "netdoc" ──

class TestLargeNetwork:
    """100 switchy — 80 z 'public', 20 z custom community 'netdoc2026'."""

    def _make_large_network(self, n=100):
        cm = {}
        for i in range(n):
            ip = f"10.0.{i // 256}.{i % 256}"
            if i < 80:
                cm[ip] = {"public"}
            else:
                cm[ip] = {"netdoc2026"}
        return cm

    def test_public_switches_found_quickly(self):
        """Switche z 'public' powinny byc znalezione na 1. probie."""
        cm = self._make_large_network(10)
        ip = "10.0.0.0"  # ma 'public'

        mock_walk = _make_snmp_walk_mock(cm)
        tried = []

        def counting_walk(ip_arg, base, community="public", timeout=2.0, max_iter=500):
            tried.append(community)
            return mock_walk(ip_arg, base, community, timeout, max_iter)

        with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=counting_walk):
            result = snmp_find_community(ip, ("public", "netdoc2026"), inter_probe_delay=0)

        assert result == "public"
        assert tried == ["public"]  # tylko 1 proba (sysDescr)

    def test_custom_community_switch_found_on_second_probe(self):
        """Switche z custom community wymagaja 2 prob (public fail, netdoc2026 ok)."""
        cm = self._make_large_network(10)
        ip = "10.0.0.8"  # ma 'netdoc2026' (indeks 8 >= 80? nie, bo n=10, ale >=80 nie ma — zmien)
        # Wygenerujmy switch z custom community jawnie
        cm["10.0.0.8"] = {"netdoc2026"}

        tried = []
        mock_walk = _make_snmp_walk_mock(cm)

        def counting_walk(ip_arg, base, community="public", timeout=2.0, max_iter=500):
            tried.append(community)
            return mock_walk(ip_arg, base, community, timeout, max_iter)

        with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=counting_walk):
            result = snmp_find_community(
                "10.0.0.8", ("public", "netdoc2026"), inter_probe_delay=0
            )

        assert result == "netdoc2026"
        # Musimy probowac 2 razy (sysDescr dla public + sysDescr dla netdoc2026)
        assert tried.count("public") >= 1
        assert tried.count("netdoc2026") >= 1

    def test_rate_limiting_with_large_community_list(self):
        """Przy 100 community i 1 urzadzeniu — sleep wywolywany 99 razy."""
        communities = tuple(f"comm_{i}" for i in range(100))
        sleep_calls = []

        with patch("netdoc.collector.snmp_walk.snmp_walk", return_value=[]):
            with patch("netdoc.collector.snmp_walk._time.sleep") as mock_sleep:
                mock_sleep.side_effect = lambda s: sleep_calls.append(s)
                snmp_find_community("10.0.0.1", communities, inter_probe_delay=0.1)

        # 100 community → 99 sleepow (nie przed 1.)
        assert len(sleep_calls) == 99
        # Kazdy >= 0.3s (adaptacja >50 community)
        assert all(s >= 0.3 for s in sleep_calls)


# ─── Scenariusz 3: Zmiana community na urzadzeniu ─────────────────────────────

class TestCommunityChange:
    """Symuluje sytuacje kiedy administrator zmienil community string na urzadzeniu."""

    def test_old_community_no_longer_works(self):
        """Stara community 'public' przestala dzialac (admin zmienil na 'newcomm')."""
        # Urzadzenie odpowiada TYLKO na 'newcomm'
        cm = {"10.0.0.1": {"newcomm"}}

        with patch("netdoc.collector.snmp_walk.snmp_walk",
                   side_effect=_make_snmp_walk_mock(cm)):
            # Lista community: stara (public) + nowe (newcomm) — nowe na koncu listy
            result = snmp_find_community(
                "10.0.0.1", ("public", "newcomm"), inter_probe_delay=0
            )

        assert result == "newcomm"  # znaleziono nowa community

    def test_old_community_alone_returns_none(self):
        """Jesli lista ma tylko stara community — nic nie zwroci."""
        cm = {"10.0.0.1": {"newcomm"}}

        with patch("netdoc.collector.snmp_walk.snmp_walk",
                   side_effect=_make_snmp_walk_mock(cm)):
            result = snmp_find_community(
                "10.0.0.1", ("public",), inter_probe_delay=0
            )

        assert result is None  # stara community nie dziala

    def test_per_device_community_has_priority(self):
        """Per-device community (nowsza) jest probowana przed globalna.

        Symulacja: globalna lista = ('public',), per-device = ('newcomm',)
        Wywolujacy skleja: per-device + globalne → ('newcomm', 'public')
        """
        cm = {"10.0.0.1": {"newcomm"}}
        tried = []
        mock_walk = _make_snmp_walk_mock(cm)

        def counting_walk(ip, base, community="public", timeout=2.0, max_iter=500):
            tried.append(community)
            return mock_walk(ip, base, community, timeout, max_iter)

        # Per-device na poczatku listy
        communities = ("newcomm", "public")
        with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=counting_walk):
            result = snmp_find_community("10.0.0.1", communities, inter_probe_delay=0)

        assert result == "newcomm"
        assert tried[0] == "newcomm"  # probowano najpierw per-device
        assert "public" not in tried   # nie probowano globalnej (znaleziono wczesniej)

    def test_community_field_in_discover_result_when_changed(self):
        """snmp_discover_networks zwraca dzialajaca community w polu 'community'."""
        cm = {"10.0.0.1": {"newcomm"}}

        def fake_walk(ip, base, community="public", timeout=2.0, max_iter=500):
            if community == "newcomm" and base == "1.3.6.1.2.1.1.1":
                return [("1.3.6.1.2.1.1.1.0", b"Cisco IOS", 0x04)]
            return []

        with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=fake_walk):
            result = snmp_discover_networks(
                "10.0.0.1", ("public", "newcomm"), inter_probe_delay=0
            )

        assert result["community"] == "newcomm"


# ─── Scenariusz 4: Mix urzadzen, rozne community ──────────────────────────────

class TestMixedCommunities:
    """Siec z 5 urzadzeniami, kazde z innym community."""

    DEVICES = {
        "10.0.0.1": "public",
        "10.0.0.2": "private",
        "10.0.0.3": "cisco123",
        "10.0.0.4": "hp_switch",
        "10.0.0.5": "public",   # to samo co 1
    }

    def test_all_devices_found_with_full_community_list(self):
        """Wszystkie urzadzenia sa znalezione gdy lista zawiera wszystkie community."""
        cm = {ip: {comm} for ip, comm in self.DEVICES.items()}
        all_communities = ("public", "private", "cisco123", "hp_switch")

        for ip, expected_comm in self.DEVICES.items():
            with patch("netdoc.collector.snmp_walk.snmp_walk",
                       side_effect=_make_snmp_walk_mock(cm)):
                found = snmp_find_community(ip, all_communities, inter_probe_delay=0)
            assert found == expected_comm, f"{ip}: oczekiwano {expected_comm!r}, dostano {found!r}"

    def test_missing_community_device_not_found(self):
        """Urzadzenie z community spoza listy nie zostanie znalezione."""
        cm = {"10.0.0.3": {"cisco123"}}

        with patch("netdoc.collector.snmp_walk.snmp_walk",
                   side_effect=_make_snmp_walk_mock(cm)):
            # Lista bez 'cisco123'
            result = snmp_find_community(
                "10.0.0.3", ("public", "private"), inter_probe_delay=0
            )

        assert result is None

    def test_arp_discovery_reveals_hosts_behind_each_device(self):
        """Kazde urzadzenie ma inne hosty w ARP table — lacznie zbieramy wszystkie."""
        cm = {
            "10.0.0.1": {"public"},
            "10.0.0.2": {"private"},
        }
        arp = {
            "10.0.0.1": {
                "192.168.1.10": "aa:bb:cc:00:00:01",
                "192.168.1.11": "aa:bb:cc:00:00:02",
            },
            "10.0.0.2": {
                "172.16.0.50": "dd:ee:ff:00:00:01",
            },
        }

        all_found_ips = set()
        for ip, communities in [("10.0.0.1", ("public",)), ("10.0.0.2", ("private",))]:
            with patch("netdoc.collector.snmp_walk.snmp_walk",
                       side_effect=_make_snmp_walk_mock(cm, arp)):
                data = snmp_discover_networks(ip, communities, inter_probe_delay=0)
            all_found_ips.update(data["arp"].keys())

        assert "192.168.1.10" in all_found_ips
        assert "192.168.1.11" in all_found_ips
        assert "172.16.0.50" in all_found_ips


# ─── Scenariusz 5: SNMP niedostepny (firewall, brak SNMP) ─────────────────────

class TestSnmpUnavailable:
    """Urzadzenia ktore nie odpowiadaja na SNMP."""

    def test_no_response_at_all(self):
        with patch("netdoc.collector.snmp_walk.snmp_walk", return_value=[]):
            result = snmp_discover_networks(
                "10.0.0.99", ("public", "private"), inter_probe_delay=0
            )
        assert result["community"] is None
        assert result["arp"] == {}
        assert result["macs"] == []
        assert result["ifaces"] == []

    def test_socket_error_treated_as_no_response(self):
        """OSError (np. ICMP port unreachable) nie powoduje wyjatku."""
        with patch("netdoc.collector.snmp_walk._socket.socket") as mock_cls:
            mock_s = MagicMock()
            mock_cls.return_value = mock_s
            mock_s.connect.side_effect = OSError("Network unreachable")
            result = snmp_find_community("10.0.0.99", ("public",), inter_probe_delay=0)
        assert result is None

    def test_partial_firewall_blocks_some_walks(self):
        """Sysinfo dostepne (znaleziono community) ale ARP table zablokowana przez ACL."""
        def fake_walk(ip, base, community="public", timeout=2.0, max_iter=500):
            if base == "1.3.6.1.2.1.1.1":
                return [("1.3.6.1.2.1.1.1.0", b"Linux", 0x04)]
            # ARP table zablokowana
            return []

        with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=fake_walk):
            result = snmp_discover_networks("10.0.0.1", ("public",), inter_probe_delay=0)

        # Community znaleziono, ale tablice puste (ACL)
        assert result["community"] == "public"
        assert result["arp"] == {}
        assert result["macs"] == []


# ─── Scenariusz 6: Odkrywanie nowych podsieci przez ipRouteTable ──────────────

class TestRouteTableNetworkDiscovery:
    """Router zdradza nowe podsieci przez SNMP routing table."""

    def test_direct_routes_reveal_subnets(self):
        """Trasy direct (type=3) to podsieci bezposrednie — odkrywamy je."""
        from netdoc.collector.snmp_walk import snmp_route_table

        BASE_DEST    = "1.3.6.1.2.1.4.21.1.1"
        BASE_MASK    = "1.3.6.1.2.1.4.21.1.11"
        BASE_NEXTHOP = "1.3.6.1.2.1.4.21.1.7"
        BASE_TYPE    = "1.3.6.1.2.1.4.21.1.8"

        def fake_walk(ip, base, community="public", timeout=2.0, max_iter=500):
            if base == BASE_DEST:
                return [
                    (BASE_DEST + ".192.168.10.0", b"\xc0\xa8\x0a\x00", 0x40),  # 192.168.10.0
                    (BASE_DEST + ".172.16.5.0",   b"\xac\x10\x05\x00", 0x40),  # 172.16.5.0
                    (BASE_DEST + ".0.0.0.0",       b"\x00\x00\x00\x00", 0x40), # default route
                ]
            elif base == BASE_MASK:
                return [
                    (BASE_MASK + ".192.168.10.0", b"\xff\xff\xff\x00", 0x40),  # /24
                    (BASE_MASK + ".172.16.5.0",   b"\xff\xff\xff\x00", 0x40),  # /24
                    (BASE_MASK + ".0.0.0.0",       b"\x00\x00\x00\x00", 0x40), # /0
                ]
            elif base == BASE_NEXTHOP:
                return [
                    (BASE_NEXTHOP + ".192.168.10.0", b"\x00\x00\x00\x00", 0x40),
                    (BASE_NEXTHOP + ".172.16.5.0",   b"\x00\x00\x00\x00", 0x40),
                    (BASE_NEXTHOP + ".0.0.0.0",       b"\xc0\xa8\x01\x01", 0x40),
                ]
            elif base == BASE_TYPE:
                return [
                    (BASE_TYPE + ".192.168.10.0", b"\x03", 0x02),  # direct
                    (BASE_TYPE + ".172.16.5.0",   b"\x03", 0x02),  # direct
                    (BASE_TYPE + ".0.0.0.0",       b"\x04", 0x02),  # indirect
                ]
            return []

        with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=fake_walk):
            routes = snmp_route_table("10.0.0.1")

        direct = [r for r in routes if r["type"] == 3]
        dests = {r["dest"] for r in direct}
        assert "192.168.10.0" in dests
        assert "172.16.5.0" in dests
        # default route (0.0.0.0) jest indirect — nie w direct
        assert "0.0.0.0" not in dests or any(r["type"] != 3 for r in routes if r["dest"] == "0.0.0.0")

    def test_ifip_table_reveals_interface_addresses(self):
        """ipAddrTable pokazuje adresy interfejsow — kazdy to inna podsiec."""
        from netdoc.collector.snmp_walk import snmp_ifip_table

        BASE_ADDR = "1.3.6.1.2.1.4.20.1.1"
        BASE_MASK = "1.3.6.1.2.1.4.20.1.3"

        call_count = [0]

        def fake_walk(ip, base, community="public", timeout=2.0, max_iter=500):
            call_count[0] += 1
            if base == BASE_ADDR:
                return [
                    (BASE_ADDR + ".10.0.1.1",     b"\x0a\x00\x01\x01", 0x40),
                    (BASE_ADDR + ".10.0.2.1",     b"\x0a\x00\x02\x01", 0x40),
                    (BASE_ADDR + ".192.168.99.1", b"\xc0\xa8\x63\x01", 0x40),
                ]
            elif base == BASE_MASK:
                return [
                    (BASE_MASK + ".10.0.1.1",     b"\xff\xff\xff\x00", 0x40),
                    (BASE_MASK + ".10.0.2.1",     b"\xff\xff\xff\x00", 0x40),
                    (BASE_MASK + ".192.168.99.1", b"\xff\xff\xff\x00", 0x40),
                ]
            return []

        with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=fake_walk):
            ifaces = snmp_ifip_table("10.0.0.1")

        ips = {i["ip"] for i in ifaces}
        assert "10.0.1.1" in ips
        assert "10.0.2.1" in ips
        assert "192.168.99.1" in ips
        # Kazdy ma maske
        for i in ifaces:
            assert i.get("mask"), f"Interfejs {i['ip']} bez maski"


# ─── Scenariusz 7: _is_valid_private_ip — weryfikacja ───────────────────────

class TestPrivateIpValidation:
    """Sprawdza czy filtr prywatnych IP dziala poprawnie dla roznych adresow."""

    @pytest.mark.parametrize("ip,expected", [
        ("10.0.0.1", True),
        ("10.255.255.255", True),
        ("172.16.0.1", True),
        ("172.31.255.254", True),
        ("192.168.0.1", True),
        ("192.168.255.255", True),
        # Nie prywatne
        ("172.15.255.255", False),  # poza 172.16-31
        ("172.32.0.0", False),      # poza 172.16-31
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("127.0.0.1", False),       # loopback
        ("0.0.0.0", False),
        ("255.255.255.255", False),
        ("169.254.0.1", False),     # link-local
        # Niepoprawny format
        ("not.an.ip", False),
        ("", False),
        ("999.999.999.999", False),
    ])
    def test_validation(self, ip, expected):
        assert _is_valid_private_ip(ip) == expected, f"IP {ip!r}: oczekiwano {expected}"


# ─── Scenariusz 8: Wydajnosc — wiele community, zero opoznien w testach ────────

class TestPerformanceSimulation:
    """Sprawdza ze mechanizm nie jest 'stuck' przy duzych listach."""

    def test_1000_community_no_match_returns_quickly_with_mocked_sleep(self):
        """1000 community, brak dopasowania — nie zawiesza sie (sleep jest mockowany)."""
        communities = tuple(f"comm_{i}" for i in range(1000))
        sleep_count = [0]

        with patch("netdoc.collector.snmp_walk.snmp_walk", return_value=[]):
            with patch("netdoc.collector.snmp_walk._time.sleep") as mock_sleep:
                mock_sleep.side_effect = lambda s: sleep_count.__setitem__(0, sleep_count[0] + 1)
                result = snmp_find_community("10.0.0.1", communities, inter_probe_delay=0.1)

        assert result is None
        assert sleep_count[0] == 999  # sleep po kazdej probie oprocz pierwszej

    def test_first_community_works_no_sleep_called(self):
        """Jesli pierwsza community dziala — sleep nigdy nie jest wywolywany."""
        def always_works(ip, base, community="public", timeout=2.0, max_iter=500):
            return [("1.3.6.1.2.1.1.1.0", b"Linux", 0x04)]

        with patch("netdoc.collector.snmp_walk.snmp_walk", side_effect=always_works):
            with patch("netdoc.collector.snmp_walk._time.sleep") as mock_sleep:
                result = snmp_find_community(
                    "10.0.0.1", ("public", "private", "other"), inter_probe_delay=0.5
                )
                assert mock_sleep.call_count == 0  # brak sleep — znaleziono od razu
        assert result == "public"
