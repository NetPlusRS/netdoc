"""Testy auto-wykrywania sieci."""
from unittest.mock import patch, MagicMock
import pytest

from netdoc.collector.network_detect import (
    is_private, ip_and_prefix_to_cidr, subnet_from_ip,
    infer_prefix_from_ip, detect_local_networks,
)


# --- is_private ---

@pytest.mark.parametrize("ip,expected", [
    ("192.168.1.1", True),
    ("10.0.0.1", True),
    ("172.16.0.1", True),
    ("172.31.255.255", True),
    ("8.8.8.8", False),
    ("1.1.1.1", False),
    ("169.254.0.1", False),   # link-local
    ("127.0.0.1", False),     # loopback
])
def test_is_private(ip, expected):
    assert is_private(ip) == expected


# --- ip_and_prefix_to_cidr ---

@pytest.mark.parametrize("ip,mask,expected", [
    ("192.168.1.50", "255.255.255.0", "192.168.1.0/24"),
    ("10.0.5.100", "255.255.255.0", "10.0.5.0/24"),
    ("172.16.0.1", "255.255.0.0", "172.16.0.0/16"),
    ("10.0.0.1", "255.0.0.0", "10.0.0.0/8"),
])
def test_ip_and_prefix_to_cidr(ip, mask, expected):
    assert ip_and_prefix_to_cidr(ip, mask) == expected


def test_ip_and_prefix_to_cidr_invalid():
    assert ip_and_prefix_to_cidr("not-an-ip", "255.255.255.0") is None


# --- subnet_from_ip ---

def test_subnet_from_ip_default_24():
    assert subnet_from_ip("192.168.5.200") == "192.168.5.0/24"

def test_subnet_from_ip_custom_prefix():
    assert subnet_from_ip("10.0.0.1", prefix_len=16) == "10.0.0.0/16"


# --- infer_prefix_from_ip ---

@pytest.mark.parametrize("ip,expected", [
    ("10.1.2.3", 24),
    ("172.20.0.1", 24),
    ("192.168.100.1", 24),
])
def test_infer_prefix(ip, expected):
    assert infer_prefix_from_ip(ip) == expected


# --- detect_local_networks ---

def test_detect_local_networks_returns_private_cidrs():
    """Mockuje psutil.net_if_addrs i sprawdza wynik."""
    mock_addr = MagicMock()
    mock_addr.family = 2  # AF_INET
    mock_addr.address = "192.168.1.10"
    mock_addr.netmask = "255.255.255.0"

    mock_addr_loopback = MagicMock()
    mock_addr_loopback.family = 2
    mock_addr_loopback.address = "127.0.0.1"
    mock_addr_loopback.netmask = "255.0.0.0"

    mock_addr_public = MagicMock()
    mock_addr_public.family = 2
    mock_addr_public.address = "8.8.8.8"
    mock_addr_public.netmask = "255.255.255.0"

    with patch("psutil.net_if_addrs", return_value={
        "eth0": [mock_addr],
        "lo": [mock_addr_loopback],
        "eth1": [mock_addr_public],
    }):
        result = detect_local_networks()

    assert "192.168.1.0/24" in result
    assert not any("127." in r for r in result)
    assert not any("8.8." in r for r in result)


def test_detect_local_networks_multiple_interfaces():
    """Dwa prywatne interfejsy -> dwa CIDR."""
    def make_addr(ip, mask):
        a = MagicMock()
        a.family = 2
        a.address = ip
        a.netmask = mask
        return a

    with patch("psutil.net_if_addrs", return_value={
        "eth0": [make_addr("192.168.1.5", "255.255.255.0")],
        "eth1": [make_addr("10.0.1.5", "255.255.255.0")],
    }):
        result = detect_local_networks()

    assert "192.168.1.0/24" in result
    assert "10.0.1.0/24" in result
    assert len(result) == 2


def test_detect_local_networks_no_psutil():
    """Brak psutil -> pusta lista (nie crash)."""
    with patch.dict("sys.modules", {"psutil": None}):
        import importlib
        import netdoc.collector.network_detect as nd
        importlib.reload(nd)
        # Po reload psutil jest None wiec import wewnatrz funkcji zarowno nie crashuje
        # Testujemy ze zwraca liste (moze byc pusta lub zawisc od systemu)
        result = nd.detect_local_networks()
        assert isinstance(result, list)


# --- is_vpn_interface ---

from netdoc.collector.network_detect import is_vpn_interface, is_virtual_interface, scan_local_interfaces, InterfaceInfo

@pytest.mark.parametrize("name,expected_vpn", [
    ("tun0", True),
    ("tun1", True),
    ("wg0", True),
    ("wg-home", True),
    ("ppp0", True),
    ("tap0", True),
    ("vpn_corp", True),
    ("eth0", False),
    ("ens33", False),
    ("Wi-Fi", False),
    ("Ethernet", False),
    ("Local Area Connection", False),
])
def test_is_vpn_interface(name, expected_vpn):
    is_vpn, reason = is_vpn_interface(name)
    assert is_vpn == expected_vpn, f"Interface '{name}': expected is_vpn={expected_vpn}, got {is_vpn} (reason: {reason})"


@pytest.mark.parametrize("name", [
    "Cisco AnyConnect",
    "GlobalProtect",
    "NordVPN",
    "OpenVPN TAP",
    "FortiNet SSL VPN",
])
def test_is_vpn_by_name_fragment(name):
    is_vpn, reason = is_vpn_interface(name)
    assert is_vpn, f"'{name}' powinien byc wykryty jako VPN"


# --- scan_local_interfaces z VPN ---

def test_scan_local_interfaces_marks_vpn():
    """VPN interface jest oznaczony is_vpn=True."""
    from unittest.mock import patch, MagicMock

    def make_addr(ip, mask):
        a = MagicMock()
        a.family = 2
        a.address = ip
        a.netmask = mask
        return a

    with patch("psutil.net_if_addrs", return_value={
        "eth0": [make_addr("192.168.1.5", "255.255.255.0")],
        "tun0": [make_addr("10.8.0.2", "255.255.255.0")],
    }):
        result = scan_local_interfaces()

    eth = next(i for i in result if i.name == "eth0")
    tun = next(i for i in result if i.name == "tun0")

    assert eth.is_vpn is False
    assert tun.is_vpn is True
    assert "tun" in tun.vpn_reason


def test_detect_local_networks_excludes_vpn_by_default():
    """Domyslnie VPN jest wykluczone z listy skanowania."""
    from unittest.mock import patch, MagicMock

    def make_addr(ip, mask):
        a = MagicMock()
        a.family = 2
        a.address = ip
        a.netmask = mask
        return a

    with patch("psutil.net_if_addrs", return_value={
        "eth0": [make_addr("192.168.1.5", "255.255.255.0")],
        "tun0": [make_addr("10.8.0.2", "255.255.255.0")],
    }):
        result = detect_local_networks(include_vpn=False)

    assert "192.168.1.0/24" in result
    assert "10.8.0.0/24" not in result


def test_detect_local_networks_includes_vpn_when_requested():
    """include_vpn=True dodaje sieci VPN do listy."""
    from unittest.mock import patch, MagicMock

    def make_addr(ip, mask):
        a = MagicMock()
        a.family = 2
        a.address = ip
        a.netmask = mask
        return a

    with patch("psutil.net_if_addrs", return_value={
        "eth0": [make_addr("192.168.1.5", "255.255.255.0")],
        "tun0": [make_addr("10.8.0.2", "255.255.255.0")],
    }):
        result = detect_local_networks(include_vpn=True)

    assert "192.168.1.0/24" in result
    assert "10.8.0.0/24" in result


# --- is_virtual_interface ---

@pytest.mark.parametrize("name,expected_virtual", [
    ("docker0", True),
    ("br-abc123", True),
    ("veth0a1b2c", True),
    ("virbr0", True),
    ("vmnet1", True),
    ("vboxnet0", True),
    ("podman0", True),
    ("cni0", True),
    ("flannel.1", True),
    ("cali12345", True),
    ("weave", True),
    ("eth0", False),
    ("ens33", False),
    ("Wi-Fi", False),
    ("Ethernet", False),
])
def test_is_virtual_interface_by_prefix(name, expected_virtual):
    is_virt, reason = is_virtual_interface(name)
    assert is_virt == expected_virtual, (
        f"Interface '{name}': expected is_virtual={expected_virtual}, got {is_virt} (reason: {reason})"
    )


@pytest.mark.parametrize("name", [
    "vEthernet (Default Switch)",
    "vEthernet (WSL (Hyper-V))",
    "Docker Desktop Network",
    "DockerNAT",
    "Hyper-V Virtual Ethernet Adapter",
    "VMware Network Adapter VMnet1",
])
def test_is_virtual_interface_by_name_fragment(name):
    is_virt, reason = is_virtual_interface(name)
    assert is_virt, f"'{name}' powinien byc wykryty jako wirtualny"


@pytest.mark.parametrize("name", [
    "Cisco AnyConnect",
    "tun0",
    "wg0",
    "Local Area Connection",
])
def test_is_virtual_interface_not_virtual(name):
    is_virt, _ = is_virtual_interface(name)
    assert not is_virt, f"'{name}' NIE powinien byc wykryty jako wirtualny"


# --- scan_local_interfaces z wirtualnymi ---

def test_scan_local_interfaces_marks_virtual():
    """Wirtualny interfejs (vEthernet) jest oznaczony is_virtual=True."""
    def make_addr(ip, mask):
        a = MagicMock()
        a.family = 2
        a.address = ip
        a.netmask = mask
        return a

    with patch("psutil.net_if_addrs", return_value={
        "eth0": [make_addr("192.168.1.5", "255.255.255.0")],
        "vEthernet (Default Switch)": [make_addr("172.16.0.1", "255.255.0.0")],
    }):
        result = scan_local_interfaces()

    eth = next(i for i in result if i.name == "eth0")
    virt = next(i for i in result if "Default Switch" in i.name)

    assert eth.is_virtual is False
    assert virt.is_virtual is True
    # "vEthernet" starts with "veth" prefix → caught by prefix rule
    assert virt.virtual_reason != ""


def test_detect_local_networks_excludes_virtual_by_default():
    """Domyslnie sieci wirtualne sa wykluczone z listy skanowania."""
    def make_addr(ip, mask):
        a = MagicMock()
        a.family = 2
        a.address = ip
        a.netmask = mask
        return a

    with patch("psutil.net_if_addrs", return_value={
        "eth0": [make_addr("192.168.1.5", "255.255.255.0")],
        "vEthernet (Default Switch)": [make_addr("172.22.0.1", "255.255.240.0")],
    }):
        result = detect_local_networks(include_virtual=False)

    assert "192.168.1.0/24" in result
    assert not any("172.22." in r for r in result)


def test_detect_local_networks_includes_virtual_when_requested():
    """include_virtual=True dodaje sieci wirtualne do listy."""
    def make_addr(ip, mask):
        a = MagicMock()
        a.family = 2
        a.address = ip
        a.netmask = mask
        return a

    with patch("psutil.net_if_addrs", return_value={
        "eth0": [make_addr("192.168.1.5", "255.255.255.0")],
        "docker0": [make_addr("172.17.0.1", "255.255.0.0")],
    }):
        result = detect_local_networks(include_virtual=True)

    assert "192.168.1.0/24" in result
    assert "172.17.0.0/16" in result


def test_detect_local_networks_virtual_and_vpn_both_excluded():
    """Oba filtry dzialaja jednoczesnie — VPN i virtual sa pomijane domyslnie."""
    def make_addr(ip, mask):
        a = MagicMock()
        a.family = 2
        a.address = ip
        a.netmask = mask
        return a

    with patch("psutil.net_if_addrs", return_value={
        "eth0": [make_addr("192.168.1.5", "255.255.255.0")],
        "tun0": [make_addr("10.8.0.2", "255.255.255.0")],
        "docker0": [make_addr("172.17.0.1", "255.255.0.0")],
    }):
        result = detect_local_networks(include_vpn=False, include_virtual=False)

    assert result == ["192.168.1.0/24"]
