"""
Auto-wykrywanie lokalnych sieci do skanowania.

Logika:
  1. Pobiera adresy wszystkich interfejsow sieciowych (psutil)
  2. Filtruje do prywatnych klas adresowych (RFC 1918)
  3. Wylicza CIDR podsieci (np. 192.168.1.0/24)
  4. Pomija loopback, link-local (169.254.x.x), IPv6

Prywatne klasy adresowe (RFC 1918):
  - 10.0.0.0/8       (klasa A)
  - 172.16.0.0/12    (klasa B)
  - 192.168.0.0/16   (klasa C)
"""
import ipaddress
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)
from dataclasses import dataclass

# Prefiksy nazw interfejsow VPN (Linux, Windows, macOS)
_VPN_PREFIXES = (
    'tun',      # OpenVPN, WireGuard legacy, Linux generic
    'tap',      # OpenVPN bridge mode
    'wg',       # WireGuard
    'ppp',      # PPTP, L2TP, starsze VPN
    'vpn',      # ogolny
    'ipsec',    # IPSec
    'l2tp',     # L2TP
    'sstp',     # SSTP (Windows)
)

# Windows: nazwy adapterow VPN w pelnej nazwie
_VPN_NAME_FRAGMENTS = (
    'vpn', 'cisco anyconnect', 'globalprotect', 'pulse', 'fortinet',
    'nordvpn', 'expressvpn', 'openvpn', 'wireguard',
)

# Prefiksy wirtualnych interfejsow (Docker, Hyper-V, VMware, WSL, VirtualBox)
_VIRTUAL_PREFIXES = (
    'docker',   # Docker bridge (docker0, docker_gwbridge)
    'br-',      # Docker user-defined bridge networks
    'veth',     # Docker/Linux container veth pairs
    'virbr',    # libvirt (KVM/QEMU)
    'vmnet',    # VMware Workstation/Fusion
    'vboxnet',  # VirtualBox host-only
    'podman',   # Podman
    'cni',      # Kubernetes CNI
    'flannel',  # Kubernetes Flannel
    'cali',     # Kubernetes Calico
    'weave',    # Kubernetes Weave
)

# Fragmenty nazw wirtualnych adapterow (Windows: Hyper-V, WSL, Docker Desktop)
_VIRTUAL_NAME_FRAGMENTS = (
    'vethernet',        # Hyper-V virtual switch (vEthernet (Default Switch) itp.)
    'default switch',   # Hyper-V Default Switch
    'wsl',              # WSL (Windows Subsystem for Linux)
    'dockernat',        # Docker Desktop NAT (stare wersje)
    'docker desktop',   # Docker Desktop
    'hyperv',           # ogolny Hyper-V
    'hyper-v',          # ogolny Hyper-V (z myslnikiem)
    'nat network',      # VirtualBox NAT Network
    'host-only',        # VirtualBox Host-Only
    'vmware',           # VMware adaptery Windows
)


def is_virtual_interface(iface_name: str) -> tuple:
    """
    Sprawdza czy interfejs wyglada jak wirtualny (Docker, Hyper-V, WSL, VMware itp.).

    Returns:
        (is_virtual: bool, reason: str)
    """
    name_lower = iface_name.lower()
    for prefix in _VIRTUAL_PREFIXES:
        if name_lower.startswith(prefix):
            return True, f"prefiks wirtualny: {prefix}"
    for fragment in _VIRTUAL_NAME_FRAGMENTS:
        if fragment in name_lower:
            return True, f"nazwa zawiera: {fragment}"
    return False, ""


@dataclass
class InterfaceInfo:
    name: str
    ip: str
    cidr: str
    is_vpn: bool
    vpn_reason: str = ""
    is_virtual: bool = False
    virtual_reason: str = ""


def is_vpn_interface(iface_name: str) -> tuple:
    """
    Sprawdza czy interfejs wyglada jak VPN.

    Returns:
        (is_vpn: bool, reason: str)
    """
    name_lower = iface_name.lower()
    for prefix in _VPN_PREFIXES:
        if name_lower.startswith(prefix):
            return True, f"prefiks interfejsu: {prefix}"
    for fragment in _VPN_NAME_FRAGMENTS:
        if fragment in name_lower:
            return True, f"nazwa zawiera: {fragment}"
    return False, ""



# RFC 1918 prywatne zakresy
_PRIVATE_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]


def is_private(ip: str) -> bool:
    """Zwraca True jezeli adres nalezy do prywatnej klasy RFC 1918."""
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def ip_and_prefix_to_cidr(ip: str, netmask: str) -> Optional[str]:
    """
    Konwertuje adres IP + maska sieciowa na CIDR podsieci.

    Przyklad: ('192.168.1.50', '255.255.255.0') -> '192.168.1.0/24'
    """
    try:
        interface = ipaddress.IPv4Interface(f"{ip}/{netmask}")
        return str(interface.network)
    except ValueError:
        return None


def scan_local_interfaces() -> List[InterfaceInfo]:
    """
    Skanuje wszystkie lokalne interfejsy i zwraca pelna liste InterfaceInfo.
    Rozdziela VPN od fizycznych/wirtualnych sieci lokalnych.

    Returns:
        Lista InterfaceInfo z polem is_vpn.
    """
    try:
        import psutil
    except ImportError:
        logger.warning(
            "psutil nie jest zainstalowany — auto-wykrywanie sieci niedostepne. "
            "pip install psutil  lub podaj NETWORK_RANGES w .env"
        )
        return []

    result = []

    for iface_name, addrs in psutil.net_if_addrs().items():
        vpn, vpn_reason = is_vpn_interface(iface_name)
        virtual, virtual_reason = is_virtual_interface(iface_name)
        for addr in addrs:
            if addr.family != 2:   # tylko IPv4
                continue
            ip = addr.address
            netmask = addr.netmask
            if not ip or not netmask or not is_private(ip):
                continue
            cidr = ip_and_prefix_to_cidr(ip, netmask)
            if not cidr:
                continue

            info = InterfaceInfo(
                name=iface_name, ip=ip, cidr=cidr,
                is_vpn=vpn, vpn_reason=vpn_reason,
                is_virtual=virtual, virtual_reason=virtual_reason,
            )
            result.append(info)

            if vpn:
                logger.warning(
                    "Wykryto interfejs VPN: %s (%s) -> %s [%s]. "
                    "Ta siec NIE bedzie skanowana automatycznie. "
                    "Wlacz SCAN_VPN_NETWORKS=true w .env aby zezwolic.",
                    iface_name, ip, cidr, vpn_reason,
                )
            elif virtual:
                logger.info(
                    "Wykryto interfejs wirtualny: %s (%s) -> %s [%s]. "
                    "Pomijany (SCAN_VIRTUAL_NETWORKS=false).",
                    iface_name, ip, cidr, virtual_reason,
                )
            else:
                logger.info("Wykryto lokalna siec: %s (interfejs: %s, IP: %s)", cidr, iface_name, ip)

    return result


def detect_local_networks(include_vpn: bool = False,
                          include_virtual: bool = False) -> List[str]:
    """
    Zwraca liste CIDR do skanowania z lokalnych interfejsow.

    Args:
        include_vpn:     jezeli True, dolacza sieci VPN (domyslnie False).
        include_virtual: jezeli True, dolacza sieci wirtualne: Docker, Hyper-V,
                         WSL, VMware itp. (domyslnie False — nie skanuj wirtualnych).

    Returns:
        Lista CIDR posortowana od najbardziej szczegolowej.
    """
    interfaces = scan_local_interfaces()

    cidrs = set()
    for iface in interfaces:
        if iface.is_vpn and not include_vpn:
            continue
        if iface.is_virtual and not include_virtual:
            continue
        cidrs.add(iface.cidr)

    result = sorted(cidrs, key=lambda n: ipaddress.IPv4Network(n).prefixlen, reverse=True)

    if not result:
        skipped_vpn = [i.cidr for i in interfaces if i.is_vpn]
        skipped_virt = [i.cidr for i in interfaces if i.is_virtual and not i.is_vpn]
        if skipped_vpn and not include_vpn:
            logger.warning(
                "Wszystkie wykryte sieci to VPN (%s). "
                "Uzyj SCAN_VPN_NETWORKS=true w .env aby je skanowac.",
                ", ".join(skipped_vpn),
            )
        elif skipped_virt and not include_virtual:
            logger.warning(
                "Wszystkie wykryte sieci to wirtualne (%s). "
                "Uzyj SCAN_VIRTUAL_NETWORKS=true w .env aby je skanowac.",
                ", ".join(skipped_virt),
            )
        else:
            logger.warning(
                "Nie wykryto zadnych prywatnych sieci lokalnych. "
                "Podaj NETWORK_RANGES w .env lub podlacz do sieci."
            )

    return result


def subnet_from_ip(ip: str, prefix_len: int = 24) -> Optional[str]:
    """
    Wylicza podsiec /prefix_len dla podanego IP.
    Uzywane gdy odkryjemy nowy host przez LLDP w nieznanej podsieci.

    Przyklad: ('10.2.5.100', 24) -> '10.2.5.0/24'
    """
    try:
        net = ipaddress.IPv4Network(f"{ip}/{prefix_len}", strict=False)
        return str(net)
    except ValueError:
        return None


def infer_prefix_from_ip(ip: str) -> int:
    """
    Heurystyczny prefix length na podstawie klasy adresowej RFC 1918.
    Uzywany gdy LLDP nie podaje maski.
    """
    try:
        addr = ipaddress.IPv4Address(ip)
        if addr in ipaddress.IPv4Network("10.0.0.0/8"):
            return 24   # najczesciej /24 w sieciach firmowych
        if addr in ipaddress.IPv4Network("172.16.0.0/12"):
            return 24
        if addr in ipaddress.IPv4Network("192.168.0.0/16"):
            return 24
    except ValueError:
        pass
    return 24
