import ipaddress
import re
import subprocess

MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def is_local_ip(ip) -> bool:
    """True for private IPv4 ranges and loopback."""
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    if not isinstance(address, ipaddress.IPv4Address):
        return False
    return (
        address.is_loopback
        or address in ipaddress.ip_network("10.0.0.0/8")
        or address in ipaddress.ip_network("172.16.0.0/12")
        or address in ipaddress.ip_network("192.168.0.0/16")
    )


def get_mac_from_ip(ip):
    """Windows ARP-table lookup. Works only for local devices this PC has recently talked to."""
    if not is_local_ip(ip):
        return None
    try:
        result = subprocess.run(["arp", "-a", str(ip)], capture_output=True, text=True, timeout=3)
        match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", result.stdout)
        if match:
            return match.group(0).lower().replace("-", ":")
    except Exception:
        pass
    return None


def resolve_mac(src_ip, src_mac=None):
    """
    Return a MAC only when the source is on the local network.
    For an external source, any MAC seen on our LAN is the router's, so we return None.
    """
    if not is_local_ip(src_ip):
        return None
    if src_mac:
        if not MAC_PATTERN.match(str(src_mac)):
            raise ValueError("src_mac must look like aa:bb:cc:dd:ee:ff")
        return str(src_mac).lower().replace("-", ":")
    return get_mac_from_ip(src_ip)