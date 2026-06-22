from __future__ import annotations

import ipaddress
import socket
from typing import Iterable, Set


def is_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def ip_obj(value: str | None):
    if not is_ip(value):
        return None
    return ipaddress.ip_address(value)  # type: ignore[arg-type]


def is_private_ip(value: str | None) -> bool:
    ip = ip_obj(value)
    if ip is None:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def is_link_local_ip(value: str | None) -> bool:
    ip = ip_obj(value)
    return bool(ip and ip.is_link_local)


def is_multicast_ip(value: str | None) -> bool:
    ip = ip_obj(value)
    return bool(ip and ip.is_multicast)


def is_broadcast_ip(value: str | None) -> bool:
    return value in {"255.255.255.255"} or (isinstance(value, str) and value.endswith(".255"))


def is_special_noise_ip(value: str | None) -> bool:
    """Traffic that is common local discovery/noise and should not become a security incident by default."""
    return is_multicast_ip(value) or is_broadcast_ip(value) or is_link_local_ip(value)


def normalize_ip(value: str | None) -> str:
    return value.strip() if value else ""


def get_local_ips() -> Set[str]:
    """Return local IPv4/IPv6 addresses for the host.

    Uses psutil when available because it is reliable on Windows with multiple adapters.
    Falls back to socket-based discovery when psutil is unavailable.
    """
    ips: Set[str] = set()
    try:
        import psutil  # type: ignore

        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                family = getattr(addr, "family", None)
                if family in (socket.AF_INET, socket.AF_INET6):
                    ip = getattr(addr, "address", "")
                    if ip and not ip.startswith("127.") and ip != "::1":
                        # Windows IPv6 addresses can include a scope ID after %.
                        ips.add(ip.split("%")[0])
    except Exception:
        pass

    try:
        hostname = socket.gethostname()
        for result in socket.getaddrinfo(hostname, None):
            ip = result[4][0]
            if ip and not ip.startswith("127.") and ip != "::1":
                ips.add(ip.split("%")[0])
    except Exception:
        pass

    return ips


def derive_gateway_candidates(local_ips: Iterable[str]) -> Set[str]:
    """Guess common home/office gateway IPs from local IPv4 addresses.

    Example: if the local host is 192.168.4.165, add 192.168.4.1.
    This is used as a default trusted network-device suppression to reduce false positives.
    """
    candidates: Set[str] = set()
    for ip in local_ips:
        try:
            obj = ipaddress.ip_address(ip)
            if obj.version != 4:
                continue
            parts = ip.split(".")
            if len(parts) == 4:
                candidates.add(".".join(parts[:3] + ["1"]))
        except Exception:
            continue
    return candidates


def infer_direction(src_ip: str, dst_ip: str, local_ips: Iterable[str]) -> str:
    local = set(local_ips)
    if src_ip in local and dst_ip not in local:
        return "outbound"
    if dst_ip in local and src_ip not in local:
        return "inbound"
    if src_ip in local and dst_ip in local:
        return "local"
    if is_private_ip(src_ip) and not is_private_ip(dst_ip):
        return "outbound_private"
    if not is_private_ip(src_ip) and is_private_ip(dst_ip):
        return "inbound_private"
    return "unknown"
