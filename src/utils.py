#!/usr/bin/env python3
"""Utility helpers for GhostScanner."""

import ipaddress
import random
from typing import List, Set
from pathlib import Path


# Most common ports (used with --top)
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 1723, 3306, 3389, 5432, 5900, 5901, 6379, 8080, 8443, 8888,
    27017, 631, 902
]


def parse_targets(target_input: str) -> List[str]:
    targets: Set[str] = set()
    path = Path(target_input)

    if path.is_file():
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        for line in lines:
            targets.update(_expand_target(line))
    else:
        targets.update(_expand_target(target_input))

    return sorted(targets, key=lambda x: ipaddress.ip_address(x) if _is_ip(x) else x)


def _expand_target(target: str) -> List[str]:
    target = target.strip()
    try:
        network = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in network.hosts()] or [str(network.network_address)]
    except ValueError:
        return [target]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_ports(port_str: str, use_top: bool = False) -> List[int]:
    if use_top:
        return TOP_PORTS

    if not port_str:
        return TOP_PORTS

    ports: Set[int] = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                ports.update(range(int(start), int(end) + 1))
            except ValueError:
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue

    return sorted(p for p in ports if 1 <= p <= 65535)


def random_jitter(base: float = 0.05, variance: float = 0.03) -> float:
    return max(0.0, base + random.uniform(-variance, variance))


SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
    1433: "ms-sql", 1521: "oracle", 1723: "pptp", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 5901: "vnc",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    27017: "mongodb", 631: "ipp", 902: "vmware-auth"
}


def guess_service(port: int, banner: str = "") -> str:
    if banner:
        banner_l = banner.lower()
        if "ssh" in banner_l: return "ssh"
        if "http" in banner_l or "nginx" in banner_l or "apache" in banner_l: return "http"
        if "ftp" in banner_l: return "ftp"
        if "smtp" in banner_l: return "smtp"
        if "mysql" in banner_l: return "mysql"
        if "redis" in banner_l: return "redis"
        if "vmware" in banner_l: return "vmware-auth"
        if "ipp" in banner_l or "cups" in banner_l: return "ipp"
    return SERVICE_MAP.get(port, "unknown")