#!/usr/bin/env python3
"""Utility helpers for GhostScanner Professional"""

import ipaddress
import random
from typing import List, Set
from pathlib import Path

# Real Nmap-style top ports (most common)
TOP_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000,
    5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900,
    6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
    9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157
]

COMMON_UDP_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 4500, 5353]

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

def parse_ports(port_str: str | None, use_top: bool = False, udp: bool = False) -> List[int]:
    if use_top:
        return COMMON_UDP_PORTS if udp else TOP_PORTS

    if not port_str:
        return COMMON_UDP_PORTS if udp else TOP_PORTS

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

def random_jitter(base: float = 0.03, variance: float = 0.025) -> float:
    return max(0.0, base + random.uniform(-variance, variance))
