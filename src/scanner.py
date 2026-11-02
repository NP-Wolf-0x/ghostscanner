#!/usr/bin/env python3
"""
GhostScanner Professional - Core scanning engine
TCP + UDP discovery
"""

import asyncio
import socket
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from .utils import random_jitter

console = Console()

@dataclass
class PortResult:
    host: str
    port: int
    status: str          # open / closed / filtered / open|filtered
    protocol: str = "tcp"
    service: str = ""
    banner: str = ""
    latency_ms: float = 0.0

@dataclass
class ScanResult:
    host: str
    open_ports: List[PortResult] = field(default_factory=list)
    scan_time: float = 0.0

class GhostScanner:
    def __init__(
        self,
        targets: List[str],
        ports: List[int],
        concurrency: int = 1000,
        timeout: float = 1.0,
        stealth: bool = False,
        grab_banner: bool = False,
        verbose: bool = False,
        udp: bool = False,
    ):
        self.targets = targets
        self.ports = ports
        self.concurrency = concurrency
        self.timeout = timeout
        self.stealth = stealth
        self.grab_banner = grab_banner
        self.verbose = verbose
        self.udp = udp
        self.results: Dict[str, ScanResult] = {}
        self._semaphore = asyncio.Semaphore(concurrency)
        self._total_checks = len(targets) * len(ports)
        self._completed = 0
        self._open_count = 0

    async def _check_tcp(self, host: str, port: int) -> PortResult:
        async with self._semaphore:
            start = time.perf_counter()
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
                latency = (time.perf_counter() - start) * 1000
                banner = ""

                if self.grab_banner:
                    try:
                        writer.write(b"\r\n")
                        await writer.drain()
                        data = await asyncio.wait_for(reader.read(256), timeout=0.7)
                        banner = data.decode("utf-8", errors="ignore").strip()[:100]
                    except Exception:
                        pass

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                self._open_count += 1
                if self.verbose:
                    console.print(f"[green]{host}:{port}/tcp open[/green]  {banner[:40]}")

                return PortResult(
                    host=host,
                    port=port,
                    status="open",
                    protocol="tcp",
                    banner=banner,
                    latency_ms=round(latency, 2),
                )

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return PortResult(host=host, port=port, status="closed", protocol="tcp")
            finally:
                self._completed += 1
                if self.stealth:
                    await asyncio.sleep(random_jitter())

    async def _check_udp(self, host: str, port: int) -> PortResult:
        """Basic UDP probe - limited reliability (UDP is connectionless)"""
        async with self._semaphore:
            start = time.perf_counter()
            try:
                loop = asyncio.get_event_loop()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                sock.settimeout(self.timeout)

                # Send a small probe
                await loop.sock_sendto(sock, b"\x00\x00\x00\x00", (host, port))

                try:
                    data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 256), timeout=self.timeout)
                    latency = (time.perf_counter() - start) * 1000
                    sock.close()
                    self._open_count += 1
                    if self.verbose:
                        console.print(f"[green]{host}:{port}/udp open|filtered[/green]")
                    return PortResult(
                        host=host,
                        port=port,
                        status="open|filtered",
                        protocol="udp",
                        latency_ms=round(latency, 2),
                    )
                except (asyncio.TimeoutError, OSError):
                    sock.close()
                    return PortResult(host=host, port=port, status="open|filtered", protocol="udp")

            except Exception:
                return PortResult(host=host, port=port, status="closed", protocol="udp")
            finally:
                self._completed += 1
                if self.stealth:
                    await asyncio.sleep(random_jitter())

    async def scan_host(self, host: str) -> ScanResult:
        if self.udp:
            tasks = [self._check_udp(host, port) for port in self.ports]
        else:
            tasks = [self._check_tcp(host, port) for port in self.ports]

        port_results = await asyncio.gather(*tasks)
        open_ports = [r for r in port_results if r.status.startswith("open")]
        return ScanResult(host=host, open_ports=open_ports)

    async def run(self) -> Dict[str, ScanResult]:
        proto = "UDP" if self.udp else "TCP"
        console.print(f"[bold cyan][*] GhostScanner Professional[/bold cyan] — {proto} Discovery")
        console.print(f"[*] Targets: {len(self.targets)} | Ports: {len(self.ports)} | Concurrency: {self.concurrency}")
        if self.stealth:
            console.print("[*] Stealth mode enabled")
        console.print("[*] Starting scan...\n")

        start_time = time.perf_counter()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=self._total_checks)

            async def update_progress():
                while self._completed < self._total_checks:
                    progress.update(task, completed=self._completed)
                    await asyncio.sleep(0.15)
                progress.update(task, completed=self._total_checks)

            progress_task = asyncio.create_task(update_progress())
            host_tasks = [self.scan_host(host) for host in self.targets]
            host_results = await asyncio.gather(*host_tasks)

            progress_task.cancel()
            try:
                await progress_task
            except asyncio.CancelledError:
                pass

        elapsed = time.perf_counter() - start_time

        for res in host_results:
            res.scan_time = elapsed
            self.results[res.host] = res

        total_open = sum(len(r.open_ports) for r in self.results.values())
        pps = self._total_checks / elapsed if elapsed > 0 else 0

        console.print(f"\n[bold green][+] Scan completed in {elapsed:.2f}s[/bold green]")
        console.print(f"[+] {total_open} open ports found | {pps:,.0f} ports/sec")

        return self.results
