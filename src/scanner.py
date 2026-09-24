#!/usr/bin/env python3
"""Core asynchronous scanning engine for GhostScanner."""

import asyncio
import time
from dataclasses import dataclass, field
from typing import List, Dict
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from .utils import random_jitter, guess_service

console = Console()


@dataclass
class PortResult:
    host: str
    port: int
    status: str
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
    ):
        self.targets = targets
        self.ports = ports
        self.concurrency = concurrency
        self.timeout = timeout
        self.stealth = stealth
        self.grab_banner = grab_banner
        self.verbose = verbose
        self.results: Dict[str, ScanResult] = {}
        self._semaphore = asyncio.Semaphore(concurrency)
        self._total_checks = len(targets) * len(ports)
        self._completed = 0

    async def _check_port(self, host: str, port: int) -> PortResult:
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
                        data = await asyncio.wait_for(reader.read(256), timeout=0.8)
                        banner = data.decode("utf-8", errors="ignore").strip()[:120]
                    except Exception:
                        pass

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                service = guess_service(port, banner)
                result = PortResult(
                    host=host,
                    port=port,
                    status="open",
                    service=service,
                    banner=banner,
                    latency_ms=round(latency, 2),
                )

                if self.verbose:
                    console.print(f"[green]{host}:{port}[/green]  open  {service}  {banner[:40]}")

                return result

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return PortResult(host=host, port=port, status="closed")
            finally:
                self._completed += 1
                if self.stealth:
                    await asyncio.sleep(random_jitter(0.01, 0.02))

    async def scan_host(self, host: str) -> ScanResult:
        tasks = [self._check_port(host, port) for port in self.ports]
        port_results = await asyncio.gather(*tasks)
        open_ports = [r for r in port_results if r.status == "open"]
        return ScanResult(host=host, open_ports=open_ports)

    async def run(self) -> Dict[str, ScanResult]:
        console.print(f"[bold cyan][*] GhostScanner[/bold cyan] – Asynchronous Port Scanner")
        console.print(f"[*] Targets: {len(self.targets)} | Ports: {len(self.ports)} | Concurrency: {self.concurrency}")
        if self.stealth:
            console.print("[*] Stealth mode enabled (randomized jitter)")
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
                    await asyncio.sleep(0.1)
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
        console.print(f"\n[bold green][+] Scan completed in {elapsed:.2f}s[/bold green]")
        console.print(f"[+] {total_open} open ports found")

        return self.results