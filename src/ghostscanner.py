#!/usr/bin/env python3
"""
GhostScanner Professional
Fast async TCP/UDP discovery + Nmap integration
For authorized security testing only
"""

import asyncio
import sys
import subprocess
import shutil
import click
from rich.console import Console
from rich.table import Table

from .scanner import GhostScanner
from .reporter import export_json, export_csv, export_pdf
from .utils import parse_targets, parse_ports

console = Console()
__version__ = "2.0.0"

def run_nmap(hosts_ports: dict, extra_args: str = "-sV -sC"):
    """Run Nmap on discovered open ports"""
    if not shutil.which("nmap"):
        console.print("[red][!] Nmap not found. Install it to use --nmap[/red]")
        return

    console.print("\n[bold cyan][*] Launching Nmap on discovered ports...[/bold cyan]")

    for host, ports in hosts_ports.items():
        if not ports:
            continue
        port_str = ",".join(str(p) for p in ports)
        cmd = f"nmap -Pn -p {port_str} {extra_args} {host}"
        console.print(f"[*] {cmd}")
        try:
            subprocess.run(cmd, shell=True, check=False)
        except Exception as e:
            console.print(f"[red][!] Nmap error on {host}: {e}[/red]")

@click.command()
@click.argument("targets")
@click.option("-p", "--ports", default=None, help="Ports to scan (e.g. 22,80,443 or 1-1000)")
@click.option("--top", is_flag=True, help="Use common top ports")
@click.option("--udp", is_flag=True, help="UDP scan (basic)")
@click.option("-r", "--rate", default=1200, show_default=True, help="Max concurrent connections")
@click.option("-t", "--timeout", default=1.0, show_default=True, type=float, help="Timeout in seconds")
@click.option("--stealth", is_flag=True, help="Enable randomized delays")
@click.option("--banner", is_flag=True, help="Attempt banner grabbing (TCP only)")
@click.option("--nmap", "nmap_args", default=None, help="Run Nmap on open ports. Pass extra args as a string, e.g. --nmap=\"-sV -sC -D RND:5\"")
@click.option("--json", "json_file", default=None, help="Export JSON")
@click.option("--csv", "csv_file", default=None, help="Export CSV")
@click.option("--pdf", "pdf_file", default=None, help="Export PDF")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.version_option(__version__, prog_name="GhostScanner Professional")
def main(targets, ports, top, udp, rate, timeout, stealth, banner, nmap_args, json_file, csv_file, pdf_file, verbose):
    """GhostScanner Professional – Fast discovery + Nmap integration

    TARGETS can be an IP, CIDR, or file with targets.
    """
    try:
        target_list = parse_targets(targets)
        if not target_list:
            console.print("[red][!] No valid targets[/red]")
            sys.exit(1)

        port_list = parse_ports(ports, use_top=top, udp=udp)

        scanner = GhostScanner(
            targets=target_list,
            ports=port_list,
            concurrency=rate,
            timeout=timeout,
            stealth=stealth,
            grab_banner=banner and not udp,
            verbose=verbose,
            udp=udp,
        )

        results = asyncio.run(scanner.run())

        # Display results
        open_map = {}
        for host, result in results.items():
            if result.open_ports:
                table = Table(title=f"Open ports on {host}", show_header=True, header_style="bold green")
                table.add_column("Port", style="cyan", width=10)
                table.add_column("Proto", style="magenta")
                table.add_column("Banner / Info", style="white")
                table.add_column("Latency", style="yellow", justify="right")

                ports_for_nmap = []
                for p in result.open_ports:
                    table.add_row(
                        str(p.port),
                        p.protocol,
                        p.banner[:60] if p.banner else p.status,
                        f"{p.latency_ms} ms"
                    )
                    ports_for_nmap.append(p.port)

                console.print(table)
                open_map[host] = ports_for_nmap
            else:
                if verbose:
                    console.print(f"[yellow]No open ports on {host}[/yellow]")

        # Exports
        if json_file:
            export_json(results, json_file)
        if csv_file:
            export_csv(results, csv_file)
        if pdf_file:
            export_pdf(results, pdf_file)

        # Nmap integration
        if nmap_args is not None and open_map:
            run_nmap(open_map, extra_args=nmap_args if nmap_args else "-sV -sC")

    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red][!] Error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
