#!/usr/bin/env python3
"""
GhostScanner – High-performance asynchronous port scanner
"""

import asyncio
import sys
import click
from rich.console import Console
from rich.table import Table

from .scanner import GhostScanner
from .reporter import export_json, export_pdf, export_csv
from .utils import parse_targets, parse_ports

console = Console()
__version__ = "1.2.0"


@click.command()
@click.argument("targets")
@click.option("-p", "--ports", default=None, help="Ports to scan (e.g. 22,80,443,8000-8100)")
@click.option("--top", is_flag=True, help="Scan only the most common ports")
@click.option("-r", "--rate", default=1000, show_default=True, help="Max concurrent connections")
@click.option("-t", "--timeout", default=1.0, show_default=True, type=float, help="Connection timeout (seconds)")
@click.option("--stealth", is_flag=True, help="Enable randomized delays + jitter")
@click.option("--banner", is_flag=True, help="Attempt banner grabbing")
@click.option("--json", "json_file", default=None, help="Export results to JSON file")
@click.option("--csv", "csv_file", default=None, help="Export results to CSV file")
@click.option("--pdf", "pdf_file", default=None, help="Export results to PDF file")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.version_option(__version__, prog_name="GhostScanner")
def main(targets, ports, top, rate, timeout, stealth, banner, json_file, csv_file, pdf_file, verbose):
    """GhostScanner – High-performance asynchronous port scanner."""
    try:
        target_list = parse_targets(targets)
        if not target_list:
            console.print("[red][!] No valid targets found[/red]")
            sys.exit(1)

        port_list = parse_ports(ports, use_top=top)

        scanner = GhostScanner(
            targets=target_list,
            ports=port_list,
            concurrency=rate,
            timeout=timeout,
            stealth=stealth,
            grab_banner=banner,
            verbose=verbose,
        )

        results = asyncio.run(scanner.run())

        # Clean table output
        for host, result in results.items():
            if result.open_ports:
                table = Table(title=f"Open ports on {host}", show_header=True, header_style="bold green")
                table.add_column("Port", style="cyan", width=8)
                table.add_column("Service", style="magenta")
                table.add_column("Banner", style="white")
                table.add_column("Latency", style="yellow", justify="right")

                for p in result.open_ports:
                    table.add_row(
                        str(p.port),
                        p.service,
                        p.banner[:70] if p.banner else "-",
                        f"{p.latency_ms} ms"
                    )
                console.print(table)
            else:
                console.print(f"[yellow]No open ports found on {host}[/yellow]")

        # Calculate stats
        total_ports = len(port_list) * len(target_list)
        elapsed = next(iter(results.values())).scan_time if results else 0
        if elapsed > 0:
            pps = total_ports / elapsed
            console.print(f"\n[bold]Performance:[/bold] {pps:,.0f} ports/sec")

        if json_file:
            export_json(results, json_file)
        if csv_file:
            export_csv(results, csv_file)
        if pdf_file:
            export_pdf(results, pdf_file)

    except KeyboardInterrupt:
        console.print("\n[yellow][!] Scan interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red][!] Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()