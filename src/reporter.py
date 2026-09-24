#!/usr/bin/env python3
"""Report generation – JSON, PDF and CSV."""

import json
import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from .scanner import ScanResult


def export_json(results: Dict[str, ScanResult], output_path: str) -> None:
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanner": "GhostScanner v1.2.0",
        "hosts": {},
    }

    for host, result in results.items():
        data["hosts"][host] = {
            "scan_time_seconds": round(result.scan_time, 3),
            "open_ports": [
                {
                    "port": p.port,
                    "service": p.service,
                    "banner": p.banner,
                    "latency_ms": p.latency_ms,
                }
                for p in result.open_ports
            ],
        }

    Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"[+] JSON report saved → {output_path}")


def export_csv(results: Dict[str, ScanResult], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Port", "Service", "Banner", "Latency_ms"])

        for host, result in results.items():
            for p in result.open_ports:
                writer.writerow([host, p.port, p.service, p.banner, p.latency_ms])

    print(f"[+] CSV report saved → {output_path}")


def export_pdf(results: Dict[str, ScanResult], output_path: str) -> None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
    except ImportError:
        print("[!] reportlab not installed – skipping PDF export")
        return

    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        textColor=colors.HexColor("#00ff41"),
        spaceAfter=12,
    )

    elements = []
    elements.append(Paragraph("GhostScanner Report", title_style))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    elements.append(Spacer(1, 8 * mm))

    for host, result in results.items():
        elements.append(Paragraph(f"<b>Host: {host}</b>", styles["Heading2"]))
        if not result.open_ports:
            elements.append(Paragraph("No open ports found.", styles["Normal"]))
            continue

        table_data = [["Port", "Service", "Banner", "Latency (ms)"]]
        for p in result.open_ports:
            table_data.append([
                str(p.port),
                p.service,
                (p.banner[:60] + "…") if len(p.banner) > 60 else p.banner,
                str(p.latency_ms),
            ])

        table = Table(table_data, colWidths=[50, 80, 250, 70])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#003300")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#00ff41")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#00aa33")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#001a00"), colors.HexColor("#002200")]),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#00ff41")),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 6 * mm))

    doc.build(elements)
    print(f"[+] PDF report saved → {output_path}")