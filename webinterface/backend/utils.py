import os
import json
from datetime import datetime

from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib import colors

from Core.orchestrator import (
    validate_creds,
    discover_enabled_services,
    thread_audits
)

def list_json_results(folder: str):
    """
    Return a sorted list of JSON filenames in the given folder.
    """
    return sorted(f for f in os.listdir(folder) if f.lower().endswith('.json'))

def run_scan_and_save_pdf(access_key: str,
                          secret_key: str,
                          session_token: str = None,
                          region: str = None,
                          folder: str = 'scans'):
    """
    1) validate_creds
    2) discover_enabled_services
    3) thread_audits
    4) generate & save PDF from raw results
    5) save JSON
    Returns (pdf_filename, report_json)
    """
    valid, message, session = validate_creds(
        access_key, secret_key, session_token, region
    )
    if not valid:
        raise RuntimeError(f"Credential validation failed: {message}")

    # Discover services and collect raw audit results (list of lists)
    enabled_services = discover_enabled_services(session)
    print(enabled_services)
    raw_results = thread_audits(enabled_services, session)

    # Build report data
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    report_json = {
        "timestamp": timestamp,
        "validate": message,
        "services": enabled_services,
        "raw_results": raw_results
    }

    # Ensure output folder exists
    os.makedirs(folder, exist_ok=True)

    # Save PDF
    ts_fname = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    base_name = f"scan_{ts_fname}"
    pdf_path = os.path.join(folder, f"{base_name}.pdf")
    _build_pdf(pdf_path, report_json)

    # Save JSON
    json_path = os.path.join(folder, f"{base_name}.json")
    with open(json_path, 'w') as jf:
        json.dump(report_json, jf, indent=2)

    return f"{base_name}.pdf", report_json

def _build_pdf(path: str, report: dict):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(
        path,
        rightMargin=inch, leftMargin=inch,
        topMargin=inch, bottomMargin=inch
    )
    elems = []

    # Title page
    elems.append(Paragraph("CIS Benchmark Scan Report", styles['Title']))
    elems.append(Spacer(1, 0.2 * inch))
    elems.append(Paragraph(f"Generated: {report['timestamp']}", styles['Normal']))
    elems.append(Spacer(1, 0.2 * inch))
    elems.append(Paragraph(f"Validation: {report['validate']}", styles['Normal']))
    elems.append(PageBreak())

    # Summary table
    elems.append(Paragraph("Summary of Findings", styles['Heading2']))
    summary = [["Service", "Findings Count"]]
    for group in report['raw_results']:
        if group:
            svc = group[0].get('service', 'Unknown')
        else:
            svc = 'Unknown'
        summary.append([svc, str(len(group))])
    tbl = Table(summary, hAlign='LEFT', colWidths=[3*inch, 1.5*inch])
    tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
    ]))
    elems.append(tbl)
    elems.append(PageBreak())

    # Detailed findings per service
    for group in report['raw_results']:
        if group:
            svc = group[0].get('service', 'Unknown')
        else:
            svc = 'Unknown'
        elems.append(Paragraph(f"Service: {svc}", styles['Heading2']))
        if not group:
            elems.append(Paragraph("No findings.", styles['Normal']))
        else:
            for f in group:
                check_id = f.get('check_id')
                status = f.get('status')
                evidence = f.get('evidence')
                text = f"[{check_id}] {status}"
                if evidence:
                    text += f": {evidence}"
                elems.append(Paragraph(f"• {text}", styles['Bullet']))
        elems.append(Spacer(1, 0.2 * inch))

    doc.build(elems)


if __name__ == "__main__":
    # Example invocation; replace with real credentials and region
    run_scan_and_save_pdf(
        "ASIATMINPL6ZDEMNIS2J",
        "ktTzmIeA9AyJN+t00ElnLzlSTH1BeqLL/Qdbe6pf",
        "IQoJb3JpZ2luX2VjEOf//////////wEaCXVzLXdlc3QtMiJGMEQCIGZzajWtvXtQu6sHYMGe4eWZWqFymuTpJFCct0nV5tN5AiAzUzBcyn+Xm8TuOLLpJYbVhFrJ3a6ITs8ehBmHJnNnmyqyAgiQ//////////8BEAAaDDIzMjQ5MzM3NTQxMCIMmPpCd37G2+ZSIvxMKoYCPo1DGKRLsxOqrVOHLIZejA3ucC8fiiIfKs1paqQDVXpbr8HH/pMtglI9sBiHz05mYVS8xIWUMl4MCU/z9PUpVVYzWukfispts995Q9/23L0K/UtSjWkRtrHdzFTsFkUgxnMPDui419CzfUTQJStgrTQ09R7n1tYARemDx/SvtS1qSmh3taDOJr1321k4bisxWbGARZbDrjCLpkCcHN0G8k0C2iGyllWNq/7SxxJq7NcC9V/3SVbCeF4DuyCtyIF1qsratPjSjBPUdP2xjvJ7OeOGWit/Yjk8FHPZj5c2/c8wYj6nBX9wugvMJulPrAl/a3l/EZm8lrAtHjcw+TsXa6u77M6idTChpfjABjqeATjpMyNL/zD+iRfQzKsDj/Bl3NpXaG24QZg4gRx6M5bHB22fDvCRh2NFo5qWqZyJ9AEAfwkmTl+/VpP6kS8rgmvPBLBqr10PK8pH2uc7PIgePwVb7Ps7eY5Ffo7anYcoRu5L/QWCKZLUIiqBRYwS8fa9yyN6/R1+9hbERtaFGWLadHdofdPN6dwzGMgw2p8PKcNVb8j725B4q0moigXR",
        "us-east-1"
    )
