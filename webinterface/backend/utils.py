import json
from datetime import datetime
from Core.orchestrator import (
    validate_creds,
    discover_enabled_services,
    thread_audits
)
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import inch
from reportlab.lib import colors
import os
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
    styles.add(ParagraphStyle('CenteredTitle',
                              parent=styles['Title'],
                              alignment=TA_CENTER,
                              spaceAfter=20))
    styles.add(ParagraphStyle('NormalCenter',
                              parent=styles['Normal'],
                              alignment=TA_CENTER))
    styles.add(ParagraphStyle('SmallItalic',
                              parent=styles['Normal'],
                              fontSize=8,
                              textColor=colors.grey))
    # For wrapped cells
    styles.add(ParagraphStyle('CellWrap',
                              parent=styles['Normal'],
                              fontSize=9,
                              leading=11))

    doc = SimpleDocTemplate(
        path,
        rightMargin=inch, leftMargin=inch,
        topMargin=inch, bottomMargin=inch
    )
    elems = []

    # ----- COVER PAGE -----
    logo_path = '../frontend/public/logo.png'
    if os.path.exists(logo_path):
        elems.append(Image(logo_path, width=2*inch, height=2*inch, hAlign='CENTER'))
        elems.append(Spacer(1, 0.2*inch))

    elems.append(Paragraph("CIS Benchmark Security Audit Report", styles['CenteredTitle']))
    elems.append(Spacer(1, 0.1*inch))
    # Tool description—customize this line:
    elems.append(Paragraph("An automated auditing tool for AWS accounts based on the CIS Benchmark v4.", styles['NormalCenter']))
    elems.append(Spacer(1, 0.2*inch))
    elems.append(Paragraph(report['timestamp'], styles['SmallItalic']))
    elems.append(PageBreak())

    # ----- SUMMARY PAGE -----
    elems.append(Paragraph("Summary of Audit", styles['Heading1']))
    elems.append(Spacer(1, 0.2*inch))

    # Count failed findings
    total_fail = sum(1 for group in report['raw_results'] for f in group if f['status']=='FAIL')
    # Services checked
    services = report.get('services', [])
    # Resources per service
    resource_counts = {
        svc: sum(1 for f in group)
        for svc, group in zip(services, report['raw_results'])
    }

    summary_table_data = [
        ['Total Failed Checks', str(total_fail)],
        ['Benchmarks Checked', ', '.join(services)]
    ]
    for svc, count in resource_counts.items():
        summary_table_data.append([f'Resources in {svc}', str(count)])

    summary_tbl = Table(summary_table_data, hAlign='LEFT', colWidths=[2.5*inch, 3*inch])
    summary_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
    ]))
    elems.append(summary_tbl)
    elems.append(PageBreak())

    # ----- DETAILED FAILS -----
    elems.append(Paragraph("Detailed Findings", styles['Heading1']))

    # Build a single table for all FAIL findings
    detail_data = [['Service', 'Check ID', 'Resource', 'Evidence', 'Remediation']]
    for group in report['raw_results']:
        for f in group:
            if f['status'] != 'FAIL':
                continue
            # Wrap evidence and remediation in Paragraphs
            res=Paragraph(f.get('resource',''), styles['CellWrap'])
            ev = Paragraph(f.get('evidence',''), styles['CellWrap'])
            rem = Paragraph(f.get('remediation',''), styles['CellWrap'])
            detail_data.append([
                f.get('service',''),
                f.get('check_id',''),
                res,
                ev,
                rem
            ])

    detail_tbl = Table(detail_data, repeatRows=1,
                       colWidths=[1*inch, 1*inch, 1*inch, 2*inch, 2*inch])
    detail_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#CCCCCC')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.black),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        # Make status column text red
        ('TEXTCOLOR', (1,1), (1,-1), colors.red),
    ]))

    # Wrap table to avoid text overlap
    elems.append(KeepTogether(detail_tbl))

    doc.build(elems)

