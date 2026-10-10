import io
import csv
import datetime
from typing import List
from sqlalchemy.orm import Session
from app.models import Device, Alert, Policy

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_devices_csv(devices: List[Device]) -> str:
    """Exports all devices and calculated posture fields as CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)

    headers = [
        "device_id", "hostname", "owner_name", "owner_email", "department",
        "role_level", "device_type", "os_name", "os_version", "days_since_patch",
        "pending_critical_patches", "disk_encryption", "firewall_enabled",
        "antivirus_enabled", "edr_agent_running", "screen_lock_enabled",
        "secure_boot", "tpm_present", "jailbroken_or_rooted", "mdm_enrolled",
        "ownership", "failed_login_count_24h", "vpn_connected", "network_type",
        "wifi_security", "dns_security", "geo_country", "impossible_travel_flag",
        "access_sensitivity", "mfa_enabled", "privileged_account",
        "risk_score", "risk_level", "compliance_percentage", "compliance_status",
        "ztna_decision"
    ]
    writer.writerow(headers)

    for d in devices:
        writer.writerow([
            d.device_id, d.hostname, d.owner_name, d.owner_email, d.department,
            d.role_level, d.device_type, d.os_name, d.os_version, d.days_since_patch,
            d.pending_critical_patches, d.disk_encryption, d.firewall_enabled,
            d.antivirus_enabled, d.edr_agent_running, d.screen_lock_enabled,
            d.secure_boot, d.tpm_present, d.jailbroken_or_rooted, d.mdm_enrolled,
            d.ownership, d.failed_login_count_24h, d.vpn_connected, d.network_type,
            d.wifi_security, d.dns_security, d.geo_country, d.impossible_travel_flag,
            d.access_sensitivity, d.mfa_enabled, d.privileged_account,
            d.risk_score, d.risk_level, d.compliance_percentage, d.compliance_status,
            d.ztna_decision
        ])

    return output.getvalue()

def generate_pdf_executive_report(db: Session) -> bytes:
    """Generates a professional executive cybersecurity posture report in PDF format."""
    devices = db.query(Device).all()
    alerts = db.query(Alert).filter(Alert.status == "Open").all()

    total_devices = len(devices) or 1
    avg_risk = round(sum([d.risk_score for d in devices]) / total_devices, 1)
    compliance_avg = round(sum([d.compliance_percentage for d in devices]) / total_devices, 1)
    critical_count = len([d for d in devices if d.risk_level == "Critical"])
    high_count = len([d for d in devices if d.risk_level == "High"])
    compliant_count = len([d for d in devices if d.compliance_status == "Compliant"])

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#0f172a')
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748b')
    )
    h2_style = ParagraphStyle(
        'Heading2Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )

    story = []

    # Title & Header
    story.append(Paragraph("SentinelEdge – Executive Security Posture Report", title_style))
    story.append(Paragraph(f"Zero Trust Architecture & Remote Workforce Monitoring | Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=15))

    # Executive Summary Paragraph
    exec_text = (
        f"This report summarizes endpoint compliance, composite risk calculations, and Zero Trust access "
        f"enforcement across the enterprise's remote endpoints. The fleet currently maintains an overall "
        f"average risk index of <b>{avg_risk}/100</b> with a baseline compliance rate of <b>{compliance_avg}%</b>. "
        f"A total of <b>{critical_count} critical devices</b> and <b>{len(alerts)} open security alerts</b> require prioritized remediation."
    )
    story.append(Paragraph(exec_text, body_style))
    story.append(Spacer(1, 15))

    # KPI Table
    kpi_data = [
        ["Fleet Size", "Average Risk", "Compliance Rate", "Critical Risk Devices", "Open Security Alerts"],
        [f"{total_devices}", f"{avg_risk} / 100", f"{compliance_avg}%", f"{critical_count}", f"{len(alerts)}"]
    ]
    kpi_table = Table(kpi_data, colWidths=[105, 105, 105, 115, 105])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f8fafc')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 20))

    # Top Riskiest Devices Table
    story.append(Paragraph("Top Priority Riskiest Endpoints", h2_style))
    riskiest = sorted(devices, key=lambda x: x.risk_score, reverse=True)[:8]

    risk_data = [["Device ID", "Hostname", "Owner", "Department", "Risk Score", "ZTNA Decision"]]
    for d in riskiest:
        risk_data.append([
            d.device_id,
            d.hostname,
            d.owner_name,
            d.department,
            f"{d.risk_score} ({d.risk_level})",
            d.ztna_decision
        ])

    risk_table = Table(risk_data, colWidths=[70, 110, 100, 95, 80, 80])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('ALIGN', (4, 0), (5, -1), 'CENTER'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f1f5f9')]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 20))

    # Strategic Zero Trust Recommendations
    story.append(Paragraph("Strategic Corrective Action Items", h2_style))
    recs = [
        "1. <b>Mandatory Disk Encryption:</b> Enforce BitLocker/FileVault fleet-wide to prevent data compromise on lost/stolen endpoints.",
        "2. <b>EDR Coverage Enforcement:</b> Re-activate offline endpoint detection agents to maintain real-time threat visibility.",
        "3. <b>Untrusted Wi-Fi Controls:</b> Restrict access to sensitive enterprise data when connected via open or insecure Wi-Fi without VPN.",
        "4. <b>MFA Hardening:</b> Enforce FIDO2/WebAuthn step-up authentication across all privileged identity access vectors."
    ]
    for r in recs:
        story.append(Paragraph(r, body_style))
        story.append(Spacer(1, 4))

    doc.build(story)
    return buffer.getvalue()
