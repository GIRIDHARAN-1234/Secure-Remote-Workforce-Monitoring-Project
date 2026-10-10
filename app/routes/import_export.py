import io
from typing import Optional
from fastapi import APIRouter, Depends, UploadFile, File, Response, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Device, AuditLog, User
from app.auth.deps import get_current_user, require_role, get_client_ip
from app.schemas import ImportSummaryResponse
from app.services.importer import validate_and_import_telemetry, REQUIRED_COLUMNS
from app.services.reports import generate_devices_csv, generate_pdf_executive_report

router = APIRouter(prefix="/import-export", tags=["Import & Export"])

@router.post("/import-csv", response_model=ImportSummaryResponse)
async def import_telemetry(
    file: UploadFile = File(...),
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"]))
):
    contents = await file.read()
    filename = file.filename.lower()
    is_json = filename.endswith(".json")

    result = validate_and_import_telemetry(db, contents, is_json=is_json)

    # Log audit
    client_ip = get_client_ip(request)
    audit = AuditLog(
        user_email=current_user.email,
        action="DATA_IMPORT",
        target=file.filename,
        details=f"Imported {result['total_rows']} rows: {result['created']} created, {result['updated']} updated, {len(result['errors'])} errors.",
        ip_address=client_ip
    )
    db.add(audit)
    db.commit()

    return ImportSummaryResponse(**result)

@router.get("/template")
def download_sample_template():
    """Generates a downloadable CSV template with required and sample columns."""
    sample_csv = (
        "device_id,hostname,owner_name,owner_email,department,role_level,device_type,os_name,os_version,"
        "days_since_patch,pending_critical_patches,disk_encryption,firewall_enabled,antivirus_enabled,"
        "antivirus_signature_age_days,edr_agent_running,screen_lock_enabled,secure_boot,tpm_present,"
        "jailbroken_or_rooted,mdm_enrolled,ownership,failed_login_count_24h,vpn_connected,network_type,"
        "wifi_security,dns_security,geo_country,impossible_travel_flag,access_sensitivity,mfa_enabled,"
        "privileged_account,installed_risky_apps\n"
        "DEV-9001,ENG-LAP-901,Jane Doe,jane.doe@sentineledge.io,Engineering,employee,laptop,Windows,Windows 11 23H2,"
        "12,0,True,True,True,2,True,True,True,True,False,True,corporate,0,True,home,WPA3,DoH,United States,False,high,True,False,0\n"
        "DEV-9002,FIN-BYOD-902,John Contractor,john.c@external.com,Finance,contractor,laptop,macOS,macOS Sonoma 14.4,"
        "65,1,False,True,True,9,False,False,True,True,False,False,BYOD,3,False,public_wifi,open,standard,United States,False,critical,False,False,1\n"
    )
    return Response(
        content=sample_csv,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentineledge_telemetry_template.csv"}
    )

@router.get("/export-csv")
def export_posture_csv(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"]))
):
    devices = db.query(Device).all()
    csv_data = generate_devices_csv(devices)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentineledge_posture_fleet.csv"}
    )

@router.get("/export-pdf")
def export_posture_pdf(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"]))
):
    pdf_bytes = generate_pdf_executive_report(db)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=sentineledge_executive_report.pdf"}
    )
