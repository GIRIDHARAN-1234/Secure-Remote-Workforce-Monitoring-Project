import json
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.database import get_db
from app.models import Device, Policy, Alert, AuditLog, User
from app.auth.deps import get_current_user, require_role, get_client_ip
from app.schemas import DeviceResponse, DeviceDetailResponse, DeviceRemediateRequest
from app.services.recommendations import get_device_recommendations, apply_remediation_to_device
from app.services.ztna import evaluate_ztna_access

router = APIRouter(prefix="/devices", tags=["Devices"])

@router.get("/")
def list_devices(
    search: Optional[str] = None,
    status: Optional[str] = None,
    risk_level: Optional[str] = None,
    department: Optional[str] = None,
    os_name: Optional[str] = None,
    network_type: Optional[str] = None,
    ownership: Optional[str] = None,
    antivirus_enabled: Optional[bool] = None,
    disk_encryption: Optional[bool] = None,
    sort_by: str = "risk_score",
    order: str = "desc",
    skip: int = Query(0, ge=0),
    limit: int = Query(25, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Device)

    if search:
        search_fmt = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Device.hostname.ilike(search_fmt),
                Device.owner_name.ilike(search_fmt),
                Device.owner_email.ilike(search_fmt),
                Device.device_id.ilike(search_fmt)
            )
        )

    if status:
        query = query.filter(Device.compliance_status == status)
    if risk_level:
        query = query.filter(Device.risk_level == risk_level)
    if department:
        query = query.filter(Device.department == department)
    if os_name:
        query = query.filter(Device.os_name == os_name)
    if network_type:
        query = query.filter(Device.network_type == network_type)
    if ownership:
        query = query.filter(Device.ownership == ownership)
    if antivirus_enabled is not None:
        query = query.filter(Device.antivirus_enabled == antivirus_enabled)
    if disk_encryption is not None:
        query = query.filter(Device.disk_encryption == disk_encryption)

    total = query.count()

    # Sorting
    sort_column = getattr(Device, sort_by, Device.risk_score)
    if order.lower() == "asc":
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())

    devices = query.offset(skip).limit(limit).all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": [DeviceResponse.model_validate(d) for d in devices]
    }

@router.get("/{device_id}", response_model=DeviceDetailResponse)
def get_device_detail(
    device_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found.")

    # All policies lookup
    all_policies = {p.id: p for p in db.query(Policy).all()}

    failed_ids = []
    try:
        failed_ids = json.loads(device.failed_policies) if device.failed_policies else []
    except Exception:
        pass

    failed_details = []
    passed_details = []

    for pid, p in all_policies.items():
        pol_obj = {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "category": p.category,
            "severity": p.severity,
            "weight": p.weight
        }
        if pid in failed_ids:
            failed_details.append(pol_obj)
        else:
            passed_details.append(pol_obj)

    recommendations, projected_score = get_device_recommendations(device)
    active_alerts = db.query(Alert).filter(Alert.device_id == device_id, Alert.status.in_(["Open", "Investigating"])).all()
    ztna_info = evaluate_ztna_access(device)

    resp_dict = DeviceResponse.model_validate(device).model_dump()
    resp_dict.update({
        "failed_policy_details": failed_details,
        "passed_policy_details": passed_details,
        "remediation_recommendations": recommendations,
        "projected_risk_score": projected_score,
        "active_alerts": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "category": a.category,
                "mitre_technique": a.mitre_technique,
                "created_at": a.created_at
            }
            for a in active_alerts
        ],
        "ztna_explanation": ztna_info
    })

    return resp_dict

@router.post("/{device_id}/remediate")
def remediate_single_device(
    device_id: str,
    req: DeviceRemediateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin"]))
):
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found.")

    client_ip = get_client_ip(request)
    old_score = device.risk_score

    result = apply_remediation_to_device(db, device, req.policy_ids)

    # Log audit
    audit = AuditLog(
        user_email=current_user.email,
        action="DEVICE_REMEDIATION",
        target=device.device_id,
        details=f"Remediated {result['remediated_count']} policies on {device.hostname}. Risk score dropped from {old_score} to {result['new_risk_score']}.",
        ip_address=client_ip
    )
    db.add(audit)
    db.commit()

    return {
        "message": f"Remediation successfully applied to {device.hostname}.",
        "result": result
    }

@router.post("/remediate-bulk")
def remediate_bulk_devices(
    request: Request,
    policy_id: Optional[str] = None,
    device_ids: Optional[List[str]] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin"]))
):
    client_ip = get_client_ip(request)
    remediated_devices = []

    if device_ids:
        devices = db.query(Device).filter(Device.device_id.in_(device_ids)).all()
        for dev in devices:
            res = apply_remediation_to_device(db, dev, [policy_id] if policy_id else None)
            remediated_devices.append(res)
    elif policy_id:
        devices = db.query(Device).all()
        for dev in devices:
            failed_list = json.loads(dev.failed_policies) if dev.failed_policies else []
            if policy_id in failed_list:
                res = apply_remediation_to_device(db, dev, [policy_id])
                remediated_devices.append(res)

    audit = AuditLog(
        user_email=current_user.email,
        action="BULK_REMEDIATION",
        target=policy_id or f"{len(remediated_devices)} devices",
        details=f"Bulk remediation executed across {len(remediated_devices)} endpoints.",
        ip_address=client_ip
    )
    db.add(audit)
    db.commit()

    return {
        "message": f"Bulk remediation executed across {len(remediated_devices)} devices.",
        "remediated_count": len(remediated_devices),
        "results": remediated_devices
    }
