import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.database import get_db
from app.models import Alert, Device, AuditLog, User
from app.auth.deps import get_current_user, require_role, get_client_ip
from app.schemas import AlertResponse, AlertUpdateStatus, AlertBulkUpdate

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("/")
def list_alerts(
    search: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    device_id: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(30, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Alert)

    if search:
        s_fmt = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Alert.title.ilike(s_fmt),
                Alert.description.ilike(s_fmt),
                Alert.mitre_technique.ilike(s_fmt),
                Alert.device_id.ilike(s_fmt)
            )
        )

    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)
    if category:
        query = query.filter(Alert.category == category)
    if device_id:
        query = query.filter(Alert.device_id == device_id)

    total = query.count()
    alerts = query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": [AlertResponse.model_validate(a) for a in alerts]
    }

@router.get("/stats")
def get_alert_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alerts = db.query(Alert).all()
    
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_status = {"Open": 0, "Acknowledged": 0, "Investigating": 0, "Resolved": 0, "False Positive": 0}

    for a in alerts:
        sev = a.severity.lower() if a.severity else "medium"
        by_severity[sev] = by_severity.get(sev, 0) + 1
        stat = a.status if a.status else "Open"
        by_status[stat] = by_status.get(stat, 0) + 1

    return {
        "total": len(alerts),
        "by_severity": by_severity,
        "by_status": by_status
    }

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert_detail(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")
    return alert

@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert_status(
    alert_id: str,
    update_data: AlertUpdateStatus,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"]))
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")

    client_ip = get_client_ip(request)
    old_status = alert.status
    alert.status = update_data.status

    if update_data.assigned_to is not None:
        alert.assigned_to = update_data.assigned_to
    if update_data.notes is not None:
        alert.notes = update_data.notes

    alert.updated_at = datetime.datetime.utcnow()

    # Log audit
    audit = AuditLog(
        user_email=current_user.email,
        action="ALERT_STATUS_UPDATE",
        target=alert.id,
        details=f"Alert status modified from '{old_status}' to '{alert.status}' by {current_user.email}",
        ip_address=client_ip
    )
    db.add(audit)
    db.commit()
    db.refresh(alert)

    return alert

@router.post("/bulk-update")
def bulk_update_alerts(
    bulk_data: AlertBulkUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"]))
):
    client_ip = get_client_ip(request)
    alerts = db.query(Alert).filter(Alert.id.in_(bulk_data.alert_ids)).all()
    
    for a in alerts:
        a.status = bulk_data.status
        if bulk_data.assigned_to:
            a.assigned_to = bulk_data.assigned_to
        a.updated_at = datetime.datetime.utcnow()

    audit = AuditLog(
        user_email=current_user.email,
        action="ALERT_BULK_UPDATE",
        target=f"{len(alerts)} alerts",
        details=f"Updated status of {len(alerts)} alerts to '{bulk_data.status}'",
        ip_address=client_ip
    )
    db.add(audit)
    db.commit()

    return {"message": f"Successfully updated {len(alerts)} alerts to '{bulk_data.status}'."}
