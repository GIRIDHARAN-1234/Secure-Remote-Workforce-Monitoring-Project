from typing import Optional, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.database import get_db
from app.models import AuditLog, User
from app.auth.deps import require_role
from app.schemas import AuditLogResponse

router = APIRouter(prefix="/audit", tags=["Audit Log"])

@router.get("/")
def list_audit_logs(
    action: Optional[str] = None,
    user_email: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role(["admin"]))
):
    query = db.query(AuditLog)

    if action:
        query = query.filter(AuditLog.action == action)
    if user_email:
        query = query.filter(AuditLog.user_email.ilike(f"%{user_email}%"))
    if search:
        s_fmt = f"%{search.strip()}%"
        query = query.filter(
            or_(
                AuditLog.action.ilike(s_fmt),
                AuditLog.user_email.ilike(s_fmt),
                AuditLog.target.ilike(s_fmt),
                AuditLog.details.ilike(s_fmt)
            )
        )

    total = query.count()
    logs = query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": [AuditLogResponse.model_validate(l) for l in logs]
    }
