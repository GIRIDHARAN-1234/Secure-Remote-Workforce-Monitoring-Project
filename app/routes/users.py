from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, AuditLog
from app.auth.deps import require_role, get_client_ip
from app.schemas import UserResponse, UserUpdateRole, UserToggleActive
from app.auth.security import security_limiter

router = APIRouter(prefix="/users", tags=["User Management"])

@router.get("/", response_model=List[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role(["admin"]))
):
    users = db.query(User).order_by(User.id.asc()).all()
    return users

@router.patch("/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: int,
    req: UserUpdateRole,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role(["admin"]))
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if req.role not in ["admin", "analyst", "viewer"]:
        raise HTTPException(status_code=400, detail="Invalid role specified.")

    old_role = user.role
    user.role = req.role

    client_ip = get_client_ip(request)
    audit = AuditLog(
        user_email=admin_user.email,
        action="USER_ROLE_CHANGED",
        target=user.email,
        details=f"Role changed from {old_role} to {user.role}",
        ip_address=client_ip
    )
    db.add(audit)
    db.commit()
    db.refresh(user)

    return user

@router.patch("/{user_id}/status", response_model=UserResponse)
def toggle_user_active_status(
    user_id: int,
    req: UserToggleActive,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role(["admin"]))
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if user.id == admin_user.id:
        raise HTTPException(status_code=400, detail="Administrators cannot deactivate their own account.")

    user.is_active = req.is_active

    client_ip = get_client_ip(request)
    audit = AuditLog(
        user_email=admin_user.email,
        action="USER_STATUS_TOGGLED",
        target=user.email,
        details=f"Active status toggled to {user.is_active}",
        ip_address=client_ip
    )
    db.add(audit)
    db.commit()
    db.refresh(user)

    return user

@router.post("/{user_id}/unlock", response_model=UserResponse)
def unlock_user_account(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role(["admin"]))
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user.is_locked = False
    user.failed_logins = 0
    user.locked_until = None
    security_limiter.reset_failed_logins(user.email)

    client_ip = get_client_ip(request)
    audit = AuditLog(
        user_email=admin_user.email,
        action="USER_ACCOUNT_UNLOCKED",
        target=user.email,
        details="Account unlocked administratively.",
        ip_address=client_ip
    )
    db.add(audit)
    db.commit()
    db.refresh(user)

    return user
